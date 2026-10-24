//! Sign-in through an external OpenID Connect provider.
//!
//! Two paths share one trust decision. The web client uses the authorization-code flow with
//! PKCE; mail clients present an access token with SASL XOAUTH2 or OAUTHBEARER. Either way the
//! server asks the provider's userinfo endpoint who the token belongs to, over TLS, and maps
//! the verified e-mail address to an existing local account. Accounts are never created here.
//!
//! A token presented by a mail client must also have been issued to this server's client: an
//! access token another application obtained from the same provider would otherwise open the
//! mailbox too. The provider's introspection endpoint (RFC 7662) answers that; without one, a
//! JWT access token's own audience claims are used (its signature is vouched for by the
//! userinfo endpoint accepting it). Opaque tokens that cannot be checked are refused.

use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::{
    app::App,
    auth::{Account, AuthError, Protocol},
    util::{random_token, sanitize_line, sha256, sha256_hex},
};

const SETTING_KEY: &str = "oauth.config";
const STATE_TTL: Duration = Duration::from_secs(600);
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
const TOKEN_CACHE_TTL: Duration = Duration::from_secs(300);
const MAX_PENDING: usize = 10_000;
/// Sign-ins one network (an address, or an IPv6 /64) may have open, so that nobody fills the
/// table and keeps everybody else out.
const MAX_PENDING_PER_NETWORK: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OauthConfig {
    pub enabled: bool,
    /// Label of the sign-in button.
    #[serde(default = "default_name")]
    pub name: String,
    /// The provider's issuer URL; its discovery document is read from
    /// `<issuer>/.well-known/openid-configuration`.
    pub issuer: String,
    pub client_id: String,
    /// Sealed with the server key.
    #[serde(default)]
    pub client_secret: String,
    #[serde(default = "default_scopes")]
    pub scopes: String,
    /// Refuse sign-in unless the provider states that the e-mail address is verified.
    #[serde(default = "yes")]
    pub require_verified_email: bool,
}

fn default_name() -> String {
    "Single sign-on".into()
}

fn default_scopes() -> String {
    "openid email profile".into()
}

fn yes() -> bool {
    true
}

impl OauthConfig {
    pub fn validate(&self, allow_plain_http: bool) -> Result<(), String> {
        let url = reqwest::Url::parse(&self.issuer).map_err(|_| "the issuer must be a URL")?;
        if !(url.scheme() == "https" || (allow_plain_http && url.scheme() == "http")) || url.host_str().is_none() {
            return Err("the issuer must be an https:// URL".into());
        }
        if self.client_id.trim().is_empty() || self.client_id.len() > 300 {
            return Err("a client id is required".into());
        }
        if self.name.trim().is_empty() || self.name.chars().count() > 40 || self.name.chars().any(char::is_control) {
            return Err("the button label must be 1 to 40 characters".into());
        }
        if !self.scopes.split_whitespace().any(|s| s == "openid") || self.scopes.len() > 200 || !self.scopes.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
            return Err("the scopes must include \"openid\"".into());
        }
        Ok(())
    }
}

pub async fn load(app: &App) -> sqlx::Result<Option<OauthConfig>> {
    Ok(crate::db::get_setting(&app.db, SETTING_KEY).await?.and_then(|json| serde_json::from_str(&json).ok()))
}

pub async fn save(app: &App, config: &OauthConfig) -> sqlx::Result<()> {
    crate::db::set_setting(&app.db, SETTING_KEY, &serde_json::to_string(config).unwrap_or_default()).await?;
    // Nothing learned from the previous provider may outlive a change of configuration.
    app.oauth.discovery.lock().clear();
    app.oauth.tokens.lock().clear();
    app.oauth.pending.lock().clear();
    Ok(())
}

/// The configuration, if single sign-on is switched on.
pub async fn active(app: &App) -> Option<OauthConfig> {
    load(app).await.ok().flatten().filter(|config| config.enabled)
}

#[derive(Debug, Clone, Deserialize)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    #[serde(default)]
    introspection_endpoint: Option<String>,
}

/// Who the provider says signed in: (subject, e-mail address).
type Identity = (String, String);

/// Pending web sign-ins: state -> (PKCE verifier, network of the browser, started).
type Pending = HashMap<String, (String, String, Instant)>;

/// What single sign-on keeps in memory, per server instance (one configuration each).
#[derive(Default)]
pub struct Caches {
    /// The provider's discovery document, by issuer.
    discovery: Mutex<HashMap<String, (Discovery, Instant)>>,
    pending: Mutex<Pending>,
    /// Recently verified access tokens: sha256(token) -> (identity, verified at).
    tokens: Mutex<HashMap<String, (Identity, Instant)>>,
}

async fn discover(app: &App, config: &OauthConfig) -> Result<Discovery, String> {
    let issuer = config.issuer.trim_end_matches('/').to_owned();
    if let Some((found, at)) = app.oauth.discovery.lock().get(&issuer)
        && at.elapsed() < DISCOVERY_TTL
    {
        return Ok(found.clone());
    }
    let response = app.http.get(format!("{issuer}/.well-known/openid-configuration")).send().await.map_err(|_| "the identity provider cannot be reached")?;
    if !response.status().is_success() {
        return Err("the identity provider did not return its configuration".into());
    }
    let found: Discovery = response.json().await.map_err(|_| "the identity provider returned an invalid configuration")?;
    // Every endpoint must live on the same kind of transport as the issuer itself.
    let scheme = if issuer.starts_with("https://") { "https://" } else { "http://" };
    if ![&found.authorization_endpoint, &found.token_endpoint, &found.userinfo_endpoint].iter().all(|url| url.starts_with(scheme))
        || found.introspection_endpoint.as_ref().is_some_and(|url| !url.starts_with(scheme))
    {
        return Err("the identity provider advertises endpoints that are not secure".into());
    }
    app.oauth.discovery.lock().insert(issuer, (found.clone(), Instant::now()));
    Ok(found)
}

/// The address the provider sends the browser back to.
pub fn redirect_uri(app: &App) -> String {
    format!("{}/api/auth/oauth/callback", app.cfg.public_url())
}

/// Starts a web sign-in: returns the provider URL to send the browser to and the state value
/// that must come back (also bound to the browser with a cookie by the caller).
pub async fn begin(app: &App, ip: IpAddr) -> Result<(String, String), String> {
    let config = active(app).await.ok_or("single sign-on is not enabled")?;
    let discovery = discover(app, &config).await?;
    let (state, verifier) = (random_token(), random_token());
    let challenge = URL_SAFE_NO_PAD.encode(sha256(verifier.as_bytes()));
    {
        let mut pending = app.oauth.pending.lock();
        pending.retain(|_, (.., started)| started.elapsed() < STATE_TTL);
        let network = crate::auth::network(ip);
        if pending.len() >= MAX_PENDING || pending.values().filter(|(_, from, _)| *from == network).count() >= MAX_PENDING_PER_NETWORK {
            return Err("too many sign-ins are in progress, try again shortly".into());
        }
        pending.insert(state.clone(), (verifier, network, Instant::now()));
    }
    let mut url = reqwest::Url::parse(&discovery.authorization_endpoint).map_err(|_| "the identity provider returned an invalid address")?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &redirect_uri(app))
        .append_pair("scope", &config.scopes)
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    Ok((url.to_string(), state))
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct UserInfo {
    sub: Option<String>,
    email: Option<String>,
    email_verified: Option<serde_json::Value>,
}

/// Asks the provider who an access token belongs to. Returns (subject, e-mail).
async fn identify(app: &App, config: &OauthConfig, access_token: &str) -> Result<(String, String), String> {
    let discovery = discover(app, config).await?;
    let response = app.http.get(&discovery.userinfo_endpoint).bearer_auth(access_token).send().await.map_err(|_| "the identity provider cannot be reached")?;
    if !response.status().is_success() {
        return Err("the identity provider rejected the token".into());
    }
    let info: UserInfo = response.json().await.map_err(|_| "the identity provider returned an invalid profile")?;
    // Providers report the flag as a boolean or as the string "true".
    let verified = matches!(&info.email_verified, Some(serde_json::Value::Bool(true))) || info.email_verified.as_ref().and_then(|v| v.as_str()) == Some("true");
    if config.require_verified_email && !verified {
        return Err("the identity provider has not verified this e-mail address".into());
    }
    let email = info.email.and_then(|e| crate::util::Address::parse(&e)).ok_or("the identity provider did not return an e-mail address")?;
    Ok((info.sub.unwrap_or_default(), email.to_string()))
}

/// Whether `value` (a string or an array of strings) names `client_id`.
fn names_client(value: Option<&serde_json::Value>, client_id: &str) -> bool {
    match value {
        Some(serde_json::Value::String(s)) => s == client_id,
        Some(serde_json::Value::Array(items)) => items.iter().any(|item| item.as_str() == Some(client_id)),
        _ => false,
    }
}

/// Whether a set of token claims (from introspection or a JWT) says the token was issued to
/// `client_id`. Providers differ in the claim they use: `aud`, `azp`, `client_id`, `cid`
/// (Okta) or `appid` (Microsoft Entra).
fn issued_to(claims: &serde_json::Value, client_id: &str) -> bool {
    ["aud", "azp", "client_id", "cid", "appid"].iter().any(|claim| names_client(claims.get(*claim), client_id))
}

/// The claims of a JWT access token, without checking its signature (see the module notes).
fn jwt_claims(token: &str) -> Option<serde_json::Value> {
    let mut parts = token.split('.');
    let (_, payload, _) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?).ok().filter(serde_json::Value::is_object)
}

/// Checks that an access token presented by a mail client was issued to this server.
async fn check_audience(app: &App, config: &OauthConfig, access_token: &str) -> Result<(), String> {
    let discovery = discover(app, config).await?;
    if let Some(endpoint) = &discovery.introspection_endpoint {
        let secret = app.secrets.open(&config.client_secret).unwrap_or_default();
        let mut form = vec![("token", access_token), ("token_type_hint", "access_token"), ("client_id", config.client_id.as_str())];
        if !secret.is_empty() {
            form.push(("client_secret", secret.as_str()));
        }
        let body: String = form.iter().map(|(k, v)| format!("{k}={}", urlencode(v))).collect::<Vec<_>>().join("&");
        let response = app
            .http
            .post(endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| "the identity provider cannot be reached")?;
        if !response.status().is_success() {
            return Err("the identity provider refused to describe the token".into());
        }
        let claims: serde_json::Value = response.json().await.map_err(|_| "the identity provider returned an invalid token description")?;
        if claims.get("active") != Some(&serde_json::Value::Bool(true)) {
            return Err("the token is not active".into());
        }
        return if issued_to(&claims, &config.client_id) { Ok(()) } else { Err("the token was issued to another application".into()) };
    }
    match jwt_claims(access_token) {
        Some(claims) if issued_to(&claims, &config.client_id) => Ok(()),
        Some(_) => Err("the token was issued to another application".into()),
        None => Err("the token cannot be checked: the identity provider offers no introspection and the token is not a JWT".into()),
    }
}

async fn local_account(app: &App, email: &str) -> Result<Account, String> {
    let domain_enabled = |account: &Account| {
        let id = account.domain_id;
        async move { sqlx::query_scalar::<_, bool>("SELECT enabled FROM domains WHERE id = ?").bind(id).fetch_optional(&app.db).await.ok().flatten().unwrap_or(false) }
    };
    match Account::by_email(&app.db, email).await {
        Ok(Some(account)) if account.enabled && domain_enabled(&account).await => Ok(account),
        Ok(_) => Err("there is no mailbox for this identity on this server".into()),
        Err(_) => Err("the account could not be loaded".into()),
    }
}

/// Ties `account_id` to the provider's identity `subject` on its first sign-in, and from then
/// on refuses any other identity. The e-mail address alone is not enough: providers let users
/// change it, so a different person there could otherwise come to claim this mailbox.
/// An administrator's sign-in reset (`DELETE /api/accounts/{id}/two-factor`) removes the tie.
async fn bind_subject(app: &App, account_id: i64, subject: &str) -> Result<(), String> {
    let subject = sanitize_line(subject);
    if subject.is_empty() {
        return Err("the identity provider did not identify the user".into());
    }
    let refused = || "the account could not be loaded".to_owned();
    sqlx::query("INSERT INTO oauth_links (account_id, subject, linked_at) VALUES (?, ?, ?) ON CONFLICT(account_id) DO NOTHING")
        .bind(account_id)
        .bind(&subject)
        .bind(crate::util::now())
        .execute(&app.db)
        .await
        .map_err(|_| refused())?;
    let linked: String = sqlx::query_scalar("SELECT subject FROM oauth_links WHERE account_id = ?").bind(account_id).fetch_one(&app.db).await.map_err(|_| refused())?;
    if linked != subject {
        tracing::warn!(account_id, "single sign-on refused: the identity is not the one this mailbox is linked to");
        return Err("this mailbox is linked to a different identity at the identity provider".into());
    }
    Ok(())
}

/// Completes a web sign-in and returns the local account the identity maps to.
pub async fn finish(app: &App, state: &str, code: &str, ip: IpAddr) -> Result<Account, String> {
    let config = active(app).await.ok_or("single sign-on is not enabled")?;
    // The state is single use: remove it whatever happens next.
    let verifier = match app.oauth.pending.lock().remove(state) {
        Some((verifier, _, started)) if started.elapsed() < STATE_TTL => verifier,
        _ => return Err("the sign-in attempt has expired, please try again".into()),
    };
    let discovery = discover(app, &config).await?;
    let secret = app.secrets.open(&config.client_secret).ok_or("the stored client secret cannot be decrypted")?;
    let redirect = redirect_uri(app);
    let mut form = vec![("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirect.as_str()), ("client_id", config.client_id.as_str()), ("code_verifier", verifier.as_str())];
    if !secret.is_empty() {
        form.push(("client_secret", secret.as_str()));
    }
    let body: String = form.iter().map(|(k, v)| format!("{k}={}", urlencode(v))).collect::<Vec<_>>().join("&");
    let response = app
        .http
        .post(&discovery.token_endpoint)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|_| "the identity provider cannot be reached")?;
    if !response.status().is_success() {
        return Err("the identity provider refused the sign-in".into());
    }
    let token: TokenResponse = response.json().await.map_err(|_| "the identity provider returned an invalid token response")?;
    let (subject, email) = identify(app, &config, &token.access_token).await?;
    let account = local_account(app, &email).await?;
    bind_subject(app, account.id, &subject).await?;
    crate::db::audit(&app.db, &account.email, "login.success", "oauth", &ip.to_string(), "").await;
    Ok(account)
}

fn urlencode(value: &str) -> String {
    value.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// Verifies an access token presented by a mail client (XOAUTH2 / OAUTHBEARER) for `user`.
///
/// Goes through the same lockout, auditing and per-protocol switches as password logins.
pub async fn authenticate_token(app: &App, user: &str, token: &str, ip: IpAddr, protocol: Protocol) -> Result<Account, AuthError> {
    let user = user.trim().to_lowercase();
    if user.len() > 320 || token.is_empty() || token.len() > 8192 {
        return Err(AuthError::Invalid);
    }
    if !app.limiter.attempt(&user, ip) {
        return Err(AuthError::RateLimited);
    }
    let fail = || async {
        // The attempt is already counted; hold back the answer like for a wrong password.
        tokio::time::sleep(app.limiter.tarpit(ip)).await;
        crate::db::audit(&app.db, &sanitize_line(&user), "login.failed", &format!("{}+oauth", protocol.as_str()), &ip.to_string(), "").await;
        Err(AuthError::Invalid)
    };
    let Some(config) = active(app).await else { return fail().await };

    let Some((subject, email)) = token_identity(app, &config, token).await else { return fail().await };
    // A valid token for somebody else must not open this mailbox.
    if email != user {
        return fail().await;
    }
    let Ok(account) = local_account(app, &email).await else { return fail().await };
    if bind_subject(app, account.id, &subject).await.is_err() {
        return fail().await;
    }
    let allowed = protocol.allowed_for(&account);
    if !allowed {
        return fail().await;
    }
    app.limiter.forgive(&user, ip);
    Ok(account)
}

/// The identity (subject, address) an access token stands for, if the identity provider still
/// vouches for it and it was issued to this server. Answers are cached for [`TOKEN_CACHE_TTL`].
async fn token_identity(app: &App, config: &OauthConfig, token: &str) -> Option<Identity> {
    let key = sha256_hex(token.as_bytes());
    let cached = app.oauth.tokens.lock().get(&key).filter(|(_, at)| at.elapsed() < TOKEN_CACHE_TTL).map(|(identity, _)| identity.clone());
    if cached.is_some() {
        return cached;
    }
    let identity = identify(app, config, token).await.ok()?;
    if let Err(reason) = check_audience(app, config, token).await {
        tracing::info!(reason, "token sign-in refused");
        return None;
    }
    let mut tokens = app.oauth.tokens.lock();
    tokens.retain(|_, (_, at)| at.elapsed() < TOKEN_CACHE_TTL);
    if tokens.len() < MAX_PENDING {
        tokens.insert(key, (identity.clone(), Instant::now()));
    }
    Some(identity)
}

/// Whether a connection signed in with `token` may stay open: single sign-on is still on, the
/// provider still accepts the token for `email`, and the mailbox is still linked to that
/// identity. Revoking it there, or turning SSO off here, ends the session within a few minutes.
pub async fn token_still_valid(app: &App, email: &str, token: &str) -> bool {
    let Some(config) = active(app).await else { return false };
    let Some((subject, found)) = token_identity(app, &config, token).await else { return false };
    let linked: Option<String> = sqlx::query_scalar("SELECT l.subject FROM oauth_links l JOIN accounts a ON a.id = l.account_id WHERE a.email = ?").bind(email).fetch_optional(&app.db).await.ok().flatten();
    found == email && linked.is_some_and(|linked| linked == sanitize_line(&subject))
}

/// Extracts (user, token) from a decoded SASL XOAUTH2 or OAUTHBEARER initial response.
pub fn parse_sasl(mechanism: &str, decoded: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(decoded).ok()?;
    let mut fields = text.split('\x01');
    let user = match mechanism {
        // user=<address>^Aauth=Bearer <token>^A^A
        "XOAUTH2" => fields.next()?.strip_prefix("user=")?.to_owned(),
        // n,a=<address>,^Ahost=..^Aport=..^Aauth=Bearer <token>^A^A  (RFC 7628)
        "OAUTHBEARER" => fields.next()?.split(',').find_map(|part| part.strip_prefix("a="))?.to_owned(),
        _ => return None,
    };
    let token = fields.find_map(|field| field.strip_prefix("auth=Bearer ").or_else(|| field.strip_prefix("auth=bearer ")))?.trim().to_owned();
    (!user.is_empty() && !token.is_empty()).then_some((user, token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sasl_responses() {
        assert_eq!(parse_sasl("XOAUTH2", b"user=bob@example.org\x01auth=Bearer tok.en-1\x01\x01"), Some(("bob@example.org".into(), "tok.en-1".into())));
        assert_eq!(
            parse_sasl("OAUTHBEARER", b"n,a=bob@example.org,\x01host=mail.example.org\x01port=993\x01auth=Bearer tok\x01\x01"),
            Some(("bob@example.org".into(), "tok".into()))
        );
        for bad in [&b"user=\x01auth=Bearer tok\x01\x01"[..], b"user=bob@example.org\x01auth=Basic x\x01\x01", b"auth=Bearer tok\x01\x01", b"\xff\xfe", b""] {
            assert_eq!(parse_sasl("XOAUTH2", bad), None);
        }
        assert_eq!(parse_sasl("PLAIN", b"user=bob@example.org\x01auth=Bearer tok\x01\x01"), None);
    }

    #[test]
    fn configuration_is_validated() {
        let config = OauthConfig { enabled: true, name: "Company login".into(), issuer: "https://id.example.org/realm".into(), client_id: "unomail".into(), client_secret: String::new(), scopes: default_scopes(), require_verified_email: true };
        assert!(config.validate(false).is_ok());
        assert!(OauthConfig { issuer: "http://id.example.org".into(), ..config.clone() }.validate(false).is_err());
        assert!(OauthConfig { issuer: "http://127.0.0.1:9000".into(), ..config.clone() }.validate(true).is_ok());
        assert!(OauthConfig { issuer: "javascript:alert(1)".into(), ..config.clone() }.validate(true).is_err());
        assert!(OauthConfig { client_id: " ".into(), ..config.clone() }.validate(false).is_err());
        assert!(OauthConfig { scopes: "email".into(), ..config.clone() }.validate(false).is_err());
        assert!(OauthConfig { name: String::new(), ..config }.validate(false).is_err());
    }

    #[test]
    fn form_values_are_percent_encoded() {
        assert_eq!(urlencode("a b&c=d/é"), "a%20b%26c%3Dd%2F%C3%A9");
    }
}
