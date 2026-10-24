//! Two-step sign-in and app passwords: the second step after the password, and setting up
//! authenticator apps, passkeys, recovery codes and app passwords.

use std::{
    sync::LazyLock,
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ClientIp, JsonResult, Session, auth::AccountView};
use crate::{
    app::AppState,
    auth::{self, Account, AuthError, Protocol},
    error::ApiError,
    expiring::Expiring,
    twofactor::{self, RelyingParty, b64url, unb64url},
    util::{now, random_token, sha256_hex},
};

const PENDING_TTL: Duration = Duration::from_secs(300);
const MAX_SECOND_FACTOR_TRIES: u32 = 5;
const MAX_PASSKEYS: i64 = 20;
const MAX_APP_PASSWORDS: i64 = 50;

/// A sign-in waiting for its second step: account, address, failed tries.
type Pending = (i64, std::net::IpAddr, u32);
/// Sign-ins waiting for their second step, by token hash.
static PENDING: LazyLock<Expiring<Pending>> = LazyLock::new(|| Expiring::new(PENDING_TTL, 50_000));

fn relying_party(state: &AppState) -> Option<RelyingParty> {
    RelyingParty::from_url(&state.cfg.public_url())
}

/// The account's passkeys as credential descriptors (with the transports they reported).
async fn descriptors(state: &AppState, account_id: i64) -> Result<Vec<Value>, ApiError> {
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT credential_id, transports FROM passkeys WHERE account_id = ? ORDER BY id").bind(account_id).fetch_all(&state.db).await?;
    Ok(rows
        .into_iter()
        .map(|(id, transports)| {
            let transports: Vec<String> = serde_json::from_str(&transports).unwrap_or_default();
            if transports.is_empty() { json!({ "type": "public-key", "id": id }) } else { json!({ "type": "public-key", "id": id, "transports": transports }) }
        })
        .collect())
}

/// The WebAuthn user handle of an account: its number, which says nothing about the person.
fn user_handle(account_id: i64) -> Vec<u8> {
    account_id.to_be_bytes().to_vec()
}

/// The options for `navigator.credentials.get` with the account's passkeys.
async fn assertion_options(state: &AppState, account_id: i64, challenge_key: &str) -> Result<Option<Value>, ApiError> {
    let Some(rp) = relying_party(state) else { return Ok(None) };
    let credentials = descriptors(state, account_id).await?;
    if credentials.is_empty() {
        return Ok(None);
    }
    let challenge = state.challenges.issue(challenge_key);
    Ok(Some(json!({
        "challenge": b64url(&challenge),
        "rpId": rp.id,
        "timeout": 120_000,
        // After the password the passkey is the second factor: presence is enough.
        "userVerification": "preferred",
        "allowCredentials": credentials,
    })))
}

/// After the password: when the account has a second factor, the sign-in waits for it.
/// Returns what the client needs to ask for it.
pub async fn begin(state: &AppState, account: &Account, ip: std::net::IpAddr) -> Result<Option<Value>, ApiError> {
    let factors = twofactor::factors(&state.db, account.id).await?;
    if !factors.enabled() {
        return Ok(None);
    }
    let token = random_token();
    let key = sha256_hex(token.as_bytes());
    if !PENDING.insert(key.clone(), (account.id, ip, 0)) {
        return Err(ApiError::RateLimited);
    }
    let passkey = assertion_options(state, account.id, &format!("login:{key}")).await?;
    Ok(Some(json!({
        "token": token,
        "methods": { "totp": factors.totp, "passkey": passkey.is_some(), "recovery": factors.recovery_codes > 0 },
        "passkey": passkey,
    })))
}

#[derive(Deserialize)]
pub struct PasskeyAnswer {
    id: String,
    #[serde(rename = "clientDataJSON")]
    client_data: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    signature: String,
    /// The user handle a discoverable passkey returns (base64url).
    #[serde(rename = "userHandle", default)]
    user_handle: Option<String>,
}

/// Checks a passkey's answer to a challenge; updates its counter and backup state. Returns the
/// account it belongs to. With `account_id` the passkey must be that account's (second factor);
/// without, any account's passkey will do, and the authenticator must have verified the user
/// (the passkey replaces the password).
async fn check_passkey(state: &AppState, account_id: Option<i64>, answer: &PasskeyAnswer, challenge_key: &str) -> Result<Option<i64>, ApiError> {
    let (Some(rp), Some(challenge)) = (relying_party(state), state.challenges.take(challenge_key)) else { return Ok(None) };
    let stored: Option<(i64, i64, Vec<u8>, i64, bool)> = sqlx::query_as("SELECT id, account_id, public_key, sign_count, backup_eligible FROM passkeys WHERE credential_id = ?").bind(&answer.id).fetch_optional(&state.db).await?;
    let Some((id, owner, key, count, backup_eligible)) = stored else { return Ok(None) };
    if account_id.is_some_and(|wanted| wanted != owner) {
        return Ok(None);
    }
    let decode = |text: &str| unb64url(text).ok_or_else(|| ApiError::bad("malformed passkey answer"));
    // A discoverable passkey names its user; it has to be the one the credential was made for.
    if account_id.is_none() {
        match answer.user_handle.as_deref().map(decode).transpose()? {
            Some(handle) if crate::util::ct_eq(&handle, &user_handle(owner)) => {}
            _ => {
                tracing::info!("passkey user handle missing or not the credential's");
                return Ok(None);
            }
        }
    }
    let credential = twofactor::StoredCredential { public_key: &key, sign_count: u32::try_from(count).unwrap_or(0), backup_eligible };
    match twofactor::verify_assertion(&decode(&answer.client_data)?, &decode(&answer.authenticator_data)?, &decode(&answer.signature)?, credential, &challenge, &rp, account_id.is_none()) {
        Ok(assertion) => {
            sqlx::query("UPDATE passkeys SET sign_count = ?, backed_up = ?, last_used_at = ? WHERE id = ?")
                .bind(i64::from(assertion.sign_count))
                .bind(assertion.backed_up)
                .bind(now())
                .bind(id)
                .execute(&state.db)
                .await?;
            Ok(Some(owner))
        }
        Err(reason) => {
            tracing::info!(reason, "passkey not accepted");
            Ok(None)
        }
    }
}

// --- Signing in with a passkey alone -----------------------------------------------------------

/// Passkey sign-ins waiting for their answer: token hash → (address, its network).
static PASSKEY_LOGINS: LazyLock<Expiring<(std::net::IpAddr, String)>> = LazyLock::new(|| Expiring::new(PENDING_TTL, MAX_PASSKEY_LOGINS));
/// Open passkey sign-ins per network (an address, or an IPv6 /64) and in all, so that challenges cannot be hoarded. Every
/// visit to the sign-in page opens one (for the autofill), and an office behind one address
/// has many visitors.
const MAX_PASSKEY_LOGINS_PER_ADDRESS: usize = 500;
const MAX_PASSKEY_LOGINS: usize = 200_000;

/// Options for signing in with a passkey instead of an address and password. No credentials
/// are named: the browser offers the passkeys it holds for this site (in the address field's
/// autofill, or in its own dialog), so nothing reveals which accounts exist.
pub async fn passkey_login_options(State(state): State<AppState>, ClientIp(ip): ClientIp) -> JsonResult<Value> {
    let rp = relying_party(&state).ok_or_else(|| ApiError::bad("passkeys need the web client to be reached by a host name, not an IP address"))?;
    let token = random_token();
    let key = sha256_hex(token.as_bytes());
    let network = crate::auth::network(ip);
    let opened = PASSKEY_LOGINS.insert_limited(key.clone(), (ip, network.clone()), Instant::now() + PENDING_TTL, |(_, from)| *from == network, MAX_PASSKEY_LOGINS_PER_ADDRESS);
    if !opened {
        return Err(ApiError::RateLimited);
    }
    let challenge = state.challenges.issue(&format!("passkey-login:{key}"));
    Ok(Json(json!({
        "token": token,
        "options": {
            "challenge": b64url(&challenge),
            "rpId": rp.id,
            "timeout": PENDING_TTL.as_millis() as u64,
            "userVerification": "required",
            "allowCredentials": [],
        },
    })))
}

#[derive(Deserialize)]
pub struct PasskeyLogin {
    token: String,
    credential: PasskeyAnswer,
}

/// Signs in with a passkey alone. A verified passkey is two factors in one (the device, and
/// the PIN or biometrics that unlock it), so no second step follows.
pub async fn passkey_login(State(state): State<AppState>, ClientIp(ip): ClientIp, headers: HeaderMap, jar: CookieJar, Json(input): Json<PasskeyLogin>) -> Result<(CookieJar, Json<Value>), ApiError> {
    let key = sha256_hex(input.token.as_bytes());
    let started = PASSKEY_LOGINS.take(&key).filter(|(from, _)| *from == ip);
    if started.is_none() {
        return Err(ApiError::bad("the sign-in has expired; try again"));
    }
    let Some(account_id) = check_passkey(&state, None, &input.credential, &format!("passkey-login:{key}")).await? else {
        tokio::time::sleep(state.limiter.tarpit(ip)).await;
        let known: Option<i64> = sqlx::query_scalar("SELECT 1 FROM passkeys WHERE credential_id = ?").bind(&input.credential.id).fetch_optional(&state.db).await?;
        crate::db::audit(&state.db, "", "login.passkey_failed", "web", &ip.to_string(), if known.is_some() { "not verified" } else { "unknown passkey" }).await;
        // An unknown passkey (deleted here, still on the device) is told apart, so the
        // browser can be asked to forget it.
        return Err(if known.is_some() { ApiError::InvalidCredentials } else { ApiError::NotFound });
    };
    let account = Account::by_id(&state.db, account_id).await?.filter(|a| a.enabled).ok_or(ApiError::InvalidCredentials)?;
    if !state.limiter.attempt(&account.email, ip) {
        return Err(ApiError::RateLimited);
    }
    state.limiter.forgive(&account.email, ip);
    let (token, csrf_token) = super::auth::start_session(&state, &account, ip, &headers).await?;
    crate::db::audit(&state.db, &account.email, "login.success", "web", &ip.to_string(), "passkey").await;
    let jar = super::auth::issue_session(&state, jar, token, &account).await?;
    Ok((jar, Json(json!({ "account": AccountView::from(&account), "csrf_token": csrf_token }))))
}

#[derive(Deserialize)]
pub struct SecondFactor {
    token: String,
    code: Option<String>,
    recovery_code: Option<String>,
    passkey: Option<PasskeyAnswer>,
}

/// The second step of a sign-in: an authenticator code, a passkey, or a recovery code.
pub async fn second_factor(State(state): State<AppState>, ClientIp(ip): ClientIp, headers: HeaderMap, jar: CookieJar, Json(input): Json<SecondFactor>) -> Result<(CookieJar, Json<Value>), ApiError> {
    let key = sha256_hex(input.token.as_bytes());
    let expired = || ApiError::bad("the sign-in has expired; enter your password again");
    let Some((account_id, started_from, _)) = PENDING.get(&key) else { return Err(expired()) };
    if started_from != ip {
        return Err(expired());
    }
    // The try is counted before the code is checked, in one step: parallel guesses cannot all
    // see the same count and so get more tries than allowed.
    if PENDING.update(&key, |entry| { entry.2 += 1; entry.2 }).is_none_or(|tries| tries > MAX_SECOND_FACTOR_TRIES) {
        PENDING.remove(&key);
        return Err(expired());
    }
    let account = Account::by_id(&state.db, account_id).await?.filter(|a| a.enabled).ok_or(ApiError::InvalidCredentials)?;
    // The codes are short: guessing them meets the same limiter as passwords, and few tries per sign-in.
    if !state.limiter.attempt(&account.email, ip) {
        return Err(ApiError::RateLimited);
    }
    let ok = if let Some(code) = &input.code {
        twofactor::check_totp(&state.db, &state.secrets, account.id, code).await?
    } else if let Some(code) = &input.recovery_code {
        twofactor::use_recovery_code(&state.db, &state.secrets, account.id, code).await?
    } else if let Some(answer) = &input.passkey {
        check_passkey(&state, Some(account.id), answer, &format!("login:{key}")).await?.is_some()
    } else {
        return Err(ApiError::bad("enter a code or use a passkey"));
    };
    if !ok {
        tokio::time::sleep(state.limiter.tarpit(ip)).await;
        crate::db::audit(&state.db, &account.email, "login.second_factor_failed", "web", &ip.to_string(), "").await;
        // A new passkey challenge for the next try.
        let passkey = if input.passkey.is_some() { assertion_options(&state, account.id, &format!("login:{key}")).await? } else { None };
        return Err(ApiError::Conflict(if passkey.is_some() { "that did not work; try again".into() } else { "the code is not correct".into() }));
    }
    PENDING.remove(&key);
    state.limiter.forgive(&account.email, ip);
    let (token, csrf_token) = super::auth::start_session(&state, &account, ip, &headers).await?;
    let how = if input.code.is_some() { "totp" } else if input.recovery_code.is_some() { "recovery code" } else { "passkey" };
    crate::db::audit(&state.db, &account.email, "login.success", "web", &ip.to_string(), how).await;
    let jar = super::auth::issue_session(&state, jar, token, &account).await?;
    Ok((jar, Json(json!({ "account": AccountView::from(&account), "csrf_token": csrf_token }))))
}

/// A fresh passkey challenge for a waiting sign-in (after a cancelled browser prompt).
#[derive(Deserialize)]
pub struct TokenOnly {
    token: String,
}

pub async fn passkey_retry(State(state): State<AppState>, Json(input): Json<TokenOnly>) -> JsonResult<Value> {
    let key = sha256_hex(input.token.as_bytes());
    let Some((account_id, ..)) = PENDING.get(&key) else { return Err(ApiError::bad("the sign-in has expired; enter your password again")) };
    Ok(Json(json!({ "passkey": assertion_options(&state, account_id, &format!("login:{key}")).await? })))
}

// --- Setting the factors up -------------------------------------------------------------------

/// Changes that weaken an account need the password again, so that a borrowed session is not enough.
async fn confirm_password(state: &AppState, session: &Session, password: &str) -> Result<(), ApiError> {
    match auth::authenticate(&state.db, &state.limiter, &session.account.email, password, session.ip, Protocol::Web).await {
        Ok(_) => Ok(()),
        Err(AuthError::RateLimited) => Err(ApiError::RateLimited),
        Err(_) => Err(ApiError::InvalidCredentials),
    }
}

/// When the last factor goes, the recovery codes go with it.
async fn tidy(state: &AppState, account_id: i64) -> Result<(), ApiError> {
    if !twofactor::factors(&state.db, account_id).await?.enabled() {
        sqlx::query("DELETE FROM recovery_codes WHERE account_id = ?").bind(account_id).execute(&state.db).await?;
    }
    Ok(())
}

/// Recovery codes for an account that just got its first factor.
async fn first_codes(state: &AppState, account_id: i64) -> Result<Option<Vec<String>>, ApiError> {
    Ok(if twofactor::recovery_codes_left(&state.db, account_id).await? == 0 { Some(twofactor::new_recovery_codes(&state.db, &state.secrets, account_id).await?) } else { None })
}

/// id, name, created, last used, backup eligible, backed up, discoverable.
type PasskeyRow = (i64, String, i64, Option<i64>, bool, bool, Option<bool>);

pub async fn overview(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let factors = twofactor::factors(&state.db, session.account.id).await?;
    let passkeys: Vec<PasskeyRow> =
        sqlx::query_as("SELECT id, name, created_at, last_used_at, backup_eligible, backed_up, discoverable FROM passkeys WHERE account_id = ? ORDER BY id").bind(session.account.id).fetch_all(&state.db).await?;
    Ok(Json(json!({
        "enabled": factors.enabled(),
        "totp": factors.totp,
        "recovery_codes_left": factors.recovery_codes,
        "passkeys_supported": relying_party(&state).is_some(),
        "passkeys": passkeys
            .into_iter()
            .map(|(id, name, created, used, eligible, backed_up, discoverable)| {
                json!({ "id": id, "name": name, "created_at": created, "last_used_at": used, "synced": eligible && backed_up, "backup_eligible": eligible, "discoverable": discoverable })
            })
            .collect::<Vec<_>>(),
    })))
}

/// A new authenticator secret, not active until a code from it is entered.
///
/// An authenticator in use is never replaced here: that would switch the second factor off
/// without the password that [`totp_disable`] asks for.
pub async fn totp_setup(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let secret = twofactor::new_totp_secret();
    let stored = sqlx::query(
        "INSERT INTO totp_secrets (account_id, secret, enabled, created_at) VALUES (?, ?, 0, ?)
         ON CONFLICT(account_id) DO UPDATE SET secret = excluded.secret, enabled = 0, last_step = 0, created_at = excluded.created_at
         WHERE totp_secrets.enabled = 0",
    )
    .bind(session.account.id)
    .bind(state.secrets.seal(&secret))
    .bind(now())
    .execute(&state.db)
    .await?;
    if stored.rows_affected() == 0 {
        return Err(ApiError::Conflict("an authenticator app is already set up; turn it off first".into()));
    }
    let issuer = session.account.email.rsplit_once('@').map_or("unoMail", |(_, domain)| domain).to_owned();
    Ok(Json(json!({ "secret": secret, "uri": twofactor::otpauth_uri(&issuer, &session.account.email, &secret) })))
}

#[derive(Deserialize)]
pub struct EnableInput {
    code: String,
    password: String,
}

/// Turns a new authenticator on. This changes how the account signs in, so a borrowed session
/// is not enough: someone who could enrol their own phone could then lock the owner out.
pub async fn totp_enable(State(state): State<AppState>, session: Session, Json(input): Json<EnableInput>) -> JsonResult<Value> {
    confirm_password(&state, &session, &input.password).await?;
    let sealed: Option<String> = sqlx::query_scalar("SELECT secret FROM totp_secrets WHERE account_id = ?").bind(session.account.id).fetch_optional(&state.db).await?;
    let secret = sealed.and_then(|sealed| state.secrets.open(&sealed)).and_then(|text| twofactor::unbase32(&text)).ok_or_else(|| ApiError::bad("set up the authenticator first"))?;
    let step = twofactor::matching_step(&secret, &input.code, now()).ok_or_else(|| ApiError::bad("the code is not correct; check the time on the phone"))?;
    sqlx::query("UPDATE totp_secrets SET enabled = 1, last_step = ? WHERE account_id = ?").bind(step).bind(session.account.id).execute(&state.db).await?;
    session.audit(&state, "twofactor.totp_enabled", "", "").await;
    Ok(Json(json!({ "ok": true, "recovery_codes": first_codes(&state, session.account.id).await? })))
}

#[derive(Deserialize)]
pub struct PasswordInput {
    password: String,
}

pub async fn totp_disable(State(state): State<AppState>, session: Session, Json(input): Json<PasswordInput>) -> JsonResult<Value> {
    confirm_password(&state, &session, &input.password).await?;
    sqlx::query("DELETE FROM totp_secrets WHERE account_id = ?").bind(session.account.id).execute(&state.db).await?;
    tidy(&state, session.account.id).await?;
    session.audit(&state, "twofactor.totp_disabled", "", "").await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn recovery_codes(State(state): State<AppState>, session: Session, Json(input): Json<PasswordInput>) -> JsonResult<Value> {
    confirm_password(&state, &session, &input.password).await?;
    if !twofactor::factors(&state.db, session.account.id).await?.enabled() {
        return Err(ApiError::bad("set up two-step sign-in first"));
    }
    let codes = twofactor::new_recovery_codes(&state.db, &state.secrets, session.account.id).await?;
    session.audit(&state, "twofactor.recovery_codes_renewed", "", "").await;
    Ok(Json(json!({ "recovery_codes": codes })))
}

/// The options for `navigator.credentials.create`. A passkey signs in on its own, so adding
/// one needs the password, like the other changes that open the account to a new credential;
/// the challenge handed out here is what [`passkey_finish`] requires.
pub async fn passkey_start(State(state): State<AppState>, session: Session, Json(input): Json<PasswordInput>) -> JsonResult<Value> {
    confirm_password(&state, &session, &input.password).await?;
    let rp = relying_party(&state).ok_or_else(|| ApiError::bad("passkeys need the web client to be reached by a host name, not an IP address"))?;
    let existing = descriptors(&state, session.account.id).await?;
    if existing.len() as i64 >= MAX_PASSKEYS {
        return Err(ApiError::bad(format!("at most {MAX_PASSKEYS} passkeys")));
    }
    let challenge = state.challenges.issue(&format!("register:{}", session.account.id));
    Ok(Json(json!({
        "challenge": b64url(&challenge),
        "rp": { "id": rp.id, "name": "unoMail" },
        "user": { "id": b64url(&user_handle(session.account.id)), "name": session.account.email, "displayName": if session.account.display_name.is_empty() { &session.account.email } else { &session.account.display_name } },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }, { "type": "public-key", "alg": -8 }, { "type": "public-key", "alg": -257 }],
        "timeout": 120_000,
        "attestation": "none",
        // A passkey proper: stored on the authenticator (so it signs in without an address)
        // and unlocked by the user's PIN or biometrics (so it replaces the password).
        "authenticatorSelection": { "residentKey": "required", "requireResidentKey": true, "userVerification": "required" },
        "extensions": { "credProps": true },
        "excludeCredentials": existing,
    })))
}

#[derive(Deserialize)]
pub struct PasskeyRegistration {
    name: String,
    #[serde(rename = "clientDataJSON")]
    client_data: String,
    #[serde(rename = "attestationObject")]
    attestation_object: String,
    /// What `getTransports()` reported.
    #[serde(default)]
    transports: Vec<String>,
    /// The `credProps` extension: whether the passkey is discoverable.
    #[serde(default)]
    discoverable: Option<bool>,
}

const TRANSPORTS: [&str; 6] = ["usb", "nfc", "ble", "smart-card", "hybrid", "internal"];

pub async fn passkey_finish(State(state): State<AppState>, session: Session, Json(input): Json<PasskeyRegistration>) -> JsonResult<Value> {
    let rp = relying_party(&state).ok_or_else(|| ApiError::bad("passkeys are not available here"))?;
    let challenge = state.challenges.take(&format!("register:{}", session.account.id)).ok_or_else(|| ApiError::bad("the request has expired; try again"))?;
    let decode = |text: &str| unb64url(text).ok_or_else(|| ApiError::bad("malformed passkey response"));
    let credential = twofactor::verify_registration(&decode(&input.client_data)?, &decode(&input.attestation_object)?, &challenge, &rp).map_err(ApiError::bad)?;
    let name: String = input.name.trim().chars().filter(|c| !c.is_control()).take(100).collect();
    let name = if name.is_empty() { "Passkey".to_owned() } else { name };
    let transports: Vec<&str> = TRANSPORTS.iter().copied().filter(|known| input.transports.iter().any(|t| t == known)).collect();
    sqlx::query(
        "INSERT INTO passkeys (account_id, credential_id, public_key, sign_count, name, created_at, backup_eligible, backed_up, discoverable, transports, aaguid)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
        .bind(session.account.id)
        .bind(b64url(&credential.id))
        .bind(&credential.public_key)
        .bind(i64::from(credential.sign_count))
        .bind(&name)
        .bind(now())
        .bind(credential.backup_eligible)
        .bind(credential.backed_up)
        .bind(input.discoverable)
        .bind(serde_json::to_string(&transports).unwrap_or_else(|_| "[]".into()))
        .bind(credential.aaguid.iter().map(|b| format!("{b:02x}")).collect::<String>())
        .execute(&state.db)
        .await
        .map_err(|_| ApiError::Conflict("this passkey is registered already".into()))?;
    session.audit(&state, "twofactor.passkey_added", &name, "").await;
    Ok(Json(json!({ "ok": true, "recovery_codes": first_codes(&state, session.account.id).await? })))
}

pub async fn passkey_delete(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<PasswordInput>) -> JsonResult<Value> {
    confirm_password(&state, &session, &input.password).await?;
    let removed = sqlx::query("DELETE FROM passkeys WHERE id = ? AND account_id = ?").bind(id).bind(session.account.id).execute(&state.db).await?;
    if removed.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    tidy(&state, session.account.id).await?;
    session.audit(&state, "twofactor.passkey_removed", "", "").await;
    Ok(Json(json!({ "ok": true, "signal": accepted_credentials(&state, session.account.id).await? })))
}

/// What the browser's Signal API needs to drop passkeys this server no longer accepts.
async fn accepted_credentials(state: &AppState, account_id: i64) -> Result<Value, ApiError> {
    let Some(rp) = relying_party(state) else { return Ok(Value::Null) };
    let ids: Vec<String> = sqlx::query_scalar("SELECT credential_id FROM passkeys WHERE account_id = ? ORDER BY id").bind(account_id).fetch_all(&state.db).await?;
    Ok(json!({ "rpId": rp.id, "userId": b64url(&user_handle(account_id)), "allAcceptedCredentialIds": ids }))
}

#[derive(Deserialize)]
pub struct PasskeyName {
    name: String,
}

/// Renames a passkey (to tell them apart in the list).
pub async fn passkey_rename(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<PasskeyName>) -> JsonResult<Value> {
    let name: String = input.name.trim().chars().filter(|c| !c.is_control()).take(100).collect();
    if name.is_empty() {
        return Err(ApiError::bad("give the passkey a name"));
    }
    let renamed = sqlx::query("UPDATE passkeys SET name = ? WHERE id = ? AND account_id = ?").bind(&name).bind(id).bind(session.account.id).execute(&state.db).await?;
    if renamed.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    session.audit(&state, "twofactor.passkey_renamed", &name, "").await;
    Ok(Json(json!({ "ok": true, "name": name })))
}

// --- App passwords ----------------------------------------------------------------------------

pub async fn app_passwords(State(state): State<AppState>, session: Session) -> JsonResult<Vec<Value>> {
    let rows: Vec<(i64, String, String, i64, Option<i64>, String)> = sqlx::query_as("SELECT id, name, scopes, created_at, last_used_at, last_ip FROM app_passwords WHERE account_id = ? ORDER BY id").bind(session.account.id).fetch_all(&state.db).await?;
    Ok(Json(rows.into_iter().map(|(id, name, scopes, created, used, ip)| json!({ "id": id, "name": name, "scopes": scopes.split(',').collect::<Vec<_>>(), "created_at": created, "last_used_at": used, "last_ip": ip })).collect()))
}

#[derive(Deserialize)]
pub struct NewAppPassword {
    name: String,
    scopes: Vec<String>,
    password: String,
}

/// Creates an app password and returns it, the only time it is shown.
pub async fn app_password_create(State(state): State<AppState>, session: Session, Json(input): Json<NewAppPassword>) -> JsonResult<Value> {
    confirm_password(&state, &session, &input.password).await?;
    let name: String = input.name.trim().chars().filter(|c| !c.is_control()).take(100).collect();
    if name.is_empty() {
        return Err(ApiError::bad("name the program the password is for"));
    }
    let mut scopes: Vec<&str> = twofactor::SCOPES.iter().copied().filter(|scope| input.scopes.iter().any(|s| s == scope)).collect();
    scopes.dedup();
    if scopes.is_empty() {
        return Err(ApiError::bad("choose what the password may be used for"));
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app_passwords WHERE account_id = ?").bind(session.account.id).fetch_one(&state.db).await?;
    if count >= MAX_APP_PASSWORDS {
        return Err(ApiError::bad(format!("at most {MAX_APP_PASSWORDS} app passwords")));
    }
    let password = twofactor::new_app_password();
    let normalized = twofactor::normalize_app_password(&password).expect("generated in the accepted form");
    let id = sqlx::query("INSERT INTO app_passwords (account_id, name, hash, scopes, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(session.account.id)
        .bind(&name)
        .bind(twofactor::app_password_hash(&normalized))
        .bind(scopes.join(","))
        .bind(now())
        .execute(&state.db)
        .await?
        .last_insert_rowid();
    session.audit(&state, "app_password.created", &name, &scopes.join(",")).await;
    Ok(Json(json!({ "id": id, "name": name, "password": password, "scopes": scopes })))
}

pub async fn app_password_delete(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    let name: Option<String> = sqlx::query_scalar("DELETE FROM app_passwords WHERE id = ? AND account_id = ? RETURNING name").bind(id).bind(session.account.id).fetch_optional(&state.db).await?;
    let name = name.ok_or(ApiError::NotFound)?;
    crate::jmap::submission::cancel_from_app_password(&state.db, session.account.id, id).await?;
    session.audit(&state, "app_password.revoked", &name, "").await;
    Ok(Json(json!({ "ok": true })))
}

/// An administrator resets the second factors of a mailbox whose owner lost them. App passwords
/// go too (one may live on the lost device), and so do the sessions they protected. So does the
/// link to a single sign-on identity: the next identity to sign in with the address is linked.
pub async fn admin_reset(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    session.require_admin()?;
    let account = super::accounts::load_managed(&state, &session, id).await?;
    let mut tx = state.db.begin().await?;
    for table in ["totp_secrets", "passkeys", "recovery_codes", "app_passwords", "sessions", "oauth_links"] {
        sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM {table} WHERE account_id = ?"))).bind(account.id).execute(&mut *tx).await?;
    }
    crate::jmap::submission::cancel_pending(&mut *tx, account.id).await?;
    tx.commit().await?;
    session.audit(&state, "twofactor.reset", &account.email, "").await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn admin_status(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    session.require_admin()?;
    let account = super::accounts::load_managed(&state, &session, id).await?;
    let factors = twofactor::factors(&state.db, account.id).await?;
    let apps: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app_passwords WHERE account_id = ?").bind(account.id).fetch_one(&state.db).await?;
    let sso_linked: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM oauth_links WHERE account_id = ?)").bind(account.id).fetch_one(&state.db).await?;
    Ok(Json(json!({ "enabled": factors.enabled(), "totp": factors.totp, "passkeys": factors.passkeys, "app_passwords": apps, "sso_linked": sso_linked })))
}
