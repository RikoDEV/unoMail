//! Automated certificates via ACME (Let's Encrypt): HTTP-01 and DNS-01 (Cloudflare) challenges,
//! background renewal, and hot activation through the [`TlsManager`](crate::tls::TlsManager).

use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    app::{App, AppState},
    db,
    tls::{CertKind, RENEW_BEFORE_SECS},
    util::{normalize_domain, now},
};

const SETTING_CONFIG: &str = "acme.config";
const SETTING_CREDENTIALS: &str = "acme.credentials";
const SETTING_LAST_ERROR: &str = "acme.last_error";
const SETTING_LAST_ATTEMPT: &str = "acme.last_attempt";
const MAX_DOMAINS: usize = 20;
/// Minimum spacing between automatic attempts, to stay well within CA rate limits.
const RETRY_INTERVAL_SECS: i64 = 6 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Challenge {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    pub domains: Vec<String>,
    pub email: String,
    pub challenge: Challenge,
    /// Cloudflare API token with DNS edit permission, required for DNS-01.
    #[serde(default)]
    pub cloudflare_token: Option<String>,
}

impl AcmeConfig {
    /// Validates and normalizes user supplied settings.
    pub fn validated(mut self) -> Result<Self, String> {
        if self.domains.is_empty() || self.domains.len() > MAX_DOMAINS {
            return Err(format!("between 1 and {MAX_DOMAINS} domain names are required"));
        }
        let mut domains = Vec::new();
        for name in &self.domains {
            let wildcard = name.trim().strip_prefix("*.");
            let base = normalize_domain(wildcard.unwrap_or(name)).ok_or_else(|| format!("invalid domain name: {}", crate::util::sanitize_line(name)))?;
            if wildcard.is_some() && self.challenge != Challenge::Dns01 {
                return Err("wildcard certificates require the DNS-01 challenge".into());
            }
            let full = if wildcard.is_some() { format!("*.{base}") } else { base };
            if !domains.contains(&full) {
                domains.push(full);
            }
        }
        self.domains = domains;
        let email = self.email.trim();
        if crate::util::Address::parse(email).is_none() {
            return Err("a valid contact e-mail address is required".into());
        }
        self.email = email.to_owned();
        self.cloudflare_token = self.cloudflare_token.map(|t| t.trim().to_owned()).filter(|t| !t.is_empty());
        if self.challenge == Challenge::Dns01 {
            let token = self.cloudflare_token.as_deref().ok_or("DNS-01 requires a Cloudflare API token")?;
            if token.len() > 200 || !token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
                return Err("the Cloudflare API token contains invalid characters".into());
            }
        } else {
            self.cloudflare_token = None;
        }
        Ok(self)
    }
}

pub async fn load_config(app: &App) -> anyhow::Result<Option<AcmeConfig>> {
    Ok(match db::get_setting(&app.db, SETTING_CONFIG).await? {
        Some(json) => Some(serde_json::from_str(&json)?),
        None => None,
    })
}

pub async fn save_config(app: &App, config: &AcmeConfig) -> anyhow::Result<()> {
    db::set_setting(&app.db, SETTING_CONFIG, &serde_json::to_string(config)?).await?;
    Ok(())
}

pub async fn clear_config(app: &App) -> anyhow::Result<()> {
    db::delete_setting(&app.db, SETTING_CONFIG).await?;
    db::delete_setting(&app.db, SETTING_LAST_ERROR).await?;
    Ok(())
}

pub async fn last_error(app: &App) -> Option<String> {
    db::get_setting(&app.db, SETTING_LAST_ERROR).await.ok().flatten()
}

fn account_builder(app: &App) -> anyhow::Result<instant_acme::AccountBuilder> {
    Ok(match &app.cfg.acme_ca_file {
        Some(path) => Account::builder_with_root(path)?,
        None => Account::builder()?,
    })
}

async fn account(app: &App, config: &AcmeConfig) -> anyhow::Result<Account> {
    // Credentials are bound to the directory they were created with.
    let key = format!("{SETTING_CREDENTIALS}:{}", app.cfg.acme_directory);
    if let Some(stored) = db::get_setting(&app.db, &key).await? {
        let credentials: AccountCredentials = serde_json::from_str(&stored)?;
        return Ok(account_builder(app)?.from_credentials(credentials).await?);
    }
    let contact = format!("mailto:{}", config.email);
    let (account, credentials) = account_builder(app)?
        .create(
            &NewAccount { contact: &[&contact], terms_of_service_agreed: true, only_return_existing: false },
            app.cfg.acme_directory.clone(),
            None,
        )
        .await?;
    db::set_setting(&app.db, &key, &serde_json::to_string(&credentials)?).await?;
    Ok(account)
}

/// Minimal Cloudflare DNS API client for DNS-01 challenges.
struct Cloudflare<'a> {
    app: &'a App,
    token: &'a str,
}

impl Cloudflare<'_> {
    async fn call(&self, method: reqwest::Method, path: &str, body: Option<serde_json::Value>) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}{path}", self.app.cfg.cloudflare_api_url.trim_end_matches('/'));
        let mut request = self.app.http.request(method, url).bearer_auth(self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response: serde_json::Value = request.send().await?.json().await?;
        if response["success"].as_bool() != Some(true) {
            anyhow::bail!("Cloudflare API error: {}", response["errors"]);
        }
        Ok(response["result"].clone())
    }

    /// Finds the zone containing `name` by trying successively shorter suffixes.
    async fn zone_id(&self, name: &str) -> anyhow::Result<String> {
        let labels: Vec<&str> = name.split('.').collect();
        for start in 0..labels.len().saturating_sub(1) {
            let candidate = labels[start..].join(".");
            let result = self.call(reqwest::Method::GET, &format!("/zones?name={candidate}"), None).await?;
            if let Some(id) = result.get(0).and_then(|zone| zone["id"].as_str()) {
                return Ok(id.to_owned());
            }
        }
        anyhow::bail!("no Cloudflare zone found for {name}")
    }

    async fn create_txt(&self, name: &str, value: &str) -> anyhow::Result<(String, String)> {
        let zone = self.zone_id(name).await?;
        let record = self
            .call(
                reqwest::Method::POST,
                &format!("/zones/{zone}/dns_records"),
                Some(json!({ "type": "TXT", "name": name, "content": format!("\"{value}\""), "ttl": 60 })),
            )
            .await?;
        let id = record["id"].as_str().ok_or_else(|| anyhow::anyhow!("Cloudflare did not return a record id"))?;
        Ok((zone, id.to_owned()))
    }

    async fn delete(&self, zone: &str, record: &str) {
        if let Err(err) = self.call(reqwest::Method::DELETE, &format!("/zones/{zone}/dns_records/{record}"), None).await {
            tracing::warn!(error = %err, "failed to remove ACME challenge record");
        }
    }
}

async fn run_order(app: &App, config: &AcmeConfig, tokens: &mut Vec<String>, records: &mut Vec<(String, String)>) -> anyhow::Result<(String, String)> {
    let account = account(app, config).await?;
    let identifiers: Vec<Identifier> = config.domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
    let cloudflare = config.cloudflare_token.as_deref().map(|token| Cloudflare { app, token });

    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            status => anyhow::bail!("unexpected authorization status: {status:?}"),
        }
        match config.challenge {
            Challenge::Http01 => {
                let mut challenge = authz
                    .challenge(ChallengeType::Http01)
                    .ok_or_else(|| anyhow::anyhow!("the CA did not offer an HTTP-01 challenge"))?;
                let token = challenge.token.clone();
                app.tls.http_challenges.lock().insert(token.clone(), challenge.key_authorization().as_str().to_owned());
                tokens.push(token);
                challenge.set_ready().await?;
            }
            Challenge::Dns01 => {
                let cloudflare = cloudflare.as_ref().ok_or_else(|| anyhow::anyhow!("no DNS provider configured"))?;
                let mut challenge = authz
                    .challenge(ChallengeType::Dns01)
                    .ok_or_else(|| anyhow::anyhow!("the CA did not offer a DNS-01 challenge"))?;
                let name = format!("_acme-challenge.{}", challenge.identifier().to_string().trim_start_matches("*."));
                records.push(cloudflare.create_txt(&name, &challenge.key_authorization().dns_value()).await?);
                // Give the record time to reach the provider's authoritative servers.
                tokio::time::sleep(Duration::from_secs(app.cfg.acme_dns_wait_secs)).await;
                challenge.set_ready().await?;
            }
        }
    }

    let status = order.poll_ready(&RetryPolicy::default()).await?;
    if status != OrderStatus::Ready {
        anyhow::bail!("the CA could not validate domain ownership (order status: {status:?})");
    }
    let key_pem = order.finalize().await?;
    let cert_pem = order.poll_certificate(&RetryPolicy::default()).await?;
    Ok((cert_pem, key_pem))
}

/// Requests a certificate for the configured names and activates it.
pub async fn issue(app: &App) -> anyhow::Result<()> {
    let config = load_config(app).await?.ok_or_else(|| anyhow::anyhow!("automatic certificates are not configured"))?;
    db::set_setting(&app.db, SETTING_LAST_ATTEMPT, &now().to_string()).await?;

    let (mut tokens, mut records) = (Vec::new(), Vec::new());
    let result = run_order(app, &config, &mut tokens, &mut records).await;
    // Always clean up challenge material, whatever the outcome.
    {
        let mut challenges = app.tls.http_challenges.lock();
        for token in &tokens {
            challenges.remove(token);
        }
    }
    if let Some(token) = config.cloudflare_token.as_deref() {
        let cloudflare = Cloudflare { app, token };
        for (zone, record) in &records {
            cloudflare.delete(zone, record).await;
        }
    }

    let outcome = match result {
        Ok((cert_pem, key_pem)) => app.tls.install(CertKind::Acme, &cert_pem, &key_pem).await.map(|_| ()).map_err(|e| anyhow::anyhow!(e)),
        Err(err) => Err(err),
    };
    match &outcome {
        Ok(()) => {
            db::delete_setting(&app.db, SETTING_LAST_ERROR).await?;
            db::audit(&app.db, "system", "tls.acme_issued", &config.domains.join(","), "", "").await;
        }
        Err(err) => {
            let message = crate::util::sanitize_line(&format!("{err:#}"));
            db::set_setting(&app.db, SETTING_LAST_ERROR, &message).await?;
            db::audit(&app.db, "system", "tls.acme_failed", &config.domains.join(","), "", &message).await;
        }
    }
    outcome
}

/// True when the active certificate should be (re)issued for `config`.
pub fn needs_issue(kind: CertKind, cert_domains: &[String], seconds_remaining: i64, config: &AcmeConfig) -> bool {
    kind != CertKind::Acme
        || seconds_remaining < RENEW_BEFORE_SECS
        || !config.domains.iter().all(|d| cert_domains.iter().any(|c| c.eq_ignore_ascii_case(d)))
}

/// Background task: issues the first certificate and renews it 30 days before expiry.
pub async fn renewal_loop(app: AppState) {
    // Let the HTTP listener come up before the first HTTP-01 challenge.
    tokio::time::sleep(Duration::from_secs(10)).await;
    loop {
        match load_config(&app).await {
            Ok(Some(config)) => {
                let info = app.tls.info();
                let last_attempt = db::get_setting(&app.db, SETTING_LAST_ATTEMPT).await.ok().flatten().and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
                if needs_issue(info.kind, &info.domains, info.seconds_remaining(), &config) && now() - last_attempt >= RETRY_INTERVAL_SECS {
                    tracing::info!(domains = ?config.domains, "requesting certificate via ACME");
                    if let Err(err) = issue(&app).await {
                        tracing::error!(error = %format!("{err:#}"), "ACME certificate request failed");
                    }
                }
            }
            Ok(None) => {}
            Err(err) => tracing::error!(error = ?err, "failed to load ACME configuration"),
        }
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(domains: &[&str], challenge: Challenge, token: Option<&str>) -> AcmeConfig {
        AcmeConfig {
            domains: domains.iter().map(|s| s.to_string()).collect(),
            email: " admin@example.com ".into(),
            challenge,
            cloudflare_token: token.map(str::to_owned),
        }
    }

    #[test]
    fn validation() {
        let ok = config(&["Mail.Example.com", "mail.example.com", "example.com"], Challenge::Http01, Some("unused")).validated().unwrap();
        assert_eq!(ok.domains, ["mail.example.com", "example.com"]);
        assert_eq!(ok.email, "admin@example.com");
        assert_eq!(ok.cloudflare_token, None, "the token is dropped when it is not needed");

        assert!(config(&[], Challenge::Http01, None).validated().is_err());
        assert!(config(&["not a domain"], Challenge::Http01, None).validated().is_err());
        assert!(config(&["*.example.com"], Challenge::Http01, None).validated().is_err());
        assert!(config(&["*.example.com"], Challenge::Dns01, None).validated().is_err());
        assert!(config(&["*.example.com"], Challenge::Dns01, Some("tok\r\nX-Evil: 1")).validated().is_err());
        let wildcard = config(&["*.example.com"], Challenge::Dns01, Some("abc_DEF-123")).validated().unwrap();
        assert_eq!(wildcard.domains, ["*.example.com"]);
        let mut bad_email = config(&["example.com"], Challenge::Http01, None);
        bad_email.email = "nope".into();
        assert!(bad_email.validated().is_err());
    }

    #[test]
    fn renewal_decision() {
        let cfg = config(&["mail.example.com"], Challenge::Http01, None).validated().unwrap();
        let names = vec!["mail.example.com".to_string()];
        let day = 86400;
        assert!(needs_issue(CertKind::SelfSigned, &names, 300 * day, &cfg), "replace the self-signed fallback");
        assert!(needs_issue(CertKind::Custom, &names, 300 * day, &cfg));
        assert!(!needs_issue(CertKind::Acme, &names, 60 * day, &cfg));
        assert!(needs_issue(CertKind::Acme, &names, 29 * day, &cfg), "renew inside the 30 day window");
        assert!(needs_issue(CertKind::Acme, &["other.example.com".to_string()], 60 * day, &cfg), "name set changed");
    }
}
