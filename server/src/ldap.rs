//! LDAP directory connector for the address book: recipient suggestions are looked up in a
//! company directory configured by the administrator.

use std::time::Duration;

use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry, SearchOptions, ldap_escape};
use serde::{Deserialize, Serialize};

use crate::app::App;

const SETTING_KEY: &str = "ldap.config";
const TIMEOUT: Duration = Duration::from_secs(4);
const MAX_RESULTS: i32 = 10;
pub const DEFAULT_FILTER: &str = "(&(mail=*)(|(cn=*{q}*)(mail=*{q}*)))";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LdapConfig {
    pub enabled: bool,
    /// `ldaps://host[:port]` or `ldap://host[:port]`.
    pub url: String,
    /// Upgrade an `ldap://` connection with StartTLS.
    #[serde(default)]
    pub starttls: bool,
    #[serde(default)]
    pub bind_dn: String,
    /// Sealed with the server key.
    #[serde(default)]
    pub bind_password: String,
    pub base_dn: String,
    /// Search filter; `{q}` is replaced by the escaped search text.
    #[serde(default = "default_filter")]
    pub filter: String,
    #[serde(default = "default_name_attribute")]
    pub name_attribute: String,
    #[serde(default = "default_mail_attribute")]
    pub mail_attribute: String,
}

fn default_filter() -> String {
    DEFAULT_FILTER.into()
}

fn default_name_attribute() -> String {
    "cn".into()
}

fn default_mail_attribute() -> String {
    "mail".into()
}

fn valid_attribute(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

impl LdapConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(self.url.starts_with("ldaps://") || self.url.starts_with("ldap://")) || self.url.len() > 300 || self.url.chars().any(char::is_whitespace) {
            return Err("the URL must start with ldaps:// or ldap://".into());
        }
        if self.base_dn.trim().is_empty() || self.base_dn.len() > 500 {
            return Err("a base DN is required".into());
        }
        if !self.filter.contains("{q}") || self.filter.len() > 500 || !self.filter.starts_with('(') {
            return Err("the filter must be an LDAP filter containing {q}".into());
        }
        if !valid_attribute(&self.name_attribute) || !valid_attribute(&self.mail_attribute) {
            return Err("invalid attribute name".into());
        }
        Ok(())
    }

    /// The filter for a search text, with the text escaped so it cannot alter the filter.
    pub fn filter_for(&self, query: &str) -> String {
        self.filter.replace("{q}", &ldap_escape(query))
    }
}

pub async fn load(app: &App) -> sqlx::Result<Option<LdapConfig>> {
    Ok(crate::db::get_setting(&app.db, SETTING_KEY).await?.and_then(|json| serde_json::from_str(&json).ok()))
}

pub async fn save(app: &App, config: &LdapConfig) -> sqlx::Result<()> {
    crate::db::set_setting(&app.db, SETTING_KEY, &serde_json::to_string(config).unwrap_or_default()).await
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    pub name: String,
    pub email: String,
}

/// Runs a directory search with an explicit configuration (also used by the "test" button).
pub async fn search_with(app: &App, config: &LdapConfig, query: &str) -> Result<Vec<Entry>, String> {
    let password = app.secrets.open(&config.bind_password).ok_or("the stored bind password cannot be decrypted")?;
    let settings = LdapConnSettings::new()
        .set_conn_timeout(TIMEOUT)
        .set_starttls(config.starttls)
        // Directory certificates are verified against the public roots, like any other TLS client.
        .set_config(crate::smtp::client::tls_config(true));
    let work = async {
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &config.url).await.map_err(|e| format!("cannot connect: {e}"))?;
        ldap3::drive!(conn);
        if !config.bind_dn.is_empty() {
            ldap.simple_bind(&config.bind_dn, &password).await.and_then(|r| r.success()).map_err(|e| format!("bind failed: {e}"))?;
        }
        let attributes = vec![config.name_attribute.as_str(), config.mail_attribute.as_str()];
        let (entries, _) = ldap
            .with_search_options(SearchOptions::new().sizelimit(MAX_RESULTS))
            .search(&config.base_dn, Scope::Subtree, &config.filter_for(query), attributes)
            .await
            // A size-limit result still carries the first entries; it is not an error for us.
            .map(|r| (r.0, r.1))
            .map_err(|e| format!("search failed: {e}"))?;
        let _ = ldap.unbind().await;
        let mut out = Vec::new();
        for entry in entries.into_iter().take(MAX_RESULTS as usize) {
            let entry = SearchEntry::construct(entry);
            let first = |attribute: &str| {
                entry.attrs.iter().find(|(name, _)| name.eq_ignore_ascii_case(attribute)).and_then(|(_, values)| values.first()).map(|v| crate::util::sanitize_line(v))
            };
            // Directory content is untrusted: only well-formed addresses are passed on.
            if let Some(email) = first(&config.mail_attribute).and_then(|m| crate::util::Address::parse(&m)) {
                out.push(Entry { name: first(&config.name_attribute).unwrap_or_default(), email: email.to_string() });
            }
        }
        Ok::<_, String>(out)
    };
    tokio::time::timeout(TIMEOUT * 2, work).await.map_err(|_| "the directory did not answer in time".to_owned())?
}

/// Recipient suggestions from the configured directory; empty when none is configured.
pub async fn search(app: &App, query: &str) -> Result<Vec<Entry>, String> {
    match load(app).await.map_err(|e| e.to_string())? {
        Some(config) if config.enabled => search_with(app, &config, query).await.inspect_err(|err| tracing::warn!(err, "LDAP lookup failed")),
        _ => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> LdapConfig {
        LdapConfig {
            enabled: true,
            url: "ldaps://ldap.example.org".into(),
            starttls: false,
            bind_dn: String::new(),
            bind_password: String::new(),
            base_dn: "dc=example,dc=org".into(),
            filter: DEFAULT_FILTER.into(),
            name_attribute: "cn".into(),
            mail_attribute: "mail".into(),
        }
    }

    #[test]
    fn search_text_cannot_change_the_filter() {
        let filter = config().filter_for("a)(uid=*))(|(uid=*");
        assert_eq!(filter, "(&(mail=*)(|(cn=*a\\29\\28uid=\\2a\\29\\29\\28|\\28uid=\\2a*)(mail=*a\\29\\28uid=\\2a\\29\\29\\28|\\28uid=\\2a*)))");
    }

    #[test]
    fn validation() {
        assert!(config().validate().is_ok());
        for bad in [
            LdapConfig { url: "http://ldap.example.org".into(), ..config() },
            LdapConfig { url: "ldaps://host name".into(), ..config() },
            LdapConfig { base_dn: " ".into(), ..config() },
            LdapConfig { filter: "(cn=*)".into(), ..config() },
            LdapConfig { filter: "cn={q}".into(), ..config() },
            LdapConfig { mail_attribute: "mail)(x".into(), ..config() },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }
}
