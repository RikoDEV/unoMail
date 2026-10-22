//! Server settings that administrators can change at runtime from the admin panel.
//!
//! Defaults come from the environment (`Config`); overrides are stored in the database and
//! applied without a restart.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::SqlitePool;

use crate::{config::Config, util::normalize_domain};

const SETTING_KEY: &str = "config.runtime";

fn forward_max_copies_per_hour() -> i64 {
    1000
}

fn queue_max_entries() -> i64 {
    50_000
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Runtime {
    pub greylist_enabled: bool,
    pub greylist_delay_secs: i64,
    pub max_message_size: usize,
    pub max_recipients: usize,
    pub dnsbl_zones: Vec<String>,
    pub abuseipdb_threshold: u8,
    /// Refuse inbound mail on port 25 from servers that do not use STARTTLS.
    pub smtp_require_tls: bool,
    pub outbound_require_tls: bool,
    /// Check certificates against DNSSEC-signed TLSA records when receivers publish them.
    #[serde(default = "yes")]
    pub dane_enabled: bool,
    /// Honour the MTA-STS policies of receiving domains.
    #[serde(default = "yes")]
    pub mta_sts_enabled: bool,
    /// Send daily SMTP TLS reports to the domains asking for them.
    #[serde(default = "yes")]
    pub tls_reports_enabled: bool,
    /// Send daily DMARC aggregate reports to the domains asking for them.
    #[serde(default = "yes")]
    pub dmarc_reports_enabled: bool,
    /// Days a message stays in Trash before it is deleted for good (0: forever).
    #[serde(default = "thirty")]
    pub trash_retention_days: i64,
    /// Days a message stays in Junk before it is deleted for good (0: forever).
    #[serde(default = "thirty")]
    pub junk_retention_days: i64,
    /// Refuse messages carrying programs (.exe, .js, .scr, ...), also inside ZIP archives.
    #[serde(default = "yes")]
    pub block_executable_attachments: bool,
    /// Learn each user's spam reports and file mail their filter is sure about into Junk.
    #[serde(default = "yes")]
    pub personal_spam_filter: bool,
    pub rspamd_fail_open: bool,
    pub outbound_max_messages_per_hour: i64,
    pub outbound_max_recipients_per_hour: i64,
    /// Copies one alias or mailing list may send on to other servers per hour.
    #[serde(default = "forward_max_copies_per_hour")]
    pub forward_max_copies_per_hour: i64,
    /// Waiting outbound messages beyond which forwarded and list mail is deferred.
    #[serde(default = "queue_max_entries")]
    pub queue_max_entries: i64,

    // Spam and reputation.
    /// Scan mail from other servers with the content filter.
    #[serde(default = "yes")]
    pub spam_check_inbound: bool,
    /// Scan mail sent by users with the content filter.
    #[serde(default = "yes")]
    pub spam_check_outbound: bool,
    /// Prepend `spam_subject_prefix` to the subject of incoming mail scoring at least
    /// `spam_subject_score`.
    #[serde(default)]
    pub spam_subject_enabled: bool,
    #[serde(default = "spam_subject_score")]
    pub spam_subject_score: f64,
    #[serde(default = "spam_subject_prefix")]
    pub spam_subject_prefix: String,
    /// File mail into Junk when it comes over a connection that misbehaved (protocol errors,
    /// unknown recipients) or from an address with a bad record.
    #[serde(default)]
    pub quarantine_misbehaving: bool,
    /// Run the server's own tests (links, reputation, origin) on incoming mail.
    #[serde(default = "yes")]
    pub native_filter: bool,
    /// Score of those tests at which mail goes to Junk.
    #[serde(default = "native_filter_score")]
    pub native_filter_score: f64,
    /// Learn and use the reputation of sending networks, autonomous systems and domains.
    #[serde(default = "yes")]
    pub sender_reputation: bool,
    /// Addresses nobody uses: mail to them teaches the filter and is not delivered.
    #[serde(default)]
    pub spam_traps: Vec<String>,
    /// Autonomous systems (numbers) and countries (ISO codes) whose mail scores `origin_score`.
    #[serde(default)]
    pub penalized_asns: Vec<String>,
    #[serde(default)]
    pub penalized_countries: Vec<String>,
    #[serde(default = "origin_score")]
    pub origin_score: f64,

    // Antivirus.
    #[serde(default = "yes")]
    pub antivirus_inbound: bool,
    #[serde(default = "yes")]
    pub antivirus_outbound: bool,
    /// Deliver infected incoming mail to Junk, marked, instead of refusing it.
    #[serde(default)]
    pub virus_quarantine: bool,

    // Default SMTP route.
    /// Hand all outgoing mail to `default_route` instead of the recipients' servers.
    #[serde(default)]
    pub default_route_enabled: bool,
    /// `host:port` of that server.
    #[serde(default)]
    pub default_route: String,
    /// Sign in to it with the user name and password below.
    #[serde(default)]
    pub default_route_auth: bool,
    /// Credentials for the default route. The password is stored sealed.
    #[serde(default)]
    pub default_route_username: String,
    #[serde(default)]
    pub default_route_password: String,
    /// The From header of submitted mail must be an address of the sender.
    #[serde(default = "yes")]
    pub strict_from_check: bool,
    /// Mail filters (Sieve) may redirect mail to addresses outside this server.
    #[serde(default = "yes")]
    pub sieve_external_redirect: bool,

    // Privacy of submitted mail.
    #[serde(default)]
    pub privacy_remove_x_headers: bool,
    #[serde(default)]
    pub privacy_remove_user_agent: bool,
    /// Record the sending client as localhost in the last `Received:` header instead of its
    /// address.
    #[serde(default = "yes")]
    pub privacy_hide_client_ip: bool,

    // Storage.
    /// Days the delivery and audit logs are kept.
    #[serde(default = "ninety")]
    pub log_retention_days: i64,
    /// Days the dashboard's daily statistics are kept.
    #[serde(default = "four_hundred")]
    pub stats_retention_days: i64,

    // Login limits.
    /// Minutes over which failed logins are counted.
    #[serde(default = "login_window_mins")]
    pub login_window_mins: i64,
    #[serde(default = "login_max_failures_per_account_and_ip")]
    pub login_max_failures_per_account_and_ip: u32,
    #[serde(default = "login_max_failures_per_ip")]
    pub login_max_failures_per_ip: u32,
    #[serde(default = "login_max_failures_per_account")]
    pub login_max_failures_per_account: u32,
    /// Hours a repeat offender can be locked out at most.
    #[serde(default = "login_max_lock_hours")]
    pub login_max_lock_hours: i64,
    /// Failures from a network after which each further one is answered slowly.
    #[serde(default = "login_tarpit_after")]
    pub login_tarpit_after: u32,
    /// Failures from a network after which it is reported for guessing passwords.
    #[serde(default = "login_report_after")]
    pub login_report_after: u32,

    // Captcha on the web sign-in page.
    /// `""` (off), `hcaptcha`, `turnstile`, `recaptcha` or `altcha`.
    #[serde(default)]
    pub captcha_provider: String,
    /// The public key the widget is shown with (not used by ALTCHA).
    #[serde(default)]
    pub captcha_site_key: String,
    /// The provider's secret for checking answers, stored sealed (not used by ALTCHA).
    #[serde(default)]
    pub captcha_secret_key: String,
}

fn login_window_mins() -> i64 {
    crate::auth::WINDOW_SECS / 60
}

fn login_max_failures_per_account_and_ip() -> u32 {
    crate::auth::MAX_FAILURES_PER_ACCOUNT_AND_IP
}

fn login_max_failures_per_ip() -> u32 {
    crate::auth::MAX_FAILURES_PER_IP
}

fn login_max_failures_per_account() -> u32 {
    crate::auth::MAX_FAILURES_PER_ACCOUNT
}

fn login_max_lock_hours() -> i64 {
    crate::auth::MAX_LOCK_SECS / 3600
}

fn login_tarpit_after() -> u32 {
    crate::auth::TARPIT_AFTER
}

fn login_report_after() -> u32 {
    crate::auth::REPORT_AFTER
}

fn ninety() -> i64 {
    90
}

fn four_hundred() -> i64 {
    400
}

fn spam_subject_score() -> f64 {
    6.0
}

fn native_filter_score() -> f64 {
    5.0
}

fn origin_score() -> f64 {
    2.0
}

fn spam_subject_prefix() -> String {
    "[SPAM]".into()
}

/// A secret the settings API never shows: it is replaced by this marker when listed.
pub const SECRET_KEYS: [&str; 2] = ["default_route_password", "captcha_secret_key"];

fn yes() -> bool {
    true
}

fn thirty() -> i64 {
    30
}

impl Runtime {
    /// The settings before any override: the environment's values where it has them, the
    /// serde defaults above for everything else.
    pub fn from_config(cfg: &Config) -> Self {
        serde_json::from_value(json!({
            "greylist_enabled": cfg.greylist_enabled,
            "greylist_delay_secs": cfg.greylist_delay_secs,
            "max_message_size": cfg.max_message_size,
            "max_recipients": cfg.max_recipients,
            "dnsbl_zones": cfg.dnsbl_zones,
            "abuseipdb_threshold": cfg.abuseipdb_threshold,
            "smtp_require_tls": cfg.smtp_require_tls,
            "outbound_require_tls": cfg.outbound_require_tls,
            "rspamd_fail_open": cfg.rspamd_fail_open,
            "outbound_max_messages_per_hour": cfg.outbound_max_messages_per_hour,
            "outbound_max_recipients_per_hour": cfg.outbound_max_recipients_per_hour,
            "virus_quarantine": cfg.virus_quarantine,
            "default_route_enabled": cfg.outbound_relay.is_some(),
            "default_route": cfg.outbound_relay.clone().unwrap_or_default(),
        }))
        .expect("every setting the environment does not give has a default")
    }

    /// The server all outgoing mail goes to, when the default route is on and complete.
    pub fn route(&self) -> Option<&str> {
        (self.default_route_enabled && !self.default_route.is_empty()).then_some(self.default_route.as_str())
    }

    /// Whether to sign in to the default route: switched on and with a user name.
    pub fn route_signs_in(&self) -> bool {
        self.default_route_auth && !self.default_route_username.is_empty()
    }

    /// The captcha the sign-in page asks for: switched on and, for the hosted providers, with
    /// both keys entered.
    pub fn captcha(&self) -> Option<crate::captcha::Provider> {
        let provider = crate::captcha::Provider::parse(&self.captcha_provider)?;
        (!provider.hosted() || (!self.captcha_site_key.is_empty() && !self.captcha_secret_key.is_empty())).then_some(provider)
    }

    pub fn login_limits(&self) -> crate::auth::LoginLimits {
        crate::auth::LoginLimits {
            window_secs: self.login_window_mins * 60,
            max_failures_per_account_and_ip: self.login_max_failures_per_account_and_ip,
            max_failures_per_ip: self.login_max_failures_per_ip,
            max_failures_per_account: self.login_max_failures_per_account,
            max_lock_secs: self.login_max_lock_hours * 3600,
            tarpit_after: self.login_tarpit_after,
            report_after: self.login_report_after,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if !(0..=3650).contains(&self.trash_retention_days) || !(0..=3650).contains(&self.junk_retention_days) {
            return Err("retention must be between 0 (keep forever) and 3650 days".into());
        }
        if !(0..=86_400).contains(&self.greylist_delay_secs) {
            return Err("the greylisting delay must be between 0 and 86400 seconds".into());
        }
        if !(64 * 1024..=1024 * 1024 * 1024).contains(&self.max_message_size) {
            return Err("the maximum message size must be between 64 KiB and 1 GiB".into());
        }
        if !(1..=10_000).contains(&self.max_recipients) {
            return Err("the recipient limit must be between 1 and 10000".into());
        }
        if self.abuseipdb_threshold > 100 {
            return Err("the AbuseIPDB threshold must be between 0 and 100".into());
        }
        if self.outbound_max_messages_per_hour < 1 || self.outbound_max_recipients_per_hour < 1 {
            return Err("sending limits must be at least 1".into());
        }
        if self.forward_max_copies_per_hour < 1 || self.queue_max_entries < 1 {
            return Err("forwarding and queue limits must be at least 1".into());
        }
        if self.dnsbl_zones.len() > 20 {
            return Err("at most 20 blocklist zones are supported".into());
        }
        if let Some(bad) = self.dnsbl_zones.iter().find(|zone| normalize_domain(zone).as_deref() != Some(zone.as_str())) {
            return Err(format!("invalid blocklist zone: {}", crate::util::sanitize_line(bad)));
        }
        if !self.spam_subject_score.is_finite() || !(0.0..=1000.0).contains(&self.spam_subject_score) {
            return Err("the spam score for the subject mark must be between 0 and 1000".into());
        }
        if !self.native_filter_score.is_finite() || !(0.5..=100.0).contains(&self.native_filter_score) {
            return Err("the junk score of the built-in filter must be between 0.5 and 100".into());
        }
        if !self.origin_score.is_finite() || !(0.0..=100.0).contains(&self.origin_score) {
            return Err("the score for penalised origins must be between 0 and 100".into());
        }
        if self.spam_traps.len() > 100 || self.penalized_asns.len() > 1000 || self.penalized_countries.len() > 250 {
            return Err("too many spam traps, autonomous systems or countries".into());
        }
        if let Some(bad) = self.spam_traps.iter().find(|trap| crate::util::Address::parse(trap).is_none_or(|a| a.to_string() != **trap)) {
            return Err(format!("invalid spam trap address: {}", crate::util::sanitize_line(bad)));
        }
        if let Some(bad) = self.penalized_asns.iter().find(|asn| asn.parse::<u32>().map_or(true, |n| n.to_string() != **asn)) {
            return Err(format!("autonomous systems are numbers, like 64500: {}", crate::util::sanitize_line(bad)));
        }
        if let Some(bad) = self.penalized_countries.iter().find(|c| c.len() != 2 || !c.bytes().all(|b| b.is_ascii_uppercase())) {
            return Err(format!("countries are two-letter codes in capitals, like DE: {}", crate::util::sanitize_line(bad)));
        }
        let prefix = self.spam_subject_prefix.trim();
        if prefix.is_empty() || prefix.chars().count() > 40 || prefix.chars().any(char::is_control) {
            return Err("the subject mark must be 1 to 40 characters on one line".into());
        }
        if !self.default_route.is_empty() && crate::smtp::client::parse_relay(&self.default_route).is_none() {
            return Err("the default route must be host:port, for example smtp.example.com:587".into());
        }
        if self.default_route_username.chars().count() > 200 || self.default_route_username.chars().any(char::is_control) {
            return Err("invalid user name for the default route".into());
        }
        if !(1..=3650).contains(&self.log_retention_days) || !(1..=3650).contains(&self.stats_retention_days) {
            return Err("log and statistics retention must be between 1 and 3650 days".into());
        }
        if !(1..=1440).contains(&self.login_window_mins) {
            return Err("the login counting window must be between 1 and 1440 minutes".into());
        }
        if [self.login_max_failures_per_account_and_ip, self.login_max_failures_per_ip, self.login_max_failures_per_account].iter().any(|n| !(1..=10_000).contains(n)) {
            return Err("failed login limits must be between 1 and 10000".into());
        }
        if !(1..=720).contains(&self.login_max_lock_hours) || self.login_max_lock_hours * 60 < self.login_window_mins {
            return Err("the longest login lockout must be between 1 and 720 hours, and not shorter than the counting window".into());
        }
        if !(1..=10_000).contains(&self.login_tarpit_after) || !(1..=10_000).contains(&self.login_report_after) {
            return Err("the slow-down and report thresholds must be between 1 and 10000".into());
        }
        if !self.captcha_provider.is_empty() && crate::captcha::Provider::parse(&self.captcha_provider).is_none() {
            return Err("the captcha must be one of hcaptcha, turnstile, recaptcha or altcha".into());
        }
        if self.captcha_site_key.len() > 200 || !self.captcha_site_key.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
            return Err("invalid captcha site key".into());
        }
        Ok(())
    }

    /// Applies a JSON object of overrides on top of `self`. Unknown keys are an error.
    pub fn with_overrides(&self, overrides: &Map<String, Value>) -> Result<Runtime, String> {
        let Value::Object(mut merged) = serde_json::to_value(self).map_err(|e| e.to_string())? else { unreachable!("Runtime serializes to an object") };
        for (key, value) in overrides {
            if !merged.contains_key(key) {
                return Err(format!("unknown setting: {}", crate::util::sanitize_line(key)));
            }
            merged.insert(key.clone(), value.clone());
        }
        let runtime: Runtime = serde_json::from_value(Value::Object(merged)).map_err(|e| format!("invalid value: {e}"))?;
        runtime.validate()?;
        Ok(runtime)
    }
}

pub async fn load_overrides(db: &SqlitePool) -> sqlx::Result<Map<String, Value>> {
    Ok(crate::db::get_setting(db, SETTING_KEY).await?.and_then(|json| serde_json::from_str(&json).ok()).unwrap_or_default())
}

pub async fn save_overrides(db: &SqlitePool, overrides: &Map<String, Value>) -> sqlx::Result<()> {
    crate::db::set_setting(db, SETTING_KEY, &Value::Object(overrides.clone()).to_string()).await
}

/// Effective settings at startup: environment defaults plus stored overrides. Overrides that
/// no longer validate (for example after an upgrade) are ignored rather than fatal.
pub async fn load(db: &SqlitePool, cfg: &Config) -> sqlx::Result<Runtime> {
    let defaults = Runtime::from_config(cfg);
    let overrides = load_overrides(db).await?;
    if overrides.is_empty() {
        return Ok(defaults);
    }
    Ok(defaults.with_overrides(&overrides).unwrap_or_else(|reason| {
        tracing::warn!(reason, "stored server settings are invalid, using defaults");
        defaults
    }))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn defaults() -> Runtime {
        Runtime::from_config(&Config::for_tests(std::path::PathBuf::from(".")))
    }

    #[test]
    fn overrides_are_merged_and_validated() {
        let base = defaults();
        let changed = base.with_overrides(json!({ "greylist_enabled": true, "max_recipients": 50, "dnsbl_zones": ["zen.spamhaus.org"] }).as_object().unwrap()).unwrap();
        assert!(changed.greylist_enabled && changed.max_recipients == 50 && changed.dnsbl_zones == ["zen.spamhaus.org"]);
        assert_eq!(changed.max_message_size, base.max_message_size, "untouched settings keep their defaults");
        let changed = base
            .with_overrides(json!({ "spam_subject_enabled": true, "spam_subject_score": 4.5, "spam_subject_prefix": "*** SPAM ***", "default_route": "smtp.example.com:587" }).as_object().unwrap())
            .unwrap();
        assert!(changed.spam_subject_enabled && changed.spam_subject_score == 4.5 && changed.default_route == "smtp.example.com:587");
        // The route is used only when switched on, and signs in only when asked to and possible.
        assert_eq!(changed.route(), None);
        let on = changed.with_overrides(json!({ "default_route_enabled": true, "default_route_auth": true }).as_object().unwrap()).unwrap();
        assert_eq!(on.route(), Some("smtp.example.com:587"));
        assert!(!on.route_signs_in(), "no user name yet");
        assert!(on.with_overrides(json!({ "default_route_username": "relay" }).as_object().unwrap()).unwrap().route_signs_in());
        // Settings stored by an older version (without the new keys) still load.
        let old: Runtime = serde_json::from_value(json!({
            "greylist_enabled": true, "greylist_delay_secs": 60, "max_message_size": 1048576, "max_recipients": 10, "dnsbl_zones": [], "abuseipdb_threshold": 50,
            "smtp_require_tls": false, "outbound_require_tls": false, "rspamd_fail_open": false, "outbound_max_messages_per_hour": 10, "outbound_max_recipients_per_hour": 10,
        }))
        .unwrap();
        assert!(old.spam_check_inbound && old.privacy_hide_client_ip && old.strict_from_check && old.log_retention_days == 90 && !old.quarantine_misbehaving);

        // A hosted captcha is used only once both keys are entered; ALTCHA needs none.
        assert!(base.with_overrides(json!({ "captcha_provider": "turnstile", "captcha_site_key": "0x4AAA" }).as_object().unwrap()).unwrap().captcha().is_none());
        let both = json!({ "captcha_provider": "turnstile", "captcha_site_key": "0x4AAA", "captcha_secret_key": "sealed" });
        assert!(base.with_overrides(both.as_object().unwrap()).unwrap().captcha().is_some());
        assert!(base.with_overrides(json!({ "captcha_provider": "altcha" }).as_object().unwrap()).unwrap().captcha().is_some());

        for bad in [
            json!({ "max_recipients": 0 }),
            json!({ "max_recipients": "many" }),
            json!({ "max_message_size": 10 }),
            json!({ "abuseipdb_threshold": 101 }),
            json!({ "greylist_delay_secs": -1 }),
            json!({ "dnsbl_zones": ["not a zone"] }),
            json!({ "dnsbl_zones": ["Zen.Spamhaus.org"] }),
            json!({ "outbound_max_messages_per_hour": 0 }),
            json!({ "admin_password": "x" }),
            json!({ "spam_subject_score": -1 }),
            json!({ "spam_subject_prefix": "" }),
            json!({ "spam_subject_prefix": "two\nlines" }),
            json!({ "default_route": "no-port" }),
            json!({ "log_retention_days": 0 }),
            json!({ "stats_retention_days": 4000 }),
            json!({ "spam_traps": ["not an address"] }),
            json!({ "penalized_countries": ["pl"] }),
            json!({ "native_filter_score": 0 }),
            json!({ "login_window_mins": 0 }),
            json!({ "login_max_failures_per_ip": 0 }),
            json!({ "login_max_lock_hours": 0 }),
            json!({ "login_window_mins": 120, "login_max_lock_hours": 1 }),
            json!({ "captcha_provider": "geetest" }),
            json!({ "captcha_site_key": "<script>" }),
        ] {
            assert!(base.with_overrides(bad.as_object().unwrap()).is_err(), "{bad}");
        }
    }
}
