//! Runtime configuration, read from `UNOMAIL_*` environment variables.

use std::{net::IpAddr, path::PathBuf, str::FromStr};

use anyhow::{Context, bail};

/// Big mailbox providers and forwarders that seal ARC chains (RFC 8617) when they forward.
pub const DEFAULT_ARC_SEALERS: &[&str] = &["google.com", "microsoft.com", "outlook.com", "yahoo.com", "icloud.com", "fastmail.com", "fastmail.fm", "zoho.com", "proton.me"];

#[derive(Debug, Clone)]
pub enum BackupTarget {
    Dir(PathBuf),
    S3(crate::s3::S3Config),
}

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    /// Public hostname announced in SMTP banners, HELO and used for the default certificate.
    pub hostname: String,
    pub bind: IpAddr,

    pub http_port: u16,
    pub https_port: u16,
    /// Port clients reach HTTPS on (differs from `https_port` behind port mappings).
    pub public_https_port: u16,
    /// Address users reach the web interface at, when it differs from `https://<hostname>`.
    pub public_url_override: Option<String>,
    /// Redirect plain HTTP to HTTPS. Disable when a reverse proxy terminates TLS.
    pub http_redirect: bool,
    /// Bearer token required to scrape `/metrics` from non-private addresses.
    pub metrics_token: Option<String>,
    pub cloudflare_api_url: String,
    pub smtp_port: u16,
    pub submission_port: u16,
    pub smtps_port: u16,
    pub imaps_port: u16,
    /// IMAP with mandatory STARTTLS.
    pub imap_port: u16,
    pub pop3s_port: u16,
    /// ManageSieve (STARTTLS), 0 to disable.
    pub sieve_port: u16,
    /// LMTP for a mail server in front of this one, 0 to disable (the default).
    pub lmtp_port: u16,

    /// Directory with the built web UI (served as static files with SPA fallback).
    pub web_dir: Option<PathBuf>,
    /// Mark session cookies `Secure`. Only disable for plain-HTTP local development.
    pub cookie_secure: bool,
    /// Trust `X-Forwarded-For` from these proxies when determining the client address.
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Networks whose mail servers are trusted on port 25 like the server itself: their mail is
    /// not checked for SPF/DKIM/DMARC and not greylisted, and they may read `/metrics` without
    /// the token. Loopback is always trusted; private ranges are not, because behind NAT (for
    /// example Docker's userland proxy) every client can appear to come from one.
    pub trusted_networks: Vec<ipnet::IpNet>,

    pub admin_email: Option<String>,
    pub admin_password: Option<String>,

    pub max_message_size: usize,
    pub max_recipients: usize,

    pub greylist_enabled: bool,
    pub greylist_delay_secs: i64,
    pub dnsbl_zones: Vec<String>,
    pub rspamd_url: Option<String>,
    pub rspamd_socket: Option<PathBuf>,
    pub rspamd_controller_socket: Option<PathBuf>,
    pub rspamd_password: Option<String>,
    /// Accept mail unscanned when the configured filter is unreachable (default: defer it).
    pub rspamd_fail_open: bool,
    /// `host:port` of clamd for scanning complete messages (INSTREAM).
    pub clamav_addr: Option<String>,
    /// Deliver incoming mail with a virus to the Junk folder, marked, instead of refusing it.
    pub virus_quarantine: bool,
    /// Where sender pictures are asked for by address hash; `None` turns Gravatar off.
    pub gravatar_url: Option<String>,
    /// Domains whose ARC seal is trusted to vouch for mail they forwarded (lists, forwarders).
    pub arc_trusted_sealers: Vec<String>,
    /// Content filters speaking the milter protocol, `host:port`, run on incoming mail in order.
    pub milters: Vec<String>,
    /// Accept mail unfiltered when a milter is unreachable (default: defer it).
    pub milter_fail_open: bool,
    /// Keep message contents in an S3 bucket instead of `<data>/blobs` (`UNOMAIL_S3_*`).
    pub blob_s3: Option<crate::s3::S3Config>,
    /// Encrypt message contents at rest with the key in `<data>/blob.key`.
    pub encrypt_mail: bool,
    /// Where scheduled backups go: a directory, or a bucket (`UNOMAIL_BACKUP_S3_*`).
    pub backup_target: Option<BackupTarget>,
    /// Hour of the day (UTC) for the daily backup.
    pub backup_hour: u32,
    /// How many database snapshots to keep.
    pub backup_keep: usize,
    /// Rspamd controller, used to train Bayes and fuzzy storage from user feedback.
    pub rspamd_controller_url: Option<String>,
    /// Refuse inbound mail on port 25 unless the sending server uses STARTTLS.
    pub smtp_require_tls: bool,
    /// Extra PEM root certificate trusted for the ACME directory (private or test CAs).
    pub acme_ca_file: Option<PathBuf>,
    /// Seconds to wait for a DNS-01 record to propagate before asking the CA to validate.
    pub acme_dns_wait_secs: u64,
    pub abuseipdb_key: Option<String>,
    pub abuseipdb_url: String,
    /// AbuseIPDB confidence score at or above which inbound connections are refused.
    pub abuseipdb_threshold: u8,
    /// Report addresses caught guessing passwords to AbuseIPDB (needs the key).
    pub abuseipdb_report: bool,

    /// Deliver all outbound mail through this `host:port` instead of MX lookups.
    pub outbound_relay: Option<String>,
    /// Lets identity SMTP servers and the image proxy reach private addresses, and identities
    /// use unencrypted SMTP. For tests and closed networks only.
    pub allow_private_destinations: bool,
    pub identity_relay_allow_private: bool,
    /// Lets packages be installed from local (`file://`) repositories. For tests only.
    pub packages_allow_local: bool,
    /// Refuse to deliver outbound mail over connections that are not TLS protected.
    pub outbound_require_tls: bool,
    pub queue_max_age_secs: i64,

    /// Messages / recipients an account may submit per hour before it is blocked.
    pub outbound_max_messages_per_hour: i64,
    pub outbound_max_recipients_per_hour: i64,

    pub acme_directory: String,
    pub session_ttl_secs: i64,
}

impl Config {
    /// Base URL of the web interface as users see it, without a trailing slash.
    pub fn public_url(&self) -> String {
        match &self.public_url_override {
            Some(url) => url.clone(),
            None if self.public_https_port == 443 => format!("https://{}", self.hostname),
            None => format!("https://{}:{}", self.hostname, self.public_https_port),
        }
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

fn parse<T: FromStr>(name: &str, default: T) -> anyhow::Result<T>
where
    T::Err: std::fmt::Display,
{
    match var(name) {
        Some(v) => v.parse().map_err(|e| anyhow::anyhow!("invalid {name}={v:?}: {e}")),
        None => Ok(default),
    }
}

fn parse_bool(name: &str, default: bool) -> anyhow::Result<bool> {
    match var(name).as_deref() {
        None => Ok(default),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        Some(v) => bail!("invalid {name}={v:?}: expected a boolean"),
    }
}

fn parse_list(name: &str) -> Vec<String> {
    var(name)
        .map(|v| v.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let hostname = var("UNOMAIL_HOSTNAME").unwrap_or_else(|| "localhost".into()).to_ascii_lowercase();
        let networks = |name: &str| {
            parse_list(name)
                .iter()
                .map(|s| {
                    s.parse::<ipnet::IpNet>()
                        .or_else(|_| s.parse::<IpAddr>().map(ipnet::IpNet::from))
                        .with_context(|| format!("invalid {name} entry {s:?}"))
                })
                .collect::<anyhow::Result<Vec<_>>>()
        };
        let trusted_proxies = networks("UNOMAIL_TRUSTED_PROXIES")?;
        let trusted_networks = networks("UNOMAIL_TRUSTED_NETWORKS")?;

        let cfg = Config {
            data_dir: PathBuf::from(var("UNOMAIL_DATA_DIR").unwrap_or_else(|| "./data".into())),
            hostname,
            bind: parse("UNOMAIL_BIND", IpAddr::from([0, 0, 0, 0]))?,
            http_port: parse("UNOMAIL_HTTP_PORT", 80)?,
            https_port: parse("UNOMAIL_HTTPS_PORT", 443)?,
            public_https_port: parse("UNOMAIL_PUBLIC_HTTPS_PORT", parse("UNOMAIL_HTTPS_PORT", 443)?)?,
            public_url_override: var("UNOMAIL_PUBLIC_URL").map(|url| url.trim_end_matches('/').to_owned()),
            http_redirect: parse_bool("UNOMAIL_HTTP_REDIRECT", true)?,
            metrics_token: var("UNOMAIL_METRICS_TOKEN"),
            cloudflare_api_url: var("UNOMAIL_CLOUDFLARE_API_URL").unwrap_or_else(|| "https://api.cloudflare.com/client/v4".into()),
            smtp_port: parse("UNOMAIL_SMTP_PORT", 25)?,
            submission_port: parse("UNOMAIL_SUBMISSION_PORT", 587)?,
            smtps_port: parse("UNOMAIL_SMTPS_PORT", 465)?,
            imaps_port: parse("UNOMAIL_IMAPS_PORT", 993)?,
            imap_port: parse("UNOMAIL_IMAP_PORT", 143)?,
            pop3s_port: parse("UNOMAIL_POP3S_PORT", 995)?,
            sieve_port: parse("UNOMAIL_SIEVE_PORT", 4190)?,
            lmtp_port: parse("UNOMAIL_LMTP_PORT", 0)?,
            web_dir: var("UNOMAIL_WEB_DIR").map(PathBuf::from),
            cookie_secure: parse_bool("UNOMAIL_COOKIE_SECURE", true)?,
            trusted_proxies,
            trusted_networks,
            admin_email: var("UNOMAIL_ADMIN_EMAIL"),
            admin_password: var("UNOMAIL_ADMIN_PASSWORD"),
            max_message_size: parse("UNOMAIL_MAX_MESSAGE_SIZE", 50 * 1024 * 1024)?,
            max_recipients: parse("UNOMAIL_MAX_RECIPIENTS", 100)?,
            greylist_enabled: parse_bool("UNOMAIL_GREYLIST", true)?,
            greylist_delay_secs: parse("UNOMAIL_GREYLIST_DELAY", 60)?,
            // Spamhaus unless the variable is set; set but empty turns the blocklists off.
            dnsbl_zones: if std::env::var_os("UNOMAIL_DNSBL_ZONES").is_some() { parse_list("UNOMAIL_DNSBL_ZONES") } else { vec!["zen.spamhaus.org".into()] },
            rspamd_url: var("UNOMAIL_RSPAMD_URL"),
            rspamd_socket: var("UNOMAIL_RSPAMD_SOCKET").map(PathBuf::from),
            rspamd_controller_socket: var("UNOMAIL_RSPAMD_CONTROLLER_SOCKET").map(PathBuf::from),
            rspamd_password: var("UNOMAIL_RSPAMD_PASSWORD"),
            rspamd_fail_open: parse_bool("UNOMAIL_RSPAMD_FAIL_OPEN", false)?,
            clamav_addr: var("UNOMAIL_CLAMAV_ADDR"),
            virus_quarantine: match var("UNOMAIL_VIRUS_ACTION").as_deref() {
                None | Some("reject") => false,
                Some("quarantine") => true,
                Some(other) => bail!("invalid UNOMAIL_VIRUS_ACTION={other:?}: expected reject or quarantine"),
            },
            gravatar_url: match var("UNOMAIL_GRAVATAR").as_deref() {
                None | Some("1" | "true" | "yes" | "on") => Some("https://www.gravatar.com/avatar".into()),
                Some("0" | "false" | "no" | "off") => None,
                Some(url) if url.starts_with("https://") || url.starts_with("http://") => Some(url.to_owned()),
                Some(other) => bail!("invalid UNOMAIL_GRAVATAR={other:?}: expected on, off or the address of a compatible service"),
            },
            arc_trusted_sealers: match var("UNOMAIL_ARC_TRUSTED_SEALERS") {
                Some(list) => list.split([',', ' ']).map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase()).filter(|d| !d.is_empty()).collect(),
                None => DEFAULT_ARC_SEALERS.iter().map(|d| (*d).to_owned()).collect(),
            },
            milters: parse_list("UNOMAIL_MILTERS"),
            milter_fail_open: parse_bool("UNOMAIL_MILTER_FAIL_OPEN", false)?,
            blob_s3: crate::s3::S3Config::from_env("UNOMAIL_S3_")?,
            encrypt_mail: parse_bool("UNOMAIL_ENCRYPT_MAIL", false)?,
            backup_target: match (var("UNOMAIL_BACKUP_DIR"), crate::s3::S3Config::from_env("UNOMAIL_BACKUP_S3_")?) {
                (Some(_), Some(_)) => bail!("set either UNOMAIL_BACKUP_DIR or UNOMAIL_BACKUP_S3_BUCKET, not both"),
                (Some(dir), None) => Some(BackupTarget::Dir(PathBuf::from(dir))),
                (None, Some(s3)) => Some(BackupTarget::S3(s3)),
                (None, None) => None,
            },
            backup_hour: match parse("UNOMAIL_BACKUP_HOUR", 3u32)? {
                hour @ 0..=23 => hour,
                other => bail!("invalid UNOMAIL_BACKUP_HOUR={other}: expected 0 to 23"),
            },
            backup_keep: parse("UNOMAIL_BACKUP_KEEP", 7usize)?.max(1),
            rspamd_controller_url: var("UNOMAIL_RSPAMD_CONTROLLER_URL"),
            smtp_require_tls: parse_bool("UNOMAIL_SMTP_REQUIRE_TLS", false)?,
            acme_ca_file: var("UNOMAIL_ACME_CA_FILE").map(PathBuf::from),
            acme_dns_wait_secs: parse("UNOMAIL_ACME_DNS_WAIT", 20)?,
            abuseipdb_key: var("UNOMAIL_ABUSEIPDB_KEY"),
            abuseipdb_url: var("UNOMAIL_ABUSEIPDB_URL").unwrap_or_else(|| "https://api.abuseipdb.com".into()),
            abuseipdb_threshold: parse("UNOMAIL_ABUSEIPDB_THRESHOLD", 90)?,
            abuseipdb_report: parse_bool("UNOMAIL_ABUSEIPDB_REPORT", false)?,
            outbound_relay: var("UNOMAIL_OUTBOUND_RELAY"),
            allow_private_destinations: parse("UNOMAIL_ALLOW_PRIVATE_DESTINATIONS", false)?,
            identity_relay_allow_private: parse("UNOMAIL_ALLOW_PRIVATE_DESTINATIONS", false)?,
            packages_allow_local: parse("UNOMAIL_PACKAGES_ALLOW_LOCAL", false)?,
            outbound_require_tls: parse_bool("UNOMAIL_OUTBOUND_REQUIRE_TLS", false)?,
            queue_max_age_secs: parse("UNOMAIL_QUEUE_MAX_AGE", 5 * 24 * 3600)?,
            outbound_max_messages_per_hour: parse("UNOMAIL_OUTBOUND_MAX_MESSAGES_PER_HOUR", 300)?,
            outbound_max_recipients_per_hour: parse("UNOMAIL_OUTBOUND_MAX_RECIPIENTS_PER_HOUR", 1000)?,
            acme_directory: var("UNOMAIL_ACME_DIRECTORY")
                .unwrap_or_else(|| "https://acme-v02.api.letsencrypt.org/directory".into()),
            session_ttl_secs: parse("UNOMAIL_SESSION_TTL", 12 * 3600)?,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if !crate::util::is_valid_domain(&self.hostname) && self.hostname != "localhost" {
            bail!("UNOMAIL_HOSTNAME {:?} is not a valid hostname", self.hostname);
        }
        if self.max_message_size < 1024 {
            bail!("UNOMAIL_MAX_MESSAGE_SIZE is too small");
        }
        if self.abuseipdb_threshold > 100 {
            bail!("UNOMAIL_ABUSEIPDB_THRESHOLD must be between 0 and 100");
        }
        Ok(())
    }

    /// Configuration for tests: ephemeral ports, no external lookups.
    pub fn for_tests(data_dir: PathBuf) -> Self {
        Config {
            data_dir,
            hostname: "mail.test.example".into(),
            bind: IpAddr::from([127, 0, 0, 1]),
            http_port: 0,
            https_port: 0,
            public_https_port: 443,
            public_url_override: None,
            http_redirect: false,
            metrics_token: None,
            cloudflare_api_url: "http://127.0.0.1:9".into(),
            smtp_port: 0,
            submission_port: 0,
            smtps_port: 0,
            imaps_port: 0,
            imap_port: 0,
            pop3s_port: 0,
            sieve_port: 0,
            lmtp_port: 0,
            web_dir: None,
            cookie_secure: false,
            trusted_proxies: Vec::new(),
            trusted_networks: Vec::new(),
            admin_email: None,
            admin_password: None,
            max_message_size: 1024 * 1024,
            max_recipients: 10,
            greylist_enabled: false,
            greylist_delay_secs: 60,
            dnsbl_zones: Vec::new(),
            rspamd_url: None,
            rspamd_socket: None,
            rspamd_controller_socket: None,
            rspamd_password: None,
            rspamd_fail_open: false,
            clamav_addr: None,
            virus_quarantine: false,
            gravatar_url: None,
            arc_trusted_sealers: DEFAULT_ARC_SEALERS.iter().map(|d| (*d).to_owned()).collect(),
            milters: Vec::new(),
            milter_fail_open: false,
            blob_s3: None,
            encrypt_mail: false,
            backup_target: None,
            backup_hour: 3,
            backup_keep: 7,
            rspamd_controller_url: None,
            smtp_require_tls: false,
            acme_ca_file: None,
            acme_dns_wait_secs: 1,
            abuseipdb_key: None,
            abuseipdb_url: "http://127.0.0.1:9".into(),
            abuseipdb_threshold: 90,
            abuseipdb_report: false,
            outbound_relay: None,
            allow_private_destinations: true,
            identity_relay_allow_private: true,
            packages_allow_local: true,
            outbound_require_tls: false,
            queue_max_age_secs: 3600,
            outbound_max_messages_per_hour: 300,
            outbound_max_recipients_per_hour: 1000,
            acme_directory: "https://acme.invalid/directory".into(),
            session_ttl_secs: 3600,
        }
    }
}
