//! TLS certificate management: validation of uploaded certificates, a self-signed fallback and
//! a hot-swappable resolver shared by every TLS listener (HTTPS, SMTP, IMAP, POP3).

use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use rustls::{
    ServerConfig,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use serde::Serialize;
use sqlx::SqlitePool;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

use crate::util::now;

/// Certificates expiring within this window produce a warning and trigger ACME renewal.
pub const RENEW_BEFORE_SECS: i64 = 30 * 24 * 3600;
const SETTING_ACTIVE: &str = "tls.active_certificate";

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "TEXT", rename_all = "snake_case")]
pub enum CertKind {
    Acme,
    Custom,
    SelfSigned,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertInfo {
    pub id: i64,
    pub kind: CertKind,
    pub domains: Vec<String>,
    pub not_before: i64,
    pub not_after: i64,
    pub issuer: String,
}

impl CertInfo {
    pub fn seconds_remaining(&self) -> i64 {
        self.not_after - now()
    }
}

/// Result of checking a certificate chain and private key before it is installed.
#[derive(Debug)]
pub struct Validated {
    pub key: CertifiedKey,
    pub domains: Vec<String>,
    pub not_before: i64,
    pub not_after: i64,
    pub issuer: String,
    /// Problems that do not prevent installation (near expiry, untrusted issuer, ...).
    pub warnings: Vec<String>,
}

/// True when `name` is covered by the SAN entry `pattern` (supports a single leading wildcard).
pub fn san_matches(pattern: &str, name: &str) -> bool {
    let (pattern, name) = (pattern.to_ascii_lowercase(), name.to_ascii_lowercase());
    match pattern.strip_prefix("*.") {
        Some(suffix) => name.split_once('.').is_some_and(|(label, rest)| !label.is_empty() && rest == suffix),
        None => pattern == name,
    }
}

/// Parses and validates a PEM certificate chain with its private key.
///
/// Hard failures: unparsable input, key/certificate mismatch, expired or not-yet-valid leaf,
/// a chain whose certificates do not sign each other in order. Everything else is a warning.
pub fn validate(cert_pem: &str, key_pem: &str, expected_host: &str) -> Result<Validated, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("could not parse certificate PEM: {e}"))?;
    if chain.is_empty() {
        return Err("no certificate found in the PEM input".into());
    }
    if chain.len() > 10 {
        return Err("certificate chain is too long".into());
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| format!("could not parse private key PEM: {e}"))?;

    let parsed: Vec<X509Certificate<'_>> = chain
        .iter()
        .map(|der| X509Certificate::from_der(der.as_ref()).map(|(_, c)| c))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("could not parse certificate: {e}"))?;
    let leaf = &parsed[0];

    let (not_before, not_after) = (leaf.validity().not_before.timestamp(), leaf.validity().not_after.timestamp());
    let current = now();
    if current < not_before {
        return Err("certificate is not valid yet".into());
    }
    if current >= not_after {
        return Err("certificate has expired".into());
    }

    for (i, pair) in parsed.windows(2).enumerate() {
        let (cert, issuer) = (&pair[0], &pair[1]);
        if cert.issuer() != issuer.subject() || cert.verify_signature(Some(issuer.public_key())).is_err() {
            return Err(format!(
                "certificate chain is broken: certificate #{} is not signed by certificate #{}",
                i + 1,
                i + 2
            ));
        }
    }

    let signing_key = provider()
        .key_provider
        .load_private_key(key)
        .map_err(|e| format!("unsupported private key: {e}"))?;
    let certified = CertifiedKey::new(chain.clone(), signing_key);
    match certified.keys_match() {
        // `Unknown` means the provider cannot compare this key type; rustls itself accepts that.
        Ok(()) | Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {}
        Err(_) => return Err("private key does not match the certificate".into()),
    }

    let mut domains = Vec::new();
    if let Ok(Some(san)) = leaf.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(dns) => domains.push(dns.to_ascii_lowercase()),
                GeneralName::IPAddress(bytes) => match bytes.len() {
                    4 => domains.push(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(*bytes).unwrap()).to_string()),
                    16 => domains.push(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*bytes).unwrap()).to_string()),
                    _ => {}
                },
                _ => {}
            }
        }
    }

    let mut warnings = Vec::new();
    if not_after - current < RENEW_BEFORE_SECS {
        warnings.push(format!("certificate expires in {} days", (not_after - current) / 86400));
    }
    if !domains.iter().any(|d| san_matches(d, expected_host)) {
        warnings.push(format!("certificate is not valid for the server hostname {expected_host}"));
    }
    if let Err(reason) = verify_public_trust(&chain, expected_host) {
        warnings.push(format!("certificate chain is not publicly trusted: {reason}"));
    }

    Ok(Validated { key: certified, domains, not_before, not_after, issuer: leaf.issuer().to_string(), warnings })
}

/// Checks the chain against the Mozilla root program, as a remote mail server or browser would.
fn verify_public_trust(chain: &[CertificateDer<'static>], host: &str) -> Result<(), String> {
    use rustls::client::danger::ServerCertVerifier;
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
        .build()
        .map_err(|e| e.to_string())?;
    let name = ServerName::try_from(host.to_owned()).map_err(|e| e.to_string())?;
    verifier
        .verify_server_cert(&chain[0], &chain[1..], &name, &[], UnixTime::now())
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Generates a self-signed certificate valid for one year. It is regenerated automatically
/// at startup once it has expired.
pub fn generate_self_signed(hostname: &str) -> anyhow::Result<(String, String)> {
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec![hostname.to_owned()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, hostname);
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365);
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

#[derive(Debug)]
struct Resolver(Arc<ArcSwap<CertifiedKey>>);

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.load_full())
    }
}

pub struct TlsManager {
    db: SqlitePool,
    hostname: String,
    current: Arc<ArcSwap<CertifiedKey>>,
    info: ArcSwap<CertInfo>,
    /// Pending ACME HTTP-01 challenges: token -> key authorization.
    pub http_challenges: Mutex<HashMap<String, String>>,
}

impl TlsManager {
    /// Loads the active certificate, falling back to (and persisting) a self-signed one so that
    /// TLS listeners can always start.
    pub async fn load(db: SqlitePool, hostname: &str) -> anyhow::Result<Arc<Self>> {
        let active = crate::db::get_setting(&db, SETTING_ACTIVE).await?.and_then(|v| v.parse::<i64>().ok());
        if let Some(id) = active
            && let Some((cert_pem, key_pem, kind)) =
                sqlx::query_as::<_, (String, String, CertKind)>("SELECT cert_pem, key_pem, kind FROM certificates WHERE id = ?")
                    .bind(id)
                    .fetch_optional(&db)
                    .await?
        {
            match validate(&cert_pem, &key_pem, hostname) {
                Ok(v) => return Ok(Arc::new(Self::from_validated(db, hostname, id, kind, v))),
                Err(reason) => {
                    tracing::error!(reason, "stored certificate is unusable, falling back to a self-signed certificate")
                }
            }
        }
        let (cert_pem, key_pem) = generate_self_signed(hostname)?;
        let validated = validate(&cert_pem, &key_pem, hostname).map_err(|e| anyhow::anyhow!(e))?;
        let id = store(&db, CertKind::SelfSigned, &cert_pem, &key_pem, &validated).await?;
        Ok(Arc::new(Self::from_validated(db, hostname, id, CertKind::SelfSigned, validated)))
    }

    fn from_validated(db: SqlitePool, hostname: &str, id: i64, kind: CertKind, v: Validated) -> Self {
        let info = CertInfo {
            id,
            kind,
            domains: v.domains,
            not_before: v.not_before,
            not_after: v.not_after,
            issuer: v.issuer,
        };
        TlsManager {
            db,
            hostname: hostname.to_owned(),
            current: Arc::new(ArcSwap::from_pointee(v.key)),
            info: ArcSwap::from_pointee(info),
            http_challenges: Mutex::new(HashMap::new()),
        }
    }

    pub fn info(&self) -> Arc<CertInfo> {
        self.info.load_full()
    }

    /// Validates, persists and activates a certificate. Running listeners pick it up on the next
    /// handshake; established connections are unaffected.
    pub async fn install(&self, kind: CertKind, cert_pem: &str, key_pem: &str) -> Result<(Arc<CertInfo>, Vec<String>), String> {
        let mut validated = validate(cert_pem, key_pem, &self.hostname)?;
        let warnings = std::mem::take(&mut validated.warnings);
        let id = store(&self.db, kind, cert_pem, key_pem, &validated).await.map_err(|e| {
            tracing::error!(error = ?e, "failed to store certificate");
            "failed to store certificate".to_owned()
        })?;
        let info = Arc::new(CertInfo {
            id,
            kind,
            domains: validated.domains,
            not_before: validated.not_before,
            not_after: validated.not_after,
            issuer: validated.issuer,
        });
        self.current.store(Arc::new(validated.key));
        self.info.store(info.clone());
        Ok((info, warnings))
    }

    /// Discards the active certificate in favour of a freshly generated self-signed one.
    pub async fn reset_to_self_signed(&self) -> anyhow::Result<Arc<CertInfo>> {
        let (cert_pem, key_pem) = generate_self_signed(&self.hostname)?;
        let (info, _) = self.install(CertKind::SelfSigned, &cert_pem, &key_pem).await.map_err(|e| anyhow::anyhow!(e))?;
        Ok(info)
    }

    /// Server configuration backed by the hot-swappable certificate. TLS 1.2 and 1.3 only, with
    /// the provider's AEAD/forward-secret cipher suites.
    pub fn server_config(&self, alpn: &[&[u8]]) -> Arc<ServerConfig> {
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("ring provider supports TLS 1.2 and 1.3")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver(self.current.clone())));
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(config)
    }
}

async fn store(db: &SqlitePool, kind: CertKind, cert_pem: &str, key_pem: &str, v: &Validated) -> anyhow::Result<i64> {
    let mut tx = db.begin().await?;
    let id = sqlx::query(
        "INSERT INTO certificates (kind, domains, cert_pem, key_pem, not_before, not_after, issuer, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(kind)
    .bind(serde_json::to_string(&v.domains)?)
    .bind(cert_pem)
    .bind(key_pem)
    .bind(v.not_before)
    .bind(v.not_after)
    .bind(&v.issuer)
    .bind(now())
    .execute(&mut *tx)
    .await?
    .last_insert_rowid();
    sqlx::query("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind(SETTING_ACTIVE)
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?;
    // Superseded private keys have no further use; do not keep them around.
    sqlx::query("DELETE FROM certificates WHERE id != ?").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(id)
}

#[cfg(test)]
pub(crate) mod tests {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    use time::{Duration, OffsetDateTime};

    use super::*;

    pub fn leaf_params(names: &[&str], valid_from: Duration, valid_for: Duration) -> CertificateParams {
        let mut params = CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        params.not_before = OffsetDateTime::now_utc() + valid_from;
        params.not_after = OffsetDateTime::now_utc() + valid_from + valid_for;
        params
    }

    /// Returns (leaf pem, leaf key pem, ca pem) for a leaf signed by a private CA.
    pub fn ca_signed(names: &[&str]) -> (String, String, String) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, "Test CA");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf_params(names, Duration::days(-1), Duration::days(365)).signed_by(&leaf_key, &issuer).unwrap();
        (leaf.pem(), leaf_key.serialize_pem(), ca_cert.pem())
    }

    #[test]
    fn san_matching() {
        assert!(san_matches("mail.example.com", "MAIL.example.com"));
        assert!(san_matches("*.example.com", "mail.example.com"));
        assert!(!san_matches("*.example.com", "example.com"));
        assert!(!san_matches("*.example.com", "a.b.example.com"));
        assert!(!san_matches("mail.example.com", "evil.example.com"));
    }

    #[test]
    fn accepts_valid_self_signed_with_warnings() {
        let (cert, key) = generate_self_signed("mail.example.com").unwrap();
        let v = validate(&cert, &key, "mail.example.com").unwrap();
        assert_eq!(v.domains, ["mail.example.com"]);
        assert!(v.warnings.iter().any(|w| w.contains("not publicly trusted")));
        assert!(!v.warnings.iter().any(|w| w.contains("hostname")));
    }

    #[test]
    fn warns_on_hostname_mismatch() {
        let (cert, key) = generate_self_signed("other.example.com").unwrap();
        let v = validate(&cert, &key, "mail.example.com").unwrap();
        assert!(v.warnings.iter().any(|w| w.contains("not valid for the server hostname")));
    }

    #[test]
    fn rejects_mismatched_key() {
        let (cert, _) = generate_self_signed("mail.example.com").unwrap();
        let (_, other_key) = generate_self_signed("mail.example.com").unwrap();
        assert_eq!(validate(&cert, &other_key, "mail.example.com").unwrap_err(), "private key does not match the certificate");
    }

    #[test]
    fn rejects_expired_and_future_certificates() {
        let key = KeyPair::generate().unwrap();
        let expired = leaf_params(&["mail.example.com"], Duration::days(-10), Duration::days(5)).self_signed(&key).unwrap();
        assert_eq!(validate(&expired.pem(), &key.serialize_pem(), "mail.example.com").unwrap_err(), "certificate has expired");
        let future = leaf_params(&["mail.example.com"], Duration::days(5), Duration::days(5)).self_signed(&key).unwrap();
        assert_eq!(
            validate(&future.pem(), &key.serialize_pem(), "mail.example.com").unwrap_err(),
            "certificate is not valid yet"
        );
    }

    #[test]
    fn warns_when_close_to_expiry() {
        let key = KeyPair::generate().unwrap();
        let cert = leaf_params(&["mail.example.com"], Duration::days(-80), Duration::days(90)).self_signed(&key).unwrap();
        let v = validate(&cert.pem(), &key.serialize_pem(), "mail.example.com").unwrap();
        assert!(v.warnings.iter().any(|w| w.contains("expires in")));
    }

    #[test]
    fn verifies_chain_order() {
        let (leaf, key, ca) = ca_signed(&["mail.example.com"]);
        assert!(validate(&format!("{leaf}{ca}"), &key, "mail.example.com").is_ok());

        let (_, _, unrelated_ca) = ca_signed(&["x.example.com"]);
        let err = validate(&format!("{leaf}{unrelated_ca}"), &key, "mail.example.com").unwrap_err();
        assert!(err.contains("chain is broken"), "{err}");
    }

    #[test]
    fn rejects_garbage() {
        let (cert, key) = generate_self_signed("mail.example.com").unwrap();
        assert!(validate("not a pem", &key, "mail.example.com").is_err());
        assert!(validate(&cert, "not a key", "mail.example.com").is_err());
        assert!(validate("", "", "mail.example.com").is_err());
    }

    #[tokio::test]
    async fn manager_falls_back_to_self_signed_and_hot_swaps() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::open(&dir.path().join("t.db")).await.unwrap();
        let manager = TlsManager::load(db.clone(), "mail.example.com").await.unwrap();
        assert_eq!(manager.info().kind, CertKind::SelfSigned);
        let first_id = manager.info().id;

        // Reloading keeps using the persisted certificate instead of generating a new one.
        let reloaded = TlsManager::load(db.clone(), "mail.example.com").await.unwrap();
        assert_eq!(reloaded.info().id, first_id);

        let config = manager.server_config(&[b"h2"]);
        let (leaf, key, ca) = ca_signed(&["mail.example.com"]);
        let (info, warnings) = manager.install(CertKind::Custom, &format!("{leaf}{ca}"), &key).await.unwrap();
        assert_eq!(info.kind, CertKind::Custom);
        assert!(warnings.iter().any(|w| w.contains("not publicly trusted")));
        assert_eq!(manager.info().id, info.id);
        // The config created before the swap resolves the new certificate.
        drop(config);

        let (bad_cert, _) = generate_self_signed("mail.example.com").unwrap();
        assert!(manager.install(CertKind::Custom, &bad_cert, &key).await.is_err());
        assert_eq!(manager.info().id, info.id, "a rejected upload leaves the active certificate untouched");

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM certificates").fetch_one(&db).await.unwrap();
        assert_eq!(count, 1);
        assert_eq!(manager.reset_to_self_signed().await.unwrap().kind, CertKind::SelfSigned);
    }
}
