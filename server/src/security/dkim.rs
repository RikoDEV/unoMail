//! DKIM key management and message signing.

use base64::{Engine, engine::general_purpose::STANDARD};
use mail_auth::{
    common::{
        crypto::{Ed25519Key, RsaKey, Sha256},
        headers::HeaderWriter,
    },
    dkim::DkimSigner,
};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
use serde::Serialize;
use sqlx::SqlitePool;

use crate::util::now;

const SIGNED_HEADERS: [&str; 14] = [
    // From is listed twice ("oversigned") so a second From header cannot be appended to a
    // signed message without invalidating the signature.
    "From", "From", "To", "Cc", "Subject", "Date", "Message-ID", "Reply-To", "In-Reply-To", "References",
    "MIME-Version", "Content-Type", "List-Unsubscribe", "List-Unsubscribe-Post",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, sqlx::Type)]
#[sqlx(type_name = "TEXT")]
pub enum Algorithm {
    #[serde(rename = "rsa-sha256")]
    #[sqlx(rename = "rsa-sha256")]
    Rsa,
    #[serde(rename = "ed25519-sha256")]
    #[sqlx(rename = "ed25519-sha256")]
    Ed25519,
}

impl Algorithm {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "rsa-sha256" | "rsa" => Some(Algorithm::Rsa),
            "ed25519-sha256" | "ed25519" => Some(Algorithm::Ed25519),
            _ => None,
        }
    }

    fn dns_key_type(self) -> &'static str {
        match self {
            Algorithm::Rsa => "rsa",
            Algorithm::Ed25519 => "ed25519",
        }
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct DkimKey {
    pub id: i64,
    pub domain_id: i64,
    pub selector: String,
    pub algorithm: Algorithm,
    #[serde(skip)]
    pub private_key: String,
    pub public_key: String,
    pub active: bool,
    pub created_at: i64,
}

impl DkimKey {
    pub fn dns_name(&self, domain: &str) -> String {
        format!("{}._domainkey.{}", self.selector, domain)
    }

    pub fn dns_value(&self) -> String {
        format!("v=DKIM1; k={}; p={}", self.algorithm.dns_key_type(), self.public_key)
    }
}

pub fn is_valid_selector(selector: &str) -> bool {
    !selector.is_empty()
        && selector.len() <= 63
        && !selector.starts_with('-')
        && !selector.ends_with('-')
        && selector.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Adapter exposing the system CSPRNG to the `rsa` crate.
struct SystemRng;

impl rsa::rand_core::RngCore for SystemRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(crate::util::random_bytes())
    }
    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(crate::util::random_bytes())
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use ring::rand::SecureRandom;
        ring::rand::SystemRandom::new().fill(dest).expect("system random number generator failed");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rsa::rand_core::CryptoRng for SystemRng {}

/// Generates a key pair, returning (private key, public key as published in `p=`).
fn generate(algorithm: Algorithm) -> anyhow::Result<(String, String)> {
    match algorithm {
        Algorithm::Rsa => {
            let key = rsa::RsaPrivateKey::new(&mut SystemRng, 2048)?;
            let private = key.to_pkcs8_pem(LineEnding::LF)?.to_string();
            let public = STANDARD.encode(key.to_public_key().to_public_key_der()?.as_bytes());
            Ok((private, public))
        }
        Algorithm::Ed25519 => {
            let pkcs8 = Ed25519Key::generate_pkcs8().map_err(|e| anyhow::anyhow!("ed25519 key generation failed: {e}"))?;
            let key = Ed25519Key::from_pkcs8_der(&pkcs8).map_err(|e| anyhow::anyhow!("invalid generated key: {e}"))?;
            Ok((STANDARD.encode(&pkcs8), STANDARD.encode(key.public_key())))
        }
    }
}

pub async fn create_key(db: &SqlitePool, domain_id: i64, selector: &str, algorithm: Algorithm) -> anyhow::Result<DkimKey> {
    anyhow::ensure!(is_valid_selector(selector), "invalid selector");
    let (private, public) = tokio::task::spawn_blocking(move || generate(algorithm)).await??;
    let id = sqlx::query(
        "INSERT INTO dkim_keys (domain_id, selector, algorithm, private_key, public_key, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(domain_id)
    .bind(selector)
    .bind(algorithm)
    .bind(private)
    .bind(public)
    .bind(now())
    .execute(db)
    .await?
    .last_insert_rowid();
    Ok(sqlx::query_as("SELECT * FROM dkim_keys WHERE id = ?").bind(id).fetch_one(db).await?)
}

pub async fn keys_for_domain(db: &SqlitePool, domain_id: i64) -> sqlx::Result<Vec<DkimKey>> {
    sqlx::query_as("SELECT * FROM dkim_keys WHERE domain_id = ? ORDER BY created_at DESC, id DESC")
        .bind(domain_id)
        .fetch_all(db)
        .await
}

fn sign_with(key: &DkimKey, domain: &str, message: &[u8]) -> anyhow::Result<String> {
    let err = |e: mail_auth::Error| anyhow::anyhow!("DKIM signing failed for selector {}: {e}", key.selector);
    let header = match key.algorithm {
        Algorithm::Rsa => {
            let der = PrivateKeyDer::from_pem_slice(key.private_key.as_bytes())
                .map_err(|e| anyhow::anyhow!("stored DKIM key for selector {} is unreadable: {e}", key.selector))?;
            DkimSigner::from_key(RsaKey::<Sha256>::from_key_der(der).map_err(err)?)
                .domain(domain)
                .selector(&key.selector)
                .headers(SIGNED_HEADERS)
                .sign(message)
                .map_err(err)?
                .to_header()
        }
        Algorithm::Ed25519 => {
            let der = STANDARD.decode(&key.private_key)?;
            DkimSigner::from_key(Ed25519Key::from_pkcs8_der(&der).map_err(err)?)
                .domain(domain)
                .selector(&key.selector)
                .headers(SIGNED_HEADERS)
                .sign(message)
                .map_err(err)?
                .to_header()
        }
    };
    Ok(header)
}

/// A domain's key for sealing forwarded mail (ARC, RFC 8617).
pub enum SealKey {
    Rsa(RsaKey<Sha256>),
    Ed25519(Ed25519Key),
}

pub struct ArcSealKey {
    pub domain: String,
    pub selector: String,
    pub key: SealKey,
}

/// The first active DKIM key of a domain, ready to seal with.
pub async fn arc_key(db: &SqlitePool, domain: &str) -> Option<ArcSealKey> {
    let key: DkimKey = sqlx::query_as("SELECT k.* FROM dkim_keys k JOIN domains d ON d.id = k.domain_id WHERE d.name = ? AND k.active = 1 ORDER BY k.id LIMIT 1").bind(domain).fetch_optional(db).await.ok()??;
    let seal = match key.algorithm {
        Algorithm::Rsa => SealKey::Rsa(RsaKey::<Sha256>::from_key_der(PrivateKeyDer::from_pem_slice(key.private_key.as_bytes()).ok()?).ok()?),
        Algorithm::Ed25519 => SealKey::Ed25519(Ed25519Key::from_pkcs8_der(&STANDARD.decode(&key.private_key).ok()?).ok()?),
    };
    Some(ArcSealKey { domain: domain.to_owned(), selector: key.selector, key: seal })
}

/// Returns `message` with one `DKIM-Signature` header per active key of `domain` prepended.
/// A domain without keys is returned unsigned.
pub async fn sign(db: &SqlitePool, domain: &str, message: &[u8]) -> anyhow::Result<Vec<u8>> {
    let keys: Vec<DkimKey> = sqlx::query_as(
        "SELECT k.* FROM dkim_keys k JOIN domains d ON d.id = k.domain_id WHERE d.name = ? AND k.active = 1 ORDER BY k.id",
    )
    .bind(domain)
    .fetch_all(db)
    .await?;
    let mut out = Vec::with_capacity(message.len() + keys.len() * 600);
    for key in &keys {
        out.extend_from_slice(sign_with(key, domain, message)?.as_bytes());
    }
    out.extend_from_slice(message);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = b"From: alice@example.org\r\nTo: bob@example.net\r\nSubject: Test\r\n\r\nBody\r\n";

    #[test]
    fn selectors() {
        assert!(is_valid_selector("mail2026"));
        assert!(is_valid_selector("key-1"));
        for bad in ["", "-a", "a-", "A", "a.b", "a b", "a;b", &"a".repeat(64)] {
            assert!(!is_valid_selector(bad), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn generates_keys_and_signs_with_every_active_selector() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::open(&dir.path().join("t.db")).await.unwrap();
        sqlx::query("INSERT INTO domains (name, created_at) VALUES ('example.org', 0)").execute(&db).await.unwrap();

        assert_eq!(sign(&db, "example.org", MESSAGE).await.unwrap(), MESSAGE, "no keys: message is unchanged");

        let rsa = create_key(&db, 1, "rsa1", Algorithm::Rsa).await.unwrap();
        let ed = create_key(&db, 1, "ed1", Algorithm::Ed25519).await.unwrap();
        assert!(rsa.private_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(rsa.dns_value().starts_with("v=DKIM1; k=rsa; p=MII"));
        assert_eq!(rsa.dns_name("example.org"), "rsa1._domainkey.example.org");
        assert_eq!(STANDARD.decode(&ed.public_key).unwrap().len(), 32);
        assert!(create_key(&db, 1, "rsa1", Algorithm::Ed25519).await.is_err(), "selectors are unique per domain");
        assert!(create_key(&db, 1, "Bad Selector", Algorithm::Ed25519).await.is_err());

        let signed = String::from_utf8(sign(&db, "example.org", MESSAGE).await.unwrap()).unwrap();
        assert!(signed.ends_with(std::str::from_utf8(MESSAGE).unwrap()));
        assert_eq!(signed.matches("DKIM-Signature:").count(), 2);
        assert!(signed.contains("a=rsa-sha256") && signed.contains("a=ed25519-sha256"));
        assert!(signed.contains("s=rsa1") && signed.contains("s=ed1") && signed.contains("d=example.org"));

        sqlx::query("UPDATE dkim_keys SET active = 0 WHERE selector = 'rsa1'").execute(&db).await.unwrap();
        let signed = String::from_utf8(sign(&db, "example.org", MESSAGE).await.unwrap()).unwrap();
        assert_eq!(signed.matches("DKIM-Signature:").count(), 1);

        // The private key must never be serialized into API responses.
        assert!(!serde_json::to_string(&rsa).unwrap().contains("PRIVATE"));
    }
}
