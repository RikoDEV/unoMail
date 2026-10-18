//! Encryption at rest for third-party credentials the server has to be able to use again
//! (identity SMTP passwords, LDAP bind password, OAuth client secret, webhook secrets) and
//! long-lived signing keys and secrets (DKIM and TLS private keys, PGP private keys, the SRS
//! and list HMAC secrets).
//!
//! The key lives in its own file in the data directory, not in the database, so a leaked
//! database dump or backup alone does not reveal those credentials. A second key derived from
//! it keys the digests of short secrets (recovery codes) that would otherwise be guessed
//! offline from a dump.

use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};

const PREFIX: &str = "v1:";

pub struct SecretBox(LessSafeKey, Vec<u8>);

impl SecretBox {
    /// Loads the key from `<data_dir>/secret.key`, creating it on first start.
    pub fn load(data_dir: &Path) -> std::io::Result<Self> {
        let path = data_dir.join("secret.key");
        let key = match std::fs::read(&path) {
            Ok(bytes) if bytes.len() == 32 => {
                restrict_key_file(&path)?;
                bytes
            }
            Ok(_) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "secret.key must be exactly 32 bytes")),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let bytes = crate::util::random_bytes::<32>().to_vec();
                std::fs::write(&path, &bytes)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                }
                bytes
            }
            Err(err) => return Err(err),
        };
        Ok(Self::from_key(&key))
    }

    pub(crate) fn from_key(key: &[u8]) -> Self {
        let mac_key = crate::util::hmac_sha256(key, b"unomail digest key");
        SecretBox(LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).expect("the key is 32 bytes")), mac_key)
    }

    /// A keyed digest (HMAC-SHA256, hex) of `data`: comparable, but useless without the key.
    pub fn digest(&self, data: &[u8]) -> String {
        hex::encode(crate::util::hmac_sha256(&self.1, data))
    }

    /// Encrypts `plaintext`. An empty value stays empty so "no password" needs no special case.
    pub fn seal(&self, plaintext: &str) -> String {
        if plaintext.is_empty() {
            return String::new();
        }
        let nonce = crate::util::random_bytes::<NONCE_LEN>();
        let mut data = plaintext.as_bytes().to_vec();
        self.0
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut data)
            .expect("sealing with a valid key cannot fail");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&data);
        format!("{PREFIX}{}", STANDARD_NO_PAD.encode(out))
    }

    /// Decrypts a value produced by `seal`. Returns `None` for anything else, including values
    /// sealed with a different key.
    pub fn open(&self, sealed: &str) -> Option<String> {
        if sealed.is_empty() {
            return Some(String::new());
        }
        let mut data = STANDARD_NO_PAD.decode(sealed.strip_prefix(PREFIX)?).ok()?;
        if data.len() < NONCE_LEN {
            return None;
        }
        let nonce: [u8; NONCE_LEN] = data[..NONCE_LEN].try_into().ok()?;
        let plain = self.0.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut data[NONCE_LEN..]).ok()?;
        String::from_utf8(plain.to_vec()).ok()
    }
}

/// Makes a key file readable by its owner only, repairing looser permissions (a copy restored
/// with the wrong mode) instead of carrying on with a key others can read.
pub fn restrict_key_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            tracing::warn!(path = %path.display(), mode = format!("{:o}", mode & 0o777), "key file was readable by others; restricting it to 0600");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Columns that hold a sealed value, as (select plain-text rows, update one row) statements;
/// rows written before they were sealed are sealed in place.
const SEALED_COLUMNS: &[(&str, &str)] = &[
    ("SELECT rowid, private_key FROM dkim_keys WHERE private_key != '' AND private_key NOT LIKE 'v1:%'", "UPDATE dkim_keys SET private_key = ? WHERE rowid = ?"),
    ("SELECT rowid, key_pem FROM certificates WHERE key_pem != '' AND key_pem NOT LIKE 'v1:%'", "UPDATE certificates SET key_pem = ? WHERE rowid = ?"),
    ("SELECT rowid, private_key FROM pgp_keys WHERE private_key != '' AND private_key NOT LIKE 'v1:%'", "UPDATE pgp_keys SET private_key = ? WHERE rowid = ?"),
];
/// Settings that hold a sealed value.
pub const SEALED_SETTINGS: &[&str] = &["srs.secret", "lists.secret"];

/// Seals any value in a sealed column or setting still stored in plain text (written by an
/// older version, or restored from an old backup). Runs at startup; a no-op once done.
pub async fn seal_plaintext(db: &sqlx::SqlitePool, secrets: &SecretBox) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    let mut sealed = 0usize;
    for (select, update) in SEALED_COLUMNS {
        let rows: Vec<(i64, String)> = sqlx::query_as(*select).fetch_all(&mut *tx).await?;
        for (rowid, plain) in rows {
            sqlx::query(*update).bind(secrets.seal(&plain)).bind(rowid).execute(&mut *tx).await?;
            sealed += 1;
        }
    }
    for key in SEALED_SETTINGS {
        let plain: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key = ? AND value != '' AND value NOT LIKE 'v1:%'")
            .bind(key)
            .fetch_optional(&mut *tx)
            .await?;
        if let Some(plain) = plain {
            sqlx::query("UPDATE settings SET value = ? WHERE key = ?").bind(secrets.seal(&plain)).bind(key).execute(&mut *tx).await?;
            sealed += 1;
        }
    }
    tx.commit().await?;
    if sealed > 0 {
        tracing::info!(sealed, "sealed stored keys and secrets with secret.key");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper_detection() {
        let secrets = SecretBox::from_key(&[7u8; 32]);
        let sealed = secrets.seal("hunter2 ✓");
        assert!(sealed.starts_with("v1:") && !sealed.contains("hunter2"));
        assert_ne!(sealed, secrets.seal("hunter2 ✓"), "every seal uses a fresh nonce");
        assert_eq!(secrets.open(&sealed).as_deref(), Some("hunter2 ✓"));
        assert_eq!(secrets.open("").as_deref(), Some(""));
        assert_eq!(secrets.seal(""), "");

        let mut tampered = sealed.clone();
        tampered.pop();
        tampered.push(if sealed.ends_with('A') { 'B' } else { 'A' });
        assert_eq!(secrets.open(&tampered), None);
        assert_eq!(SecretBox::from_key(&[8u8; 32]).open(&sealed), None, "a different key cannot open it");
        assert_eq!(secrets.open("plain text"), None);
    }

    #[tokio::test]
    async fn plain_text_keys_are_sealed_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::open(&dir.path().join("t.db")).await.unwrap();
        let secrets = SecretBox::from_key(&[9u8; 32]);
        sqlx::query("INSERT INTO settings (key, value) VALUES ('srs.secret', 'legacy')").execute(&db).await.unwrap();
        seal_plaintext(&db, &secrets).await.unwrap();
        let stored = crate::db::get_setting(&db, "srs.secret").await.unwrap().unwrap();
        assert!(stored.starts_with(PREFIX));
        assert_eq!(crate::db::get_or_create_secret(&db, &secrets, "srs.secret").await.unwrap(), "legacy");
        seal_plaintext(&db, &secrets).await.unwrap();
        assert_eq!(crate::db::get_setting(&db, "srs.secret").await.unwrap().unwrap(), stored, "sealing twice is a no-op");
        let fresh = crate::db::get_or_create_secret(&db, &secrets, "lists.secret").await.unwrap();
        assert!(!crate::db::get_setting(&db, "lists.secret").await.unwrap().unwrap().contains(&fresh));
        assert!(crate::db::get_or_create_secret(&db, &SecretBox::from_key(&[1u8; 32]), "srs.secret").await.is_err());
    }

    #[test]
    fn key_file_is_created_once() {
        let dir = tempfile::tempdir().unwrap();
        let sealed = SecretBox::load(dir.path()).unwrap().seal("x");
        assert_eq!(SecretBox::load(dir.path()).unwrap().open(&sealed).as_deref(), Some("x"));
        std::fs::write(dir.path().join("secret.key"), b"short").unwrap();
        assert!(SecretBox::load(dir.path()).is_err());
    }
}
