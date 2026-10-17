//! Encryption at rest for third-party credentials the server has to be able to use again
//! (identity SMTP passwords, LDAP bind password, OAuth client secret, webhook secrets).
//!
//! The key lives in its own file in the data directory, not in the database, so a leaked
//! database dump or backup alone does not reveal those credentials.

use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};

const PREFIX: &str = "v1:";

pub struct SecretBox(LessSafeKey);

impl SecretBox {
    /// Loads the key from `<data_dir>/secret.key`, creating it on first start.
    pub fn load(data_dir: &Path) -> std::io::Result<Self> {
        let path = data_dir.join("secret.key");
        let key = match std::fs::read(&path) {
            Ok(bytes) if bytes.len() == 32 => bytes,
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

    fn from_key(key: &[u8]) -> Self {
        SecretBox(LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).expect("the key is 32 bytes")))
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

    #[test]
    fn key_file_is_created_once() {
        let dir = tempfile::tempdir().unwrap();
        let sealed = SecretBox::load(dir.path()).unwrap().seal("x");
        assert_eq!(SecretBox::load(dir.path()).unwrap().open(&sealed).as_deref(), Some("x"));
        std::fs::write(dir.path().join("secret.key"), b"short").unwrap();
        assert!(SecretBox::load(dir.path()).is_err());
    }
}
