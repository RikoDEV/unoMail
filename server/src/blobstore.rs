//! Where message contents live: a directory on disk or an S3 bucket, optionally encrypted.
//!
//! Blobs are addressed by the SHA-256 of their plaintext. With encryption at rest, each one
//! is sealed with ChaCha20-Poly1305 under a key kept in `<data>/blob.key`, bound to its
//! address, so a copy of the message store (a leaked bucket, stolen blob files) does not reveal
//! the messages without the key. The database is not covered: it holds subjects, addresses,
//! previews and the full-text search index in plaintext (backups seal their copy of it).
//! Blobs stored before encryption was switched on stay readable.

use std::path::{Path, PathBuf};

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};

use crate::{
    s3::{S3, S3Error},
    store::StoreError,
};

const MAGIC: &[u8] = b"UNOBLOB1";

pub enum Backend {
    Disk(PathBuf),
    S3(S3),
}

pub struct Blobs {
    backend: Backend,
    cipher: Option<LessSafeKey>,
    /// New blobs are sealed (otherwise the key only opens older ones).
    seal_new: bool,
}

/// Loads the encryption key from `<data_dir>/blob.key`, creating it on first use.
pub fn load_key(data_dir: &Path) -> std::io::Result<[u8; 32]> {
    let path = data_dir.join("blob.key");
    match std::fs::read(&path) {
        Ok(bytes) => bytes.try_into().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "blob.key must be exactly 32 bytes")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let key = crate::util::random_bytes::<32>();
            std::fs::write(&path, key)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(key)
        }
        Err(err) => Err(err),
    }
}

fn s3_error(err: S3Error) -> StoreError {
    match err {
        S3Error::NotFound => StoreError::NotFound,
        S3Error::Request(message) => StoreError::Io(std::io::Error::other(message)),
    }
}

/// `aa/bb/<hash>`: the layout shared by the disk store, S3 and backups.
pub fn relative_path(hash: &str) -> String {
    format!("{}/{}/{hash}", &hash[..2], &hash[2..4])
}

impl Blobs {
    pub fn new(backend: Backend, key: Option<[u8; 32]>) -> Self {
        let cipher = key.map(|key| LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).expect("the key is 32 bytes")));
        let seal_new = cipher.is_some();
        Blobs { backend, cipher, seal_new }
    }

    /// Keeps the key for reading what was sealed before, but stores new blobs as they are.
    pub fn read_only_key(mut self) -> Self {
        self.seal_new = false;
        self
    }

    pub fn encrypted(&self) -> bool {
        self.seal_new
    }

    pub fn describe(&self) -> String {
        match &self.backend {
            Backend::Disk(dir) => dir.display().to_string(),
            Backend::S3(s3) => s3.cfg.describe(),
        }
    }

    fn disk_path(dir: &Path, hash: &str) -> PathBuf {
        dir.join(&hash[..2]).join(&hash[2..4]).join(hash)
    }

    fn object_name(hash: &str) -> String {
        format!("blobs/{}", relative_path(hash))
    }

    /// What is written for `data`: sealed when encryption is on.
    pub fn seal(&self, hash: &str, data: &[u8]) -> Vec<u8> {
        let Some(cipher) = self.cipher.as_ref().filter(|_| self.seal_new) else { return data.to_vec() };
        let nonce = crate::util::random_bytes::<NONCE_LEN>();
        let mut sealed = data.to_vec();
        cipher
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(hash.as_bytes()), &mut sealed)
            .expect("in-memory encryption does not fail");
        [MAGIC, &nonce, &sealed].concat()
    }

    /// The plaintext of what was stored for `hash`.
    pub fn open(&self, hash: &str, stored: Vec<u8>) -> Result<Vec<u8>, StoreError> {
        let Some(rest) = stored.strip_prefix(MAGIC) else { return Ok(stored) };
        let cipher = self.cipher.as_ref().ok_or(StoreError::Invalid("this message is encrypted, but no blob.key is configured"))?;
        if rest.len() < NONCE_LEN {
            return Err(StoreError::Invalid("stored message is truncated"));
        }
        let (nonce, sealed) = rest.split_at(NONCE_LEN);
        let mut buffer = sealed.to_vec();
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| StoreError::Invalid("stored message is damaged"))?;
        let plain = cipher.open_in_place(nonce, Aad::from(hash.as_bytes()), &mut buffer).map_err(|_| StoreError::Invalid("stored message cannot be decrypted (wrong blob.key?)"))?;
        Ok(plain.to_vec())
    }

    /// Stores the blob unless it is already there.
    pub async fn put(&self, hash: &str, data: &[u8]) -> Result<(), StoreError> {
        if self.exists(hash).await? {
            return Ok(());
        }
        let stored = self.seal(hash, data);
        self.put_stored(hash, stored).await
    }

    /// Writes stored bytes as they are (sealed or not), as a restore does.
    pub async fn put_stored(&self, hash: &str, stored: Vec<u8>) -> Result<(), StoreError> {
        match &self.backend {
            Backend::Disk(dir) => {
                let path = Self::disk_path(dir, hash);
                let parent = path.parent().expect("blob path has a parent");
                tokio::fs::create_dir_all(parent).await?;
                let tmp = parent.join(format!(".{}.tmp", crate::util::random_token()));
                tokio::fs::write(&tmp, &stored).await?;
                if let Err(err) = tokio::fs::rename(&tmp, &path).await {
                    let _ = tokio::fs::remove_file(&tmp).await;
                    return Err(err.into());
                }
                Ok(())
            }
            Backend::S3(s3) => s3.put(&Self::object_name(hash), stored).await.map_err(s3_error),
        }
    }

    pub async fn exists(&self, hash: &str) -> Result<bool, StoreError> {
        match &self.backend {
            Backend::Disk(dir) => Ok(tokio::fs::try_exists(Self::disk_path(dir, hash)).await?),
            Backend::S3(s3) => s3.exists(&Self::object_name(hash)).await.map_err(s3_error),
        }
    }

    /// The bytes as stored (sealed when encryption is on), for backups.
    pub async fn get_stored(&self, hash: &str) -> Result<Vec<u8>, StoreError> {
        match &self.backend {
            Backend::Disk(dir) => match tokio::fs::read(Self::disk_path(dir, hash)).await {
                Ok(data) => Ok(data),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(StoreError::NotFound),
                Err(e) => Err(e.into()),
            },
            Backend::S3(s3) => s3.get(&Self::object_name(hash)).await.map_err(s3_error),
        }
    }

    pub async fn get(&self, hash: &str) -> Result<Vec<u8>, StoreError> {
        let stored = self.get_stored(hash).await?;
        self.open(hash, stored)
    }

    /// The first `limit` bytes. A sealed blob has to be read whole to be authenticated.
    pub async fn head(&self, hash: &str, limit: usize) -> Result<Vec<u8>, StoreError> {
        let partial = match &self.backend {
            Backend::Disk(dir) => {
                use tokio::io::AsyncReadExt;
                let file = match tokio::fs::File::open(Self::disk_path(dir, hash)).await {
                    Ok(file) => file,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(StoreError::NotFound),
                    Err(e) => return Err(e.into()),
                };
                let mut data = Vec::with_capacity(limit.min(64 * 1024));
                file.take(limit.max(MAGIC.len()) as u64).read_to_end(&mut data).await?;
                data
            }
            Backend::S3(s3) => s3.get_head(&Self::object_name(hash), limit.max(MAGIC.len())).await.map_err(s3_error)?,
        };
        if partial.starts_with(MAGIC) {
            let mut whole = self.get(hash).await?;
            whole.truncate(limit);
            return Ok(whole);
        }
        let mut partial = partial;
        partial.truncate(limit);
        Ok(partial)
    }

    pub async fn remove(&self, hash: &str) -> Result<(), StoreError> {
        match &self.backend {
            Backend::Disk(dir) => match tokio::fs::remove_file(Self::disk_path(dir, hash)).await {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.into()),
            },
            Backend::S3(s3) => s3.delete(&Self::object_name(hash)).await.map_err(s3_error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sealed_blobs_round_trip_and_stay_bound_to_their_address() {
        let dir = tempfile::tempdir().unwrap();
        let plain = Blobs::new(Backend::Disk(dir.path().to_owned()), None);
        let sealed = Blobs::new(Backend::Disk(dir.path().to_owned()), Some([7; 32]));
        let hash = crate::util::sha256_hex(b"old message");
        plain.put(&hash, b"old message").await.unwrap();
        assert_eq!(sealed.get(&hash).await.unwrap(), b"old message", "plaintext from before stays readable");

        let data = b"Subject: secret\r\n\r\nthe body";
        let hash = crate::util::sha256_hex(data);
        sealed.put(&hash, data).await.unwrap();
        let on_disk = std::fs::read(dir.path().join(&hash[..2]).join(&hash[2..4]).join(&hash)).unwrap();
        assert!(on_disk.starts_with(MAGIC) && !on_disk.windows(6).any(|w| w == b"secret"));
        assert_eq!(sealed.get(&hash).await.unwrap(), data);
        assert_eq!(sealed.head(&hash, 7).await.unwrap(), b"Subject");
        assert!(matches!(plain.get(&hash).await, Err(StoreError::Invalid(_))), "unreadable without the key");
        let wrong_key = Blobs::new(Backend::Disk(dir.path().to_owned()), Some([8; 32]));
        assert!(matches!(wrong_key.get(&hash).await, Err(StoreError::Invalid(_))));
        // Moved to another address, the ciphertext no longer opens.
        let other = crate::util::sha256_hex(b"x");
        sealed.put_stored(&other, on_disk).await.unwrap();
        assert!(sealed.get(&other).await.is_err());
        sealed.remove(&hash).await.unwrap();
        assert!(matches!(sealed.get(&hash).await, Err(StoreError::NotFound)));
    }
}
