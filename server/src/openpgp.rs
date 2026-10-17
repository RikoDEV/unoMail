//! OpenPGP encryption at rest: a user who uploads their public key gets every incoming
//! message stored encrypted to it (PGP/MIME, RFC 3156). Only the routing headers stay
//! readable; the server, a backup or a stolen disk cannot read the content any more. Mail
//! programs with the private key (Thunderbird, Apple Mail with GPG Suite, K-9/FairEmail with
//! OpenKeychain, ...) open such messages as usual, and so can the web mail in the browser.

use pgp::{
    composed::{ArmorOptions, Deserializable, MessageBuilder, SignedPublicKey, SignedPublicSubKey},
    crypto::sym::SymmetricKeyAlgorithm,
    packet::SignatureType,
    types::KeyDetails,
};
use serde::Serialize;

use crate::{app::App, security::authn::find_header_end, util::random_token};

/// A certificate as shown to its owner.
#[derive(Debug, Clone, Serialize)]
pub struct KeyInfo {
    pub fingerprint: String,
    pub user_ids: Vec<String>,
    pub created_at: i64,
}

/// Parses an armored (or binary) public key and checks that mail can be encrypted to it.
pub fn parse_certificate(data: &[u8]) -> Result<(SignedPublicKey, KeyInfo), String> {
    let (key, _) = SignedPublicKey::from_reader_single(data).map_err(|_| "this is not an OpenPGP public key".to_owned())?;
    key.verify_bindings().map_err(|e| format!("the key's signatures do not verify: {e}"))?;
    if encryption_subkeys(&key).is_empty() {
        return Err("the key has no subkey usable for encryption".into());
    }
    let user_ids = key.details.users.iter().map(|u| String::from_utf8_lossy(u.id.id()).chars().filter(|c| !c.is_control()).collect()).collect();
    let info = KeyInfo { fingerprint: format!("{:X}", key.fingerprint()), user_ids, created_at: i64::from(key.primary_key.created_at().as_secs()) };
    Ok((key, info))
}

/// Subkeys flagged for encryption, not revoked and not expired.
fn encryption_subkeys(key: &SignedPublicKey) -> Vec<&SignedPublicSubKey> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    key.public_subkeys
        .iter()
        .filter(|sub| sub.key.algorithm().can_encrypt())
        .filter(|sub| !sub.signatures.iter().any(|s| s.typ() == Some(SignatureType::SubkeyRevocation)))
        .filter(|sub| {
            let Some(binding) = sub.signatures.iter().rev().find(|s| s.typ() == Some(SignatureType::SubkeyBinding)) else { return false };
            let flags = binding.key_flags();
            let expired = binding.key_expiration_time().is_some_and(|valid| valid.as_secs() > 0 && u64::from(sub.key.created_at().as_secs()) + u64::from(valid.as_secs()) < now);
            (flags.encrypt_comms() || flags.encrypt_storage()) && !expired
        })
        .collect()
}

/// Whether a message is encrypted already (PGP/MIME, inline PGP or S/MIME).
pub fn is_encrypted(raw: &[u8]) -> bool {
    let headers = String::from_utf8_lossy(&raw[..find_header_end(raw).min(raw.len())]).to_ascii_lowercase();
    let unfolded = headers.replace("\r\n\t", " ").replace("\r\n ", " ");
    unfolded.lines().any(|line| {
        line.starts_with("content-type:") && (line.contains("multipart/encrypted") || line.contains("application/pkcs7-mime") || line.contains("application/x-pkcs7-mime"))
    }) || raw.windows(27).take(64 * 1024).any(|w| w == b"-----BEGIN PGP MESSAGE-----")
}

/// Splits a message into the headers that stay outside (routing, addressing, subject) and
/// the MIME entity that gets encrypted (its `Content-*` headers and the body).
fn split(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let end = find_header_end(raw).min(raw.len());
    let (head, body) = raw.split_at(end);
    let mut outer = Vec::with_capacity(head.len());
    let mut inner = Vec::new();
    let text = head;
    let mut start = 0;
    // Header fields, each with its continuation lines.
    let mut fields: Vec<&[u8]> = Vec::new();
    for i in 0..text.len() {
        if text[i] == b'\n' && i + 1 < text.len() && text[i + 1] != b' ' && text[i + 1] != b'\t' {
            fields.push(&text[start..=i]);
            start = i + 1;
        }
    }
    if start < text.len() {
        fields.push(&text[start..]);
    }
    for field in fields {
        let lower = field.iter().take(30).map(u8::to_ascii_lowercase).collect::<Vec<u8>>();
        if lower.starts_with(b"content-") {
            inner.extend_from_slice(field);
        } else if !lower.starts_with(b"mime-version:") && field != b"\r\n" && field != b"\n" {
            outer.extend_from_slice(field);
        }
    }
    if inner.is_empty() {
        inner.extend_from_slice(b"Content-Type: text/plain; charset=us-ascii\r\n");
    }
    // The blank line between the entity's headers and its body.
    let body = body.strip_prefix(b"\r\n").or_else(|| body.strip_prefix(b"\n")).unwrap_or(body);
    inner.extend_from_slice(b"\r\n");
    inner.extend_from_slice(body);
    (outer, inner)
}

/// Encrypts a message to `key` as PGP/MIME, keeping its outer headers.
pub fn encrypt_message(key: &SignedPublicKey, raw: &[u8]) -> Result<Vec<u8>, String> {
    let subkeys = encryption_subkeys(key);
    if subkeys.is_empty() {
        return Err("no usable encryption subkey".into());
    }
    let (outer, inner) = split(raw);
    let mut rng = rand::thread_rng();
    let mut builder = MessageBuilder::from_bytes("", inner).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    for subkey in subkeys {
        builder.encrypt_to_key(&mut rng, subkey).map_err(|e| e.to_string())?;
    }
    let armored = builder.to_armored_string(&mut rng, ArmorOptions::default()).map_err(|e| e.to_string())?;
    let boundary = format!("pgp-{}", random_token());
    let mut out = outer;
    out.extend_from_slice(
        format!(
            "MIME-Version: 1.0\r\n\
             Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{boundary}\"\r\n\
             \r\n\
             This is an OpenPGP/MIME encrypted message (RFC 3156).\r\n\
             --{boundary}\r\n\
             Content-Type: application/pgp-encrypted\r\n\
             Content-Description: PGP/MIME version identification\r\n\
             \r\n\
             Version: 1\r\n\
             \r\n\
             --{boundary}\r\n\
             Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\
             Content-Description: OpenPGP encrypted message\r\n\
             Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\
             \r\n\
             {armored}\r\n\
             --{boundary}--\r\n",
            armored = armored.replace("\r\n", "\n").replace('\n', "\r\n").trim_end()
        )
        .as_bytes(),
    );
    Ok(out)
}

/// The message as it should be stored for `account_id`: encrypted when the account asked for
/// it, unchanged otherwise (or when it is encrypted already).
pub async fn protect(app: &App, account_id: i64, raw: Vec<u8>) -> Vec<u8> {
    let armored: Option<String> = sqlx::query_scalar("SELECT public_key FROM pgp_keys WHERE account_id = ? AND encrypt_incoming = 1").bind(account_id).fetch_optional(&app.db).await.ok().flatten();
    let Some(armored) = armored else { return raw };
    if is_encrypted(&raw) {
        return raw;
    }
    let raw = std::sync::Arc::new(raw);
    let input = raw.clone();
    let result = tokio::task::spawn_blocking(move || {
        let (key, _) = parse_certificate(armored.as_bytes())?;
        encrypt_message(&key, &input)
    })
    .await;
    match result {
        Ok(Ok(encrypted)) => encrypted,
        // Never lose mail over a key problem: it is stored as it came.
        Ok(Err(err)) => {
            tracing::warn!(account_id, %err, "could not encrypt a message to the account's OpenPGP key");
            std::sync::Arc::unwrap_or_clone(raw)
        }
        Err(err) => {
            tracing::warn!(account_id, %err, "OpenPGP encryption task failed");
            std::sync::Arc::unwrap_or_clone(raw)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use pgp::composed::{EncryptionCaps, KeyType, Message, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder};

    use super::*;

    #[test]
    fn hostile_messages_split_without_panicking() {
        for raw in crate::fuzzing::inputs(8, 3000, 16) {
            let _ = is_encrypted(&raw);
            let (outer, inner) = split(&raw);
            assert!(outer.len() + inner.len() <= raw.len() + 64);
        }
    }


    /// A fresh key pair: (secret key, armored public key).
    pub fn key_pair(uid: &str) -> (SignedSecretKey, String) {
        let mut encryption = SubkeyParamsBuilder::default();
        encryption.key_type(KeyType::ECDH(pgp::crypto::ecc_curve::ECCCurve::Curve25519Legacy)).can_sign(false).can_encrypt(EncryptionCaps::All).can_authenticate(false);
        let mut params = SecretKeyParamsBuilder::default();
        params.key_type(KeyType::Ed25519Legacy).can_certify(true).can_sign(true).can_encrypt(EncryptionCaps::None).primary_user_id(uid.into()).subkeys(vec![encryption.build().unwrap()]);
        let secret = params.build().unwrap().generate(rand::thread_rng()).unwrap();
        let public = SignedPublicKey::from(secret.clone()).to_armored_string(ArmorOptions::default()).unwrap();
        (secret, public)
    }

    #[test]
    fn messages_are_wrapped_as_pgp_mime_and_open_with_the_private_key() {
        let (secret, public) = key_pair("Bob <bob@example.org>");
        let (key, info) = parse_certificate(public.as_bytes()).unwrap();
        assert_eq!(info.user_ids, ["Bob <bob@example.org>"]);
        assert_eq!(info.fingerprint.len(), 40);
        assert!(parse_certificate(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nnope\r\n").is_err());

        let raw = b"Received: from x\r\nFrom: Alice <alice@example.net>\r\nTo: bob@example.org\r\nSubject: Plans\r\nMIME-Version: 1.0\r\nContent-Type: text/plain;\r\n charset=utf-8\r\n\r\nThe secret plans\r\n";
        assert!(!is_encrypted(raw));
        let encrypted = encrypt_message(&key, raw).unwrap();
        let text = String::from_utf8(encrypted.clone()).unwrap();
        assert!(text.starts_with("Received: from x\r\nFrom: Alice <alice@example.net>\r\nTo: bob@example.org\r\nSubject: Plans\r\nMIME-Version: 1.0\r\nContent-Type: multipart/encrypted;"), "{text}");
        assert!(!text.contains("secret plans") && !text.contains("charset=utf-8"));
        assert!(is_encrypted(&encrypted), "never encrypted twice");
        let parsed = mail_parser::MessageParser::default().parse(&encrypted).unwrap();
        assert_eq!(parsed.subject(), Some("Plans"));

        let armored = text.split("-----BEGIN PGP MESSAGE-----").nth(1).unwrap().split("-----END PGP MESSAGE-----").next().unwrap();
        let armored = format!("-----BEGIN PGP MESSAGE-----{armored}-----END PGP MESSAGE-----\r\n");
        let (message, _) = Message::from_armor(armored.as_bytes()).unwrap();
        let mut decrypted = message.decrypt(&"".into(), &secret).unwrap();
        if decrypted.is_compressed() {
            decrypted = decrypted.decompress().unwrap();
        }
        let inner = String::from_utf8(decrypted.as_data_vec().unwrap()).unwrap();
        assert_eq!(inner, "Content-Type: text/plain;\r\n charset=utf-8\r\n\r\nThe secret plans\r\n");
    }
}
