//! Second sign-in factors and app passwords.
//!
//! - Authenticator apps: time-based one-time passwords (TOTP, RFC 6238; HMAC-SHA1, 6 digits,
//!   30 seconds), the secret sealed at rest, every code accepted once.
//! - Passkeys and security keys: WebAuthn (Level 2) registration and assertion, verified here
//!   without attestation (`"none"`): ES256, EdDSA and RS256 keys.
//! - Recovery codes: ten single-use codes, stored hashed.
//! - App passwords: random passwords for one program each, accepted for the protocols they
//!   were made for and never for the web sign-in.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use parking_lot::Mutex;
use ring::{hmac, signature};
use serde_json::Value;
use sqlx::SqlitePool;

use crate::{
    secretbox::SecretBox,
    util::{now, random_bytes, sha256, sha256_hex},
};

// --- TOTP --------------------------------------------------------------------------------------

const STEP: i64 = 30;
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in data {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            out.push(BASE32[((buffer >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn unbase32(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '=' && *c != '-') {
        let value = BASE32.iter().position(|b| *b as char == c.to_ascii_uppercase())? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            out.push((buffer >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

/// The code an authenticator shows for `step` (RFC 4226 HOTP with the time step as counter).
pub fn code_at(secret: &[u8], step: i64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let digest = hmac::sign(&key, &step.to_be_bytes());
    let bytes = digest.as_ref();
    let offset = (bytes[19] & 0x0f) as usize;
    let value = (u32::from(bytes[offset]) & 0x7f) << 24 | u32::from(bytes[offset + 1]) << 16 | u32::from(bytes[offset + 2]) << 8 | u32::from(bytes[offset + 3]);
    format!("{:06}", value % 1_000_000)
}

/// The time step a code is valid for, allowing one step of clock drift either way.
pub fn matching_step(secret: &[u8], code: &str, at: i64) -> Option<i64> {
    let code: String = code.chars().filter(char::is_ascii_digit).collect();
    if code.len() != 6 {
        return None;
    }
    let current = at.div_euclid(STEP);
    (current - 1..=current + 1).find(|step| crate::util::ct_eq(code_at(secret, *step).as_bytes(), code.as_bytes()))
}

pub fn new_totp_secret() -> String {
    base32(&random_bytes::<20>())
}

/// The address an authenticator app reads from the QR code.
pub fn otpauth_uri(issuer: &str, email: &str, secret: &str) -> String {
    let encode = |s: &str| s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~@".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect::<String>();
    format!("otpauth://totp/{}:{}?secret={secret}&issuer={}&algorithm=SHA1&digits=6&period=30", encode(issuer), encode(email), encode(issuer))
}

// --- Recovery codes ---------------------------------------------------------------------------

const RECOVERY_CODES: usize = 10;

fn normalize_code(code: &str) -> String {
    code.chars().filter(char::is_ascii_alphanumeric).collect::<String>().to_ascii_lowercase()
}

/// How a recovery code is stored: keyed with the server's secret, so that a copy of the
/// database alone is no help in guessing the codes.
fn code_digest(secrets: &SecretBox, code: &str) -> String {
    secrets.digest(format!("recovery:{}", normalize_code(code)).as_bytes())
}

/// Makes new recovery codes (replacing the old ones) and returns them for showing once.
pub async fn new_recovery_codes(db: &SqlitePool, secrets: &SecretBox, account_id: i64) -> sqlx::Result<Vec<String>> {
    // 80 bits each: out of reach of guessing even with the digests in hand.
    let codes: Vec<String> = (0..RECOVERY_CODES)
        .map(|_| {
            let raw = base32(&random_bytes::<10>()).to_ascii_lowercase();
            format!("{}-{}-{}-{}", &raw[..4], &raw[4..8], &raw[8..12], &raw[12..16])
        })
        .collect();
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM recovery_codes WHERE account_id = ?").bind(account_id).execute(&mut *tx).await?;
    for code in &codes {
        sqlx::query("INSERT INTO recovery_codes (account_id, code_hash) VALUES (?, ?)").bind(account_id).bind(code_digest(secrets, code)).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(codes)
}

/// Uses up a recovery code; true when it was valid and unused. Codes made before they were
/// keyed (plain SHA-256) still work until they are replaced.
pub async fn use_recovery_code(db: &SqlitePool, secrets: &SecretBox, account_id: i64, code: &str) -> sqlx::Result<bool> {
    let used = sqlx::query("UPDATE recovery_codes SET used_at = ? WHERE account_id = ? AND code_hash IN (?, ?) AND used_at IS NULL")
        .bind(now())
        .bind(account_id)
        .bind(code_digest(secrets, code))
        .bind(sha256_hex(normalize_code(code).as_bytes()))
        .execute(db)
        .await?;
    Ok(used.rows_affected() == 1)
}

pub async fn recovery_codes_left(db: &SqlitePool, account_id: i64) -> sqlx::Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM recovery_codes WHERE account_id = ? AND used_at IS NULL").bind(account_id).fetch_one(db).await
}

// --- What an account has set up ---------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Factors {
    pub totp: bool,
    pub passkeys: i64,
    pub recovery_codes: i64,
}

impl Factors {
    pub fn enabled(&self) -> bool {
        self.totp || self.passkeys > 0
    }
}

pub async fn factors(db: &SqlitePool, account_id: i64) -> sqlx::Result<Factors> {
    let (totp, passkeys, recovery): (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM totp_secrets WHERE account_id = ?1 AND enabled = 1),
                (SELECT COUNT(*) FROM passkeys WHERE account_id = ?1),
                (SELECT COUNT(*) FROM recovery_codes WHERE account_id = ?1 AND used_at IS NULL)",
    )
    .bind(account_id)
    .fetch_one(db)
    .await?;
    Ok(Factors { totp: totp > 0, passkeys, recovery_codes: recovery })
}

/// Checks an authenticator code for an account and remembers it as used.
pub async fn check_totp(db: &SqlitePool, secrets: &crate::secretbox::SecretBox, account_id: i64, code: &str) -> sqlx::Result<bool> {
    let row: Option<(String, i64)> = sqlx::query_as("SELECT secret, last_step FROM totp_secrets WHERE account_id = ? AND enabled = 1").bind(account_id).fetch_optional(db).await?;
    let Some((sealed, last_step)) = row else { return Ok(false) };
    let Some(secret) = secrets.open(&sealed).and_then(|text| unbase32(&text)) else { return Ok(false) };
    match matching_step(&secret, code, now()) {
        // A code seen before (or an older one) does not count twice.
        Some(step) if step > last_step => {
            let claimed = sqlx::query("UPDATE totp_secrets SET last_step = ? WHERE account_id = ? AND last_step < ?").bind(step).bind(account_id).bind(step).execute(db).await?;
            Ok(claimed.rows_affected() == 1)
        }
        _ => Ok(false),
    }
}

// --- App passwords ----------------------------------------------------------------------------

/// What an app password may be used for.
pub const SCOPES: [&str; 3] = ["mail", "dav", "jmap"];

/// Four groups of four lowercase letters, as shown to the user.
pub fn new_app_password() -> String {
    let bytes = random_bytes::<16>();
    let letters: String = bytes.iter().map(|b| (b'a' + b % 26) as char).collect();
    format!("{} {} {} {}", &letters[..4], &letters[4..8], &letters[8..12], &letters[12..])
}

/// The form an app password is compared in: the letters only. `None` when the input cannot
/// be one, so ordinary passwords are not looked up as app passwords.
pub fn normalize_app_password(input: &str) -> Option<String> {
    let letters: String = input.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>().to_ascii_lowercase();
    (letters.len() == 16 && letters.bytes().all(|b| b.is_ascii_lowercase())).then_some(letters)
}

pub fn app_password_hash(normalized: &str) -> String {
    sha256_hex(format!("unomail-app-password\0{normalized}").as_bytes())
}

// --- CBOR (RFC 8949), as far as WebAuthn needs it ----------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Cbor {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
    Null,
}

impl Cbor {
    pub fn get(&self, key: i128) -> Option<&Cbor> {
        match self {
            Cbor::Map(entries) => entries.iter().find(|(k, _)| *k == Cbor::Int(key)).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn get_text(&self, key: &str) -> Option<&Cbor> {
        match self {
            Cbor::Map(entries) => entries.iter().find(|(k, _)| matches!(k, Cbor::Text(t) if t == key)).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn bytes(&self) -> Option<&[u8]> {
        if let Cbor::Bytes(b) = self { Some(b) } else { None }
    }

    pub fn int(&self) -> Option<i128> {
        if let Cbor::Int(n) = self { Some(*n) } else { None }
    }
}

/// Decodes one CBOR item from the start of `data`; returns it and the bytes it took.
pub fn cbor(data: &[u8]) -> Option<(Cbor, usize)> {
    decode(data, 0)
}

fn decode(data: &[u8], depth: usize) -> Option<(Cbor, usize)> {
    if depth > 16 {
        return None;
    }
    let first = *data.first()?;
    let (major, info) = (first >> 5, first & 31);
    let (argument, mut used): (u64, usize) = match info {
        0..=23 => (u64::from(info), 1),
        24 => (u64::from(*data.get(1)?), 2),
        25 => (u64::from(u16::from_be_bytes(data.get(1..3)?.try_into().ok()?)), 3),
        26 => (u64::from(u32::from_be_bytes(data.get(1..5)?.try_into().ok()?)), 5),
        27 => (u64::from_be_bytes(data.get(1..9)?.try_into().ok()?), 9),
        // Indefinite lengths and reserved values never occur in WebAuthn structures.
        _ => return None,
    };
    // A length can never exceed what is left (each element takes at least a byte).
    let length = || usize::try_from(argument).ok().filter(|n| *n <= data.len());
    let item = match major {
        0 => Cbor::Int(i128::from(argument)),
        1 => Cbor::Int(-1 - i128::from(argument)),
        2 | 3 => {
            let length = length()?;
            let bytes = data.get(used..used + length)?.to_vec();
            used += length;
            if major == 2 { Cbor::Bytes(bytes) } else { Cbor::Text(String::from_utf8(bytes).ok()?) }
        }
        4 => {
            let length = length()?;
            let mut items = Vec::with_capacity(length.min(64));
            for _ in 0..length {
                let (item, n) = decode(data.get(used..)?, depth + 1)?;
                items.push(item);
                used += n;
            }
            Cbor::Array(items)
        }
        5 => {
            let length = length()?;
            let mut entries = Vec::with_capacity(length.min(64));
            for _ in 0..length {
                let (key, n) = decode(data.get(used..)?, depth + 1)?;
                used += n;
                let (value, m) = decode(data.get(used..)?, depth + 1)?;
                used += m;
                entries.push((key, value));
            }
            Cbor::Map(entries)
        }
        7 => match info {
            20 => Cbor::Bool(false),
            21 => Cbor::Bool(true),
            22 | 23 => Cbor::Null,
            _ => return None,
        },
        _ => return None,
    };
    Some((item, used))
}

// --- WebAuthn ---------------------------------------------------------------------------------

/// The site passkeys are bound to: the host the web client is reached at.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    pub id: String,
    pub origin: String,
}

impl RelyingParty {
    /// From the public address of the web client. Passkeys need a name, not an IP address.
    pub fn from_url(public_url: &str) -> Option<Self> {
        let url = reqwest::Url::parse(public_url).ok()?;
        let host = url.host_str()?.to_ascii_lowercase();
        if host.parse::<std::net::IpAddr>().is_ok() || host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        Some(RelyingParty { origin: url.origin().ascii_serialization(), id: host })
    }
}

/// What a client data JSON must say, and the challenge it must carry.
fn check_client_data(raw: &[u8], kind: &str, challenge: &[u8], rp: &RelyingParty) -> Result<(), &'static str> {
    let data: Value = serde_json::from_slice(raw).map_err(|_| "unreadable client data")?;
    if data["type"] != kind {
        return Err("wrong ceremony");
    }
    let sent = data["challenge"].as_str().and_then(|c| URL_SAFE_NO_PAD.decode(c).ok()).ok_or("no challenge")?;
    if !crate::util::ct_eq(&sent, challenge) {
        return Err("the challenge does not match");
    }
    if data["origin"] != rp.origin.as_str() {
        return Err("the request comes from another site");
    }
    if data["crossOrigin"] == Value::Bool(true) {
        return Err("cross-origin requests are not accepted");
    }
    Ok(())
}

/// Authenticator data flags (WebAuthn section 6.1).
const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
const FLAG_BACKED_UP: u8 = 0x10;
const FLAG_ATTESTED: u8 = 0x40;

/// Facts from authenticator data (WebAuthn section 6.1).
struct AuthenticatorData<'a> {
    flags: u8,
    sign_count: u32,
    /// Attested credential data and extensions, if present.
    rest: &'a [u8],
}

impl AuthenticatorData<'_> {
    fn user_verified(&self) -> bool {
        self.flags & FLAG_USER_VERIFIED != 0
    }
    /// A passkey that may be synced to the user's other devices (a "multi-device" credential).
    fn backup_eligible(&self) -> bool {
        self.flags & FLAG_BACKUP_ELIGIBLE != 0
    }
    fn backed_up(&self) -> bool {
        self.flags & FLAG_BACKED_UP != 0
    }
}

fn authenticator_data<'a>(data: &'a [u8], rp: &RelyingParty) -> Result<AuthenticatorData<'a>, &'static str> {
    if data.len() < 37 {
        return Err("authenticator data too short");
    }
    if !crate::util::ct_eq(&data[..32], &sha256(rp.id.as_bytes())) {
        return Err("the passkey is for another site");
    }
    let flags = data[32];
    if flags & FLAG_USER_PRESENT == 0 {
        return Err("the user was not present");
    }
    // Backed up without being able to be: the authenticator contradicts itself.
    if flags & FLAG_BACKED_UP != 0 && flags & FLAG_BACKUP_ELIGIBLE == 0 {
        return Err("inconsistent backup flags");
    }
    Ok(AuthenticatorData { flags, sign_count: u32::from_be_bytes(data[33..37].try_into().expect("length checked")), rest: &data[37..] })
}

/// A credential just registered.
#[derive(Debug, Clone, PartialEq)]
pub struct NewCredential {
    pub id: Vec<u8>,
    /// The public key, COSE encoded as the authenticator gave it.
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    /// The authenticator model (all zero when the authenticator does not say).
    pub aaguid: [u8; 16],
    /// Whether the passkey can be synced, and whether it is.
    pub backup_eligible: bool,
    pub backed_up: bool,
}

/// What a verified sign-in with a passkey tells about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assertion {
    pub sign_count: u32,
    pub user_verified: bool,
    pub backed_up: bool,
}

/// Verifies a registration (`navigator.credentials.create`) for `challenge`.
pub fn verify_registration(client_data: &[u8], attestation_object: &[u8], challenge: &[u8], rp: &RelyingParty) -> Result<NewCredential, &'static str> {
    check_client_data(client_data, "webauthn.create", challenge, rp)?;
    let (attestation, _) = cbor(attestation_object).ok_or("unreadable attestation")?;
    let data = attestation.get_text("authData").and_then(Cbor::bytes).ok_or("no authenticator data")?;
    let parsed = authenticator_data(data, rp)?;
    if parsed.flags & FLAG_ATTESTED == 0 {
        return Err("no credential in the response");
    }
    // Registration asks for user verification: a passkey must be usable as the only factor.
    if !parsed.user_verified() {
        return Err("the authenticator did not verify the user");
    }
    // AAGUID (16), credential id length (2), credential id, then the COSE key.
    let rest = parsed.rest;
    let length = usize::from(u16::from_be_bytes(rest.get(16..18).ok_or("truncated credential")?.try_into().expect("two bytes")));
    let id = rest.get(18..18 + length).ok_or("truncated credential")?.to_vec();
    if id.is_empty() || id.len() > 1023 {
        return Err("invalid credential id");
    }
    let (key, used) = cbor(&rest[18 + length..]).ok_or("unreadable public key")?;
    public_key(&key)?;
    let aaguid: [u8; 16] = rest[..16].try_into().expect("length checked above");
    Ok(NewCredential {
        id,
        public_key: rest[18 + length..18 + length + used].to_vec(),
        sign_count: parsed.sign_count,
        aaguid,
        backup_eligible: parsed.backup_eligible(),
        backed_up: parsed.backed_up(),
    })
}

/// A verifiable key from a COSE key (RFC 9053): its algorithm and the key bytes ring takes.
fn public_key(key: &Cbor) -> Result<(&'static dyn signature::VerificationAlgorithm, Vec<u8>), &'static str> {
    match (key.get(1).and_then(Cbor::int), key.get(3).and_then(Cbor::int)) {
        // EC2, ES256 on P-256: an uncompressed point.
        (Some(2), Some(-7)) => {
            let (x, y) = (key.get(-2).and_then(Cbor::bytes).ok_or("no x")?, key.get(-3).and_then(Cbor::bytes).ok_or("no y")?);
            if key.get(-1).and_then(Cbor::int) != Some(1) || x.len() != 32 || y.len() != 32 {
                return Err("unsupported curve");
            }
            Ok((&signature::ECDSA_P256_SHA256_ASN1, [&[4u8][..], x, y].concat()))
        }
        // OKP, EdDSA on Ed25519.
        (Some(1), Some(-8)) => {
            let x = key.get(-2).and_then(Cbor::bytes).ok_or("no key")?;
            if key.get(-1).and_then(Cbor::int) != Some(6) || x.len() != 32 {
                return Err("unsupported curve");
            }
            Ok((&signature::ED25519, x.to_vec()))
        }
        // RSA, RS256: ring takes the DER encoded RSAPublicKey.
        (Some(3), Some(-257)) => {
            let (n, e) = (key.get(-1).and_then(Cbor::bytes).ok_or("no modulus")?, key.get(-2).and_then(Cbor::bytes).ok_or("no exponent")?);
            Ok((&signature::RSA_PKCS1_2048_8192_SHA256, rsa_public_key_der(n, e)))
        }
        _ => Err("unsupported key type"),
    }
}

fn der_length(length: usize) -> Vec<u8> {
    match length {
        0..=127 => vec![length as u8],
        128..=255 => vec![0x81, length as u8],
        _ => vec![0x82, (length >> 8) as u8, length as u8],
    }
}

fn der_integer(value: &[u8]) -> Vec<u8> {
    let trimmed: &[u8] = { let start = value.iter().position(|b| *b != 0).unwrap_or(value.len().saturating_sub(1)); &value[start..] };
    let mut content = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.first().is_some_and(|b| b & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(trimmed);
    [vec![0x02], der_length(content.len()), content].concat()
}

fn rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let body = [der_integer(n), der_integer(e)].concat();
    [vec![0x30], der_length(body.len()), body].concat()
}

/// The stored facts about a credential that an assertion is checked against.
#[derive(Debug, Clone, Copy)]
pub struct StoredCredential<'a> {
    pub public_key: &'a [u8],
    pub sign_count: u32,
    pub backup_eligible: bool,
}

/// Verifies an assertion (`navigator.credentials.get`) against a stored credential.
/// `require_user_verification` is set when the passkey replaces the password: the
/// authenticator must then have checked the user's PIN or biometrics.
pub fn verify_assertion(
    client_data: &[u8],
    authenticator: &[u8],
    signature_bytes: &[u8],
    stored: StoredCredential<'_>,
    challenge: &[u8],
    rp: &RelyingParty,
    require_user_verification: bool,
) -> Result<Assertion, &'static str> {
    check_client_data(client_data, "webauthn.get", challenge, rp)?;
    let parsed = authenticator_data(authenticator, rp)?;
    if require_user_verification && !parsed.user_verified() {
        return Err("the authenticator did not verify the user");
    }
    // Whether a credential can be synced is fixed when it is made (WebAuthn section 7.2, step 19).
    if parsed.backup_eligible() != stored.backup_eligible {
        return Err("the passkey's backup eligibility changed");
    }
    let (stored_key, stored_count) = (stored.public_key, stored.sign_count);
    let (key, _) = cbor(stored_key).ok_or("unreadable stored key")?;
    let (algorithm, key_bytes) = public_key(&key)?;
    let signed = [authenticator, &sha256(client_data)[..]].concat();
    signature::UnparsedPublicKey::new(algorithm, key_bytes).verify(&signed, signature_bytes).map_err(|_| "the signature is wrong")?;
    // A counter that does not grow means the key was copied (when the authenticator counts).
    if (parsed.sign_count != 0 || stored_count != 0) && parsed.sign_count <= stored_count {
        return Err("the passkey's counter went backwards");
    }
    Ok(Assertion { sign_count: parsed.sign_count, user_verified: parsed.user_verified(), backed_up: parsed.backed_up() })
}

type Challenge = (Vec<u8>, Instant);
const CHALLENGE_TTL: Duration = Duration::from_secs(300);

/// Challenges handed out and not used yet, by purpose and account. Kept by each server
/// instance: account ids only mean something within one database.
#[derive(Default)]
pub struct Challenges(Mutex<HashMap<String, Challenge>>);

impl Challenges {
    pub fn issue(&self, key: &str) -> Vec<u8> {
        let challenge = random_bytes::<32>().to_vec();
        let mut map = self.0.lock();
        map.retain(|_, (_, at)| at.elapsed() < CHALLENGE_TTL);
        // Room for the open passkey sign-ins (see api::signin) and the other ceremonies.
        if map.len() < 250_000 {
            map.insert(key.to_owned(), (challenge.clone(), Instant::now()));
        }
        challenge
    }

    /// Takes the challenge issued for `key` (each one is good for a single answer).
    pub fn take(&self, key: &str) -> Option<Vec<u8>> {
        self.0.lock().remove(key).filter(|(_, at)| at.elapsed() < CHALLENGE_TTL).map(|(challenge, _)| challenge)
    }
}

pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn unb64url(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
    };

    use super::*;

    #[test]
    fn totp_matches_the_rfc_vectors() {
        // RFC 6238 appendix B, SHA-1, the eight-digit codes cut to six.
        let secret = b"12345678901234567890";
        for (time, code) in [(59, "287082"), (1_111_111_109, "081804"), (1_234_567_890, "005924"), (2_000_000_000, "279037")] {
            assert_eq!(code_at(secret, time / 30), code, "{time}");
        }
        assert_eq!(matching_step(secret, "287 082", 59), Some(1));
        assert_eq!(matching_step(secret, "287082", 59 + 30), Some(1), "one step of drift");
        assert_eq!(matching_step(secret, "287082", 59 + 90), None);
        assert_eq!(matching_step(secret, "28708", 59), None);
        assert_eq!(unbase32(&base32(secret)).unwrap(), secret);
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert!(otpauth_uri("unoMail", "józef@example.org", "ABC").starts_with("otpauth://totp/unoMail:j%C3%B3zef@example.org?secret=ABC&issuer=unoMail"));
    }

    #[test]
    fn app_passwords_look_like_app_passwords() {
        let password = new_app_password();
        assert_eq!(password.len(), 19);
        assert_eq!(normalize_app_password(&password).unwrap().len(), 16);
        assert_eq!(normalize_app_password("ABCD-efgh ijkl mnop").as_deref(), Some("abcdefghijklmnop"));
        for not in ["correct horse battery staple", "abcd", "abcdefghijklmnop1", "ąbcdefghijklmnop"] {
            assert_eq!(normalize_app_password(not), None, "{not}");
        }
    }

    /// A software authenticator holding one P-256 key, for tests.
    pub struct Authenticator {
        key: EcdsaKeyPair,
        pub credential_id: Vec<u8>,
        pub counter: u32,
        /// Flags of the next answer (user present and verified by default).
        pub flags: u8,
    }

    impl Authenticator {
        pub fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            Authenticator { key: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap(), credential_id: random_bytes::<16>().to_vec(), counter: 0, flags: 0x05 }
        }

        fn cose_key(&self) -> Vec<u8> {
            let point = self.key.public_key().as_ref();
            // {1: 2, 3: -7, -1: 1, -2: x, -3: y}
            let mut out = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
            out.extend_from_slice(&point[1..33]);
            out.extend_from_slice(&[0x22, 0x58, 0x20]);
            out.extend_from_slice(&point[33..65]);
            out
        }

        fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({ "type": kind, "challenge": b64url(challenge), "origin": origin, "crossOrigin": false })).unwrap()
        }

        /// (clientDataJSON, attestationObject) for a registration.
        pub fn register(&self, challenge: &[u8], rp_id: &str, origin: &str) -> (Vec<u8>, Vec<u8>) {
            let mut auth_data = sha256(rp_id.as_bytes()).to_vec();
            auth_data.push(self.flags | 0x40); // as set, plus attested credential data
            auth_data.extend_from_slice(&0u32.to_be_bytes());
            auth_data.extend_from_slice(&[0u8; 16]);
            auth_data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
            auth_data.extend_from_slice(&self.credential_id);
            auth_data.extend_from_slice(&self.cose_key());
            // {"fmt": "none", "attStmt": {}, "authData": bytes}
            let mut object = vec![0xa3, 0x63];
            object.extend_from_slice(b"fmt");
            object.extend_from_slice(&[0x64]);
            object.extend_from_slice(b"none");
            object.extend_from_slice(&[0x67]);
            object.extend_from_slice(b"attStmt");
            object.extend_from_slice(&[0xa0, 0x68]);
            object.extend_from_slice(b"authData");
            object.extend_from_slice(&[0x59, (auth_data.len() >> 8) as u8, auth_data.len() as u8]);
            object.extend_from_slice(&auth_data);
            (Self::client_data("webauthn.create", challenge, origin), object)
        }

        /// (clientDataJSON, authenticatorData, signature) for a sign-in.
        pub fn sign(&mut self, challenge: &[u8], rp_id: &str, origin: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            self.counter += 1;
            let mut auth_data = sha256(rp_id.as_bytes()).to_vec();
            auth_data.push(self.flags);
            auth_data.extend_from_slice(&self.counter.to_be_bytes());
            let client = Self::client_data("webauthn.get", challenge, origin);
            let signed = [&auth_data[..], &sha256(&client)[..]].concat();
            let signature = self.key.sign(&SystemRandom::new(), &signed).unwrap().as_ref().to_vec();
            (client, auth_data, signature)
        }
    }

    #[test]
    fn passkeys_register_and_sign_in() {
        let rp = RelyingParty::from_url("https://mail.example.org").unwrap();
        assert_eq!((rp.id.as_str(), rp.origin.as_str()), ("mail.example.org", "https://mail.example.org"));
        assert!(RelyingParty::from_url("http://127.0.0.1:8080").is_none(), "passkeys need a host name");
        let mut device = Authenticator::new();

        let challenge = random_bytes::<32>();
        let (client, attestation) = device.register(&challenge, &rp.id, &rp.origin);
        let credential = verify_registration(&client, &attestation, &challenge, &rp).unwrap();
        assert_eq!(credential.id, device.credential_id);
        assert_eq!(verify_registration(&client, &attestation, b"another challenge", &rp), Err("the challenge does not match"));
        let elsewhere = RelyingParty { id: "evil.example".into(), origin: "https://evil.example".into() };
        assert!(verify_registration(&client, &attestation, &challenge, &elsewhere).is_err());

        let challenge = random_bytes::<32>();
        let (client, data, signature) = device.sign(&challenge, &rp.id, &rp.origin);
        let stored = |count: u32| StoredCredential { public_key: &credential.public_key, sign_count: count, backup_eligible: credential.backup_eligible };
        assert_eq!(verify_assertion(&client, &data, &signature, stored(0), &challenge, &rp, true), Ok(Assertion { sign_count: 1, user_verified: true, backed_up: false }));
        // A replayed answer, a foreign challenge, a tampered signature, a cloned key.
        assert!(verify_assertion(&client, &data, &signature, stored(1), &challenge, &rp, false).is_err());
        assert!(verify_assertion(&client, &data, &signature, stored(0), b"other", &rp, false).is_err());
        let mut broken = signature.clone();
        *broken.last_mut().unwrap() ^= 1;
        assert!(verify_assertion(&client, &data, &broken, stored(0), &challenge, &rp, false).is_err());
        let (phished, data2, signature2) = device.sign(&challenge, &rp.id, "https://mail.example.org.evil.test");
        assert_eq!(verify_assertion(&phished, &data2, &signature2, stored(1), &challenge, &rp, false), Err("the request comes from another site"));

        // Without user verification it is a second factor only.
        device.flags = 0x01;
        let (client, data, signature) = device.sign(&challenge, &rp.id, &rp.origin);
        assert_eq!(verify_assertion(&client, &data, &signature, stored(2), &challenge, &rp, true), Err("the authenticator did not verify the user"));
        assert!(verify_assertion(&client, &data, &signature, stored(2), &challenge, &rp, false).is_ok());
        // Backup eligibility is fixed at registration; "backed up" alone is a contradiction.
        device.flags = 0x05 | 0x08;
        let (client, data, signature) = device.sign(&challenge, &rp.id, &rp.origin);
        assert_eq!(verify_assertion(&client, &data, &signature, stored(4), &challenge, &rp, true), Err("the passkey's backup eligibility changed"));
        device.flags = 0x05 | 0x10;
        let (client, data, signature) = device.sign(&challenge, &rp.id, &rp.origin);
        assert_eq!(verify_assertion(&client, &data, &signature, stored(5), &challenge, &rp, true), Err("inconsistent backup flags"));

        // Registering needs user verification.
        device.flags = 0x41;
        let challenge = random_bytes::<32>();
        let (client, attestation) = device.register(&challenge, &rp.id, &rp.origin);
        assert_eq!(verify_registration(&client, &attestation, &challenge, &rp), Err("the authenticator did not verify the user"));
    }

    #[test]
    fn cbor_reads_what_webauthn_sends_and_nothing_strange() {
        assert_eq!(cbor(&[0x18, 0x64]), Some((Cbor::Int(100), 2)));
        assert_eq!(cbor(&[0x38, 0x63]), Some((Cbor::Int(-100), 2)));
        assert_eq!(cbor(&[0x63, b'a', b'b', b'c']), Some((Cbor::Text("abc".into()), 4)));
        assert_eq!(cbor(&[0xa1, 0x01, 0xf5]), Some((Cbor::Map(vec![(Cbor::Int(1), Cbor::Bool(true))]), 3)));
        for bad in [&[0x5f][..], &[0x9f], &[0x5a, 0xff, 0xff, 0xff, 0xff], &[0x62, b'a'], &[]] {
            assert_eq!(cbor(bad), None, "{bad:?}");
        }
        let mut deep = vec![0x81; 40];
        deep.push(0x00);
        assert_eq!(cbor(&deep), None, "nesting is bounded");
        assert_eq!(rsa_public_key_der(&[0x80, 1], &[1, 0, 1]), vec![0x30, 0x0a, 0x02, 0x03, 0x00, 0x80, 0x01, 0x02, 0x03, 0x01, 0x00, 0x01]);
    }
}
