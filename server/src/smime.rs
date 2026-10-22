//! S/MIME (RFC 8551): signed and encrypted mail with X.509 certificates.
//!
//! - Incoming signatures are verified (detached `multipart/signed` and opaque signed-data):
//!   the signature itself, the certificate's validity, whether it belongs to the sender, and
//!   whether it chains to a trusted authority. Certificates of correspondents who sign their
//!   mail are kept, so that mail to them can be encrypted.
//! - A user can store their certificate and private key (imported from a PKCS#12 file). The
//!   key is kept sealed with the server key; with it the server signs outgoing mail, encrypts
//!   it to its recipients (and to the sender, so that Sent stays readable), and decrypts mail
//!   encrypted to the user when it is read.

use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine, engine::general_purpose::STANDARD};
use cms::{
    builder::{ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyEncryptionInfo, KeyTransRecipientInfoBuilder, SignedDataBuilder, SignerInfoBuilder, create_signing_time_attribute},
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::ContentInfo,
    enveloped_data::{EnvelopedData, RecipientIdentifier, RecipientInfo},
    signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier},
};
use der::{Any, Decode, Encode, asn1::OctetString, oid::ObjectIdentifier};
use mail_parser::{MessageParser, MimeHeaders};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{Pkcs1v15Encrypt, Pkcs1v15Sign},
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use serde::Serialize;
use sha2::Digest;
use x509_cert::{Certificate, spki::AlgorithmIdentifierOwned};

use crate::{app::App, security::authn::find_header_end, util::now};

const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_ENVELOPED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const ID_RSAES_OAEP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.7");
const SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const AES128_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.2");
const AES192_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.22");
const AES256_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

// --- Certificates ------------------------------------------------------------------------------

/// What a certificate says, as shown to people.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub emails: Vec<String>,
    pub not_before: i64,
    pub not_after: i64,
    pub fingerprint: String,
}

pub fn cert_info(der: &[u8]) -> Option<CertInfo> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let mut emails: Vec<String> = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::RFC822Name(email) = name {
                emails.push(email.to_ascii_lowercase());
            }
        }
    }
    for email in cert.subject().iter_email() {
        if let Ok(email) = email.as_str() {
            let email = email.to_ascii_lowercase();
            if !emails.contains(&email) {
                emails.push(email);
            }
        }
    }
    Some(CertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        emails,
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        fingerprint: hex::encode(sha2::Sha256::digest(der)),
    })
}

/// Trust anchors: the web PKI roots (most public S/MIME authorities are among them) and any
/// extra ones the administrator put into `<data>/smime-roots/`.
fn anchors(app: Option<&App>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if let Some(app) = app
        && let Ok(entries) = std::fs::read_dir(app.cfg.data_dir.join("smime-roots"))
    {
        for entry in entries.flatten() {
            let Ok(data) = std::fs::read(entry.path()) else { continue };
            if data.starts_with(b"-----") {
                for pem in x509_parser::pem::Pem::iter_from_buffer(&data).flatten() {
                    out.push(pem.contents);
                }
            } else {
                out.push(data);
            }
        }
    }
    out
}

/// Whether `leaf` chains, through the `intermediates`, to a trusted authority.
fn trusted(app: Option<&App>, leaf: &[u8], intermediates: &[Vec<u8>]) -> bool {
    use rustls::pki_types::{CertificateDer, UnixTime};
    if intermediates.len() > 16 || !signing_key_usage(leaf, false) {
        return false;
    }
    let extra: Vec<CertificateDer<'_>> = anchors(app).into_iter().map(CertificateDer::from).collect();
    let mut roots = webpki_roots::TLS_SERVER_ROOTS.to_vec();
    roots.extend(extra.iter().filter_map(|der| webpki::anchor_from_trusted_cert(der).ok()));
    let leaf = CertificateDer::from(leaf);
    let Ok(cert) = webpki::EndEntityCert::try_from(&leaf) else { return false };
    let chain: Vec<_> = intermediates.iter().filter(|der| der.as_slice() != leaf.as_ref()).map(|der| CertificateDer::from(der.as_slice())).collect();
    // id-kp-emailProtection. WebPKI enforces CA, validity, path length, critical
    // extensions and name constraints (unsupported constrained names fail closed).
    let usage = webpki::KeyUsage::required_if_present(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04]);
    let provider = crate::tls::provider();
    let Ok(path) = cert.verify_for_usage(provider.signature_verification_algorithms.all, &roots, &chain, UnixTime::now(), usage, None, None) else { return false };
    // WebPKI deliberately does not enforce the KeyUsage bit string; S/MIME does.
    path.intermediate_certificates().all(|cert| signing_key_usage(cert.der().as_ref(), true))
}

fn signing_key_usage(der: &[u8], ca: bool) -> bool {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else { return false };
    match cert.key_usage() {
        Ok(Some(usage)) if ca => usage.value.key_cert_sign(),
        Ok(Some(usage)) => usage.value.digital_signature() || usage.value.non_repudiation(),
        Ok(None) => true,
        Err(_) => false,
    }
}

fn issuer_and_serial(cert: &Certificate) -> IssuerAndSerialNumber {
    IssuerAndSerialNumber { issuer: cert.tbs_certificate.issuer.clone(), serial_number: cert.tbs_certificate.serial_number.clone() }
}

fn rsa_public_key(cert: &Certificate) -> Option<RsaPublicKey> {
    RsaPublicKey::from_public_key_der(&cert.tbs_certificate.subject_public_key_info.to_der().ok()?).ok()
}

// --- Verification ------------------------------------------------------------------------------

/// The outcome of checking a signature.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Signature {
    /// `valid`, `untrusted` (signature fine, authority unknown), `expired`, `invalid`.
    pub status: &'static str,
    pub signer: Option<CertInfo>,
    /// The certificate is for the address the message claims to be from.
    pub matches_sender: bool,
    pub reason: Option<String>,
    #[serde(skip)]
    pub certificate: Option<Vec<u8>>,
}

impl Signature {
    fn invalid(reason: impl Into<String>) -> Self {
        Signature { status: "invalid", signer: None, matches_sender: false, reason: Some(reason.into()), certificate: None }
    }
}

fn digest(algorithm: &ObjectIdentifier, data: &[u8]) -> Option<Vec<u8>> {
    Some(match *algorithm {
        SHA1 => sha1::Sha1::digest(data).to_vec(),
        SHA256 => sha2::Sha256::digest(data).to_vec(),
        SHA384 => sha2::Sha384::digest(data).to_vec(),
        SHA512 => sha2::Sha512::digest(data).to_vec(),
        _ => return None,
    })
}

fn pkcs1_scheme(algorithm: &ObjectIdentifier) -> Option<Pkcs1v15Sign> {
    Some(match *algorithm {
        SHA1 => Pkcs1v15Sign::new::<sha1::Sha1>(),
        SHA256 => Pkcs1v15Sign::new::<sha2::Sha256>(),
        SHA384 => Pkcs1v15Sign::new::<sha2::Sha384>(),
        SHA512 => Pkcs1v15Sign::new::<sha2::Sha512>(),
        _ => return None,
    })
}

/// Checks CMS signed-data. `content` is the signed MIME entity of a detached signature; for
/// an opaque one it is inside the structure. Returns the outcome and the signed content.
pub fn verify_signed_data(app: Option<&App>, der: &[u8], content: Option<&[u8]>, sender: &str) -> (Signature, Option<Vec<u8>>) {
    let Some(info) = content_info(der) else { return (Signature::invalid("the signature cannot be read"), None) };
    if info.content_type != ID_SIGNED_DATA {
        return (Signature::invalid("not a signature"), None);
    }
    let Ok(signed) = info.content.decode_as::<SignedData>() else { return (Signature::invalid("the signature cannot be read"), None) };
    let embedded = signed.encap_content_info.econtent.as_ref().and_then(|any| any.decode_as::<OctetString>().ok()).map(|o| o.as_bytes().to_vec());
    let Some(content) = content.map(<[u8]>::to_vec).or(embedded) else { return (Signature::invalid("nothing was signed"), None) };
    let certs: Vec<Certificate> = signed
        .certificates
        .as_ref()
        .map(|set| set.0.iter().filter_map(|c| if let CertificateChoices::Certificate(cert) = c { Some(cert.clone()) } else { None }).collect())
        .unwrap_or_default();
    let Some(signer_info) = signed.signer_infos.0.iter().next() else { return (Signature::invalid("the message is not signed"), Some(content)) };
    let signer = certs.iter().find(|cert| match &signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber(id) => cert.tbs_certificate.issuer == id.issuer && cert.tbs_certificate.serial_number == id.serial_number,
        SignerIdentifier::SubjectKeyIdentifier(ski) => cert
            .tbs_certificate
            .extensions
            .as_ref()
            .is_some_and(|exts| exts.iter().any(|e| e.extn_id == ObjectIdentifier::new_unwrap("2.5.29.14") && e.extn_value.as_bytes().ends_with(ski.0.as_bytes()))),
    });
    let Some(signer) = signer else { return (Signature::invalid("the signer's certificate is not included"), Some(content)) };
    let Ok(signer_der) = signer.to_der() else { return (Signature::invalid("the certificate cannot be read"), Some(content)) };
    let digest_alg = signer_info.digest_alg.oid;
    let Some(content_digest) = digest(&digest_alg, &content) else { return (Signature::invalid("unsupported digest algorithm"), Some(content)) };
    // With signed attributes, the signature covers them, and they hold the content digest.
    let signed_bytes = match &signer_info.signed_attrs {
        Some(attrs) => {
            let declared = attrs.iter().find(|a| a.oid == ID_MESSAGE_DIGEST).and_then(|a| a.values.iter().next()).and_then(|v| v.decode_as::<OctetString>().ok());
            if declared.as_ref().map(OctetString::as_bytes) != Some(&content_digest[..]) {
                return (Signature::invalid("the message was changed after it was signed"), Some(content));
            }
            match attrs.to_der() {
                Ok(der) => der,
                Err(_) => return (Signature::invalid("the signature cannot be read"), Some(content)),
            }
        }
        None => content.clone(),
    };
    let signature = signer_info.signature.as_bytes();
    let ok = match signer_info.signature_algorithm.oid {
        ECDSA_SHA256 | ECDSA_SHA384 => {
            let algorithm: &dyn ring::signature::VerificationAlgorithm =
                if signer_info.signature_algorithm.oid == ECDSA_SHA256 { &ring::signature::ECDSA_P256_SHA256_ASN1 } else { &ring::signature::ECDSA_P384_SHA384_ASN1 };
            let key = signer.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
            ring::signature::UnparsedPublicKey::new(algorithm, key).verify(&signed_bytes, signature).is_ok()
        }
        // rsaEncryption and the sha*WithRSAEncryption identifiers: PKCS #1 v1.5.
        _ => match (rsa_public_key(signer), pkcs1_scheme(&digest_alg), digest(&digest_alg, &signed_bytes)) {
            (Some(key), Some(scheme), Some(hashed)) => key.verify(scheme, &hashed, signature).is_ok(),
            _ => false,
        },
    };
    let info = cert_info(&signer_der);
    let matches_sender = info.as_ref().is_some_and(|i| i.emails.iter().any(|e| e.eq_ignore_ascii_case(sender)));
    let status = if !ok {
        "invalid"
    } else if info.as_ref().is_some_and(|i| now() < i.not_before || now() > i.not_after) {
        "expired"
    } else {
        let intermediates: Vec<Vec<u8>> = certs.iter().filter_map(|c| c.to_der().ok()).collect();
        if trusted(app, &signer_der, &intermediates) { "valid" } else { "untrusted" }
    };
    let reason = (!ok).then(|| "the signature does not match the message".to_owned());
    (Signature { status, signer: info, matches_sender, reason, certificate: Some(signer_der) }, Some(content))
}

/// Reads a CMS structure; Thunderbird (NSS) and streaming OpenSSL write BER with indefinite
/// lengths, which is converted to DER first.
fn content_info(der: &[u8]) -> Option<ContentInfo> {
    ContentInfo::from_der(der).ok().or_else(|| ContentInfo::from_der(&ber_to_der(der)?).ok())
}

/// Re-encodes BER as DER: indefinite lengths become definite ones and constructed OCTET
/// STRINGs are joined. Definite-length primitive contents are kept byte for byte, so the
/// certificates and signed attributes inside still verify.
fn ber_to_der(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let (_, used) = ber_element(input, 0, &mut out)?;
    (used == input.len() || input[used..].iter().all(|b| *b == 0)).then_some(out)
}

/// Converts one element into `out`; returns (whether it was an end-of-contents marker, bytes read).
fn ber_element(input: &[u8], depth: usize, out: &mut Vec<u8>) -> Option<(bool, usize)> {
    if depth > 64 {
        return None;
    }
    let mut pos = 0;
    let first = *input.get(pos)?;
    pos += 1;
    if first & 0x1f == 0x1f {
        while *input.get(pos)? & 0x80 != 0 {
            pos += 1;
        }
        pos += 1;
    }
    let tag = &input[..pos];
    let length_byte = *input.get(pos)?;
    pos += 1;
    if first == 0 && length_byte == 0 {
        return Some((true, pos));
    }
    let constructed = first & 0x20 != 0;
    let mut content = Vec::new();
    if length_byte == 0x80 {
        if !constructed {
            return None;
        }
        loop {
            let (end, used) = ber_element(&input[pos..], depth + 1, &mut content)?;
            pos += used;
            if end {
                break;
            }
        }
    } else {
        let length = if length_byte & 0x80 == 0 {
            usize::from(length_byte)
        } else {
            let count = usize::from(length_byte & 0x7f);
            if count > 4 {
                return None;
            }
            let bytes = input.get(pos..pos + count)?;
            pos += count;
            bytes.iter().fold(0usize, |acc, b| (acc << 8) | usize::from(*b))
        };
        let body = input.get(pos..pos.checked_add(length)?)?;
        pos += length;
        if constructed {
            let mut inner = 0;
            while inner < body.len() {
                let (end, used) = ber_element(&body[inner..], depth + 1, &mut content)?;
                if end {
                    return None;
                }
                inner += used;
            }
        } else {
            content.extend_from_slice(body);
        }
    }
    if first == 0x24 {
        // A constructed OCTET STRING: DER has only the primitive form.
        let mut joined = Vec::new();
        let mut inner = 0;
        while inner < content.len() {
            if content[inner] != 0x04 {
                return None;
            }
            let (header, length) = der_header(&content[inner..])?;
            joined.extend_from_slice(content.get(inner + header..inner + header + length)?);
            inner += header + length;
        }
        out.push(0x04);
        der_length(joined.len(), out);
        out.extend_from_slice(&joined);
    } else {
        out.extend_from_slice(tag);
        der_length(content.len(), out);
        out.extend_from_slice(&content);
    }
    Some((false, pos))
}

/// (header size, content length) of an element written by `ber_element`.
fn der_header(input: &[u8]) -> Option<(usize, usize)> {
    let length_byte = *input.get(1)?;
    if length_byte & 0x80 == 0 {
        return Some((2, usize::from(length_byte)));
    }
    let count = usize::from(length_byte & 0x7f);
    let length = input.get(2..2 + count)?.iter().fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
    Some((2 + count, length))
}

fn der_length(length: usize, out: &mut Vec<u8>) {
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes: Vec<u8> = length.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
}

// --- MIME --------------------------------------------------------------------------------------

/// Content type of a message or part: (`type/subtype` lower-case, parameter lookup).
fn content_type(raw: &[u8]) -> Option<(String, Vec<(String, String)>)> {
    let message = MessageParser::default().parse_headers(raw)?;
    let ct = message.content_type()?;
    let kind = format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("")).to_ascii_lowercase();
    let params = ct.attributes().map(|attrs| attrs.iter().map(|a| (a.name.to_ascii_lowercase(), a.value.to_string())).collect()).unwrap_or_default();
    Some((kind, params))
}

fn param<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

/// The two halves of a `multipart/signed` message: the signed entity, exactly as it was
/// transmitted, and the decoded signature.
fn split_signed(raw: &[u8], boundary: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let body = &raw[find_header_end(raw).min(raw.len())..];
    let delimiter = format!("--{boundary}");
    let first = find(body, delimiter.as_bytes())?;
    let start = first + delimiter.len();
    let start = start + if body[start..].starts_with(b"\r\n") { 2 } else if body[start..].starts_with(b"\n") { 1 } else { 0 };
    let next = format!("\r\n--{boundary}");
    let (end, after) = match find(&body[start..], next.as_bytes()) {
        Some(pos) => (start + pos, start + pos + next.len()),
        None => {
            let lf = format!("\n--{boundary}");
            let pos = find(&body[start..], lf.as_bytes())?;
            (start + pos, start + pos + lf.len())
        }
    };
    // Signatures cover the entity with CRLF line breaks (RFC 8551 section 3.1.1).
    let signed = canonical(&body[start..end]);
    let rest = &body[after..];
    let part_end = find(rest, delimiter.as_bytes()).unwrap_or(rest.len());
    let part = &rest[..part_end];
    let part = part.strip_prefix(b"\r\n").or_else(|| part.strip_prefix(b"\n")).unwrap_or(part);
    let header_end = find_header_end(part).min(part.len());
    let encoded: Vec<u8> = part[header_end..].iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    let signature = STANDARD.decode(encoded).ok()?;
    Some((signed, signature))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The base64 body of a single-part message (an `application/pkcs7-mime` one).
fn decoded_body(raw: &[u8]) -> Option<Vec<u8>> {
    let message = MessageParser::default().parse(raw)?;
    Some(message.parts.first()?.contents().to_vec())
}

fn author(raw: &[u8]) -> String {
    MessageParser::default().parse_headers(raw).and_then(|m| m.from().and_then(|f| f.first()).and_then(|a| a.address().map(str::to_ascii_lowercase))).unwrap_or_default()
}

/// Outer headers (everything but `Content-*` and `MIME-Version`) and the MIME entity.
fn split_entity(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let end = find_header_end(raw).min(raw.len());
    let (head, body) = raw.split_at(end);
    let mut outer = Vec::new();
    let mut inner = Vec::new();
    let mut in_content = false;
    for line in head.split_inclusive(|b| *b == b'\n') {
        if line == b"\r\n" || line == b"\n" {
            continue;
        }
        if !line.starts_with(b" ") && !line.starts_with(b"\t") {
            let lower = line.iter().take(20).map(u8::to_ascii_lowercase).collect::<Vec<u8>>();
            in_content = lower.starts_with(b"content-") || lower.starts_with(b"mime-version:");
            if lower.starts_with(b"mime-version:") {
                continue;
            }
        } else if in_content && line.is_empty() {
            continue;
        }
        if in_content {
            if !line.iter().take(13).map(u8::to_ascii_lowercase).collect::<Vec<u8>>().starts_with(b"mime-version:") {
                inner.extend_from_slice(line);
            }
        } else {
            outer.extend_from_slice(line);
        }
    }
    if inner.is_empty() {
        inner.extend_from_slice(b"Content-Type: text/plain; charset=us-ascii\r\n");
    }
    let body = body.strip_prefix(b"\r\n").or_else(|| body.strip_prefix(b"\n")).unwrap_or(body);
    inner.extend_from_slice(b"\r\n");
    inner.extend_from_slice(body);
    (outer, canonical(&inner))
}

/// Line breaks as CRLF, as signatures are computed over (RFC 8551 section 3.1.1).
fn canonical(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 40);
    for (i, &b) in data.iter().enumerate() {
        if b == b'\n' && (i == 0 || data[i - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

fn wrap_base64(data: &[u8]) -> String {
    let encoded = STANDARD.encode(data);
    encoded.as_bytes().chunks(76).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("\r\n")
}

// --- The user's own certificate ----------------------------------------------------------------

pub struct Identity {
    pub certificate: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
    pub key: RsaPrivateKey,
}

/// Reads a PKCS #12 file: (certificate, PKCS #8 private key, other certificates).
/// A certificate, its PKCS #8 private key and the other certificates of its chain (DER).
pub type Imported = (Vec<u8>, Vec<u8>, Vec<Vec<u8>>);

/// A real process boundary: timing out a blocking thread cannot stop its KDF.
pub async fn import_p12_isolated(data: Vec<u8>, password: String) -> Result<Imported, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    static IMPORTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    if data.len() > 64 * 1024 || password.len() > 256 { return Err("certificate or password is too large".into()); }
    let permit = IMPORTS.try_acquire().map_err(|_| "another certificate import is in progress")?;
    let mut executable = std::env::current_exe().map_err(|_| "cannot locate certificate parser")?;
    // Cargo integration tests live in target/<profile>/deps, next to built binaries.
    if cfg!(debug_assertions) && executable.parent().is_some_and(|p| p.ends_with("deps")) { executable.pop(); }
    executable.set_file_name(format!("unomail-p12{}", std::env::consts::EXE_SUFFIX));
    // Keep the permit and process alive in this task even if the HTTP request is cancelled.
    tokio::spawn(async move {
        let _permit = permit;
        let mut child = tokio::process::Command::new(executable)
            .env_clear().stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null()).kill_on_drop(true).spawn().map_err(|_| "cannot start certificate parser".to_owned())?;
        let request = serde_json::to_vec(&(STANDARD.encode(data), password)).map_err(|_| "cannot encode certificate".to_owned())?;
        let exchange = async {
            let mut input = child.stdin.take().ok_or("cannot open parser input")?;
            input.write_all(&request).await.map_err(|_| "certificate parser stopped")?;
            drop(input);
            let output = child.stdout.take().ok_or("cannot open parser output")?;
            let mut bytes = Vec::new();
            output.take(512 * 1024 + 1).read_to_end(&mut bytes).await.map_err(|_| "cannot read parser output")?;
            if bytes.len() > 512 * 1024 { return Err("certificate parser output is too large".to_owned()); }
            if !child.wait().await.map_err(|_| "cannot wait for parser")?.success() { return Err("certificate exceeds parser resource limits or is invalid".to_owned()); }
            serde_json::from_slice::<Result<Imported, String>>(&bytes).map_err(|_| "invalid parser output".to_owned())?
        };
        match tokio::time::timeout(std::time::Duration::from_secs(20), exchange).await {
            Ok(result) => { if result.is_err() { let _ = child.kill().await; } result }
            Err(_) => { let _ = child.kill().await; let _ = child.wait().await; Err("the file takes too long to open".into()) }
        }
    }).await.map_err(|_| "certificate parser task failed".to_owned())?
}

pub fn import_p12(data: &[u8], password: &str) -> Result<Imported, String> {
    let store = p12_keystore::KeyStore::from_pkcs12(data, password, p12_keystore::Pkcs12ImportPolicy::Strict).map_err(|_| "the file could not be opened: wrong password, or not a PKCS #12 (.p12/.pfx) file".to_owned())?;
    let (_, chain) = store.private_key_chain().ok_or("the file contains no private key")?;
    let mut certs = chain.certs().iter().map(|c| c.as_der().to_vec());
    let certificate = certs.next().ok_or("the file contains no certificate")?;
    let key = chain.key().as_der().to_vec();
    let rsa = RsaPrivateKey::from_pkcs8_der(&key).map_err(|_| "only RSA keys are supported for S/MIME")?;
    let cert = Certificate::from_der(&certificate).map_err(|_| "the certificate cannot be read")?;
    if rsa_public_key(&cert).as_ref() != Some(&rsa.to_public_key()) {
        return Err("the private key does not belong to the certificate".into());
    }
    Ok((certificate, key, certs.collect()))
}

/// The account's stored identity, unsealed.
pub async fn identity(app: &App, account_id: i64) -> Option<Identity> {
    let row: Option<(String, String, String)> = sqlx::query_as("SELECT certificate, chain, key_sealed FROM smime_identities WHERE account_id = ?").bind(account_id).fetch_optional(&app.db).await.ok()?;
    let (certificate, chain, sealed) = row?;
    let key = app.secrets.open(&sealed)?;
    let key = RsaPrivateKey::from_pkcs8_der(&STANDARD.decode(key).ok()?).ok()?;
    let chain: Vec<String> = serde_json::from_str(&chain).unwrap_or_default();
    Some(Identity { certificate: STANDARD.decode(certificate).ok()?, chain: chain.iter().filter_map(|c| STANDARD.decode(c).ok()).collect(), key })
}

// --- Signing and encrypting --------------------------------------------------------------------

/// Signs a message (detached signature, `multipart/signed`).
pub fn sign(raw: &[u8], identity: &Identity) -> Result<Vec<u8>, String> {
    let (outer, inner) = split_entity(raw);
    let cert = Certificate::from_der(&identity.certificate).map_err(|e| e.to_string())?;
    let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(identity.key.clone());
    let content = EncapsulatedContentInfo { econtent_type: ID_DATA, econtent: None };
    let digest_alg = AlgorithmIdentifierOwned { oid: SHA256, parameters: None };
    let message_digest = sha2::Sha256::digest(&inner).to_vec();
    let mut signer_info = SignerInfoBuilder::new(&signer, SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial(&cert)), digest_alg.clone(), &content, Some(&message_digest)).map_err(|e| e.to_string())?;
    signer_info.add_signed_attribute(create_signing_time_attribute().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let mut builder = SignedDataBuilder::new(&content);
    builder.add_digest_algorithm(digest_alg).map_err(|e| e.to_string())?;
    builder.add_certificate(CertificateChoices::Certificate(cert)).map_err(|e| e.to_string())?;
    for extra in &identity.chain {
        if let Ok(cert) = Certificate::from_der(extra) {
            builder.add_certificate(CertificateChoices::Certificate(cert)).map_err(|e| e.to_string())?;
        }
    }
    builder.add_signer_info::<_, rsa::pkcs1v15::Signature>(signer_info).map_err(|e| e.to_string())?;
    let signature = builder.build().map_err(|e| e.to_string())?.to_der().map_err(|e| e.to_string())?;
    let boundary = format!("smime-{}", crate::util::random_token());
    let mut out = outer;
    out.extend_from_slice(
        format!("MIME-Version: 1.0\r\nContent-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=\"{boundary}\"\r\n\r\nThis is a cryptographically signed message in MIME format.\r\n\r\n--{boundary}\r\n").as_bytes(),
    );
    out.extend_from_slice(&inner);
    out.extend_from_slice(
        format!(
            "\r\n--{boundary}\r\nContent-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"smime.p7s\"\r\nContent-Description: S/MIME Cryptographic Signature\r\n\r\n{}\r\n\r\n--{boundary}--\r\n",
            wrap_base64(&signature)
        )
        .as_bytes(),
    );
    Ok(out)
}

/// Encrypts a message to the holders of `certificates` (AES-256-CBC, RSA key transport).
pub fn encrypt(raw: &[u8], certificates: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let (outer, inner) = split_entity(raw);
    let certs: Vec<Certificate> = certificates.iter().map(|c| Certificate::from_der(c).map_err(|e| e.to_string())).collect::<Result<_, _>>()?;
    let mut rng = rand::thread_rng();
    let mut rngs: Vec<rand::rngs::ThreadRng> = certs.iter().map(|_| rand::thread_rng()).collect();
    let mut builder = EnvelopedDataBuilder::new(None, &inner, ContentEncryptionAlgorithm::Aes256Cbc, None).map_err(|e| e.to_string())?;
    for (cert, rng) in certs.iter().zip(rngs.iter_mut()) {
        let key = rsa_public_key(cert).ok_or("only RSA certificates can be encrypted to")?;
        let recipient = KeyTransRecipientInfoBuilder::new(RecipientIdentifier::IssuerAndSerialNumber(issuer_and_serial(cert)), KeyEncryptionInfo::Rsa(key), rng).map_err(|e| e.to_string())?;
        builder.add_recipient_info(recipient).map_err(|e| e.to_string())?;
    }
    let enveloped = builder.build_with_rng(&mut rng).map_err(|e| e.to_string())?;
    let info = ContentInfo { content_type: ID_ENVELOPED_DATA, content: Any::encode_from(&enveloped).map_err(|e| e.to_string())? };
    let der = info.to_der().map_err(|e| e.to_string())?;
    let mut out = outer;
    out.extend_from_slice(
        format!(
            "MIME-Version: 1.0\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"smime.p7m\"\r\nContent-Description: S/MIME Encrypted Message\r\n\r\n{}\r\n",
            wrap_base64(&der)
        )
        .as_bytes(),
    );
    Ok(out)
}

/// Decrypts CMS enveloped-data addressed to `identity`.
pub fn decrypt(der: &[u8], identity: &Identity) -> Result<Vec<u8>, String> {
    let info = content_info(der).ok_or("the encrypted message cannot be read")?;
    if info.content_type != ID_ENVELOPED_DATA {
        return Err("not an encrypted message".into());
    }
    let enveloped = info.content.decode_as::<EnvelopedData>().map_err(|_| "the encrypted message cannot be read")?;
    let cert = Certificate::from_der(&identity.certificate).map_err(|e| e.to_string())?;
    let mine = issuer_and_serial(&cert);
    let recipient = enveloped
        .recip_infos
        .0
        .iter()
        .find_map(|r| match r {
            RecipientInfo::Ktri(k) => match &k.rid {
                RecipientIdentifier::IssuerAndSerialNumber(id) if *id == mine => Some(k.clone()),
                _ => None,
            },
            _ => None,
        })
        .ok_or("the message was not encrypted to your certificate")?;
    let content_key = match recipient.key_enc_alg.oid {
        RSA_ENCRYPTION => identity.key.decrypt(Pkcs1v15Encrypt, recipient.enc_key.as_bytes()),
        ID_RSAES_OAEP => identity.key.decrypt(rsa::Oaep::new::<sha1::Sha1>(), recipient.enc_key.as_bytes()),
        _ => return Err("unsupported key encryption".into()),
    }
    .map_err(|_| "the message key could not be decrypted")?;
    let algorithm = &enveloped.encrypted_content.content_enc_alg;
    let iv = algorithm.parameters.as_ref().and_then(|p| p.decode_as::<OctetString>().ok()).ok_or("missing initialisation vector")?;
    let data = enveloped.encrypted_content.encrypted_content.as_ref().ok_or("no encrypted content")?.as_bytes();
    let bad = |_| "the message could not be decrypted".to_owned();
    match algorithm.oid {
        AES128_CBC => cbc::Decryptor::<aes::Aes128>::new_from_slices(&content_key, iv.as_bytes()).map_err(|_| "bad key".to_owned())?.decrypt_padded_vec::<Pkcs7>(data).map_err(bad),
        AES192_CBC => cbc::Decryptor::<aes::Aes192>::new_from_slices(&content_key, iv.as_bytes()).map_err(|_| "bad key".to_owned())?.decrypt_padded_vec::<Pkcs7>(data).map_err(bad),
        AES256_CBC => cbc::Decryptor::<aes::Aes256>::new_from_slices(&content_key, iv.as_bytes()).map_err(|_| "bad key".to_owned())?.decrypt_padded_vec::<Pkcs7>(data).map_err(bad),
        _ => Err("unsupported content encryption (only AES is)".into()),
    }
}

// --- Reading -----------------------------------------------------------------------------------

/// What S/MIME did to a message, for the reader.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Status {
    pub encrypted: bool,
    pub decrypted: bool,
    pub signature: Option<Signature>,
    pub problem: Option<String>,
}

fn with_outer(raw: &[u8], entity: &[u8]) -> Vec<u8> {
    let (outer, _) = split_entity(raw);
    let mut out = outer;
    out.extend_from_slice(b"MIME-Version: 1.0\r\n");
    out.extend_from_slice(entity);
    out
}

/// The message as it should be shown (decrypted, unwrapped) and what S/MIME says about it;
/// `None` for messages that are not S/MIME.
pub async fn view(app: &App, account_id: i64, raw: Vec<u8>) -> (Vec<u8>, Option<Status>) {
    let Some((kind, params)) = content_type(&raw) else { return (raw, None) };
    let pkcs7 = matches!(kind.as_str(), "application/pkcs7-mime" | "application/x-pkcs7-mime");
    let signed = kind == "multipart/signed" && param(&params, "protocol").is_some_and(|p| p.eq_ignore_ascii_case("application/pkcs7-signature") || p.eq_ignore_ascii_case("application/x-pkcs7-signature"));
    if !pkcs7 && !signed {
        return (raw, None);
    }
    let sender = author(&raw);
    let mut status = Status::default();
    let mut current = raw;
    // An encrypted message is often signed inside: unwrap at most two layers.
    for _ in 0..2 {
        let Some((kind, params)) = content_type(&current) else { break };
        if kind == "multipart/signed" {
            if let Some(boundary) = param(&params, "boundary")
                && let Some((entity, signature)) = split_signed(&current, boundary)
            {
                let (result, _) = verify_signed_data(Some(app), &signature, Some(&entity), &sender);
                status.signature = Some(result);
            }
            break;
        }
        if !matches!(kind.as_str(), "application/pkcs7-mime" | "application/x-pkcs7-mime") {
            break;
        }
        let Some(der) = decoded_body(&current) else { break };
        let smime_type = param(&params, "smime-type").unwrap_or("").to_ascii_lowercase();
        let is_signed = smime_type == "signed-data" || content_info(&der).is_some_and(|i| i.content_type == ID_SIGNED_DATA);
        if is_signed {
            let (result, content) = verify_signed_data(Some(app), &der, None, &sender);
            status.signature = Some(result);
            if let Some(content) = content {
                current = with_outer(&current, &content);
            }
            break;
        }
        status.encrypted = true;
        let Some(identity) = identity(app, account_id).await else {
            status.problem = Some("This message is encrypted with S/MIME. Add your certificate in Settings to read it here.".into());
            break;
        };
        match decrypt(&der, &identity) {
            Ok(entity) => {
                status.decrypted = true;
                current = with_outer(&current, &entity);
            }
            Err(problem) => {
                status.problem = Some(problem);
                break;
            }
        }
    }
    (current, Some(status))
}

/// Keeps the certificate of a correspondent whose signed message arrived, so that mail to
/// them can be encrypted.
pub async fn collect(app: &App, account_id: i64, raw: &[u8]) {
    let head = &raw[..find_header_end(raw).min(raw.len())];
    let lower = String::from_utf8_lossy(head).to_ascii_lowercase();
    if !lower.contains("pkcs7-signature") && !lower.contains("signed-data") {
        return;
    }
    let (_, status) = view(app, account_id, raw.to_vec()).await;
    let Some(signature) = status.and_then(|s| s.signature) else { return };
    let (Some(certificate), Some(info)) = (&signature.certificate, &signature.signer) else { return };
    if !matches!(signature.status, "valid" | "untrusted") || !signature.matches_sender {
        return;
    }
    // Anyone can make a self-signed certificate for any address and forge the From header.
    // An unverified certificate is kept only when the sender itself was authenticated (DMARC
    // passed, or a user of this server sent it); otherwise later "encrypted" mail would be
    // encrypted to an impostor's key.
    if signature.status == "untrusted" {
        let verdict = crate::security::summary::summarize(raw, &app.cfg.hostname).verdict;
        if !matches!(verdict, "verified" | "internal") {
            return;
        }
    }
    let sender = author(raw);
    let _ = sqlx::query(
        "INSERT INTO smime_certificates (account_id, email, certificate, not_after, updated_at) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (account_id, email) DO UPDATE SET certificate = excluded.certificate, not_after = excluded.not_after, updated_at = excluded.updated_at
         WHERE excluded.not_after >= smime_certificates.not_after",
    )
    .bind(account_id)
    .bind(&sender)
    .bind(STANDARD.encode(certificate))
    .bind(info.not_after)
    .bind(now())
    .execute(&app.db)
    .await;
}

/// The certificates known for `emails` (lower-case address → DER), valid now.
pub async fn certificates(app: &App, account_id: i64, emails: &[String]) -> sqlx::Result<std::collections::HashMap<String, Vec<u8>>> {
    let mut out = std::collections::HashMap::new();
    for email in emails {
        let row: Option<String> = sqlx::query_scalar("SELECT certificate FROM smime_certificates WHERE account_id = ? AND email = ? AND not_after > ?").bind(account_id).bind(email.to_ascii_lowercase()).bind(now()).fetch_optional(&app.db).await?;
        if let Some(cert) = row.and_then(|c| STANDARD.decode(c).ok()) {
            out.insert(email.to_ascii_lowercase(), cert);
        }
    }
    Ok(out)
}

#[cfg(test)]
pub mod tests {
    use rsa::pkcs8::EncodePrivateKey;

    use super::*;

    #[test]
    fn hostile_mime_and_cms_do_not_panic() {
        for raw in crate::fuzzing::inputs(5, 2000, 16) {
            let _ = content_type(&raw);
            let _ = split_signed(&raw, "b");
            let _ = decoded_body(&raw);
            let _ = cert_info(&raw);
            let (signature, _) = verify_signed_data(None, &raw, Some(b"content"), "a@b.example");
            assert_ne!(signature.status, "valid");
            let _ = split_entity(&raw);
        }
    }


    /// Rewrites the constructed elements of the first `levels` levels with indefinite lengths.
    fn indefinite(der: &[u8], levels: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < der.len() {
            let (header, length) = der_header(&der[pos..]).unwrap();
            let body = &der[pos + header..pos + header + length];
            if levels > 0 && der[pos] & 0x20 != 0 {
                out.extend_from_slice(&[der[pos], 0x80]);
                out.extend(indefinite(body, levels - 1));
                out.extend_from_slice(&[0, 0]);
            } else {
                out.extend_from_slice(&der[pos..pos + header + length]);
            }
            pos += header + length;
        }
        out
    }

    /// A self-signed RSA certificate for `email`: (certificate DER, PKCS #8 key DER).
    pub fn certificate(email: &str) -> (Vec<u8>, Vec<u8>) {
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pkcs8 = key.to_pkcs8_der().unwrap().as_bytes().to_vec();
        let pair = rcgen::KeyPair::try_from(pkcs8.as_slice()).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![rcgen::SanType::Rfc822Name(email.try_into().unwrap())];
        params.distinguished_name.push(rcgen::DnType::CommonName, email);
        let cert = params.self_signed(&pair).unwrap();
        (cert.der().to_vec(), pkcs8)
    }

    #[test]
    fn sign_verify_encrypt_decrypt() {
        let (cert, key) = certificate("bob@example.org");
        let identity = Identity { certificate: cert.clone(), chain: Vec::new(), key: RsaPrivateKey::from_pkcs8_der(&key).unwrap() };
        let message = b"From: Bob <bob@example.org>\r\nTo: alice@example.net\r\nSubject: Signed\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello, this is signed.\r\n";

        let signed = sign(message, &identity).unwrap();
        let text = String::from_utf8_lossy(&signed).into_owned();
        assert!(text.starts_with("From: Bob <bob@example.org>\r\nTo: alice@example.net\r\nSubject: Signed\r\nMIME-Version: 1.0\r\nContent-Type: multipart/signed;"), "{text}");
        let (_, params) = content_type(&signed).unwrap();
        let (entity, signature) = split_signed(&signed, param(&params, "boundary").unwrap()).unwrap();
        assert_eq!(entity, b"Content-Type: text/plain; charset=utf-8\r\n\r\nHello, this is signed.\r\n");
        let (result, _) = verify_signed_data(None, &signature, Some(&entity), "bob@example.org");
        assert_eq!(result.status, "untrusted", "{result:?}");
        assert!(result.matches_sender);
        assert_eq!(result.signer.unwrap().emails, ["bob@example.org"]);
        let mut tampered = entity.clone();
        tampered[30] ^= 1;
        assert_eq!(verify_signed_data(None, &signature, Some(&tampered), "bob@example.org").0.status, "invalid");

        // As NSS writes it: the outer structures with indefinite lengths.
        let ber = indefinite(&signature, 3);
        assert!(ContentInfo::from_der(&ber).is_err());
        assert_eq!(ber_to_der(&ber).as_deref(), Some(&signature[..]));
        assert_eq!(verify_signed_data(None, &ber, Some(&entity), "bob@example.org").0.status, "untrusted");

        let encrypted = encrypt(&signed, std::slice::from_ref(&cert)).unwrap();
        let text = String::from_utf8_lossy(&encrypted).into_owned();
        assert!(text.contains("smime-type=enveloped-data") && !text.contains("Hello, this is signed"));
        let der = decoded_body(&encrypted).unwrap();
        let inner = decrypt(&der, &identity).unwrap();
        assert!(String::from_utf8_lossy(&inner).contains("multipart/signed"));
        let (other, other_key) = certificate("eve@example.org");
        let eve = Identity { certificate: other, chain: Vec::new(), key: RsaPrivateKey::from_pkcs8_der(&other_key).unwrap() };
        assert!(decrypt(&der, &eve).is_err());
    }

    #[tokio::test]
    async fn certificate_paths_enforce_ca_usage_validity_and_email_purpose() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType};
        let dir = tempfile::tempdir().unwrap();
        let app = crate::app::App::new(crate::config::Config::for_tests(dir.path().to_owned()), None).await.unwrap();
        let roots = dir.path().join("smime-roots");
        std::fs::create_dir(&roots).unwrap();
        let mut root = CertificateParams::new(Vec::<String>::new()).unwrap();
        root.distinguished_name.push(DnType::CommonName, "Test root");
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let root_key = KeyPair::generate().unwrap();
        std::fs::write(roots.join("root.pem"), root.self_signed(&root_key).unwrap().pem()).unwrap();
        for case in ["valid", "non-ca", "wrong-key-usage", "expired", "wrong-purpose"] {
            let mut issuer = CertificateParams::new(Vec::<String>::new()).unwrap();
            issuer.distinguished_name.push(DnType::CommonName, "Intermediate");
            issuer.is_ca = if case == "non-ca" { IsCa::ExplicitNoCa } else { IsCa::Ca(BasicConstraints::Unconstrained) };
            issuer.key_usages = vec![if case == "wrong-key-usage" { KeyUsagePurpose::DigitalSignature } else { KeyUsagePurpose::KeyCertSign }];
            if case == "expired" { issuer.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1); }
            let issuer_key = KeyPair::generate().unwrap();
            let issuer_cert = issuer.signed_by(&issuer_key, &Issuer::from_params(&root, &root_key)).unwrap();
            let mut leaf = CertificateParams::new(Vec::<String>::new()).unwrap();
            leaf.subject_alt_names = vec![SanType::Rfc822Name("ceo@example.org".try_into().unwrap())];
            leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            leaf.extended_key_usages = vec![if case == "wrong-purpose" { ExtendedKeyUsagePurpose::ServerAuth } else { ExtendedKeyUsagePurpose::EmailProtection }];
            let cert = leaf.signed_by(&KeyPair::generate().unwrap(), &Issuer::from_params(&issuer, &issuer_key)).unwrap();
            assert_eq!(trusted(Some(&app), cert.der(), &[issuer_cert.der().to_vec()]), case == "valid", "{case}");
        }
    }
}

/// Writes test material for checking against another implementation (OpenSSL):
/// `UNOMAIL_SMIME_OUT=dir cargo test --lib smime::interop -- --ignored`. When the directory
/// holds `openssl-signed.eml` and `openssl-encrypted.eml` (made with the key written there),
/// they are checked too.
#[cfg(test)]
mod interop {
    use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};

    use super::*;

    #[test]
    #[ignore]
    fn interop() {
        let Ok(dir) = std::env::var("UNOMAIL_SMIME_OUT") else { return };
        let dir = std::path::Path::new(&dir);
        let key_path = dir.join("key.pem");
        let (cert, key) = if key_path.exists() {
            let key = RsaPrivateKey::from_pkcs8_pem(&std::fs::read_to_string(&key_path).unwrap()).unwrap();
            let cert = x509_parser::pem::parse_x509_pem(&std::fs::read(dir.join("cert.pem")).unwrap()).unwrap().1.contents;
            (cert, key)
        } else {
            let (cert, pkcs8) = tests::certificate("bob@example.org");
            let key = RsaPrivateKey::from_pkcs8_der(&pkcs8).unwrap();
            std::fs::write(&key_path, key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes()).unwrap();
            std::fs::write(dir.join("cert.pem"), format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", wrap_base64(&cert).replace("\r\n", "\n"))).unwrap();
            (cert, key)
        };
        let identity = Identity { certificate: cert.clone(), chain: Vec::new(), key };
        let message = b"From: bob@example.org\r\nTo: alice@example.net\r\nSubject: Interop\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nInterop works.\r\n";
        std::fs::write(dir.join("signed.eml"), sign(message, &identity).unwrap()).unwrap();
        std::fs::write(dir.join("encrypted.eml"), encrypt(message, std::slice::from_ref(&cert)).unwrap()).unwrap();
        if let Ok(theirs) = std::fs::read(dir.join("openssl-signed.eml")) {
            let (_, params) = content_type(&theirs).unwrap();
            let (entity, signature) = split_signed(&theirs, param(&params, "boundary").unwrap()).unwrap();
            let (result, _) = verify_signed_data(None, &signature, Some(&entity), "bob@example.org");
            assert_eq!(result.status, "untrusted", "{result:?}");
            println!("openssl signature verified");
        }
        if let Ok(theirs) = std::fs::read(dir.join("openssl-encrypted.eml")) {
            let inner = decrypt(&decoded_body(&theirs).unwrap(), &identity).unwrap();
            assert!(String::from_utf8_lossy(&inner).contains("From OpenSSL"), "{}", String::from_utf8_lossy(&inner));
            println!("openssl encryption decrypted");
        }
    }
}
