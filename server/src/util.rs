//! Small shared helpers: randomness, hashing, address validation.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    digest, hmac,
    rand::{SecureRandom, SystemRandom},
};

pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    // The system CSPRNG failing is unrecoverable; refusing to continue is the only safe option.
    SystemRandom::new().fill(&mut buf).expect("system random number generator failed");
    buf
}

/// 256 bits of entropy, URL-safe.
pub fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes::<32>())
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, data).as_ref());
    out
}

/// Escapes text for HTML element content and attribute values.
pub fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data).as_ref().to_vec()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Validates an ASCII (already IDNA-encoded) domain name.
pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return false;
    }
    // A numeric top-level label means this is an IP address, not a name.
    if domain.rsplit('.').next().is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit())) {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Lowercases and IDNA-encodes a domain, returning `None` when it is not a valid hostname.
pub fn normalize_domain(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.');
    let ascii = idna::domain_to_ascii(domain).ok()?;
    is_valid_domain(&ascii).then_some(ascii)
}

/// Local parts we allow for mailboxes and aliases we host. Deliberately stricter than RFC 5321:
/// no quoting, no path separators or shell metacharacters. Letters and digits of any script
/// are accepted (internationalized addresses, RFC 6531).
pub fn is_valid_local_part(local: &str) -> bool {
    !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+') || (!c.is_ascii() && c.is_alphanumeric()))
}

/// A parsed, normalized e-mail address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    pub local: String,
    pub domain: String,
}

impl Address {
    /// Parses an envelope address. Accepts any RFC 5321 dot-string local part (remote senders
    /// may use characters we don't allow for our own mailboxes) but never control characters,
    /// whitespace or angle brackets, which could be used for header or command injection.
    pub fn parse(addr: &str) -> Option<Self> {
        let addr = addr.trim();
        if addr.len() > 320 {
            return None;
        }
        let (local, domain) = addr.rsplit_once('@')?;
        if local.is_empty() || local.len() > 64 {
            return None;
        }
        // Non-ASCII characters are allowed (RFC 6531) as long as they are printable.
        let ok = local.chars().all(|c| {
            c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~.".contains(c) || (!c.is_ascii() && !c.is_control() && !c.is_whitespace())
        });
        if !ok || local.starts_with('.') || local.ends_with('.') || local.contains("..") {
            return None;
        }
        Some(Address { local: local.to_lowercase(), domain: normalize_domain(domain)? })
    }

    /// False for internationalized addresses, which need the SMTPUTF8 extension in transit.
    pub fn is_ascii(&self) -> bool {
        self.local.is_ascii()
    }

    /// Parses an address that must be usable as a hosted mailbox/alias name.
    pub fn parse_local(addr: &str) -> Option<Self> {
        let a = Self::parse(addr)?;
        is_valid_local_part(&a.local).then_some(a)
    }

    /// The address without any `+tag` subaddress.
    pub fn without_tag(&self) -> Address {
        let local = self.local.split('+').next().unwrap_or(&self.local);
        Address { local: local.to_owned(), domain: self.domain.clone() }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

/// Strips CR/LF and other control characters so a value can be safely placed in a header or log.
pub fn sanitize_line(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(500).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("a-b.example.co.uk"));
        assert!(!is_valid_domain("localhost"));
        assert!(!is_valid_domain("-bad.example.com"));
        assert!(!is_valid_domain("exa mple.com"));
        assert!(!is_valid_domain("example..com"));
        assert!(!is_valid_domain("192.0.2.1"));
        assert_eq!(normalize_domain("ExAmple.COM.").as_deref(), Some("example.com"));
        assert_eq!(normalize_domain("bücher.example").as_deref(), Some("xn--bcher-kva.example"));
        assert_eq!(normalize_domain("../etc"), None);
    }

    #[test]
    fn addresses() {
        let a = Address::parse("John.Doe+tag@Example.com").unwrap();
        assert_eq!(a.to_string(), "john.doe+tag@example.com");
        assert_eq!(a.without_tag().to_string(), "john.doe@example.com");
        for bad in [
            "", "nodomain", "@example.com", "a@", "a b@example.com", "a@b", "a\r\n@example.com",
            "<a>@example.com", ".a@example.com", "a..b@example.com", "\"quoted\"@example.com",
        ] {
            assert!(Address::parse(bad).is_none(), "{bad:?} should be rejected");
        }
        assert!(Address::parse_local("o'brien@example.com").is_none());

        // Internationalized addresses: any printable local part, IDNA domain.
        let utf8 = Address::parse("JÓZEF@Bücher.example").unwrap();
        assert_eq!(utf8.to_string(), "józef@xn--bcher-kva.example");
        assert!(!utf8.is_ascii() && a.is_ascii());
        assert!(Address::parse_local("józef.żółw@example.com").is_some());
        assert!(Address::parse_local("用户@example.com").is_some());
        for bad in ["a\u{200b}b@example.com", "smile😀@example.com"] {
            assert!(Address::parse_local(bad).is_none(), "{bad:?} is not a mailbox name");
        }
        assert!(Address::parse("line\u{2028}break@example.com").is_none());
        assert!(Address::parse("o'brien@example.com").is_some());
    }

    #[test]
    fn tokens_are_unique_and_long() {
        let (a, b) = (random_token(), random_token());
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_line("a\r\nb\0c"), "abc");
    }
}
