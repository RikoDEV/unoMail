//! Sender Rewriting Scheme (SRS0) for forwarded mail.
//!
//! When mail from `user@origin.example` is forwarded by one of our domains, the envelope sender
//! is rewritten to `SRS0=HHHH=TT=origin.example=user@our.example` so that SPF checks at the
//! final destination evaluate our domain, and bounces can be routed back to the original sender.

use crate::util::{Address, ct_eq, hmac_sha256, now};

const HASH_LEN: usize = 8;
/// Bounces are accepted for this long after the forward was sent.
const MAX_AGE_DAYS: i64 = 21;
const TIMESTAMP_MODULUS: i64 = 1024;
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn timestamp(day: i64) -> String {
    let slot = day.rem_euclid(TIMESTAMP_MODULUS) as usize;
    String::from_utf8(vec![BASE32[slot >> 5], BASE32[slot & 31]]).expect("base32 alphabet is ASCII")
}

fn parse_timestamp(ts: &str) -> Option<i64> {
    let bytes = ts.as_bytes();
    if bytes.len() != 2 {
        return None;
    }
    let digit = |b: u8| BASE32.iter().position(|c| c.eq_ignore_ascii_case(&b));
    Some(((digit(bytes[0])? << 5) | digit(bytes[1])?) as i64)
}

fn hash(secret: &str, ts: &str, domain: &str, local: &str) -> String {
    let data = format!("{}\0{}\0{}", ts.to_ascii_uppercase(), domain.to_ascii_lowercase(), local.to_ascii_lowercase());
    // Hex, because intermediate servers (and our own address parser) may lowercase local parts.
    let mut encoded = hex::encode(hmac_sha256(secret.as_bytes(), data.as_bytes()));
    encoded.truncate(HASH_LEN);
    encoded
}

/// Rewrites `sender` so that it belongs to `forwarder_domain`. Returns `None` when the result
/// would not fit in a local part, in which case the caller falls back to a null sender.
pub fn forward(secret: &str, sender: &Address, forwarder_domain: &str) -> Option<String> {
    forward_at(secret, sender, forwarder_domain, now() / 86400)
}

fn forward_at(secret: &str, sender: &Address, forwarder_domain: &str, day: i64) -> Option<String> {
    // Already ours (or already rewritten by us): nothing to do.
    if sender.domain == forwarder_domain {
        return Some(sender.to_string());
    }
    let ts = timestamp(day);
    let local = format!("SRS0={}={}={}={}", hash(secret, &ts, &sender.domain, &sender.local), ts, sender.domain, sender.local);
    (local.len() <= 64).then(|| format!("{local}@{forwarder_domain}"))
}

pub fn is_srs(local: &str) -> bool {
    // `get`, not slicing: the local part may contain multi-byte characters.
    local.len() > 5 && local.get(..5).is_some_and(|prefix| prefix.eq_ignore_ascii_case("srs0="))
}

/// Recovers the original sender from an SRS0 local part, verifying the signature and age.
/// Forged or expired addresses yield `None`, so we never become a bounce relay.
pub fn reverse(secret: &str, local: &str) -> Option<Address> {
    reverse_at(secret, local, now() / 86400)
}

fn reverse_at(secret: &str, local: &str, day: i64) -> Option<Address> {
    if !is_srs(local) {
        return None;
    }
    let mut parts = local[5..].splitn(4, '=');
    let (sig, ts, domain, orig_local) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    if !ct_eq(sig.to_ascii_lowercase().as_bytes(), hash(secret, ts, domain, orig_local).as_bytes()) {
        return None;
    }
    let age = (day.rem_euclid(TIMESTAMP_MODULUS) - parse_timestamp(ts)?).rem_euclid(TIMESTAMP_MODULUS);
    if age > MAX_AGE_DAYS {
        return None;
    }
    Address::parse(&format!("{orig_local}@{domain}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret";

    fn addr(s: &str) -> Address {
        Address::parse(s).unwrap()
    }

    #[test]
    fn round_trip() {
        let rewritten = forward_at(SECRET, &addr("alice@origin.example"), "fwd.example", 20000).unwrap();
        assert!(rewritten.starts_with("SRS0="), "{rewritten}");
        assert!(rewritten.ends_with("=origin.example=alice@fwd.example"));
        let local = rewritten.rsplit_once('@').unwrap().0;
        assert_eq!(reverse_at(SECRET, local, 20000).unwrap(), addr("alice@origin.example"));
        // Receiving servers may lowercase the local part.
        assert_eq!(reverse_at(SECRET, &local.to_ascii_lowercase(), 20005).unwrap(), addr("alice@origin.example"));
        assert_eq!(reverse_at(SECRET, local, 20005).unwrap(), addr("alice@origin.example"));
    }

    #[test]
    fn rejects_forged_expired_and_malformed() {
        let rewritten = forward_at(SECRET, &addr("alice@origin.example"), "fwd.example", 20000).unwrap();
        let local = rewritten.rsplit_once('@').unwrap().0;
        assert!(reverse_at("other-secret", local, 20000).is_none());
        assert!(reverse_at(SECRET, &local.replace("alice", "mallory"), 20000).is_none());
        assert!(reverse_at(SECRET, &local.replace("origin.example", "victim.example"), 20000).is_none());
        assert!(reverse_at(SECRET, local, 20000 + MAX_AGE_DAYS + 1).is_none());
        // Timestamp wrap-around is handled.
        let wrapped = forward_at(SECRET, &addr("a@b.example"), "fwd.example", 1023).unwrap();
        assert!(reverse_at(SECRET, wrapped.rsplit_once('@').unwrap().0, 1024 + 3).is_some());
        for bad in ["", "alice", "SRS0=", "SRS0=abc", "SRS0=a=b=c", "SRS1=a=b=c=d"] {
            assert!(reverse_at(SECRET, bad, 20000).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn local_senders_are_not_rewritten_and_long_ones_are_refused() {
        assert_eq!(forward(SECRET, &addr("bob@fwd.example"), "fwd.example").unwrap(), "bob@fwd.example");
        let long = addr(&format!("{}@a-rather-long-domain-name.example", "x".repeat(40)));
        assert!(forward(SECRET, &long, "fwd.example").is_none());
    }
}
