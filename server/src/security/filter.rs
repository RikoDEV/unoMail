//! The server's own spam tests, run on incoming mail after the content filter:
//!
//! - **Links**: addresses written as IP numbers, look-alike (homograph) domains, user names in
//!   front of the host (`https://bank.example@evil.example`), link shorteners, links whose
//!   visible text names a different domain than they lead to, and floods of domains.
//! - **Reputation**: what was learned about the sending network (the /24 or /48), its
//!   autonomous system and the verified sender domain, from the server's verdicts, spam traps
//!   and users' "spam" / "not spam" decisions.
//! - **Origin**: autonomous systems and countries the administrator penalises, looked up in
//!   the DNS service of Team Cymru (`origin.asn.cymru.com`), so no database is shipped.
//! - **Spam traps**: addresses that no person uses. Whatever is sent to them teaches the
//!   reputation that its source sends spam, and is never delivered.
//!
//! The tests add up to a score, recorded in an `X-Unomail-Filter` header together with the
//! reputation keys of the message (so a user's later decision can be learned from it). Mail
//! at or above the administrator's threshold goes to Junk.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::LazyLock,
};

use mail_parser::MessageParser;
use parking_lot::Mutex;
use regex::Regex;

use crate::{app::App, util::now};

pub const HEADER: &str = "X-Unomail-Filter";

const MAX_TEXT_BYTES: usize = 512 * 1024;
const MAX_URLS: usize = 500;
/// Verdicts needed on a key before its reputation counts.
const MIN_SAMPLES: i64 = 5;
const SHORTENERS: [&str; 16] = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "v.gd", "s.id", "shorte.st",
];

/// One test that matched, with its points.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub name: &'static str,
    pub score: f64,
}

/// What the tests found about a message.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Assessment {
    pub score: f64,
    pub hits: Vec<Hit>,
    /// Reputation keys of the message: `ip:…`, `asn:…`, `domain:…`.
    pub keys: Vec<String>,
}

impl Assessment {
    fn add(&mut self, name: &'static str, score: f64) {
        self.score += score;
        self.hits.push(Hit { name, score });
    }

    /// The header recording the outcome; ends with CRLF.
    pub fn header(&self) -> String {
        let tests = if self.hits.is_empty() { "none".to_owned() } else { self.hits.iter().map(|h| format!("{}={:.1}", h.name, h.score)).collect::<Vec<_>>().join(",") };
        format!("{HEADER}: score={:.1}; tests={tests}; keys={}\r\n", self.score, self.keys.join(","))
    }
}

// --- Links -----------------------------------------------------------------------------------

static URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)\bhttps?://[^\s"'<>()\[\]{}]+"#).expect("valid regex"));
static ANCHOR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?is)<a\s[^>]*?href\s*=\s*["']?([^"'\s>]+)["']?[^>]*>(.*?)</a\s*>"#).expect("valid regex"));
static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<[^>]*>").expect("valid regex"));

/// The host of an http(s) URL, lower case, and whether a user name precedes it.
fn host_of(url: &str) -> Option<(String, bool)> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let (userinfo, host) = match authority.rsplit_once('@') {
        Some((user, host)) => (!user.is_empty(), host),
        None => (false, authority),
    };
    let host = if host.starts_with('[') { host.split(']').next()?.trim_start_matches('[') } else { host.rsplit_once(':').map_or(host, |(h, port)| if port.bytes().all(|b| b.is_ascii_digit()) { h } else { host }) };
    let host = host.trim_end_matches('.').to_lowercase();
    (!host.is_empty()).then_some((host, userinfo))
}

/// The last two labels of a host: a cheap stand-in for the registrable domain.
fn base_domain(host: &str) -> String {
    let labels: Vec<&str> = host.rsplit('.').take(2).collect();
    labels.into_iter().rev().collect::<Vec<_>>().join(".")
}

/// Latin letters mixed with Cyrillic or Greek ones in one label: the stuff of look-alike domains.
fn mixed_script(host: &str) -> bool {
    let (unicode, _) = idna::domain_to_unicode(host);
    unicode.split('.').any(|label| {
        // Greek (U+0370) up to the end of Cyrillic Supplement (U+052F).
        let latin = label.chars().any(|c| c.is_ascii_alphabetic());
        let other = label.chars().any(|c| matches!(c as u32, 0x370..=0x52F));
        latin && other
    })
}

/// Whether anchor text reads like an address of its own (`www.bank.example`, `https://…`).
fn text_domain(text: &str) -> Option<String> {
    let text = text.trim().trim_end_matches('/');
    if text.is_empty() || text.contains(char::is_whitespace) || !text.contains('.') {
        return None;
    }
    let with_scheme = if text.contains("://") { text.to_owned() } else { format!("http://{text}") };
    let (host, _) = host_of(&with_scheme)?;
    // A word with a dot ("e.g.") is not a domain: a domain ends in letters.
    let tld = host.rsplit('.').next()?;
    (tld.len() >= 2 && tld.chars().all(|c| c.is_alphabetic())).then_some(host)
}

/// Link tests on the text of a message.
pub fn link_tests(raw: &[u8], assessment: &mut Assessment) {
    let Some(message) = MessageParser::default().parse(raw) else { return };
    let mut text = String::new();
    for index in 0..message.text_body.len().min(10) {
        if let Some(part) = message.body_text(index) {
            text.push_str(&part);
            text.push('\n');
        }
    }
    let mut html = String::new();
    for index in 0..message.html_body.len().min(10) {
        if let Some(part) = message.body_html(index) {
            html.push_str(&part);
            html.push('\n');
        }
    }
    text.truncate(text.char_indices().nth(MAX_TEXT_BYTES).map_or(text.len(), |(i, _)| i));
    html.truncate(html.char_indices().nth(MAX_TEXT_BYTES).map_or(html.len(), |(i, _)| i));

    let mut hosts: HashSet<String> = HashSet::new();
    let (mut ip, mut homograph, mut userinfo, mut shortener) = (false, false, false, false);
    let mut note = |url: &str| {
        let Some((host, has_user)) = host_of(url) else { return };
        ip |= host.parse::<IpAddr>().is_ok();
        homograph |= (host.split('.').any(|l| l.starts_with("xn--")) || !host.is_ascii()) && mixed_script(&host);
        userinfo |= has_user;
        shortener |= SHORTENERS.contains(&host.as_str());
        hosts.insert(host);
    };
    for found in URL.find_iter(&text).chain(URL.find_iter(&html)).take(MAX_URLS) {
        note(found.as_str());
    }
    let mut mismatch = false;
    for anchor in ANCHOR.captures_iter(&html).take(MAX_URLS) {
        let href = anchor[1].replace("&amp;", "&");
        note(&href);
        let shown = TAG.replace_all(&anchor[2], "").replace("&nbsp;", " ");
        if let (Some((target, _)), Some(claimed)) = (host_of(&href), text_domain(&shown)) {
            let (target, claimed) = (base_domain(&target), base_domain(&claimed));
            mismatch |= target != claimed;
        }
    }
    if ip {
        assessment.add("URL_IP_LITERAL", 2.5);
    }
    if homograph {
        assessment.add("URL_HOMOGRAPH", 3.0);
    }
    if userinfo {
        assessment.add("URL_USERINFO", 2.0);
    }
    if shortener {
        assessment.add("URL_SHORTENER", 1.0);
    }
    if mismatch {
        assessment.add("URL_TEXT_MISMATCH", 3.5);
    }
    if hosts.len() > 15 {
        assessment.add("URL_MANY_DOMAINS", 1.0);
    }
}

// --- Origin (ASN and country) ----------------------------------------------------------------

/// Where an address is announced from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub asn: u32,
    /// ISO 3166 code, upper case; empty when not known.
    pub country: String,
}

/// The DNS name asking Team Cymru about `ip`.
pub fn origin_query(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.origin.asn.cymru.com")
        }
        IpAddr::V6(v6) => {
            let nibbles: String = v6.octets().iter().rev().flat_map(|byte| [byte & 0x0f, byte >> 4]).map(|n| format!("{n:x}.")).collect();
            format!("{nibbles}origin6.asn.cymru.com")
        }
    }
}

/// Reads an answer such as `13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11`. Several ASNs may
/// announce a prefix; the first is taken.
pub fn parse_origin(txt: &str) -> Option<Origin> {
    let mut fields = txt.split('|').map(str::trim);
    let asn = fields.next()?.split_whitespace().next()?.parse().ok()?;
    let country = fields.nth(1).unwrap_or("").to_ascii_uppercase();
    let country = if country.len() == 2 && country.bytes().all(|b| b.is_ascii_alphabetic()) { country } else { String::new() };
    Some(Origin { asn, country })
}

/// Looked-up origins: (when, what was found).
type OriginCache = HashMap<IpAddr, (i64, Option<Origin>)>;

static ORIGINS: LazyLock<Mutex<OriginCache>> = LazyLock::new(Default::default);

/// The origin of a public address, cached for a day.
pub async fn origin(app: &App, ip: IpAddr) -> Option<Origin> {
    if crate::security::reputation::is_private(ip) {
        return None;
    }
    if let Some((at, cached)) = ORIGINS.lock().get(&ip)
        && now() - at < 86_400
    {
        return cached.clone();
    }
    let resolver = app.authenticator.as_ref()?;
    let found = crate::dns::txt(resolver, &origin_query(ip)).await.ok().and_then(|answers| answers.iter().find_map(|a| parse_origin(a)));
    let mut cache = ORIGINS.lock();
    if cache.len() >= 10_000 {
        cache.clear();
    }
    cache.insert(ip, (now(), found.clone()));
    found
}

// --- Reputation ------------------------------------------------------------------------------

/// The network an address belongs to for reputation: its /24, or /48 for IPv6.
pub fn network_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("ip:{a}.{b}.{c}.0/24")
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("ip:{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

/// Points for a reputation: spam-only sources score high, consistently good ones lose a little.
pub fn reputation_score(ham: i64, spam: i64) -> f64 {
    let total = ham + spam;
    if total < MIN_SAMPLES {
        return 0.0;
    }
    let ratio = spam as f64 / total as f64;
    if ratio >= 0.9 {
        3.0
    } else if ratio >= 0.6 {
        1.5
    } else if ratio <= 0.1 && total >= 2 * MIN_SAMPLES {
        -1.0
    } else {
        0.0
    }
}

async fn reputation_tests(app: &App, assessment: &mut Assessment) {
    for key in assessment.keys.clone() {
        let row: Option<(i64, i64)> = sqlx::query_as("SELECT ham, spam FROM sender_reputation WHERE key = ?").bind(&key).fetch_optional(&app.db).await.ok().flatten();
        let Some((ham, spam)) = row else { continue };
        let points = reputation_score(ham, spam);
        // Large autonomous systems carry everybody's mail: their record counts for half.
        let points = if key.starts_with("asn:") { points / 2.0 } else { points };
        if points == 0.0 {
            continue;
        }
        let name = match (key.split(':').next(), points > 0.0) {
            (Some("ip"), true) => "REP_NETWORK_BAD",
            (Some("ip"), false) => "REP_NETWORK_GOOD",
            (Some("asn"), true) => "REP_ASN_BAD",
            (Some("asn"), false) => "REP_ASN_GOOD",
            (_, true) => "REP_DOMAIN_BAD",
            (_, false) => "REP_DOMAIN_GOOD",
        };
        assessment.add(name, points);
    }
}

/// Records a verdict on every key of a message.
pub async fn learn(app: &App, keys: &[String], spam: bool) {
    for key in keys.iter().take(8) {
        let result = sqlx::query(
            "INSERT INTO sender_reputation (key, ham, spam, updated_at) VALUES (?, ?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET ham = ham + excluded.ham, spam = spam + excluded.spam, updated_at = excluded.updated_at",
        )
        .bind(key)
        .bind(i64::from(!spam))
        .bind(i64::from(spam))
        .bind(now())
        .execute(&app.db)
        .await;
        if let Err(err) = result {
            tracing::warn!(%err, "sender reputation not updated");
        }
    }
}

/// The reputation keys recorded in a stored message's filter header, which the server wrote
/// itself (any copy that came from outside is removed on arrival).
pub fn keys_in(raw: &[u8]) -> Vec<String> {
    let end = crate::security::authn::find_header_end(raw).min(raw.len());
    let headers = String::from_utf8_lossy(&raw[..end]);
    let prefix = format!("{}:", HEADER.to_ascii_lowercase());
    headers
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with(&prefix))
        .and_then(|line| line.split("keys=").nth(1))
        .map(|keys| keys.trim().split(',').filter(|k| !k.is_empty()).take(8).map(str::to_owned).collect())
        .unwrap_or_default()
}

/// A user's decision on a stored message teaches the reputation of its source.
pub async fn learn_from_message(app: &App, raw: &[u8], spam: bool) {
    let keys = keys_in(raw);
    if !keys.is_empty() {
        learn(app, &keys, spam).await;
    }
}

/// Drops filter headers that arrived with a message, so only the server's own is trusted.
pub fn strip_header(raw: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    let end = crate::security::authn::find_header_end(raw).min(raw.len());
    let prefix = format!("{}:", HEADER.to_ascii_lowercase());
    let head = &raw[..end];
    if !String::from_utf8_lossy(head).to_ascii_lowercase().contains(&prefix) {
        return std::borrow::Cow::Borrowed(raw);
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut skipping = false;
    for line in head.split_inclusive(|b| *b == b'\n') {
        let continuation = line.first().is_some_and(|b| *b == b' ' || *b == b'\t');
        if !continuation {
            skipping = String::from_utf8_lossy(line).to_ascii_lowercase().starts_with(&prefix);
        }
        if !skipping {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(&raw[end..]);
    std::borrow::Cow::Owned(out)
}

// --- Putting it together ---------------------------------------------------------------------

/// What the filter knows about a message's sender.
pub struct Sender<'a> {
    pub ip: IpAddr,
    /// A domain the message is verified to come from (DMARC-aligned author or SPF-passing
    /// envelope sender), if any.
    pub verified_domain: Option<&'a str>,
}

/// Runs every test on a message.
pub async fn assess(app: &App, sender: &Sender<'_>, raw: &[u8]) -> Assessment {
    let mut assessment = Assessment::default();
    let rt = app.rt();
    if !crate::security::reputation::is_private(sender.ip) {
        assessment.keys.push(network_key(sender.ip));
    }
    if let Some(origin) = origin(app, sender.ip).await {
        assessment.keys.push(format!("asn:{}", origin.asn));
        if rt.penalized_asns.contains(&origin.asn.to_string()) {
            assessment.add("ORIGIN_ASN", rt.origin_score);
        }
        if !origin.country.is_empty() && rt.penalized_countries.iter().any(|c| c.eq_ignore_ascii_case(&origin.country)) {
            assessment.add("ORIGIN_COUNTRY", rt.origin_score);
        }
    }
    if let Some(domain) = sender.verified_domain {
        assessment.keys.push(format!("domain:{}", domain.to_ascii_lowercase()));
    }
    if rt.sender_reputation {
        reputation_tests(app, &mut assessment).await;
    }
    link_tests(raw, &mut assessment);
    assessment
}

/// Whether `address` is one of the administrator's spam traps.
pub fn is_trap(app: &App, address: &str) -> bool {
    app.rt().spam_traps.iter().any(|trap| trap.eq_ignore_ascii_case(address))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assess_links(body: &str, html: bool) -> Vec<&'static str> {
        let kind = if html { "text/html" } else { "text/plain" };
        let raw = format!("From: a@b.example\r\nTo: c@d.example\r\nSubject: x\r\nContent-Type: {kind}; charset=utf-8\r\n\r\n{body}\r\n");
        let mut assessment = Assessment::default();
        link_tests(raw.as_bytes(), &mut assessment);
        assessment.hits.iter().map(|h| h.name).collect()
    }

    #[test]
    fn links_are_judged() {
        assert!(assess_links("Hello, see https://example.org/page and https://www.example.org", false).is_empty());
        assert_eq!(assess_links("Log in at http://192.0.2.7/login", false), ["URL_IP_LITERAL"]);
        assert_eq!(assess_links("https://bank.example@evil.example/x", false), ["URL_USERINFO"]);
        assert_eq!(assess_links("https://bit.ly/abc", false), ["URL_SHORTENER"]);
        // A Cyrillic letter among Latin ones, written as punycode or as it is.
        let look_alike = idna::domain_to_ascii("p\u{0430}ypal.com").unwrap();
        assert!(look_alike.starts_with("xn--"));
        assert_eq!(assess_links(&format!("https://{look_alike}/"), false), ["URL_HOMOGRAPH"]);
        assert_eq!(assess_links("https://p\u{0430}ypal.com/", false), ["URL_HOMOGRAPH"]);
        assert!(assess_links("https://xn--bcher-kva.example/", false).is_empty(), "a German umlaut is no look-alike");
        assert_eq!(assess_links(r#"<a href="https://evil.example/x">https://www.mybank.example</a>"#, true), ["URL_TEXT_MISMATCH"]);
        assert!(assess_links(r#"<a href="https://news.mybank.example/x">www.mybank.example</a> <a href="https://x.example">Click here</a>"#, true).is_empty());
        let many: String = (0..20).map(|i| format!("https://site{i}.example/ ")).collect();
        assert_eq!(assess_links(&many, false), ["URL_MANY_DOMAINS"]);
    }

    #[test]
    fn hosts_are_read_like_a_browser() {
        assert_eq!(host_of("https://Example.ORG:8443/a"), Some(("example.org".into(), false)));
        assert_eq!(host_of("http://[2001:db8::1]/"), Some(("2001:db8::1".into(), false)));
        assert_eq!(host_of("http://user:pw@host.example/"), Some(("host.example".into(), true)));
        assert_eq!(text_domain("Click here"), None);
        assert_eq!(text_domain("e.g."), None);
        assert_eq!(text_domain("WWW.Bank.example/login"), Some("www.bank.example".into()));
    }

    #[test]
    fn origins_are_parsed() {
        assert_eq!(origin_query("192.0.2.10".parse().unwrap()), "10.2.0.192.origin.asn.cymru.com");
        assert!(origin_query("2001:db8::1".parse().unwrap()).ends_with(".8.b.d.0.1.0.0.2.origin6.asn.cymru.com"));
        assert_eq!(parse_origin("13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"), Some(Origin { asn: 13335, country: "AU".into() }));
        assert_eq!(parse_origin("23028 1234 | 216.90.108.0/24 | us | arin |"), Some(Origin { asn: 23028, country: "US".into() }));
        assert_eq!(parse_origin("garbage"), None);
    }

    #[test]
    fn reputation_needs_evidence() {
        assert_eq!(reputation_score(0, 4), 0.0);
        assert_eq!(reputation_score(0, 5), 3.0);
        assert_eq!(reputation_score(3, 7), 1.5);
        assert_eq!(reputation_score(9, 1), -1.0);
        assert_eq!(reputation_score(4, 0), 0.0);
        assert_eq!(network_key("192.0.2.77".parse().unwrap()), "ip:192.0.2.0/24");
        assert_eq!(network_key("2001:db8:1:2::5".parse().unwrap()), "ip:2001:db8:1::/48");
    }

    #[test]
    fn the_header_carries_the_keys_and_forged_ones_are_removed() {
        let assessment = Assessment { score: 3.5, hits: vec![Hit { name: "URL_TEXT_MISMATCH", score: 3.5 }], keys: vec!["ip:192.0.2.0/24".into(), "asn:64500".into()] };
        let header = assessment.header();
        assert_eq!(header, "X-Unomail-Filter: score=3.5; tests=URL_TEXT_MISMATCH=3.5; keys=ip:192.0.2.0/24,asn:64500\r\n");
        let raw = format!("{header}Subject: x\r\n\r\nbody");
        assert_eq!(keys_in(raw.as_bytes()), ["ip:192.0.2.0/24", "asn:64500"]);
        let forged = b"Subject: x\r\nX-Unomail-Filter: score=0.0; keys=domain:bank.example\r\n\tcontinued\r\nTo: y\r\n\r\nX-Unomail-Filter: in the body stays\r\n";
        assert_eq!(&*strip_header(forged), b"Subject: x\r\nTo: y\r\n\r\nX-Unomail-Filter: in the body stays\r\n".as_slice());
    }
}
