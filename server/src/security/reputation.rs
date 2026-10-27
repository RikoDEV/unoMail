//! IP reputation: DNS blocklists and AbuseIPDB lookups.

use std::net::IpAddr;

use serde::Deserialize;

use crate::{app::App, util::now};

const ABUSEIPDB_CACHE_SECS: i64 = 24 * 3600;

/// The DNSBL query name for `ip` in `zone` (reversed octets / nibbles).
pub fn dnsbl_query(ip: IpAddr, zone: &str) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.{}", o[3], o[2], o[1], o[0], zone)
        }
        IpAddr::V6(v6) => {
            let nibbles: Vec<String> =
                v6.octets().iter().rev().flat_map(|b| [format!("{:x}", b & 0xf), format!("{:x}", b >> 4)]).collect();
            format!("{}.{}", nibbles.join("."), zone)
        }
    }
}

/// Addresses that are never looked up in public reputation services, and never connected to
/// on a remote party's behalf: private, loopback, link-local and otherwise non-public ranges,
/// including IPv6 forms that carry such an IPv4 address inside (NAT64, 6to4, IPv4-compatible).
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast()
                // "This network" 0.0.0.0/8, carrier-grade NAT 100.64.0.0/10, IETF protocol
                // assignments 192.0.0.0/24, benchmarking 198.18.0.0/15, reserved 240.0.0.0/4.
                || a == 0
                || (a == 100 && (b & 0xc0) == 64)
                || (a == 192 && b == 0 && c == 0)
                || (a == 198 && (b & 0xfe) == 18)
                || a >= 240
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private(IpAddr::V4(v4));
            }
            let s = v6.segments();
            let embedded = |high: u16, low: u16| is_private(IpAddr::V4(std::net::Ipv4Addr::from((u32::from(high) << 16) | u32::from(low))));
            // NAT64 (64:ff9b::/96) reaches the IPv4 address in its last 32 bits.
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                return embedded(s[6], s[7]);
            }
            // 6to4 (2002::/16) carries the relay's IPv4 address in bits 16 to 47.
            if s[0] == 0x2002 {
                return embedded(s[1], s[2]);
            }
            // Deprecated IPv4-compatible addresses (::a.b.c.d).
            if s[..6] == [0; 6] && !v6.is_loopback() && !v6.is_unspecified() {
                return embedded(s[6], s[7]);
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                // Site-local (deprecated), local-use NAT64 64:ff9b:1::/48, Teredo 2001::/32.
                || (s[0] & 0xffc0) == 0xfec0
                || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1)
                || (s[0] == 0x2001 && s[1] == 0)
        }
    }
}

/// Whether mail and requests from `ip` are trusted like the server's own: loopback, and the
/// networks the operator listed in `UNOMAIL_TRUSTED_NETWORKS`. Private ranges are not trusted
/// by themselves: behind NAT every client can appear to come from one.
pub fn is_trusted_source(cfg: &crate::config::Config, ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    ip.is_loopback() || cfg.trusted_networks.iter().any(|net| net.contains(&ip))
}

/// Logs, once per run, that port 25 sees a private address it does not trust. Usually NAT in
/// front of the server (Docker's userland proxy, a load balancer): all clients then share one
/// address, so blocklists, reputation and greylisting cannot tell them apart.
pub fn note_untrusted_private_peer(ip: IpAddr) {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(
            %ip,
            "inbound SMTP connection from a private address; if a NAT or proxy sits in front of the server, make it pass on client addresses \
             (Docker: publish ports without the userland proxy, or use host networking). List real relays in UNOMAIL_TRUSTED_NETWORKS"
        );
    }
}

/// Whether a blocklist answer lists the address: blocklists answer in 127.0.0.0/8 (anything
/// else is a hijacked or expired zone), but 127.255.255.0/24 reports an error instead, such as
/// Spamhaus refusing queries that come through a public resolver.
fn is_dnsbl_listing(answer: IpAddr) -> bool {
    matches!(answer, IpAddr::V4(v4) if v4.octets()[0] == 127) && !is_dnsbl_error(answer)
}

fn is_dnsbl_error(answer: IpAddr) -> bool {
    matches!(answer, IpAddr::V4(v4) if v4.octets()[..3] == [127, 255, 255])
}

/// Warns once that a blocklist refuses to answer, which leaves it without effect.
fn note_refused_dnsbl(zone: &str) {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(
            zone,
            "the DNS blocklist refuses queries from this server, usually because they reach it through a public resolver (8.8.8.8, 1.1.1.1,              a cloud provider's); its answers are ignored. Use a resolver of your own, e.g. Docker's `dns:` option, or a key-based mirror"
        );
    }
}

/// Zones (from the configured list) that list `ip`. DNS failures count as "not listed".
pub async fn dnsbl_listings(app: &App, ip: IpAddr) -> Vec<String> {
    let Some(resolver) = &app.authenticator else { return Vec::new() };
    if is_private(ip) {
        return Vec::new();
    }
    let settings = app.rt();
    let lookups = settings.dnsbl_zones.iter().map(|zone| async move {
        let listed = match crate::dns::ips(resolver, &dnsbl_query(ip, zone)).await {
            Ok(answers) => {
                if answers.iter().any(|a| is_dnsbl_error(*a)) {
                    note_refused_dnsbl(zone);
                }
                answers.iter().any(|a| is_dnsbl_listing(*a))
            }
            Err(_) => false,
        };
        listed.then(|| zone.clone())
    });
    futures_util::future::join_all(lookups).await.into_iter().flatten().collect()
}

#[derive(Deserialize)]
struct AbuseResponse {
    data: AbuseData,
}

#[derive(Deserialize)]
struct AbuseData {
    #[serde(rename = "abuseConfidenceScore")]
    score: u8,
}

/// AbuseIPDB confidence score (0-100) for `ip`, cached for a day. `None` when the integration
/// is disabled, the address is private, or the lookup failed.
pub async fn abuseipdb_score(app: &App, ip: IpAddr) -> Option<u8> {
    let key = app.cfg.abuseipdb_key.as_deref()?;
    if is_private(ip) {
        return None;
    }
    let ip_text = ip.to_string();
    let cached: Option<(i64, i64)> = sqlx::query_as("SELECT score, checked_at FROM ip_reputation WHERE ip = ?")
        .bind(&ip_text)
        .fetch_optional(&app.db)
        .await
        .ok()
        .flatten();
    if let Some((score, checked_at)) = cached
        && now() - checked_at < ABUSEIPDB_CACHE_SECS
    {
        return Some(score.clamp(0, 100) as u8);
    }

    let result = async {
        let resp = app
            .http
            .get(format!("{}/api/v2/check", app.cfg.abuseipdb_url.trim_end_matches('/')))
            .query(&[("ipAddress", ip_text.as_str()), ("maxAgeInDays", "90")])
            .header("Key", key)
            .header("Accept", "application/json")
            .send()
            .await?
            .error_for_status()?;
        anyhow::Ok(resp.json::<AbuseResponse>().await?.data.score.min(100))
    }
    .await;
    match result {
        Ok(score) => {
            let _ = sqlx::query(
                "INSERT INTO ip_reputation (ip, score, checked_at) VALUES (?, ?, ?)
                 ON CONFLICT(ip) DO UPDATE SET score = excluded.score, checked_at = excluded.checked_at",
            )
            .bind(&ip_text)
            .bind(score as i64)
            .bind(now())
            .execute(&app.db)
            .await;
            Some(score)
        }
        Err(err) => {
            tracing::warn!(error = %err, "AbuseIPDB lookup failed");
            None
        }
    }
}

const SETTING_STATUS: &str = "reputation.status";

/// Result of the latest scheduled blocklist check of the server's own addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
pub struct Status {
    pub checked_at: i64,
    pub addresses: Vec<String>,
    /// "address zone" pairs.
    pub listed: Vec<String>,
}

/// Listings present in `new` that were not in `previous`.
pub fn newly_listed(previous: &Status, new: &Status) -> Vec<String> {
    new.listed.iter().filter(|entry| !previous.listed.contains(entry)).cloned().collect()
}

pub async fn stored_status(app: &App) -> Option<Status> {
    crate::db::get_setting(&app.db, SETTING_STATUS).await.ok().flatten().and_then(|json| serde_json::from_str(&json).ok())
}

/// AbuseIPDB accepts one report of an address per 15 minutes from each reporter.
const REPORT_INTERVAL_SECS: i64 = 15 * 60;
/// AbuseIPDB categories (https://www.abuseipdb.com/categories).
const CATEGORY_PHISHING: u8 = 7;
const CATEGORY_EMAIL_SPAM: u8 = 11;
const CATEGORY_PORT_SCAN: u8 = 14;
const CATEGORY_HACKING: u8 = 15;
const CATEGORY_BAD_WEB_BOT: u8 = 19;
const CATEGORY_WEB_APP_ATTACK: u8 = 21;
const CATEGORY_BRUTE_FORCE: u8 = 18;
/// Reports waiting for the next round; more are dropped until then.
const MAX_PENDING_ABUSE: usize = 1000;

/// Abuse seen over SMTP that is worth telling AbuseIPDB about. Only clear cases: a wrong
/// report harms a legitimate server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Abuse {
    /// Mail to one of the administrator's spam traps.
    SpamTrap,
    /// Mail the content filter refused as spam.
    Spam,
    /// Mail carrying a virus.
    Virus,
    /// Many unknown recipients tried in one connection.
    DirectoryHarvest,
    /// Repeated attempts to relay to other domains through this server.
    RelayProbe,
    /// Mail refused as phishing.
    Phishing,
    /// A connection dropped for too many invalid commands before any sign-in.
    ProtocolGarbage(Service),
    /// Requests for well-known vulnerable web paths that this server never had.
    WebScan,
}

/// The mail service a connection was made to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Service {
    Smtp,
    Imap,
    Pop3,
    Sieve,
}

impl Abuse {
    fn categories(self) -> &'static [u8] {
        match self {
            Abuse::RelayProbe => &[CATEGORY_HACKING],
            Abuse::Phishing => &[CATEGORY_PHISHING, CATEGORY_EMAIL_SPAM],
            Abuse::ProtocolGarbage(_) => &[CATEGORY_PORT_SCAN, CATEGORY_HACKING],
            Abuse::WebScan => &[CATEGORY_WEB_APP_ATTACK, CATEGORY_BAD_WEB_BOT],
            _ => &[CATEGORY_EMAIL_SPAM],
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Abuse::SpamTrap => "Spam sent to a spam trap address",
            Abuse::Spam => "Spam refused by the content filter",
            Abuse::Virus => "Mail carrying a virus",
            Abuse::DirectoryHarvest => "Directory harvest attack (many unknown recipients)",
            Abuse::RelayProbe => "Open relay probing (relaying to foreign domains refused)",
            Abuse::Phishing => "Phishing mail refused",
            Abuse::ProtocolGarbage(Service::Smtp) => "Invalid SMTP commands (connection dropped before sign-in)",
            Abuse::ProtocolGarbage(Service::Imap) => "Invalid IMAP commands (connection dropped before sign-in)",
            Abuse::ProtocolGarbage(Service::Pop3) => "Invalid POP3 commands (connection dropped before sign-in)",
            Abuse::ProtocolGarbage(Service::Sieve) => "Invalid ManageSieve commands (connection dropped before sign-in)",
            Abuse::WebScan => "Web vulnerability scanning (requests for paths like /wp-login.php or /.env)",
        }
    }
}

/// SMTP abuse waiting to be reported, with the address it came from.
#[derive(Default)]
pub struct AbuseQueue(parking_lot::Mutex<Vec<(IpAddr, Abuse)>>);

impl AbuseQueue {
    fn take(&self) -> Vec<(IpAddr, Abuse)> {
        std::mem::take(&mut *self.0.lock())
    }

    pub fn snapshot(&self) -> Vec<(IpAddr, Abuse)> {
        self.0.lock().clone()
    }

    pub fn restore(&self, saved: Vec<(IpAddr, Abuse)>) {
        let mut pending = self.0.lock();
        for item in saved {
            if pending.len() < MAX_PENDING_ABUSE && !pending.contains(&item) {
                pending.push(item);
            }
        }
    }
}

/// Snapshot name of when each address was last reported to AbuseIPDB.
const REPORTED_SNAPSHOT: &str = "abuseipdb_reported";

/// Notes abuse from `ip` for the next report to AbuseIPDB. Nothing happens unless reporting
/// is on, and private or trusted addresses are never reported.
pub fn report_abuse(app: &App, ip: IpAddr, abuse: Abuse) {
    if app.cfg.abuseipdb_key.is_none() || !app.cfg.abuseipdb_report || is_private(ip) || is_trusted_source(&app.cfg, ip) {
        return;
    }
    let mut pending = app.abuse.0.lock();
    if pending.len() < MAX_PENDING_ABUSE && !pending.contains(&(ip, abuse)) {
        pending.push((ip, abuse));
    }
}

/// Reports abusive addresses to AbuseIPDB, when `UNOMAIL_ABUSEIPDB_REPORT` is on: password
/// guessers and the SMTP abuse noted with [`report_abuse`]. Never private or trusted
/// addresses; a report names the protocol or behaviour, not the accounts or recipients.
pub async fn report_offenders(app: crate::app::AppState) {
    if app.cfg.abuseipdb_key.is_none() || !app.cfg.abuseipdb_report {
        return;
    }
    let mut reported: std::collections::HashMap<IpAddr, i64> = crate::snapshot::load(&app.db, REPORTED_SNAPSHOT).await.ok().flatten().unwrap_or_default();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tick.tick().await;
        report_pending(&app, &mut reported).await;
        if let Err(err) = crate::snapshot::save(&app.db, REPORTED_SNAPSHOT, &reported).await {
            tracing::warn!(%err, "AbuseIPDB report times not saved");
        }
    }
}

/// One round of [`report_offenders`]: reports what the login limiter and the SMTP server
/// caught since the last round, one report per address with all its reasons. `reported`
/// remembers when each address was last reported.
pub async fn report_pending(app: &App, reported: &mut std::collections::HashMap<IpAddr, i64>) {
    let Some(key) = app.cfg.abuseipdb_key.as_deref() else { return };
    let now = now();
    reported.retain(|_, at| now - *at < REPORT_INTERVAL_SECS);
    // Address → (categories, reasons), in order of first appearance.
    let mut order: Vec<IpAddr> = Vec::new();
    let mut found: std::collections::HashMap<IpAddr, (Vec<u8>, Vec<String>)> = std::collections::HashMap::new();
    let mut note = |ip: IpAddr, category: u8, reason: String| {
        let (categories, reasons) = found.entry(ip).or_insert_with(|| {
            order.push(ip);
            Default::default()
        });
        if !categories.contains(&category) {
            categories.push(category);
        }
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    };
    for (ip, protocol) in app.limiter.take_offenders() {
        note(ip, CATEGORY_BRUTE_FORCE, format!("Password guessing ({protocol} sign-in)"));
    }
    for (ip, abuse) in app.abuse.take() {
        for &category in abuse.categories() {
            note(ip, category, abuse.describe().to_owned());
        }
    }
    for ip in order {
        if is_private(ip) || is_trusted_source(&app.cfg, ip) || reported.contains_key(&ip) {
            continue;
        }
        reported.insert(ip, now);
        let (categories, reasons) = &found[&ip];
        let categories = categories.iter().map(u8::to_string).collect::<Vec<_>>().join(",");
        let comment = format!("{} on {}", reasons.join("; "), app.cfg.hostname);
        let sent = app
            .http
            .post(format!("{}/api/v2/report", app.cfg.abuseipdb_url.trim_end_matches('/')))
            .header("Key", key)
            .header("Accept", "application/json")
            .query(&[("ip", ip.to_string().as_str()), ("categories", categories.as_str()), ("comment", comment.as_str())])
            .send()
            .await
            .and_then(reqwest::Response::error_for_status);
        match sent {
            Ok(_) => crate::db::audit(&app.db, "system", "abuseipdb.reported", &ip.to_string(), &ip.to_string(), &format!("categories {categories}: {}", reasons.join("; "))).await,
            Err(err) => tracing::warn!(%ip, error = %err, "AbuseIPDB report failed"),
        }
    }
}

/// Checks every public address of the server hostname against the configured blocklists and
/// records the result. A new listing is written to the audit log.
pub async fn check_now(app: &App) -> Option<Status> {
    let resolver = app.authenticator.as_ref()?;
    if app.rt().dnsbl_zones.is_empty() {
        return None;
    }
    let addresses = crate::dns::ips(resolver, &app.cfg.hostname).await.ok()?;
    let mut status = Status { checked_at: now(), ..Default::default() };
    for ip in addresses.into_iter().filter(|ip| !is_private(*ip)) {
        status.addresses.push(ip.to_string());
        for zone in dnsbl_listings(app, ip).await {
            status.listed.push(format!("{ip} {zone}"));
        }
    }
    status.listed.sort();
    let previous = stored_status(app).await.unwrap_or_default();
    for entry in newly_listed(&previous, &status) {
        tracing::warn!(entry, "server address is listed on a DNS blocklist");
        crate::db::audit(&app.db, "system", "reputation.listed", &entry, "", "outgoing mail may be rejected by other servers").await;
    }
    for entry in newly_listed(&status, &previous) {
        crate::db::audit(&app.db, "system", "reputation.delisted", &entry, "", "").await;
    }
    if let Ok(json) = serde_json::to_string(&status) {
        let _ = crate::db::set_setting(&app.db, SETTING_STATUS, &json).await;
    }
    Some(status)
}

/// Background task: hourly reputation check.
pub async fn monitor(app: crate::app::AppState) {
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    loop {
        check_now(&app).await;
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn listing_transitions() {
        let status = |listed: &[&str]| Status { listed: listed.iter().map(|s| s.to_string()).collect(), ..Default::default() };
        let (before, after) = (status(&["1.2.3.4 a.example"]), status(&["1.2.3.4 a.example", "1.2.3.4 b.example"]));
        assert_eq!(newly_listed(&before, &after), ["1.2.3.4 b.example"]);
        assert!(newly_listed(&after, &before).is_empty());
        assert_eq!(newly_listed(&after, &status(&[])), Vec::<String>::new());
    }

    use super::*;

    #[test]
    fn blocklist_answers() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(is_dnsbl_listing(ip("127.0.0.2")) && is_dnsbl_listing(ip("127.0.0.11")));
        // Spamhaus error codes (public resolver, excessive queries) and answers outside 127/8.
        for refused in ["127.255.255.254", "127.255.255.255", "127.255.255.252", "192.0.2.1"] {
            assert!(!is_dnsbl_listing(ip(refused)), "{refused}");
        }
        assert!(is_dnsbl_error(ip("127.255.255.254")) && !is_dnsbl_error(ip("127.0.0.2")));
    }

    #[test]
    fn query_names() {
        assert_eq!(dnsbl_query("192.0.2.99".parse().unwrap(), "zen.spamhaus.org"), "99.2.0.192.zen.spamhaus.org");
        assert_eq!(
            dnsbl_query("2001:db8::1".parse().unwrap(), "bl.example"),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.bl.example"
        );
    }

    #[test]
    fn trusted_sources() {
        let mut cfg = crate::config::Config::for_tests(std::path::PathBuf::from("."));
        assert!(is_trusted_source(&cfg, "127.0.0.1".parse().unwrap()) && is_trusted_source(&cfg, "::1".parse().unwrap()) && is_trusted_source(&cfg, "::ffff:127.0.0.1".parse().unwrap()));
        assert!(!is_trusted_source(&cfg, "172.17.0.1".parse().unwrap()), "private is not trusted by itself");
        cfg.trusted_networks = vec!["172.17.0.0/16".parse().unwrap()];
        assert!(is_trusted_source(&cfg, "172.17.0.1".parse().unwrap()) && !is_trusted_source(&cfg, "10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn private_ranges() {
        for ip in [
            "127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "0.1.2.3", "192.0.0.8", "198.18.0.1",
            "198.19.255.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::1", "fd00::1", "fe80::1", "fec0::1", "ff02::1", "::ffff:10.0.0.1",
            "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::1", "2002:7f00:1::1", "2002:c0a8:101::1", "::127.0.0.1", "::10.0.0.1", "2001:0:4136:e378::1",
        ] {
            assert!(is_private(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "203.0.113.1", "100.128.0.1", "198.20.0.1", "2001:4860:4860::8888", "64:ff9b::808:808", "2002:808:808::1"] {
            assert!(!is_private(ip.parse().unwrap()), "{ip}");
        }
    }
}
