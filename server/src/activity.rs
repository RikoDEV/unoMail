//! Live view of who is talking to the server: the remote addresses that connected recently
//! and the last SMTP replies they were given. Kept in memory only; it is an operator's
//! at-a-glance view, not a log.

use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    time::Duration,
};

use parking_lot::Mutex;
use serde::Serialize;

use crate::{
    app::App,
    security::reputation::{dnsbl_query, is_private},
    util::{now, sanitize_line},
};

const MAX_IPS: usize = 5000;
const MAX_REPLIES: usize = 500;
const LOOKUP_TTL_SECS: i64 = 6 * 3600;
const FAILED_LOOKUP_TTL_SECS: i64 = 300;
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, Default)]
pub struct Seen {
    pub connections: u64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Reply {
    pub ts: i64,
    pub ip: String,
    pub code: u16,
    pub text: String,
}

/// What is known about a remote address beyond the address itself.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Described {
    /// Reverse DNS name.
    pub rdns: Option<String>,
    /// ISO 3166 country code of the network the address belongs to.
    pub country: Option<String>,
}

#[derive(Default)]
struct Inner {
    ips: HashMap<IpAddr, Seen>,
    replies: VecDeque<Reply>,
    lookups: HashMap<IpAddr, (Described, i64)>,
}

#[derive(Default)]
pub struct Activity(Mutex<Inner>);

impl Activity {
    /// Notes a new connection from `ip` (any mail protocol).
    pub fn connection(&self, ip: IpAddr) {
        let mut inner = self.0.lock();
        if inner.ips.len() >= MAX_IPS && !inner.ips.contains_key(&ip) {
            // Forget the half that has been quiet the longest.
            let mut times: Vec<i64> = inner.ips.values().map(|seen| seen.last_seen).collect();
            times.sort_unstable();
            let cutoff = times[times.len() / 2];
            inner.ips.retain(|_, seen| seen.last_seen > cutoff);
        }
        let seen = inner.ips.entry(ip).or_default();
        seen.connections += 1;
        seen.last_seen = now();
    }

    /// Notes an SMTP reply line sent to `ip`.
    pub fn reply(&self, ip: IpAddr, line: &str) {
        let Some(code) = line.get(..3).and_then(|c| c.parse::<u16>().ok()) else { return };
        let text: String = sanitize_line(line.get(4..).unwrap_or("")).chars().take(200).collect();
        crate::logstream::record_smtp(&ip.to_string(), code, &text);
        let mut inner = self.0.lock();
        if inner.replies.len() >= MAX_REPLIES {
            inner.replies.pop_front();
        }
        inner.replies.push_back(Reply { ts: now(), ip: ip.to_string(), code, text });
    }

    /// The addresses seen most recently, newest first.
    pub fn recent_ips(&self, limit: usize) -> Vec<(IpAddr, Seen)> {
        let mut list: Vec<(IpAddr, Seen)> = self.0.lock().ips.iter().map(|(ip, seen)| (*ip, *seen)).collect();
        list.sort_by(|a, b| b.1.last_seen.cmp(&a.1.last_seen).then(b.1.connections.cmp(&a.1.connections)));
        list.truncate(limit);
        list
    }

    /// The latest SMTP replies, newest first.
    pub fn recent_replies(&self, limit: usize) -> Vec<Reply> {
        self.0.lock().replies.iter().rev().take(limit).cloned().collect()
    }
}

/// Extracts the country code from a Team Cymru origin record,
/// e.g. `13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11`.
pub fn country_from_origin(record: &str) -> Option<String> {
    let code = record.split('|').nth(2)?.trim();
    (code.len() == 2 && code.bytes().all(|b| b.is_ascii_alphabetic())).then(|| code.to_ascii_uppercase())
}

/// Reverse DNS name and country of an address, from DNS, cached for a few hours.
///
/// The country comes from Team Cymru's IP-to-ASN service, which answers over plain DNS and
/// needs no account or database download. Private addresses are never looked up.
pub async fn describe(app: &App, ip: IpAddr) -> Described {
    if is_private(ip) {
        return Described::default();
    }
    if let Some((known, at)) = app.activity.0.lock().lookups.get(&ip)
        // An answer is kept for hours; a failed lookup is retried after a few minutes.
        && now() - at < if known.rdns.is_some() || known.country.is_some() { LOOKUP_TTL_SECS } else { FAILED_LOOKUP_TTL_SECS }
    {
        return known.clone();
    }
    let Some(resolver) = &app.authenticator else { return Described::default() };
    let zone = if ip.is_ipv4() { "origin.asn.cymru.com" } else { "origin6.asn.cymru.com" };
    let origin = dnsbl_query(ip, zone);
    let (names, origins) = tokio::join!(
        tokio::time::timeout(LOOKUP_TIMEOUT, crate::dns::ptr(resolver, ip)),
        tokio::time::timeout(LOOKUP_TIMEOUT, crate::dns::txt(resolver, &origin)),
    );
    let described = Described {
        rdns: names.ok().and_then(Result::ok).and_then(|list| list.into_iter().next()).map(|name| sanitize_line(name.trim_end_matches('.'))).filter(|name| !name.is_empty()),
        country: origins.ok().and_then(Result::ok).and_then(|records| records.iter().find_map(|record| country_from_origin(record))),
    };
    let mut inner = app.activity.0.lock();
    if inner.lookups.len() >= MAX_IPS {
        inner.lookups.clear();
    }
    inner.lookups.insert(ip, (described.clone(), now()));
    described
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_and_addresses_are_kept_newest_first_and_bounded() {
        let activity = Activity::default();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        activity.connection(ip);
        activity.connection(ip);
        activity.connection("198.51.100.1".parse().unwrap());
        let ips = activity.recent_ips(10);
        assert_eq!(ips.len(), 2);
        assert_eq!(ips.iter().find(|(seen_ip, _)| *seen_ip == ip).unwrap().1.connections, 2);

        activity.reply(ip, "250 2.0.0 Ok: queued as abc");
        activity.reply(ip, "221 2.0.0 mail.example.org closing connection.\r\nInjected");
        activity.reply(ip, "not a reply line");
        let replies = activity.recent_replies(10);
        assert_eq!(replies.len(), 2);
        assert_eq!((replies[0].code, replies[0].text.as_str()), (221, "2.0.0 mail.example.org closing connection.Injected"));
        assert_eq!(replies[1].code, 250);
        for n in 0..(MAX_REPLIES + 50) {
            activity.reply(ip, &format!("250 reply {n}"));
        }
        assert_eq!(activity.recent_replies(usize::MAX).len(), MAX_REPLIES);
    }

    #[test]
    fn origin_records() {
        assert_eq!(country_from_origin("13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11").as_deref(), Some("AU"));
        assert_eq!(country_from_origin("15169 | 2001:4860::/32 | us | arin |").as_deref(), Some("US"));
        assert_eq!(country_from_origin("garbage"), None);
        assert_eq!(country_from_origin("1 | x | <script> | y"), None);
    }
}
