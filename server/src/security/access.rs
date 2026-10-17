//! SMTP access control: administrator-defined blacklist and whitelist rules, rules the server
//! creates on its own, and the per-address behaviour score ("karma") that drives them.

use std::net::IpAddr;

use ipnet::IpNet;
use parking_lot::RwLock;

use crate::{
    app::App,
    security::reputation::is_private,
    util::{now, sanitize_line},
};

/// Rules are re-read at least this often, so expired ones stop applying on their own.
const RELOAD_SECS: i64 = 30;
/// A score at or below this blacklists the address automatically.
pub const AUTO_BLOCK_SCORE: i64 = -20;
/// How long an automatic blacklist entry lasts.
pub const AUTO_BLOCK_SECS: i64 = 24 * 3600;
const SCORE_LIMIT: i64 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum List {
    Blacklist,
    Whitelist,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No rule matches; the usual checks apply.
    Neutral,
    /// Whitelisted: blocklist, reputation and greylisting checks are skipped.
    Allowed,
    Blocked,
}

#[derive(Debug, Clone)]
struct Rule {
    id: i64,
    list: List,
    net: IpNet,
    priority: i64,
    expires_at: Option<i64>,
}

#[derive(Default)]
pub struct AccessList {
    rules: RwLock<(Vec<Rule>, i64)>,
}

/// Parses an address or a network in CIDR notation into its canonical network.
pub fn parse_network(input: &str) -> Option<IpNet> {
    let input = input.trim();
    match input.parse::<IpNet>() {
        Ok(net) => Some(net.trunc()),
        Err(_) => input.parse::<IpAddr>().ok().map(IpNet::from),
    }
}

/// A network as shown to people: single addresses without their prefix length.
pub fn display(net: &IpNet) -> String {
    if net.prefix_len() == net.max_prefix_len() { net.addr().to_string() } else { net.to_string() }
}

/// The rule that decides for `ip`: highest priority, then the most specific network, then
/// the whitelist (so an explicit exception inside a blocked range works without priorities).
fn decide(rules: &[Rule], ip: IpAddr, at: i64) -> Option<&Rule> {
    rules
        .iter()
        .filter(|rule| rule.net.contains(&ip) && rule.expires_at.is_none_or(|expires| expires > at))
        .max_by_key(|rule| (rule.priority, rule.net.prefix_len(), rule.list == List::Whitelist))
}

pub async fn reload(app: &App) {
    let rows: Vec<(i64, String, String, i64, Option<i64>)> = match sqlx::query_as("SELECT id, list, network, priority, expires_at FROM ip_rules").fetch_all(&app.db).await {
        Ok(rows) => rows,
        Err(err) => return tracing::error!(%err, "could not load the SMTP access rules"),
    };
    let rules = rows
        .into_iter()
        .filter_map(|(id, list, network, priority, expires_at)| {
            Some(Rule { id, list: if list == "whitelist" { List::Whitelist } else { List::Blacklist }, net: network.parse().ok()?, priority, expires_at })
        })
        .collect();
    *app.access.rules.write() = (rules, now());
}

/// Decides whether a connecting address is blocked, explicitly allowed, or neither.
pub async fn check(app: &App, ip: IpAddr) -> Verdict {
    if now() - app.access.rules.read().1 >= RELOAD_SECS {
        reload(app).await;
    }
    let matched = decide(&app.access.rules.read().0, ip, now()).map(|rule| (rule.id, rule.list));
    let Some((id, list)) = matched else { return Verdict::Neutral };
    if let Err(err) = sqlx::query("UPDATE ip_rules SET hits = hits + 1, last_seen = ? WHERE id = ?").bind(now()).bind(id).execute(&app.db).await {
        tracing::error!(%err, "could not count a hit on an SMTP access rule");
    }
    match list {
        List::Whitelist => Verdict::Allowed,
        List::Blacklist => Verdict::Blocked,
    }
}

/// Records good (`delta > 0`) or bad behaviour of a remote address. An address whose score
/// falls to `AUTO_BLOCK_SCORE` is blacklisted for a day; private addresses never are, so the
/// server cannot lock out its own network.
pub async fn karma(app: &App, ip: IpAddr, delta: i64, event: &str) {
    let result: sqlx::Result<i64> = sqlx::query_scalar(
        "INSERT INTO ip_karma (ip, score, good, bad, hits, last_seen, last_event) VALUES (?1, MAX(-?6, MIN(?6, ?2)), ?3, ?4, 1, ?5, ?7)
         ON CONFLICT(ip) DO UPDATE SET score = MAX(-?6, MIN(?6, score + ?2)), good = good + ?3, bad = bad + ?4, hits = hits + 1,
             last_seen = ?5, last_event = ?7
         RETURNING score",
    )
    .bind(ip.to_string())
    .bind(delta)
    .bind(i64::from(delta > 0))
    .bind(i64::from(delta < 0))
    .bind(now())
    .bind(SCORE_LIMIT)
    .bind(sanitize_line(event))
    .fetch_one(&app.db)
    .await;
    let score = match result {
        Ok(score) => score,
        Err(err) => return tracing::error!(%err, "could not record karma"),
    };
    if score > AUTO_BLOCK_SCORE || delta >= 0 || is_private(ip) {
        return;
    }
    let network = IpNet::from(ip).to_string();
    let inserted = sqlx::query(
        "INSERT INTO ip_rules (list, source, network, priority, description, created_at, expires_at) VALUES ('blacklist', 'auto', ?, 0, ?, ?, ?)
         ON CONFLICT(list, network) DO UPDATE SET expires_at = excluded.expires_at, description = excluded.description WHERE ip_rules.source = 'auto'",
    )
    .bind(&network)
    .bind(format!("Karma dropped to {score} ({})", sanitize_line(event)))
    .bind(now())
    .bind(now() + AUTO_BLOCK_SECS)
    .execute(&app.db)
    .await;
    match inserted {
        Ok(_) => {
            crate::db::audit(&app.db, "system", "smtp.auto_blacklisted", &ip.to_string(), &ip.to_string(), &format!("karma {score}")).await;
            reload(app).await;
        }
        Err(err) => tracing::error!(%err, "could not create an automatic blacklist rule"),
    }
}

/// The behaviour score of an address: below zero once it has done more harm than good.
pub async fn karma_of(app: &App, ip: IpAddr) -> i64 {
    sqlx::query_scalar("SELECT score FROM ip_karma WHERE ip = ?").bind(ip.to_string()).fetch_optional(&app.db).await.ok().flatten().unwrap_or(0)
}

/// Removes automatic rules that have lapsed and karma records that have been idle for a month.
pub async fn prune(app: &App) {
    let _ = sqlx::query("DELETE FROM ip_rules WHERE expires_at IS NOT NULL AND expires_at <= ?").bind(now()).execute(&app.db).await;
    let _ = sqlx::query("DELETE FROM ip_karma WHERE last_seen < ?").bind(now() - 30 * 86400).execute(&app.db).await;
    reload(app).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: i64, list: List, net: &str, priority: i64, expires_at: Option<i64>) -> Rule {
        Rule { id, list, net: net.parse().unwrap(), priority, expires_at }
    }

    #[test]
    fn networks_are_canonical() {
        assert_eq!(parse_network(" 203.0.113.77/24 ").unwrap().to_string(), "203.0.113.0/24");
        assert_eq!(display(&parse_network("203.0.113.7").unwrap()), "203.0.113.7");
        assert_eq!(display(&parse_network("2001:DB8::1").unwrap()), "2001:db8::1");
        assert_eq!(display(&parse_network("2001:db8::/32").unwrap()), "2001:db8::/32");
        for bad in ["", "example.org", "203.0.113.7/33", "203.0.113", "1.2.3.4; DROP TABLE"] {
            assert!(parse_network(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn the_most_important_then_most_specific_rule_decides() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let rules = vec![
            rule(1, List::Blacklist, "203.0.113.0/24", 0, None),
            rule(2, List::Whitelist, "203.0.113.7/32", 0, None),
            rule(3, List::Blacklist, "198.51.100.0/24", 50, None),
        ];
        assert_eq!(decide(&rules, ip, 100).map(|r| r.id), Some(2), "an exception inside a blocked range");
        assert_eq!(decide(&rules, "203.0.113.8".parse().unwrap(), 100).map(|r| r.id), Some(1));
        assert_eq!(decide(&rules, "192.0.2.1".parse().unwrap(), 100).map(|r| r.id), None);

        // Priority outranks specificity; on a full tie the whitelist wins.
        let rules = vec![rule(1, List::Blacklist, "203.0.113.0/24", 10, None), rule(2, List::Whitelist, "203.0.113.7/32", 0, None)];
        assert_eq!(decide(&rules, ip, 100).map(|r| r.id), Some(1));
        let rules = vec![rule(1, List::Blacklist, "203.0.113.7/32", 0, None), rule(2, List::Whitelist, "203.0.113.7/32", 0, None)];
        assert_eq!(decide(&rules, ip, 100).map(|r| r.id), Some(2));

        // Expired rules no longer apply.
        let rules = vec![rule(1, List::Blacklist, "203.0.113.7/32", 0, Some(50))];
        assert_eq!(decide(&rules, ip, 100).map(|r| r.id), None);
        assert_eq!(decide(&rules, ip, 10).map(|r| r.id), Some(1));
    }
}
