//! Daily statistics for the dashboard: SMTP connections and what became of mail, one counter
//! per UTC day and metric.
//!
//! Deliveries are counted in the same place they are logged (`db::log_delivery`). Connections
//! can arrive in floods (a botnet knocking on port 25), so they are counted in memory and
//! written once a minute instead of once each.

use std::{collections::HashMap, sync::Mutex, time::Duration};

use serde::Serialize;
use sqlx::SqlitePool;

use crate::{app::AppState, util::now};

/// The longest period the chart can ask for.
const MAX_DAYS: i64 = 3650;
const FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// A counted event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Metric {
    /// An SMTP client got the greeting.
    ConnectionValid,
    /// Refused by the blacklist, a DNS blocklist, a poor reputation or the LMTP restriction.
    ConnectionBlocked,
    /// Refused because the address had too many connections open.
    ConnectionLimited,
    DeliveredLocal,
    DeliveredRemote,
    Bounced,
    Quarantined,
    Discarded,
}

impl Metric {
    pub fn as_str(self) -> &'static str {
        match self {
            Metric::ConnectionValid => "connection_valid",
            Metric::ConnectionBlocked => "connection_blocked",
            Metric::ConnectionLimited => "connection_limited",
            Metric::DeliveredLocal => "delivered_local",
            Metric::DeliveredRemote => "delivered_remote",
            Metric::Bounced => "bounced",
            Metric::Quarantined => "quarantined",
            Metric::Discarded => "discarded",
        }
    }

    /// What a delivery log entry counts as; deferred and queued mail is not counted until it
    /// has an outcome.
    pub fn for_delivery(direction: &str, status: &str) -> Option<Metric> {
        Some(match status {
            "delivered" if direction == "outbound" => Metric::DeliveredRemote,
            "delivered" => Metric::DeliveredLocal,
            "bounced" | "rejected" => Metric::Bounced,
            "junk" => Metric::Quarantined,
            "discarded" => Metric::Discarded,
            _ => return None,
        })
    }
}

fn day_of(ts: i64) -> i64 {
    ts.div_euclid(86400)
}

/// Counts not yet written to the database.
#[derive(Default)]
pub struct Pending {
    counts: Mutex<HashMap<(i64, Metric), i64>>,
}

impl Pending {
    pub fn add(&self, metric: Metric) {
        let mut counts = self.counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *counts.entry((day_of(now()), metric)).or_default() += 1;
    }

    fn take(&self) -> HashMap<(i64, Metric), i64> {
        std::mem::take(&mut *self.counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
    }

    fn snapshot(&self) -> HashMap<(i64, Metric), i64> {
        self.counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }
}

async fn increment(db: &SqlitePool, day: i64, metric: Metric, by: i64) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO daily_stats (day, metric, count) VALUES (?, ?, ?) ON CONFLICT (day, metric) DO UPDATE SET count = count + excluded.count")
        .bind(day)
        .bind(metric.as_str())
        .bind(by)
        .execute(db)
        .await?;
    Ok(())
}

/// Counts one delivery log entry (see `db::log_delivery`).
pub async fn record_delivery(db: &SqlitePool, direction: &str, status: &str) {
    if let Some(metric) = Metric::for_delivery(direction, status)
        && let Err(err) = increment(db, day_of(now()), metric, 1).await
    {
        tracing::warn!(%err, "daily statistics not updated");
    }
}

/// Writes the counts gathered in memory.
pub async fn flush(app: &AppState) {
    for ((day, metric), count) in app.daily.take() {
        if let Err(err) = increment(&app.db, day, metric, count).await {
            tracing::warn!(%err, "daily statistics not written");
            // Kept for the next attempt.
            let mut counts = app.daily.counts.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            *counts.entry((day, metric)).or_default() += count;
        }
    }
}

/// Flushes the in-memory counts once a minute, and forgets days past the retention period.
pub async fn run(app: AppState) {
    let mut rounds = 0u64;
    loop {
        tokio::time::sleep(FLUSH_INTERVAL).await;
        flush(&app).await;
        app.save_state().await;
        rounds += 1;
        if rounds % 60 == 1
            && let Err(err) = sqlx::query("DELETE FROM daily_stats WHERE day < ?").bind(day_of(now()) - app.rt().stats_retention_days).execute(&app.db).await
        {
            tracing::warn!(%err, "old daily statistics not removed");
        }
    }
}

/// One day of the dashboard's chart.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct Day {
    /// `YYYY-MM-DD`, UTC.
    pub date: String,
    pub connections_valid: i64,
    pub connections_blocked: i64,
    pub connections_limited: i64,
    pub delivered_local: i64,
    pub delivered_remote: i64,
    pub bounced: i64,
    pub quarantined: i64,
    pub discarded: i64,
}

impl Day {
    fn add(&mut self, metric: Metric, count: i64) {
        let field = match metric {
            Metric::ConnectionValid => &mut self.connections_valid,
            Metric::ConnectionBlocked => &mut self.connections_blocked,
            Metric::ConnectionLimited => &mut self.connections_limited,
            Metric::DeliveredLocal => &mut self.delivered_local,
            Metric::DeliveredRemote => &mut self.delivered_remote,
            Metric::Bounced => &mut self.bounced,
            Metric::Quarantined => &mut self.quarantined,
            Metric::Discarded => &mut self.discarded,
        };
        *field += count;
    }
}

const METRICS: [Metric; 8] = [
    Metric::ConnectionValid,
    Metric::ConnectionBlocked,
    Metric::ConnectionLimited,
    Metric::DeliveredLocal,
    Metric::DeliveredRemote,
    Metric::Bounced,
    Metric::Quarantined,
    Metric::Discarded,
];

/// The last `days` days, oldest first and up to today, with days without events as zeros.
/// Counts not yet written are included, so the chart is current.
pub async fn history(app: &AppState, days: i64) -> sqlx::Result<Vec<Day>> {
    let days = days.clamp(1, MAX_DAYS);
    let last = day_of(now());
    let first = last - days + 1;
    let rows: Vec<(i64, String, i64)> = sqlx::query_as("SELECT day, metric, count FROM daily_stats WHERE day BETWEEN ? AND ?").bind(first).bind(last).fetch_all(&app.db).await?;
    let mut out: Vec<Day> = (first..=last)
        .map(|day| Day { date: time::OffsetDateTime::from_unix_timestamp(day * 86400).map(|at| at.date().to_string()).unwrap_or_default(), ..Day::default() })
        .collect();
    let mut put = |day: i64, metric: Metric, count: i64| {
        if (first..=last).contains(&day) {
            out[(day - first) as usize].add(metric, count);
        }
    };
    for (day, name, count) in rows {
        if let Some(metric) = METRICS.into_iter().find(|metric| metric.as_str() == name) {
            put(day, metric, count);
        }
    }
    for ((day, metric), count) in app.daily.snapshot() {
        put(day, metric, count);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deliveries_are_counted_by_outcome() {
        assert_eq!(Metric::for_delivery("inbound", "delivered"), Some(Metric::DeliveredLocal));
        assert_eq!(Metric::for_delivery("local", "delivered"), Some(Metric::DeliveredLocal));
        assert_eq!(Metric::for_delivery("outbound", "delivered"), Some(Metric::DeliveredRemote));
        assert_eq!(Metric::for_delivery("outbound", "bounced"), Some(Metric::Bounced));
        assert_eq!(Metric::for_delivery("local", "rejected"), Some(Metric::Bounced));
        assert_eq!(Metric::for_delivery("inbound", "junk"), Some(Metric::Quarantined));
        assert_eq!(Metric::for_delivery("inbound", "discarded"), Some(Metric::Discarded));
        assert_eq!(Metric::for_delivery("outbound", "deferred"), None);
        assert_eq!(Metric::for_delivery("outbound", "queued"), None);
        assert_eq!(day_of(86400 * 3 + 5), 3);
    }
}
