//! SQLite pool setup and small cross-cutting queries (settings, logs).

use std::{path::Path, time::Duration};

use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

use crate::util::now;

pub async fn open(path: &Path) -> anyhow::Result<SqlitePool> {
    let opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(10))
        // Reads through a memory map share the operating system's page cache between the
        // pool's connections; each connection's own cache is small and was found to make
        // the same query take 15 ms on one connection and 97 ms on another.
        .pragma("mmap_size", "268435456")
        // The write-ahead log is cut back to this size whenever it restarts; without a limit
        // it keeps the size of its largest burst (it grew past 1 GB under a delivery load).
        .pragma("journal_size_limit", "67108864");
    let pool = SqlitePoolOptions::new().max_connections(8).connect_with(opts).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// Copies the write-ahead log into the database and truncates it (run by the maintenance task).
/// A busy database simply leaves the rest for the next run.
pub async fn checkpoint(db: &SqlitePool) {
    if let Err(err) = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(db).await {
        tracing::warn!(%err, "database checkpoint failed");
    }
}

pub async fn get_setting(db: &SqlitePool, key: &str) -> sqlx::Result<Option<String>> {
    sqlx::query_scalar("SELECT value FROM settings WHERE key = ?").bind(key).fetch_optional(db).await
}

pub async fn set_setting(db: &SqlitePool, key: &str, value: &str) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind(key)
        .bind(value)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete_setting(db: &SqlitePool, key: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM settings WHERE key = ?").bind(key).execute(db).await?;
    Ok(())
}

/// Returns the stored secret for `key`, generating and persisting a random one on first use.
/// It is stored sealed with `secret.key`, so a database copy alone does not reveal it.
pub async fn get_or_create_secret(db: &SqlitePool, secrets: &crate::secretbox::SecretBox, key: &str) -> sqlx::Result<String> {
    debug_assert!(crate::secretbox::SEALED_SETTINGS.contains(&key), "{key} must be listed as a sealed setting");
    let sealed = match get_setting(db, key).await? {
        Some(v) => v,
        None => {
            sqlx::query("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)")
                .bind(key)
                .bind(secrets.seal(&crate::util::random_token()))
                .execute(db)
                .await?;
            get_setting(db, key).await?.expect("secret was just inserted")
        }
    };
    secrets.open(&sealed).ok_or_else(|| sqlx::Error::Decode(format!("the stored {key} cannot be decrypted with secret.key").into()))
}

/// Records a security-relevant action. Failures are logged rather than propagated: an audit
/// write must never turn a completed operation into an error for the caller.
pub async fn audit(db: &SqlitePool, actor: &str, action: &str, target: &str, ip: &str, detail: &str) {
    let res = sqlx::query("INSERT INTO audit_log (ts, actor, action, target, ip, detail) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(now())
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(ip)
        .bind(detail)
        .execute(db)
        .await;
    match res {
        Ok(done) => crate::logstream::publish(
            "audit",
            serde_json::json!({ "id": done.last_insert_rowid(), "ts": now(), "actor": actor, "action": action, "target": target, "ip": ip, "detail": detail }),
        ),
        Err(err) => tracing::error!(%err, action, actor, "failed to write audit log entry"),
    }
    tracing::info!(target: "audit", actor, action, target_ = target, ip, detail);
}

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Inbound,
    Outbound,
    Local,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
            Direction::Local => "local",
        }
    }
}

pub struct DeliveryEvent<'a> {
    pub direction: Direction,
    pub sender: &'a str,
    pub recipient: &'a str,
    pub status: &'a str,
    pub detail: &'a str,
    pub remote: &'a str,
    pub message_id: &'a str,
    pub size: i64,
}

pub async fn log_delivery(db: &SqlitePool, ev: DeliveryEvent<'_>) {
    let res = sqlx::query(
        "INSERT INTO delivery_log (ts, direction, sender, recipient, status, detail, remote, message_id, size)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(now())
    .bind(ev.direction.as_str())
    .bind(ev.sender)
    .bind(ev.recipient)
    .bind(ev.status)
    .bind(crate::util::sanitize_line(ev.detail))
    .bind(ev.remote)
    .bind(crate::util::sanitize_line(ev.message_id))
    .bind(ev.size)
    .execute(db)
    .await;
    crate::dailystats::record_delivery(db, ev.direction.as_str(), ev.status).await;
    match res {
        Ok(done) => crate::logstream::publish(
            "delivery",
            serde_json::json!({
                "id": done.last_insert_rowid(), "ts": now(), "direction": ev.direction.as_str(), "sender": ev.sender,
                "recipient": ev.recipient, "status": ev.status, "detail": crate::util::sanitize_line(ev.detail), "remote": ev.remote,
                "message_id": crate::util::sanitize_line(ev.message_id), "size": ev.size,
            }),
        ),
        Err(err) => tracing::error!(%err, "failed to write delivery log entry"),
    }
    tracing::info!(
        target: "delivery",
        direction = ev.direction.as_str(),
        sender = ev.sender,
        recipient = ev.recipient,
        status = ev.status,
        detail = ev.detail,
        remote = ev.remote,
    );
}
