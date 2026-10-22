//! Subscription management: the senders whose mail offers a way to unsubscribe, as Gmail lists
//! them. Whether a content offers one is recorded once per stored content, on delivery or by the
//! backfill for mail stored before, so the list is a plain query.

use serde_json::{Value, json};
use sqlx::{Sqlite, SqlitePool};

use crate::app::AppState;

const BACKFILL_BATCH: i64 = 100;
/// Senders with offering mail this recent are listed.
const LISTED_DAYS: i64 = 90;
/// How much mail a sender sent "recently", for the volume shown next to it.
const RECENT_DAYS: i64 = 30;

/// Whether a message offers any way to unsubscribe.
pub fn offered(raw: &[u8]) -> bool {
    !crate::api::mailtools::unsubscribe_options(raw).is_empty()
}

/// Records whether a content offers a way to unsubscribe.
pub async fn store<'e, E: sqlx::Executor<'e, Database = Sqlite>>(db: E, hash: &str, offered: bool) -> sqlx::Result<()> {
    sqlx::query("INSERT OR IGNORE INTO message_unsubscribe (hash, offered) VALUES (?, ?)").bind(hash).bind(offered).execute(db).await?;
    Ok(())
}

/// Records, in the background and a batch at a time, messages stored before the table existed.
pub async fn backfill(app: AppState) {
    loop {
        let pending: Vec<String> = match sqlx::query_scalar("SELECT DISTINCT m.blob_hash FROM messages m WHERE NOT EXISTS (SELECT 1 FROM message_unsubscribe u WHERE u.hash = m.blob_hash) LIMIT ?").bind(BACKFILL_BATCH).fetch_all(&app.db).await {
            Ok(pending) => pending,
            Err(err) => {
                tracing::warn!(%err, "subscription backfill stopped");
                return;
            }
        };
        if pending.is_empty() {
            return;
        }
        for hash in pending {
            // A content that cannot be read is recorded as offering nothing, so it is not tried forever.
            let offers = app.store.read_blob(&hash).await.is_ok_and(|raw| offered(&raw));
            if let Err(err) = store(&app.db, &hash, offers).await {
                tracing::warn!(%err, "could not record a message's unsubscribe options");
                return;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// The user's subscriptions: senders of recent received mail that offers a way to unsubscribe,
/// busiest first, without those the user already unsubscribed from.
pub async fn list(db: &SqlitePool, account_id: i64) -> sqlx::Result<Vec<Value>> {
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT LOWER(m.from_addr) AS sender,
                (SELECT n.from_name FROM messages n WHERE n.account_id = ?1 AND LOWER(n.from_addr) = LOWER(m.from_addr) ORDER BY n.internal_date DESC LIMIT 1),
                SUM(m.internal_date >= CAST(strftime('%s', 'now') AS INTEGER) - ?3 * 86400)
         FROM messages m JOIN message_unsubscribe u ON u.hash = m.blob_hash AND u.offered = 1
         WHERE m.account_id = ?1 AND m.from_addr != ''
           AND m.internal_date >= CAST(strftime('%s', 'now') AS INTEGER) - ?2 * 86400
           AND COALESCE((SELECT role FROM mailboxes WHERE id = m.mailbox_id), '') NOT IN ('junk', 'trash', 'sent', 'drafts')
           AND NOT EXISTS (SELECT 1 FROM unsubscribed_senders s WHERE s.account_id = ?1 AND s.sender = LOWER(m.from_addr))
         GROUP BY sender
         ORDER BY 3 DESC, 2 COLLATE NOCASE",
    )
    .bind(account_id)
    .bind(LISTED_DAYS)
    .bind(RECENT_DAYS)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|(sender, name, recent)| json!({ "sender": sender, "name": name, "recent": recent })).collect())
}

/// The newest message from a sender that offers a way to unsubscribe: the one to act on.
pub async fn newest_offering(db: &SqlitePool, account_id: i64, sender: &str) -> sqlx::Result<Option<i64>> {
    sqlx::query_scalar(
        "SELECT m.id FROM messages m JOIN message_unsubscribe u ON u.hash = m.blob_hash AND u.offered = 1
         WHERE m.account_id = ? AND LOWER(m.from_addr) = LOWER(?) ORDER BY m.internal_date DESC LIMIT 1",
    )
    .bind(account_id)
    .bind(sender)
    .fetch_optional(db)
    .await
}

/// Hides a sender from the list once the user unsubscribed.
pub async fn mark_unsubscribed(db: &SqlitePool, account_id: i64, sender: &str) -> sqlx::Result<()> {
    sqlx::query("INSERT OR REPLACE INTO unsubscribed_senders (account_id, sender, at) VALUES (?, LOWER(?), CAST(strftime('%s', 'now') AS INTEGER))")
        .bind(account_id)
        .bind(sender)
        .execute(db)
        .await?;
    Ok(())
}
