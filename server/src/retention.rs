//! Emptying Trash and Junk: messages that have sat there longer than the configured number
//! of days are deleted for good.

use crate::{app::App, util::now};

/// Deletes what is due. Returns how many messages were removed.
pub async fn run(app: &App) -> usize {
    let rt = app.rt();
    let mut removed = 0;
    for (role, days) in [("trash", rt.trash_retention_days), ("junk", rt.junk_retention_days)] {
        if days <= 0 {
            continue;
        }
        let cutoff = now() - days * 86_400;
        loop {
            // Messages from before arrival times were recorded count from their date.
            let due: Vec<(i64, i64)> = match sqlx::query_as(
                "SELECT m.account_id, m.id FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id
                 WHERE b.role = ? AND MAX(m.mailbox_since, m.internal_date) < ? LIMIT 500",
            )
            .bind(role)
            .bind(cutoff)
            .fetch_all(&app.db)
            .await
            {
                Ok(due) => due,
                Err(err) => {
                    tracing::warn!(%err, "retention lookup failed");
                    return removed;
                }
            };
            if due.is_empty() {
                break;
            }
            let batch = due.len();
            for (account_id, id) in due {
                match app.store.delete_message(account_id, id).await {
                    Ok(()) => removed += 1,
                    Err(err) => {
                        tracing::warn!(%err, id, "could not remove an expired message");
                        return removed;
                    }
                }
            }
            if batch < 500 {
                break;
            }
        }
    }
    removed
}
