//! Snoozing: a message leaves for the "Snoozed" folder and comes back, unread and on top,
//! at the chosen time. Moving it out of "Snoozed" by hand cancels the snooze.

use std::time::Duration;

use crate::{
    app::{App, AppState},
    store::StoreError,
    util::now,
};

pub const ROLE: &str = "snoozed";
const MAX_SNOOZE: i64 = 366 * 86_400;

/// The account's "Snoozed" folder, created on first use.
pub async fn mailbox(app: &App, account_id: i64) -> Result<i64, StoreError> {
    if let Some(mailbox) = app.store.mailbox_by_role(account_id, ROLE).await? {
        return Ok(mailbox.id);
    }
    let mailbox = match app.store.mailbox_by_name(account_id, "Snoozed").await? {
        Some(mailbox) => mailbox,
        None => app.store.create_mailbox(account_id, "Snoozed").await?,
    };
    sqlx::query("UPDATE mailboxes SET role = ? WHERE id = ?").bind(ROLE).bind(mailbox.id).execute(&app.db).await?;
    Ok(mailbox.id)
}

/// Snoozes a message of the account until `until`.
pub async fn snooze(app: &App, account_id: i64, message_id: i64, until: i64) -> Result<(), StoreError> {
    if until <= now() || until > now() + MAX_SNOOZE {
        return Err(StoreError::Invalid("choose a time within the next year"));
    }
    let message = app.store.message(account_id, message_id).await?;
    let snoozed = mailbox(app, account_id).await?;
    // Snoozing again only changes the time; the message still returns where it came from.
    let return_to: i64 = match sqlx::query_scalar::<_, i64>("SELECT return_mailbox_id FROM snoozes WHERE message_id = ?").bind(message_id).fetch_optional(&app.db).await? {
        Some(previous) if message.mailbox_id == snoozed => previous,
        _ => message.mailbox_id,
    };
    sqlx::query("INSERT INTO snoozes (message_id, account_id, until, return_mailbox_id, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT (message_id) DO UPDATE SET until = excluded.until, return_mailbox_id = excluded.return_mailbox_id")
        .bind(message_id)
        .bind(account_id)
        .bind(until)
        .bind(return_to)
        .bind(now())
        .execute(&app.db)
        .await?;
    if message.mailbox_id != snoozed {
        app.store.move_message(account_id, message_id, snoozed).await?;
    }
    Ok(())
}

/// Brings a snoozed message back now: unread, on top of its folder.
pub async fn wake(app: &App, account_id: i64, message_id: i64) -> Result<(), StoreError> {
    let return_to: Option<i64> = sqlx::query_scalar("DELETE FROM snoozes WHERE message_id = ? AND account_id = ? RETURNING return_mailbox_id").bind(message_id).bind(account_id).fetch_optional(&app.db).await?;
    let Some(return_to) = return_to else { return Err(StoreError::NotFound) };
    let message = match app.store.message(account_id, message_id).await {
        Ok(message) => message,
        Err(StoreError::NotFound) => return Ok(()),
        Err(err) => return Err(err),
    };
    // Moved out of Snoozed meanwhile: the user has dealt with it.
    let snoozed = app.store.mailbox_by_role(account_id, ROLE).await?.map(|m| m.id);
    if Some(message.mailbox_id) != snoozed {
        return Ok(());
    }
    let target = match app.store.mailbox(account_id, return_to).await {
        Ok(mailbox) => mailbox.id,
        Err(_) => app.store.mailbox_by_role(account_id, "inbox").await?.ok_or(StoreError::NotFound)?.id,
    };
    sqlx::query("UPDATE messages SET internal_date = ? WHERE id = ?").bind(now()).bind(message_id).execute(&app.db).await?;
    let flags = crate::store::Flags { seen: false, answered: message.answered, flagged: message.flagged, deleted: false, draft: message.draft };
    let keywords: Vec<String> = serde_json::from_str(&message.keywords).unwrap_or_default();
    app.store.set_flags_and_keywords(account_id, message_id, flags, &keywords).await?;
    app.store.move_message(account_id, message_id, target).await?;
    Ok(())
}

/// The account's snoozed messages and when they return.
pub async fn list(app: &App, account_id: i64) -> sqlx::Result<Vec<(i64, i64)>> {
    sqlx::query_as("SELECT message_id, until FROM snoozes WHERE account_id = ? ORDER BY until").bind(account_id).fetch_all(&app.db).await
}

/// Wakes what is due. Checked every 30 seconds.
pub async fn run(app: AppState) {
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        wake_due(&app).await;
    }
}

pub async fn wake_due(app: &App) {
    let due: Vec<(i64, i64)> = sqlx::query_as("SELECT account_id, message_id FROM snoozes WHERE until <= ? LIMIT 500").bind(now()).fetch_all(&app.db).await.unwrap_or_default();
    for (account_id, message_id) in due {
        if let Err(err) = wake(app, account_id, message_id).await {
            tracing::warn!(%err, message_id, "a snoozed message could not be brought back");
            let _ = sqlx::query("DELETE FROM snoozes WHERE message_id = ?").bind(message_id).execute(&app.db).await;
        }
    }
}
