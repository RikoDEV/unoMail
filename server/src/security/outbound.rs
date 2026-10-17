//! Outbound abuse control: per-account sending limits and automatic blocking of accounts that
//! behave like compromised senders.

use crate::{app::App, auth::Account, util::now};

/// Spam verdicts on outgoing mail within an hour after which the account is blocked.
pub const MAX_SPAM_HITS_PER_HOUR: i64 = 3;

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The account was already blocked.
    Blocked,
    /// This submission pushed the account over a limit; it is blocked from now on.
    LimitExceeded,
}

async fn block(app: &App, account: &Account, reason: &str) {
    let res = sqlx::query("UPDATE accounts SET outbound_blocked = 1, outbound_blocked_reason = ? WHERE id = ?")
        .bind(reason)
        .bind(account.id)
        .execute(&app.db)
        .await;
    if let Err(err) = res {
        tracing::error!(%err, account = account.email, "failed to block account for outbound mail");
    }
    crate::db::audit(&app.db, "system", "account.outbound_blocked", &account.email, "", reason).await;
}

async fn hour_totals(app: &App, account_id: i64) -> sqlx::Result<(i64, i64, i64)> {
    // Two buckets approximate a sliding hour without per-message rows.
    sqlx::query_as(
        "SELECT COALESCE(SUM(messages), 0), COALESCE(SUM(recipients), 0), COALESCE(SUM(spam_hits), 0)
         FROM outbound_stats WHERE account_id = ? AND bucket >= ?",
    )
    .bind(account_id)
    .bind(now() / 3600 - 1)
    .fetch_one(&app.db)
    .await
}

/// Accounts for one submission with `recipients` recipients, refusing it when the account is
/// blocked or the submission exceeds its hourly allowance.
pub async fn register_submission(app: &App, account: &Account, recipients: usize) -> anyhow::Result<Result<(), Refusal>> {
    let blocked: bool = sqlx::query_scalar("SELECT outbound_blocked FROM accounts WHERE id = ?")
        .bind(account.id)
        .fetch_one(&app.db)
        .await?;
    if blocked {
        return Ok(Err(Refusal::Blocked));
    }
    sqlx::query(
        "INSERT INTO outbound_stats (account_id, bucket, messages, recipients) VALUES (?, ?, 1, ?)
         ON CONFLICT(account_id, bucket) DO UPDATE SET messages = messages + 1, recipients = recipients + excluded.recipients",
    )
    .bind(account.id)
    .bind(now() / 3600)
    .bind(recipients as i64)
    .execute(&app.db)
    .await?;
    let (messages, rcpts, _) = hour_totals(app, account.id).await?;
    if messages > app.rt().outbound_max_messages_per_hour || rcpts > app.rt().outbound_max_recipients_per_hour {
        block(app, account, &format!("hourly sending limit exceeded ({messages} messages, {rcpts} recipients)")).await;
        return Ok(Err(Refusal::LimitExceeded));
    }
    Ok(Ok(()))
}

/// Records that the filter classified an outgoing message as spam. Returns true when this
/// caused the account to be blocked.
pub async fn register_spam(app: &App, account: &Account) -> anyhow::Result<bool> {
    sqlx::query(
        "INSERT INTO outbound_stats (account_id, bucket, spam_hits) VALUES (?, ?, 1)
         ON CONFLICT(account_id, bucket) DO UPDATE SET spam_hits = spam_hits + 1",
    )
    .bind(account.id)
    .bind(now() / 3600)
    .execute(&app.db)
    .await?;
    let (_, _, spam) = hour_totals(app, account.id).await?;
    if spam >= MAX_SPAM_HITS_PER_HOUR {
        block(app, account, "outgoing mail repeatedly classified as spam").await;
        return Ok(true);
    }
    Ok(false)
}

pub async fn prune(app: &App) {
    let _ = sqlx::query("DELETE FROM outbound_stats WHERE bucket < ?").bind(now() / 3600 - 48).execute(&app.db).await;
}
