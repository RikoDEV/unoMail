//! A single bounded worker, with a durable lease and finite retries. Delivery only enqueues;
//! neither DNS nor provider requests are made in the message-storage transaction.

use std::{sync::LazyLock, time::Duration};
use regex::Regex;
use crate::{app::AppState, error::ApiError, util::now};
use super::{config, extract, persist, preferences};

static PURCHASE_WORDS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(order|purchase|shipment|shipping|delivery|tracking|zamów|przesył|bestell|liefer|commande|livraison|objedn|zásilk|spedizione|pedido)").unwrap());

pub fn candidate(text: &str) -> bool { PURCHASE_WORDS.is_match(text) }

pub async fn enqueue(state: &AppState, account: i64, message: i64, use_ai: bool) -> Result<(), ApiError> {
    let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM summary_card_jobs WHERE state IN ('pending', 'running')").fetch_one(&state.db).await?;
    if pending >= 5000 { return Err(ApiError::RateLimited); }
    // Never reset an active lease: repeated clicks must not create concurrent provider calls.
    sqlx::query("INSERT INTO summary_card_jobs (message_id, account_id, use_ai) VALUES (?, ?, ?) ON CONFLICT(message_id) DO UPDATE SET state = 'pending', use_ai = excluded.use_ai, attempts = 0, next_attempt = 0, error = NULL WHERE summary_card_jobs.state NOT IN ('pending', 'running')")
        .bind(message).bind(account).bind(use_ai).execute(&state.db).await?;
    Ok(())
}

async fn process(state: &AppState, account: i64, id: i64, explicit_ai: bool) -> Result<(), ApiError> {
    let (enabled, opted_in) = preferences(state, account).await?;
    if !enabled { return Ok(()); }
    let message = state.store.message(account, id).await?;
    let mailbox = state.store.mailbox(account, message.mailbox_id).await?;
    if message.deleted || message.draft || matches!(mailbox.role.as_deref(), Some("junk" | "trash" | "drafts" | "sent")) { return Ok(()); }
    let raw = state.store.read_blob(&message.blob_hash).await?;
    if crate::openpgp::is_encrypted(&raw) { return Ok(()); }
    let structured = extract::structured(&raw);
    if !structured.is_empty() { return persist(state, account, id, &message.from_addr, structured, "structured").await; }
    let config = config(state).await?;
    if config.model_id.is_empty() || !(explicit_ai || config.automatic_ai && opted_in) { return Ok(()); }
    let parsed = crate::search::extract(&raw, &message.blob_hash);
    if parsed.body.trim().is_empty() || parsed.body.chars().count() > 60_000 { return Ok(()); }
    if !explicit_ai && !PURCHASE_WORDS.is_match(&format!("{} {}", parsed.subject, parsed.body.chars().take(4000).collect::<String>())) { return Ok(()); }
    let source = format!("From: {} <{}>\nSubject: {}\n\n{}", message.from_name, message.from_addr, parsed.subject.chars().take(1000).collect::<String>(), parsed.body);
    let urls = extract::source_urls(&raw);
    let prompt = format!("{source}\n\nOriginal action URLs: {}", serde_json::to_string(&urls).unwrap_or_default());
    let output = crate::api::models::generate(state, account, &config.model_id, extract::INSTRUCTION, &prompt).await?;
    let purchases = extract::ai_result(&output, &source, &urls).map_err(ApiError::bad)?;
    // Recheck the user's and administrator's switches after the provider finishes.
    let (enabled, opted_in) = preferences(state, account).await?;
    let current = super::config(state).await?;
    if !enabled || (!explicit_ai && (!opted_in || !current.automatic_ai)) || current.model_id != config.model_id { return Ok(()); }
    persist(state, account, id, &message.from_addr, purchases, "ai").await
}

pub async fn tick(state: &AppState) -> Result<bool, ApiError> {
    let job: Option<(i64, i64, bool, i64)> = sqlx::query_as("UPDATE summary_card_jobs SET state = 'running', attempts = attempts + 1, next_attempt = ?1 WHERE message_id = (SELECT message_id FROM summary_card_jobs WHERE (state = 'pending' OR state = 'running') AND next_attempt <= ?2 ORDER BY next_attempt, message_id LIMIT 1) RETURNING message_id, account_id, use_ai, attempts")
        .bind(now() + 120).bind(now()).fetch_optional(&state.db).await?;
    let Some((message, account, explicit_ai, attempts)) = job else { return Ok(false) };
    let result = process(state, account, message, explicit_ai).await;
    let (status, error, next, saved_attempts) = match result {
        Ok(()) => ("done", None, 0, attempts),
        Err(ApiError::NotFound) => ("done", None, 0, attempts),
        // Backpressure is not a failed extraction. Defer without exhausting the retry budget.
        Err(ApiError::RateLimited) => ("pending", None, now() + 65, attempts - 1),
        Err(_) => {
            // A safe fixed error goes to the UI; provider bodies and mail never enter logs.
            tracing::debug!(message, account, attempt = attempts, "purchase card extraction failed");
            let retry = attempts < 3;
            let next = now() + 30 * attempts;
            (if retry { "pending" } else { "failed" }, Some("Purchase card extraction failed. You can retry."), next, attempts)
        }
    };
    sqlx::query("UPDATE summary_card_jobs SET state = ?, error = ?, next_attempt = ?, attempts = ? WHERE message_id = ? AND attempts = ?")
        .bind(status).bind(error).bind(next).bind(saved_attempts).bind(message).bind(attempts).execute(&state.db).await?;
    Ok(true)
}

pub async fn run(state: AppState) {
    loop {
        match tick(&state).await {
            Ok(true) => tokio::time::sleep(Duration::from_millis(100)).await,
            Ok(false) => tokio::time::sleep(Duration::from_secs(2)).await,
            Err(_) => tokio::time::sleep(Duration::from_secs(5)).await,
        }
    }
}
