use axum::{Json, extract::{Path, Query, State}};
use serde::Deserialize;
use serde_json::{Value, json};
use super::{JsonResult, Session};
use crate::{app::AppState, error::ApiError, summary_cards::{self as cards, Config}};

pub async fn config_get(State(state): State<AppState>, session: Session) -> JsonResult<Config> {
    session.require_super()?;
    Ok(Json(cards::config(&state).await?))
}
pub async fn config_put(State(state): State<AppState>, session: Session, Json(config): Json<Config>) -> JsonResult<Config> {
    session.require_super()?;
    if !config.model_id.is_empty() { super::models::require_enabled(&state, &config.model_id).await?; }
    if config.automatic_ai && config.model_id.is_empty() { return Err(ApiError::bad("choose a model for automatic extraction")); }
    crate::db::set_setting(&state.db, "summary_cards.config", &serde_json::to_string(&config).map_err(anyhow::Error::from)?).await?;
    session.audit(&state, "summary_cards.configured", "server", &config.model_id).await;
    Ok(Json(config))
}

#[derive(Deserialize)]
pub struct MessageQuery { email_id: String }

async fn owned_message(state: &AppState, session: &Session, email: &str) -> Result<crate::store::Message, ApiError> {
    let id = crate::jmap::parse_id(email, 'm').ok_or(ApiError::NotFound)?;
    let message = state.store.message(session.account.id, id).await?;
    let mailbox = state.store.mailbox(session.account.id, message.mailbox_id).await?;
    if message.deleted || message.draft || matches!(mailbox.role.as_deref(), Some("junk" | "trash" | "drafts" | "sent")) { return Err(ApiError::NotFound); }
    Ok(message)
}

pub async fn list(State(state): State<AppState>, session: Session, Query(query): Query<MessageQuery>) -> JsonResult<Value> {
    let message = owned_message(&state, &session, &query.email_id).await?;
    let (enabled, _) = cards::preferences(&state, session.account.id).await?;
    let config = cards::config(&state).await?;
    let job: Option<(String, Option<String>)> = sqlx::query_as("SELECT state, error FROM summary_card_jobs WHERE message_id = ? AND account_id = ?")
        .bind(message.id).bind(session.account.id).fetch_optional(&state.db).await?;
    let result = if enabled { cards::cards_for(&state, session.account.id, message.id).await? } else { vec![] };
    let ai_available = !config.model_id.is_empty() && super::models::require_enabled(&state, &config.model_id).await.is_ok();
    Ok(Json(json!({ "enabled": enabled, "ai_available": ai_available, "suggest_ai": cards::jobs::candidate(&format!("{} {}", message.subject, message.snippet)), "cards": result,
        "state": job.as_ref().map(|j| j.0.as_str()).unwrap_or("unprocessed"), "error": job.and_then(|j| j.1) })))
}

#[derive(Deserialize)]
pub struct ExtractInput { email_id: String, #[serde(default)] use_ai: bool }

pub async fn extract(State(state): State<AppState>, session: Session, Json(input): Json<ExtractInput>) -> JsonResult<Value> {
    let message = owned_message(&state, &session, &input.email_id).await?;
    let (enabled, _) = cards::preferences(&state, session.account.id).await?;
    if !enabled { return Err(ApiError::bad("summary cards are disabled in your preferences")); }
    if input.use_ai {
        let config = cards::config(&state).await?;
        super::models::require_enabled(&state, &config.model_id).await?;
    }
    cards::jobs::enqueue(&state, session.account.id, message.id, input.use_ai).await?;
    Ok(Json(json!({ "queued": true })))
}

#[derive(Deserialize)]
pub struct Update { dismissed: bool }
pub async fn update(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<Update>) -> JsonResult<Value> {
    let changed = sqlx::query("UPDATE purchase_cards SET dismissed = ? WHERE id = ? AND account_id = ?")
        .bind(input.dismissed).bind(id).bind(session.account.id).execute(&state.db).await?.rows_affected();
    if changed == 0 { return Err(ApiError::NotFound); }
    Ok(Json(json!({ "ok": true })))
}

/// A finite, recent-mail backfill. Re-enabling the feature does not send an entire archive
/// to a provider; automatic AI still requires both switches when each job executes.
pub async fn backfill(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    if !cards::preferences(&state, session.account.id).await?.0 { return Err(ApiError::bad("summary cards are disabled")); }
    let messages: Vec<i64> = sqlx::query_scalar("SELECT m.id FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id WHERE m.account_id = ? AND m.deleted = 0 AND m.draft = 0 AND COALESCE(b.role, '') NOT IN ('junk', 'trash', 'sent', 'drafts') ORDER BY m.internal_date DESC, m.id DESC LIMIT 200")
        .bind(session.account.id).fetch_all(&state.db).await?;
    for id in &messages { cards::jobs::enqueue(&state, session.account.id, *id, false).await?; }
    Ok(Json(json!({ "queued": messages.len() })))
}
