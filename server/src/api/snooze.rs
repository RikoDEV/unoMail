//! Snoozing messages from the web client.

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{JsonResult, Session};
use crate::{app::AppState, error::ApiError, jmap::parse_id, snooze};

/// The snoozed messages, with when each returns.
pub async fn list(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let rows = snooze::list(&state, session.account.id).await?;
    Ok(Json(json!(rows.into_iter().map(|(id, until)| json!({ "email_id": format!("m{id}"), "until": until })).collect::<Vec<_>>())))
}

#[derive(Deserialize)]
pub struct SnoozeInput {
    email_ids: Vec<String>,
    until: i64,
}

pub async fn snooze(State(state): State<AppState>, session: Session, Json(input): Json<SnoozeInput>) -> JsonResult<Value> {
    if input.email_ids.len() > 500 {
        return Err(ApiError::bad("at most 500 messages at a time"));
    }
    for id in &input.email_ids {
        let message_id = parse_id(id, 'm').ok_or(ApiError::NotFound)?;
        snooze::snooze(&state, session.account.id, message_id, input.until).await?;
    }
    Ok(Json(json!({ "snoozed": input.email_ids.len() })))
}

/// Brings a message back now.
pub async fn wake(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> JsonResult<Value> {
    let message_id = parse_id(&id, 'm').ok_or(ApiError::NotFound)?;
    snooze::wake(&state, session.account.id, message_id).await?;
    Ok(Json(json!({ "ok": true })))
}
