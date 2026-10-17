//! Outgoing webhooks: the server-side half of the plug-in API. External services subscribe to
//! mail events and receive a signed JSON notification for each of them.
//!
//! Notifications carry envelope metadata only, never message content, and are signed with
//! HMAC-SHA256 (`X-Unomail-Signature: sha256=<hex>`) so receivers can verify their origin.

use std::sync::Arc;

use serde_json::{Value, json};
use sqlx::SqlitePool;

use crate::{
    app::App,
    secretbox::SecretBox,
    util::{hmac_sha256, now, sanitize_line},
};

pub const EVENTS: &[&str] = &["message.received", "message.sent", "message.bounced", "account.created"];

struct Hook {
    id: i64,
    url: String,
    secret: String,
}

/// The notification for an event, written once: every try sends the same bytes (and the same
/// signature), so a receiver can recognise a repeat.
fn notification(event: &str, data: &Value) -> String {
    json!({ "event": event, "timestamp": now(), "data": data }).to_string()
}

async fn send(db: &SqlitePool, http: &reqwest::Client, hook: &Hook, event: &str, body: &str) -> String {
    let body = body.to_owned();
    let signature = hex::encode(hmac_sha256(hook.secret.as_bytes(), body.as_bytes()));
    let result = http
        .post(&hook.url)
        .header("content-type", "application/json")
        .header("user-agent", "unoMail-webhook")
        .header("x-unomail-event", event)
        .header("x-unomail-signature", format!("sha256={signature}"))
        .body(body)
        .send()
        .await;
    let status = match result {
        Ok(response) => format!("HTTP {}", response.status().as_u16()),
        Err(err) if err.is_timeout() => "timed out".to_owned(),
        Err(_) => "connection failed".to_owned(),
    };
    let _ = sqlx::query("UPDATE webhooks SET last_status = ?, last_at = ? WHERE id = ?").bind(&status).bind(now()).bind(hook.id).execute(db).await;
    status
}

async fn hooks_for(db: &SqlitePool, secrets: &SecretBox, event: Option<&str>, only: Option<i64>) -> sqlx::Result<Vec<Hook>> {
    let rows: Vec<(i64, String, String, String)> = sqlx::query_as("SELECT id, url, secret, events FROM webhooks WHERE (?1 IS NOT NULL AND id = ?1) OR (?1 IS NULL AND enabled = 1)")
        .bind(only)
        .fetch_all(db)
        .await?;
    Ok(rows
        .into_iter()
        .filter(|(_, _, _, events)| event.is_none_or(|e| serde_json::from_str::<Vec<String>>(events).unwrap_or_default().iter().any(|x| x == e)))
        .filter_map(|(id, url, sealed, _)| Some(Hook { id, url, secret: secrets.open(&sealed)? }))
        .collect())
}

/// Events the worker may fall behind by. Beyond that, new events are dropped (with a warning)
/// rather than piling up in memory.
const BACKLOG: usize = 1000;
/// Notifications under way at once.
const PARALLEL: usize = 8;
/// Pauses (seconds) before the second and third try of a notification that failed.
const RETRY_DELAYS: [u64; 2] = [5, 30];

/// Whether a notification that ended with `status` is worth trying again: the receiver was
/// unreachable, failed, or asked us to slow down. Other refusals stay refusals.
fn retryable(status: &str) -> bool {
    match status.strip_prefix("HTTP ").and_then(|code| code.parse::<u16>().ok()) {
        Some(code) => code == 408 || code == 429 || code >= 500,
        None => true,
    }
}

/// Notifies every subscribed webhook in the background. Never blocks or fails mail handling.
pub fn emit(app: &App, event: &'static str, data: Value) {
    let queue = app.webhooks.get_or_init(|| start(app));
    if queue.try_send((event, data)).is_err() {
        tracing::warn!(event, "webhook notifications are backed up; event dropped");
    }
}

/// The worker: takes events in order and sends each to its subscribers, a few at a time, with
/// retries.
fn start(app: &App) -> tokio::sync::mpsc::Sender<(&'static str, Value)> {
    let (sender, mut events) = tokio::sync::mpsc::channel::<(&'static str, Value)>(BACKLOG);
    let (db, http, secrets): (SqlitePool, reqwest::Client, Arc<SecretBox>) = (app.db.clone(), app.http.clone(), app.secrets.clone());
    tokio::spawn(async move {
        let slots = Arc::new(tokio::sync::Semaphore::new(PARALLEL));
        while let Some((event, data)) = events.recv().await {
            let body = notification(event, &data);
            let hooks = match hooks_for(&db, &secrets, Some(event), None).await {
                Ok(hooks) => hooks,
                Err(err) => {
                    tracing::error!(%err, "could not load webhooks");
                    continue;
                }
            };
            for hook in hooks {
                let Ok(slot) = slots.clone().acquire_owned().await else { return };
                let (db, http, body) = (db.clone(), http.clone(), body.clone());
                tokio::spawn(async move {
                    for delay in std::iter::once(0).chain(RETRY_DELAYS) {
                        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                        let status = send(&db, &http, &hook, event, &body).await;
                        tracing::debug!(url = %sanitize_line(&hook.url), event, status, "webhook notified");
                        if !retryable(&status) {
                            break;
                        }
                    }
                    drop(slot);
                });
            }
        }
    });
    sender
}

/// Sends one event to one webhook and returns the outcome (used by the "test" button).
pub async fn deliver_to(app: &App, id: i64, event: &str, data: Value) -> sqlx::Result<Option<String>> {
    let hooks = hooks_for(&app.db, &app.secrets, None, Some(id)).await?;
    match hooks.first() {
        Some(hook) => Ok(Some(send(&app.db, &app.http, hook, event, &notification(event, &data)).await)),
        None => Ok(None),
    }
}
