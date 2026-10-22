//! Outgoing webhooks: the server-side half of the plug-in API. External services subscribe to
//! mail events and receive a signed JSON notification for each of them.
//!
//! Notifications carry envelope metadata only, never message content, and are signed with
//! HMAC-SHA256 (`X-Unomail-Signature: sha256=<hex>`) so receivers can verify their origin.

use std::{net::SocketAddr, sync::Arc};

use serde_json::{Value, json};
use sqlx::SqlitePool;

use crate::{
    app::App,
    secretbox::SecretBox,
    security::reputation::is_private,
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

/// Where a notification for `url` may be sent: the host and the one address checked for it.
///
/// Receivers named as localhost were chosen deliberately and are reached as they are. Any
/// other host must resolve to public addresses only, checked at every send rather than when
/// the webhook was saved, so that DNS cannot later point it at an internal service.
async fn destination(url: &str, allow_private: bool) -> Result<Option<(String, SocketAddr)>, &'static str> {
    let url = reqwest::Url::parse(url).map_err(|_| "invalid URL")?;
    let host = url.host_str().ok_or("invalid URL")?.trim_matches(['[', ']']).to_owned();
    if allow_private || matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1") {
        return Ok(None);
    }
    let port = url.port_or_known_default().ok_or("invalid URL")?;
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port)).await.map_err(|_| "connection failed")?.collect();
    match addrs.first() {
        Some(addr) if !addrs.iter().any(|a| is_private(a.ip())) => Ok(Some((host, *addr))),
        Some(_) => Err("refused: private address"),
        None => Err("connection failed"),
    }
}

async fn send(db: &SqlitePool, http: &reqwest::Client, allow_private: bool, hook: &Hook, event: &str, body: &str) -> String {
    let status = match destination(&hook.url, allow_private).await {
        Ok(target) => post(http, target, hook, event, body).await,
        Err(refused) => refused.to_owned(),
    };
    let _ = sqlx::query("UPDATE webhooks SET last_status = ?, last_at = ? WHERE id = ?").bind(&status).bind(now()).bind(hook.id).execute(db).await;
    status
}

async fn post(http: &reqwest::Client, target: Option<(String, SocketAddr)>, hook: &Hook, event: &str, body: &str) -> String {
    // The connection goes to exactly the address that was checked.
    let pinned;
    let http = match target {
        None => http,
        Some((host, addr)) => {
            match crate::outbound::pinned(&host, addr, std::time::Duration::from_secs(15)) {
                Ok(client) => {
                    pinned = client;
                    &pinned
                }
                Err(_) => return "connection failed".to_owned(),
            }
        }
    };
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
    match result {
        Ok(response) => format!("HTTP {}", response.status().as_u16()),
        Err(err) if err.is_timeout() => "timed out".to_owned(),
        Err(_) => "connection failed".to_owned(),
    }
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
        // A refused destination stays refused.
        None => !status.starts_with("refused"),
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
    let allow_private = app.cfg.allow_private_destinations;
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
                        let status = send(&db, &http, allow_private, &hook, event, &body).await;
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
        Some(hook) => Ok(Some(send(&app.db, &app.http, app.cfg.allow_private_destinations, hook, event, &notification(event, &data)).await)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn webhooks_do_not_reach_private_addresses() {
        assert_eq!(destination("https://10.0.0.5/hook", false).await, Err("refused: private address"));
        assert_eq!(destination("https://[fd00::1]:8443/hook", false).await, Err("refused: private address"));
        assert_eq!(destination("https://169.254.169.254/latest", false).await, Err("refused: private address"));
        assert_eq!(destination("http://localhost:9000/hook", false).await, Ok(None), "localhost is chosen deliberately");
        assert_eq!(destination("https://10.0.0.5/hook", true).await, Ok(None));
        let public = destination("https://203.0.113.7:8443/hook", false).await.unwrap().unwrap();
        assert_eq!(public.1, "203.0.113.7:8443".parse().unwrap());
        assert!(!retryable("refused: private address"));
    }
}
