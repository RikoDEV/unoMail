//! Dashboard, queue management, log viewers, health and metrics.

use std::sync::atomic::Ordering;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{ClientIp, JsonResult, Session, clamp_limit, like_pattern};
use crate::{
    app::{AppState, Metrics},
    error::ApiError,
    security::reputation::is_trusted_source,
    util::{ct_eq, now},
};

async fn count(state: &AppState, sql: &'static str) -> Result<i64, ApiError> {
    Ok(sqlx::query_scalar(sql).fetch_one(&state.db).await?)
}

fn disk_usage(path: &std::path::Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            match entry.metadata() {
                Ok(meta) if meta.is_dir() => stack.push(entry.path()),
                Ok(meta) => total += meta.len(),
                Err(_) => {}
            }
        }
    }
    total
}

pub async fn dashboard(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    session.require_super()?;
    let day_ago = now() - 86400;
    let per_status: Vec<(String, String, i64)> =
        sqlx::query_as("SELECT direction, status, COUNT(*) FROM delivery_log WHERE ts >= ? GROUP BY direction, status")
            .bind(day_ago)
            .fetch_all(&state.db)
            .await?;
    let data_dir = state.cfg.data_dir.clone();
    let disk_bytes = tokio::task::spawn_blocking(move || disk_usage(&data_dir)).await.unwrap_or(0);
    let cert = state.tls.info();
    let m = &state.metrics;
    Ok(Json(json!({
        "hostname": state.cfg.hostname,
        "uptime_seconds": now() - state.started_at,
        "domains": count(&state, "SELECT COUNT(*) FROM domains").await?,
        "mailboxes": count(&state, "SELECT COUNT(*) FROM accounts").await?,
        "aliases": count(&state, "SELECT COUNT(*) FROM aliases").await?,
        "queue_size": count(&state, "SELECT COUNT(*) FROM queue").await?,
        "queue_deferred": count(&state, "SELECT COUNT(*) FROM queue WHERE attempts > 0").await?,
        "blocked_accounts": count(&state, "SELECT COUNT(*) FROM accounts WHERE outbound_blocked = 1").await?,
        "mail_bytes": count(&state, "SELECT COALESCE(SUM(used_bytes), 0) FROM accounts").await?,
        "disk_bytes": disk_bytes,
        "active_connections": m.active_connections.load(Ordering::Relaxed),
        "spam_blocked": Metrics::get(&m.spam_blocked),
        "messages_received": Metrics::get(&m.messages_received),
        "messages_sent": Metrics::get(&m.messages_sent),
        "messages_rejected": Metrics::get(&m.messages_rejected),
        "auth_failures": Metrics::get(&m.auth_failures),
        "last_24h": per_status.iter().map(|(d, s, c)| json!({ "direction": d, "status": s, "count": c })).collect::<Vec<_>>(),
        "certificate": {
            "kind": cert.kind,
            "not_after": cert.not_after,
            "seconds_remaining": cert.seconds_remaining(),
            "healthy": cert.kind != crate::tls::CertKind::SelfSigned && cert.seconds_remaining() > crate::tls::RENEW_BEFORE_SECS,
        },
        "rspamd_enabled": state.cfg.rspamd_url.is_some(),
        "clamav_enabled": state.cfg.clamav_addr.is_some(),
        "reputation": crate::security::reputation::stored_status(&state).await,
    })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct QueueEntry {
    id: i64,
    sender: String,
    recipient: String,
    size: i64,
    attempts: i64,
    next_attempt_at: i64,
    created_at: i64,
    expires_at: i64,
    last_error: Option<String>,
    status: String,
}

pub async fn queue_list(State(state): State<AppState>, session: Session) -> JsonResult<Vec<QueueEntry>> {
    session.require_super()?;
    let rows = sqlx::query_as(
        "SELECT id, sender, recipient, size, attempts, next_attempt_at, created_at, expires_at, last_error, status
         FROM queue ORDER BY created_at DESC LIMIT 500",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}

pub async fn queue_retry(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    session.require_super()?;
    let changed = sqlx::query("UPDATE queue SET next_attempt_at = ?, status = 'queued' WHERE id = ? AND status != 'sending'")
        .bind(now())
        .bind(id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if changed == 0 {
        return Err(ApiError::NotFound);
    }
    state.queue_wake.notify_one();
    session.audit(&state, "queue.retry", &id.to_string(), "").await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn queue_delete(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    session.require_super()?;
    let recipient: Option<String> = sqlx::query_scalar("DELETE FROM queue WHERE id = ? AND status != 'sending' RETURNING recipient")
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    let recipient = recipient.ok_or(ApiError::NotFound)?;
    session.audit(&state, "queue.deleted", &recipient, &id.to_string()).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct LogQuery {
    q: Option<String>,
    status: Option<String>,
    /// Return entries with an id greater than this (live tail).
    after: Option<i64>,
    /// Return entries with an id lower than this (paging backwards).
    before: Option<i64>,
    limit: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct DeliveryRow {
    id: i64,
    ts: i64,
    direction: String,
    sender: String,
    recipient: String,
    status: String,
    detail: String,
    remote: String,
    message_id: String,
    size: i64,
}

pub async fn delivery_log(State(state): State<AppState>, session: Session, Query(query): Query<LogQuery>) -> JsonResult<Vec<DeliveryRow>> {
    let managed = session.managed_domains(&state.db).await?;
    // Domain administrators only see traffic of their own domains.
    let domains: Vec<String> = match &managed {
        None => Vec::new(),
        Some(ids) => {
            let scope = serde_json::to_string(ids).map_err(anyhow::Error::from)?;
            sqlx::query_scalar("SELECT name FROM domains WHERE id IN (SELECT value FROM json_each(?))").bind(scope).fetch_all(&state.db).await?
        }
    };
    let domain_patterns = serde_json::to_string(&domains.iter().map(|d| format!("%@{d}")).collect::<Vec<_>>()).map_err(anyhow::Error::from)?;
    let rows = sqlx::query_as(
        "SELECT id, ts, direction, sender, recipient, status, detail, remote, message_id, size FROM delivery_log
         WHERE (?1 = 1 OR EXISTS (SELECT 1 FROM json_each(?2) p WHERE sender LIKE p.value OR recipient LIKE p.value))
           AND (sender LIKE ?3 ESCAPE '\\' OR recipient LIKE ?3 ESCAPE '\\' OR detail LIKE ?3 ESCAPE '\\' OR message_id LIKE ?3 ESCAPE '\\')
           AND (?4 IS NULL OR status = ?4)
           AND (?5 IS NULL OR id > ?5)
           AND (?6 IS NULL OR id < ?6)
         ORDER BY id DESC LIMIT ?7",
    )
    .bind(managed.is_none())
    .bind(domain_patterns)
    .bind(like_pattern(query.q.as_deref().unwrap_or("").trim()))
    .bind(query.status.filter(|s| !s.is_empty()))
    .bind(query.after)
    .bind(query.before)
    .bind(clamp_limit(query.limit))
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct AuditRow {
    id: i64,
    ts: i64,
    actor: String,
    action: String,
    target: String,
    ip: String,
    detail: String,
}

pub async fn audit_log(State(state): State<AppState>, session: Session, Query(query): Query<LogQuery>) -> JsonResult<Vec<AuditRow>> {
    session.require_super()?;
    let rows = sqlx::query_as(
        "SELECT id, ts, actor, action, target, ip, detail FROM audit_log
         WHERE (actor LIKE ?1 ESCAPE '\\' OR action LIKE ?1 ESCAPE '\\' OR target LIKE ?1 ESCAPE '\\' OR ip LIKE ?1 ESCAPE '\\')
           AND (?2 IS NULL OR id > ?2)
           AND (?3 IS NULL OR id < ?3)
         ORDER BY id DESC LIMIT ?4",
    )
    .bind(like_pattern(query.q.as_deref().unwrap_or("").trim()))
    .bind(query.after)
    .bind(query.before)
    .bind(clamp_limit(query.limit))
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}

/// Liveness/readiness probe. Deliberately reveals nothing beyond "up" or "down".
pub async fn health(State(state): State<AppState>) -> Response {
    match sqlx::query_scalar::<_, i64>("SELECT 1").fetch_one(&state.db).await {
        Ok(_) => Json(json!({ "status": "ok" })).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "status": "unavailable" }))).into_response(),
    }
}

/// Prometheus metrics. Available to private/loopback scrapers, or with the bearer token from
/// `UNOMAIL_METRICS_TOKEN`; never to anonymous clients on the public internet.
pub async fn metrics(State(state): State<AppState>, ClientIp(ip): ClientIp, headers: HeaderMap) -> Response {
    let bearer = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
    let authorized = match (&state.cfg.metrics_token, bearer) {
        (Some(expected), Some(given)) => ct_eq(expected.as_bytes(), given.as_bytes()),
        (Some(_), None) => false,
        (None, _) => is_trusted_source(&state.cfg, ip),
    };
    if !authorized {
        return StatusCode::NOT_FOUND.into_response();
    }
    let queue: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM queue").fetch_one(&state.db).await.unwrap_or(-1);
    let m = &state.metrics;
    let listings = crate::security::reputation::stored_status(&state).await.map_or(0, |s| s.listed.len() as i64);
    let mut out = String::new();
    let mut metric = |name: &str, kind: &str, help: &str, value: i64| {
        out.push_str(&format!("# HELP unomail_{name} {help}\n# TYPE unomail_{name} {kind}\nunomail_{name} {value}\n"));
    };
    let c = |counter| Metrics::get(counter) as i64;
    metric("up", "gauge", "Whether the server is running.", 1);
    metric("uptime_seconds", "gauge", "Seconds since the server started.", now() - state.started_at);
    metric("queue_size", "gauge", "Messages waiting in the outbound queue.", queue);
    metric("active_connections", "gauge", "Open mail protocol connections.", m.active_connections.load(Ordering::Relaxed));
    metric("certificate_expiry_seconds", "gauge", "Seconds until the active TLS certificate expires.", state.tls.info().seconds_remaining());
    metric("blocklist_listings", "gauge", "DNS blocklists currently listing one of the server's addresses.", listings);
    metric("smtp_connections_total", "counter", "Accepted SMTP connections.", c(&m.smtp_connections));
    metric("imap_connections_total", "counter", "Accepted IMAP connections.", c(&m.imap_connections));
    metric("pop3_connections_total", "counter", "Accepted POP3 connections.", c(&m.pop3_connections));
    metric("messages_received_total", "counter", "Messages received from other servers.", c(&m.messages_received));
    metric("messages_delivered_local_total", "counter", "Messages stored in local mailboxes.", c(&m.messages_delivered_local));
    metric("messages_sent_total", "counter", "Messages delivered to remote servers.", c(&m.messages_sent));
    metric("messages_bounced_total", "counter", "Bounces generated.", c(&m.messages_bounced));
    metric("messages_rejected_total", "counter", "Inbound messages rejected.", c(&m.messages_rejected));
    metric("spam_blocked_total", "counter", "Messages classified as spam.", c(&m.spam_blocked));
    metric("auth_failures_total", "counter", "Failed authentication attempts.", c(&m.auth_failures));
    metric("http_requests_total", "counter", "HTTP requests served.", c(&m.http_requests));
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], out).into_response()
}
