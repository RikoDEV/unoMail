//! Server settings, DMARC reports, mailbox imports and live log streams.

use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State},
    response::{
        IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio_stream::wrappers::BroadcastStream;

use super::{JsonResult, Session};
use crate::{
    app::AppState,
    dmarc_reports::{self, Ingested},
    error::ApiError,
    import::{self, ImapSource},
    logstream,
    settings::{self, Runtime},
    util::now,
};

// --- Server settings -----------------------------------------------------------------------

async fn settings_json(state: &AppState) -> Result<Value, ApiError> {
    let overrides = settings::load_overrides(&state.db).await?;
    let mut values = serde_json::to_value(&*state.rt()).map_err(anyhow::Error::from)?;
    // Secrets are never sent back; the page only learns whether one is set.
    let mut secrets_set = Map::new();
    for key in settings::SECRET_KEYS {
        let set = values[key].as_str().is_some_and(|value| !value.is_empty());
        values[key] = json!("");
        secrets_set.insert(key.into(), json!(set));
    }
    Ok(json!({
        "values": values,
        "defaults": Runtime::from_config(&state.cfg),
        "overridden": overrides.keys().collect::<Vec<_>>(),
        "secrets_set": secrets_set,
    }))
}

pub async fn settings_get(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    session.require_super()?;
    Ok(Json(settings_json(&state).await?))
}

/// Changes runtime settings. A `null` value resets a setting to its environment default.
/// Changes take effect immediately, without a restart.
pub async fn settings_patch(State(state): State<AppState>, session: Session, Json(changes): Json<Map<String, Value>>) -> JsonResult<Value> {
    session.require_super()?;
    let mut overrides = settings::load_overrides(&state.db).await?;
    for (key, value) in &changes {
        if value.is_null() {
            overrides.remove(key);
        } else if settings::SECRET_KEYS.contains(&key.as_str()) {
            // Stored sealed with the server key, like the passwords of identity SMTP servers.
            let plain = value.as_str().ok_or_else(|| ApiError::bad(format!("{key} must be text")))?;
            if plain.chars().count() > 500 || plain.chars().any(char::is_control) {
                return Err(ApiError::bad("invalid password"));
            }
            overrides.insert(key.clone(), json!(if plain.is_empty() { String::new() } else { state.secrets.seal(plain) }));
        } else {
            overrides.insert(key.clone(), value.clone());
        }
    }
    let runtime = Runtime::from_config(&state.cfg).with_overrides(&overrides).map_err(ApiError::bad)?;
    settings::save_overrides(&state.db, &overrides).await?;
    state.limiter.set_limits(runtime.login_limits());
    state.settings.store(std::sync::Arc::new(runtime));
    let summary: Vec<String> = changes.iter().map(|(k, v)| if settings::SECRET_KEYS.contains(&k.as_str()) { format!("{k}=(changed)") } else { format!("{k}={v}") }).collect();
    session.audit(&state, "settings.updated", "server", &summary.join(" ")).await;
    Ok(Json(settings_json(&state).await?))
}

// --- DMARC reports -------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct DmarcQuery {
    /// Look-back window in days (default 30).
    days: Option<i64>,
}

/// JSON array with the names of the domains the session may see reports for.
async fn visible_domains(state: &AppState, session: &Session) -> Result<String, ApiError> {
    let names: Vec<String> = match session.managed_domains(&state.db).await? {
        None => sqlx::query_scalar("SELECT name FROM domains").fetch_all(&state.db).await?,
        Some(ids) => {
            let scope = serde_json::to_string(&ids).map_err(anyhow::Error::from)?;
            sqlx::query_scalar("SELECT name FROM domains WHERE id IN (SELECT value FROM json_each(?))").bind(scope).fetch_all(&state.db).await?
        }
    };
    Ok(serde_json::to_string(&names).map_err(anyhow::Error::from)?)
}

/// id, received_at, reporter, feedback_type, auth_failure, source_ip, reported_domain, original_from, subject, incidents
type FeedbackRow = (i64, i64, String, String, String, String, String, String, String, i64);

pub async fn dmarc_overview(State(state): State<AppState>, session: Session, Query(query): Query<DmarcQuery>) -> JsonResult<Value> {
    let domains = visible_domains(&state, &session).await?;
    let since = now() - query.days.unwrap_or(30).clamp(1, 365) * 86400;
    // Feedback reports (complaints, failure reports) about the domains this session sees.
    let feedback: Vec<FeedbackRow> = sqlx::query_as(
        "SELECT id, received_at, reporter, feedback_type, auth_failure, source_ip, reported_domain, original_from, subject, incidents FROM feedback_reports
         WHERE received_at >= ? AND lower(reported_domain) IN (SELECT lower(value) FROM json_each(?)) ORDER BY received_at DESC LIMIT 200",
    )
    .bind(since)
    .bind(&domains)
    .fetch_all(&state.db)
    .await?;
    let feedback: Vec<Value> = feedback
        .into_iter()
        .map(|(id, received_at, reporter, kind, auth_failure, source_ip, domain, from, subject, incidents)| {
            json!({ "id": id, "received_at": received_at, "reporter": reporter, "type": kind, "auth_failure": auth_failure, "source_ip": source_ip, "domain": domain, "from": from, "subject": subject, "incidents": incidents })
        })
        .collect();
    Ok(Json(json!({
        "domains": dmarc_reports::summary(&state, &domains, since).await?,
        "sources": dmarc_reports::sources(&state, &domains, since).await?,
        "reports": dmarc_reports::reports(&state, &domains, since).await?,
        "feedback": feedback,
    })))
}

/// TLS reports other servers sent about hosted domains, and how our own outgoing sessions went.
pub async fn tls_reports(State(state): State<AppState>, session: Session, Query(query): Query<DmarcQuery>) -> JsonResult<Value> {
    let domains = visible_domains(&state, &session).await?;
    let since = now() - query.days.unwrap_or(30).clamp(1, 365) * 86400;
    let mut received = Vec::new();
    {
        type Row = (i64, String, String, String, String, i64, i64, i64, i64, String);
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT id, reporter, report_id, domain, policy_type, date_begin, date_end, successes, failures, details FROM tls_reports WHERE domain IN (SELECT value FROM json_each(?)) AND date_end >= ? ORDER BY date_begin DESC LIMIT 500",
        )
        .bind(&domains)
        .bind(since)
        .fetch_all(&state.db)
        .await?;
        received.extend(rows.into_iter().map(|(id, reporter, report_id, domain, policy, begin, end, ok, failed, details)| {
            json!({ "id": id, "reporter": reporter, "report_id": report_id, "domain": domain, "policy_type": policy, "date_begin": begin, "date_end": end, "successes": ok, "failures": failed, "details": serde_json::from_str::<Value>(&details).unwrap_or(Value::Null) })
        }));
    }
    received.sort_by_key(|r| std::cmp::Reverse(r["date_begin"].as_i64()));
    // Outgoing: only a super administrator sees where this server sends mail.
    let outgoing = if session.is_super() {
        let rows: Vec<(String, String, String, i64)> = sqlx::query_as("SELECT domain, policy_type, result_type, SUM(count) FROM tls_rpt_results WHERE day >= ? GROUP BY domain, policy_type, result_type ORDER BY SUM(count) DESC LIMIT 200")
            .bind(since / 86_400)
            .fetch_all(&state.db)
            .await?;
        rows.into_iter().map(|(domain, policy, result, count)| json!({ "domain": domain, "policy_type": policy, "result": result, "count": count })).collect()
    } else {
        Vec::new()
    };
    Ok(Json(json!({ "received": received, "outgoing": outgoing })))
}

pub async fn dmarc_report(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    let domains = visible_domains(&state, &session).await?;
    let records = dmarc_reports::records(&state, &domains, id).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(json!({ "records": records })))
}

/// Uploads an aggregate report (XML, gzip, zip, or the report e-mail itself).
pub async fn dmarc_upload(State(state): State<AppState>, session: Session, body: Bytes) -> JsonResult<Value> {
    session.require_super()?;
    match dmarc_reports::ingest(&state, &body).await.map_err(ApiError::bad)? {
        Ingested::Stored { domain, records } => {
            session.audit(&state, "dmarc.report_uploaded", &domain, &records.to_string()).await;
            Ok(Json(json!({ "stored": true, "domain": domain, "records": records })))
        }
        Ingested::Duplicate => Ok(Json(json!({ "stored": false, "duplicate": true }))),
    }
}

// --- Mailbox import ------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImportRequest {
    Imap {
        host: String,
        /// Defaults to 993 for implicit TLS and 143 for STARTTLS.
        port: Option<u16>,
        /// `tls` (default) or `starttls`. Plaintext connections are not supported.
        #[serde(default)]
        security: Option<String>,
        username: String,
        password: String,
        #[serde(default)]
        allow_invalid_certificate: bool,
    },
    Maildir {
        path: String,
    },
}

pub async fn import_list(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Vec<import::Job>> {
    session.require_admin()?;
    super::accounts::load_managed(&state, &session, id).await?;
    Ok(Json(import::jobs(&state, id).await?))
}

pub async fn import_start(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(request): Json<ImportRequest>) -> JsonResult<Value> {
    session.require_admin()?;
    let account = super::accounts::load_managed(&state, &session, id).await?;
    let (job, source) = match request {
        ImportRequest::Imap { host, port, security, username, password, allow_invalid_certificate } => {
            let starttls = match security.as_deref() {
                None | Some("tls") => false,
                Some("starttls") => true,
                Some(_) => return Err(ApiError::bad("security must be \"tls\" or \"starttls\"")),
            };
            let port = port.unwrap_or(if starttls { 143 } else { 993 });
            // Reaching internal hosts and skipping certificate checks are both ways to abuse
            // the server's network position; only super administrators may do either.
            if allow_invalid_certificate && !session.is_super() {
                return Err(ApiError::Forbidden);
            }
            let host = host.trim().to_ascii_lowercase();
            let source = ImapSource { host: host.clone(), port, starttls, username, password, allow_invalid_certificate, allow_private: session.is_super() };
            (import::start_imap(&state, id, source).await.map_err(ApiError::bad)?, format!("imap {host}:{port}"))
        }
        ImportRequest::Maildir { path } => {
            // Reads files from the server's own disk.
            session.require_super()?;
            (import::start_maildir(&state, id, &path).await.map_err(ApiError::bad)?, format!("maildir {}", crate::util::sanitize_line(&path)))
        }
    };
    session.audit(&state, "import.started", &account.email, &source).await;
    Ok(Json(json!({ "job": job })))
}

// --- Logs ----------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct StreamQuery {
    kind: String,
}

#[derive(Deserialize)]
pub struct SystemLogQuery {
    q: Option<String>,
    limit: Option<usize>,
}

pub async fn system_log(State(_state): State<AppState>, session: Session, Query(query): Query<SystemLogQuery>) -> JsonResult<Vec<Value>> {
    session.require_super()?;
    Ok(Json(logstream::recent_system(query.limit.unwrap_or(200).clamp(1, 2000), query.q.as_deref().unwrap_or("").trim())))
}

/// Recent SMTP replies the server sent to clients.
pub async fn smtp_log(State(_state): State<AppState>, session: Session, Query(query): Query<SystemLogQuery>) -> JsonResult<Vec<Value>> {
    session.require_super()?;
    Ok(Json(logstream::recent_smtp(query.limit.unwrap_or(200).clamp(1, 2000), query.q.as_deref().unwrap_or("").trim())))
}

/// Server-sent events carrying new log entries of one kind as they are written.
pub async fn log_stream(State(state): State<AppState>, session: Session, Query(query): Query<StreamQuery>) -> Result<impl IntoResponse, ApiError> {
    let kind: &'static str = match query.kind.as_str() {
        "delivery" => "delivery",
        "audit" => "audit",
        "system" => "system",
        "smtp" => "smtp",
        _ => return Err(ApiError::bad("unknown log kind")),
    };
    // Domain administrators may follow the delivery log of their own domains only.
    let scope: Option<Vec<String>> = if kind == "delivery" {
        match session.managed_domains(&state.db).await? {
            None => None,
            Some(ids) => {
                let ids = serde_json::to_string(&ids).map_err(anyhow::Error::from)?;
                Some(sqlx::query_scalar("SELECT name FROM domains WHERE id IN (SELECT value FROM json_each(?))").bind(ids).fetch_all(&state.db).await?)
            }
        }
    } else {
        session.require_super()?;
        None
    };
    let _ = scope; // Initial authorization above also determines the HTTP status.
    let auth = super::LiveAuth::Session(session.token_hash.clone());
    let (app, live) = (state.clone(), auth.clone());
    let stream = BroadcastStream::new(logstream::subscribe()).filter_map(move |event| {
        let (state, auth, original) = (app.clone(), live.clone(), session.clone());
        async move {
            let account = auth.account(&state).await?;
            let current = Session { account, ..original };
            let scope = if kind == "delivery" {
                match current.managed_domains(&state.db).await.ok()? {
                    None => None,
                    Some(ids) => Some(sqlx::query_scalar::<_, String>("SELECT name FROM domains WHERE id IN (SELECT value FROM json_each(?))")
                        .bind(serde_json::to_string(&ids).ok()?).fetch_all(&state.db).await.ok()?),
                }
            } else {
                current.require_super().ok()?;
                None
            };
            let event = event.ok()?;
            if event.kind != kind {
                return None;
            }
            if let Some(domains) = &scope {
                let in_scope = |field: &str| event.entry[field].as_str().and_then(|a| a.rsplit_once('@')).is_some_and(|(_, d)| domains.iter().any(|x| x == d));
                if !in_scope("sender") && !in_scope("recipient") {
                    return None;
                }
            }
            Some(Ok::<_, std::convert::Infallible>(Event::default().event(kind).data(event.entry.to_string())))
        }
    });
    Ok(Sse::new(super::guard_stream(state, auth, stream)).keep_alive(KeepAlive::default()))
}
