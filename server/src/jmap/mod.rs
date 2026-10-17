//! JMAP (RFC 8620 / RFC 8621) endpoint used by the web client and third-party JMAP clients.
//!
//! Implemented: Core/echo, Mailbox/get|set, Email/query|get|set|import, Thread/get, Identity/get and
//! EmailSubmission/set, the `/changes` family and Email/queryChanges, plus blob upload/download
//! and an event source for push. Beyond mail: Quota (RFC 9425), SieveScript (RFC 9661),
//! AddressBook and ContactCard (RFC 9610), and Calendar and CalendarEvent (JMAP Calendars).

use std::collections::HashMap;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, FromRequestParts, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use serde_json::{Map, Value, json};
use tokio_stream::wrappers::BroadcastStream;

use crate::{
    api::{ClientIp, Session},
    app::{AppState, Metrics},
    auth::{self, Account, AuthError, Protocol},
    error::ApiError,
};

mod calendar;
mod contacts;
mod email;
mod mailbox;
mod mdn;
pub mod objects;
mod quota;
mod sieve;
pub mod push;
pub mod submission;
mod ws;

const MAX_CALLS: usize = 32;
pub const MAX_OBJECTS: usize = 500;
const MAX_EXPANDED_BYTES: usize = 16 * 1024 * 1024;
const MAX_EXPANDED_NODES: usize = 100_000;

struct Budget { bytes: usize, nodes: usize }
impl Budget {
    fn new() -> Self { Self { bytes: MAX_EXPANDED_BYTES, nodes: MAX_EXPANDED_NODES } }
    fn charge(&mut self, value: &Value, depth: usize) -> Result<(), MethodError> {
        if depth > 64 { return Err(MethodError("tooLarge", "result nesting is too deep".into())); }
        self.nodes = self.nodes.checked_sub(1).ok_or_else(|| MethodError("tooLarge", "too many expanded values".into()))?;
        let bytes = match value { Value::String(s) => s.len().saturating_mul(6).saturating_add(128), _ => 128 };
        self.bytes = self.bytes.checked_sub(bytes).ok_or_else(|| MethodError("tooLarge", "expanded request or response is too large".into()))?;
        match value {
            Value::Array(items) => for item in items { self.charge(item, depth + 1)?; },
            Value::Object(items) => for (key, item) in items {
                self.bytes = self.bytes.checked_sub(key.len().saturating_mul(6)).ok_or_else(|| MethodError("tooLarge", "expanded keys are too large".into()))?;
                self.charge(item, depth + 1)?;
            },
            _ => {}
        }
        Ok(())
    }
}

static REQUESTS: std::sync::LazyLock<parking_lot::Mutex<HashMap<(usize, i64), usize>>> = std::sync::LazyLock::new(Default::default);
struct RequestSlot((usize, i64));
impl RequestSlot {
    fn take(state: &AppState, account: i64) -> Option<Self> {
        let id = (std::sync::Arc::as_ptr(state) as usize, account);
        let mut running = REQUESTS.lock();
        if running.values().sum::<usize>() >= 64 || running.get(&id).copied().unwrap_or(0) >= 4 { return None; }
        *running.entry(id).or_default() += 1;
        Some(Self(id))
    }
}
impl Drop for RequestSlot {
    fn drop(&mut self) {
        let mut running = REQUESTS.lock();
        if let Some(count) = running.get_mut(&self.0) { *count -= 1; if *count == 0 { running.remove(&self.0); } }
    }
}

/// A JMAP method-level error (RFC 8620 section 3.6.2).
#[derive(Debug)]
pub struct MethodError(pub &'static str, pub String);

impl MethodError {
    pub fn invalid(msg: impl Into<String>) -> Self {
        MethodError("invalidArguments", msg.into())
    }

    pub fn server(err: impl std::fmt::Debug) -> Self {
        tracing::error!(error = ?err, "JMAP method failed");
        MethodError("serverFail", "internal error".into())
    }
}

impl From<sqlx::Error> for MethodError {
    fn from(err: sqlx::Error) -> Self {
        MethodError::server(err)
    }
}

impl From<crate::store::StoreError> for MethodError {
    fn from(err: crate::store::StoreError) -> Self {
        use crate::store::StoreError;
        match err {
            StoreError::NotFound => MethodError("notFound", "not found".into()),
            StoreError::QuotaExceeded => MethodError("overQuota", "mailbox quota exceeded".into()),
            StoreError::Invalid(msg) => MethodError::invalid(msg),
            StoreError::Exists => MethodError::invalid("already exists"),
            other => MethodError::server(other),
        }
    }
}

pub type MethodResult = Result<Value, MethodError>;

/// Per-item failure inside a `/set` response.
pub fn set_error(kind: &str, description: impl Into<String>) -> Value {
    json!({ "type": kind, "description": description.into() })
}

pub fn account_id(account: &Account) -> String {
    format!("a{}", account.id)
}

/// Parses an identifier with a one-letter type prefix, e.g. `m42`.
pub fn parse_id(id: &str, prefix: char) -> Option<i64> {
    id.strip_prefix(prefix)?.parse().ok().filter(|n: &i64| *n > 0)
}

/// The authenticated JMAP user: a browser session (cookie + CSRF token) or HTTP Basic
/// credentials for external clients.
pub struct JmapUser {
    pub account: Account,
    pub ip: std::net::IpAddr,
    pub auth: crate::api::LiveAuth,
}

impl FromRequestParts<AppState> for JmapUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let ClientIp(ip) = ClientIp::from_request_parts(parts, state).await.map_err(IntoResponse::into_response)?;
        let basic = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Basic "))
            .and_then(|b64| STANDARD.decode(b64.trim()).ok())
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|creds| creds.split_once(':').map(|(u, p)| (u.to_owned(), p.to_owned())));
        if let Some((user, password)) = basic {
            return match auth::authenticate_with(&state.db, &state.limiter, &user, &password, ip, Protocol::Jmap).await {
                Ok((account, credential)) => {
                    let auth = crate::api::LiveAuth::Credential(auth::Grant::new(&account, Protocol::Jmap, Some(credential)), account.id);
                    Ok(JmapUser { account, ip, auth })
                }
                Err(AuthError::RateLimited) => Err(ApiError::RateLimited.into_response()),
                Err(_) => {
                    Metrics::inc(&state.metrics.auth_failures);
                    Err(unauthorized())
                }
            };
        }
        match Session::from_request_parts(parts, state).await {
            Ok(session) => Ok(JmapUser { account: session.account, ip, auth: crate::api::LiveAuth::Session(session.token_hash) }),
            Err(ApiError::Unauthorized) => Err(unauthorized()),
            Err(other) => Err(other.into_response()),
        }
    }
}

fn unauthorized() -> Response {
    ApiError::Unauthorized.into_response()
}

async fn session_object(State(state): State<AppState>, user: JmapUser) -> Result<Json<Value>, ApiError> {
    let id = account_id(&user.account);
    let state_string = state.store.account_state(user.account.id).await?.to_string();
    let mail_caps = json!({
        "maxMailboxesPerEmail": 1,
        "maxMailboxDepth": 10,
        "maxSizeMailboxName": crate::store::MAX_MAILBOX_NAME_LEN,
        "maxSizeAttachmentsPerEmail": state.rt().max_message_size,
        "emailQuerySortOptions": ["receivedAt"],
        "mayCreateTopLevelMailbox": true,
    });
    let calendar_caps = json!({
        "maxCalendarsPerEvent": 1,
        "minDateTime": "1900-01-01T00:00:00Z",
        "maxDateTime": "2200-01-01T00:00:00Z",
        "maxExpandedQueryDuration": "P366D",
        "maxParticipantsPerEvent": crate::calendar::ical::MAX_ATTENDEES + 1,
        "mayCreateCalendar": true,
    });
    let submission_caps = json!({ "maxDelayedSend": submission::MAX_DELAY, "submissionExtensions": { "FUTURERELEASE": [submission::MAX_DELAY.to_string()] } });
    Ok(Json(json!({
        "capabilities": {
            "urn:ietf:params:jmap:core": {
                "maxSizeUpload": state.rt().max_message_size,
                "maxConcurrentUpload": 4,
                "maxSizeRequest": 10 * 1024 * 1024,
                "maxConcurrentRequests": 4,
                "maxCallsInRequest": MAX_CALLS,
                "maxObjectsInGet": MAX_OBJECTS,
                "maxObjectsInSet": MAX_OBJECTS,
                "collationAlgorithms": [],
            },
            "urn:ietf:params:jmap:mail": mail_caps,
            "urn:ietf:params:jmap:submission": submission_caps.clone(),
            "urn:ietf:params:jmap:websocket": { "url": ws::url(&state), "supportsPush": true },
            "urn:ietf:params:jmap:mdn": {},
            "urn:ietf:params:jmap:quota": {},
            "urn:ietf:params:jmap:sieve": {},
            "urn:ietf:params:jmap:contacts": {},
            "urn:ietf:params:jmap:calendars": {},
            "urn:ietf:params:jmap:webpush-vapid": { "applicationServerKey": push::application_server_key(&state) },
        },
        "accounts": {
            id.clone(): {
                "name": user.account.email,
                "isPersonal": true,
                "isReadOnly": false,
                "accountCapabilities": {
                    "urn:ietf:params:jmap:mail": mail_caps,
                    "urn:ietf:params:jmap:submission": submission_caps,
                    "urn:ietf:params:jmap:quota": {},
                    "urn:ietf:params:jmap:sieve": sieve::capability(),
                    "urn:ietf:params:jmap:contacts": { "maxAddressBooksPerCard": 1, "mayCreateAddressBook": false },
                    "urn:ietf:params:jmap:calendars": calendar_caps,
                },
            }
        },
        "primaryAccounts": {
            "urn:ietf:params:jmap:mail": id, "urn:ietf:params:jmap:submission": id, "urn:ietf:params:jmap:quota": id,
            "urn:ietf:params:jmap:sieve": id, "urn:ietf:params:jmap:contacts": id, "urn:ietf:params:jmap:calendars": id,
        },
        "username": user.account.email,
        "apiUrl": "/jmap/api",
        "downloadUrl": "/jmap/download/{accountId}/{blobId}/{name}?type={type}",
        "uploadUrl": "/jmap/upload/{accountId}",
        "eventSourceUrl": "/jmap/eventsource",
        "state": state_string,
    })))
}

/// Evaluates a JSON pointer that may contain `*` segments, which map over arrays (RFC 8620 3.7).
fn pointer<'a>(value: &'a Value, segments: &[&str]) -> Option<Vec<&'a Value>> {
    let Some((first, rest)) = segments.split_first() else { return Some(vec![value]) };
    match (*first, value) {
        ("*", Value::Array(items)) => {
            let mut out = Vec::new();
            for item in items {
                out.extend(pointer(item, rest)?);
            }
            Some(out)
        }
        (key, Value::Object(map)) => pointer(map.get(key)?, rest),
        (index, Value::Array(items)) => pointer(items.get(index.parse::<usize>().ok()?)?, rest),
        _ => None,
    }
}

/// Replaces `#name` arguments with values taken from earlier responses in the same request.
fn resolve_references(args: &mut Map<String, Value>, responses: &[Value], budget: &mut Budget) -> Result<(), MethodError> {
    let keys: Vec<String> = args.keys().filter(|k| k.starts_with('#')).cloned().collect();
    for key in keys {
        let reference = args.remove(&key).unwrap_or(Value::Null);
        let bad = || MethodError("invalidResultReference", format!("cannot resolve {key}"));
        let (result_of, name, path) = (
            reference["resultOf"].as_str().ok_or_else(bad)?,
            reference["name"].as_str().ok_or_else(bad)?,
            reference["path"].as_str().ok_or_else(bad)?,
        );
        let source = responses.iter().find(|r| r[2] == result_of && r[0] == name).ok_or_else(bad)?;
        let segments: Vec<&str> = path.split('/').skip(1).collect();
        if segments.len() > 64 { return Err(bad()); }
        let has_wildcard = segments.contains(&"*");
        let found = pointer(&source[1], &segments).ok_or_else(bad)?;
        // Charge every copy before allocating it, including repeated references to
        // the same previous result. Input size alone cannot bound this expansion.
        for value in &found { budget.charge(value, 0)?; }
        let value = if has_wildcard {
            // Arrays produced by a wildcard are flattened one level.
            Value::Array(found.into_iter().flat_map(|v| match v {
                Value::Array(inner) => inner.clone(),
                other => vec![other.clone()],
            }).collect())
        } else {
            found.into_iter().next().cloned().ok_or_else(bad)?
        };
        args.insert(key[1..].to_owned(), value);
    }
    Ok(())
}

pub struct Context<'a> {
    pub app: &'a AppState,
    pub account: &'a Account,
    pub ip: std::net::IpAddr,
    /// Creation ids from earlier `/set` calls in this request mapped to the real ids.
    pub created: HashMap<String, String>,
}

impl Context<'_> {
    /// Resolves an id that may be a `#creationId` reference.
    pub fn resolve_id(&self, id: &str) -> String {
        id.strip_prefix('#').and_then(|c| self.created.get(c)).cloned().unwrap_or_else(|| id.to_owned())
    }

    pub async fn state(&self) -> Result<String, MethodError> {
        Ok(self.app.store.account_state(self.account.id).await?.to_string())
    }

    /// A mailbox the user can see (their own, or one shared with them) and the rights they
    /// hold on it.
    pub async fn mailbox(&self, id: i64) -> Result<Option<(crate::store::Mailbox, String)>, MethodError> {
        Ok(crate::sharing::mailbox(&self.app.db, self.account, id).await?)
    }

    /// A message the user may read, with the rights they hold on its mailbox. The message may
    /// belong to another account when its mailbox is shared.
    pub async fn message(&self, id: i64) -> Result<Option<(crate::store::Message, String)>, MethodError> {
        let location: Option<(i64, i64)> = sqlx::query_as("SELECT account_id, mailbox_id FROM messages WHERE id = ?").bind(id).fetch_optional(&self.app.db).await?;
        let Some((owner, mailbox_id)) = location else { return Ok(None) };
        let Some((_, rights)) = self.mailbox(mailbox_id).await? else { return Ok(None) };
        if !rights.contains('r') {
            return Ok(None);
        }
        match self.app.store.message(owner, id).await {
            Ok(message) => Ok(Some((message, rights))),
            Err(crate::store::StoreError::NotFound) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }
}

async fn dispatch(ctx: &mut Context<'_>, name: &str, args: &Map<String, Value>) -> MethodResult {
    if name == "Core/echo" {
        return Ok(Value::Object(args.clone()));
    }
    // Push subscriptions belong to the user, not to an account.
    match name {
        "PushSubscription/get" => return push::get(ctx, args).await,
        "PushSubscription/set" => return push::set(ctx, args).await,
        _ => {}
    }
    match args.get("accountId").and_then(Value::as_str) {
        Some(id) if id == account_id(ctx.account) => {}
        _ => return Err(MethodError("accountNotFound", "unknown accountId".into())),
    }
    match name {
        "Mailbox/get" => mailbox::get(ctx, args).await,
        "Mailbox/set" => mailbox::set(ctx, args).await,
        "Email/query" => email::query(ctx, args).await,
        "Email/get" => email::get(ctx, args).await,
        "Email/set" => email::set(ctx, args).await,
        "Email/import" => email::import(ctx, args).await,
        "Thread/get" => email::thread_get(ctx, args).await,
        "Identity/get" => email::identity_get(ctx, args).await,
        "EmailSubmission/set" => submission::set(ctx, args).await,
        "EmailSubmission/get" => submission::get(ctx, args).await,
        "MDN/send" => mdn::send(ctx, args).await,
        "EmailSubmission/query" => submission::query(ctx, args).await,
        "Email/changes" => email::changes(ctx, args, "email").await,
        "Mailbox/changes" => email::changes(ctx, args, "mailbox").await,
        "Thread/changes" => email::changes(ctx, args, "thread").await,
        "Email/queryChanges" => email::query_changes(ctx, args).await,
        "Quota/get" => quota::get(ctx, args).await,
        "Quota/changes" => quota::changes(ctx, args).await,
        "Quota/query" => quota::query(ctx, args).await,
        "Quota/queryChanges" => quota::query_changes(ctx, args).await,
        "SieveScript/get" => sieve::get(ctx, args).await,
        "SieveScript/changes" => sieve::changes(ctx, args).await,
        "SieveScript/set" => sieve::set(ctx, args).await,
        "SieveScript/query" => sieve::query(ctx, args).await,
        "SieveScript/validate" => sieve::validate(ctx, args).await,
        "AddressBook/get" => contacts::book_get(ctx, args).await,
        "AddressBook/changes" => contacts::book_changes(ctx, args).await,
        "AddressBook/set" => contacts::book_set(ctx, args).await,
        "ContactCard/get" => contacts::get(ctx, args).await,
        "ContactCard/changes" => contacts::changes(ctx, args).await,
        "ContactCard/query" => contacts::query(ctx, args).await,
        "ContactCard/set" => contacts::set(ctx, args).await,
        "Calendar/get" => calendar::calendar_get(ctx, args).await,
        "Calendar/changes" => calendar::calendar_changes(ctx, args).await,
        "Calendar/set" => calendar::calendar_set(ctx, args).await,
        "CalendarEvent/get" => calendar::event_get(ctx, args).await,
        "CalendarEvent/changes" => calendar::event_changes(ctx, args).await,
        "CalendarEvent/query" => calendar::event_query(ctx, args).await,
        "CalendarEvent/set" => calendar::event_set(ctx, args).await,
        _ => Err(MethodError("unknownMethod", format!("unknown method {name}"))),
    }
}

fn request_error(kind: &str, detail: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/problem+json")],
        json!({ "type": format!("urn:ietf:params:jmap:error:{kind}"), "status": 400, "detail": detail }).to_string(),
    )
        .into_response()
}

/// Runs one JMAP request object; on failure, the request-level error type and detail.
pub(crate) async fn process(state: &AppState, account: &Account, ip: std::net::IpAddr, request: &Value) -> Result<Value, (&'static str, &'static str)> {
    let Some(_slot) = RequestSlot::take(state, account.id) else { return Err(("limit", "too many concurrent requests")) };
    let mut budget = Budget::new();
    budget.charge(request, 0).map_err(|_| ("limit", "request structure is too large"))?;
    let Some(calls) = request["methodCalls"].as_array() else {
        return Err(("notRequest", "methodCalls is missing"));
    };
    if calls.len() > MAX_CALLS {
        return Err(("limit", "too many method calls"));
    }
    let mut ctx = Context { app: state, account, ip, created: HashMap::new() };
    let mut responses: Vec<Value> = Vec::with_capacity(calls.len());
    for call in calls {
        let (Some(name), Some(args), Some(call_id)) = (call[0].as_str(), call[1].as_object(), call[2].as_str()) else {
            return Err(("notRequest", "malformed method call"));
        };
        let mut args = args.clone();
        let result = match resolve_references(&mut args, &responses, &mut budget) {
            Ok(()) => {
                Metrics::inc(&state.metrics.jmap_calls);
                let span = tracing::info_span!("jmap.method", jmap.method = name, jmap.error = tracing::field::Empty);
                let result = tracing::Instrument::instrument(dispatch(&mut ctx, name, &args), span.clone()).await;
                if let Err(MethodError(kind, _)) = &result {
                    span.record("jmap.error", *kind);
                }
                result
            }
            Err(err) => Err(err),
        };
        if let Ok(value) = &result {
            budget.charge(value, 0).map_err(|_| ("limit", "expanded response is too large"))?;
        }
        responses.push(match result {
            Ok(value) => json!([name, value, call_id]),
            Err(MethodError(kind, description)) => json!(["error", { "type": kind, "description": description }, call_id]),
        });
    }
    let session_state = state.store.account_state(account.id).await.map(|s| s.to_string()).unwrap_or_default();
    Ok(json!({ "methodResponses": responses, "createdIds": ctx.created, "sessionState": session_state }))
}

async fn api(State(state): State<AppState>, user: JmapUser, body: Bytes) -> Response {
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return request_error("notJSON", "the request body is not valid JSON");
    };
    match process(&state, &user.account, user.ip, &request).await {
        Ok(response) => Json(response).into_response(),
        Err((kind, detail)) => request_error(kind, detail),
    }
}

fn own_account(user: &JmapUser, id: &str) -> Result<(), ApiError> {
    if id == account_id(&user.account) { Ok(()) } else { Err(ApiError::NotFound) }
}

/// Uploads one account may have running at once (advertised as `maxConcurrentUpload`).
const MAX_CONCURRENT_UPLOADS: usize = 4;
/// Uploads not yet used in a message, per account: they expire after a day, and until then
/// take room on disk that no quota counts.
const MAX_PENDING_UPLOAD_BYTES: i64 = 1024 * 1024 * 1024;

static UPLOADING: std::sync::LazyLock<parking_lot::Mutex<HashMap<i64, usize>>> = std::sync::LazyLock::new(Default::default);

/// One of an account's running uploads; the place is given back when it is dropped.
struct UploadSlot(i64);

impl UploadSlot {
    fn take(account_id: i64) -> Option<UploadSlot> {
        let mut running = UPLOADING.lock();
        let count = running.entry(account_id).or_default();
        if *count >= MAX_CONCURRENT_UPLOADS {
            return None;
        }
        *count += 1;
        Some(UploadSlot(account_id))
    }
}

impl Drop for UploadSlot {
    fn drop(&mut self) {
        let mut running = UPLOADING.lock();
        if let Some(count) = running.get_mut(&self.0) {
            *count -= 1;
            if *count == 0 {
                running.remove(&self.0);
            }
        }
    }
}

async fn upload(State(state): State<AppState>, user: JmapUser, Path(account): Path<String>, headers: HeaderMap, body: axum::body::Body) -> Result<Response, ApiError> {
    own_account(&user, &account)?;
    // The size is checked before anything is read, and the body read no further than it.
    let limit = state.rt().max_message_size;
    let declared = headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|length| length > limit as u64) {
        return Err(ApiError::TooLarge);
    }
    let Some(_slot) = UploadSlot::take(user.account.id) else { return Err(ApiError::RateLimited) };
    let body = axum::body::to_bytes(body, limit).await.map_err(|_| ApiError::TooLarge)?;
    if body.is_empty() {
        return Err(ApiError::bad("empty upload"));
    }
    // Pending uploads count against the mailbox's free space, and are capped in any case.
    let hash_of_body = crate::util::sha256_hex(&body);
    let pending: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(size), 0) FROM uploads WHERE account_id = ? AND created_at >= ? AND hash != ?")
        .bind(user.account.id)
        .bind(crate::util::now() - 86_400)
        .bind(&hash_of_body)
        .fetch_one(&state.db)
        .await
        .map_err(anyhow::Error::from)?;
    let used: i64 = sqlx::query_scalar("SELECT used_bytes FROM accounts WHERE id = ?").bind(user.account.id).fetch_one(&state.db).await.map_err(anyhow::Error::from)?;
    let room = if user.account.quota_bytes > 0 { (user.account.quota_bytes - used).min(MAX_PENDING_UPLOAD_BYTES) } else { MAX_PENDING_UPLOAD_BYTES };
    if pending + body.len() as i64 > room {
        return Err(ApiError::Conflict("not enough space left for this upload: send or discard the drafts with attachments first".into()));
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 100 && v.parse::<mime::Mime>().is_ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let hash = state.store.put_blob(&body).await?;
    sqlx::query(
        "INSERT INTO uploads (account_id, hash, content_type, size, created_at) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(account_id, hash) DO UPDATE SET created_at = excluded.created_at, content_type = excluded.content_type",
    )
    .bind(user.account.id)
    .bind(&hash)
    .bind(&content_type)
    .bind(body.len() as i64)
    .bind(crate::util::now())
    .execute(&state.db)
    .await?;
    let reply = json!({ "accountId": account, "blobId": format!("u{hash}"), "type": content_type, "size": body.len() });
    Ok((StatusCode::CREATED, Json(reply)).into_response())
}

/// Content types that are safe to hand to the browser for inline display. Everything else is
/// served as an opaque download so that user-controlled content can never run in our origin.
const INLINE_TYPES: &[&str] = &["image/png", "image/jpeg", "image/gif", "image/webp"];

async fn download(
    State(state): State<AppState>,
    user: JmapUser,
    Path((account, blob_id, name)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    own_account(&user, &account)?;
    let found = if blob_id.starts_with('s') {
        sieve::load_blob(&state, user.account.id, &blob_id).await.map_err(anyhow::Error::from)?.map(|data| (data, "application/sieve".to_owned()))
    } else {
        email::load_blob(&state, &user.account, &blob_id).await?
    };
    let (data, content_type) = found.ok_or(ApiError::NotFound)?;
    let inline = INLINE_TYPES.contains(&content_type.as_str());
    let safe_name: String = name.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ')).take(150).collect();
    let safe_name = if safe_name.trim_matches(['.', ' ']).is_empty() { "download".to_owned() } else { safe_name };
    let mut response = data.into_response();
    let headers = response.headers_mut();
    let served_type = if inline { content_type.as_str() } else { "application/octet-stream" };
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(served_type).unwrap_or(HeaderValue::from_static("application/octet-stream")));
    let disposition = format!("{}; filename=\"{safe_name}\"", if inline { "inline" } else { "attachment" });
    headers.insert(header::CONTENT_DISPOSITION, HeaderValue::from_str(&disposition).unwrap_or(HeaderValue::from_static("attachment")));
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'none'; sandbox"));
    Ok(response)
}

/// The picture for the sender of a message: a brand logo (BIMI) or a Gravatar, if the message
/// earned one. With `?info` the answer describes the picture instead.
async fn avatar(
    State(state): State<AppState>,
    user: JmapUser,
    Path((account, email_id)): Path<(String, String)>,
    axum::extract::Query(query): axum::extract::Query<crate::api::avatar::AvatarQuery>,
) -> Result<Response, ApiError> {
    own_account(&user, &account)?;
    let ctx = Context { app: &state, account: &user.account, ip: user.ip, created: HashMap::new() };
    let id = parse_id(&email_id, 'm').ok_or(ApiError::NotFound)?;
    let (message, _) = ctx.message(id).await.map_err(|_| ApiError::NotFound)?.ok_or(ApiError::NotFound)?;
    // Only the headers matter here; a message full of attachments is not read in full.
    let raw = state.store.read_blob_head(&message.blob_hash, 128 * 1024).await?;
    let security = crate::security::summary::summarize(&raw, &state.cfg.hostname);
    let found = crate::api::avatar::for_sender(&state, &message.from_addr, &security).await?;
    Ok(crate::api::avatar::respond(found, &query))
}

#[derive(serde::Deserialize)]
struct AvatarsQuery {
    /// Comma separated email ids (`m12,m13`).
    ids: String,
}

/// Most messages answered by one `avatars` request.
const MAX_AVATAR_BATCH: usize = 200;

/// The picture source (`bimi-verified`, `bimi`, `gravatar`, `none`) of each listed message's
/// sender, so the message list asks for the pictures that exist instead of one per row.
async fn avatars(
    State(state): State<AppState>,
    user: JmapUser,
    Path(account): Path<String>,
    axum::extract::Query(query): axum::extract::Query<AvatarsQuery>,
) -> Result<Response, ApiError> {
    own_account(&user, &account)?;
    let ids: Vec<String> = query.ids.split(',').filter(|id| !id.is_empty()).take(MAX_AVATAR_BATCH).map(str::to_owned).collect();
    let ctx = Context { app: &state, account: &user.account, ip: user.ip, created: HashMap::new() };
    let lookups = ids.into_iter().map(|email_id: String| {
        let (ctx, state) = (&ctx, &state);
        async move {
            let source = async {
                let id = parse_id(&email_id, 'm')?;
                let (message, _) = ctx.message(id).await.ok()??;
                let raw = state.store.read_blob_head(&message.blob_hash, 128 * 1024).await.ok()?;
                let security = crate::security::summary::summarize(&raw, &state.cfg.hostname);
                crate::api::avatar::for_sender(state, &message.from_addr, &security).await.ok().map(|found| found.source)
            }
            .await
            .unwrap_or_else(|| "none".to_owned());
            (email_id, Value::String(source))
        }
    });
    // A few at a time: a sender not seen before may need a lookup on the network.
    let found: Map<String, Value> = futures_util::stream::iter(lookups).buffer_unordered(8).collect().await;
    Ok(Json(Value::Object(found)).into_response())
}

async fn event_source(State(state): State<AppState>, user: JmapUser) -> impl IntoResponse {
    let (app, auth) = (state.clone(), user.auth.clone());
    let stream = BroadcastStream::new(state.store.subscribe()).filter_map(move |change| {
        let (state, auth) = (app.clone(), auth.clone());
        async move {
            let account = auth.account(&state).await?;
            // A lagged receiver simply means "something changed"; treat it like any change.
            if let Ok(change) = &change
                && change.account_id != account.id
                && !crate::sharing::mailbox(&state.db, &account, change.mailbox_id).await.ok().flatten().is_some_and(|(_, rights)| rights.contains('r'))
            {
                return None;
            }
            let id = account_id(&account);
            let state_string = state.store.account_state(account.id).await.ok()?.to_string();
            let data = json!({ "@type": "StateChange", "changed": { id: { "Email": state_string, "Mailbox": state_string, "Thread": state_string } } });
            Some(Ok::<_, std::convert::Infallible>(Event::default().event("state").data(data.to_string())))
        }
    });
    Sse::new(crate::api::guard_stream(state, user.auth, stream)).keep_alive(KeepAlive::default())
}

pub fn routes(_state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/.well-known/jmap", get(session_object))
        .route("/jmap/session", get(session_object))
        .route("/jmap/api", post(api).layer(DefaultBodyLimit::max(10 * 1024 * 1024)))
        .route("/jmap/upload/{account}", post(upload))
        .route("/jmap/download/{account}/{blob}/{name}", get(download))
        .route("/jmap/avatar/{account}/{email}", get(avatar))
        .route("/jmap/avatars/{account}", get(avatars))
        .route("/jmap/eventsource", get(event_source))
        .route("/jmap/ws", get(ws::upgrade))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert_eq!(parse_id("m42", 'm'), Some(42));
        assert_eq!(parse_id("b42", 'm'), None);
        assert_eq!(parse_id("m-1", 'm'), None);
        assert_eq!(parse_id("m0", 'm'), None);
        assert_eq!(parse_id("m1 OR 1=1", 'm'), None);
    }

    #[test]
    fn result_references() {
        let responses = vec![
            json!(["Email/query", { "ids": ["m1", "m2"] }, "q"]),
            json!(["Email/get", { "list": [{ "threadId": "t1", "x": ["a"] }, { "threadId": "t2", "x": ["b", "c"] }] }, "g"]),
        ];
        let mut args = json!({ "#ids": { "resultOf": "q", "name": "Email/query", "path": "/ids" }, "keep": 1 }).as_object().unwrap().clone();
        resolve_references(&mut args, &responses, &mut Budget::new()).unwrap();
        assert_eq!(Value::Object(args), json!({ "ids": ["m1", "m2"], "keep": 1 }));

        let mut args = json!({ "#ids": { "resultOf": "g", "name": "Email/get", "path": "/list/*/threadId" } }).as_object().unwrap().clone();
        resolve_references(&mut args, &responses, &mut Budget::new()).unwrap();
        assert_eq!(args["ids"], json!(["t1", "t2"]));

        let mut args = json!({ "#ids": { "resultOf": "g", "name": "Email/get", "path": "/list/*/x" } }).as_object().unwrap().clone();
        resolve_references(&mut args, &responses, &mut Budget::new()).unwrap();
        assert_eq!(args["ids"], json!(["a", "b", "c"]));

        for bad in [
            json!({ "#ids": { "resultOf": "nope", "name": "Email/query", "path": "/ids" } }),
            json!({ "#ids": { "resultOf": "q", "name": "Email/get", "path": "/ids" } }),
            json!({ "#ids": { "resultOf": "q", "name": "Email/query", "path": "/missing" } }),
            json!({ "#ids": "not an object" }),
        ] {
            let mut args = bad.as_object().unwrap().clone();
            assert_eq!(resolve_references(&mut args, &responses, &mut Budget::new()).unwrap_err().0, "invalidResultReference");
        }
    }
}
