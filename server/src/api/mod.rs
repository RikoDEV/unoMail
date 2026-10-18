//! HTTP API: routing, session handling, CSRF protection and security headers.

use std::net::{IpAddr, SocketAddr};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequestParts, Request, State},
    http::{HeaderName, HeaderValue, Method, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, delete, get, patch, post, put},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Serialize;
use sqlx::SqlitePool;
use tower_http::services::{ServeDir, ServeFile};

use crate::{
    app::{AppState, Metrics},
    auth::{Account, Role},
    error::{ApiError, ApiResult},
    util::{ct_eq, sha256_hex},
};

pub mod access;
pub mod accounts;
pub mod admin;
pub mod aliases;
pub mod auth;
pub mod domains;
pub mod extend;
pub mod mailboxes;
pub mod avatar;
pub mod calendar;
pub mod signin;
pub mod smime;
pub mod snooze;
pub mod storage;
pub mod lists;
pub mod mailtools;
pub mod me;
pub mod oauth;
pub mod openapi;
pub mod personal;
pub mod spamfilter;
pub mod system;
pub mod tls;

pub const CSRF_HEADER: &str = "x-csrf-token";
/// Default request body limit; endpoints that accept messages raise it explicitly.
const BODY_LIMIT: usize = 1024 * 1024;

/// Address of the directly connected peer, attached to every request by the HTTP server.
#[derive(Debug, Clone, Copy)]
pub struct PeerAddr(pub SocketAddr);

/// The client's address, taking `X-Forwarded-For` into account only when the request arrives
/// from a configured trusted proxy.
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub IpAddr);

fn client_ip(parts: &Parts, state: &AppState) -> IpAddr {
    let peer = parts.extensions.get::<PeerAddr>().map_or(IpAddr::from([0, 0, 0, 0]), |p| p.0.ip());
    let trusted = |ip: &IpAddr| state.cfg.trusted_proxies.iter().any(|net| net.contains(ip));
    if !trusted(&peer) {
        return peer;
    }
    let values: Vec<&str> = parts.headers.get_all("x-forwarded-for").iter().map(|v| v.to_str().unwrap_or("?")).collect();
    forwarded_client(peer, &values, trusted)
}

/// The client named by `X-Forwarded-For` values that a trusted proxy (`peer`) passed on.
///
/// The chain is walked right to left; the first address that is not one of our proxies is the
/// client. Anything further left was supplied by the client itself and cannot be trusted, so
/// an entry that cannot be read ends the walk at the last proxy rather than being skipped.
pub fn forwarded_client(peer: IpAddr, values: &[&str], trusted: impl Fn(&IpAddr) -> bool) -> IpAddr {
    let mut last = peer;
    for entry in values.iter().flat_map(|v| v.split(',')).collect::<Vec<_>>().into_iter().rev() {
        let Some(ip) = forwarded_address(entry.trim()) else { return last };
        if !trusted(&ip) {
            return ip;
        }
        last = ip;
    }
    last
}

/// An address as proxies write it: `192.0.2.1`, `192.0.2.1:4711`, `2001:db8::1`, `[2001:db8::1]`
/// or `[2001:db8::1]:4711`.
fn forwarded_address(entry: &str) -> Option<IpAddr> {
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(socket) = entry.parse::<std::net::SocketAddr>() {
        return Some(socket.ip());
    }
    entry.strip_prefix('[')?.strip_suffix(']')?.parse().ok()
}

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(client_ip(parts, state)))
    }
}

pub fn cookie_name(state: &AppState) -> &'static str {
    // The __Host- prefix makes browsers refuse the cookie unless it is Secure, host-only and
    // scoped to "/", which rules out injection from sibling subdomains.
    if state.cfg.cookie_secure { "__Host-unomail" } else { "unomail" }
}

/// The cookie holding the browser's other signed-in sessions (the account switcher).
pub fn others_cookie_name(state: &AppState) -> &'static str {
    if state.cfg.cookie_secure { "__Host-unomail-more" } else { "unomail-more" }
}

pub fn others_cookie(state: &AppState, tokens: &[String], max_age_secs: i64) -> Cookie<'static> {
    Cookie::build((others_cookie_name(state), tokens.join(".")))
        .path("/")
        .http_only(true)
        .secure(state.cfg.cookie_secure)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::seconds(if tokens.is_empty() { 0 } else { max_age_secs }))
        .build()
}

pub fn session_cookie(state: &AppState, token: String, max_age_secs: i64) -> Cookie<'static> {
    Cookie::build((cookie_name(state), token))
        .path("/")
        .http_only(true)
        .secure(state.cfg.cookie_secure)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::seconds(max_age_secs))
        .build()
}

/// An authenticated browser session.
#[derive(Debug, Clone)]
pub struct Session {
    pub account: Account,
    pub csrf_token: String,
    pub token_hash: String,
    pub ip: IpAddr,
}

/// Authentication provenance for connections that outlive an HTTP request.
#[derive(Clone)]
pub enum LiveAuth {
    Session(String),
    Credential(crate::auth::Grant, i64),
}

impl LiveAuth {
    /// The credential, as recorded with what it schedules (see `email_submissions.origin`).
    pub fn origin(&self) -> String {
        match self {
            Self::Session(hash) => format!("session:{hash}"),
            Self::Credential(grant, _) => grant.origin(),
        }
    }

    pub async fn account(&self, state: &AppState) -> Option<Account> {
        match self {
            Self::Session(hash) => Account::by_session(&state.db, hash).await.ok().flatten().map(|(account, _)| account),
            Self::Credential(grant, id) if grant.valid(state).await => Account::by_id(&state.db, *id).await.ok().flatten(),
            _ => None,
        }
    }
}

/// End idle streams too, rather than waiting for the next event after revocation.
pub fn guard_stream<S, T>(state: AppState, auth: LiveAuth, stream: S) -> impl futures_util::Stream<Item = T>
where S: futures_util::Stream<Item = T> + Send + 'static, T: Send + 'static {
    use futures_util::StreamExt;
    let ticks = tokio::time::interval(crate::auth::RECHECK_INTERVAL);
    futures_util::stream::unfold((state, auth, Box::pin(stream), ticks), |(state, auth, mut stream, mut ticks)| async move {
        loop {
            tokio::select! {
                _ = ticks.tick() => { auth.account(&state).await?; }
                item = stream.next() => {
                    let item = item?;
                    auth.account(&state).await?;
                    return Some((item, (state, auth, stream, ticks)));
                }
            }
        }
    })
}

impl FromRequestParts<AppState> for Session {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar.get(cookie_name(state)).map(|c| c.value().to_owned()).ok_or(ApiError::Unauthorized)?;
        let token_hash = sha256_hex(token.as_bytes());
        let (account, csrf_token) = Account::by_session(&state.db, &token_hash).await?.ok_or(ApiError::Unauthorized)?;

        // Cookies are sent automatically by browsers; state-changing requests must also prove
        // they come from our own front-end by echoing the per-session token.
        if !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS) {
            let supplied = parts.headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("");
            if !ct_eq(supplied.as_bytes(), csrf_token.as_bytes()) {
                return Err(ApiError::Forbidden);
            }
        }
        Ok(Session { account, csrf_token, token_hash, ip: client_ip(parts, state) })
    }
}

impl Session {
    pub fn is_super(&self) -> bool {
        self.account.role == Role::SuperAdmin
    }

    pub fn require_super(&self) -> ApiResult<()> {
        if self.is_super() { Ok(()) } else { Err(ApiError::Forbidden) }
    }

    /// Requires any administrative role.
    pub fn require_admin(&self) -> ApiResult<()> {
        if self.account.role == Role::User { Err(ApiError::Forbidden) } else { Ok(()) }
    }

    /// Domains this session may administer. `None` means all of them.
    pub async fn managed_domains(&self, db: &SqlitePool) -> ApiResult<Option<Vec<i64>>> {
        match self.account.role {
            Role::SuperAdmin => Ok(None),
            Role::DomainAdmin => Ok(Some(
                sqlx::query_scalar("SELECT domain_id FROM domain_admins WHERE account_id = ?")
                    .bind(self.account.id)
                    .fetch_all(db)
                    .await?,
            )),
            Role::User => Err(ApiError::Forbidden),
        }
    }

    pub async fn require_domain(&self, db: &SqlitePool, domain_id: i64) -> ApiResult<()> {
        match self.managed_domains(db).await? {
            None => Ok(()),
            Some(ids) if ids.contains(&domain_id) => Ok(()),
            // Not found rather than forbidden: do not reveal which domains exist.
            Some(_) => Err(ApiError::NotFound),
        }
    }

    pub async fn audit(&self, state: &AppState, action: &str, target: &str, detail: &str) {
        crate::db::audit(&state.db, &self.account.email, action, target, &self.ip.to_string(), detail).await;
    }
}

#[derive(Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: i64,
}

pub fn clamp_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(50).clamp(1, 500)
}

/// Escapes `%`, `_` and `\` so user input can be used inside a `LIKE ... ESCAPE '\'` pattern.
pub fn like_pattern(query: &str) -> String {
    let mut out = String::with_capacity(query.len() + 2);
    out.push('%');
    for c in query.chars().take(200) {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

async fn security_headers(State(state): State<AppState>, request: Request, next: Next) -> Response {
    Metrics::inc(&state.metrics.http_requests);
    let path = request.uri().path();
    // Responses carrying personal data or one-time tokens: the API, calendars and contacts
    // (DAV), the mailing-list confirmation pages and the mail-client setup files.
    let private = [
        "/api/",
        "/jmap/",
        "/dav",
        "/.well-known/caldav",
        "/.well-known/carddav",
        "/lists/",
        "/email.mobileconfig",
        "/mail/config-v1.1.xml",
        "/.well-known/autoconfig/",
        "/autodiscover/",
        "/Autodiscover/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix));
    let asset = path.starts_with("/assets/");
    // Traced by route, not by path: ids in paths would make every request its own kind.
    let route = request.extensions().get::<axum::extract::MatchedPath>().map_or("other", |p| p.as_str()).to_owned();
    let span = tracing::info_span!("http.request", http.request.method = %request.method(), http.route = %route, http.response.status_code = tracing::field::Empty);
    let started = std::time::Instant::now();
    let mut response = tracing::Instrument::instrument(next.run(request), span.clone()).await;
    state.metrics.http_duration.observe(started.elapsed());
    span.record("http.response.status_code", response.status().as_u16());
    let headers = response.headers_mut();
    let cached = headers.contains_key("cache-control");
    let mut set = |name: &'static str, value: &'static str| {
        headers.insert(HeaderName::from_static(name), HeaderValue::from_static(value));
    };
    set("x-content-type-options", "nosniff");
    set("x-frame-options", "DENY");
    set("referrer-policy", "no-referrer");
    set("cross-origin-opener-policy", "same-origin");
    set("cross-origin-resource-policy", "same-origin");
    set("x-permitted-cross-domain-policies", "none");
    set(
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), hid=(), bluetooth=(), midi=(), \
         display-capture=(), accelerometer=(), gyroscope=(), magnetometer=(), browsing-topics=()",
    );
    set("strict-transport-security", "max-age=63072000; includeSubDomains");
    // Inline styles are required by the UI toolkit; scripts are restricted to our own origin.
    // Message bodies are rendered in a sandboxed frame and may only load inline/attached images.
    if private {
        // Never let intermediaries or the browser cache these.
        set("cache-control", "no-store");
    } else if !cached {
        // Built assets carry a content hash in their name; everything else (index.html,
        // the service worker) must be revalidated so an upgrade reaches the browser.
        set("cache-control", if asset { "public, max-age=31536000, immutable" } else { "no-cache" });
    }
    // Handlers serving user-controlled content (downloads, proxied images) set a stricter
    // policy of their own, which must not be replaced by the application's.
    if !headers.contains_key("content-security-policy") {
        headers.insert(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; \
                 font-src 'self' data:; connect-src 'self'; frame-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'self'; \
                 form-action 'self'; frame-ancestors 'none'",
            ),
        );
    }
    response
}

/// Bounds reads before extractors buffer a body. The deadline covers the entire
/// body, not just the gap between successive chunks (slow trickle uploads).
async fn request_limits(mut request: Request, next: Next) -> Response {
    use futures_util::StreamExt;
    static REQUESTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(256);
    // Only body-heavy endpoints share the small pool; /jmap/api has its own per-account slot.
    static LARGE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);
    let Ok(_request) = REQUESTS.try_acquire() else { return StatusCode::TOO_MANY_REQUESTS.into_response() };
    // Mailbox imports take bodies of up to 256 MiB, held in memory while they are stored.
    static IMPORTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
    let import = request.uri().path().ends_with("/import");
    let large = request.uri().path().starts_with("/jmap/upload/") || import;
    let _large = if large {
        match LARGE.try_acquire() { Ok(permit) => Some(permit), Err(_) => return StatusCode::TOO_MANY_REQUESTS.into_response() }
    } else { None };
    let _import = if import {
        match IMPORTS.try_acquire() { Ok(permit) => Some(permit), Err(_) => return StatusCode::TOO_MANY_REQUESTS.into_response() }
    } else { None };
    let body = std::mem::replace(request.body_mut(), axum::body::Body::empty());
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    let stream = futures_util::stream::unfold((body.into_data_stream(), false), move |(mut stream, done)| async move {
        if done { return None; }
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Ok(Some(chunk)) => Some((chunk.map_err(std::io::Error::other), (stream, false))),
            Ok(None) => None,
            Err(_) => Some((Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "request body deadline exceeded")), (stream, true))),
        }
    });
    *request.body_mut() = axum::body::Body::from_stream(stream);
    next.run(request).await
}

async fn not_found() -> ApiError {
    ApiError::NotFound
}

async fn acme_challenge(State(state): State<AppState>, axum::extract::Path(token): axum::extract::Path<String>) -> Response {
    match state.tls.http_challenges.lock().get(&token) {
        Some(key_authorization) => ([(header::CONTENT_TYPE, "text/plain")], key_authorization.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/accounts", get(auth::accounts))
        .route("/auth/switch", post(auth::switch))
        .route("/auth/me", get(auth::me))
        .route("/auth/oauth", get(oauth::info))
        .route("/auth/oauth/start", get(oauth::start))
        .route("/auth/oauth/callback", get(oauth::callback))
        .route("/auth/oauth/result", get(oauth::result))
        .route("/oauth", get(oauth::config_get).put(oauth::config_put))
        .route("/auth/password", post(auth::change_password))
        .route("/auth/second-factor", post(signin::second_factor))
        .route("/auth/second-factor/passkey", post(signin::passkey_retry))
        .route("/auth/passkey", get(signin::passkey_login_options).post(signin::passkey_login))
        .route("/me/two-factor", get(signin::overview))
        .route("/me/two-factor/totp", post(signin::totp_setup).put(signin::totp_enable).delete(signin::totp_disable))
        .route("/me/two-factor/recovery-codes", post(signin::recovery_codes))
        .route("/me/passkeys/register/options", post(signin::passkey_start))
        .route("/me/passkeys/register", post(signin::passkey_finish))
        .route("/me/passkeys/{id}", delete(signin::passkey_delete).patch(signin::passkey_rename))
        .route("/me/app-passwords", get(signin::app_passwords).post(signin::app_password_create))
        .route("/me/app-passwords/{id}", delete(signin::app_password_delete))
        .route("/me/pgp/encryption", get(storage::encryption).put(storage::encryption_set))
        .route("/accounts/{id}/two-factor", get(signin::admin_status).delete(signin::admin_reset))
        .route("/auth/sessions", get(auth::sessions).delete(auth::revoke_other_sessions))
        .route("/domains", get(domains::list).post(domains::create))
        .route("/domains/{id}", get(domains::get).patch(domains::update).delete(domains::remove))
        .route("/domains/{id}/dns", get(domains::dns_records))
        .route("/domains/{id}/dkim", get(domains::dkim_list).post(domains::dkim_create))
        .route("/domains/{id}/dkim/{key_id}", patch(domains::dkim_update).delete(domains::dkim_delete))
        .route("/domains/{id}/admins", get(domains::admins_list).put(domains::admins_set))
        .route("/accounts", get(accounts::list).post(accounts::create))
        .route("/accounts/{id}", get(accounts::get).patch(accounts::update).delete(accounts::remove))
        .route("/aliases", get(aliases::list).post(aliases::create))
        .route("/aliases/{id}", patch(aliases::update).delete(aliases::remove))
        .route("/lists", get(lists::list).post(lists::create))
        .route("/lists/{id}", get(lists::get_one).patch(lists::update).delete(lists::remove))
        .route("/lists/{id}/members", get(lists::members).post(lists::add_members))
        .route("/lists/{id}/members/{member}", patch(lists::update_member).delete(lists::remove_member))
        .route("/lists/{id}/held", get(lists::held))
        .route("/lists/{id}/held/{token}", post(lists::decide))
        .route("/tls", get(tls::status))
        .route("/tls/validate", post(tls::validate))
        .route("/tls/custom", put(tls::install_custom))
        .route("/tls/self-signed", post(tls::self_signed))
        .route("/tls/acme", put(tls::configure_acme).delete(tls::disable_acme))
        .route("/tls/acme/renew", post(tls::renew_acme))
        .route("/dashboard", get(system::dashboard))
        .route("/dashboard/activity", get(access::activity))
        .route("/dashboard/system", get(access::system_history))
        .route("/dashboard/daily", get(access::daily_stats))
        .route("/smtp-access/rules", get(access::rules_list).post(access::rule_create))
        .route("/smtp-access/rules/{id}", put(access::rule_update).delete(access::rule_delete))
        .route("/smtp-access/karma", get(access::karma_list))
        .route("/smtp-access/karma/{ip}", delete(access::karma_delete))
        .route("/spam-filter", get(spamfilter::overview))
        .route("/spam-filter/thresholds", put(spamfilter::actions_put))
        .route("/spam-filter/rules", put(spamfilter::symbol_put))
        .route("/queue", get(system::queue_list))
        .route("/queue/{id}", delete(system::queue_delete))
        .route("/queue/{id}/retry", post(system::queue_retry))
        .route("/logs/delivery", get(system::delivery_log))
        .route("/logs/audit", get(system::audit_log))
        .route("/logs/system", get(admin::system_log))
        .route("/logs/stream", get(admin::log_stream))
        .route("/settings", get(admin::settings_get).patch(admin::settings_patch))
        .route("/dmarc", get(admin::dmarc_overview))
        .route("/tls-reports", get(admin::tls_reports))
        .route("/backups", get(storage::backups).post(storage::backup_start))
        .route("/dmarc/reports", post(admin::dmarc_upload).layer(DefaultBodyLimit::max(20 * 1024 * 1024)))
        .route("/dmarc/reports/{id}", get(admin::dmarc_report))
        .route("/accounts/{id}/import", get(admin::import_list).post(admin::import_start))
        .route("/me/vacation", get(me::vacation_get).put(me::vacation_put))
        .route("/me/sieve", get(me::sieve_get).put(me::sieve_put).delete(me::sieve_delete))
        .route("/me/sieve/scripts", get(me::sieve_list))
        .route("/sieve/global", get(me::sieve_global_list).put(me::sieve_global_put).delete(me::sieve_global_delete))
        .route("/me/labels", get(me::labels).delete(me::label_delete))
        .route("/me/snoozes", get(snooze::list).post(snooze::snooze))
        .route("/me/smime", get(smime::get).put(smime::import).delete(smime::remove))
        .route("/me/smime/lookup", get(smime::lookup))
        .route("/me/snoozes/{id}", delete(snooze::wake))
        .route("/me/labels/rename", post(me::label_rename))
        .route("/me/identities", get(personal::identities_list).post(personal::identity_create))
        .route("/me/identities/{id}", put(personal::identity_update).delete(personal::identity_delete))
        .route("/me/contacts", get(personal::contacts_list).post(personal::contact_create))
        .route("/me/contacts/suggest", get(personal::contacts_suggest))
        .route("/me/contacts/export", get(personal::contacts_export))
        .route("/me/contacts/import", post(personal::contacts_import))
        .route("/me/contacts/{id}", put(personal::contact_update).delete(personal::contact_delete))
        .route("/me/contact-groups", get(personal::groups_list).post(personal::group_create))
        .route("/me/contact-groups/{id}", put(personal::group_update).delete(personal::group_delete))
        .route("/me/contact-groups/{id}/members", get(personal::group_members_get).put(personal::group_members_put))
        .route("/me/templates", get(personal::templates_list).post(personal::template_create))
        .route("/me/signatures", get(personal::signatures_list).post(personal::signature_create))
        .route("/me/signatures/defaults", put(personal::signature_defaults_put))
        .route("/me/signatures/{id}", put(personal::signature_update).delete(personal::signature_delete))
        .route("/me/templates/{id}", put(personal::template_update).delete(personal::template_delete))
        .route("/me/preferences", get(personal::preferences_get).put(personal::preferences_put))
        .route("/me/startup", get(personal::startup))
        .route("/me/pgp", get(personal::pgp_get).put(personal::pgp_put).delete(personal::pgp_delete))
        .route("/me/pgp/lookup", get(personal::pgp_lookup))
        .route("/me/mailboxes/{id}/export", get(mailboxes::export))
        .route("/me/mailboxes/{id}/import", post(mailboxes::import).layer(DefaultBodyLimit::max(256 * 1024 * 1024)))
        .route("/me/mailboxes/{id}/acl", get(mailboxes::acl_get).put(mailboxes::acl_put))
        .route("/me/image-proxy", get(mailboxes::image_proxy))
        .route("/me/spam-filter", get(mailtools::spam_filter).delete(mailtools::spam_filter_reset))
        .route("/me/blocked-senders", get(mailtools::blocked_list).post(mailtools::blocked_add).delete(mailtools::blocked_remove))
        .route("/me/label-details", get(mailtools::label_details).put(mailtools::label_put))
        .route("/me/categories", get(mailtools::category_counts))
        .route("/me/newest-unread", get(mailtools::newest_unread))
        .route("/me/categories/learning", get(mailtools::category_learning).delete(mailtools::category_learning_reset))
        .route("/me/unsubscribe", post(mailtools::unsubscribe))
        .route("/me/calendars", get(calendar::list).post(calendar::create))
        .route("/me/calendars/events", get(calendar::events))
        .route("/me/calendars/tasks", get(calendar::tasks))
        .route("/me/calendars/reminders", get(calendar::reminders))
        .route("/me/calendars/freebusy", get(calendar::freebusy))
        .route("/me/calendars/invitations/inspect", post(calendar::invitation_inspect))
        .route("/me/calendars/invitations/respond", post(calendar::invitation_respond))
        .route("/me/calendars/{id}", patch(calendar::update).delete(calendar::delete))
        .route("/me/calendars/{id}/shares", get(calendar::shares_get).put(calendar::shares_put))
        .route("/me/calendars/{id}/tasks", post(calendar::task_create))
        .route("/me/calendars/{id}/tasks/{object_id}", put(calendar::task_update))
        .route("/me/calendars/{id}/events", post(calendar::event_create))
        .route("/me/calendars/{id}/events/{object_id}", get(calendar::event).put(calendar::event_update).delete(calendar::event_delete))
        .route("/me/calendars/{id}/export", get(calendar::export))
        .route("/me/calendars/{id}/import", post(calendar::import))
        .route("/ldap", get(extend::ldap_get).put(extend::ldap_put))
        .route("/ldap/test", post(extend::ldap_test))
        .route("/skins", get(extend::skins_get).put(extend::skins_put))
        .route("/plugins", get(extend::plugins_get))
        .route("/plugins/{id}", put(extend::plugin_toggle))
        .route("/plugins/{id}/plugin.js", get(extend::plugin_script))
        .route("/webhooks", get(extend::webhooks_list).post(extend::webhook_create))
        .route("/webhooks/{id}", put(extend::webhook_update).delete(extend::webhook_delete))
        .route("/webhooks/{id}/test", post(extend::webhook_test))
        .route("/openapi.json", get(openapi::serve))
        .route("/diagnostics/server", get(me::server_diagnostics))
        .fallback(not_found);

    let mut router = Router::new()
        .nest("/api", api)
        .merge(crate::jmap::routes(&state))
        .route("/health", get(system::health))
        .route("/metrics", get(system::metrics))
        .route("/.well-known/acme-challenge/{token}", get(acme_challenge))
        // Mail client auto-configuration (Thunderbird, Outlook, Apple Mail).
        .route("/mail/config-v1.1.xml", get(me::thunderbird))
        .route("/.well-known/autoconfig/mail/config-v1.1.xml", get(me::thunderbird))
        .route("/autodiscover/autodiscover.xml", post(me::outlook))
        .route("/Autodiscover/Autodiscover.xml", post(me::outlook))
        .route("/email.mobileconfig", get(me::apple))
        // Calendars and contacts for other programs. WebDAV uses its own methods, hence the catch-all.
        .route("/.well-known/mta-sts.txt", get(domains::mta_sts_policy))
        // Links that mailing lists send out.
        .route("/lists/confirm/{token}", get(lists::confirm_page).post(lists::confirm_post))
        .route("/lists/moderate/{token}", get(lists::moderate_page).post(lists::moderate_post))
        .route("/lists/unsubscribe/{token}", get(lists::unsubscribe_page).post(lists::unsubscribe_post))
        .route("/.well-known/caldav", any(crate::calendar::dav::well_known))
        .route("/.well-known/carddav", any(crate::calendar::dav::well_known))
        .route("/dav", any(crate::calendar::dav::serve))
        .route("/dav/", any(crate::calendar::dav::serve))
        .route("/dav/{*path}", any(crate::calendar::dav::serve));

    router = match &state.cfg.web_dir {
        Some(dir) => {
            let index = ServeFile::new(dir.join("index.html")).precompressed_br().precompressed_gzip();
            let files = ServeDir::new(dir).precompressed_br().precompressed_gzip().append_index_html_on_directories(true);
            router.fallback_service(files.fallback(index))
        }
        None => router.fallback(not_found),
    };

    router
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(middleware::from_fn(request_limits))
        .layer(middleware::from_fn_with_state(state.clone(), security_headers))
        .with_state(state)
}

/// Whether `host` is a name this server answers for.
async fn served_name(state: &AppState, host: &str) -> bool {
    if host.eq_ignore_ascii_case(&state.cfg.hostname) {
        return true;
    }
    let parent = host.split_once('.').map(|(_, rest)| rest);
    for domain in std::iter::once(host).chain(parent) {
        if crate::smtp::delivery::is_local_domain(state, domain).await.unwrap_or(false) {
            return true;
        }
    }
    false
}

/// Redirects everything except ACME challenges to HTTPS.
pub fn redirect_router(state: AppState) -> Router {
    async fn redirect(State(state): State<AppState>, request: Request) -> Response {
        let claimed = request
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.rsplit_once(':').map_or(h, |(name, _)| name).to_ascii_lowercase())
            .filter(|h| crate::util::is_valid_domain(h));
        // The Host header is the client's to write: redirect only to names this server answers
        // for (its own, a hosted domain or a name under one), never to someone else's site.
        let host = match claimed {
            Some(host) if served_name(&state, &host).await => host,
            _ => state.cfg.hostname.clone(),
        };
        let port = if state.cfg.public_https_port == 443 { String::new() } else { format!(":{}", state.cfg.public_https_port) };
        let path = request.uri().path_and_query().map_or("/", |p| p.as_str());
        match HeaderValue::from_str(&format!("https://{host}{port}{path}")) {
            Ok(location) => (StatusCode::PERMANENT_REDIRECT, [(header::LOCATION, location)]).into_response(),
            Err(_) => StatusCode::BAD_REQUEST.into_response(),
        }
    }
    Router::new()
        .route("/.well-known/acme-challenge/{token}", get(acme_challenge))
        .route("/health", get(system::health))
        .fallback(redirect)
        .with_state(state)
}

pub type JsonResult<T> = ApiResult<Json<T>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_is_the_first_untrusted_hop_from_the_right() {
        let proxy: IpAddr = "10.0.0.2".parse().unwrap();
        let trusted = |ip: &IpAddr| ip.to_string().starts_with("10.");
        let client = |values: &[&str]| forwarded_client(proxy, values, trusted).to_string();
        assert_eq!(client(&["203.0.113.9"]), "203.0.113.9");
        assert_eq!(client(&["6.6.6.6, 203.0.113.9"]), "203.0.113.9", "what the client wrote itself is ignored");
        assert_eq!(client(&["6.6.6.6", "203.0.113.9, 10.0.0.7"]), "203.0.113.9");
        assert_eq!(client(&["6.6.6.6, 203.0.113.9:4711"]), "203.0.113.9", "a port does not hide the real entry");
        assert_eq!(client(&["6.6.6.6, [2001:db8::5]:4711"]), "2001:db8::5");
        assert_eq!(client(&["6.6.6.6, [2001:db8::5]"]), "2001:db8::5");
        assert_eq!(client(&["6.6.6.6, unknown"]), "10.0.0.2", "an unreadable entry ends the walk");
        assert_eq!(client(&["6.6.6.6, garbage, 10.0.0.7"]), "10.0.0.7");
        assert_eq!(client(&[]), "10.0.0.2");
    }

    #[test]
    fn like_patterns_escape_wildcards() {
        assert_eq!(like_pattern("50%_off\\"), "%50\\%\\_off\\\\%");
        assert_eq!(like_pattern(""), "%%");
    }

    #[test]
    fn limits_are_clamped() {
        assert_eq!(clamp_limit(None), 50);
        assert_eq!(clamp_limit(Some(0)), 1);
        assert_eq!(clamp_limit(Some(100_000)), 500);
    }
}
