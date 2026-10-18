//! Domain management, DKIM keys and DNS diagnostics.

use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{JsonResult, Session};
use crate::{
    app::AppState,
    diagnostics,
    directory,
    error::ApiError,
    security::dkim::{self, Algorithm, DkimKey},
    util::Address,
};

#[derive(Serialize, sqlx::FromRow)]
pub struct DomainView {
    id: i64,
    name: String,
    enabled: bool,
    max_mailboxes: i64,
    default_quota_bytes: i64,
    catch_all: Option<String>,
    /// The MTA-STS policy published for the domain: none, testing or enforce.
    mta_sts_mode: String,
    created_at: i64,
    mailbox_count: i64,
    alias_count: i64,
    used_bytes: i64,
}

const DOMAIN_SELECT: &str = "SELECT d.id, d.name, d.enabled, d.max_mailboxes, d.default_quota_bytes, d.catch_all, d.mta_sts_mode, d.created_at,
        (SELECT COUNT(*) FROM accounts a WHERE a.domain_id = d.id) AS mailbox_count,
        (SELECT COUNT(*) FROM aliases l WHERE l.domain_id = d.id) AS alias_count,
        (SELECT COALESCE(SUM(a.used_bytes), 0) FROM accounts a WHERE a.domain_id = d.id) AS used_bytes
     FROM domains d";

async fn load(state: &AppState, id: i64) -> Result<DomainView, ApiError> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("{DOMAIN_SELECT} WHERE d.id = ?")))
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)
}

pub async fn list(State(state): State<AppState>, session: Session) -> JsonResult<Vec<DomainView>> {
    let managed = session.managed_domains(&state.db).await?;
    let all: Vec<DomainView> =
        sqlx::query_as(sqlx::AssertSqlSafe(format!("{DOMAIN_SELECT} ORDER BY d.name"))).fetch_all(&state.db).await?;
    Ok(Json(match managed {
        None => all,
        Some(ids) => all.into_iter().filter(|d| ids.contains(&d.id)).collect(),
    }))
}

#[derive(Deserialize)]
pub struct CreateDomain {
    name: String,
}

pub async fn create(State(state): State<AppState>, session: Session, Json(req): Json<CreateDomain>) -> JsonResult<DomainView> {
    session.require_super()?;
    let id = directory::create_domain(&state.db, &req.name).await?;
    // Every domain starts with a signing key so that outgoing mail is authenticated from day one.
    dkim::create_key(&state.db, &state.secrets, id, &default_selector(), Algorithm::Rsa).await?;
    directory::ensure_postmaster(&state, id).await?;
    let domain = load(&state, id).await?;
    session.audit(&state, "domain.created", &domain.name, "").await;
    Ok(Json(domain))
}

fn default_selector() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!("uno{}{:02}", now.year(), u8::from(now.month()))
}

pub async fn get(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<DomainView> {
    session.require_domain(&state.db, id).await?;
    Ok(Json(load(&state, id).await?))
}

#[derive(Deserialize)]
pub struct UpdateDomain {
    enabled: Option<bool>,
    max_mailboxes: Option<i64>,
    default_quota_bytes: Option<i64>,
    /// `Some(None)` clears the catch-all address.
    #[serde(default, with = "double_option")]
    catch_all: Option<Option<String>>,
    mta_sts_mode: Option<String>,
}

/// Distinguishes an absent field from an explicit `null`.
pub mod double_option {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, T: Deserialize<'de>, D: Deserializer<'de>>(de: D) -> Result<Option<Option<T>>, D::Error> {
        Option::<T>::deserialize(de).map(Some)
    }
}

pub async fn update(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
    Json(req): Json<UpdateDomain>,
) -> JsonResult<DomainView> {
    session.require_domain(&state.db, id).await?;
    let current = load(&state, id).await?;
    // Limits and the enabled flag constrain domain administrators, so only a super
    // administrator may change them.
    if req.enabled.is_some() || req.max_mailboxes.is_some() {
        session.require_super()?;
    }
    if req.max_mailboxes.is_some_and(|v| v < 0) || req.default_quota_bytes.is_some_and(|v| v < 0) {
        return Err(ApiError::bad("limits must not be negative"));
    }
    let catch_all = match req.catch_all {
        None => current.catch_all.clone(),
        Some(None) => None,
        Some(Some(addr)) if addr.trim().is_empty() => None,
        Some(Some(addr)) => {
            let addr = Address::parse(&addr).ok_or_else(|| ApiError::bad("invalid catch-all address"))?;
            // A catch-all pointing outside the domain would turn every typo into a forward.
            if addr.domain != current.name {
                return Err(ApiError::bad("the catch-all address must belong to this domain"));
            }
            Some(addr.to_string())
        }
    };
    let mta_sts_mode = match req.mta_sts_mode.as_deref() {
        None => current.mta_sts_mode.clone(),
        Some(mode @ ("none" | "testing" | "enforce")) => mode.to_owned(),
        Some(_) => return Err(ApiError::bad("the MTA-STS mode must be none, testing or enforce")),
    };
    sqlx::query("UPDATE domains SET enabled = ?, max_mailboxes = ?, default_quota_bytes = ?, catch_all = ?, mta_sts_mode = ? WHERE id = ?")
        .bind(req.enabled.unwrap_or(current.enabled))
        .bind(req.max_mailboxes.unwrap_or(current.max_mailboxes))
        .bind(req.default_quota_bytes.unwrap_or(current.default_quota_bytes))
        .bind(catch_all)
        .bind(mta_sts_mode)
        .bind(id)
        .execute(&state.db)
        .await?;
    session.audit(&state, "domain.updated", &current.name, "").await;
    Ok(Json(load(&state, id).await?))
}

pub async fn remove(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    session.require_super()?;
    let domain = load(&state, id).await?;
    if session.account.domain_id == id {
        return Err(ApiError::bad("you cannot delete the domain of your own account"));
    }
    sqlx::query("DELETE FROM domains WHERE id = ?").bind(id).execute(&state.db).await?;
    session.audit(&state, "domain.deleted", &domain.name, &format!("{} mailboxes", domain.mailbox_count)).await;
    Ok(Json(json!({ "ok": true })))
}

/// `https://mta-sts.<domain>/.well-known/mta-sts.txt`: the policy of a hosted domain that
/// publishes one (RFC 8461 section 3.2).
pub async fn mta_sts_policy(State(state): State<AppState>, headers: axum::http::HeaderMap) -> axum::response::Response {
    use axum::response::IntoResponse;
    let host = headers.get(axum::http::header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    let host = host.rsplit_once(':').filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit())).map_or(host, |(name, _)| name).to_ascii_lowercase();
    let Some(domain) = host.strip_prefix("mta-sts.") else { return axum::http::StatusCode::NOT_FOUND.into_response() };
    let mode: Option<String> = sqlx::query_scalar("SELECT mta_sts_mode FROM domains WHERE name = ? AND enabled = 1").bind(domain).fetch_optional(&state.db).await.ok().flatten();
    match mode.and_then(|mode| crate::smtp::transport::policy_for_hosted(&mode, &state.cfg.hostname)) {
        Some(policy) => ([(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8"), (axum::http::header::CACHE_CONTROL, "max-age=3600")], policy).into_response(),
        None => axum::http::StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn dns_records(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    session.require_domain(&state.db, id).await?;
    let domain = load(&state, id).await?;
    let keys = dkim::keys_for_domain(&state.db, id).await?;
    let checks = diagnostics::domain_report(&state, &domain.name, &keys, &domain.mta_sts_mode).await;
    Ok(Json(json!({ "domain": domain.name, "checks": checks })))
}

#[derive(Serialize)]
pub struct DkimView {
    #[serde(flatten)]
    key: DkimKey,
    dns_name: String,
    dns_value: String,
}

fn dkim_view(key: DkimKey, domain: &str) -> DkimView {
    DkimView { dns_name: key.dns_name(domain), dns_value: key.dns_value(), key }
}

pub async fn dkim_list(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Vec<DkimView>> {
    session.require_domain(&state.db, id).await?;
    let domain = load(&state, id).await?;
    let keys = dkim::keys_for_domain(&state.db, id).await?;
    Ok(Json(keys.into_iter().map(|k| dkim_view(k, &domain.name)).collect()))
}

#[derive(Deserialize)]
pub struct CreateDkim {
    selector: String,
    #[serde(default)]
    algorithm: Option<String>,
}

pub async fn dkim_create(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
    Json(req): Json<CreateDkim>,
) -> JsonResult<DkimView> {
    session.require_domain(&state.db, id).await?;
    let domain = load(&state, id).await?;
    let selector = req.selector.trim().to_ascii_lowercase();
    if !dkim::is_valid_selector(&selector) {
        return Err(ApiError::bad("selectors may contain lowercase letters, digits and hyphens (max 63 characters)"));
    }
    let algorithm = match req.algorithm.as_deref() {
        None => Algorithm::Rsa,
        Some(name) => Algorithm::parse(name).ok_or_else(|| ApiError::bad("unsupported algorithm"))?,
    };
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dkim_keys WHERE domain_id = ?").bind(id).fetch_one(&state.db).await?;
    if count >= 10 {
        return Err(ApiError::Conflict("a domain can have at most 10 DKIM keys; delete unused ones first".into()));
    }
    let exists: Option<i64> = sqlx::query_scalar("SELECT 1 FROM dkim_keys WHERE domain_id = ? AND selector = ?")
        .bind(id)
        .bind(&selector)
        .fetch_optional(&state.db)
        .await?;
    if exists.is_some() {
        return Err(ApiError::Conflict("a key with this selector already exists".into()));
    }
    let key = dkim::create_key(&state.db, &state.secrets, id, &selector, algorithm).await?;
    session.audit(&state, "dkim.created", &domain.name, &selector).await;
    Ok(Json(dkim_view(key, &domain.name)))
}

#[derive(Deserialize)]
pub struct UpdateDkim {
    active: bool,
}

pub async fn dkim_update(
    State(state): State<AppState>,
    session: Session,
    Path((id, key_id)): Path<(i64, i64)>,
    Json(req): Json<UpdateDkim>,
) -> JsonResult<Value> {
    session.require_domain(&state.db, id).await?;
    let domain = load(&state, id).await?;
    let selector: Option<String> =
        sqlx::query_scalar("UPDATE dkim_keys SET active = ? WHERE id = ? AND domain_id = ? RETURNING selector")
            .bind(req.active)
            .bind(key_id)
            .bind(id)
            .fetch_optional(&state.db)
            .await?;
    let selector = selector.ok_or(ApiError::NotFound)?;
    session.audit(&state, if req.active { "dkim.activated" } else { "dkim.deactivated" }, &domain.name, &selector).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn dkim_delete(State(state): State<AppState>, session: Session, Path((id, key_id)): Path<(i64, i64)>) -> JsonResult<Value> {
    session.require_domain(&state.db, id).await?;
    let domain = load(&state, id).await?;
    let selector: Option<String> = sqlx::query_scalar("DELETE FROM dkim_keys WHERE id = ? AND domain_id = ? RETURNING selector")
        .bind(key_id)
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    let selector = selector.ok_or(ApiError::NotFound)?;
    session.audit(&state, "dkim.deleted", &domain.name, &selector).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn admins_list(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Vec<String>> {
    session.require_super()?;
    load(&state, id).await?;
    let admins = sqlx::query_scalar(
        "SELECT a.email FROM domain_admins da JOIN accounts a ON a.id = da.account_id WHERE da.domain_id = ? ORDER BY a.email",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(admins))
}

#[derive(Deserialize)]
pub struct SetAdmins {
    emails: Vec<String>,
}

/// Replaces the set of delegated administrators of a domain.
pub async fn admins_set(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
    Json(req): Json<SetAdmins>,
) -> JsonResult<Vec<String>> {
    session.require_super()?;
    let domain = load(&state, id).await?;
    if req.emails.len() > 100 {
        return Err(ApiError::bad("too many administrators"));
    }
    let mut tx = state.db.begin().await?;
    let mut ids = Vec::new();
    for email in &req.emails {
        let row: Option<(i64, String)> = sqlx::query_as("SELECT id, role FROM accounts WHERE email = ?")
            .bind(email.trim().to_ascii_lowercase())
            .fetch_optional(&mut *tx)
            .await?;
        let (account_id, role) = row.ok_or_else(|| ApiError::bad(format!("unknown account: {}", crate::util::sanitize_line(email))))?;
        if role == "user" {
            // Delegation implies the role; promote explicitly so the two never disagree.
            sqlx::query("UPDATE accounts SET role = 'domain_admin' WHERE id = ?").bind(account_id).execute(&mut *tx).await?;
        }
        ids.push(account_id);
    }
    sqlx::query("DELETE FROM domain_admins WHERE domain_id = ?").bind(id).execute(&mut *tx).await?;
    for account_id in &ids {
        sqlx::query("INSERT OR IGNORE INTO domain_admins (account_id, domain_id) VALUES (?, ?)")
            .bind(account_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    // Domain administrators left without any domain revert to ordinary users.
    sqlx::query(
        "UPDATE accounts SET role = 'user' WHERE role = 'domain_admin' AND id NOT IN (SELECT account_id FROM domain_admins)",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    session.audit(&state, "domain.admins_changed", &domain.name, &req.emails.join(",")).await;
    admins_list(State(state), session, Path(id)).await
}
