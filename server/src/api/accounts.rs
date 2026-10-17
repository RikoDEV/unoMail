//! Mailbox (account) management.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{JsonResult, Page, Session, clamp_limit, like_pattern};
use crate::{
    app::AppState,
    auth::{self, Role},
    directory::{self, NewAccount},
    error::{ApiError, ApiResult},
    util::Address,
};

#[derive(Serialize, sqlx::FromRow)]
pub struct AccountRow {
    pub(crate) id: i64,
    domain_id: i64,
    pub(crate) email: String,
    display_name: String,
    role: Role,
    quota_bytes: i64,
    used_bytes: i64,
    enabled: bool,
    imap_enabled: bool,
    pop3_enabled: bool,
    smtp_enabled: bool,
    outbound_blocked: bool,
    outbound_blocked_reason: Option<String>,
    send_only: bool,
    /// Kept by the server (postmaster@): cannot be deleted.
    system: bool,
    created_at: i64,
}

const SELECT: &str = "SELECT id, domain_id, email, display_name, role, quota_bytes, used_bytes, enabled, imap_enabled, \
     pop3_enabled, smtp_enabled, outbound_blocked, outbound_blocked_reason, send_only, system, created_at FROM accounts";

async fn load(state: &AppState, id: i64) -> ApiResult<AccountRow> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} WHERE id = ?")))
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)
}

/// Loads an account the session is allowed to administer.
///
/// Domain administrators manage ordinary mailboxes in their domains only: they can neither
/// see nor modify administrator accounts, which would otherwise be a path to privilege
/// escalation (e.g. resetting a super administrator's password).
pub(crate) async fn load_managed(state: &AppState, session: &Session, id: i64) -> ApiResult<AccountRow> {
    let account = load(state, id).await?;
    session.require_domain(&state.db, account.domain_id).await?;
    if !session.is_super() && account.role != Role::User && account.id != session.account.id {
        return Err(ApiError::NotFound);
    }
    Ok(account)
}

#[derive(Deserialize)]
pub struct ListQuery {
    domain_id: Option<i64>,
    q: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

pub async fn list(State(state): State<AppState>, session: Session, Query(query): Query<ListQuery>) -> JsonResult<Page<AccountRow>> {
    let managed = session.managed_domains(&state.db).await?;
    if let Some(domain_id) = query.domain_id {
        session.require_domain(&state.db, domain_id).await?;
    }
    // The set of visible domains is passed as a JSON array so the statement stays static.
    let scope = serde_json::to_string(&managed.clone().unwrap_or_default()).map_err(anyhow::Error::from)?;
    let filter = "WHERE (?1 = 1 OR domain_id IN (SELECT value FROM json_each(?2)))
                    AND (?3 IS NULL OR domain_id = ?3)
                    AND (email LIKE ?4 ESCAPE '\\' OR display_name LIKE ?4 ESCAPE '\\')
                    AND (?5 = 1 OR role = 'user' OR id = ?6)";
    let pattern = like_pattern(query.q.as_deref().unwrap_or("").trim());
    let all_domains = managed.is_none();

    let total: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM accounts {filter}")))
        .bind(all_domains)
        .bind(&scope)
        .bind(query.domain_id)
        .bind(&pattern)
        .bind(session.is_super())
        .bind(session.account.id)
        .fetch_one(&state.db)
        .await?;
    let items = sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} {filter} ORDER BY email LIMIT ?7 OFFSET ?8")))
        .bind(all_domains)
        .bind(&scope)
        .bind(query.domain_id)
        .bind(&pattern)
        .bind(session.is_super())
        .bind(session.account.id)
        .bind(clamp_limit(query.limit))
        .bind(query.offset.unwrap_or(0).max(0))
        .fetch_all(&state.db)
        .await?;
    Ok(Json(Page { items, total }))
}

#[derive(Deserialize)]
pub struct CreateAccount {
    email: String,
    password: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    role: Option<String>,
    quota_bytes: Option<i64>,
}

pub async fn create(State(state): State<AppState>, session: Session, Json(req): Json<CreateAccount>) -> JsonResult<AccountRow> {
    session.require_admin()?;
    let address = Address::parse_local(&req.email).ok_or_else(|| ApiError::bad("invalid e-mail address"))?;
    let domain_id: i64 = sqlx::query_scalar("SELECT id FROM domains WHERE name = ?")
        .bind(&address.domain)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::bad("domain is not hosted on this server"))?;
    session.require_domain(&state.db, domain_id).await.map_err(|_| ApiError::Forbidden)?;

    let role = match req.role.as_deref() {
        None | Some("user") => Role::User,
        Some(other) => {
            // Only a super administrator can hand out administrative roles.
            session.require_super()?;
            Role::parse(other).ok_or_else(|| ApiError::bad("invalid role"))?
        }
    };
    let account = directory::create_account(
        &state,
        NewAccount { email: &req.email, password: &req.password, display_name: req.display_name.trim(), role, quota_bytes: req.quota_bytes },
    )
    .await?;
    session.audit(&state, "account.created", &account.email, role.as_str()).await;
    Ok(Json(load(&state, account.id).await?))
}

pub async fn get(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<AccountRow> {
    session.require_admin()?;
    Ok(Json(load_managed(&state, &session, id).await?))
}

#[derive(Deserialize)]
pub struct UpdateAccount {
    display_name: Option<String>,
    password: Option<String>,
    role: Option<String>,
    quota_bytes: Option<i64>,
    enabled: Option<bool>,
    imap_enabled: Option<bool>,
    pop3_enabled: Option<bool>,
    smtp_enabled: Option<bool>,
    outbound_blocked: Option<bool>,
    send_only: Option<bool>,
}

pub async fn update(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
    Json(req): Json<UpdateAccount>,
) -> JsonResult<AccountRow> {
    session.require_admin()?;
    let current = load_managed(&state, &session, id).await?;
    let is_self = current.id == session.account.id;

    let role = match req.role.as_deref() {
        None => current.role,
        Some(name) => {
            session.require_super()?;
            let role = Role::parse(name).ok_or_else(|| ApiError::bad("invalid role"))?;
            if is_self && role != current.role {
                return Err(ApiError::bad("you cannot change your own role"));
            }
            role
        }
    };
    if is_self && req.enabled == Some(false) {
        return Err(ApiError::bad("you cannot disable your own account"));
    }
    if is_self && !session.is_super() && (req.quota_bytes.is_some() || req.outbound_blocked.is_some()) {
        return Err(ApiError::Forbidden);
    }
    if req.quota_bytes.is_some_and(|q| q < 0) {
        return Err(ApiError::bad("quota must not be negative"));
    }
    let display_name = req.display_name.as_deref().map(str::trim).unwrap_or(&current.display_name).to_owned();
    if display_name.chars().count() > 200 || display_name.chars().any(|c| c.is_control()) {
        return Err(ApiError::bad("invalid display name"));
    }
    // Changing one's own password asks for the current one (Settings); this path does not.
    if is_self && req.password.is_some() {
        return Err(ApiError::bad("change your own password in your settings, where the current one is asked for"));
    }
    let password_hash = match &req.password {
        Some(password) => {
            auth::validate_new_password(password).map_err(ApiError::bad)?;
            Some(auth::hash_password(password).await?)
        }
        None => None,
    };
    let unblocking = current.outbound_blocked && req.outbound_blocked == Some(false);

    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE accounts SET display_name = ?, role = ?, quota_bytes = ?, enabled = ?, imap_enabled = ?, pop3_enabled = ?,
            smtp_enabled = ?, outbound_blocked = ?, outbound_blocked_reason = CASE WHEN ? THEN outbound_blocked_reason ELSE NULL END,
            send_only = ?, password_hash = COALESCE(?, password_hash)
         WHERE id = ?",
    )
    .bind(&display_name)
    .bind(role)
    .bind(req.quota_bytes.unwrap_or(current.quota_bytes))
    .bind(req.enabled.unwrap_or(current.enabled))
    .bind(req.imap_enabled.unwrap_or(current.imap_enabled))
    .bind(req.pop3_enabled.unwrap_or(current.pop3_enabled))
    .bind(req.smtp_enabled.unwrap_or(current.smtp_enabled))
    .bind(req.outbound_blocked.unwrap_or(current.outbound_blocked))
    .bind(req.outbound_blocked.unwrap_or(current.outbound_blocked))
    .bind(req.send_only.unwrap_or(current.send_only))
    .bind(&password_hash)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    if role != Role::DomainAdmin {
        sqlx::query("DELETE FROM domain_admins WHERE account_id = ?").bind(id).execute(&mut *tx).await?;
    }
    // A password reset or deactivation must end every existing session of that account, and a
    // reset also every app password: whoever took the account over may have made one.
    if password_hash.is_some() || req.enabled == Some(false) {
        sqlx::query("DELETE FROM sessions WHERE account_id = ?").bind(id).execute(&mut *tx).await?;
    }
    if password_hash.is_some() {
        sqlx::query("DELETE FROM app_passwords WHERE account_id = ?").bind(id).execute(&mut *tx).await?;
        crate::jmap::submission::cancel_pending(&mut *tx, id).await?;
    }
    if unblocking {
        // Start with a clean slate, otherwise the next message would trip the limit again.
        sqlx::query("DELETE FROM outbound_stats WHERE account_id = ?").bind(id).execute(&mut *tx).await?;
    }
    tx.commit().await?;

    let mut changes = Vec::new();
    if password_hash.is_some() {
        changes.push("password");
    }
    if role != current.role {
        changes.push("role");
    }
    if req.enabled.is_some_and(|e| e != current.enabled) {
        changes.push(if current.enabled { "disabled" } else { "enabled" });
    }
    if unblocking {
        changes.push("outbound_unblocked");
    }
    session.audit(&state, "account.updated", &current.email, &changes.join(",")).await;
    Ok(Json(load(&state, id).await?))
}

pub async fn remove(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    session.require_admin()?;
    let account = load_managed(&state, &session, id).await?;
    if account.id == session.account.id {
        return Err(ApiError::bad("you cannot delete your own account"));
    }
    if account.system {
        return Err(ApiError::bad("postmaster mailboxes are kept by the server and cannot be deleted"));
    }
    if account.role == Role::SuperAdmin {
        let others: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE role = 'super_admin' AND enabled = 1 AND id != ?")
            .bind(id)
            .fetch_one(&state.db)
            .await?;
        if others == 0 {
            return Err(ApiError::bad("the last super administrator cannot be deleted"));
        }
    }
    sqlx::query("DELETE FROM accounts WHERE id = ?").bind(id).execute(&state.db).await?;
    session.audit(&state, "account.deleted", &account.email, "").await;
    Ok(Json(json!({ "ok": true })))
}
