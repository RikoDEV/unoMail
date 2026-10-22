//! Login, logout and password management.

use axum::{Json, extract::State, http::HeaderMap};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{ClientIp, JsonResult, Session, cookie_name, others_cookie, others_cookie_name, session_cookie};
use crate::{
    app::{AppState, Metrics},
    auth::{self, Account, AuthError, Protocol},
    error::ApiError,
    util::{now, random_token, sanitize_line, sha256_hex},
};

const MAX_SESSIONS_PER_ACCOUNT: i64 = 20;
/// Accounts one browser can be signed in to at the same time.
pub const MAX_ACCOUNTS: usize = 5;

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
    /// The answer to the captcha, when one is set up.
    #[serde(default)]
    captcha: Option<String>,
}

#[derive(Serialize)]
pub struct AccountView {
    pub id: i64,
    pub email: String,
    pub display_name: String,
    pub role: auth::Role,
    pub quota_bytes: i64,
    pub used_bytes: i64,
}

impl From<&Account> for AccountView {
    fn from(a: &Account) -> Self {
        AccountView {
            id: a.id,
            email: a.email.clone(),
            display_name: a.display_name.clone(),
            role: a.role,
            quota_bytes: a.quota_bytes,
            used_bytes: a.used_bytes,
        }
    }
}

pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<Value>), ApiError> {
    // Before the password: unsolved captchas neither reach nor count toward the login limits.
    if !crate::captcha::verify(&state, req.captcha.as_deref(), ip).await {
        return Err(ApiError::bad("captcha"));
    }
    let account = match auth::authenticate(&state.db, &state.limiter, &req.email, &req.password, ip, Protocol::Web).await {
        Ok(account) => account,
        Err(AuthError::Invalid) => {
            Metrics::inc(&state.metrics.auth_failures);
            return Err(ApiError::InvalidCredentials);
        }
        Err(AuthError::RateLimited) => return Err(ApiError::RateLimited),
        Err(AuthError::Internal) => return Err(ApiError::Internal(anyhow::anyhow!("authentication backend failure"))),
    };

    // A second factor set up: the password alone does not sign in.
    if let Some(second) = super::signin::begin(&state, &account, ip).await? {
        crate::db::audit(&state.db, &account.email, "login.password_ok", "web", &ip.to_string(), "second factor pending").await;
        return Ok((jar, Json(json!({ "second_factor": second }))));
    }
    let (token, csrf_token) = start_session(&state, &account, ip, &headers).await?;
    crate::db::audit(&state.db, &account.email, "login.success", "web", &ip.to_string(), "").await;
    let jar = issue_session(&state, jar, token, &account).await?;
    Ok((jar, Json(json!({ "account": AccountView::from(&account), "csrf_token": csrf_token }))))
}

/// The browser's other signed-in session tokens, as stored in its cookie.
fn other_tokens(state: &AppState, jar: &CookieJar) -> Vec<String> {
    jar.get(others_cookie_name(state))
        .map(|c| c.value().split('.').filter(|t| t.len() == 43 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')).take(MAX_ACCOUNTS).map(str::to_owned).collect())
        .unwrap_or_default()
}

async fn account_of(state: &AppState, token: &str) -> sqlx::Result<Option<Account>> {
    Ok(Account::by_session(&state.db, &sha256_hex(token.as_bytes())).await?.map(|(account, _)| account))
}

async fn end_session(state: &AppState, token: &str) {
    let _ = sqlx::query("DELETE FROM sessions WHERE token_hash = ?").bind(sha256_hex(token.as_bytes())).execute(&state.db).await;
}

/// Makes `token` the browser's session for `account`. The session the browser had stays
/// signed in among its others (account switcher); a second session for the same account
/// replaces the first, and beyond `MAX_ACCOUNTS` the oldest is signed out.
pub async fn issue_session(state: &AppState, jar: CookieJar, token: String, account: &Account) -> Result<CookieJar, ApiError> {
    let mut others = other_tokens(state, &jar);
    if let Some(previous) = jar.get(cookie_name(state)).map(|c| c.value().to_owned()) {
        others.insert(0, previous);
    }
    let mut kept: Vec<String> = Vec::new();
    let mut seen = vec![account.id];
    for other in others {
        match account_of(state, &other).await? {
            Some(signed_in) if !seen.contains(&signed_in.id) && kept.len() + 1 < MAX_ACCOUNTS => {
                seen.push(signed_in.id);
                kept.push(other);
            }
            // The same account twice, or one too many: that session ends.
            Some(_) => end_session(state, &other).await,
            None => {}
        }
    }
    let had_others = jar.get(others_cookie_name(state)).is_some();
    let jar = jar.add(session_cookie(state, token, state.cfg.session_ttl_secs));
    // The second cookie only once the browser holds more than one account.
    Ok(if kept.is_empty() && !had_others { jar } else { jar.add(others_cookie(state, &kept, state.cfg.session_ttl_secs)) })
}

/// Every account this browser is signed in to, the current one first.
pub async fn accounts(State(state): State<AppState>, session: Session, jar: CookieJar) -> Result<(CookieJar, Json<Value>), ApiError> {
    let unread = |id: i64| {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM messages WHERE mailbox_id = (SELECT id FROM mailboxes WHERE account_id = ?1 AND role = 'inbox') AND account_id = ?1 AND seen = 0")
            .bind(id)
            .fetch_one(&state.db)
    };
    let mut list = vec![json!({ "account": AccountView::from(&session.account), "active": true, "unread": unread(session.account.id).await? })];
    let mut kept = Vec::new();
    for token in other_tokens(&state, &jar) {
        if let Some(account) = account_of(&state, &token).await?
            && account.id != session.account.id
        {
            list.push(json!({ "account": AccountView::from(&account), "active": false, "unread": unread(account.id).await? }));
            kept.push(token);
        }
    }
    // Sessions that ended elsewhere (expired, signed out, password changed) drop out.
    let jar = if jar.get(others_cookie_name(&state)).is_some() { jar.add(others_cookie(&state, &kept, state.cfg.session_ttl_secs)) } else { jar };
    Ok((jar, Json(json!({ "accounts": list }))))
}

#[derive(Deserialize)]
pub struct SwitchRequest {
    account_id: i64,
}

/// Makes another signed-in account the current one.
pub async fn switch(State(state): State<AppState>, session: Session, jar: CookieJar, Json(req): Json<SwitchRequest>) -> Result<(CookieJar, Json<Value>), ApiError> {
    let current = jar.get(cookie_name(&state)).map(|c| c.value().to_owned()).ok_or(ApiError::Unauthorized)?;
    let mut others = other_tokens(&state, &jar);
    let mut target = None;
    for (index, token) in others.iter().enumerate() {
        if let Some((account, csrf)) = Account::by_session(&state.db, &sha256_hex(token.as_bytes())).await?
            && account.id == req.account_id
        {
            target = Some((index, account, csrf));
            break;
        }
    }
    let (index, account, csrf_token) = target.ok_or(ApiError::NotFound)?;
    let token = others.remove(index);
    others.insert(0, current);
    session.audit(&state, "login.switched", &account.email, "").await;
    let jar = jar.add(session_cookie(&state, token, state.cfg.session_ttl_secs)).add(others_cookie(&state, &others, state.cfg.session_ttl_secs));
    Ok((jar, Json(json!({ "account": AccountView::from(&account), "csrf_token": csrf_token }))))
}

/// Creates a browser session for `account` and returns its (session token, CSRF token).
pub async fn start_session(state: &AppState, account: &Account, ip: std::net::IpAddr, headers: &HeaderMap) -> Result<(String, String), ApiError> {
    // A fresh token on every login: an attacker cannot fixate a session identifier.
    let token = random_token();
    let csrf_token = random_token();
    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(sanitize_line).unwrap_or_default();
    let now = now();
    sqlx::query("DELETE FROM sessions WHERE expires_at <= ?").bind(now).execute(&state.db).await?;
    sqlx::query("INSERT INTO sessions (token_hash, account_id, csrf_token, created_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(sha256_hex(token.as_bytes()))
        .bind(account.id)
        .bind(&csrf_token)
        .bind(now)
        .bind(now + state.cfg.session_ttl_secs)
        .bind(ip.to_string())
        .bind(user_agent.chars().take(200).collect::<String>())
        .execute(&state.db)
        .await?;
    // Bound the number of concurrent sessions by discarding the oldest ones.
    sqlx::query(
        "DELETE FROM sessions WHERE account_id = ?1 AND token_hash NOT IN (
             SELECT token_hash FROM sessions WHERE account_id = ?1 ORDER BY created_at DESC LIMIT ?2)",
    )
    .bind(account.id)
    .bind(MAX_SESSIONS_PER_ACCOUNT)
    .execute(&state.db)
    .await?;
    Ok((token, csrf_token))
}

#[derive(Deserialize, Default)]
pub struct LogoutRequest {
    /// Sign out of every account this browser is signed in to.
    #[serde(default)]
    all: bool,
}

/// Signs out of the current account. Another account the browser is signed in to (if any)
/// becomes the current one, and is returned; with `all`, every one is signed out.
pub async fn logout(State(state): State<AppState>, session: Session, jar: CookieJar, body: Option<Json<LogoutRequest>>) -> Result<(CookieJar, Json<Value>), ApiError> {
    let all = body.is_some_and(|b| b.all);
    sqlx::query("DELETE FROM sessions WHERE token_hash = ?").bind(&session.token_hash).execute(&state.db).await?;
    session.audit(&state, "logout", "web", if all { "all accounts" } else { "" }).await;
    let mut others = other_tokens(&state, &jar);
    if all {
        for token in &others {
            end_session(&state, token).await;
        }
        others.clear();
    }
    while !others.is_empty() {
        let token = others.remove(0);
        if let Some((account, csrf_token)) = Account::by_session(&state.db, &sha256_hex(token.as_bytes())).await? {
            let jar = jar.add(session_cookie(&state, token, state.cfg.session_ttl_secs)).add(others_cookie(&state, &others, state.cfg.session_ttl_secs));
            return Ok((jar, Json(json!({ "ok": true, "next": { "account": AccountView::from(&account), "csrf_token": csrf_token } }))));
        }
    }
    let had_others = jar.get(others_cookie_name(&state)).is_some();
    let jar = jar.remove(session_cookie(&state, String::new(), 0));
    let jar = if had_others { jar.remove(others_cookie(&state, &[], 0)) } else { jar };
    Ok((jar, Json(json!({ "ok": true, "next": null }))))
}

/// The captcha the sign-in page shows, with a fresh challenge for ALTCHA.
pub async fn captcha(State(state): State<AppState>) -> Json<Value> {
    Json(crate::captcha::widget(&state))
}

pub async fn me(session: Session) -> JsonResult<Value> {
    Ok(Json(json!({ "account": AccountView::from(&session.account), "csrf_token": session.csrf_token })))
}

#[derive(Deserialize)]
pub struct PasswordChange {
    current_password: String,
    new_password: String,
    /// Also revoke every app password (mail, calendar and contacts programs).
    #[serde(default)]
    revoke_app_passwords: bool,
}

pub async fn change_password(State(state): State<AppState>, session: Session, Json(req): Json<PasswordChange>) -> JsonResult<Value> {
    // Re-authenticate through the common path so guessing the current password is rate limited.
    match auth::authenticate(&state.db, &state.limiter, &session.account.email, &req.current_password, session.ip, Protocol::Web).await {
        Ok(_) => {}
        Err(AuthError::RateLimited) => return Err(ApiError::RateLimited),
        Err(_) => return Err(ApiError::InvalidCredentials),
    }
    auth::validate_new_password(&req.new_password).map_err(ApiError::bad)?;
    if req.new_password == req.current_password {
        return Err(ApiError::bad("the new password must differ from the current one"));
    }
    let hash = auth::hash_password(&req.new_password).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE accounts SET password_hash = ? WHERE id = ?").bind(hash).bind(session.account.id).execute(&mut *tx).await?;
    // Anyone holding another session (including an attacker) is signed out.
    sqlx::query("DELETE FROM sessions WHERE account_id = ? AND token_hash != ?")
        .bind(session.account.id)
        .bind(&session.token_hash)
        .execute(&mut *tx)
        .await?;
    if req.revoke_app_passwords {
        sqlx::query("DELETE FROM app_passwords WHERE account_id = ?").bind(session.account.id).execute(&mut *tx).await?;
    }
    crate::jmap::submission::cancel_revoked(&mut *tx, session.account.id, &session.token_hash, true, req.revoke_app_passwords).await?;
    tx.commit().await?;
    session.audit(&state, "account.password_changed", &session.account.email, if req.revoke_app_passwords { "app passwords revoked" } else { "" }).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct SessionView {
    created_at: i64,
    expires_at: i64,
    ip: String,
    user_agent: String,
    current: bool,
}

pub async fn sessions(State(state): State<AppState>, session: Session) -> JsonResult<Vec<SessionView>> {
    let rows = sqlx::query_as(
        "SELECT created_at, expires_at, ip, user_agent, token_hash = ? AS current FROM sessions
         WHERE account_id = ? AND expires_at > ? ORDER BY created_at DESC",
    )
    .bind(&session.token_hash)
    .bind(session.account.id)
    .bind(now())
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}

pub async fn revoke_other_sessions(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let revoked = sqlx::query("DELETE FROM sessions WHERE account_id = ? AND token_hash != ?")
        .bind(session.account.id)
        .bind(&session.token_hash)
        .execute(&state.db)
        .await?
        .rows_affected();
    crate::jmap::submission::cancel_revoked(&state.db, session.account.id, &session.token_hash, false, false).await?;
    session.audit(&state, "sessions.revoked", &session.account.email, &revoked.to_string()).await;
    Ok(Json(json!({ "revoked": revoked })))
}
