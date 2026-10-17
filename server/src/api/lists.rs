//! Mailing list administration, and the public pages behind the links lists send out
//! (confirming a subscription, moderating a post, one-click unsubscribe).

use axum::{
    Form, Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{JsonResult, Session};
use crate::{
    app::AppState,
    error::{ApiError, ApiResult},
    lists::{self, List, Member},
    util::{Address, now},
};

async fn load_managed(state: &AppState, session: &Session, id: i64) -> ApiResult<List> {
    let list = lists::load(state, id).await?.ok_or(ApiError::NotFound)?;
    session.require_domain(&state.db, list.domain_id).await?;
    Ok(list)
}

#[derive(Deserialize)]
pub struct ListQuery {
    domain_id: Option<i64>,
}

pub async fn list(State(state): State<AppState>, session: Session, Query(query): Query<ListQuery>) -> JsonResult<Vec<Value>> {
    let managed = session.managed_domains(&state.db).await?;
    let scope = serde_json::to_string(&managed.clone().unwrap_or_default()).map_err(anyhow::Error::from)?;
    let rows: Vec<List> = sqlx::query_as(
        "SELECT * FROM mailing_lists WHERE (?1 = 1 OR domain_id IN (SELECT value FROM json_each(?2))) AND (?3 IS NULL OR domain_id = ?3) ORDER BY address",
    )
    .bind(managed.is_none())
    .bind(scope)
    .bind(query.domain_id)
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let (members, held): (i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM list_members WHERE list_id = ?1), (SELECT COUNT(*) FROM list_pending WHERE list_id = ?1 AND kind = 'post')",
        )
        .bind(row.id)
        .fetch_one(&state.db)
        .await?;
        let mut value = serde_json::to_value(&row).map_err(anyhow::Error::from)?;
        value["members"] = json!(members);
        value["held"] = json!(held);
        out.push(value);
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct ListInput {
    address: Option<String>,
    name: Option<String>,
    description: Option<String>,
    posting: Option<String>,
    subscription: Option<String>,
    reply_to_list: Option<bool>,
    subject_prefix: Option<String>,
    enabled: Option<bool>,
}

fn clean(text: &str, max: usize) -> String {
    text.trim().chars().filter(|c| !c.is_control()).take(max).collect()
}

fn validate(input: &ListInput) -> ApiResult<()> {
    if input.posting.as_deref().is_some_and(|p| !matches!(p, "anyone" | "members" | "moderated" | "announce")) {
        return Err(ApiError::bad("posting must be anyone, members, moderated or announce"));
    }
    if input.subscription.as_deref().is_some_and(|s| !matches!(s, "open" | "closed")) {
        return Err(ApiError::bad("subscription must be open or closed"));
    }
    Ok(())
}

pub async fn create(State(state): State<AppState>, session: Session, Json(input): Json<ListInput>) -> JsonResult<List> {
    session.require_admin()?;
    validate(&input)?;
    let address = input.address.as_deref().and_then(Address::parse_local).ok_or_else(|| ApiError::bad("invalid list address"))?;
    if address.local.contains('+') || ["-request", "-owner", "-bounces"].iter().any(|s| address.local.ends_with(s)) {
        return Err(ApiError::bad("list addresses may not contain '+' or end in -request, -owner or -bounces"));
    }
    let domain_id: i64 = sqlx::query_scalar("SELECT id FROM domains WHERE name = ?").bind(&address.domain).fetch_optional(&state.db).await?.ok_or_else(|| ApiError::bad("domain is not hosted on this server"))?;
    session.require_domain(&state.db, domain_id).await.map_err(|_| ApiError::Forbidden)?;
    // The list and its special addresses must all be free.
    for suffix in ["", "-request", "-owner", "-bounces"] {
        let candidate = format!("{}{suffix}@{}", address.local, address.domain);
        let taken: Option<i64> = sqlx::query_scalar("SELECT 1 FROM accounts WHERE email = ?1 UNION SELECT 1 FROM aliases WHERE source = ?1 UNION SELECT 1 FROM mailing_lists WHERE address = ?1")
            .bind(&candidate)
            .fetch_optional(&state.db)
            .await?;
        if taken.is_some() {
            return Err(ApiError::Conflict(format!("{candidate} is already in use")));
        }
    }
    let name = clean(input.name.as_deref().unwrap_or(&address.local), 100);
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO mailing_lists (domain_id, address, name, description, posting, subscription, reply_to_list, subject_prefix, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(domain_id)
    .bind(address.to_string())
    .bind(if name.is_empty() { address.local.clone() } else { name })
    .bind(clean(input.description.as_deref().unwrap_or(""), 2000))
    .bind(input.posting.as_deref().unwrap_or("members"))
    .bind(input.subscription.as_deref().unwrap_or("closed"))
    .bind(input.reply_to_list.unwrap_or(false))
    .bind(clean(input.subject_prefix.as_deref().unwrap_or(""), 40))
    .bind(now())
    .fetch_one(&state.db)
    .await?;
    session.audit(&state, "list.created", &address.to_string(), "").await;
    Ok(Json(load_managed(&state, &session, id).await?))
}

pub async fn get_one(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<List> {
    session.require_admin()?;
    Ok(Json(load_managed(&state, &session, id).await?))
}

pub async fn update(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<ListInput>) -> JsonResult<List> {
    session.require_admin()?;
    validate(&input)?;
    let list = load_managed(&state, &session, id).await?;
    sqlx::query("UPDATE mailing_lists SET name = ?, description = ?, posting = ?, subscription = ?, reply_to_list = ?, subject_prefix = ?, enabled = ? WHERE id = ?")
        .bind(input.name.as_deref().map(|n| clean(n, 100)).filter(|n| !n.is_empty()).unwrap_or(list.name.clone()))
        .bind(input.description.as_deref().map(|d| clean(d, 2000)).unwrap_or(list.description.clone()))
        .bind(input.posting.unwrap_or(list.posting.clone()))
        .bind(input.subscription.unwrap_or(list.subscription.clone()))
        .bind(input.reply_to_list.unwrap_or(list.reply_to_list))
        .bind(input.subject_prefix.as_deref().map(|p| clean(p, 40)).unwrap_or(list.subject_prefix.clone()))
        .bind(input.enabled.unwrap_or(list.enabled))
        .bind(id)
        .execute(&state.db)
        .await?;
    session.audit(&state, "list.updated", &list.address, "").await;
    Ok(Json(load_managed(&state, &session, id).await?))
}

pub async fn remove(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    session.require_admin()?;
    let list = load_managed(&state, &session, id).await?;
    sqlx::query("DELETE FROM mailing_lists WHERE id = ?").bind(id).execute(&state.db).await?;
    session.audit(&state, "list.deleted", &list.address, "").await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn members(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Vec<Member>> {
    session.require_admin()?;
    load_managed(&state, &session, id).await?;
    Ok(Json(sqlx::query_as("SELECT * FROM list_members WHERE list_id = ? ORDER BY role DESC, email").bind(id).fetch_all(&state.db).await?))
}

#[derive(Deserialize)]
pub struct NewMembers {
    /// Addresses, one per line or separated by commas; `Name <address>` works too.
    addresses: String,
    #[serde(default)]
    role: Option<String>,
}

/// Adds members in bulk. Returns which addresses were added and which were not understood.
pub async fn add_members(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<NewMembers>) -> JsonResult<Value> {
    session.require_admin()?;
    let list = load_managed(&state, &session, id).await?;
    let role = input.role.as_deref().unwrap_or("member");
    if !matches!(role, "member" | "moderator" | "owner") {
        return Err(ApiError::bad("role must be member, moderator or owner"));
    }
    let (mut added, mut invalid) = (Vec::new(), Vec::new());
    for entry in input.addresses.split(['\n', ',', ';']).map(str::trim).filter(|e| !e.is_empty()).take(lists::MAX_MEMBERS as usize) {
        let (name, address) = match entry.rsplit_once('<') {
            Some((name, rest)) => (name.trim().trim_matches('"'), rest.trim_end_matches('>').trim()),
            None => ("", entry),
        };
        match Address::parse(address) {
            Some(address) if address.to_string() != list.address => {
                lists::add_member(&state, id, &address.to_string(), &clean(name, 100), role).await.map_err(|e| ApiError::bad(e.to_string()))?;
                added.push(address.to_string());
            }
            _ => invalid.push(entry.to_owned()),
        }
    }
    session.audit(&state, "list.members_added", &list.address, &format!("{} as {role}", added.len())).await;
    Ok(Json(json!({ "added": added, "invalid": invalid })))
}

#[derive(Deserialize)]
pub struct MemberChange {
    role: String,
}

pub async fn update_member(State(state): State<AppState>, session: Session, Path((id, member)): Path<(i64, i64)>, Json(input): Json<MemberChange>) -> JsonResult<Value> {
    session.require_admin()?;
    load_managed(&state, &session, id).await?;
    if !matches!(input.role.as_str(), "member" | "moderator" | "owner") {
        return Err(ApiError::bad("role must be member, moderator or owner"));
    }
    let changed = sqlx::query("UPDATE list_members SET role = ? WHERE id = ? AND list_id = ?").bind(&input.role).bind(member).bind(id).execute(&state.db).await?;
    if changed.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove_member(State(state): State<AppState>, session: Session, Path((id, member)): Path<(i64, i64)>) -> JsonResult<Value> {
    session.require_admin()?;
    let list = load_managed(&state, &session, id).await?;
    let removed: Option<String> = sqlx::query_scalar("DELETE FROM list_members WHERE id = ? AND list_id = ? RETURNING email").bind(member).bind(id).fetch_optional(&state.db).await?;
    let email = removed.ok_or(ApiError::NotFound)?;
    session.audit(&state, "list.member_removed", &list.address, &email).await;
    Ok(Json(json!({ "ok": true })))
}

/// Posts waiting for a moderator.
pub async fn held(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Vec<Value>> {
    session.require_admin()?;
    load_managed(&state, &session, id).await?;
    let rows: Vec<(String, String, String, String, i64)> = sqlx::query_as("SELECT token, email, subject, reason, created_at FROM list_pending WHERE list_id = ? AND kind = 'post' ORDER BY id").bind(id).fetch_all(&state.db).await?;
    Ok(Json(rows.into_iter().map(|(token, email, subject, reason, at)| json!({ "token": token, "sender": email, "subject": subject, "reason": reason, "received_at": at })).collect()))
}

#[derive(Deserialize)]
pub struct Decision {
    action: String,
}

pub async fn decide(State(state): State<AppState>, session: Session, Path((id, token)): Path<(i64, String)>, Json(input): Json<Decision>) -> JsonResult<Value> {
    session.require_admin()?;
    let list = load_managed(&state, &session, id).await?;
    let belongs: Option<i64> = sqlx::query_scalar("SELECT 1 FROM list_pending WHERE token = ? AND list_id = ?").bind(&token).bind(id).fetch_optional(&state.db).await?;
    if belongs.is_none() {
        return Err(ApiError::NotFound);
    }
    let approve = match input.action.as_str() {
        "approve" => true,
        "discard" => false,
        _ => return Err(ApiError::bad("action must be approve or discard")),
    };
    let outcome = lists::moderate(&state, &token, approve).await?.ok_or(ApiError::NotFound)?;
    session.audit(&state, if approve { "list.post_approved" } else { "list.post_discarded" }, &list.address, "").await;
    Ok(Json(json!({ "result": outcome })))
}

// --- Public pages -----------------------------------------------------------------------------

fn page(title: &str, body: &str) -> Response {
    let escape = crate::util::html_escape;
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{t}</title>\
         <style>body{{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#222}}button{{font:inherit;padding:.5rem 1rem;margin-right:.5rem;cursor:pointer}}</style></head>\
         <body><h1>{t}</h1>{body}</body></html>",
        t = escape(title)
    );
    ([(header::CACHE_CONTROL, "no-store"), (header::REFERRER_POLICY, "no-referrer")], Html(html)).into_response()
}

fn form(action: &str, buttons: &[(&str, &str)]) -> String {
    let buttons: String = buttons.iter().map(|(value, label)| format!("<button name=\"action\" value=\"{value}\">{label}</button>")).collect();
    format!("<form method=\"post\" action=\"{action}\">{buttons}</form>")
}

/// Link scanners follow links: nothing changes before the button is pressed.
pub async fn confirm_page(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    let pending: Option<(String, String, String)> = sqlx::query_as("SELECT p.kind, p.email, l.address FROM list_pending p JOIN mailing_lists l ON l.id = p.list_id WHERE p.token = ? AND p.kind != 'post'")
        .bind(&token)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let escape = crate::util::html_escape;
    match pending {
        Some((kind, email, list)) => {
            let what = if kind == "subscribe" { format!("Subscribe {} to {}?", escape(&email), escape(&list)) } else { format!("Remove {} from {}?", escape(&email), escape(&list)) };
            page("Confirm", &format!("<p>{what}</p>{}", form(&format!("/lists/confirm/{}", escape(&token)), &[("confirm", "Confirm")])))
        }
        None => page("Link expired", "<p>This link is no longer valid.</p>"),
    }
}

pub async fn confirm_post(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    match lists::confirm(&state, &token).await {
        Ok(Some(done)) => page("Done", &format!("<p>{}</p>", crate::util::html_escape(&done))),
        Ok(None) => page("Link expired", "<p>This link is no longer valid.</p>"),
        Err(_) => page("Something went wrong", "<p>Please try again later.</p>"),
    }
}

pub async fn moderate_page(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    let pending: Option<(String, String, String)> = sqlx::query_as("SELECT p.email, p.subject, l.address FROM list_pending p JOIN mailing_lists l ON l.id = p.list_id WHERE p.token = ? AND p.kind = 'post'")
        .bind(&token)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let escape = crate::util::html_escape;
    match pending {
        Some((sender, subject, list)) => page(
            "Held message",
            &format!(
                "<p>To <b>{}</b> from <b>{}</b>:<br>\u{201c}{}\u{201d}</p>{}",
                escape(&list),
                escape(&sender),
                escape(&subject),
                form(&format!("/lists/moderate/{}", escape(&token)), &[("approve", "Send to the list"), ("discard", "Discard")])
            ),
        ),
        None => page("Already handled", "<p>This message was approved or discarded already.</p>"),
    }
}

#[derive(Deserialize)]
pub struct Choice {
    action: String,
}

pub async fn moderate_post(State(state): State<AppState>, Path(token): Path<String>, Form(choice): Form<Choice>) -> Response {
    let approve = choice.action == "approve";
    match lists::moderate(&state, &token, approve).await {
        Ok(Some(done)) => page("Done", &format!("<p>{}</p>", crate::util::html_escape(&done))),
        Ok(None) => page("Already handled", "<p>This message was approved or discarded already.</p>"),
        Err(_) => page("Something went wrong", "<p>Please try again later.</p>"),
    }
}

pub async fn unsubscribe_page(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    let escape = crate::util::html_escape;
    match lists::member_for_token(&state, &token).await {
        Ok(Some(member)) => {
            let list = lists::load(&state, member.list_id).await.ok().flatten().map(|l| l.address).unwrap_or_default();
            page("Unsubscribe", &format!("<p>Stop sending mail from {} to {}?</p>{}", escape(&list), escape(&member.email), form(&format!("/lists/unsubscribe/{}", escape(&token)), &[("unsubscribe", "Unsubscribe")])))
        }
        _ => page("Not subscribed", "<p>This address is not subscribed (any more).</p>"),
    }
}

/// One-click unsubscribe (RFC 8058): mail programs post `List-Unsubscribe=One-Click` here.
pub async fn unsubscribe_post(State(state): State<AppState>, Path(token): Path<String>, headers: HeaderMap) -> Response {
    let one_click = headers.get(header::CONTENT_TYPE).is_some();
    match lists::member_for_token(&state, &token).await {
        Ok(Some(member)) => {
            let _ = sqlx::query("DELETE FROM list_members WHERE id = ?").bind(member.id).execute(&state.db).await;
            crate::db::audit(&state.db, &member.email, "list.unsubscribed", &member.email, "", "one-click").await;
            if one_click { page("Unsubscribed", &format!("<p>{} will get no more mail from this list.</p>", crate::util::html_escape(&member.email))) } else { StatusCode::OK.into_response() }
        }
        _ => page("Not subscribed", "<p>This address is not subscribed (any more).</p>"),
    }
}
