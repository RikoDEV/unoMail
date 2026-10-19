//! Administration of SMTP access control (blacklist, whitelist, karma) and the live view of
//! remote addresses and SMTP replies on the dashboard.

use std::net::IpAddr;

use axum::{
    Json,
    extract::{Path, Query, State},
};
use futures_util::future::join_all;
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{JsonResult, Session};
use crate::{
    activity::{self, Described},
    app::AppState,
    error::ApiError,
    security::access,
    util::{now, sanitize_line},
};

const MAX_RULES: i64 = 10_000;

/// Reverse DNS and country for a single address; for a wider network only the country.
async fn describe_network(state: &AppState, net: &IpNet) -> Described {
    let described = activity::describe(state, net.addr()).await;
    if net.prefix_len() == net.max_prefix_len() { described } else { Described { rdns: None, ..described } }
}

#[derive(Deserialize)]
pub struct RulesQuery {
    /// `user` (default) or `auto`.
    source: Option<String>,
}

type RuleRow = (i64, String, String, String, i64, i64, Option<i64>, String, i64, Option<i64>);

pub async fn rules_list(State(state): State<AppState>, session: Session, Query(query): Query<RulesQuery>) -> JsonResult<Vec<Value>> {
    session.require_super()?;
    let source = if query.source.as_deref() == Some("auto") { "auto" } else { "user" };
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT id, list, source, network, priority, hits, last_seen, description, created_at, expires_at FROM ip_rules
         WHERE source = ?1 AND (expires_at IS NULL OR expires_at > ?2) ORDER BY priority DESC, last_seen DESC NULLS LAST, id DESC LIMIT 1000",
    )
    .bind(source)
    .bind(now())
    .fetch_all(&state.db)
    .await?;
    let out = join_all(rows.into_iter().map(|(id, list, source, network, priority, hits, last_seen, description, created_at, expires_at)| {
        let state = state.clone();
        async move {
            let net: Option<IpNet> = network.parse().ok();
            let described = match &net {
                Some(net) => describe_network(&state, net).await,
                None => Described::default(),
            };
            json!({
                "id": id, "list": list, "source": source,
                "network": net.as_ref().map_or(network, access::display),
                "priority": priority, "hits": hits, "last_seen": last_seen, "description": description,
                "created_at": created_at, "expires_at": expires_at,
                "rdns": described.rdns, "country": described.country,
            })
        }
    }))
    .await;
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct RuleInput {
    list: String,
    network: String,
    #[serde(default)]
    priority: i64,
    #[serde(default)]
    description: String,
}

fn clean_rule(input: &RuleInput) -> Result<(String, String), ApiError> {
    if !matches!(input.list.as_str(), "blacklist" | "whitelist") {
        return Err(ApiError::bad("list must be \"blacklist\" or \"whitelist\""));
    }
    let net = access::parse_network(&input.network).ok_or_else(|| ApiError::bad("enter an IP address or a network such as 203.0.113.0/24"))?;
    // A rule this wide is almost certainly a typo, and as a blacklist it would stop all mail.
    if net.prefix_len() < 8 {
        return Err(ApiError::bad("networks wider than /8 are not accepted"));
    }
    if !(-1000..=1000).contains(&input.priority) {
        return Err(ApiError::bad("the priority must be between -1000 and 1000"));
    }
    let description = sanitize_line(input.description.trim());
    if description.chars().count() > 200 {
        return Err(ApiError::bad("the description is too long"));
    }
    Ok((net.to_string(), description))
}

fn duplicate(err: sqlx::Error) -> ApiError {
    match &err {
        sqlx::Error::Database(db) if db.is_unique_violation() => ApiError::Conflict("this address or network is already on that list".into()),
        _ => err.into(),
    }
}

pub async fn rule_create(State(state): State<AppState>, session: Session, Json(input): Json<RuleInput>) -> JsonResult<Value> {
    session.require_super()?;
    let (network, description) = clean_rule(&input)?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ip_rules").fetch_one(&state.db).await?;
    if count >= MAX_RULES {
        return Err(ApiError::Conflict(format!("at most {MAX_RULES} rules can be stored")));
    }
    let id = sqlx::query("INSERT INTO ip_rules (list, source, network, priority, description, created_at) VALUES (?, 'user', ?, ?, ?, ?)")
        .bind(&input.list)
        .bind(&network)
        .bind(input.priority)
        .bind(&description)
        .bind(now())
        .execute(&state.db)
        .await
        .map_err(duplicate)?
        .last_insert_rowid();
    access::reload(&state).await;
    session.audit(&state, "smtp_access.rule_created", &network, &input.list).await;
    Ok(Json(json!({ "id": id })))
}

/// Updates a rule. Editing an automatic rule adopts it: it becomes a permanent, user-defined one.
pub async fn rule_update(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<RuleInput>) -> JsonResult<Value> {
    session.require_super()?;
    let (network, description) = clean_rule(&input)?;
    let changed = sqlx::query("UPDATE ip_rules SET list = ?, network = ?, priority = ?, description = ?, source = 'user', expires_at = NULL WHERE id = ?")
        .bind(&input.list)
        .bind(&network)
        .bind(input.priority)
        .bind(&description)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(duplicate)?
        .rows_affected();
    if changed == 0 {
        return Err(ApiError::NotFound);
    }
    access::reload(&state).await;
    session.audit(&state, "smtp_access.rule_updated", &network, &input.list).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn rule_delete(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    session.require_super()?;
    let network: Option<String> = sqlx::query_scalar("DELETE FROM ip_rules WHERE id = ? RETURNING network").bind(id).fetch_optional(&state.db).await?;
    let Some(network) = network else { return Err(ApiError::NotFound) };
    access::reload(&state).await;
    session.audit(&state, "smtp_access.rule_deleted", &network, "").await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn karma_list(State(state): State<AppState>, session: Session) -> JsonResult<Vec<Value>> {
    session.require_super()?;
    let rows: Vec<(String, i64, i64, i64, i64, i64, String)> =
        sqlx::query_as("SELECT ip, score, good, bad, hits, last_seen, last_event FROM ip_karma ORDER BY last_seen DESC LIMIT 1000").fetch_all(&state.db).await?;
    let out = join_all(rows.into_iter().map(|(ip, score, good, bad, hits, last_seen, last_event)| {
        let state = state.clone();
        async move {
            let described = match ip.parse::<IpAddr>() {
                Ok(address) => activity::describe(&state, address).await,
                Err(_) => Described::default(),
            };
            json!({ "ip": ip, "score": score, "good": good, "bad": bad, "hits": hits, "last_seen": last_seen, "last_event": last_event, "rdns": described.rdns, "country": described.country })
        }
    }))
    .await;
    Ok(Json(out))
}

/// Forgets the record of an address, giving it a clean slate.
pub async fn karma_delete(State(state): State<AppState>, session: Session, Path(ip): Path<String>) -> JsonResult<Value> {
    session.require_super()?;
    let address: IpAddr = ip.parse().map_err(|_| ApiError::bad("invalid IP address"))?;
    let removed = sqlx::query("DELETE FROM ip_karma WHERE ip = ?").bind(address.to_string()).execute(&state.db).await?.rows_affected();
    if removed == 0 {
        return Err(ApiError::NotFound);
    }
    session.audit(&state, "smtp_access.karma_reset", &address.to_string(), "").await;
    Ok(Json(json!({ "ok": true })))
}

/// Networks and accounts the login limiter refuses right now.
pub async fn login_blocks(State(state): State<AppState>, session: Session) -> JsonResult<Vec<Value>> {
    session.require_super()?;
    let blocks = state.limiter.blocks();
    let out = join_all(blocks.into_iter().take(1000).map(|block| {
        let state = state.clone();
        async move {
            // A single address is described; an IPv6 /64 only by its country.
            let described = match block.network.as_deref().and_then(|n| n.parse::<IpAddr>().ok().map(IpNet::from).or_else(|| n.parse::<IpNet>().ok())) {
                Some(net) => describe_network(&state, &net).await,
                None => Described::default(),
            };
            json!({
                "key": block.key, "kind": block.kind, "network": block.network, "email": block.email,
                "failures": block.failures, "until": block.until, "rdns": described.rdns, "country": described.country,
            })
        }
    }))
    .await;
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct UnblockInput {
    key: String,
}

/// Lifts a login block, forgetting the failures behind it.
pub async fn login_unblock(State(state): State<AppState>, session: Session, Json(input): Json<UnblockInput>) -> JsonResult<Value> {
    session.require_super()?;
    if input.key.len() > 400 || !state.limiter.unblock(&input.key) {
        return Err(ApiError::NotFound);
    }
    // Saved now, so that a restart before the next periodic save does not bring it back.
    state.save_state().await;
    session.audit(&state, "login.unblocked", &sanitize_line(&input.key), "").await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    /// Look-back window in hours (default 24, at most a week).
    hours: Option<i64>,
}

/// Free disk space and memory use over time, for the capacity charts.
pub async fn system_history(State(state): State<AppState>, session: Session, Query(query): Query<HistoryQuery>) -> JsonResult<Value> {
    session.require_super()?;
    let mut samples = crate::sysstat::history(&state, query.hours.unwrap_or(24)).await?;
    // Right after the first start there is nothing stored yet: measure now.
    if samples.is_empty()
        && let Some(sample) = crate::sysstat::record(&state).await
    {
        samples.push(sample);
    }
    Ok(Json(json!({ "samples": samples })))
}

#[derive(Deserialize)]
pub struct DailyQuery {
    days: Option<i64>,
}

/// Connections and mail per day, for the dashboard's daily statistics.
pub async fn daily_stats(State(state): State<AppState>, session: Session, Query(query): Query<DailyQuery>) -> JsonResult<Value> {
    session.require_super()?;
    Ok(Json(json!({ "days": crate::dailystats::history(&state, query.days.unwrap_or(30)).await? })))
}

/// Who connected recently and what the server last told SMTP clients.
pub async fn activity(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    session.require_super()?;
    let ips = join_all(state.activity.recent_ips(15).into_iter().map(|(ip, seen)| {
        let state = state.clone();
        async move {
            let described = activity::describe(&state, ip).await;
            json!({ "ip": ip.to_string(), "connections": seen.connections, "last_seen": seen.last_seen, "rdns": described.rdns, "country": described.country })
        }
    }))
    .await;
    Ok(Json(json!({ "remote_ips": ips, "replies": state.activity.recent_replies(15) })))
}
