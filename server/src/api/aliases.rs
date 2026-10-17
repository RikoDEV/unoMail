//! Alias and redirect management.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{JsonResult, Session, like_pattern};
use crate::{
    app::AppState,
    directory,
    error::{ApiError, ApiResult},
    util::Address,
};

#[derive(sqlx::FromRow)]
struct AliasRow {
    id: i64,
    domain_id: i64,
    source: String,
    destinations: String,
    enabled: bool,
    created_at: i64,
}

#[derive(Serialize)]
pub struct AliasView {
    id: i64,
    domain_id: i64,
    source: String,
    destinations: Vec<String>,
    enabled: bool,
    created_at: i64,
}

impl From<AliasRow> for AliasView {
    fn from(r: AliasRow) -> Self {
        AliasView {
            id: r.id,
            domain_id: r.domain_id,
            source: r.source,
            destinations: serde_json::from_str(&r.destinations).unwrap_or_default(),
            enabled: r.enabled,
            created_at: r.created_at,
        }
    }
}

async fn load_managed(state: &AppState, session: &Session, id: i64) -> ApiResult<AliasRow> {
    let alias: AliasRow =
        sqlx::query_as("SELECT * FROM aliases WHERE id = ?").bind(id).fetch_optional(&state.db).await?.ok_or(ApiError::NotFound)?;
    session.require_domain(&state.db, alias.domain_id).await?;
    Ok(alias)
}

#[derive(Deserialize)]
pub struct ListQuery {
    domain_id: Option<i64>,
    q: Option<String>,
}

pub async fn list(State(state): State<AppState>, session: Session, Query(query): Query<ListQuery>) -> JsonResult<Vec<AliasView>> {
    let managed = session.managed_domains(&state.db).await?;
    if let Some(domain_id) = query.domain_id {
        session.require_domain(&state.db, domain_id).await?;
    }
    let scope = serde_json::to_string(&managed.clone().unwrap_or_default()).map_err(anyhow::Error::from)?;
    let rows: Vec<AliasRow> = sqlx::query_as(
        "SELECT * FROM aliases
         WHERE (?1 = 1 OR domain_id IN (SELECT value FROM json_each(?2)))
           AND (?3 IS NULL OR domain_id = ?3)
           AND (source LIKE ?4 ESCAPE '\\' OR destinations LIKE ?4 ESCAPE '\\')
         ORDER BY source LIMIT 1000",
    )
    .bind(managed.is_none())
    .bind(scope)
    .bind(query.domain_id)
    .bind(like_pattern(query.q.as_deref().unwrap_or("").trim()))
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows.into_iter().map(AliasView::from).collect()))
}

#[derive(Deserialize)]
pub struct CreateAlias {
    source: String,
    destinations: Vec<String>,
}

pub async fn create(State(state): State<AppState>, session: Session, Json(req): Json<CreateAlias>) -> JsonResult<AliasView> {
    session.require_admin()?;
    let address = Address::parse_local(&req.source).ok_or_else(|| ApiError::bad("invalid alias address"))?;
    let domain_id: i64 = sqlx::query_scalar("SELECT id FROM domains WHERE name = ?")
        .bind(&address.domain)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::bad("domain is not hosted on this server"))?;
    session.require_domain(&state.db, domain_id).await.map_err(|_| ApiError::Forbidden)?;
    let id = directory::create_alias(&state.db, &req.source, &req.destinations).await?;
    session.audit(&state, "alias.created", &address.to_string(), &req.destinations.join(",")).await;
    Ok(Json(load_managed(&state, &session, id).await?.into()))
}

#[derive(Deserialize)]
pub struct UpdateAlias {
    destinations: Option<Vec<String>>,
    enabled: Option<bool>,
}

pub async fn update(
    State(state): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
    Json(req): Json<UpdateAlias>,
) -> JsonResult<AliasView> {
    session.require_admin()?;
    let current = load_managed(&state, &session, id).await?;
    let destinations = match &req.destinations {
        Some(list) => {
            let parsed = directory::parse_destinations(list)?;
            if parsed.contains(&current.source) {
                return Err(ApiError::bad("an alias cannot deliver to itself"));
            }
            serde_json::to_string(&parsed).map_err(anyhow::Error::from)?
        }
        None => current.destinations.clone(),
    };
    sqlx::query("UPDATE aliases SET destinations = ?, enabled = ? WHERE id = ?")
        .bind(&destinations)
        .bind(req.enabled.unwrap_or(current.enabled))
        .bind(id)
        .execute(&state.db)
        .await?;
    session.audit(&state, "alias.updated", &current.source, &destinations).await;
    Ok(Json(load_managed(&state, &session, id).await?.into()))
}

pub async fn remove(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    session.require_admin()?;
    let alias = load_managed(&state, &session, id).await?;
    sqlx::query("DELETE FROM aliases WHERE id = ?").bind(id).execute(&state.db).await?;
    session.audit(&state, "alias.deleted", &alias.source, "").await;
    Ok(Json(json!({ "ok": true })))
}
