//! Plug-in and theme packages: installing from git (administrators), opting in and per-user
//! settings and storage (everyone), and the sandboxed frame plug-ins run in.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{JsonResult, Session};
use crate::{
    app::AppState,
    error::ApiError,
    packages::{self, ConfirmError, Installed, frame, manifest},
};

async fn installed(state: &AppState, id: &str) -> Result<Installed, ApiError> {
    packages::get(&state.db, id).await?.ok_or(ApiError::NotFound)
}

/// Settings as a user sees them: secrets are never sent back, only whether they are set.
fn masked(settings: &Value) -> Value {
    let mut out = Map::new();
    for (key, value) in settings.as_object().into_iter().flatten() {
        out.insert(key.clone(), if value.get("sealed").is_some() { json!({ "set": true }) } else { value.clone() });
    }
    Value::Object(out)
}

/// Every package for administrators; for users, the ones they may use and their own choices.
pub async fn list(State(state): State<AppState>, session: Session) -> JsonResult<Vec<Value>> {
    let mut out = Vec::new();
    for package in packages::list(&state.db).await? {
        if !package.enabled && !session.is_super() {
            continue;
        }
        let user = packages::user_state(&state.db, &package.id, session.account.id).await?;
        let mut item = if session.is_super() { package.to_json() } else { json!({ "id": package.id, "type": package.kind, "commit": package.git_commit, "manifest": package.manifest(), "enabled": package.enabled }) };
        if package.kind == "theme" {
            item["manifest"]["theme"] = packages::theme_for_client(&package.id, &package.git_commit, &package.manifest());
        }
        item["user"] = json!({ "enabled": user.enabled, "settings": masked(&serde_json::from_str(&user.settings).unwrap_or(json!({}))) });
        out.push(item);
    }
    Ok(Json(out))
}

/// What the web client loads at start: the plug-ins this user opted in to and installed themes.
/// Administrators also get the plug-ins with admin pages, so those work without opting in.
pub async fn startup(state: &AppState, session: &Session) -> Result<(Vec<Value>, Vec<Value>), ApiError> {
    let (mut plugins, mut themes) = (Vec::new(), Vec::new());
    for package in packages::list(&state.db).await?.into_iter().filter(|p| p.enabled) {
        let manifest = package.manifest();
        if package.kind == "theme" {
            themes.push(packages::theme_for_client(&package.id, &package.git_commit, &manifest));
            continue;
        }
        // Server-only plug-ins have nothing to run in the browser.
        if manifest.get("entry").is_none() {
            continue;
        }
        let opted_in = packages::user_state(&state.db, &package.id, session.account.id).await?.enabled;
        let admin_pages = session.is_super() && manifest["permissions"].as_array().is_some_and(|p| p.iter().any(|p| p == "ui:admin"));
        if opted_in || admin_pages {
            plugins.push(json!({ "id": package.id, "commit": package.git_commit, "name": manifest["name"], "permissions": package.permissions(), "adminOnly": !opted_in }));
        }
    }
    Ok((plugins, themes))
}

#[derive(Deserialize)]
pub struct PreviewInput {
    url: String,
    #[serde(rename = "ref")]
    git_ref: String,
}

/// Fetches a repository and shows what installing it would mean.
pub async fn preview(State(state): State<AppState>, session: Session, Json(input): Json<PreviewInput>) -> JsonResult<Value> {
    session.require_super()?;
    Ok(Json(packages::preview(&state, &input.url, &input.git_ref, None).await.map_err(ApiError::bad)?))
}

/// Fetches the newest commit of an installed package's ref, for the administrator to approve.
pub async fn update_preview(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> JsonResult<Value> {
    session.require_super()?;
    let package = installed(&state, &id).await?;
    if packages::check_update(&state, &package).await.map_err(ApiError::bad)?.is_none() {
        return Ok(Json(json!({ "upToDate": true, "commit": package.git_commit })));
    }
    Ok(Json(packages::preview(&state, &package.source_url, &package.git_ref, Some(&package)).await.map_err(ApiError::bad)?))
}

#[derive(Deserialize)]
pub struct ConfirmInput {
    token: String,
}

pub async fn install(State(state): State<AppState>, session: Session, Json(input): Json<ConfirmInput>) -> JsonResult<Value> {
    session.require_super()?;
    let package = packages::confirm(&state, &input.token, &session.account.email).await.map_err(|err| match err {
        ConfirmError::Gone => ApiError::bad("the preview has expired; fetch the package again"),
        ConfirmError::Conflict(message) => ApiError::Conflict(message),
        ConfirmError::Failed(message) => ApiError::Internal(anyhow::anyhow!(message)),
    })?;
    session.audit(&state, "package.installed", &package.id, &format!("{} {}", package.source_url, package.git_commit)).await;
    Ok(Json(package.to_json()))
}

#[derive(Deserialize)]
pub struct EnableInput {
    enabled: bool,
}

/// Makes a package available to users, or withdraws it.
pub async fn set_enabled(State(state): State<AppState>, session: Session, Path(id): Path<String>, Json(input): Json<EnableInput>) -> JsonResult<Value> {
    session.require_super()?;
    if !packages::set_enabled(&state.db, &id, input.enabled).await? {
        return Err(ApiError::NotFound);
    }
    session.audit(&state, "package.toggled", &id, if input.enabled { "enabled" } else { "disabled" }).await;
    Ok(Json(installed(&state, &id).await?.to_json()))
}

pub async fn uninstall(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> JsonResult<Value> {
    session.require_super()?;
    if !packages::remove(&state, &id).await? {
        return Err(ApiError::NotFound);
    }
    session.audit(&state, "package.removed", &id, "").await;
    Ok(Json(json!({ "ok": true })))
}

// --- Per user ------------------------------------------------------------------------------

/// A plug-in the signed-in user may use.
async fn usable(state: &AppState, id: &str) -> Result<Installed, ApiError> {
    let package = installed(state, id).await?;
    if !package.enabled || package.kind != "plugin" { Err(ApiError::NotFound) } else { Ok(package) }
}

#[derive(Deserialize)]
pub struct UserInput {
    enabled: bool,
    #[serde(default)]
    settings: Option<Value>,
}

/// Turns a plug-in on or off for the signed-in user, and saves their settings for it.
pub async fn user_put(State(state): State<AppState>, session: Session, Path(id): Path<String>, Json(input): Json<UserInput>) -> JsonResult<Value> {
    let package = usable(&state, &id).await?;
    let current = packages::user_state(&state.db, &id, session.account.id).await?;
    let previous: Value = serde_json::from_str(&current.settings).unwrap_or(json!({}));
    let settings = match &input.settings {
        Some(settings) => packages::clean_settings(&package.manifest()["settings"], "user", settings, &previous, |s| state.secrets.seal(s)).map_err(ApiError::bad)?,
        None => previous,
    };
    packages::save_user(&state.db, &id, session.account.id, input.enabled, &settings).await?;
    Ok(Json(json!({ "enabled": input.enabled, "settings": masked(&settings) })))
}

/// The user's settings as the plug-in receives them, secrets included.
pub async fn user_settings(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> JsonResult<Value> {
    let package = usable(&state, &id).await?;
    let user = packages::user_state(&state.db, &id, session.account.id).await?;
    let stored: Value = serde_json::from_str(&user.settings).unwrap_or(json!({}));
    Ok(Json(packages::open_settings(&package.manifest()["settings"], "user", &stored, true, |s| state.secrets.open(s))))
}

/// The administrator's settings of a plug-in as its web part receives them: no secrets.
pub async fn user_admin_settings(State(state): State<AppState>, _session: Session, Path(id): Path<String>) -> JsonResult<Value> {
    let package = usable(&state, &id).await?;
    let stored: Value = serde_json::from_str(&package.admin_settings).unwrap_or(json!({}));
    Ok(Json(packages::open_settings(&package.manifest()["settings"], "admin", &stored, false, |s| state.secrets.open(s))))
}

/// A package's administrator settings for the settings form: secrets only say whether they are set.
pub async fn admin_settings_get(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> JsonResult<Value> {
    session.require_super()?;
    let package = installed(&state, &id).await?;
    let stored: Value = serde_json::from_str(&package.admin_settings).unwrap_or(json!({}));
    Ok(Json(json!({ "settings": masked(&stored), "failClosed": package.fail_closed })))
}

#[derive(Deserialize)]
pub struct AdminSettingsInput {
    #[serde(default)]
    settings: Option<Value>,
    #[serde(default, rename = "failClosed")]
    fail_closed: Option<bool>,
}

pub async fn admin_settings_put(State(state): State<AppState>, session: Session, Path(id): Path<String>, Json(input): Json<AdminSettingsInput>) -> JsonResult<Value> {
    session.require_super()?;
    let package = installed(&state, &id).await?;
    let previous: Value = serde_json::from_str(&package.admin_settings).unwrap_or(json!({}));
    let settings = match &input.settings {
        Some(settings) => packages::clean_settings(&package.manifest()["settings"], "admin", settings, &previous, |s| state.secrets.seal(s)).map_err(ApiError::bad)?,
        None => previous,
    };
    let fail_closed = input.fail_closed.unwrap_or(package.fail_closed);
    packages::save_admin(&state.db, &id, &settings, fail_closed).await?;
    session.audit(&state, "package.settings", &id, if fail_closed { "fail closed" } else { "" }).await;
    Ok(Json(json!({ "settings": masked(&settings), "failClosed": fail_closed })))
}

pub async fn storage_get(State(state): State<AppState>, session: Session, Path(id): Path<String>) -> JsonResult<Value> {
    usable(&state, &id).await?;
    let user = packages::user_state(&state.db, &id, session.account.id).await?;
    Ok(Json(serde_json::from_str(&user.storage).unwrap_or(json!({}))))
}

#[derive(Deserialize)]
pub struct StorageInput {
    key: String,
    /// `null` removes the key.
    value: Value,
}

pub async fn storage_put(State(state): State<AppState>, session: Session, Path(id): Path<String>, Json(input): Json<StorageInput>) -> JsonResult<Value> {
    usable(&state, &id).await?;
    if input.key.is_empty() || input.key.len() > 100 {
        return Err(ApiError::bad("storage keys must be 1 to 100 characters"));
    }
    let user = packages::user_state(&state.db, &id, session.account.id).await?;
    let mut storage: Map<String, Value> = serde_json::from_str(&user.storage).unwrap_or_default();
    if input.value.is_null() {
        storage.remove(&input.key);
    } else {
        storage.insert(input.key, input.value);
    }
    let storage = Value::Object(storage);
    if storage.to_string().len() > packages::MAX_STORAGE_BYTES {
        return Err(ApiError::TooLarge);
    }
    packages::save_storage(&state.db, &id, session.account.id, &storage).await?;
    Ok(Json(json!({ "ok": true })))
}

// --- Server routes -------------------------------------------------------------------------

const MAX_ROUTE_BODY: usize = 256 * 1024;

/// `/api/x/<id>/<path>`: a plug-in's own API, answered by its server module for signed-in
/// users. The module learns who is asking, and that user's settings for the plug-in.
pub async fn server_route(
    State(state): State<AppState>,
    session: Session,
    method: axum::http::Method,
    Path((id, path)): Path<(String, String)>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let package = usable(&state, &id).await?;
    if package.manifest()["server"]["routes"] != true {
        return Err(ApiError::NotFound);
    }
    if body.len() > MAX_ROUTE_BODY {
        return Err(ApiError::TooLarge);
    }
    let body: Value = if body.is_empty() { Value::Null } else { serde_json::from_slice(&body).map_err(|_| ApiError::bad("the body must be JSON"))? };
    let user = packages::user_state(&state.db, &id, session.account.id).await?;
    let stored: Value = serde_json::from_str(&user.settings).unwrap_or(json!({}));
    let user_settings = packages::open_settings(&package.manifest()["settings"], "user", &stored, true, |s| state.secrets.open(s));
    let request = json!({
        "event": "http:request",
        "method": method.as_str(),
        "path": format!("/{path}"),
        "query": query.unwrap_or_default(),
        "body": body,
        "user": { "email": session.account.email, "role": session.account.role.as_str() },
    });
    let (status, answer) = packages::hooks::route(&state, package, request, session.account.id, user_settings).await.map_err(|error| ApiError::Internal(anyhow::anyhow!(error)))?;
    let mut response = Json(answer).into_response();
    *response.status_mut() = axum::http::StatusCode::from_u16(status).unwrap_or(axum::http::StatusCode::OK);
    Ok(response)
}

// --- Theme images --------------------------------------------------------------------------

/// An image a theme package declared, at its installed commit. Like the frame, it is fetched
/// without credentials (the login page shows it too) and only declared files are served.
pub async fn asset(State(state): State<AppState>, Path((id, commit, path)): Path<(String, String, String)>) -> Result<Response, ApiError> {
    let package = installed(&state, &id).await?;
    let manifest = package.manifest();
    let declared = manifest["theme"]["images"].as_object().is_some_and(|images| images.values().any(|p| p.as_str() == Some(path.as_str())));
    if !package.enabled || package.git_commit != commit || !declared {
        return Err(ApiError::NotFound);
    }
    let media_type = manifest::image_type(&path).ok_or(ApiError::NotFound)?;
    let bytes = tokio::fs::read(packages::package_dir(&state.cfg.data_dir, &id, &commit).join(&path)).await.map_err(|_| ApiError::NotFound)?;
    if !manifest::image_matches(media_type, &bytes) {
        return Err(ApiError::NotFound);
    }
    let mut response = bytes.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(media_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=31536000, immutable"));
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; sandbox"));
    Ok(response)
}

/// Where OAuth providers return plug-ins' sign-in windows (see `frame::auth_callback`).
pub async fn auth_callback() -> Response {
    let (html, policy) = frame::auth_callback();
    let mut response = html.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    // The query holds a one-time authorization code: never cached.
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(policy) = HeaderValue::from_str(&policy) {
        headers.insert(header::CONTENT_SECURITY_POLICY, policy);
    }
    response
}

// --- The frame -----------------------------------------------------------------------------

/// The sandboxed document of an enabled plug-in at its installed commit.
///
/// The frame has an opaque origin, so the browser sends it no session cookie; this route needs
/// none. It serves only what is installed and enabled, at the exact commit, which also lets
/// browsers cache it for good.
pub async fn frame(State(state): State<AppState>, Path((id, commit)): Path<(String, String)>) -> Result<Response, ApiError> {
    let package = usable(&state, &id).await?;
    if package.git_commit != commit {
        return Err(ApiError::NotFound);
    }
    let manifest = package.manifest();
    let entry = manifest["entry"].as_str().filter(|e| manifest::valid_entry(e)).ok_or(ApiError::NotFound)?;
    let path = packages::package_dir(&state.cfg.data_dir, &id, &commit).join(entry);
    let script = match tokio::fs::metadata(&path).await {
        Ok(meta) if meta.is_file() && meta.len() <= manifest::MAX_ENTRY_BYTES => tokio::fs::read_to_string(&path).await.map_err(|_| ApiError::NotFound)?,
        _ => return Err(ApiError::NotFound),
    };
    let (html, policy) = frame::document(&package.permissions(), &script);
    let mut response = html.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=31536000, immutable"));
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_str(&policy).map_err(|e| ApiError::Internal(e.into()))?);
    Ok(response)
}
