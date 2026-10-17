//! Administration of the integrations around the web client: the LDAP directory, skins,
//! plug-ins and webhooks.

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
    ldap::{self, LdapConfig},
    util::{now, sanitize_line},
};

// --- LDAP directory ------------------------------------------------------------------------

fn ldap_view(config: Option<&LdapConfig>) -> Value {
    match config {
        Some(config) => {
            let mut view = serde_json::to_value(config).unwrap_or_default();
            // The bind password never leaves the server again.
            view["has_password"] = json!(!config.bind_password.is_empty());
            view.as_object_mut().map(|o| o.remove("bind_password"));
            view
        }
        None => Value::Null,
    }
}

pub async fn ldap_get(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    session.require_super()?;
    Ok(Json(ldap_view(ldap::load(&state).await?.as_ref())))
}

#[derive(Deserialize)]
pub struct LdapInput {
    #[serde(flatten)]
    config: LdapConfig,
    /// A new bind password; omitted keeps the stored one.
    password: Option<String>,
}

async fn ldap_from_input(state: &AppState, input: LdapInput) -> Result<LdapConfig, ApiError> {
    let mut config = input.config;
    config.url = config.url.trim().to_owned();
    config.validate().map_err(ApiError::bad)?;
    config.bind_password = match input.password {
        Some(password) => state.secrets.seal(&password),
        None => ldap::load(state).await?.map(|stored| stored.bind_password).unwrap_or_default(),
    };
    Ok(config)
}

pub async fn ldap_put(State(state): State<AppState>, session: Session, Json(input): Json<LdapInput>) -> JsonResult<Value> {
    session.require_super()?;
    let config = ldap_from_input(&state, input).await?;
    ldap::save(&state, &config).await?;
    session.audit(&state, "ldap.configured", &sanitize_line(&config.url), if config.enabled { "enabled" } else { "disabled" }).await;
    Ok(Json(ldap_view(Some(&config))))
}

#[derive(Deserialize)]
pub struct LdapTest {
    #[serde(flatten)]
    input: LdapInput,
    query: String,
}

/// Runs a search with the submitted (not yet saved) configuration.
pub async fn ldap_test(State(state): State<AppState>, session: Session, Json(test): Json<LdapTest>) -> JsonResult<Value> {
    session.require_super()?;
    let config = ldap_from_input(&state, test.input).await?;
    match ldap::search_with(&state, &config, test.query.trim()).await {
        Ok(entries) => Ok(Json(json!({ "ok": true, "entries": entries }))),
        Err(error) => Ok(Json(json!({ "ok": false, "error": sanitize_line(&error) }))),
    }
}

// --- Skins ---------------------------------------------------------------------------------

const SKINS_KEY: &str = "skins.custom";
const MAX_SKINS: usize = 20;

fn is_color(value: &Value) -> bool {
    value.as_str().is_some_and(|s| s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Skins are data, not code: a fixed set of design tokens that the client turns into a theme.
/// Anything else (in particular CSS or URLs) is refused, so a skin can never inject content.
pub fn validate_skin(skin: &Value) -> Result<(), String> {
    let object = skin.as_object().ok_or("a skin must be an object")?;
    let id = object.get("id").and_then(Value::as_str).unwrap_or("");
    if id.is_empty() || id.len() > 40 || !id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        return Err("the skin id may contain lowercase letters, digits and '-'".into());
    }
    let name = object.get("name").and_then(Value::as_str).unwrap_or("");
    if name.is_empty() || name.chars().count() > 60 || name.chars().any(char::is_control) {
        return Err("a skin needs a name of at most 60 characters".into());
    }
    for (key, value) in object {
        let ok = match key.as_str() {
            "id" | "name" => true,
            "mode" => matches!(value.as_str(), Some("light" | "dark" | "auto")),
            "primary" | "secondary" | "background" | "paper" | "text" => is_color(value),
            "radius" => value.as_u64().is_some_and(|r| r <= 32),
            "density" => matches!(value.as_str(), Some("comfortable" | "compact")),
            "font" => matches!(value.as_str(), Some("roboto" | "system" | "serif" | "mono")),
            _ => return Err(format!("unknown skin property: {}", sanitize_line(key))),
        };
        if !ok {
            return Err(format!("invalid value for {}", sanitize_line(key)));
        }
    }
    Ok(())
}

async fn custom_skins(state: &AppState) -> Result<Vec<Value>, ApiError> {
    Ok(crate::db::get_setting(&state.db, SKINS_KEY).await?.and_then(|json| serde_json::from_str(&json).ok()).unwrap_or_default())
}

/// Skins installed by the administrator, available to every signed-in user.
pub async fn skins_get(State(state): State<AppState>, _session: Session) -> JsonResult<Vec<Value>> {
    Ok(Json(custom_skins(&state).await?))
}

pub async fn skins_put(State(state): State<AppState>, session: Session, Json(skins): Json<Vec<Value>>) -> JsonResult<Vec<Value>> {
    session.require_super()?;
    if skins.len() > MAX_SKINS {
        return Err(ApiError::bad(format!("at most {MAX_SKINS} skins can be installed")));
    }
    let mut ids = std::collections::HashSet::new();
    for skin in &skins {
        validate_skin(skin).map_err(ApiError::bad)?;
        if !ids.insert(skin["id"].as_str().unwrap_or_default().to_owned()) {
            return Err(ApiError::bad("skin ids must be unique"));
        }
    }
    crate::db::set_setting(&state.db, SKINS_KEY, &Value::Array(skins.clone()).to_string()).await?;
    session.audit(&state, "skins.updated", "server", &skins.len().to_string()).await;
    Ok(Json(skins))
}

// --- Plug-ins ------------------------------------------------------------------------------

const MAX_PLUGIN_BYTES: u64 = 2 * 1024 * 1024;

fn valid_plugin_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 50 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

/// Plug-ins are directories under `<data>/plugins`, each with a `plugin.json` manifest and a
/// `plugin.js` module. Only someone with access to the server's disk can install one.
async fn installed_plugins(state: &AppState) -> Vec<Value> {
    let dir = state.cfg.data_dir.join("plugins");
    let mut out = Vec::new();
    let Ok(mut entries) = tokio::fs::read_dir(&dir).await else { return out };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let Some(id) = entry.file_name().to_str().filter(|n| valid_plugin_name(n)).map(str::to_owned) else { continue };
        let Ok(manifest) = tokio::fs::read(entry.path().join("plugin.json")).await else { continue };
        let Ok(Value::Object(manifest)) = serde_json::from_slice::<Value>(&manifest) else { continue };
        if tokio::fs::metadata(entry.path().join("plugin.js")).await.is_ok_and(|m| m.is_file() && m.len() <= MAX_PLUGIN_BYTES) {
            let field = |key: &str| manifest.get(key).and_then(Value::as_str).map(sanitize_line).unwrap_or_default();
            out.push(json!({ "id": id, "name": field("name"), "version": field("version"), "description": field("description") }));
        }
    }
    out.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    out
}

async fn disabled_plugins(state: &AppState) -> Result<Vec<String>, ApiError> {
    Ok(crate::db::get_setting(&state.db, "plugins.disabled").await?.and_then(|json| serde_json::from_str(&json).ok()).unwrap_or_default())
}

/// The plug-ins the web client should load.
pub async fn plugins_get(State(state): State<AppState>, session: Session) -> JsonResult<Vec<Value>> {
    let disabled = disabled_plugins(&state).await?;
    let mut plugins = installed_plugins(&state).await;
    for plugin in &mut plugins {
        plugin["enabled"] = json!(!disabled.iter().any(|d| Some(d.as_str()) == plugin["id"].as_str()));
    }
    // Ordinary users only learn about what actually runs in their browser.
    if !session.is_super() {
        plugins.retain(|p| p["enabled"] == true);
    }
    Ok(Json(plugins))
}

#[derive(Deserialize)]
pub struct PluginToggle {
    enabled: bool,
}

pub async fn plugin_toggle(State(state): State<AppState>, session: Session, Path(id): Path<String>, Json(toggle): Json<PluginToggle>) -> JsonResult<Value> {
    session.require_super()?;
    if !installed_plugins(&state).await.iter().any(|p| p["id"].as_str() == Some(id.as_str())) {
        return Err(ApiError::NotFound);
    }
    let mut disabled = disabled_plugins(&state).await?;
    disabled.retain(|d| d != &id);
    if !toggle.enabled {
        disabled.push(id.clone());
    }
    crate::db::set_setting(&state.db, "plugins.disabled", &json!(disabled).to_string()).await?;
    session.audit(&state, "plugin.toggled", &id, if toggle.enabled { "enabled" } else { "disabled" }).await;
    Ok(Json(json!({ "id": id, "enabled": toggle.enabled })))
}

/// Serves the script of an enabled plug-in to signed-in users.
pub async fn plugin_script(State(state): State<AppState>, _session: Session, Path(id): Path<String>) -> Result<Response, ApiError> {
    if !valid_plugin_name(&id) || disabled_plugins(&state).await?.contains(&id) {
        return Err(ApiError::NotFound);
    }
    let path = state.cfg.data_dir.join("plugins").join(&id).join("plugin.js");
    let script = match tokio::fs::metadata(&path).await {
        Ok(meta) if meta.is_file() && meta.len() <= MAX_PLUGIN_BYTES => tokio::fs::read(&path).await?,
        _ => return Err(ApiError::NotFound),
    };
    let mut response = script.into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/javascript; charset=utf-8"));
    Ok(response)
}

// --- Webhooks ------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct WebhookInput {
    url: String,
    events: Vec<String>,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
}

fn enabled_by_default() -> bool {
    true
}

fn clean_webhook(input: &WebhookInput) -> Result<(String, String), ApiError> {
    let url = reqwest::Url::parse(input.url.trim()).map_err(|_| ApiError::bad("invalid URL"))?;
    if url.scheme() != "https" && !(url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))) {
        return Err(ApiError::bad("webhooks must use https (http is allowed for localhost only)"));
    }
    if input.events.is_empty() || input.events.iter().any(|e| !crate::webhooks::EVENTS.contains(&e.as_str())) {
        return Err(ApiError::bad(format!("events must be chosen from: {}", crate::webhooks::EVENTS.join(", "))));
    }
    Ok((url.to_string(), json!(input.events).to_string()))
}

pub async fn webhooks_list(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    session.require_super()?;
    let rows: Vec<(i64, String, String, bool, String, Option<i64>)> =
        sqlx::query_as("SELECT id, url, events, enabled, last_status, last_at FROM webhooks ORDER BY id").fetch_all(&state.db).await?;
    let hooks: Vec<Value> = rows
        .into_iter()
        .map(|(id, url, events, enabled, last_status, last_at)| {
            json!({ "id": id, "url": url, "events": serde_json::from_str::<Value>(&events).unwrap_or(json!([])), "enabled": enabled, "last_status": last_status, "last_at": last_at })
        })
        .collect();
    Ok(Json(json!({ "webhooks": hooks, "events": crate::webhooks::EVENTS })))
}

pub async fn webhook_create(State(state): State<AppState>, session: Session, Json(input): Json<WebhookInput>) -> JsonResult<Value> {
    session.require_super()?;
    let (url, events) = clean_webhook(&input)?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhooks").fetch_one(&state.db).await?;
    if count >= 20 {
        return Err(ApiError::Conflict("at most 20 webhooks can be configured".into()));
    }
    // The signing secret is shown once, when the webhook is created.
    let secret = crate::util::random_token();
    let id = sqlx::query("INSERT INTO webhooks (url, secret, events, enabled, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(&url)
        .bind(state.secrets.seal(&secret))
        .bind(&events)
        .bind(input.enabled)
        .bind(now())
        .execute(&state.db)
        .await?
        .last_insert_rowid();
    session.audit(&state, "webhook.created", &sanitize_line(&url), "").await;
    Ok(Json(json!({ "id": id, "url": url, "secret": secret })))
}

pub async fn webhook_update(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<WebhookInput>) -> JsonResult<Value> {
    session.require_super()?;
    let (url, events) = clean_webhook(&input)?;
    let changed = sqlx::query("UPDATE webhooks SET url = ?, events = ?, enabled = ? WHERE id = ?").bind(&url).bind(&events).bind(input.enabled).bind(id).execute(&state.db).await?.rows_affected();
    if changed == 0 { Err(ApiError::NotFound) } else { Ok(Json(json!({ "id": id, "url": url }))) }
}

pub async fn webhook_delete(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    session.require_super()?;
    let removed = sqlx::query("DELETE FROM webhooks WHERE id = ?").bind(id).execute(&state.db).await?.rows_affected();
    if removed == 0 {
        return Err(ApiError::NotFound);
    }
    session.audit(&state, "webhook.deleted", &id.to_string(), "").await;
    Ok(Json(json!({ "ok": true })))
}

/// Sends a `ping` event to one webhook and reports the outcome.
pub async fn webhook_test(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    session.require_super()?;
    let mut data = Map::new();
    data.insert("message".into(), json!("unoMail webhook test"));
    match crate::webhooks::deliver_to(&state, id, "ping", Value::Object(data)).await? {
        Some(status) => Ok(Json(json!({ "status": status }))),
        None => Err(ApiError::NotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skins_accept_only_known_design_tokens() {
        assert!(validate_skin(&json!({ "id": "ocean", "name": "Ocean", "mode": "dark", "primary": "#0061a4", "radius": 8, "density": "compact", "font": "system" })).is_ok());
        for bad in [
            json!("ocean"),
            json!({ "id": "Ocean", "name": "x" }),
            json!({ "id": "ocean", "name": "" }),
            json!({ "id": "ocean", "name": "x", "primary": "red" }),
            json!({ "id": "ocean", "name": "x", "primary": "url(https://evil.example/x)" }),
            json!({ "id": "ocean", "name": "x", "css": "body { display: none }" }),
            json!({ "id": "ocean", "name": "x", "radius": 999 }),
            json!({ "id": "ocean", "name": "x", "font": "https://evil.example/font.woff" }),
        ] {
            assert!(validate_skin(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn plugin_names_cannot_escape_the_plugin_directory() {
        assert!(valid_plugin_name("hello-world_2"));
        for bad in ["", "..", "../x", "a/b", "A", "a.b", "a b"] {
            assert!(!valid_plugin_name(bad), "{bad:?}");
        }
    }
}
