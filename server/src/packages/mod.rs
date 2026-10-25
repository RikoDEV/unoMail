//! Plug-in and theme packages, installed by an administrator from a git repository.
//!
//! An install is two steps. The preview fetches one commit into a staging directory and
//! validates its manifest, so the administrator sees exactly what will run and what it may do;
//! confirming moves that same checkout into place. Files live at
//! `<data>/plugins/<id>/<commit>/`, so an update never changes code in place.

pub mod frame;
pub mod git;
pub mod hooks;
pub mod manifest;
pub mod wasm;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use sqlx::SqlitePool;

use crate::{app::AppState, util::now};
use manifest::{Kind, Manifest};

const PREVIEW_LIFETIME: Duration = Duration::from_secs(15 * 60);
pub const MAX_STORAGE_BYTES: usize = 64 * 1024;
const MAX_PACKAGES: i64 = 50;

/// A fetched, validated checkout waiting for the administrator's confirmation.
struct Preview {
    url: String,
    git_ref: String,
    commit: String,
    manifest: Manifest,
    dir: PathBuf,
    /// Set when the preview updates an installed package.
    updates: Option<String>,
    created: Instant,
}

static PREVIEWS: Mutex<Option<HashMap<String, Preview>>> = Mutex::new(None);

pub fn root(data_dir: &Path) -> PathBuf {
    data_dir.join("plugins")
}

fn staging(data_dir: &Path) -> PathBuf {
    root(data_dir).join(".staging")
}

pub fn package_dir(data_dir: &Path, id: &str, commit: &str) -> PathBuf {
    root(data_dir).join(id).join(commit)
}

/// Drops previews nobody confirmed, with their checkouts.
fn expire(previews: &mut HashMap<String, Preview>) {
    previews.retain(|_, preview| {
        let keep = preview.created.elapsed() < PREVIEW_LIFETIME;
        if !keep {
            let _ = std::fs::remove_dir_all(&preview.dir);
        }
        keep
    });
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Installed {
    pub id: String,
    pub kind: String,
    pub source_url: String,
    pub git_ref: String,
    pub git_commit: String,
    pub manifest: String,
    pub enabled: bool,
    pub installed_at: i64,
    pub installed_by: String,
    pub admin_settings: String,
    pub fail_closed: bool,
}

impl Installed {
    pub fn manifest(&self) -> Value {
        serde_json::from_str(&self.manifest).unwrap_or(Value::Null)
    }

    /// The permissions in force: the manifest's, plus `network:<host>` for every host the
    /// administrator entered in a `host` setting.
    pub fn permissions(&self) -> Vec<String> {
        let manifest = self.manifest();
        let mut out: Vec<String> = manifest["permissions"].as_array().into_iter().flatten().filter_map(|p| p.as_str().map(str::to_owned)).collect();
        let stored: Value = serde_json::from_str(&self.admin_settings).unwrap_or(json!({}));
        for setting in manifest["settings"].as_array().into_iter().flatten().filter(|s| s["type"] == "host") {
            let key = setting["key"].as_str().unwrap_or_default();
            let host = stored.get(key).or_else(|| setting.get("default")).and_then(Value::as_str).filter(|h| manifest::valid_host(h));
            if let Some(host) = host {
                let permission = format!("network:{host}");
                if !out.contains(&permission) {
                    out.push(permission);
                }
            }
        }
        out
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id, "type": self.kind, "url": self.source_url, "ref": self.git_ref, "commit": self.git_commit,
            "manifest": self.manifest(), "enabled": self.enabled, "installedAt": self.installed_at, "installedBy": self.installed_by,
            "failClosed": self.fail_closed,
        })
    }
}

/// A theme's tokens as the client uses them: image paths become addresses of the package's files.
pub fn theme_for_client(id: &str, commit: &str, manifest: &Value) -> Value {
    let mut theme = manifest["theme"].clone();
    if let Some(images) = theme.get_mut("images").and_then(Value::as_object_mut) {
        for path in images.values_mut() {
            if let Some(file) = path.as_str() {
                *path = json!(format!("/package-asset/{id}/{commit}/{file}"));
            }
        }
    }
    theme
}

pub async fn list(db: &SqlitePool) -> sqlx::Result<Vec<Installed>> {
    sqlx::query_as("SELECT * FROM packages ORDER BY id").fetch_all(db).await
}

pub async fn get(db: &SqlitePool, id: &str) -> sqlx::Result<Option<Installed>> {
    sqlx::query_as("SELECT * FROM packages WHERE id = ?").bind(id).fetch_optional(db).await
}

/// Fetches `url` at `git_ref` and validates it, without installing anything.
pub async fn preview(state: &AppState, url: &str, git_ref: &str, updates: Option<&Installed>) -> Result<Value, String> {
    let git_ref = git_ref.trim();
    if !git::valid_ref(git_ref) {
        return Err("enter a tag, branch or commit".into());
    }
    let allow_local = state.cfg.packages_allow_local;
    let url = git::check_url(url, allow_local, state.cfg.allow_private_destinations).await?;
    let commit = git::resolve(&url, git_ref, allow_local).await?;
    let token = crate::util::random_token();
    let dir = staging(&state.cfg.data_dir).join(&token);
    let fetched = async {
        git::fetch(&url, git_ref, &commit, &dir, allow_local).await?;
        let bytes = tokio::fs::read(dir.join(manifest::FILE)).await.map_err(|_| format!("the repository has no {} at its root", manifest::FILE))?;
        let manifest = manifest::parse(&bytes)?;
        if let Some(entry) = manifest.value["entry"].as_str() {
            match tokio::fs::metadata(dir.join(entry)).await {
                Ok(meta) if meta.is_file() && meta.len() <= manifest::MAX_ENTRY_BYTES => {}
                Ok(meta) if meta.is_file() => return Err("the entry script is larger than 2 MB".into()),
                _ => return Err(format!("the entry script {entry} is missing")),
            }
        }
        // A server module must compile and use only the plug-in ABI before anyone sees it.
        let checked_dir = dir.clone();
        let checked = manifest.value.clone();
        tokio::task::spawn_blocking(move || wasm::check_package(&checked_dir, &checked)).await.map_err(|e| e.to_string())??;
        for path in manifest.value["theme"]["images"].as_object().into_iter().flat_map(|images| images.values()).filter_map(Value::as_str) {
            let media_type = manifest::image_type(path).ok_or("invalid image")?;
            match tokio::fs::metadata(dir.join(path)).await {
                Ok(meta) if meta.is_file() && meta.len() <= manifest::MAX_IMAGE_BYTES => {}
                Ok(meta) if meta.is_file() => return Err(format!("the image {path} is larger than 2 MB")),
                _ => return Err(format!("the image {path} is missing")),
            }
            let bytes = tokio::fs::read(dir.join(path)).await.map_err(|e| e.to_string())?;
            if !manifest::image_matches(media_type, &bytes) {
                return Err(format!("{path} is not the image its name says"));
            }
        }
        Ok::<_, String>(manifest)
    }
    .await;
    let manifest = match fetched {
        Ok(manifest) => manifest,
        Err(err) => {
            let _ = tokio::fs::remove_dir_all(&dir).await;
            return Err(err);
        }
    };
    let added = match updates {
        Some(installed) if installed.id != manifest.id => {
            let _ = tokio::fs::remove_dir_all(&dir).await;
            return Err(format!("this repository now contains a different package ({})", manifest.id));
        }
        Some(installed) => json!(manifest::added_permissions(&installed.manifest(), &manifest.value)),
        None => json!(manifest.value["permissions"].as_array().cloned().unwrap_or_default()),
    };
    let out = json!({
        "token": token, "url": url, "ref": git_ref, "commit": commit, "manifest": manifest.value,
        "update": updates.map(|i| json!({ "from": i.git_commit, "fromVersion": i.manifest()["version"] })),
        "newPermissions": added,
    });
    let mut previews = PREVIEWS.lock().unwrap_or_else(|e| e.into_inner());
    let previews = previews.get_or_insert_with(HashMap::new);
    expire(previews);
    previews.insert(token, Preview { url, git_ref: git_ref.to_owned(), commit, manifest, dir, updates: updates.map(|i| i.id.clone()), created: Instant::now() });
    Ok(out)
}

pub enum ConfirmError {
    Gone,
    Conflict(String),
    Failed(String),
}

/// Installs (or updates to) the checkout a preview fetched.
pub async fn confirm(state: &AppState, token: &str, by: &str) -> Result<Installed, ConfirmError> {
    let preview = {
        let mut previews = PREVIEWS.lock().unwrap_or_else(|e| e.into_inner());
        let previews = previews.get_or_insert_with(HashMap::new);
        expire(previews);
        previews.remove(token).ok_or(ConfirmError::Gone)?
    };
    let id = preview.manifest.id.clone();
    let existing = get(&state.db, &id).await.map_err(|e| ConfirmError::Failed(e.to_string()))?;
    let discard = |message: String| {
        let _ = std::fs::remove_dir_all(&preview.dir);
        message
    };
    match (&existing, &preview.updates) {
        (Some(_), None) => return Err(ConfirmError::Conflict(discard(format!("a package named {id} is already installed")))),
        (None, Some(_)) => return Err(ConfirmError::Gone),
        (None, None) => {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM packages").fetch_one(&state.db).await.map_err(|e| ConfirmError::Failed(e.to_string()))?;
            if count >= MAX_PACKAGES {
                return Err(ConfirmError::Conflict(discard(format!("at most {MAX_PACKAGES} packages can be installed"))));
            }
        }
        (Some(_), Some(_)) => {}
    }
    let target = package_dir(&state.cfg.data_dir, &id, &preview.commit);
    if tokio::fs::metadata(&target).await.is_err() {
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| ConfirmError::Failed(e.to_string()))?;
        }
        tokio::fs::rename(&preview.dir, &target).await.map_err(|e| ConfirmError::Failed(discard(e.to_string())))?;
    } else {
        let _ = tokio::fs::remove_dir_all(&preview.dir).await;
    }
    let manifest = preview.manifest.value.to_string();
    let kind = preview.manifest.kind.as_str();
    let result = match &existing {
        // A theme is ready as soon as it is installed; a plug-in runs code, so it waits for
        // the administrator to make it available.
        None => sqlx::query("INSERT INTO packages (id, kind, source_url, git_ref, git_commit, manifest, enabled, installed_at, installed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(&id)
            .bind(kind)
            .bind(&preview.url)
            .bind(&preview.git_ref)
            .bind(&preview.commit)
            .bind(&manifest)
            .bind(preview.manifest.kind == Kind::Theme)
            .bind(now())
            .bind(by)
            .execute(&state.db)
            .await,
        Some(_) => sqlx::query("UPDATE packages SET kind = ?, source_url = ?, git_ref = ?, git_commit = ?, manifest = ?, installed_at = ?, installed_by = ? WHERE id = ?")
            .bind(kind)
            .bind(&preview.url)
            .bind(&preview.git_ref)
            .bind(&preview.commit)
            .bind(&manifest)
            .bind(now())
            .bind(by)
            .bind(&id)
            .execute(&state.db)
            .await,
    };
    result.map_err(|e| ConfirmError::Failed(e.to_string()))?;
    wasm::forget(&id);
    // The previous commit is removed only once the new one is recorded.
    if let Some(old) = existing.filter(|old| old.git_commit != preview.commit) {
        let _ = tokio::fs::remove_dir_all(package_dir(&state.cfg.data_dir, &id, &old.git_commit)).await;
    }
    get(&state.db, &id).await.map_err(|e| ConfirmError::Failed(e.to_string()))?.ok_or(ConfirmError::Gone)
}

/// Removes a package, its files and every user's settings and data for it.
pub async fn remove(state: &AppState, id: &str) -> sqlx::Result<bool> {
    let removed = sqlx::query("DELETE FROM packages WHERE id = ?").bind(id).execute(&state.db).await?.rows_affected() > 0;
    wasm::forget(id);
    if removed && manifest::valid_id(id) {
        let _ = tokio::fs::remove_dir_all(root(&state.cfg.data_dir).join(id)).await;
    }
    Ok(removed)
}

pub async fn set_enabled(db: &SqlitePool, id: &str, enabled: bool) -> sqlx::Result<bool> {
    Ok(sqlx::query("UPDATE packages SET enabled = ? WHERE id = ?").bind(enabled).bind(id).execute(db).await?.rows_affected() > 0)
}

/// Whether a newer commit is available for the installed ref.
pub async fn check_update(state: &AppState, installed: &Installed) -> Result<Option<String>, String> {
    let commit = git::resolve(&installed.source_url, &installed.git_ref, state.cfg.packages_allow_local).await?;
    Ok((commit != installed.git_commit).then_some(commit))
}

// --- Per-user state ------------------------------------------------------------------------

#[derive(sqlx::FromRow, Default)]
pub struct UserState {
    pub enabled: bool,
    pub settings: String,
    pub storage: String,
}

pub async fn user_state(db: &SqlitePool, id: &str, account: i64) -> sqlx::Result<UserState> {
    Ok(sqlx::query_as("SELECT enabled, settings, storage FROM package_users WHERE package_id = ? AND account_id = ?").bind(id).bind(account).fetch_optional(db).await?.unwrap_or_default())
}

/// Checks a user's settings against what the manifest declares. Secret values are sealed;
/// a secret left empty keeps its stored value.
pub fn clean_settings(declared: &Value, scope: &str, input: &Value, previous: &Value, seal: impl Fn(&str) -> String) -> Result<Value, String> {
    let input = input.as_object().ok_or("settings must be an object")?;
    let declared: Vec<Value> = declared.as_array().into_iter().flatten().filter(|d| setting_scope(d) == scope).cloned().collect();
    if let Some(key) = input.keys().find(|k| !declared.iter().any(|d| d["key"].as_str() == Some(k.as_str()))) {
        return Err(format!("unknown setting: {}", crate::util::sanitize_line(key)));
    }
    let mut out = serde_json::Map::new();
    for setting in &declared {
        let key = setting["key"].as_str().unwrap_or_default();
        let Some(value) = input.get(key) else {
            if let Some(old) = previous.get(key) {
                out.insert(key.to_owned(), old.clone());
            }
            continue;
        };
        let ok = match setting["type"].as_str() {
            Some("string") => value.as_str().is_some_and(|s| s.len() <= 2000),
            Some("boolean") => value.is_boolean(),
            Some("select") => setting["options"].as_array().is_some_and(|o| o.contains(value)),
            Some("host") => value.as_str().is_some_and(|h| h.is_empty() || manifest::valid_host(h)),
            _ => false,
        };
        if !ok {
            return Err(format!("invalid value for {}", crate::util::sanitize_line(key)));
        }
        if setting["secret"] == true {
            match value.as_str() {
                Some("") => {
                    if let Some(old) = previous.get(key) {
                        out.insert(key.to_owned(), old.clone());
                    }
                }
                Some(secret) => {
                    out.insert(key.to_owned(), json!({ "sealed": seal(secret) }));
                }
                None => {}
            }
        } else {
            out.insert(key.to_owned(), value.clone());
        }
    }
    Ok(Value::Object(out))
}

fn setting_scope(setting: &Value) -> &str {
    setting["scope"].as_str().unwrap_or("user")
}

/// Stored settings of one scope as their reader receives them: defaults filled in, secrets
/// opened when `secrets` is set and left out otherwise.
pub fn open_settings(declared: &Value, scope: &str, stored: &Value, secrets: bool, open: impl Fn(&str) -> Option<String>) -> Value {
    let mut out = serde_json::Map::new();
    for setting in declared.as_array().into_iter().flatten().filter(|d| setting_scope(d) == scope) {
        let key = setting["key"].as_str().unwrap_or_default();
        if setting["secret"] == true && !secrets {
            continue;
        }
        let value = match stored.get(key) {
            Some(Value::Object(sealed)) => sealed.get("sealed").and_then(Value::as_str).and_then(&open).map(Value::String),
            Some(value) => Some(value.clone()),
            None => None,
        };
        out.insert(key.to_owned(), value.or_else(|| setting.get("default").cloned()).unwrap_or(Value::Null));
    }
    Value::Object(out)
}

pub async fn save_admin(db: &SqlitePool, id: &str, settings: &Value, fail_closed: bool) -> sqlx::Result<()> {
    sqlx::query("UPDATE packages SET admin_settings = ?, fail_closed = ? WHERE id = ?").bind(settings.to_string()).bind(fail_closed).bind(id).execute(db).await?;
    Ok(())
}

pub async fn save_user(db: &SqlitePool, id: &str, account: i64, enabled: bool, settings: &Value) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO package_users (package_id, account_id, enabled, settings) VALUES (?, ?, ?, ?) \
         ON CONFLICT(package_id, account_id) DO UPDATE SET enabled = excluded.enabled, settings = excluded.settings",
    )
    .bind(id)
    .bind(account)
    .bind(enabled)
    .bind(settings.to_string())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn save_storage(db: &SqlitePool, id: &str, account: i64, data: &Value) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO package_users (package_id, account_id, storage) VALUES (?, ?, ?) ON CONFLICT(package_id, account_id) DO UPDATE SET storage = excluded.storage")
        .bind(id)
        .bind(account)
        .bind(data.to_string())
        .execute(db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_follow_the_manifest_and_seal_secrets() {
        let declared = json!([
            { "key": "token", "type": "string", "label": "Token", "secret": true },
            { "key": "lang", "type": "select", "label": "Language", "options": ["en", "pl"] },
        ]);
        let seal = |s: &str| format!("sealed({s})");
        let saved = clean_settings(&declared, "user", &json!({ "token": "abc", "lang": "pl" }), &json!({}), seal).unwrap();
        assert_eq!(saved, json!({ "token": { "sealed": "sealed(abc)" }, "lang": "pl" }));
        // An empty secret keeps the stored one.
        assert_eq!(clean_settings(&declared, "user", &json!({ "token": "" }), &saved, seal).unwrap()["token"], saved["token"]);
        assert!(clean_settings(&declared, "user", &json!({ "lang": "de" }), &json!({}), seal).is_err());
        assert!(clean_settings(&declared, "user", &json!({ "other": 1 }), &json!({}), seal).is_err());
        // Each scope sees only its own settings.
        assert!(clean_settings(&declared, "admin", &json!({ "lang": "pl" }), &json!({}), seal).is_err());
        let open = |s: &str| s.strip_prefix("sealed(").and_then(|s| s.strip_suffix(')')).map(str::to_owned);
        assert_eq!(open_settings(&declared, "user", &saved, true, open), json!({ "token": "abc", "lang": "pl" }));
        assert_eq!(open_settings(&declared, "user", &saved, false, open), json!({ "lang": "pl" }));
    }
}
