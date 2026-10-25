//! The package manifest, `unomail.json`: what a plug-in or theme is and what it may do.
//!
//! Everything a package declares is checked here, before an administrator is even asked to
//! approve it. Unknown keys and permissions are refused rather than ignored, so a manifest
//! written for a newer API never silently gains or loses capabilities.

use serde_json::{Map, Value, json};

use crate::util::sanitize_line;

pub const FILE: &str = "unomail.json";
pub const SCHEMA: u64 = 2;
/// The plug-in API this server provides; packages state the major version they target.
pub const API_MAJOR: u64 = 2;
pub const MAX_ENTRY_BYTES: u64 = 2 * 1024 * 1024;
const MAX_SETTINGS: usize = 20;

/// Permissions a plug-in may ask for; `network:<host>` is checked separately.
pub const PERMISSIONS: &[&str] = &[
    // In the web client.
    "message:read",
    "composer:read",
    "composer:write",
    "sidebar",
    "panel",
    "storage",
    "notify",
    "attachments:read",
    "auth",
    "ui:widget",
    "ui:page",
    "ui:admin",
    "ui:replace",
    // On the server (`server` in the manifest).
    "server:mail-incoming",
    "server:mail-outgoing",
    "server:mail-body",
    "server:routes",
    "server:storage",
];

/// Server hooks and the permission each needs.
pub const HOOKS: &[(&str, &str)] = &[("mail:incoming", "server:mail-incoming"), ("mail:outgoing", "server:mail-outgoing")];
pub const MAX_MODULE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    pub id: String,
    pub kind: Kind,
    /// The manifest as it should be shown and stored: only known, validated keys.
    pub value: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Plugin,
    Theme,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Plugin => "plugin",
            Kind::Theme => "theme",
        }
    }
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 40 && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') && !id.starts_with('-')
}

/// A relative path inside the package, without any way to leave it.
pub fn valid_entry(path: &str) -> bool {
    valid_path(path) && path.ends_with(".js")
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 100
        && path.split('/').all(|part| !part.is_empty() && part != "." && part != ".." && part.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
}

/// Where a theme may show a background image.
pub const IMAGE_PLACES: &[&str] = &["page", "sidebar", "login"];
pub const MAX_IMAGE_BYTES: u64 = 2 * 1024 * 1024;

/// The media type of an image file a theme may ship, from its extension.
pub fn image_type(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    if !valid_path(path) {
        None
    } else if lower.ends_with(".png") {
        Some("image/png")
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        Some("image/jpeg")
    } else if lower.ends_with(".webp") {
        Some("image/webp")
    } else {
        None
    }
}

/// Whether the file starts like the image type its name claims.
pub fn image_matches(media_type: &str, bytes: &[u8]) -> bool {
    match media_type {
        "image/png" => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg" => bytes.starts_with(&[0xff, 0xd8, 0xff]),
        "image/webp" => bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP",
        _ => false,
    }
}

/// A host a plug-in may connect to: a plain DNS name, never an address or a wildcard.
pub fn valid_host(host: &str) -> bool {
    host.len() <= 253
        && host.contains('.')
        && host.split('.').all(|label| !label.is_empty() && label.len() <= 63 && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
        && !host.split('.').next_back().is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
}

fn text(object: &Map<String, Value>, key: &str, max: usize, required: bool) -> Result<Option<String>, String> {
    match object.get(key) {
        None if required => Err(format!("{key} is required")),
        None => Ok(None),
        Some(Value::String(s)) if !s.trim().is_empty() && s.chars().count() <= max && !s.chars().any(char::is_control) => Ok(Some(s.trim().to_owned())),
        Some(_) => Err(format!("{key} must be text of at most {max} characters")),
    }
}

fn settings(value: &Value) -> Result<Value, String> {
    let list = value.as_array().ok_or("settings must be a list")?;
    if list.len() > MAX_SETTINGS {
        return Err(format!("at most {MAX_SETTINGS} settings are allowed"));
    }
    let mut keys = std::collections::HashSet::new();
    let mut out = Vec::new();
    for item in list {
        let object = item.as_object().ok_or("each setting must be an object")?;
        if let Some(key) = object.keys().find(|k| !matches!(k.as_str(), "key" | "type" | "label" | "secret" | "options" | "default" | "scope")) {
            return Err(format!("unknown setting property: {}", sanitize_line(key)));
        }
        let key = text(object, "key", 40, true)?.unwrap_or_default();
        if !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') || !keys.insert(key.clone()) {
            return Err("setting keys must be unique and use letters, digits and '_'".into());
        }
        let label = text(object, "label", 80, true)?;
        let kind = object.get("type").and_then(Value::as_str).ok_or("each setting needs a type")?;
        let scope = match object.get("scope").map(|s| s.as_str()) {
            None | Some(Some("user")) => "user",
            Some(Some("admin")) => "admin",
            _ => return Err("scope must be \"user\" or \"admin\"".into()),
        };
        let mut setting = json!({ "key": key, "type": kind, "label": label, "scope": scope });
        match kind {
            "string" => {
                if let Some(default) = object.get("default") {
                    setting["default"] = json!(default.as_str().filter(|s| s.len() <= 500).ok_or("a string default must be short text")?);
                }
            }
            "boolean" => {
                if let Some(default) = object.get("default") {
                    setting["default"] = json!(default.as_bool().ok_or("a boolean default must be true or false")?);
                }
            }
            // A server the administrator names (a self-hosted cloud, say): the plug-in may then
            // connect to it as if it had declared `network:<host>`.
            "host" => {
                if scope != "admin" {
                    return Err("host settings are for administrators (scope \"admin\")".into());
                }
                if let Some(default) = object.get("default") {
                    setting["default"] = json!(default.as_str().filter(|d| valid_host(d)).ok_or("a host default must be a host name")?);
                }
            }
            "select" => {
                let options = object.get("options").and_then(Value::as_array).filter(|o| !o.is_empty() && o.len() <= 20).ok_or("a select setting needs 1 to 20 options")?;
                let options: Vec<&str> = options.iter().map(|o| o.as_str().filter(|s| !s.is_empty() && s.len() <= 80)).collect::<Option<_>>().ok_or("select options must be short text")?;
                setting["options"] = json!(options);
                if let Some(default) = object.get("default") {
                    let default = default.as_str().filter(|d| options.contains(d)).ok_or("a select default must be one of its options")?;
                    setting["default"] = json!(default);
                }
            }
            _ => return Err(format!("unknown setting type: {}", sanitize_line(kind))),
        }
        if let Some(secret) = object.get("secret") {
            let secret = secret.as_bool().ok_or("secret must be true or false")?;
            if secret && kind != "string" {
                return Err("only string settings can be secret".into());
            }
            setting["secret"] = json!(secret);
        }
        out.push(setting);
    }
    Ok(Value::Array(out))
}

pub fn parse(bytes: &[u8]) -> Result<Manifest, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| format!("{FILE} is not valid JSON"))?;
    let object = value.as_object().ok_or(format!("{FILE} must be an object"))?;
    let allowed = ["schema", "id", "type", "name", "version", "description", "author", "homepage", "license", "api", "entry", "permissions", "settings", "server", "theme"];
    if let Some(key) = object.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("unknown manifest property: {}", sanitize_line(key)));
    }
    if object.get("schema").and_then(Value::as_u64) != Some(SCHEMA) {
        return Err(format!("schema must be {SCHEMA}"));
    }
    let id = text(object, "id", 40, true)?.unwrap_or_default();
    if !valid_id(&id) {
        return Err("the id may contain lowercase letters, digits and '-'".into());
    }
    let kind = match object.get("type").and_then(Value::as_str) {
        Some("plugin") => Kind::Plugin,
        Some("theme") => Kind::Theme,
        _ => return Err("type must be \"plugin\" or \"theme\"".into()),
    };
    let version = text(object, "version", 30, true)?.unwrap_or_default();
    if !version.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+')) {
        return Err("version may contain letters, digits, '.', '-' and '+'".into());
    }
    let mut out = json!({
        "schema": SCHEMA,
        "id": id,
        "type": kind.as_str(),
        "name": text(object, "name", 60, true)?,
        "version": version,
    });
    for (key, max) in [("description", 300), ("author", 100), ("license", 40)] {
        if let Some(value) = text(object, key, max, false)? {
            out[key] = json!(value);
        }
    }
    if let Some(homepage) = text(object, "homepage", 300, false)? {
        if reqwest::Url::parse(&homepage).map_or(true, |u| u.scheme() != "https") {
            return Err("homepage must be an https address".into());
        }
        out["homepage"] = json!(homepage);
    }

    match kind {
        Kind::Plugin => {
            if object.contains_key("theme") {
                return Err("a plug-in cannot carry a theme".into());
            }
            let api = object.get("api").and_then(Value::as_str).ok_or("api is required, for example \"^2\"")?;
            if api.strip_prefix('^').and_then(|v| v.split('.').next()).and_then(|v| v.parse::<u64>().ok()) != Some(API_MAJOR) {
                return Err(format!("this server provides plug-in API {API_MAJOR} (\"^{API_MAJOR}\")"));
            }
            out["api"] = json!(api);
            // A plug-in runs in the web client (`entry`), on the server (`server`), or both.
            if let Some(entry) = object.get("entry") {
                let entry = entry.as_str().filter(|e| valid_entry(e)).ok_or("entry must be a relative path to a .js file")?;
                out["entry"] = json!(entry);
            }
            let mut permissions: Vec<String> = Vec::new();
            for permission in object.get("permissions").map_or(Ok(&Vec::new()), |p| p.as_array().ok_or("permissions must be a list"))? {
                let permission = permission.as_str().ok_or("permissions must be text")?;
                let known = PERMISSIONS.contains(&permission) || permission.strip_prefix("network:").is_some_and(valid_host);
                if !known {
                    return Err(format!("unknown permission: {}", sanitize_line(permission)));
                }
                if !permissions.iter().any(|p| p == permission) {
                    permissions.push(permission.to_owned());
                }
            }
            if permissions.iter().filter(|p| p.starts_with("network:")).count() > 10 {
                return Err("at most 10 network hosts are allowed".into());
            }
            if let Some(server) = object.get("server") {
                out["server"] = server_part(server, &permissions)?;
            }
            if out.get("entry").is_none() && out.get("server").is_none() {
                return Err("a plug-in needs an entry script, a server module, or both".into());
            }
            out["permissions"] = json!(permissions);
            out["settings"] = object.get("settings").map_or(Ok(json!([])), settings)?;
        }
        Kind::Theme => {
            for key in ["api", "entry", "permissions", "settings", "server"] {
                if object.contains_key(key) {
                    return Err(format!("a theme cannot declare {key}"));
                }
            }
            let mut theme = object.get("theme").and_then(Value::as_object).cloned().ok_or("a theme needs its design tokens under \"theme\"")?;
            if theme.contains_key("id") || theme.contains_key("name") {
                return Err("theme tokens take their id and name from the manifest".into());
            }
            // Images are files of the package; checked here by name, at install by content.
            let images = theme.remove("images");
            theme.insert("id".into(), json!(id));
            theme.insert("name".into(), out["name"].clone());
            let mut theme = Value::Object(theme);
            crate::api::extend::validate_skin(&theme)?;
            if let Some(images) = images {
                let images = images.as_object().ok_or("images must be an object")?;
                for (place, path) in images {
                    if !IMAGE_PLACES.contains(&place.as_str()) {
                        return Err(format!("unknown image place: {}", sanitize_line(place)));
                    }
                    if path.as_str().and_then(image_type).is_none() {
                        return Err(format!("the {place} image must be a .png, .jpg or .webp file in the package"));
                    }
                }
                theme["images"] = Value::Object(images.clone());
            }
            out["theme"] = theme;
        }
    }
    Ok(Manifest { id, kind, value: out })
}

static NONE: Vec<Value> = Vec::new();

/// The `server` part of a plug-in: its WebAssembly module and what it hooks into. Each hook
/// needs its permission, so the administrator approving the package sees all of it.
fn server_part(value: &Value, permissions: &[String]) -> Result<Value, String> {
    let object = value.as_object().ok_or("server must be an object")?;
    if let Some(key) = object.keys().find(|k| !matches!(k.as_str(), "module" | "hooks" | "routes" | "schedule")) {
        return Err(format!("unknown server property: {}", sanitize_line(key)));
    }
    let module = object.get("module").and_then(Value::as_str).ok_or("server.module is required")?;
    if !valid_path(module) || !(module.ends_with(".wasm") || module.ends_with(".wat")) {
        return Err("server.module must be a relative path to a .wasm or .wat file".into());
    }
    let has = |permission: &str| permissions.iter().any(|p| p == permission);
    let mut hooks = Vec::new();
    for hook in object.get("hooks").map_or(Ok(&NONE), |h| h.as_array().ok_or("server.hooks must be a list"))? {
        let hook = hook.as_str().ok_or("hooks must be text")?;
        let (_, needs) = HOOKS.iter().find(|(name, _)| *name == hook).ok_or_else(|| format!("unknown hook: {}", sanitize_line(hook)))?;
        if !has(needs) {
            return Err(format!("the {hook} hook needs the {needs} permission"));
        }
        if !hooks.contains(&hook) {
            hooks.push(hook);
        }
    }
    let routes = match object.get("routes") {
        None => false,
        Some(Value::Bool(routes)) => *routes,
        Some(_) => return Err("server.routes must be true or false".into()),
    };
    if routes && !has("server:routes") {
        return Err("server routes need the server:routes permission".into());
    }
    if has("server:mail-body") && hooks.is_empty() {
        return Err("server:mail-body is only useful with a mail hook".into());
    }
    let mut schedule = Vec::new();
    for job in object.get("schedule").map_or(Ok(&NONE), |s| s.as_array().ok_or("server.schedule must be a list"))? {
        let job = job.as_object().ok_or("each scheduled job must be an object")?;
        let id = job.get("id").and_then(Value::as_str).filter(|id| valid_id(id)).ok_or("each scheduled job needs an id")?;
        let every = job.get("everyMinutes").and_then(Value::as_u64).filter(|m| (5..=10_080).contains(m)).ok_or("everyMinutes must be 5 to 10080")?;
        schedule.push(json!({ "id": id, "everyMinutes": every }));
    }
    if schedule.len() > 5 {
        return Err("at most 5 scheduled jobs are allowed".into());
    }
    Ok(json!({ "module": module, "hooks": hooks, "routes": routes, "schedule": schedule }))
}

/// Permissions added by `new` compared with `old`, which an update must have approved.
pub fn added_permissions(old: &Value, new: &Value) -> Vec<String> {
    let list = |v: &Value| v["permissions"].as_array().map(|a| a.iter().filter_map(|p| p.as_str().map(str::to_owned)).collect::<Vec<_>>()).unwrap_or_default();
    let before = list(old);
    list(new).into_iter().filter(|p| !before.contains(p)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin(extra: Value) -> Vec<u8> {
        let mut base = json!({ "schema": 2, "id": "hello", "type": "plugin", "name": "Hello", "version": "1.0.0", "api": "^2", "entry": "index.js" });
        for (key, value) in extra.as_object().unwrap() {
            base[key] = value.clone();
        }
        serde_json::to_vec(&base).unwrap()
    }

    #[test]
    fn a_valid_plugin_keeps_only_known_fields() {
        let manifest = parse(&plugin(json!({ "permissions": ["notify", "network:api.example.com", "notify"], "settings": [{ "key": "token", "type": "string", "label": "Token", "secret": true }] }))).unwrap();
        assert_eq!(manifest.kind, Kind::Plugin);
        assert_eq!(manifest.value["permissions"], json!(["notify", "network:api.example.com"]));
        assert_eq!(manifest.value["settings"][0]["secret"], json!(true));
    }

    #[test]
    fn unsafe_or_unknown_declarations_are_refused() {
        for extra in [
            json!({ "permissions": ["everything"] }),
            json!({ "permissions": ["network:127.0.0.1"] }),
            json!({ "permissions": ["network:*.example.com"] }),
            json!({ "permissions": ["network:https://example.com"] }),
            json!({ "entry": "../server.js" }),
            json!({ "entry": "/etc/passwd.js" }),
            json!({ "entry": "index.html" }),
            json!({ "api": "^1" }),
            json!({ "id": "../x" }),
            json!({ "homepage": "javascript:alert(1)" }),
            json!({ "css": "body {}" }),
            json!({ "theme": { "primary": "#000000" } }),
            json!({ "settings": [{ "key": "a", "type": "boolean", "label": "A", "secret": true }] }),
            json!({ "settings": [{ "key": "a", "type": "html", "label": "A" }] }),
        ] {
            assert!(parse(&plugin(extra.clone())).is_err(), "{extra}");
        }
    }

    #[test]
    fn themes_are_design_tokens_only() {
        let theme = |tokens: Value| serde_json::to_vec(&json!({ "schema": 2, "id": "ocean", "type": "theme", "name": "Ocean", "version": "1", "theme": tokens })).unwrap();
        let manifest = parse(&theme(json!({ "mode": "dark", "primary": "#0061a4" }))).unwrap();
        assert_eq!(manifest.value["theme"]["id"], json!("ocean"));
        assert!(parse(&theme(json!({ "primary": "url(https://evil.example)" }))).is_err());
        assert!(parse(&theme(json!({ "css": "body { display: none }" }))).is_err());
        assert!(parse(&theme(json!({ "images": { "page": "art/bg.webp" } }))).is_ok());
        for bad in [json!({ "page": "https://evil.example/x.png" }), json!({ "page": "../x.png" }), json!({ "page": "bg.svg" }), json!({ "header": "bg.png" })] {
            assert!(parse(&theme(json!({ "images": bad }))).is_err(), "{bad}");
        }
        assert!(image_matches("image/png", b"\x89PNG\r\n\x1a\n...") && !image_matches("image/png", b"<svg"));
    }

    #[test]
    fn the_examples_are_valid_packages() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/examples");
        let mut seen = 0;
        for kind in ["plugins", "themes"] {
            for entry in std::fs::read_dir(root.join(kind)).unwrap() {
                let dir = entry.unwrap().path();
                let manifest = parse(&std::fs::read(dir.join(FILE)).unwrap()).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
                assert_eq!(dir.file_name().unwrap().to_str(), Some(manifest.id.as_str()));
                if let Some(entry) = manifest.value["entry"].as_str() {
                    assert!(dir.join(entry).is_file(), "{}", dir.display());
                }
                super::super::wasm::check_package(&dir, &manifest.value).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
                for image in manifest.value["theme"]["images"].as_object().into_iter().flat_map(|i| i.values()) {
                    let path = image.as_str().unwrap();
                    assert!(image_matches(image_type(path).unwrap(), &std::fs::read(dir.join(path)).unwrap()), "{path}");
                }
                seen += 1;
            }
        }
        assert_eq!(seen, 7);
    }

    #[test]
    fn server_hooks_need_their_permissions() {
        let server = |permissions: Value, server: Value| parse(&plugin(json!({ "permissions": permissions, "server": server })));
        assert!(server(json!(["server:mail-incoming", "server:routes"]), json!({ "module": "server.wat", "hooks": ["mail:incoming"], "routes": true })).is_ok());
        assert!(server(json!([]), json!({ "module": "server.wat", "hooks": ["mail:incoming"] })).is_err());
        assert!(server(json!([]), json!({ "module": "server.wat", "routes": true })).is_err());
        assert!(server(json!(["server:mail-incoming"]), json!({ "module": "server.wat", "hooks": ["mail:everything"] })).is_err());
        assert!(server(json!([]), json!({ "module": "../server.wasm" })).is_err());
        assert!(server(json!([]), json!({ "module": "server.wasm", "schedule": [{ "id": "x", "everyMinutes": 1 }] })).is_err());
        // A server-only plug-in needs no entry script.
        let only = json!({ "schema": 2, "id": "tagger", "type": "plugin", "name": "T", "version": "1", "api": "^2", "server": { "module": "server.wat" } });
        assert!(parse(&serde_json::to_vec(&only).unwrap()).unwrap().value.get("entry").is_none());
    }

    #[test]
    fn host_settings_are_for_administrators_and_hold_host_names() {
        assert!(parse(&plugin(json!({ "settings": [{ "key": "server", "type": "host", "label": "Server", "scope": "admin" }] }))).is_ok());
        assert!(parse(&plugin(json!({ "settings": [{ "key": "server", "type": "host", "label": "Server" }] }))).is_err());
        assert!(parse(&plugin(json!({ "settings": [{ "key": "server", "type": "host", "label": "Server", "scope": "admin", "default": "127.0.0.1" }] }))).is_err());
    }

    #[test]
    fn settings_have_a_scope() {
        let manifest = parse(&plugin(json!({ "settings": [{ "key": "a", "type": "string", "label": "A" }, { "key": "b", "type": "string", "label": "B", "scope": "admin" }] }))).unwrap();
        assert_eq!(manifest.value["settings"][0]["scope"], "user");
        assert_eq!(manifest.value["settings"][1]["scope"], "admin");
        assert!(parse(&plugin(json!({ "settings": [{ "key": "a", "type": "string", "label": "A", "scope": "everyone" }] }))).is_err());
    }

    #[test]
    fn updates_report_new_permissions() {
        let old = json!({ "permissions": ["notify"] });
        let new = json!({ "permissions": ["notify", "storage"] });
        assert_eq!(added_permissions(&old, &new), vec!["storage".to_owned()]);
    }
}
