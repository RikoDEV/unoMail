//! Plug-in and theme packages installed from git, end to end through the API.

mod common;

use std::path::Path;

use axum::http::StatusCode;
use common::{Api, Client, TestEnv, message};
use serde_json::{Value, json};
use unomail::auth::Role;

/// Runs git in `dir` with a fixed identity, so commits work without any user configuration.
fn git(dir: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .current_dir(dir)
        .args(["-c", "user.name=Test", "-c", "user.email=test@example.org", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])
        .args(args)
        .output()
        .expect("git is installed");
    assert!(output.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A repository holding `files`, committed and tagged `tag`; returns its `file://` address.
fn repository(dir: &Path, files: &[(&str, &str)], tag: &str) -> String {
    std::fs::create_dir_all(dir).unwrap();
    if !dir.join(".git").exists() {
        git(dir, &["init", "--quiet", "--initial-branch=main"]);
    }
    for (name, content) in files {
        std::fs::write(dir.join(name), content).unwrap();
    }
    git(dir, &["add", "--all"]);
    git(dir, &["commit", "--quiet", "--message", tag]);
    git(dir, &["tag", tag]);
    reqwest::Url::from_directory_path(dir).unwrap().to_string()
}

fn manifest(version: &str, permissions: Value) -> String {
    json!({
        "schema": 2, "id": "hello", "type": "plugin", "name": "Hello", "version": version, "api": "^2", "entry": "index.js",
        "permissions": permissions,
        "settings": [{ "key": "token", "type": "string", "label": "Token", "secret": true }],
    })
    .to_string()
}

#[tokio::test]
async fn plugins_install_from_git_and_run_sandboxed() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let repos = tempfile::tempdir().unwrap();
    let url = repository(&repos.path().join("hello"), &[("unomail.json", &manifest("1.0.0", json!(["notify"]))), ("index.js", "unomail.notify('hello');")], "v1.0.0");

    // Only administrators may fetch packages, and only from acceptable addresses.
    assert_eq!(bob.post("/api/packages/preview", json!({ "url": url, "ref": "v1.0.0" })).await.status, StatusCode::FORBIDDEN);
    for (bad_url, bad_ref) in [(url.as_str(), "--upload-pack=touch /tmp/x"), ("ext::sh -c id", "main"), (url.as_str(), "missing-tag")] {
        assert_eq!(admin.post("/api/packages/preview", json!({ "url": bad_url, "ref": bad_ref })).await.status, StatusCode::BAD_REQUEST, "{bad_url} {bad_ref}");
    }

    let preview = admin.post("/api/packages/preview", json!({ "url": url, "ref": "v1.0.0" })).await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.text);
    assert_eq!(preview.body["manifest"]["name"], "Hello");
    assert_eq!(preview.body["newPermissions"], json!(["notify"]));
    let commit = preview.body["commit"].as_str().unwrap().to_owned();
    assert_eq!(commit.len(), 40);

    let installed = admin.post("/api/packages", json!({ "token": preview.body["token"] })).await;
    assert_eq!(installed.status, StatusCode::OK, "{}", installed.text);
    assert_eq!(installed.body["enabled"], false, "a plug-in waits for the administrator");
    assert_eq!(admin.post("/api/packages", json!({ "token": preview.body["token"] })).await.status, StatusCode::BAD_REQUEST, "a preview is used once");
    assert!(env.app.cfg.data_dir.join("plugins/hello").join(&commit).join("index.js").exists());
    assert!(!env.app.cfg.data_dir.join("plugins/hello").join(&commit).join(".git").exists());

    // Not offered to users, and not served, until it is enabled.
    assert_eq!(bob.get("/api/packages").await.body, json!([]));
    let frame = format!("/plugin-frame/hello/{commit}");
    assert_eq!(Api::new(&env).get(&frame).await.status, StatusCode::NOT_FOUND);
    assert_eq!(admin.put("/api/packages/hello", json!({ "enabled": true })).await.status, StatusCode::OK);

    // Users opt in one by one; their secrets are sealed and never sent back.
    assert_eq!(bob.get("/api/packages").await.body[0]["user"]["enabled"], false);
    let saved = bob.put("/api/me/packages/hello", json!({ "enabled": true, "settings": { "token": "s3cret" } })).await;
    assert_eq!(saved.body["settings"], json!({ "token": { "set": true } }));
    assert!(!bob.get("/api/packages").await.text.contains("s3cret"));
    assert_eq!(bob.get("/api/me/packages/hello/settings").await.body, json!({ "token": "s3cret" }), "the plug-in itself receives the value");
    assert_eq!(bob.put("/api/me/packages/hello", json!({ "enabled": true, "settings": { "other": 1 } })).await.status, StatusCode::BAD_REQUEST);
    let startup = bob.get("/api/me/startup").await;
    assert_eq!(startup.body["packages"][0]["commit"], json!(commit));

    // Per-user storage, bounded.
    assert_eq!(bob.put("/api/me/packages/hello/storage", json!({ "key": "count", "value": 3 })).await.status, StatusCode::OK);
    assert_eq!(bob.get("/api/me/packages/hello/storage").await.body, json!({ "count": 3 }));
    assert_eq!(bob.put("/api/me/packages/hello/storage", json!({ "key": "big", "value": "x".repeat(70_000) })).await.status, StatusCode::PAYLOAD_TOO_LARGE);

    // The frame: sandboxed, scripts allowed by hash only, no network, framed by us alone.
    let page = Api::new(&env).get(&frame).await;
    assert_eq!(page.status, StatusCode::OK);
    let policy = page.headers["content-security-policy"].to_str().unwrap();
    assert!(policy.contains("sandbox allow-scripts") && !policy.contains("allow-same-origin"), "{policy}");
    assert!(policy.contains("connect-src 'none'") && policy.contains("'sha256-"), "{policy}");
    assert_eq!(page.headers["x-frame-options"], "SAMEORIGIN");
    assert!(page.text.contains("unomail.notify('hello');"));
    assert_eq!(Api::new(&env).get(&format!("/plugin-frame/hello/{}", "0".repeat(40))).await.status, StatusCode::NOT_FOUND, "only the installed commit");
    assert_eq!(admin.get("/api/me").await.headers["x-frame-options"], "DENY");

    // An update shows the permissions it adds, and replaces the old commit once confirmed.
    assert_eq!(admin.post("/api/packages/hello/update", json!({})).await.body["upToDate"], true);
    repository(&repos.path().join("hello"), &[("unomail.json", &manifest("1.1.0", json!(["notify", "storage"])))], "v1.1.0");
    git(&repos.path().join("hello"), &["tag", "--force", "v1.0.0", "v1.1.0"]);
    let update = admin.post("/api/packages/hello/update", json!({})).await;
    assert_eq!(update.body["newPermissions"], json!(["storage"]), "{}", update.text);
    assert_eq!(update.body["update"]["from"], json!(commit));
    let updated = admin.post("/api/packages", json!({ "token": update.body["token"] })).await;
    assert_eq!(updated.body["manifest"]["version"], "1.1.0");
    assert!(!env.app.cfg.data_dir.join("plugins/hello").join(&commit).exists());

    // Installing the same id again is refused; uninstalling removes files and user data.
    let again = admin.post("/api/packages/preview", json!({ "url": url, "ref": "v1.1.0" })).await;
    assert_eq!(admin.post("/api/packages", json!({ "token": again.body["token"] })).await.status, StatusCode::CONFLICT);
    assert_eq!(bob.delete("/api/packages/hello").await.status, StatusCode::FORBIDDEN);
    assert_eq!(admin.delete("/api/packages/hello").await.status, StatusCode::OK);
    assert!(!env.app.cfg.data_dir.join("plugins/hello").exists());
    assert_eq!(bob.get("/api/me/packages/hello/storage").await.status, StatusCode::NOT_FOUND);
    let audit = admin.get("/api/logs/audit").await.text;
    assert!(audit.contains("package.installed") && audit.contains("package.removed"), "{audit}");
}

#[tokio::test]
async fn themes_install_from_git_as_design_tokens() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let repos = tempfile::tempdir().unwrap();
    let theme = |tokens: Value| json!({ "schema": 2, "id": "ocean", "type": "theme", "name": "Ocean", "version": "1", "theme": tokens }).to_string();

    let evil = repository(&repos.path().join("evil"), &[("unomail.json", &theme(json!({ "css": "body{display:none}" })))], "v1");
    let refused = admin.post("/api/packages/preview", json!({ "url": evil, "ref": "v1" })).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert!(refused.text.contains("unknown skin property"), "{}", refused.text);

    let url = repository(&repos.path().join("ocean"), &[("unomail.json", &theme(json!({ "mode": "dark", "primary": "#0061a4", "spacing": 6, "fontScale": 1.1 })))], "v1");
    let preview = admin.post("/api/packages/preview", json!({ "url": url, "ref": "main" })).await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.text);
    assert_eq!(admin.post("/api/packages", json!({ "token": preview.body["token"] })).await.body["enabled"], true, "themes carry no code");
    let startup = bob.get("/api/me/startup").await;
    assert_eq!(startup.body["themes"], json!([{ "id": "ocean", "name": "Ocean", "mode": "dark", "primary": "#0061a4", "spacing": 6, "fontScale": 1.1 }]));
    assert_eq!(bob.put("/api/me/packages/ocean", json!({ "enabled": true })).await.status, StatusCode::NOT_FOUND, "themes need no opt-in");
}

/// The files of one of the examples in `docs/examples/`.
fn example(path: &str) -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/examples").join(path);
    std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name().to_string_lossy().into_owned(), std::fs::read_to_string(entry.path()).unwrap())
        })
        .collect()
}

async fn install(admin: &Api, url: &str) -> Value {
    let preview = admin.post("/api/packages/preview", json!({ "url": url, "ref": "main" })).await;
    assert_eq!(preview.status, StatusCode::OK, "{}", preview.text);
    let installed = admin.post("/api/packages", json!({ "token": preview.body["token"] })).await;
    assert_eq!(installed.status, StatusCode::OK, "{}", installed.text);
    installed.body
}

#[tokio::test]
async fn server_plugins_tag_incoming_mail_and_answer_their_routes() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob_account = env.account("bob@example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let repos = tempfile::tempdir().unwrap();
    let files = example("plugins/subject-tagger");
    let files: Vec<(&str, &str)> = files.iter().map(|(n, c)| (n.as_str(), c.as_str())).collect();
    let url = repository(&repos.path().join("tagger"), &files, "v1");

    install(&admin, &url).await;
    // Installed but not yet available: mail is untouched.
    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail("ann@remote.example", &["bob@example.org"], &message("ann@remote.example", "bob@example.org", "Before", "x")).await.starts_with("250"));
    assert!(!env.inbox(&bob_account).await[0].contains("X-Tagged-By"));

    assert_eq!(admin.put("/api/packages/subject-tagger", json!({ "enabled": true })).await.status, StatusCode::OK);
    // Administrator settings: only administrators, and the plug-in's web part never sees secrets.
    assert_eq!(bob.get("/api/packages/subject-tagger/settings").await.status, StatusCode::FORBIDDEN);
    assert_eq!(admin.put("/api/packages/subject-tagger/settings", json!({ "settings": { "prefix": "[EXT]" } })).await.status, StatusCode::OK);
    assert_eq!(admin.put("/api/packages/subject-tagger/settings", json!({ "settings": { "unknown": "x" } })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(bob.get("/api/me/packages/subject-tagger/admin-settings").await.body, json!({ "prefix": "[EXT]" }));

    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail("ann@remote.example", &["bob@example.org"], &message("ann@remote.example", "bob@example.org", "Quarterly numbers", "x")).await.starts_with("250"));
    let inbox = env.inbox(&bob_account).await;
    let tagged = inbox.iter().find(|m| m.contains("Quarterly numbers")).unwrap();
    assert!(tagged.contains("X-Tagged-By: subject-tagger"), "{tagged}");
    assert!(tagged.contains("Subject: [EXT] Quarterly numbers"), "{tagged}");
    assert_eq!(tagged.matches("Subject:").count(), 1, "{tagged}");

    // Its own route, for signed-in users only.
    let info = bob.post("/api/x/subject-tagger/info", json!({})).await;
    assert_eq!((info.status, info.body.clone()), (StatusCode::OK, json!({ "prefix": "[EXT]" })), "{}", info.text);
    assert_eq!(Api::new(&env).post("/api/x/subject-tagger/info", json!({})).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bob.post("/api/x/hello-world/info", json!({})).await.status, StatusCode::NOT_FOUND);

    // Administrators get its admin page without opting in; the plug-in has no user opt-in to give.
    let startup = admin.get("/api/me/startup").await;
    assert_eq!(startup.body["packages"][0]["adminOnly"], true, "{}", startup.text);
    assert_eq!(bob.get("/api/me/startup").await.body["packages"], json!([]));
}

/// A server module that never finishes.
const ENDLESS: &str = r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "handle") (param i32 i32) (result i64) (loop $forever (br $forever)) (i64.const 0)))"#;

#[tokio::test]
async fn failing_mail_hooks_fail_open_unless_told_otherwise() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let repos = tempfile::tempdir().unwrap();
    let manifest = json!({
        "schema": 2, "id": "endless", "type": "plugin", "name": "Endless", "version": "1", "api": "^2",
        "permissions": ["server:mail-incoming"], "server": { "module": "server.wat", "hooks": ["mail:incoming"] },
    })
    .to_string();
    let url = repository(&repos.path().join("endless"), &[("unomail.json", &manifest), ("server.wat", ENDLESS)], "v1");
    install(&admin, &url).await;
    admin.put("/api/packages/endless", json!({ "enabled": true })).await;

    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail("ann@remote.example", &["bob@example.org"], &message("ann@remote.example", "bob@example.org", "Still delivered", "x")).await.starts_with("250"));
    assert_eq!(env.inbox(&bob).await.len(), 1, "a broken plug-in does not lose mail");

    admin.put("/api/packages/endless/settings", json!({ "failClosed": true })).await;
    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail("ann@remote.example", &["bob@example.org"], &message("ann@remote.example", "bob@example.org", "Deferred", "x")).await.starts_with("451"));

    // A module that is not the plug-in ABI is refused before it is installed.
    let wasi = json!({
        "schema": 2, "id": "wasi", "type": "plugin", "name": "W", "version": "1", "api": "^2",
        "permissions": [], "server": { "module": "server.wat" },
    })
    .to_string();
    let bad = repository(&repos.path().join("wasi"), &[("unomail.json", &wasi), ("server.wat", r#"(module (import "wasi_snapshot_preview1" "proc_exit" (func (param i32))))"#)], "v1");
    let refused = admin.post("/api/packages/preview", json!({ "url": bad, "ref": "v1" })).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert!(refused.text.contains("only unomail.call and unomail.reply"), "{}", refused.text);
}

#[tokio::test]
async fn administrators_choose_the_servers_a_plugin_may_reach() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let repos = tempfile::tempdir().unwrap();
    let manifest = json!({
        "schema": 2, "id": "cloud", "type": "plugin", "name": "Cloud", "version": "1", "api": "^2", "entry": "index.js",
        "permissions": ["attachments:read", "composer:write", "auth"],
        "settings": [{ "key": "server", "type": "host", "label": "Cloud server", "scope": "admin" }],
    })
    .to_string();
    let url = repository(&repos.path().join("cloud"), &[("unomail.json", &manifest), ("index.js", "await unomail.ready;")], "v1");
    let installed = install(&admin, &url).await;
    let commit = installed["commit"].as_str().unwrap().to_owned();
    admin.put("/api/packages/cloud", json!({ "enabled": true })).await;
    bob.put("/api/me/packages/cloud", json!({ "enabled": true })).await;

    let frame = format!("/plugin-frame/cloud/{commit}");
    let policy = |reply: &common::Reply| reply.headers["content-security-policy"].to_str().unwrap().to_owned();
    assert!(policy(&Api::new(&env).get(&frame).await).contains("connect-src 'none'"), "no server chosen yet");

    assert_eq!(admin.put("/api/packages/cloud/settings", json!({ "settings": { "server": "https://evil.example/x" } })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(admin.put("/api/packages/cloud/settings", json!({ "settings": { "server": "files.example.org" } })).await.status, StatusCode::OK);
    assert!(policy(&Api::new(&env).get(&frame).await).contains("connect-src https://files.example.org;"));
    let startup = bob.get("/api/me/startup").await;
    assert!(startup.body["packages"][0]["permissions"].as_array().unwrap().contains(&json!("network:files.example.org")), "{}", startup.text);
    // The plug-in's web part learns the server from the administrator's settings.
    assert_eq!(bob.get("/api/me/packages/cloud/admin-settings").await.body, json!({ "server": "files.example.org" }));

    // The sign-in window's return page needs no session and caches nothing.
    let callback = Api::new(&env).get("/plugin-auth/callback?code=abc&state=0123456789abcdef").await;
    assert_eq!(callback.status, StatusCode::OK);
    assert_eq!(callback.headers["cache-control"], "no-store");
    assert!(callback.text.contains("BroadcastChannel('unomail-plugin-auth')"));
    assert!(callback.headers["content-security-policy"].to_str().unwrap().contains("script-src 'sha256-"));
}
