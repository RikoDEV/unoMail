//! Server-side plug-ins: WebAssembly modules run in a sandbox (`wasmi`, an interpreter).
//!
//! A module sees nothing of the server. It exports `memory`, `alloc(len) -> ptr` and
//! `handle(ptr, len) -> i64`, and may import two functions: `unomail.call(ptr, len) -> len`
//! and `unomail.reply(ptr)`. Both directions carry JSON: the host passes an event to `handle`
//! and receives the answer, packed as `ptr << 32 | len`; the module passes a request to `call`
//! (its store, its settings, web requests to the hosts it declared), which returns the length
//! of the reply, and then fetches the reply into memory it allocated with `reply`. The host
//! never calls back into the module while it is running.
//!
//! Every call runs on a blocking thread with a fuel budget (a bound on executed instructions),
//! a memory limit and a deadline; a module that misbehaves repeatedly is suspended.

use std::{
    collections::{HashMap, VecDeque},
    path::Path,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use sqlx::SqlitePool;
use wasmi::{Caller, Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

use super::{Installed, manifest};

const MAX_MEMORY: usize = 64 * 1024 * 1024;
const MAX_MESSAGE: usize = 1024 * 1024;
const MAX_KV_BYTES: i64 = 1024 * 1024;
const MAX_USER_KV_BYTES: i64 = 256 * 1024;
const MAX_CONCURRENT: usize = 4;
const ERROR_WINDOW: Duration = Duration::from_secs(5 * 60);
const ERRORS_TO_SUSPEND: usize = 20;
const SUSPENSION: Duration = Duration::from_secs(15 * 60);

/// What a call is for, which sets its budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Mail,
    Route,
    Schedule,
}

impl Purpose {
    fn fuel(self) -> u64 {
        match self {
            Purpose::Mail => 50_000_000,
            Purpose::Route | Purpose::Schedule => 200_000_000,
        }
    }

    /// The largest web request or response a call may move: files in routes and schedules.
    fn max_transfer(self) -> usize {
        match self {
            Purpose::Mail => MAX_MESSAGE,
            Purpose::Route | Purpose::Schedule => 16 * 1024 * 1024,
        }
    }

    fn fetch_timeout(self) -> Duration {
        match self {
            Purpose::Mail => Duration::from_secs(3),
            Purpose::Route => Duration::from_secs(15),
            Purpose::Schedule => Duration::from_secs(55),
        }
    }

    fn deadline(self) -> Duration {
        match self {
            Purpose::Mail => Duration::from_secs(5),
            Purpose::Route => Duration::from_secs(20),
            Purpose::Schedule => Duration::from_secs(60),
        }
    }
}

struct Runtime {
    engine: Engine,
    /// Compiled modules by package and commit.
    modules: Mutex<HashMap<(String, String), Module>>,
    errors: Mutex<HashMap<String, VecDeque<Instant>>>,
    suspended: Mutex<HashMap<String, Instant>>,
    slots: Mutex<HashMap<String, Arc<tokio::sync::Semaphore>>>,
}

static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    let mut config = Config::default();
    config.consume_fuel(true);
    Runtime {
        engine: Engine::new(&config),
        modules: Mutex::default(),
        errors: Mutex::default(),
        suspended: Mutex::default(),
        slots: Mutex::default(),
    }
});

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// Compiles a module (binary or text) and checks that it imports and exports exactly the ABI.
pub fn compile(bytes: &[u8]) -> Result<Module, String> {
    let module = Module::new(&RUNTIME.engine, bytes).map_err(|e| format!("the server module is not valid WebAssembly: {}", crate::util::sanitize_line(&e.to_string())))?;
    for import in module.imports() {
        if import.module() != "unomail" || !matches!(import.name(), "call" | "reply") {
            return Err(format!("the server module may import only unomail.call and unomail.reply, not {}.{}", crate::util::sanitize_line(import.module()), crate::util::sanitize_line(import.name())));
        }
    }
    let exports: Vec<String> = module.exports().map(|e| e.name().to_owned()).collect();
    for needed in ["memory", "alloc", "handle"] {
        if !exports.iter().any(|e| e == needed) {
            return Err(format!("the server module must export {needed}"));
        }
    }
    Ok(module)
}

fn module_for(data_dir: &Path, package: &Installed, server: &Value) -> Result<Module, String> {
    let key = (package.id.clone(), package.git_commit.clone());
    if let Some(module) = lock(&RUNTIME.modules).get(&key) {
        return Ok(module.clone());
    }
    let path = server["module"].as_str().ok_or("no server module")?;
    let bytes = std::fs::read(super::package_dir(data_dir, &package.id, &package.git_commit).join(path)).map_err(|_| "the server module is missing".to_owned())?;
    let module = compile(&bytes)?;
    lock(&RUNTIME.modules).insert(key, module.clone());
    Ok(module)
}

/// Drops the compiled modules of a package (after an update or uninstall).
pub fn forget(id: &str) {
    lock(&RUNTIME.modules).retain(|(package, _), _| package != id);
    lock(&RUNTIME.errors).remove(id);
    lock(&RUNTIME.suspended).remove(id);
}

pub fn is_suspended(id: &str) -> bool {
    let mut suspended = lock(&RUNTIME.suspended);
    match suspended.get(id) {
        Some(since) if since.elapsed() < SUSPENSION => true,
        Some(_) => {
            suspended.remove(id);
            false
        }
        None => false,
    }
}

/// Counts a failure; returns true when it suspends the package.
fn record_error(id: &str) -> bool {
    let mut errors = lock(&RUNTIME.errors);
    let list = errors.entry(id.to_owned()).or_default();
    list.push_back(Instant::now());
    while list.front().is_some_and(|at| at.elapsed() > ERROR_WINDOW) {
        list.pop_front();
    }
    if list.len() >= ERRORS_TO_SUSPEND {
        list.clear();
        lock(&RUNTIME.suspended).insert(id.to_owned(), Instant::now());
        return true;
    }
    false
}

/// What a module may reach while it runs.
struct Host {
    package: String,
    permissions: Vec<String>,
    purpose: Purpose,
    /// The signed-in user a route call is for; their own `kv` scope.
    user: Option<i64>,
    db: SqlitePool,
    http: reqwest::Client,
    allow_private: bool,
    admin_settings: Value,
    user_settings: Value,
    deadline: Instant,
    runtime: tokio::runtime::Handle,
    limits: StoreLimits,
    /// The reply to the last `call`, until the module fetches it.
    pending: Vec<u8>,
    /// The module's memory, set once it is instantiated. (Looking exports up through the
    /// `Caller` inside a host function crashes wasmi 2.0, so the handle is kept here.)
    memory: Option<wasmi::Memory>,
}

impl Host {
    fn has(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }

    fn request(&self, request: Value) -> Result<Value, String> {
        if Instant::now() > self.deadline {
            return Err("the time for this call is up".into());
        }
        match request["op"].as_str().unwrap_or_default() {
            "log" => {
                tracing::info!(package = %self.package, message = %crate::util::sanitize_line(request["message"].as_str().unwrap_or_default()), "plug-in log");
                Ok(Value::Null)
            }
            "settings.admin" => Ok(self.admin_settings.clone()),
            "settings.user" => Ok(self.user_settings.clone()),
            "kv.get" | "kv.set" | "kv.delete" | "kv.list" => {
                if !self.has("server:storage") {
                    return Err("the plug-in did not ask for the server:storage permission".into());
                }
                self.runtime.block_on(self.kv(&request))
            }
            "http.fetch" => self.runtime.block_on(self.fetch(&request)),
            other => Err(format!("unknown request: {}", crate::util::sanitize_line(other))),
        }
    }

    /// The package's store. `"scope": "user"` (in routes) is the calling user's own part of it,
    /// for their tokens and preferences; otherwise it is shared by the whole package.
    async fn kv(&self, request: &Value) -> Result<Value, String> {
        let (prefix, quota) = match request["scope"].as_str() {
            Some("user") => match self.user {
                Some(user) => (format!("u:{user}:"), MAX_USER_KV_BYTES),
                None => return Err("the user scope is only available in routes".into()),
            },
            None | Some("package") => ("s:".to_owned(), MAX_KV_BYTES),
            Some(_) => return Err("scope must be \"user\" or \"package\"".into()),
        };
        let key = request["key"].as_str().unwrap_or_default();
        let stored = format!("{prefix}{key}");
        let like = format!("{}%", prefix.replace('%', "\\%").replace('_', "\\_"));
        let db_err = |e: sqlx::Error| e.to_string();
        match request["op"].as_str() {
            Some("kv.list") => {
                let keys: Vec<String> = sqlx::query_scalar("SELECT key FROM package_kv WHERE package_id = ? AND key LIKE ? ESCAPE '\\' ORDER BY key LIMIT 1000")
                    .bind(&self.package)
                    .bind(&like)
                    .fetch_all(&self.db)
                    .await
                    .map_err(db_err)?;
                Ok(json!(keys.into_iter().map(|k| k[prefix.len()..].to_owned()).collect::<Vec<_>>()))
            }
            _ if key.is_empty() || key.len() > 200 => Err("keys must be 1 to 200 characters".into()),
            Some("kv.get") => {
                let value: Option<String> = sqlx::query_scalar("SELECT value FROM package_kv WHERE package_id = ? AND key = ?").bind(&self.package).bind(&stored).fetch_optional(&self.db).await.map_err(db_err)?;
                Ok(value.and_then(|v| serde_json::from_str(&v).ok()).unwrap_or(Value::Null))
            }
            Some("kv.delete") => {
                sqlx::query("DELETE FROM package_kv WHERE package_id = ? AND key = ?").bind(&self.package).bind(&stored).execute(&self.db).await.map_err(db_err)?;
                Ok(Value::Null)
            }
            _ => {
                let value = request["value"].to_string();
                let used: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(LENGTH(key) + LENGTH(value)), 0) FROM package_kv WHERE package_id = ? AND key LIKE ? ESCAPE '\\' AND key != ?")
                    .bind(&self.package)
                    .bind(&like)
                    .bind(&stored)
                    .fetch_one(&self.db)
                    .await
                    .map_err(db_err)?;
                if used + (stored.len() + value.len()) as i64 > quota {
                    return Err(format!("the store is full ({} KB)", quota / 1024));
                }
                sqlx::query("INSERT INTO package_kv (package_id, key, value) VALUES (?, ?, ?) ON CONFLICT(package_id, key) DO UPDATE SET value = excluded.value")
                    .bind(&self.package)
                    .bind(&stored)
                    .bind(value)
                    .execute(&self.db)
                    .await
                    .map_err(db_err)?;
                Ok(Value::Null)
            }
        }
    }

    /// A web request to a host the manifest declared: https only, public addresses only.
    async fn fetch(&self, request: &Value) -> Result<Value, String> {
        let url = reqwest::Url::parse(request["url"].as_str().unwrap_or_default()).map_err(|_| "invalid address".to_owned())?;
        let host = url.host_str().unwrap_or_default().to_owned();
        if url.scheme() != "https" || !self.has(&format!("network:{host}")) {
            return Err(format!("the plug-in did not ask for the network:{} permission", crate::util::sanitize_line(&host)));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("addresses must not contain credentials".into());
        }
        let destination = crate::webhooks::destination(url.as_str(), self.allow_private).await.map_err(str::to_owned)?;
        // The usual methods, and WebDAV's for cloud storage.
        let method = match request["method"].as_str().unwrap_or("GET") {
            name @ ("GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "PROPFIND" | "MKCOL" | "MOVE" | "COPY") => {
                reqwest::Method::from_bytes(name.as_bytes()).map_err(|_| "invalid method".to_owned())?
            }
            _ => return Err("method must be GET, HEAD, POST, PUT, PATCH, DELETE, PROPFIND, MKCOL, MOVE or COPY".into()),
        };
        let timeout = self.purpose.fetch_timeout();
        let limit = self.purpose.max_transfer();
        // The address checked above is the one connected to, so DNS cannot change it.
        let client = match destination {
            Some((name, addr)) => crate::outbound::pinned(&name, addr, timeout).map_err(|e| e.to_string())?,
            None => self.http.clone(),
        };
        let mut builder = client.request(method, url).timeout(timeout);
        for (name, value) in request["headers"].as_object().into_iter().flatten() {
            let lower = name.to_ascii_lowercase();
            if matches!(lower.as_str(), "host" | "cookie" | "connection" | "content-length" | "transfer-encoding") {
                continue;
            }
            if let Some(value) = value.as_str() {
                builder = builder.header(name.as_str(), value);
            }
        }
        // Text as it is, or binary data (files) as base64.
        if let Some(body) = request["bodyBase64"].as_str() {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD.decode(body).map_err(|_| "bodyBase64 is not base64".to_owned())?;
            if bytes.len() > limit {
                return Err(format!("the request is larger than {} MB", limit / 1024 / 1024));
            }
            builder = builder.body(bytes);
        } else if let Some(body) = request["body"].as_str() {
            builder = builder.body(body.to_owned());
        }
        let response = builder.send().await.map_err(|_| "the request failed".to_owned())?;
        let status = response.status().as_u16();
        let content_type = response.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
        let mut body = Vec::new();
        let mut stream = response;
        while let Some(chunk) = stream.chunk().await.map_err(|_| "the response could not be read".to_owned())? {
            body.extend_from_slice(&chunk);
            if body.len() > limit {
                return Err(format!("the response is larger than {} MB", limit / 1024 / 1024));
            }
        }
        if request["binary"] == true {
            use base64::Engine;
            return Ok(json!({ "status": status, "contentType": content_type, "bodyBase64": base64::engine::general_purpose::STANDARD.encode(&body) }));
        }
        Ok(json!({ "status": status, "contentType": content_type, "body": String::from_utf8_lossy(&body) }))
    }
}

fn unpack(value: i64) -> (usize, usize) {
    let value = value as u64;
    ((value >> 32) as usize, (value & 0xffff_ffff) as usize)
}

fn memory_of(caller: &Caller<'_, Host>) -> Result<wasmi::Memory, wasmi::Error> {
    caller.data().memory.ok_or_else(|| wasmi::Error::new("the module has no memory yet"))
}

/// `unomail.call`: one request from the module, answered with `{ ok, result | error }`. The
/// reply waits in the host until `unomail.reply` copies it; the length is returned.
fn host_call(mut caller: Caller<'_, Host>, ptr: i32, len: i32) -> Result<i32, wasmi::Error> {
    let (ptr, len) = (ptr as u32 as usize, len as u32 as usize);
    // Requests may carry a file to upload (base64, a third larger than the file).
    if len > caller.data().purpose.max_transfer() * 4 / 3 + 64 * 1024 {
        return Err(wasmi::Error::new("request too large"));
    }
    let mut buffer = vec![0u8; len];
    memory_of(&caller)?.read(&caller, ptr, &mut buffer).map_err(|_| wasmi::Error::new("request out of bounds"))?;
    let reply = match serde_json::from_slice::<Value>(&buffer) {
        Ok(request) => match caller.data().request(request) {
            Ok(result) => json!({ "ok": true, "result": result }),
            Err(error) if error == "the time for this call is up" => return Err(wasmi::Error::new(error)),
            Err(error) => json!({ "ok": false, "error": error }),
        },
        Err(_) => json!({ "ok": false, "error": "requests must be JSON" }),
    };
    let reply = reply.to_string().into_bytes();
    let len = reply.len() as i32;
    caller.data_mut().pending = reply;
    Ok(len)
}

/// `unomail.reply`: copies the reply to the last call to `ptr`.
fn host_reply(mut caller: Caller<'_, Host>, ptr: i32) -> Result<(), wasmi::Error> {
    let reply = std::mem::take(&mut caller.data_mut().pending);
    memory_of(&caller)?.write(&mut caller, ptr as u32 as usize, &reply).map_err(|_| wasmi::Error::new("reply out of bounds"))
}

/// Everything a call needs, gathered before it moves to a blocking thread.
pub struct Call {
    pub package: Installed,
    pub purpose: Purpose,
    pub event: Value,
    pub admin_settings: Value,
    pub user_settings: Value,
    /// The account a route call is for.
    pub user: Option<i64>,
}

/// Runs the package's `handle` with `event` and returns its JSON answer.
pub async fn invoke(app: &crate::app::App, call: Call) -> Result<Value, String> {
    let id = call.package.id.clone();
    if is_suspended(&id) {
        return Err("the plug-in is suspended after repeated errors".into());
    }
    let manifest = call.package.manifest();
    let server = manifest.get("server").cloned().ok_or("the plug-in has no server module")?;
    let module = module_for(&app.cfg.data_dir, &call.package, &server)?;
    let slot = lock(&RUNTIME.slots).entry(id.clone()).or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT))).clone();
    let _permit = slot.acquire_owned().await.map_err(|_| "the plug-in is stopping".to_owned())?;
    let host = Host {
        package: id.clone(),
        permissions: call.package.permissions(),
        purpose: call.purpose,
        user: call.user,
        db: app.db.clone(),
        http: app.http.clone(),
        allow_private: app.cfg.allow_private_destinations,
        admin_settings: call.admin_settings,
        user_settings: call.user_settings,
        deadline: Instant::now() + call.purpose.deadline(),
        runtime: tokio::runtime::Handle::current(),
        limits: StoreLimitsBuilder::new().memory_size(MAX_MEMORY).instances(1).memories(1).tables(4).build(),
        pending: Vec::new(),
        memory: None,
    };
    let event = call.event.to_string();
    let purpose = call.purpose;
    let outcome = tokio::task::spawn_blocking(move || run(module, host, purpose, event.as_bytes())).await.map_err(|_| "the plug-in crashed".to_owned())?;
    match outcome {
        Ok(value) => Ok(value),
        Err(error) => {
            if record_error(&id) {
                tracing::warn!(package = %id, "plug-in suspended after repeated errors");
                crate::db::audit(&app.db, "server", "package.suspended", &id, "", &error).await;
            }
            tracing::info!(package = %id, %error, "plug-in call failed");
            Err(error)
        }
    }
}

fn run(module: Module, host: Host, purpose: Purpose, event: &[u8]) -> Result<Value, String> {
    let mut store = Store::new(&RUNTIME.engine, host);
    store.limiter(|host| &mut host.limits);
    store.set_fuel(purpose.fuel()).map_err(|e| e.to_string())?;
    let mut linker = <Linker<Host>>::new(&RUNTIME.engine);
    linker.func_wrap("unomail", "call", host_call).map_err(|e| e.to_string())?;
    linker.func_wrap("unomail", "reply", host_reply).map_err(|e| e.to_string())?;
    let describe = |e: wasmi::Error| {
        let text = e.to_string();
        if text.contains("fuel") { "the plug-in ran out of its computing budget".to_owned() } else { crate::util::sanitize_line(&text.chars().take(200).collect::<String>()) }
    };
    let instance = linker.instantiate_and_start(&mut store, &module).map_err(describe)?;
    let memory = instance.get_memory(&store, "memory").ok_or("the module has no memory")?;
    store.data_mut().memory = Some(memory);
    let alloc = instance.get_typed_func::<i32, i32>(&store, "alloc").map_err(describe)?;
    let handle = instance.get_typed_func::<(i32, i32), i64>(&store, "handle").map_err(describe)?;
    let ptr = alloc.call(&mut store, event.len() as i32).map_err(describe)? as u32 as usize;
    memory.write(&mut store, ptr, event).map_err(|_| "alloc returned memory out of bounds".to_owned())?;
    let result = handle.call(&mut store, (ptr as i32, event.len() as i32)).map_err(describe)?;
    let (ptr, len) = unpack(result);
    if len > MAX_MESSAGE {
        return Err("the answer is larger than 1 MB".into());
    }
    let mut answer = vec![0u8; len];
    memory.read(&store, ptr, &mut answer).map_err(|_| "the answer is out of bounds".to_owned())?;
    if answer.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&answer).map_err(|_| "the answer is not JSON".to_owned())
}

/// Checks a package's server module when it is fetched, so a broken one is never installed.
pub fn check_package(dir: &Path, manifest: &Value) -> Result<(), String> {
    let Some(path) = manifest["server"]["module"].as_str() else { return Ok(()) };
    let meta = std::fs::metadata(dir.join(path)).map_err(|_| format!("the server module {path} is missing"))?;
    if !meta.is_file() || meta.len() > manifest::MAX_MODULE_BYTES {
        return Err("the server module must be a file of at most 8 MB".into());
    }
    compile(&std::fs::read(dir.join(path)).map_err(|e| e.to_string())?).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A module answering every event with `{"echo": <event length>}`, or looping forever.
    const ECHO: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 1024))
          (func (export "alloc") (param $len i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $len)))
            (local.get $ptr))
          (data (i32.const 0) "{\"echo\":true}")
          (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
            (i64.const 13)))
    "#;

    const LOOP: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32) (i32.const 1024))
          (func (export "handle") (param i32 i32) (result i64)
            (loop $forever (br $forever))
            (i64.const 0)))
    "#;

    fn host() -> Host {
        Host {
            package: "test".into(),
            permissions: vec![],
            purpose: Purpose::Mail,
            user: None,
            db: SqlitePool::connect_lazy("sqlite::memory:").unwrap(),
            http: crate::outbound::builder().build().unwrap(),
            allow_private: false,
            admin_settings: json!({}),
            user_settings: json!({}),
            deadline: Instant::now() + Duration::from_secs(5),
            runtime: tokio::runtime::Handle::current(),
            limits: StoreLimitsBuilder::new().memory_size(MAX_MEMORY).build(),
            pending: Vec::new(),
            memory: None,
        }
    }

    #[tokio::test]
    async fn modules_answer_with_json() {
        let module = compile(ECHO.as_bytes()).unwrap();
        let answer = tokio::task::spawn_blocking(move || run(module, host(), Purpose::Mail, b"{}")).await.unwrap();
        assert_eq!(answer.unwrap(), json!({ "echo": true }));
    }

    #[tokio::test]
    async fn endless_modules_run_out_of_fuel() {
        let module = compile(LOOP.as_bytes()).unwrap();
        let answer = tokio::task::spawn_blocking(move || run(module, host(), Purpose::Mail, b"{}")).await.unwrap();
        assert!(answer.unwrap_err().contains("computing budget"));
    }

    #[tokio::test]
    async fn the_subject_tagger_example_tags_and_answers() {
        let source = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/examples/plugins/subject-tagger/server.wat")).unwrap();
        let module = compile(&source).unwrap();
        let mut host = host();
        host.admin_settings = json!({ "prefix": "[EXT]" });
        let event = json!({ "event": "mail:incoming", "headers": [["From", "a@example.org"], ["Subject", "Say \"hi\""]] }).to_string();
        let answer = tokio::task::spawn_blocking(move || run(module, host, Purpose::Mail, event.as_bytes())).await.unwrap().unwrap();
        assert_eq!(answer["setHeaders"], json!([["Subject", "[EXT] Say \"hi\""]]));
        assert_eq!(answer["addHeaders"], json!([["X-Tagged-By", "subject-tagger"]]));
    }

    #[tokio::test]
    async fn users_have_their_own_part_of_the_store() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        sqlx::query("INSERT INTO packages (id, kind, source_url, git_ref, git_commit, manifest, installed_at, installed_by) VALUES ('test', 'plugin', '', '', '', '{}', 0, '')").execute(&db).await.unwrap();
        let mut ann = host();
        ann.db = db.clone();
        ann.permissions = vec!["server:storage".into()];
        ann.user = Some(1);
        let mut bob = host();
        bob.db = db.clone();
        bob.permissions = vec!["server:storage".into()];
        bob.user = Some(2);
        ann.kv(&json!({ "op": "kv.set", "scope": "user", "key": "token", "value": "ann-secret" })).await.unwrap();
        ann.kv(&json!({ "op": "kv.set", "key": "shared", "value": 1 })).await.unwrap();
        assert_eq!(ann.kv(&json!({ "op": "kv.get", "scope": "user", "key": "token" })).await.unwrap(), json!("ann-secret"));
        assert_eq!(bob.kv(&json!({ "op": "kv.get", "scope": "user", "key": "token" })).await.unwrap(), Value::Null, "another user's part is out of reach");
        assert_eq!(bob.kv(&json!({ "op": "kv.get", "key": "shared" })).await.unwrap(), json!(1));
        assert_eq!(bob.kv(&json!({ "op": "kv.list" })).await.unwrap(), json!(["shared"]), "the shared part lists no user keys");
        assert_eq!(ann.kv(&json!({ "op": "kv.list", "scope": "user" })).await.unwrap(), json!(["token"]));
        let mut schedule = host();
        schedule.db = db;
        assert!(schedule.kv(&json!({ "op": "kv.get", "scope": "user", "key": "token" })).await.is_err(), "no user outside routes");
        assert!(ann.kv(&json!({ "op": "kv.set", "scope": "user", "key": "big", "value": "x".repeat(300 * 1024) })).await.is_err());
    }

    #[test]
    fn modules_may_import_nothing_but_the_host_call() {
        let wasi = r#"(module (import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1) (func (export "alloc") (param i32) (result i32) (i32.const 0)) (func (export "handle") (param i32 i32) (result i64) (i64.const 0)))"#;
        assert!(compile(wasi.as_bytes()).unwrap_err().contains("only unomail.call and unomail.reply"));
        assert!(compile(b"(module)").unwrap_err().contains("must export"));
        assert!(compile(b"not wasm").is_err());
    }

    #[test]
    fn repeated_errors_suspend_a_package() {
        for _ in 0..ERRORS_TO_SUSPEND - 1 {
            assert!(!record_error("flaky"));
        }
        assert!(record_error("flaky"));
        assert!(is_suspended("flaky"));
        forget("flaky");
        assert!(!is_suspended("flaky"));
    }
}
