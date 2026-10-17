//! JMAP for Sieve Scripts (RFC 9661): SieveScript/get, /changes, /set, /query and /validate.
//!
//! The scripts are the ones ManageSieve and the web client's filters use. A script's content is
//! a blob: `s` followed by the SHA-256 of its text, so a changed script gets a new blob id.
//! New content arrives as an upload.

use serde_json::{Map, Value, json};

use super::{
    Context, MethodError, MethodResult, account_id,
    objects::{self, SetResult},
    parse_id, set_error,
};
use crate::{
    managesieve::{MAX_SCRIPT, MAX_SCRIPTS},
    sieve::{self, Stored},
};

#[derive(sqlx::FromRow)]
struct Row {
    id: i64,
    name: String,
    script: String,
    active: bool,
}

async fn rows(ctx: &Context<'_>) -> Result<Vec<Row>, MethodError> {
    Ok(sqlx::query_as("SELECT id, name, script, active FROM sieve_scripts WHERE account_id = ? ORDER BY name").bind(ctx.account.id).fetch_all(&ctx.app.db).await?)
}

pub fn blob_id(script: &str) -> String {
    format!("s{}", crate::util::sha256_hex(script.as_bytes()))
}

/// The text of one of the account's scripts by its blob id.
pub async fn load_blob(app: &crate::app::AppState, account_id: i64, blob_id: &str) -> sqlx::Result<Option<Vec<u8>>> {
    let scripts = sieve::all(app, account_id).await?;
    Ok(scripts.into_iter().find(|s| self::blob_id(&s.script) == blob_id).map(|s| s.script.into_bytes()))
}

fn to_json(row: &Row) -> Value {
    json!({ "id": format!("S{}", row.id), "name": row.name, "blobId": blob_id(&row.script), "isActive": row.active })
}

pub async fn get(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let all = rows(ctx).await?;
    let (mut list, mut not_found) = (Vec::new(), Vec::new());
    match objects::requested_ids(args)? {
        None => list.extend(all.iter().map(|row| objects::select(to_json(row), args))),
        Some(ids) => {
            for id in ids {
                match parse_id(&id, 'S').and_then(|n| all.iter().find(|row| row.id == n)) {
                    Some(row) => list.push(objects::select(to_json(row), args)),
                    None => not_found.push(id),
                }
            }
        }
    }
    Ok(json!({ "accountId": account_id(ctx.account), "state": objects::state(ctx, "SieveScript").await?, "list": list, "notFound": not_found }))
}

pub async fn changes(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    objects::changes(ctx, args, "SieveScript", 'S').await
}

/// Reads script text from a blob the client uploaded (or an existing script's blob).
async fn script_text(ctx: &Context<'_>, blob_id: &str) -> Result<String, Value> {
    let blob_id = ctx.resolve_id(blob_id);
    let data = if blob_id.starts_with('s') {
        load_blob(ctx.app, ctx.account.id, &blob_id).await.map_err(|_| set_error("serverFail", "internal error"))?
    } else {
        super::email::load_blob(ctx.app, ctx.account, &blob_id).await.map_err(|_| set_error("serverFail", "internal error"))?.map(|(data, _)| data)
    };
    let data = data.ok_or_else(|| set_error("blobNotFound", "no such blob"))?;
    if data.len() > MAX_SCRIPT {
        return Err(set_error("tooLarge", format!("scripts may be at most {MAX_SCRIPT} bytes")));
    }
    String::from_utf8(data).map_err(|_| set_error("invalidScript", "the script is not UTF-8 text"))
}

/// Checks that a script compiles among the account's others.
async fn compile(ctx: &Context<'_>, name: &str, source: &str) -> Result<(), Value> {
    let scripts = sieve::all(ctx.app, ctx.account.id).await.map_err(|_| set_error("serverFail", "internal error"))?;
    let globals = sieve::globals(ctx.app).await.unwrap_or_default();
    sieve::compile_among(source, name, &scripts, &globals).map(|_| ()).map_err(|err| set_error("invalidScript", err.to_string()))
}

fn checked_name(name: &str) -> Result<(), Value> {
    if sieve::valid_script_name(name) { Ok(()) } else { Err(set_error("invalidProperties", "script names may contain letters, digits, '.', '-' and '_'")) }
}

async fn by_id(ctx: &Context<'_>, id: &str) -> Result<Row, Value> {
    let id = parse_id(&ctx.resolve_id(id), 'S').ok_or_else(|| set_error("notFound", "no such script"))?;
    rows(ctx).await.map_err(|_| set_error("serverFail", "internal error"))?.into_iter().find(|row| row.id == id).ok_or_else(|| set_error("notFound", "no such script"))
}

async fn create(ctx: &Context<'_>, spec: &Value) -> Result<Row, Value> {
    let all = rows(ctx).await.map_err(|_| set_error("serverFail", "internal error"))?;
    if all.len() >= MAX_SCRIPTS {
        return Err(set_error("overQuota", format!("at most {MAX_SCRIPTS} scripts")));
    }
    let blob = spec["blobId"].as_str().ok_or_else(|| set_error("invalidProperties", "blobId is required"))?;
    let source = script_text(ctx, blob).await?;
    // Without a name the server picks one (RFC 9661 2.2).
    let name = match spec["name"].as_str() {
        Some(name) => name.to_owned(),
        None => (1..).map(|n| format!("script-{n}")).find(|candidate| !all.iter().any(|row| &row.name == candidate)).expect("an unused name exists"),
    };
    checked_name(&name)?;
    if all.iter().any(|row| row.name == name) {
        return Err(set_error("alreadyExists", "a script with this name exists"));
    }
    compile(ctx, &name, &source).await?;
    sieve::save(ctx.app, ctx.account.id, &Stored { name: name.clone(), script: source, active: false }).await.map_err(|_| set_error("serverFail", "internal error"))?;
    rows(ctx).await.map_err(|_| set_error("serverFail", "internal error"))?.into_iter().find(|row| row.name == name).ok_or_else(|| set_error("serverFail", "internal error"))
}

async fn update(ctx: &Context<'_>, id: &str, patch: &Map<String, Value>) -> Result<Option<Value>, Value> {
    let row = by_id(ctx, id).await?;
    if patch.keys().any(|key| !matches!(key.as_str(), "name" | "blobId")) {
        return Err(set_error("invalidProperties", "only name and blobId can be changed"));
    }
    let mut name = row.name.clone();
    let mut source = row.script.clone();
    if let Some(new_name) = patch.get("name").and_then(Value::as_str).filter(|n| *n != row.name) {
        checked_name(new_name)?;
        if rows(ctx).await.map_err(|_| set_error("serverFail", "internal error"))?.iter().any(|other| other.name == new_name) {
            return Err(set_error("alreadyExists", "a script with this name exists"));
        }
        name = new_name.to_owned();
    }
    if let Some(blob) = patch.get("blobId").and_then(Value::as_str) {
        source = script_text(ctx, blob).await?;
    }
    compile(ctx, &name, &source).await?;
    sqlx::query("UPDATE sieve_scripts SET name = ?, script = ?, updated_at = ? WHERE id = ?")
        .bind(&name)
        .bind(&source)
        .bind(crate::util::now())
        .bind(row.id)
        .execute(&ctx.app.db)
        .await
        .map_err(|_| set_error("serverFail", "internal error"))?;
    // The blob id follows the content; the client learns the new one.
    Ok((source != row.script).then(|| json!({ "blobId": blob_id(&source) })))
}

pub async fn set(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    objects::check_size(args)?;
    let old_state = objects::state(ctx, "SieveScript").await?;
    objects::check_state(args, &old_state)?;
    let mut result = SetResult::default();
    if let Some(create_specs) = args.get("create").and_then(Value::as_object) {
        for (creation_id, spec) in create_specs {
            match create(ctx, spec).await {
                Ok(row) => {
                    let id = format!("S{}", row.id);
                    ctx.created.insert(creation_id.clone(), id.clone());
                    result.created.insert(creation_id.clone(), json!({ "id": id, "blobId": blob_id(&row.script), "isActive": false, "name": row.name }));
                }
                Err(err) => {
                    result.not_created.insert(creation_id.clone(), err);
                }
            }
        }
    }
    if let Some(updates) = args.get("update").and_then(Value::as_object) {
        for (id, patch) in updates {
            let Some(patch) = patch.as_object() else {
                result.not_updated.insert(id.clone(), set_error("invalidPatch", "the patch must be an object"));
                continue;
            };
            match update(ctx, id, patch).await {
                Ok(changed) => result.updated.insert(id.clone(), changed.unwrap_or(Value::Null)),
                Err(err) => result.not_updated.insert(id.clone(), err),
            };
        }
    }
    if let Some(destroy) = args.get("destroy").and_then(Value::as_array) {
        for id in destroy.iter().filter_map(Value::as_str) {
            match by_id(ctx, id).await {
                // RFC 9661 2.2: the active script cannot be destroyed.
                Ok(row) if row.active => {
                    result.not_destroyed.insert(id.to_owned(), set_error("scriptIsActive", "deactivate the script first"));
                }
                Ok(row) => {
                    if sieve::delete(ctx.app, ctx.account.id, &row.name).await.is_err() {
                        result.not_destroyed.insert(id.to_owned(), set_error("serverFail", "internal error"));
                    } else {
                        result.destroyed.push(id.to_owned());
                    }
                }
                Err(err) => {
                    result.not_destroyed.insert(id.to_owned(), err);
                }
            }
        }
    }
    // Activation happens after everything else, and only if all of it succeeded.
    let all_succeeded = result.not_created.is_empty() && result.not_updated.is_empty() && result.not_destroyed.is_empty();
    let activate = args.get("onSuccessActivateScript").and_then(Value::as_str).map(|id| ctx.resolve_id(id));
    let deactivate = args.get("onSuccessDeactivateScript").and_then(Value::as_bool).unwrap_or(false);
    if all_succeeded && (activate.is_some() || deactivate) {
        let before: Option<i64> = rows(ctx).await?.into_iter().find(|row| row.active).map(|row| row.id);
        if let Some(id) = activate {
            let row = by_id(ctx, &id).await.map_err(|_| MethodError::invalid("onSuccessActivateScript names no script"))?;
            compile(ctx, &row.name, &row.script).await.map_err(|err| MethodError("invalidScript", err["description"].as_str().unwrap_or("invalid script").to_owned()))?;
            sieve::save(ctx.app, ctx.account.id, &Stored { name: row.name.clone(), script: row.script.clone(), active: true }).await?;
            if before != Some(row.id) {
                result.updated.insert(format!("S{}", row.id), json!({ "isActive": true }));
                if let Some(old) = before {
                    result.updated.insert(format!("S{old}"), json!({ "isActive": false }));
                }
            }
        } else if let Some(old) = before {
            sqlx::query("UPDATE sieve_scripts SET active = 0 WHERE account_id = ?").bind(ctx.account.id).execute(&ctx.app.db).await?;
            result.updated.insert(format!("S{old}"), json!({ "isActive": false }));
        }
    }
    let new_state = objects::state(ctx, "SieveScript").await?;
    Ok(result.into_response(ctx, old_state, new_state))
}

pub async fn query(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let mut all = rows(ctx).await?;
    if let Some(filter) = args.get("filter").and_then(Value::as_object) {
        if let Some(text) = filter.get("name").and_then(Value::as_str) {
            let text = text.to_lowercase();
            all.retain(|row| row.name.to_lowercase().contains(&text));
        }
        if let Some(active) = filter.get("isActive").and_then(Value::as_bool) {
            all.retain(|row| row.active == active);
        }
    }
    for comparator in args.get("sort").and_then(Value::as_array).into_iter().flatten().rev() {
        let ascending = comparator["isAscending"].as_bool().unwrap_or(true);
        match comparator["property"].as_str() {
            Some("name") => all.sort_by(|a, b| a.name.cmp(&b.name)),
            Some("isActive") => all.sort_by_key(|row| row.active),
            _ => return Err(MethodError("unsupportedSort", "scripts sort by name or isActive".into())),
        }
        if !ascending {
            all.reverse();
        }
    }
    let total = all.len();
    let position = (args.get("position").and_then(Value::as_i64).unwrap_or(0).max(0) as usize).min(total);
    let limit = args.get("limit").and_then(Value::as_u64).map_or(total, |l| l as usize);
    let ids: Vec<String> = all.iter().skip(position).take(limit).map(|row| format!("S{}", row.id)).collect();
    Ok(json!({
        "accountId": account_id(ctx.account),
        "queryState": objects::state(ctx, "SieveScript").await?,
        "canCalculateChanges": false,
        "position": position,
        "ids": ids,
        "total": total,
    }))
}

pub async fn validate(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let blob = args.get("blobId").and_then(Value::as_str).ok_or_else(|| MethodError::invalid("blobId is required"))?;
    let error = match script_text(ctx, blob).await {
        Ok(source) => compile(ctx, "validated", &source).await.err(),
        Err(err) if err["type"] == "blobNotFound" => return Err(MethodError::invalid("no such blob")),
        Err(err) => Some(err),
    };
    Ok(json!({ "accountId": account_id(ctx.account), "error": error }))
}

/// The `urn:ietf:params:jmap:sieve` capability of an account.
pub fn capability() -> Value {
    json!({
        "implementation": "unoMail",
        "maxSizeScriptName": 64,
        "maxSizeScript": MAX_SCRIPT,
        "maxNumberScripts": MAX_SCRIPTS,
        "maxNumberRedirects": sieve::MAX_REDIRECTS,
        "sieveExtensions": sieve::SUPPORTED,
        "notificationMethods": null,
        "externalLists": null,
    })
}
