//! What the JMAP data types beyond mail (calendars, contacts, Sieve scripts) have in common:
//! states and `/changes` from the `jmap_changes` log, property selection, patch objects and the
//! shape of a `/set` response.

use serde_json::{Map, Value, json};

use super::{Context, MAX_OBJECTS, MethodError, MethodResult, account_id};

/// The state of one data type: the last change logged for it.
pub async fn state(ctx: &Context<'_>, kind: &str) -> Result<String, MethodError> {
    let last: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(id), 0) FROM jmap_changes WHERE account_id = ? AND kind = ?").bind(ctx.account.id).bind(kind).fetch_one(&ctx.app.db).await?;
    // Every type answers with a number: "0" until something changed.
    let floor = floor(ctx).await?;
    Ok(last.max(floor).to_string())
}

async fn floor(ctx: &Context<'_>) -> Result<i64, MethodError> {
    Ok(crate::db::get_setting(&ctx.app.db, "jmap_changes.floor").await?.and_then(|v| v.parse().ok()).unwrap_or(0))
}

/// Drops old entries of the log, remembering how far back it still reaches.
pub async fn prune(db: &sqlx::SqlitePool, keep: i64) -> sqlx::Result<()> {
    let max: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(id), 0) FROM jmap_changes").fetch_one(db).await?;
    let floor = max - keep;
    if floor > 0 {
        sqlx::query("DELETE FROM jmap_changes WHERE id <= ?").bind(floor).execute(db).await?;
        crate::db::set_setting(db, "jmap_changes.floor", &floor.to_string()).await?;
    }
    Ok(())
}

/// `Foo/changes` (RFC 8620 5.2) for a type kept in the log; ids are `prefix` + row id.
pub async fn changes(ctx: &Context<'_>, args: &Map<String, Value>, kind: &str, prefix: char) -> MethodResult {
    let since = args
        .get("sinceState")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n >= 0)
        .ok_or_else(|| MethodError("cannotCalculateChanges", "unknown state".into()))?;
    let max = args.get("maxChanges").and_then(Value::as_u64).unwrap_or(MAX_OBJECTS as u64).clamp(1, MAX_OBJECTS as u64) as usize;
    let current: i64 = state(ctx, kind).await?.parse().unwrap_or(0);
    if since < floor(ctx).await? || since > current {
        return Err(MethodError("cannotCalculateChanges", "the state is too old; refetch the data".into()));
    }
    let rows: Vec<(i64, i64, String)> = sqlx::query_as("SELECT id, item_id, change FROM jmap_changes WHERE account_id = ? AND kind = ? AND id > ? ORDER BY id")
        .bind(ctx.account.id)
        .bind(kind)
        .bind(since)
        .fetch_all(&ctx.app.db)
        .await?;
    let mut new_state = current;
    let mut has_more = false;
    let mut order: Vec<i64> = Vec::new();
    let mut seen: std::collections::HashMap<i64, (String, String)> = std::collections::HashMap::new();
    for (change_id, item, change) in rows {
        if !seen.contains_key(&item) {
            if order.len() >= max {
                // Stop at a change boundary; the client continues from this state.
                has_more = true;
                new_state = change_id - 1;
                break;
            }
            order.push(item);
        }
        seen.entry(item).and_modify(|e| e.1 = change.clone()).or_insert((change.clone(), change));
    }
    let (mut created, mut updated, mut destroyed) = (Vec::new(), Vec::new(), Vec::new());
    for item in order {
        let id = format!("{prefix}{item}");
        match &seen[&item] {
            (first, last) if first == "created" && last == "destroyed" => {}
            (first, _) if first == "created" => created.push(id),
            (_, last) if last == "destroyed" => destroyed.push(id),
            _ => updated.push(id),
        }
    }
    Ok(json!({
        "accountId": account_id(ctx.account),
        "oldState": since.to_string(),
        "newState": new_state.to_string(),
        "hasMoreChanges": has_more,
        "created": created,
        "updated": updated,
        "destroyed": destroyed,
    }))
}

/// The `ids` argument of a `/get`: `None` for all objects.
pub fn requested_ids(args: &Map<String, Value>) -> Result<Option<Vec<String>>, MethodError> {
    match args.get("ids") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(ids)) => {
            if ids.len() > MAX_OBJECTS {
                return Err(MethodError("requestTooLarge", "too many ids".into()));
            }
            Ok(Some(ids.iter().filter_map(Value::as_str).map(str::to_owned).collect()))
        }
        Some(_) => Err(MethodError::invalid("ids must be a list")),
    }
}

/// Keeps only the requested properties (the id always stays).
pub fn select(mut object: Value, args: &Map<String, Value>) -> Value {
    if let (Some(properties), Some(map)) = (args.get("properties").and_then(Value::as_array), object.as_object_mut()) {
        let wanted: Vec<&str> = properties.iter().filter_map(Value::as_str).collect();
        map.retain(|key, _| key == "id" || wanted.contains(&key.as_str()));
    }
    object
}

/// Applies a JMAP PatchObject (RFC 8620 5.3): keys are JSON pointers without the leading
/// slash; `null` removes the property.
pub fn apply_patch(target: &mut Value, patch: &Map<String, Value>) -> Result<(), String> {
    for (path, value) in patch {
        let segments: Vec<String> = path.split('/').map(|s| s.replace("~1", "/").replace("~0", "~")).collect();
        if segments.iter().any(String::is_empty) || segments.len() > 16 {
            return Err(format!("invalid patch path {path}"));
        }
        let (last, parents) = segments.split_last().expect("split always yields one segment");
        let mut node = &mut *target;
        for segment in parents {
            node = node.as_object_mut().and_then(|map| map.get_mut(segment)).ok_or_else(|| format!("the patch path {path} does not exist"))?;
        }
        let map = node.as_object_mut().ok_or_else(|| format!("the patch path {path} does not name a property"))?;
        if value.is_null() {
            map.remove(last);
        } else {
            map.insert(last.clone(), value.clone());
        }
    }
    Ok(())
}

/// The outcome of a `/set`, built up item by item.
#[derive(Default)]
pub struct SetResult {
    pub created: Map<String, Value>,
    pub not_created: Map<String, Value>,
    pub updated: Map<String, Value>,
    pub not_updated: Map<String, Value>,
    pub destroyed: Vec<String>,
    pub not_destroyed: Map<String, Value>,
}

impl SetResult {
    pub fn into_response(self, ctx: &Context<'_>, old_state: String, new_state: String) -> Value {
        json!({
            "accountId": account_id(ctx.account),
            "oldState": old_state,
            "newState": new_state,
            "created": self.created, "notCreated": self.not_created,
            "updated": self.updated, "notUpdated": self.not_updated,
            "destroyed": self.destroyed, "notDestroyed": self.not_destroyed,
        })
    }
}

/// Rejects a `/set` whose `ifInState` no longer holds.
pub fn check_state(args: &Map<String, Value>, current: &str) -> Result<(), MethodError> {
    match args.get("ifInState").and_then(Value::as_str) {
        Some(expected) if expected != current => Err(MethodError("stateMismatch", "the state has changed".into())),
        _ => Ok(()),
    }
}

/// Too many operations in one `/set`.
pub fn check_size(args: &Map<String, Value>) -> Result<(), MethodError> {
    let count = ["create", "update"].iter().filter_map(|k| args.get(*k).and_then(Value::as_object)).map(Map::len).sum::<usize>()
        + args.get("destroy").and_then(Value::as_array).map_or(0, Vec::len);
    if count > MAX_OBJECTS { Err(MethodError("requestTooLarge", "too many objects in one /set".into())) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patches() {
        let mut card = json!({ "name": { "full": "Ann" }, "emails": { "e1": { "address": "a@x.example" } } });
        let patch = json!({ "name/full": "Anna", "emails/e1": null, "notes": { "n1": { "note": "hi" } } });
        apply_patch(&mut card, patch.as_object().unwrap()).unwrap();
        assert_eq!(card, json!({ "name": { "full": "Anna" }, "emails": {}, "notes": { "n1": { "note": "hi" } } }));
        assert!(apply_patch(&mut card, json!({ "missing/deep": 1 }).as_object().unwrap()).is_err());
        assert!(apply_patch(&mut card, json!({ "name/full/x": 1 }).as_object().unwrap()).is_err());
        assert!(apply_patch(&mut card, json!({ "": 1 }).as_object().unwrap()).is_err());
    }
}
