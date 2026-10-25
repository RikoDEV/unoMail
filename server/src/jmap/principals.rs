//! JMAP Sharing (RFC 9670): the principals a user can share with, as Principal/get, /query
//! and /changes, and an always-empty ShareNotification list.
//!
//! The directory is the user's own domain: the same people the web client offers when sharing
//! a mailbox, calendar or address book. Sharing itself is set through the objects' own rights
//! (mailbox ACLs), so principals are read-only here.

use serde_json::{Map, Value, json};

use super::{Context, MethodError, MethodResult, account_id};

pub const CAPABILITY: &str = "urn:ietf:params:jmap:principals";
pub const OWNER_CAPABILITY: &str = "urn:ietf:params:jmap:principals:owner";

pub fn principal_id(account: i64) -> String {
    format!("p{account}")
}

pub fn capability(account: &crate::auth::Account) -> Value {
    json!({ "currentUserPrincipalAccountId": account_id(account), "currentUserPrincipalId": principal_id(account.id) })
}

pub fn owner_capability(account: &crate::auth::Account) -> Value {
    json!({ "accountIdForPrincipal": account_id(account), "principalId": principal_id(account.id) })
}

type Row = (i64, String, String);

async fn directory(ctx: &Context<'_>) -> Result<Vec<Row>, MethodError> {
    Ok(sqlx::query_as("SELECT id, email, display_name FROM accounts WHERE domain_id = ? AND enabled = 1 ORDER BY email LIMIT 5000")
        .bind(ctx.account.domain_id)
        .fetch_all(&ctx.app.db)
        .await?)
}

/// The state moves whenever someone joins, leaves or is renamed in the domain.
fn state_of(rows: &[Row]) -> String {
    let mut text = String::new();
    for (id, email, name) in rows {
        text.push_str(&format!("{id}\0{email}\0{name}\n"));
    }
    crate::util::sha256_hex(text.as_bytes())[..16].to_owned()
}

fn to_json(ctx: &Context<'_>, (id, email, name): &Row) -> Value {
    let mut accounts = Map::new();
    if *id == ctx.account.id {
        accounts.insert(account_id(ctx.account), json!({ OWNER_CAPABILITY: owner_capability(ctx.account) }));
    }
    json!({
        "id": principal_id(*id),
        "type": "individual",
        "name": if name.is_empty() { email } else { name },
        "description": null,
        "email": email,
        "timeZone": null,
        "capabilities": {},
        "accounts": if accounts.is_empty() { Value::Null } else { Value::Object(accounts) },
    })
}

pub async fn get(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let rows = directory(ctx).await?;
    let state = state_of(&rows);
    let (list, not_found) = match args.get("ids").and_then(Value::as_array) {
        None => (rows.iter().take(super::MAX_OBJECTS).map(|r| to_json(ctx, r)).collect::<Vec<_>>(), Vec::new()),
        Some(ids) => {
            if ids.len() > super::MAX_OBJECTS {
                return Err(MethodError("requestTooLarge", "too many ids".into()));
            }
            let mut list = Vec::new();
            let mut not_found = Vec::new();
            for id in ids.iter().filter_map(Value::as_str) {
                match rows.iter().find(|r| principal_id(r.0) == id) {
                    Some(row) => list.push(to_json(ctx, row)),
                    None => not_found.push(json!(id)),
                }
            }
            (list, not_found)
        }
    };
    Ok(json!({ "accountId": account_id(ctx.account), "state": state, "list": list, "notFound": not_found }))
}

pub async fn query(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let rows = directory(ctx).await?;
    let filter = args.get("filter").and_then(Value::as_object);
    let wanted = |key: &str| filter.and_then(|f| f.get(key)).and_then(Value::as_str).map(str::to_lowercase);
    let (email, name, text, kind) = (wanted("email"), wanted("name"), wanted("text"), wanted("type"));
    let ids: Vec<String> = rows
        .iter()
        .filter(|(_, e, n)| {
            let (e, n) = (e.to_lowercase(), n.to_lowercase());
            email.as_ref().is_none_or(|q| e.contains(q))
                && name.as_ref().is_none_or(|q| n.contains(q))
                && text.as_ref().is_none_or(|q| e.contains(q) || n.contains(q))
                && kind.as_ref().is_none_or(|q| q == "individual")
        })
        .map(|r| principal_id(r.0))
        .collect();
    let position = args.get("position").and_then(Value::as_u64).unwrap_or(0) as usize;
    let limit = args.get("limit").and_then(Value::as_u64).map_or(super::MAX_OBJECTS, |l| (l as usize).min(super::MAX_OBJECTS));
    let page: Vec<&String> = ids.iter().skip(position).take(limit).collect();
    Ok(json!({ "accountId": account_id(ctx.account), "queryState": state_of(&rows), "canCalculateChanges": false, "position": position, "ids": page, "total": ids.len() }))
}

pub async fn changes(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let rows = directory(ctx).await?;
    let state = state_of(&rows);
    if args.get("sinceState").and_then(Value::as_str) == Some(state.as_str()) {
        return Ok(json!({ "accountId": account_id(ctx.account), "oldState": state, "newState": state, "hasMoreChanges": false, "created": [], "updated": [], "destroyed": [] }));
    }
    Err(MethodError("cannotCalculateChanges", "fetch the principals again".into()))
}

/// Shares are made and removed by the users themselves here, so there is nothing to notify.
pub async fn notifications(ctx: &mut Context<'_>, name: &str, args: &Map<String, Value>) -> MethodResult {
    let account = account_id(ctx.account);
    Ok(match name {
        "ShareNotification/get" => {
            let not_found = args.get("ids").and_then(Value::as_array).cloned().unwrap_or_default();
            json!({ "accountId": account, "state": "0", "list": [], "notFound": not_found })
        }
        "ShareNotification/query" => json!({ "accountId": account, "queryState": "0", "canCalculateChanges": true, "position": 0, "ids": [], "total": 0 }),
        "ShareNotification/changes" => json!({ "accountId": account, "oldState": "0", "newState": "0", "hasMoreChanges": false, "created": [], "updated": [], "destroyed": [] }),
        _ => {
            let destroyed = args.get("destroy").and_then(Value::as_array).cloned().unwrap_or_default();
            let not_destroyed: Map<String, Value> = destroyed.iter().filter_map(Value::as_str).map(|id| (id.to_owned(), super::set_error("notFound", "no such notification"))).collect();
            json!({ "accountId": account, "oldState": "0", "newState": "0", "destroyed": [], "notDestroyed": not_destroyed })
        }
    })
}
