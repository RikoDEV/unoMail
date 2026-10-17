//! JMAP Quota (RFC 9425): the account's storage quota, as Quota/get, /changes, /query and
//! /queryChanges.
//!
//! An account has at most one quota, `q1`, counting octets of mail. Accounts without a limit
//! have none. The state is derived from the figures themselves, so it moves whenever they do.

use serde_json::{Map, Value, json};

use super::{Context, MethodError, MethodResult, account_id};

const QUOTA_ID: &str = "q1";

/// (used, limit) of the account; `None` without a limit.
async fn usage(ctx: &Context<'_>) -> Result<Option<(i64, i64)>, MethodError> {
    let (quota, used): (i64, i64) = sqlx::query_as("SELECT quota_bytes, used_bytes FROM accounts WHERE id = ?").bind(ctx.account.id).fetch_one(&ctx.app.db).await?;
    Ok((quota > 0).then_some((used.max(0), quota)))
}

fn state_of(usage: Option<(i64, i64)>) -> String {
    match usage {
        Some((used, limit)) => format!("{used}-{limit}"),
        None => "none".into(),
    }
}

fn to_json(used: i64, limit: i64) -> Value {
    json!({
        "id": QUOTA_ID,
        "resourceType": "octets",
        "used": used,
        "hardLimit": limit,
        // Warned about from 90%, like the web client does.
        "warnLimit": limit / 10 * 9,
        "scope": "account",
        "name": "Mail storage",
        "types": ["Email"],
        "description": "Space taken by the messages of this account.",
    })
}

pub async fn get(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let usage = usage(ctx).await?;
    let ids = super::objects::requested_ids(args)?;
    let (mut list, mut not_found) = (Vec::new(), Vec::new());
    match (&ids, usage) {
        (None, Some((used, limit))) => list.push(super::objects::select(to_json(used, limit), args)),
        (None, None) => {}
        (Some(ids), _) => {
            for id in ids {
                match usage {
                    Some((used, limit)) if id == QUOTA_ID => list.push(super::objects::select(to_json(used, limit), args)),
                    _ => not_found.push(id.clone()),
                }
            }
        }
    }
    Ok(json!({ "accountId": account_id(ctx.account), "state": state_of(usage), "list": list, "notFound": not_found }))
}

pub async fn changes(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let since = args.get("sinceState").and_then(Value::as_str).ok_or_else(|| MethodError::invalid("sinceState is required"))?;
    let usage = usage(ctx).await?;
    let current = state_of(usage);
    let (created, updated, destroyed): (Vec<&str>, Vec<&str>, Vec<&str>) = match (since == current, since == "none", usage.is_some()) {
        (true, _, _) => (vec![], vec![], vec![]),
        (false, true, true) => (vec![QUOTA_ID], vec![], vec![]),
        (false, false, true) => (vec![], vec![QUOTA_ID], vec![]),
        (false, _, false) => (vec![], vec![], vec![QUOTA_ID]),
    };
    Ok(json!({
        "accountId": account_id(ctx.account),
        "oldState": since,
        "newState": current,
        "hasMoreChanges": false,
        "created": created,
        "updated": updated,
        "destroyed": destroyed,
        "updatedProperties": if updated.is_empty() { Value::Null } else { json!(["used", "hardLimit", "warnLimit"]) },
    }))
}

/// Whether the one quota matches a filter (RFC 9425 4.3): name, scope, resourceType, type.
fn matches(filter: &Value) -> bool {
    let Some(filter) = filter.as_object() else { return true };
    if let Some(operator) = filter.get("operator").and_then(Value::as_str) {
        let conditions: Vec<bool> = filter.get("conditions").and_then(Value::as_array).map(|c| c.iter().map(matches).collect()).unwrap_or_default();
        return match operator {
            "AND" => conditions.iter().all(|c| *c),
            "OR" => conditions.iter().any(|c| *c),
            _ => !conditions.iter().any(|c| *c),
        };
    }
    let quota = to_json(0, 0);
    filter.iter().all(|(key, wanted)| match (key.as_str(), wanted.as_str()) {
        ("name", Some(text)) => quota["name"].as_str().is_some_and(|name| name.to_lowercase().contains(&text.to_lowercase())),
        ("scope", Some(text)) => text == "account",
        ("resourceType", Some(text)) => text == "octets",
        ("type", Some(text)) => text == "Email",
        _ => true,
    })
}

pub async fn query(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let usage = usage(ctx).await?;
    let found = usage.is_some() && args.get("filter").is_none_or(matches);
    let ids: Vec<&str> = if found { vec![QUOTA_ID] } else { vec![] };
    let position = args.get("position").and_then(Value::as_i64).unwrap_or(0);
    let ids: Vec<&str> = if position == 0 || position == -1 { ids } else { vec![] };
    Ok(json!({
        "accountId": account_id(ctx.account),
        "queryState": state_of(usage),
        "canCalculateChanges": false,
        "position": 0,
        "ids": ids,
        "total": ids.len(),
    }))
}

pub async fn query_changes(_ctx: &mut Context<'_>, _args: &Map<String, Value>) -> MethodResult {
    Err(MethodError("cannotCalculateChanges", "run the query again; it has at most one result".into()))
}
