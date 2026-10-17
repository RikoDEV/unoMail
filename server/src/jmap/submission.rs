//! EmailSubmission (RFC 8621 section 7) with delayed release (FUTURERELEASE, RFC 4865): a
//! submission may wait up to 30 days (scheduled send) or a few seconds (undo send) and can be
//! canceled until then. A waiting email carries the `$scheduled` keyword and stays where it is
//! (normally in Drafts); once sent, the changes the client asked for (`onSuccessUpdateEmail`,
//! typically "move to Sent") are applied.

use std::time::Duration;

use serde_json::{Map, Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{Context, MethodResult, account_id, email, parse_id, set_error};
use crate::{
    app::{App, AppState},
    auth::Account,
    util::now,
};

/// The longest a submission may be held back (RFC 4865 `FUTURERELEASE`).
pub const MAX_DELAY: i64 = 30 * 86_400;
pub const SCHEDULED: &str = "$scheduled";
/// Holds up to this long are an undo window rather than a schedule.
const UNDO_WINDOW: i64 = 60;

fn timestamp(secs: i64) -> Value {
    OffsetDateTime::from_unix_timestamp(secs).ok().and_then(|t| t.format(&Rfc3339).ok()).map_or(Value::Null, Value::String)
}

/// When a submission should go out, from `HOLDFOR` (seconds) or `HOLDUNTIL` (a time).
fn release_time(spec: &Value) -> Result<Option<i64>, Value> {
    let parameters = &spec["envelope"]["mailFrom"]["parameters"];
    let hold_for = match &parameters["HOLDFOR"] {
        Value::Null => None,
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    };
    let at = match (hold_for, parameters["HOLDUNTIL"].as_str()) {
        (Some(seconds), _) if (0..=MAX_DELAY).contains(&seconds) => now() + seconds,
        (Some(_), _) => return Err(set_error("invalidProperties", "HOLDFOR is out of range")),
        (None, Some(until)) => OffsetDateTime::parse(until, &Rfc3339).map_err(|_| set_error("invalidProperties", "HOLDUNTIL must be a date-time"))?.unix_timestamp(),
        (None, None) => return Ok(None),
    };
    if at > now() + MAX_DELAY {
        return Err(set_error("invalidProperties", "a submission can be held back for 30 days at most"));
    }
    Ok((at > now()).then_some(at))
}

async fn set_scheduled(ctx: &Context<'_>, message_id: i64, on: bool) {
    let patch = Map::from_iter([(format!("keywords/{SCHEDULED}"), if on { Value::Bool(true) } else { Value::Null })]);
    let _ = email::apply_update(ctx, &format!("m{message_id}"), &patch).await;
}

pub async fn set(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let (mut created, mut not_created) = (Map::new(), Map::new());
    let (mut updated, mut not_updated) = (Map::new(), Map::new());
    let (mut destroyed, mut not_destroyed) = (Vec::new(), Map::new());
    let mut email_updates = Map::new();
    for (creation_id, spec) in args.get("create").and_then(Value::as_object).into_iter().flatten() {
        let Some(message_id) = spec["emailId"].as_str().map(|id| ctx.resolve_id(id)).and_then(|id| parse_id(&id, 'm')) else {
            not_created.insert(creation_id.clone(), set_error("invalidProperties", "emailId is required"));
            continue;
        };
        let on_success = args.get("onSuccessUpdateEmail").and_then(|u| u.get(format!("#{creation_id}"))).cloned().unwrap_or(Value::Null);
        let release = match release_time(spec) {
            Ok(release) => release,
            Err(err) => {
                not_created.insert(creation_id.clone(), err);
                continue;
            }
        };
        match release {
            None => match email::send_email(ctx, message_id).await {
                Ok(()) => {
                    created.insert(creation_id.clone(), json!({ "id": format!("s{}", crate::util::random_token()), "undoStatus": "final", "sendAt": timestamp(now()) }));
                    if let Value::Object(patch) = &on_success {
                        let result = email::apply_update(ctx, &format!("m{message_id}"), patch).await;
                        email_updates.insert(format!("m{message_id}"), result.err().unwrap_or(Value::Null));
                    }
                }
                Err(err) => {
                    not_created.insert(creation_id.clone(), err);
                }
            },
            Some(at) => {
                // Checked now, so that problems show while the user is still there.
                if let Err(err) = email::prepare_email(ctx, message_id).await {
                    not_created.insert(creation_id.clone(), err);
                    continue;
                }
                // A short hold is the window to undo sending: the message already looks sent
                // (in Sent), and goes back to Drafts if called back. A scheduled one waits in
                // Drafts.
                let undo_window = at - now() <= UNDO_WINDOW;
                let stored = if undo_window && let Value::Object(patch) = &on_success {
                    let result = email::apply_update(ctx, &format!("m{message_id}"), patch).await;
                    email_updates.insert(format!("m{message_id}"), result.err().unwrap_or(Value::Null));
                    json!({ "applied": true })
                } else {
                    on_success.clone()
                };
                let id: i64 = sqlx::query_scalar("INSERT INTO email_submissions (account_id, message_id, send_at, on_success, created_at) VALUES (?, ?, ?, ?, ?) RETURNING id")
                    .bind(ctx.account.id)
                    .bind(message_id)
                    .bind(at)
                    .bind(stored.to_string())
                    .bind(now())
                    .fetch_one(&ctx.app.db)
                    .await?;
                set_scheduled(ctx, message_id, true).await;
                ctx.created.insert(creation_id.clone(), format!("s{id}"));
                created.insert(creation_id.clone(), json!({ "id": format!("s{id}"), "undoStatus": "pending", "sendAt": timestamp(at) }));
            }
        }
    }
    for (id, patch) in args.get("update").and_then(Value::as_object).into_iter().flatten() {
        let row: Option<(i64, String, String)> = match parse_id(&ctx.resolve_id(id), 's') {
            Some(row_id) => sqlx::query_as("SELECT message_id, undo_status, on_success FROM email_submissions WHERE id = ? AND account_id = ?").bind(row_id).bind(ctx.account.id).fetch_optional(&ctx.app.db).await?,
            None => None,
        };
        match (row, patch["undoStatus"].as_str()) {
            (None, _) => {
                not_updated.insert(id.clone(), set_error("notFound", "no such submission"));
            }
            (Some((message_id, status, on_success)), Some("canceled")) if status == "pending" => {
                sqlx::query("UPDATE email_submissions SET undo_status = 'canceled' WHERE id = ? AND undo_status = 'pending'").bind(parse_id(&ctx.resolve_id(id), 's')).execute(&ctx.app.db).await?;
                set_scheduled(ctx, message_id, false).await;
                // Already shown as sent: back to Drafts.
                if on_success.contains("\"applied\"")
                    && let Ok(Some(drafts)) = ctx.app.store.mailbox_by_role(ctx.account.id, "drafts").await
                {
                    let patch = Map::from_iter([("mailboxIds".to_owned(), json!({ format!("b{}", drafts.id): true })), ("keywords/$draft".to_owned(), Value::Bool(true))]);
                    let _ = email::apply_update(ctx, &format!("m{message_id}"), &patch).await;
                }
                updated.insert(id.clone(), Value::Null);
            }
            (Some(_), Some("canceled")) => {
                not_updated.insert(id.clone(), set_error("cannotUnsend", "the message has been sent already"));
            }
            _ => {
                not_updated.insert(id.clone(), set_error("invalidProperties", "only undoStatus can be changed, to canceled"));
            }
        }
    }
    for id in args.get("destroy").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
        let row: Option<(i64, String)> = match parse_id(id, 's') {
            Some(row_id) => sqlx::query_as("DELETE FROM email_submissions WHERE id = ? AND account_id = ? RETURNING message_id, undo_status").bind(row_id).bind(ctx.account.id).fetch_optional(&ctx.app.db).await?,
            None => None,
        };
        match row {
            Some((message_id, status)) => {
                if status == "pending" {
                    set_scheduled(ctx, message_id, false).await;
                }
                destroyed.push(id.to_owned());
            }
            None => {
                not_destroyed.insert(id.to_owned(), set_error("notFound", "no such submission"));
            }
        }
    }
    let state = pending_state(ctx).await;
    let null_if_empty = |map: Map<String, Value>| if map.is_empty() { Value::Null } else { Value::Object(map) };
    Ok(json!({
        "accountId": account_id(ctx.account),
        "oldState": state, "newState": state,
        "created": null_if_empty(created), "notCreated": null_if_empty(not_created),
        "updated": null_if_empty(updated), "notUpdated": null_if_empty(not_updated),
        "destroyed": if destroyed.is_empty() { Value::Null } else { json!(destroyed) }, "notDestroyed": null_if_empty(not_destroyed),
        "emailUpdates": email_updates,
    }))
}

async fn pending_state(ctx: &Context<'_>) -> String {
    sqlx::query_scalar::<_, i64>("SELECT COALESCE(MAX(id), 0) FROM email_submissions WHERE account_id = ?").bind(ctx.account.id).fetch_one(&ctx.app.db).await.unwrap_or(0).to_string()
}

type Row = (i64, i64, i64, String, String);

fn view(row: &Row) -> Value {
    let (id, message_id, send_at, status, error) = row;
    json!({
        "id": format!("s{id}"),
        "emailId": format!("m{message_id}"),
        "identityId": null,
        "envelope": null,
        "sendAt": timestamp(*send_at),
        "undoStatus": status,
        "deliveryStatus": null,
        "dsnBlobIds": [],
        "mdnBlobIds": [],
        "error": if error.is_empty() { Value::Null } else { Value::String(error.clone()) },
    })
}

async fn rows(ctx: &Context<'_>) -> Result<Vec<Row>, super::MethodError> {
    Ok(sqlx::query_as("SELECT id, message_id, send_at, undo_status, error FROM email_submissions WHERE account_id = ? ORDER BY send_at, id").bind(ctx.account.id).fetch_all(&ctx.app.db).await?)
}

pub async fn get(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let wanted: Option<Vec<String>> = args.get("ids").and_then(Value::as_array).map(|ids| ids.iter().filter_map(|i| i.as_str().map(str::to_owned)).collect());
    let all = rows(ctx).await?;
    let list: Vec<Value> = all.iter().filter(|r| wanted.as_ref().is_none_or(|w| w.contains(&format!("s{}", r.0)))).map(view).collect();
    let not_found: Vec<String> = wanted.unwrap_or_default().into_iter().filter(|id| !all.iter().any(|r| format!("s{}", r.0) == *id)).collect();
    Ok(json!({ "accountId": account_id(ctx.account), "state": pending_state(ctx).await, "list": list, "notFound": not_found }))
}

pub async fn query(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let filter = args.get("filter").cloned().unwrap_or(Value::Null);
    let status = filter["undoStatus"].as_str();
    let emails: Option<Vec<String>> = filter["emailIds"].as_array().map(|ids| ids.iter().filter_map(|i| i.as_str().map(str::to_owned)).collect());
    let ids: Vec<String> = rows(ctx)
        .await?
        .into_iter()
        .filter(|r| status.is_none_or(|s| s == r.3) && emails.as_ref().is_none_or(|e| e.contains(&format!("m{}", r.1))))
        .map(|r| format!("s{}", r.0))
        .collect();
    Ok(json!({ "accountId": account_id(ctx.account), "queryState": pending_state(ctx).await, "canCalculateChanges": false, "position": 0, "ids": ids, "total": ids.len() }))
}

/// Sends what is due. Checked every few seconds.
pub async fn run(app: AppState) {
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        release_due(&app).await;
    }
}

/// Calls off everything the account scheduled. After its credentials were reset (a takeover,
/// perhaps), mail an intruder queued for later must not go out in the owner's name.
pub async fn cancel_pending(db: impl sqlx::SqliteExecutor<'_>, account_id: i64) -> sqlx::Result<()> {
    sqlx::query("UPDATE email_submissions SET undo_status = 'canceled', error = 'canceled when the sign-in credentials were reset' WHERE account_id = ? AND undo_status = 'pending'")
        .bind(account_id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn release_due(app: &AppState) {
    let due: Vec<(i64, i64, i64, String)> = sqlx::query_as("SELECT id, account_id, message_id, on_success FROM email_submissions WHERE undo_status = 'pending' AND send_at <= ? ORDER BY send_at LIMIT 50")
        .bind(now())
        .fetch_all(&app.db)
        .await
        .unwrap_or_default();
    for (id, account, message_id, on_success) in due {
        // A disabled mailbox (or domain) sends nothing, scheduled before or not.
        let active: bool = sqlx::query_scalar("SELECT a.enabled = 1 AND d.enabled = 1 FROM accounts a JOIN domains d ON d.id = a.domain_id WHERE a.id = ?")
            .bind(account)
            .fetch_optional(&app.db)
            .await
            .ok()
            .flatten()
            .unwrap_or(false);
        if !active {
            let _ = sqlx::query("UPDATE email_submissions SET undo_status = 'canceled', error = 'the mailbox is disabled' WHERE id = ? AND undo_status = 'pending'").bind(id).execute(&app.db).await;
            continue;
        }
        // Claim it first: a cancel arriving now loses, a second worker skips it.
        let claimed = sqlx::query("UPDATE email_submissions SET undo_status = 'final' WHERE id = ? AND undo_status = 'pending'").bind(id).execute(&app.db).await;
        if !claimed.is_ok_and(|r| r.rows_affected() == 1) {
            continue;
        }
        let Ok(Some(account)) = Account::by_id(&app.db, account).await else { continue };
        let ctx = Context { app, account: &account, ip: std::net::IpAddr::from([127, 0, 0, 1]), created: Default::default() };
        set_scheduled(&ctx, message_id, false).await;
        match email::send_email(&ctx, message_id).await {
            Ok(()) => {
                if let Ok(Value::Object(patch)) = serde_json::from_str::<Value>(&on_success)
                    && !patch.contains_key("applied")
                {
                    let _ = email::apply_update(&ctx, &format!("m{message_id}"), &patch).await;
                }
            }
            Err(err) => {
                let reason = err["description"].as_str().unwrap_or("the message could not be sent").to_owned();
                let _ = sqlx::query("UPDATE email_submissions SET error = ? WHERE id = ?").bind(&reason).bind(id).execute(&app.db).await;
                tell_owner(app, &account, &reason).await;
            }
        }
    }
    // Old records go after a while.
    let _ = sqlx::query("DELETE FROM email_submissions WHERE undo_status != 'pending' AND send_at < ?").bind(now() - 7 * 86_400).execute(&app.db).await;
}

/// A note in the inbox when a scheduled message could not be sent.
async fn tell_owner(app: &App, account: &Account, reason: &str) {
    let Ok(Some(inbox)) = app.store.mailbox_by_role(account.id, "inbox").await else { return };
    let text = format!(
        "From: Mail Delivery System <MAILER-DAEMON@{host}>\r\nTo: <{to}>\r\nSubject: A scheduled message was not sent\r\nDate: {date}\r\nMessage-ID: <{id}@{host}>\r\nAuto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nA message you scheduled could not be sent: {reason}\r\nIt is still in your Drafts folder.\r\n",
        host = app.cfg.hostname,
        to = account.email,
        date = crate::smtp::delivery::rfc2822_now(),
        id = crate::util::random_token(),
        reason = crate::util::sanitize_line(reason),
    );
    let _ = app.store.append(account.id, inbox.id, text.as_bytes(), crate::store::Flags::default(), None).await;
}
