//! JMAP Mailbox methods.

use serde_json::{Map, Value, json};

use super::{Context, MAX_OBJECTS, MethodError, MethodResult, account_id, parse_id, set_error};
use crate::store::{Mailbox, StoreError};

const SORT_ORDER: [&str; 6] = ["inbox", "drafts", "sent", "archive", "junk", "trash"];

/// `owner` is set for mailboxes shared by another account; `rights` are RFC 4314 letters.
async fn to_json(ctx: &Context<'_>, mailbox: &Mailbox, rights: &str, owner: Option<&str>) -> Result<Value, MethodError> {
    let (total, unread, threads, unread_threads): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(seen = 0), 0), COUNT(DISTINCT thread_id),
                COUNT(DISTINCT CASE WHEN seen = 0 THEN thread_id END)
         FROM messages WHERE mailbox_id = ?",
    )
    .bind(mailbox.id)
    .fetch_one(&ctx.app.db)
    .await?;
    let own = owner.is_none();
    let system = mailbox.role.is_some();
    let may = |right: char| rights.contains(right);
    let sort_order = if own { mailbox.role.as_deref().and_then(|r| SORT_ORDER.iter().position(|s| *s == r)).map_or(100, |p| p as i64) } else { 200 };
    let shared_with: i64 = if own { sqlx::query_scalar("SELECT COUNT(*) FROM mailbox_acl WHERE mailbox_id = ?").bind(mailbox.id).fetch_one(&ctx.app.db).await? } else { 0 };
    Ok(json!({
        "id": format!("b{}", mailbox.id),
        "name": match owner { Some(owner) => format!("{}{owner}/{}", crate::sharing::SHARED_PREFIX, mailbox.name), None => mailbox.name.clone() },
        "parentId": null,
        // A shared mailbox keeps no special role in the account it is shared with.
        "role": if own { mailbox.role.clone() } else { None },
        "shareOwner": owner,
        "sharedWith": shared_with,
        "sortOrder": sort_order,
        "totalEmails": total,
        "unreadEmails": unread,
        "totalThreads": threads,
        "unreadThreads": unread_threads,
        "isSubscribed": mailbox.subscribed,
        "myRights": {
            "mayReadItems": may('r'), "mayAddItems": may('i'), "mayRemoveItems": may('t') && may('e'), "maySetSeen": may('s'),
            "maySetKeywords": may('w'), "mayCreateChild": own, "mayRename": own && !system, "mayDelete": own && !system, "maySubmit": own,
            "mayAdmin": may('a'),
        },
    }))
}

pub async fn get(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let own = ctx.app.store.list_mailboxes(ctx.account.id).await?;
    let shared = crate::sharing::shared_with(&ctx.app.db, ctx.account).await?;
    // (mailbox, rights, owner of a shared mailbox)
    let all: Vec<(&Mailbox, &str, Option<&str>)> = own
        .iter()
        .map(|m| (m, crate::sharing::ALL_RIGHTS, None))
        .chain(shared.iter().map(|s| (&s.mailbox, s.rights.as_str(), Some(s.owner.as_str()))))
        .collect();
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    match args.get("ids").and_then(Value::as_array) {
        Some(ids) => {
            if ids.len() > MAX_OBJECTS {
                return Err(MethodError("requestTooLarge", "too many ids".into()));
            }
            for id in ids.iter().filter_map(Value::as_str) {
                match parse_id(id, 'b').and_then(|n| all.iter().find(|(m, _, _)| m.id == n)) {
                    Some((mailbox, rights, owner)) => list.push(to_json(ctx, mailbox, rights, *owner).await?),
                    None => not_found.push(id.to_owned()),
                }
            }
        }
        None => {
            for (mailbox, rights, owner) in &all {
                list.push(to_json(ctx, mailbox, rights, *owner).await?);
            }
        }
    }
    Ok(json!({ "accountId": account_id(ctx.account), "state": ctx.state().await?, "list": list, "notFound": not_found }))
}

fn store_error(err: StoreError) -> Value {
    match err {
        StoreError::NotFound => set_error("notFound", "mailbox not found"),
        StoreError::Exists => set_error("invalidProperties", "a mailbox with this name already exists"),
        StoreError::Invalid(msg) => set_error("invalidProperties", msg),
        other => {
            tracing::error!(error = ?other, "mailbox operation failed");
            set_error("serverFail", "internal error")
        }
    }
}

pub async fn set(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let old_state = ctx.state().await?;
    let store = &ctx.app.store;
    let account = ctx.account.id;
    let (mut created, mut not_created) = (Map::new(), Map::new());
    let (mut updated, mut not_updated) = (Map::new(), Map::new());
    let (mut destroyed, mut not_destroyed) = (Vec::new(), Map::new());

    if let Some(create) = args.get("create").and_then(Value::as_object) {
        for (creation_id, spec) in create {
            let Some(name) = spec["name"].as_str() else {
                not_created.insert(creation_id.clone(), set_error("invalidProperties", "name is required"));
                continue;
            };
            match store.create_mailbox(account, name.trim()).await {
                Ok(mailbox) => {
                    let id = format!("b{}", mailbox.id);
                    ctx.created.insert(creation_id.clone(), id.clone());
                    created.insert(creation_id.clone(), json!({ "id": id }));
                }
                Err(err) => {
                    not_created.insert(creation_id.clone(), store_error(err));
                }
            }
        }
    }
    if let Some(update) = args.get("update").and_then(Value::as_object) {
        for (id, patch) in update {
            let result = async {
                let mailbox_id = parse_id(id, 'b').ok_or(StoreError::NotFound)?;
                if let Some(name) = patch["name"].as_str() {
                    store.rename_mailbox(account, mailbox_id, name.trim()).await?;
                } else {
                    store.mailbox(account, mailbox_id).await?;
                }
                if let Some(subscribed) = patch["isSubscribed"].as_bool() {
                    sqlx::query("UPDATE mailboxes SET subscribed = ? WHERE id = ? AND account_id = ?")
                        .bind(subscribed)
                        .bind(mailbox_id)
                        .bind(account)
                        .execute(&store.db)
                        .await?;
                }
                Ok::<_, StoreError>(())
            }
            .await;
            match result {
                Ok(()) => updated.insert(id.clone(), Value::Null),
                Err(err) => not_updated.insert(id.clone(), store_error(err)),
            };
        }
    }
    if let Some(destroy) = args.get("destroy").and_then(Value::as_array) {
        let remove_emails = args.get("onDestroyRemoveEmails").and_then(Value::as_bool).unwrap_or(false);
        for id in destroy.iter().filter_map(Value::as_str) {
            let result = async {
                let mailbox_id = parse_id(id, 'b').ok_or(StoreError::NotFound)?;
                store.mailbox(account, mailbox_id).await?;
                let count = store.mailbox_counts(mailbox_id).await?.total;
                if count > 0 && !remove_emails {
                    return Ok(Err(set_error("mailboxHasEmail", "the mailbox is not empty")));
                }
                store.delete_mailbox(account, mailbox_id).await?;
                Ok::<_, StoreError>(Ok(()))
            }
            .await;
            match result {
                Ok(Ok(())) => destroyed.push(id.to_owned()),
                Ok(Err(err)) => {
                    not_destroyed.insert(id.to_owned(), err);
                }
                Err(err) => {
                    not_destroyed.insert(id.to_owned(), store_error(err));
                }
            }
        }
    }
    Ok(json!({
        "accountId": account_id(ctx.account),
        "oldState": old_state,
        "newState": ctx.state().await?,
        "created": created, "notCreated": not_created,
        "updated": updated, "notUpdated": not_updated,
        "destroyed": destroyed, "notDestroyed": not_destroyed,
    }))
}
