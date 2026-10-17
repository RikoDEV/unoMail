//! JMAP for Contacts (RFC 9610): AddressBook/get|changes|set and ContactCard/get|changes|
//! query|set, with cards in JSContact form (RFC 9553).
//!
//! Every account has one address book, the one the web client and CardDAV use. A card holds
//! what the web client knows of a person: name, one e-mail address, one phone number, an
//! organization and notes. Properties beyond those, which CardDAV clients may have stored,
//! stay in the card but are not shown here.

use serde_json::{Map, Value, json};

use super::{
    Context, MethodError, MethodResult, account_id,
    objects::{self, SetResult},
    parse_id, set_error,
};
use crate::util::{Address, now};

/// The one address book of an account.
const BOOK_ID: &str = "default";
const MAX_CONTACTS: i64 = 5000;

#[derive(sqlx::FromRow)]
struct Row {
    id: i64,
    uid: String,
    name: String,
    email: String,
    phone: String,
    organization: String,
    notes: String,
    updated_at: i64,
}

const COLUMNS: &str = "id, uid, name, email, phone, organization, notes, updated_at";

fn utc(at: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(at).ok().and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok()).unwrap_or_default()
}

fn to_json(row: &Row) -> Value {
    let mut card = json!({
        "@type": "Card",
        "version": "1.0",
        "id": format!("c{}", row.id),
        "addressBookIds": { BOOK_ID: true },
        "uid": row.uid,
        "kind": "individual",
        "updated": utc(row.updated_at),
    });
    if !row.name.is_empty() {
        card["name"] = json!({ "@type": "Name", "full": row.name });
    }
    if !row.email.is_empty() {
        card["emails"] = json!({ "e1": { "@type": "EmailAddress", "address": row.email } });
    }
    if !row.phone.is_empty() {
        card["phones"] = json!({ "p1": { "@type": "Phone", "number": row.phone } });
    }
    if !row.organization.is_empty() {
        card["organizations"] = json!({ "o1": { "@type": "Organization", "name": row.organization } });
    }
    if !row.notes.is_empty() {
        card["notes"] = json!({ "n1": { "@type": "Note", "note": row.notes } });
    }
    card
}

/// The fields of a card as stored; extra entries of a map (a second e-mail address) are not
/// kept, which the client learns from the card it reads back.
#[derive(Debug, Default, PartialEq, Eq)]
struct Fields {
    uid: Option<String>,
    name: String,
    email: String,
    phone: String,
    organization: String,
    notes: String,
}

fn first<'a>(card: &'a Value, map: &str, key: &str) -> Option<&'a str> {
    card[map].as_object()?.values().find_map(|entry| entry[key].as_str())
}

fn clean(text: &str, max: usize, what: &str, multiline: bool) -> Result<String, Value> {
    let text: String = text.trim().chars().filter(|c| !c.is_control() || (multiline && *c == '\n')).collect();
    if text.chars().count() > max { Err(set_error("invalidProperties", format!("{what} is too long"))) } else { Ok(text) }
}

fn fields_of(card: &Value) -> Result<Fields, Value> {
    let Some(map) = card.as_object() else { return Err(set_error("invalidProperties", "a card must be an object")) };
    const KNOWN: [&str; 14] = ["@type", "version", "id", "addressBookIds", "uid", "kind", "updated", "created", "name", "emails", "phones", "organizations", "notes", "prodId"];
    if let Some(unknown) = map.keys().find(|key| !KNOWN.contains(&key.as_str())) {
        return Err(set_error("invalidProperties", format!("{unknown} cannot be stored")).tap_properties(unknown));
    }
    if let Some(books) = map.get("addressBookIds").and_then(Value::as_object)
        && (books.len() != 1 || books.get(BOOK_ID) != Some(&Value::Bool(true)))
    {
        return Err(set_error("invalidProperties", "cards belong to the address book \"default\"").tap_properties("addressBookIds"));
    }
    // Composed names are joined, as RFC 9553 2.2.1 allows when there is no full name.
    let name = card["name"]["full"].as_str().map(str::to_owned).unwrap_or_else(|| {
        card["name"]["components"].as_array().map(|parts| parts.iter().filter_map(|p| p["value"].as_str()).collect::<Vec<_>>().join(" ")).unwrap_or_default()
    });
    let email = match first(card, "emails", "address").map(str::trim).filter(|a| !a.is_empty()) {
        Some(address) => Address::parse(address).ok_or_else(|| set_error("invalidProperties", "invalid e-mail address").tap_properties("emails"))?.to_string(),
        None => String::new(),
    };
    let uid = match card["uid"].as_str() {
        Some(uid) if uid.is_empty() || uid.len() > 200 || uid.chars().any(char::is_control) => return Err(set_error("invalidProperties", "invalid uid").tap_properties("uid")),
        uid => uid.map(str::to_owned),
    };
    Ok(Fields {
        uid,
        name: clean(&name, 200, "the name", false)?,
        email,
        phone: clean(first(card, "phones", "number").unwrap_or(""), 50, "the phone number", false)?,
        organization: clean(first(card, "organizations", "name").unwrap_or(""), 200, "the organization", false)?,
        notes: clean(first(card, "notes", "note").unwrap_or(""), 2000, "the note", true)?,
    })
}

trait TapProperties {
    fn tap_properties(self, property: &str) -> Self;
}

impl TapProperties for Value {
    fn tap_properties(mut self, property: &str) -> Self {
        self["properties"] = json!([property]);
        self
    }
}

async fn row(ctx: &Context<'_>, id: i64) -> Result<Option<Row>, MethodError> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {COLUMNS} FROM contacts WHERE account_id = ? AND id = ?"))).bind(ctx.account.id).bind(id).fetch_optional(&ctx.app.db).await?)
}

fn book(ctx: &Context<'_>) -> Value {
    json!({
        "id": BOOK_ID,
        "name": "Contacts",
        "description": null,
        "sortOrder": 0,
        "isDefault": true,
        "isSubscribed": true,
        "shareWith": null,
        "myRights": { "mayRead": true, "mayWrite": true, "mayShare": false, "mayDelete": false },
        "owner": ctx.account.email,
    })
}

pub async fn book_get(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let (mut list, mut not_found) = (Vec::new(), Vec::new());
    match objects::requested_ids(args)? {
        None => list.push(objects::select(book(ctx), args)),
        Some(ids) => {
            for id in ids {
                if id == BOOK_ID { list.push(objects::select(book(ctx), args)) } else { not_found.push(id) }
            }
        }
    }
    // The address book itself never changes.
    Ok(json!({ "accountId": account_id(ctx.account), "state": "1", "list": list, "notFound": not_found }))
}

pub async fn book_changes(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    match args.get("sinceState").and_then(Value::as_str) {
        Some("1") => Ok(json!({ "accountId": account_id(ctx.account), "oldState": "1", "newState": "1", "hasMoreChanges": false, "created": [], "updated": [], "destroyed": [] })),
        _ => Err(MethodError("cannotCalculateChanges", "unknown state".into())),
    }
}

/// The one address book cannot be created, renamed or removed.
pub async fn book_set(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    objects::check_state(args, "1")?;
    let mut result = SetResult::default();
    let refuse = |what: &str| set_error("forbidden", format!("the address book cannot be {what}"));
    for (id, _) in args.get("create").and_then(Value::as_object).into_iter().flatten() {
        result.not_created.insert(id.clone(), refuse("added to"));
    }
    for (id, _) in args.get("update").and_then(Value::as_object).into_iter().flatten() {
        result.not_updated.insert(id.clone(), if id == BOOK_ID { refuse("changed") } else { set_error("notFound", "no such address book") });
    }
    for id in args.get("destroy").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
        result.not_destroyed.insert(id.to_owned(), if id == BOOK_ID { refuse("removed") } else { set_error("notFound", "no such address book") });
    }
    Ok(result.into_response(ctx, "1".into(), "1".into()))
}

pub async fn get(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let (mut list, mut not_found) = (Vec::new(), Vec::new());
    match objects::requested_ids(args)? {
        None => {
            let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {COLUMNS} FROM contacts WHERE account_id = ? ORDER BY id LIMIT {}", super::MAX_OBJECTS)))
                .bind(ctx.account.id)
                .fetch_all(&ctx.app.db)
                .await?;
            list.extend(rows.iter().map(|row| objects::select(to_json(row), args)));
        }
        Some(ids) => {
            for id in ids {
                match parse_id(&id, 'c') {
                    Some(n) => match row(ctx, n).await? {
                        Some(row) => list.push(objects::select(to_json(&row), args)),
                        None => not_found.push(id),
                    },
                    None => not_found.push(id),
                }
            }
        }
    }
    Ok(json!({ "accountId": account_id(ctx.account), "state": objects::state(ctx, "ContactCard").await?, "list": list, "notFound": not_found }))
}

pub async fn changes(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    objects::changes(ctx, args, "ContactCard", 'c').await
}

fn like(text: &str) -> String {
    format!("%{}%", text.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"))
}

/// ContactCard/query with the filters of RFC 9610 2.3 that apply to these cards.
pub async fn query(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let filter = args.get("filter").and_then(Value::as_object).cloned().unwrap_or_default();
    let mut conditions = vec!["account_id = ?".to_owned()];
    let mut binds: Vec<String> = Vec::new();
    for (key, value) in &filter {
        let text = value.as_str();
        let column = match key.as_str() {
            "inAddressBook" if text == Some(BOOK_ID) => continue,
            "inAddressBook" => {
                conditions.push("0".into());
                continue;
            }
            "uid" => {
                conditions.push("uid = ?".into());
                binds.push(text.unwrap_or_default().to_owned());
                continue;
            }
            "text" => "(name || ' ' || email || ' ' || phone || ' ' || organization || ' ' || notes)",
            "name" | "name/full" => "name",
            "email" => "email",
            "phone" => "phone",
            "note" => "notes",
            "organization" => "organization",
            _ => return Err(MethodError("unsupportedFilter", format!("cards cannot be filtered by {key}"))),
        };
        let Some(text) = text else { return Err(MethodError::invalid(format!("{key} needs a text"))) };
        conditions.push(format!("{column} LIKE ? ESCAPE '\\'"));
        binds.push(like(text));
    }
    let mut order = Vec::new();
    for comparator in args.get("sort").and_then(Value::as_array).into_iter().flatten() {
        let column = match comparator["property"].as_str() {
            Some("name" | "name/full") => "CASE WHEN name = '' THEN email ELSE name END COLLATE NOCASE",
            Some("created") => "id",
            Some("updated") => "updated_at",
            Some("uid") => "uid",
            _ => return Err(MethodError("unsupportedSort", "cards sort by name, created, updated or uid".into())),
        };
        order.push(format!("{column} {}", if comparator["isAscending"].as_bool().unwrap_or(true) { "ASC" } else { "DESC" }));
    }
    order.push("id".into());
    let sql = format!("SELECT id FROM contacts WHERE {} ORDER BY {}", conditions.join(" AND "), order.join(", "));
    let mut query = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql)).bind(ctx.account.id);
    for bind in &binds {
        query = query.bind(bind);
    }
    let all = query.fetch_all(&ctx.app.db).await?;
    let total = all.len();
    let position = args.get("position").and_then(Value::as_i64).unwrap_or(0);
    let position = if position < 0 { total.saturating_sub(position.unsigned_abs() as usize) } else { (position as usize).min(total) };
    let limit = args.get("limit").and_then(Value::as_u64).map_or(super::MAX_OBJECTS, |l| (l as usize).min(super::MAX_OBJECTS));
    let ids: Vec<String> = all.iter().skip(position).take(limit).map(|id| format!("c{id}")).collect();
    Ok(json!({
        "accountId": account_id(ctx.account),
        "queryState": objects::state(ctx, "ContactCard").await?,
        "canCalculateChanges": false,
        "position": position,
        "ids": ids,
        "total": total,
    }))
}

async fn create(ctx: &Context<'_>, card: &Value) -> Result<i64, Value> {
    let fields = fields_of(card)?;
    if fields.name.is_empty() && fields.email.is_empty() {
        return Err(set_error("invalidProperties", "a card needs a name or an e-mail address"));
    }
    let db = &ctx.app.db;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contacts WHERE account_id = ?").bind(ctx.account.id).fetch_one(db).await.map_err(|_| set_error("serverFail", "internal error"))?;
    if count >= MAX_CONTACTS {
        return Err(set_error("overQuota", format!("the address book is limited to {MAX_CONTACTS} contacts")));
    }
    if let Some(uid) = &fields.uid {
        let taken: Option<i64> = sqlx::query_scalar("SELECT id FROM contacts WHERE account_id = ? AND uid = ?").bind(ctx.account.id).bind(uid).fetch_optional(db).await.map_err(|_| set_error("serverFail", "internal error"))?;
        if let Some(existing) = taken {
            return Err(json!({ "type": "alreadyExists", "description": "a card with this uid exists", "existingId": format!("c{existing}") }));
        }
    }
    let at = now();
    sqlx::query("INSERT INTO contacts (account_id, name, email, phone, organization, notes, created_at, updated_at, uid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(ctx.account.id)
        .bind(&fields.name)
        .bind(&fields.email)
        .bind(&fields.phone)
        .bind(&fields.organization)
        .bind(&fields.notes)
        .bind(at)
        .bind(at)
        .bind(fields.uid.unwrap_or_default())
        .execute(db)
        .await
        .map(|done| done.last_insert_rowid())
        .map_err(|err| {
            tracing::error!(%err, "storing a contact failed");
            set_error("serverFail", "internal error")
        })
}

async fn update(ctx: &Context<'_>, id: &str, patch: &Map<String, Value>) -> Result<(), Value> {
    let row = match parse_id(&ctx.resolve_id(id), 'c') {
        Some(n) => row(ctx, n).await.map_err(|_| set_error("serverFail", "internal error"))?,
        None => None,
    };
    let row = row.ok_or_else(|| set_error("notFound", "no such card"))?;
    let mut card = to_json(&row);
    objects::apply_patch(&mut card, patch).map_err(|err| set_error("invalidPatch", err))?;
    let fields = fields_of(&card)?;
    if fields.uid.as_deref() != Some(row.uid.as_str()) {
        return Err(set_error("invalidProperties", "the uid cannot be changed").tap_properties("uid"));
    }
    sqlx::query("UPDATE contacts SET name = ?, email = ?, phone = ?, organization = ?, notes = ?, updated_at = ? WHERE id = ? AND account_id = ?")
        .bind(&fields.name)
        .bind(&fields.email)
        .bind(&fields.phone)
        .bind(&fields.organization)
        .bind(&fields.notes)
        .bind(now())
        .bind(row.id)
        .bind(ctx.account.id)
        .execute(&ctx.app.db)
        .await
        .map_err(|_| set_error("serverFail", "internal error"))?;
    Ok(())
}

pub async fn set(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    objects::check_size(args)?;
    let old_state = objects::state(ctx, "ContactCard").await?;
    objects::check_state(args, &old_state)?;
    let mut result = SetResult::default();
    if let Some(create_specs) = args.get("create").and_then(Value::as_object) {
        for (creation_id, card) in create_specs {
            match create(ctx, card).await {
                Ok(id) => {
                    let stored = row(ctx, id).await?.expect("the card was just stored");
                    let id = format!("c{id}");
                    ctx.created.insert(creation_id.clone(), id.clone());
                    result.created.insert(creation_id.clone(), json!({ "id": id, "uid": stored.uid, "updated": utc(stored.updated_at) }));
                }
                Err(err) => {
                    result.not_created.insert(creation_id.clone(), err);
                }
            }
        }
    }
    if let Some(updates) = args.get("update").and_then(Value::as_object) {
        for (id, patch) in updates {
            let outcome = match patch.as_object() {
                Some(patch) => update(ctx, id, patch).await,
                None => Err(set_error("invalidPatch", "the patch must be an object")),
            };
            match outcome {
                Ok(()) => result.updated.insert(id.clone(), Value::Null),
                Err(err) => result.not_updated.insert(id.clone(), err),
            };
        }
    }
    if let Some(destroy) = args.get("destroy").and_then(Value::as_array) {
        for id in destroy.iter().filter_map(Value::as_str) {
            let removed = match parse_id(&ctx.resolve_id(id), 'c') {
                Some(n) => sqlx::query("DELETE FROM contacts WHERE id = ? AND account_id = ?").bind(n).bind(ctx.account.id).execute(&ctx.app.db).await?.rows_affected() > 0,
                None => false,
            };
            if removed {
                result.destroyed.push(id.to_owned());
            } else {
                result.not_destroyed.insert(id.to_owned(), set_error("notFound", "no such card"));
            }
        }
    }
    let new_state = objects::state(ctx, "ContactCard").await?;
    Ok(result.into_response(ctx, old_state, new_state))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cards_round_trip() {
        let row = Row { id: 7, uid: "u-1".into(), name: "Anna Nowak".into(), email: "anna@example.org".into(), phone: "+48 123".into(), organization: "Acme".into(), notes: "a\nb".into(), updated_at: 0 };
        let card = to_json(&row);
        assert_eq!(card["id"], "c7");
        assert_eq!(card["emails"]["e1"]["address"], "anna@example.org");
        let fields = fields_of(&card).unwrap();
        assert_eq!(fields, Fields { uid: Some("u-1".into()), name: "Anna Nowak".into(), email: "anna@example.org".into(), phone: "+48 123".into(), organization: "Acme".into(), notes: "a\nb".into() });
    }

    #[test]
    fn hostile_cards_are_refused() {
        assert_eq!(fields_of(&json!({ "addresses": {} })).unwrap_err()["type"], "invalidProperties");
        assert_eq!(fields_of(&json!({ "emails": { "e": { "address": "not an address" } } })).unwrap_err()["properties"], json!(["emails"]));
        assert_eq!(fields_of(&json!({ "addressBookIds": { "other": true } })).unwrap_err()["type"], "invalidProperties");
        assert!(fields_of(&json!({ "name": { "full": "x".repeat(201) } })).is_err());
        let composed = fields_of(&json!({ "name": { "components": [{ "kind": "given", "value": "Jan" }, { "kind": "surname", "value": "Kowalski" }] } })).unwrap();
        assert_eq!(composed.name, "Jan Kowalski");
    }
}
