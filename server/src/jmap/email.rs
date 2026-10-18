//! JMAP Email, Thread, Identity and EmailSubmission methods.

use mail_builder::{MessageBuilder, headers::address::Address as BuilderAddress};
use mail_parser::{MessageParser, MimeHeaders, PartType};
use serde_json::{Map, Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{Context, MAX_OBJECTS, MethodError, MethodResult, account_id, parse_id, set_error};
use crate::{
    api::like_pattern,
    app::AppState,
    auth::Account,
    error::ApiError,
    security::authn::find_header_end,
    smtp::submit::{self, Outcome, Submission},
    store::{Flags, Message, StoreError},
    util::Address,
};

const SYSTEM_KEYWORDS: [&str; 4] = ["$seen", "$answered", "$flagged", "$draft"];
const MAX_KEYWORDS: usize = 30;
/// Body properties that require parsing the stored message.
const BODY_PROPERTIES: [&str; 16] = [
    "bodyValues", "textBody", "htmlBody", "cc", "bcc", "replyTo", "messageId", "inReplyTo", "references", "sentAt", "headers", "unsubscribe", "security",
    "receiptRequestedBy", "receiptAutomaticAllowed", "smime",
];

pub(crate) fn timestamp(secs: i64) -> Value {
    OffsetDateTime::from_unix_timestamp(secs).ok().and_then(|t| t.format(&Rfc3339).ok()).map_or(Value::Null, Value::String)
}

fn keywords_json(message: &Message) -> Value {
    let mut map = Map::new();
    for (name, set) in [("$seen", message.seen), ("$answered", message.answered), ("$flagged", message.flagged), ("$draft", message.draft)] {
        if set {
            map.insert(name.into(), Value::Bool(true));
        }
    }
    for keyword in serde_json::from_str::<Vec<String>>(&message.keywords).unwrap_or_default() {
        map.insert(keyword, Value::Bool(true));
    }
    Value::Object(map)
}

fn addresses(list: Option<&mail_parser::Address<'_>>) -> Value {
    match list {
        Some(list) => Value::Array(
            list.iter().filter_map(|a| a.address().map(|email| json!({ "name": a.name(), "email": email }))).collect(),
        ),
        None => Value::Null,
    }
}

fn id_list(value: &mail_parser::HeaderValue<'_>) -> Value {
    match value.as_text_list() {
        Some(list) if !list.is_empty() => json!(list),
        _ => Value::Null,
    }
}

fn part_type(part: &mail_parser::MessagePart<'_>, fallback: &str) -> String {
    part.content_type()
        .map(|ct| match ct.subtype() {
            Some(sub) => format!("{}/{}", ct.ctype(), sub).to_ascii_lowercase(),
            None => ct.ctype().to_ascii_lowercase(),
        })
        .unwrap_or_else(|| fallback.to_owned())
}

/// Adds the properties that require the parsed message.
fn add_body(out: &mut Map<String, Value>, message: &Message, raw: &[u8], hostname: &str) {
    let Some(parsed) = MessageParser::default().parse(raw) else { return };
    out.insert("cc".into(), addresses(parsed.cc()));
    out.insert("bcc".into(), addresses(parsed.bcc()));
    out.insert("replyTo".into(), addresses(parsed.reply_to()));
    out.insert("to".into(), addresses(parsed.to()));
    out.insert("from".into(), addresses(parsed.from()));
    out.insert("messageId".into(), parsed.message_id().map_or(Value::Null, |id| json!([id])));
    out.insert("inReplyTo".into(), id_list(parsed.in_reply_to()));
    out.insert("references".into(), id_list(parsed.references()));
    out.insert("sentAt".into(), parsed.date().map_or(Value::Null, |d| timestamp(d.to_timestamp())));
    // Which ways of unsubscribing the sender offers (List-Unsubscribe), if any.
    out.insert("unsubscribe".into(), crate::api::mailtools::unsubscribe_options(raw).to_json());
    // What the server established on delivery: sender authentication, encryption, virus scan.
    out.insert("security".into(), serde_json::to_value(crate::security::summary::summarize(raw, hostname)).unwrap_or(Value::Null));
    // Who asked for a read receipt (Disposition-Notification-To), if anyone.
    out.insert("receiptRequestedBy".into(), super::mdn::requested_by(raw).map_or(Value::Null, Value::String));
    // Whether a receipt may be sent without asking (the requester is the return path).
    out.insert("receiptAutomaticAllowed".into(), Value::Bool(super::mdn::requested_by_return_path(raw)));

    let mut body_values = Map::new();
    let describe = |index: usize, values: &mut Map<String, Value>| -> Option<Value> {
        let part = parsed.parts.get(index)?;
        let (text, kind) = match &part.body {
            PartType::Text(text) => (text.as_ref(), "text/plain"),
            PartType::Html(html) => (html.as_ref(), "text/html"),
            _ => return None,
        };
        values.insert(index.to_string(), json!({ "value": text, "isEncodingProblem": part.is_encoding_problem, "isTruncated": false }));
        Some(json!({
            "partId": index.to_string(),
            "blobId": format!("{}.{}", message.blob_hash, index),
            "size": text.len(),
            "type": kind,
            "charset": "utf-8",
        }))
    };
    let text_body: Vec<Value> = parsed.text_body.iter().filter_map(|i| describe(*i as usize, &mut body_values)).collect();
    let html_body: Vec<Value> = parsed.html_body.iter().filter_map(|i| describe(*i as usize, &mut body_values)).collect();
    let attachments = crate::search::attachment_values(&parsed, &message.blob_hash);
    out.insert("textBody".into(), Value::Array(text_body));
    out.insert("htmlBody".into(), Value::Array(html_body));
    out.insert("attachments".into(), Value::Array(attachments));
    out.insert("bodyValues".into(), Value::Object(body_values));
}

fn summary(message: &Message) -> Map<String, Value> {
    let mut out = Map::new();
    let to: Vec<Value> = message.to_addrs.split(", ").filter(|s| !s.is_empty()).map(|email| json!({ "name": null, "email": email })).collect();
    out.insert("id".into(), json!(format!("m{}", message.id)));
    out.insert("blobId".into(), json!(message.blob_hash));
    out.insert("threadId".into(), json!(format!("t{}", message.thread_id)));
    out.insert("mailboxIds".into(), json!({ format!("b{}", message.mailbox_id): true }));
    out.insert("keywords".into(), keywords_json(message));
    out.insert("size".into(), json!(message.size));
    out.insert("receivedAt".into(), timestamp(message.internal_date));
    out.insert("subject".into(), json!(message.subject));
    let from_name = if message.from_name.is_empty() { Value::Null } else { json!(message.from_name) };
    out.insert("from".into(), if message.from_addr.is_empty() { Value::Null } else { json!([{ "name": from_name, "email": message.from_addr }]) });
    out.insert("to".into(), Value::Array(to));
    out.insert("preview".into(), json!(message.snippet));
    out.insert("hasAttachment".into(), json!(message.has_attachments));
    out
}

pub async fn get(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let ids = args.get("ids").and_then(Value::as_array).ok_or_else(|| MethodError::invalid("ids is required"))?;
    if ids.len() > MAX_OBJECTS {
        return Err(MethodError("requestTooLarge", "too many ids".into()));
    }
    let properties: Option<Vec<&str>> = args.get("properties").and_then(Value::as_array).map(|p| p.iter().filter_map(Value::as_str).collect());
    let need_body = properties.as_ref().is_none_or(|p| p.iter().any(|name| BODY_PROPERTIES.contains(name)));
    // The attachment list alone (for list views) comes from the index, without parsing.
    let need_attachments = properties.as_ref().is_some_and(|p| p.contains(&"attachments"));

    let mut list = Vec::new();
    let mut not_found = Vec::new();
    for id in ids.iter().filter_map(Value::as_str) {
        let message = match parse_id(id, 'm') {
            Some(n) => ctx.message(n).await?.map(|(message, _)| message),
            None => None,
        };
        let Some(message) = message else {
            not_found.push(id.to_owned());
            continue;
        };
        let mut out = summary(&message);
        if need_body {
            match ctx.app.store.read_blob(&message.blob_hash).await {
                Ok(raw) => {
                    // S/MIME: shown decrypted with the reader's own key, signatures checked.
                    let (raw, smime) = crate::smime::view(ctx.app, ctx.account.id, raw).await;
                    add_body(&mut out, &message, &raw, &ctx.app.cfg.hostname);
                    out.insert("smime".into(), smime.map_or(Value::Null, |s| serde_json::to_value(s).unwrap_or(Value::Null)));
                }
                Err(err) => tracing::error!(%err, id, "message content is missing"),
            }
        } else if need_attachments {
            let known = match crate::search::attachments(&ctx.app.db, &message.blob_hash).await? {
                Some(known) => known,
                // Not indexed yet: index it now.
                None => match ctx.app.store.read_blob(&message.blob_hash).await {
                    Ok(raw) => crate::search::index(&ctx.app.db, &message.blob_hash, &raw).await?,
                    Err(_) => Vec::new(),
                },
            };
            out.insert("attachments".into(), Value::Array(known));
        }
        list.push(Value::Object(out));
    }
    Ok(json!({ "accountId": account_id(ctx.account), "state": ctx.state().await?, "list": list, "notFound": not_found }))
}

pub async fn query(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    query_inner(ctx, args, MAX_OBJECTS as i64).await
}

/// Upper bound on the result set considered by `Email/queryChanges`.
const QUERY_CHANGES_WINDOW: i64 = 10_000;

/// A value bound to a placeholder of a compiled filter.
#[derive(Debug, Clone, PartialEq)]
enum Bind {
    Int(i64),
    Text(String),
}

/// Deepest nesting of filter operators accepted, and most conditions in one filter.
const MAX_FILTER_DEPTH: usize = 6;
const MAX_FILTER_CONDITIONS: usize = 64;

/// The summary columns a text condition falls back to for messages not indexed yet.
fn fallback_columns(column: Option<&str>) -> &'static [&'static str] {
    match column {
        None => &["m.subject", "m.from_addr", "m.from_name", "m.to_addrs", "m.snippet"],
        Some("subject") => &["m.subject"],
        Some("sender") => &["m.from_addr", "m.from_name"],
        Some("recipients_to") => &["m.to_addrs"],
        Some("body") => &["m.snippet"],
        Some(_) => &[],
    }
}

/// `text`, `from`, `subject`, ...: the words must occur in the message (or one part of it).
fn text_clause(column: Option<&str>, value: &str, binds: &mut Vec<Bind>) -> String {
    let value = value.trim();
    if value.is_empty() {
        return "1".into();
    }
    // Placeholders are numbered in the order they appear: the index query comes first.
    let full_text = crate::search::fts_query(column, value);
    if let Some(query) = &full_text {
        binds.push(Bind::Text(query.clone()));
    }
    let columns = fallback_columns(column);
    let fallback = if columns.is_empty() {
        "0".to_owned()
    } else {
        let pattern = like_pattern(value);
        let likes: Vec<String> = columns
            .iter()
            .map(|c| {
                binds.push(Bind::Text(pattern.clone()));
                format!("{c} LIKE ? ESCAPE '\\'")
            })
            .collect();
        format!("(NOT EXISTS (SELECT 1 FROM message_extras e WHERE e.hash = m.blob_hash) AND ({}))", likes.join(" OR "))
    };
    match full_text {
        Some(_) => format!("(m.blob_hash IN (SELECT e.hash FROM message_extras e WHERE e.id IN (SELECT rowid FROM message_text WHERE message_text MATCH ?)) OR {fallback})"),
        None => fallback,
    }
}

fn keyword_clause(keyword: &str, present: bool, binds: &mut Vec<Bind>) -> String {
    let column = match keyword {
        "$seen" => Some("m.seen"),
        "$flagged" => Some("m.flagged"),
        "$answered" => Some("m.answered"),
        "$draft" => Some("m.draft"),
        _ => None,
    };
    match column {
        Some(column) => format!("{column} = {}", i64::from(present)),
        None => {
            binds.push(Bind::Text(keyword.to_owned()));
            format!("{}EXISTS (SELECT 1 FROM message_keywords k WHERE k.message_id = m.id AND k.keyword = ?)", if present { "" } else { "NOT " })
        }
    }
}

fn date_of(value: &Value, name: &str) -> Result<i64, MethodError> {
    value.as_str().and_then(|text| OffsetDateTime::parse(text, &Rfc3339).ok()).map(|t| t.unix_timestamp()).ok_or_else(|| MethodError("unsupportedFilter", format!("{name} must be a UTC date")))
}

/// Compiles a JMAP `FilterOperator` / `FilterCondition` (RFC 8621, section 4.4.1) into SQL over
/// `messages m`, appending the values to bind in order.
fn compile_filter(filter: &Map<String, Value>, binds: &mut Vec<Bind>, depth: usize, count: &mut usize) -> Result<String, MethodError> {
    if depth > MAX_FILTER_DEPTH {
        return Err(MethodError("unsupportedFilter", "the filter is nested too deeply".into()));
    }
    if let Some(operator) = filter.get("operator") {
        // An operator carries only its conditions: anything else beside it would be ignored
        // here yet could be read elsewhere (`filter_mailbox`).
        if filter.keys().any(|key| key != "operator" && key != "conditions") {
            return Err(MethodError("unsupportedFilter", "an operator cannot be combined with conditions in the same object".into()));
        }
        let conditions = filter.get("conditions").and_then(Value::as_array).ok_or_else(|| MethodError("unsupportedFilter", "an operator needs conditions".into()))?;
        let parts = conditions
            .iter()
            .map(|condition| condition.as_object().ok_or_else(|| MethodError("unsupportedFilter", "invalid condition".into())).and_then(|c| compile_filter(c, binds, depth + 1, count)))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(match (operator.as_str(), parts.is_empty()) {
            (Some("AND"), true) => "1".into(),
            (Some("OR"), true) => "0".into(),
            (Some("NOT"), true) => "1".into(),
            (Some("AND"), false) => format!("({})", parts.join(" AND ")),
            (Some("OR"), false) => format!("({})", parts.join(" OR ")),
            // NOT: none of the conditions holds.
            (Some("NOT"), false) => format!("NOT ({})", parts.join(" OR ")),
            _ => return Err(MethodError("unsupportedFilter", "the operator must be AND, OR or NOT".into())),
        });
    }

    let mut clauses: Vec<String> = Vec::new();
    for (key, value) in filter {
        *count += 1;
        if *count > MAX_FILTER_CONDITIONS {
            return Err(MethodError("unsupportedFilter", "the filter has too many conditions".into()));
        }
        let text = || value.as_str().ok_or_else(|| MethodError("unsupportedFilter", format!("{key} must be a string")));
        let clause = match key.as_str() {
            "inMailbox" => {
                let id = text().ok().and_then(|id| parse_id(id, 'b')).ok_or_else(|| MethodError::invalid("invalid mailbox id"))?;
                binds.push(Bind::Int(id));
                "m.mailbox_id = ?".to_owned()
            }
            "inMailboxOtherThan" => {
                let ids = value.as_array().ok_or_else(|| MethodError::invalid("inMailboxOtherThan must be a list"))?;
                let ids = ids.iter().take(100).map(|id| id.as_str().and_then(|id| parse_id(id, 'b')).ok_or_else(|| MethodError::invalid("invalid mailbox id"))).collect::<Result<Vec<_>, _>>()?;
                if ids.is_empty() {
                    "1".to_owned()
                } else {
                    binds.extend(ids.iter().map(|id| Bind::Int(*id)));
                    format!("m.mailbox_id NOT IN ({})", vec!["?"; ids.len()].join(", "))
                }
            }
            "before" => {
                binds.push(Bind::Int(date_of(value, "before")?));
                "m.internal_date < ?".to_owned()
            }
            "after" => {
                binds.push(Bind::Int(date_of(value, "after")?));
                "m.internal_date >= ?".to_owned()
            }
            "minSize" | "maxSize" => {
                let size = value.as_i64().filter(|size| *size >= 0).ok_or_else(|| MethodError("unsupportedFilter", format!("{key} must be a number")))?;
                binds.push(Bind::Int(size));
                if key == "minSize" { "m.size >= ?".to_owned() } else { "m.size < ?".to_owned() }
            }
            "hasAttachment" => {
                let wanted = value.as_bool().ok_or_else(|| MethodError("unsupportedFilter", "hasAttachment must be true or false".into()))?;
                format!("m.has_attachments = {}", i64::from(wanted))
            }
            "hasKeyword" | "notKeyword" => {
                let keyword = text()?.to_ascii_lowercase();
                if !(SYSTEM_KEYWORDS.contains(&keyword.as_str()) || valid_keyword(&keyword)) {
                    return Err(MethodError("unsupportedFilter", "invalid keyword".into()));
                }
                keyword_clause(&keyword, key == "hasKeyword", binds)
            }
            // Inbox category (an extension): "general" is everything without a category keyword.
            "category" => {
                let name = text()?;
                if !crate::categories::valid_name(name) {
                    return Err(MethodError("unsupportedFilter", "unknown category".into()));
                }
                if name == "general" {
                    // `$cat_` up to `$cat` + the next character after `_`: every category keyword.
                    "NOT EXISTS (SELECT 1 FROM message_keywords k WHERE k.message_id = m.id AND k.keyword >= '$cat_' AND k.keyword < '$cat`')".to_owned()
                } else {
                    binds.push(Bind::Text(format!("$cat_{name}")));
                    "EXISTS (SELECT 1 FROM message_keywords k WHERE k.message_id = m.id AND k.keyword = ?)".to_owned()
                }
            }
            "text" => text_clause(None, text()?, binds),
            "from" => text_clause(Some("sender"), text()?, binds),
            "to" => text_clause(Some("recipients_to"), text()?, binds),
            "cc" => text_clause(Some("recipients_cc"), text()?, binds),
            "bcc" => text_clause(Some("recipients_bcc"), text()?, binds),
            "subject" => text_clause(Some("subject"), text()?, binds),
            "body" => text_clause(Some("body"), text()?, binds),
            // An extension: words in the names of attached files.
            "attachmentName" => text_clause(Some("attachments"), text()?, binds),
            unknown => return Err(MethodError("unsupportedFilter", format!("unsupported filter condition: {unknown}"))),
        };
        clauses.push(clause);
    }
    Ok(if clauses.is_empty() { "1".into() } else { format!("({})", clauses.join(" AND ")) })
}

/// The mailbox a filter is confined to as a whole, if any (it decides whose messages are
/// searched, and which messages of a thread represent it).
fn filter_mailbox(filter: &Map<String, Value>) -> Option<i64> {
    if !filter.contains_key("operator") {
        return filter.get("inMailbox").and_then(Value::as_str).and_then(|id| parse_id(id, 'b'));
    }
    (filter.get("operator").and_then(Value::as_str) == Some("AND"))
        .then(|| filter.get("conditions").and_then(Value::as_array))
        .flatten()
        .and_then(|conditions| conditions.iter().filter_map(Value::as_object).find_map(filter_mailbox))
}

async fn query_inner(ctx: &Context<'_>, args: &Map<String, Value>, cap: i64) -> MethodResult {
    let empty = Map::new();
    let filter = args.get("filter").and_then(Value::as_object).unwrap_or(&empty);
    let mut binds: Vec<Bind> = Vec::new();
    let condition = compile_filter(filter, &mut binds, 0, &mut 0)?;
    let mailbox = filter_mailbox(filter);
    // Listing a shared mailbox searches its owner's messages; everything else stays within
    // the user's own account.
    let owner = match mailbox {
        Some(id) => match ctx.mailbox(id).await? {
            Some((found, rights)) if rights.contains('r') => found.account_id,
            _ => ctx.account.id,
        },
        None => ctx.account.id,
    };
    let collapse = args.get("collapseThreads").and_then(Value::as_bool).unwrap_or(false);
    let position = args.get("position").and_then(Value::as_i64).unwrap_or(0).max(0);
    let limit = args.get("limit").and_then(Value::as_i64).unwrap_or(50).clamp(0, cap);

    // A thread is represented by its newest message (in the mailbox listed, if one is).
    let thread = if collapse {
        "AND m.id = (SELECT m2.id FROM messages m2 WHERE m2.account_id = m.account_id AND m2.thread_id = m.thread_id AND (?2 IS NULL OR m2.mailbox_id = ?2) ORDER BY m2.internal_date DESC, m2.id DESC LIMIT 1)"
    } else {
        ""
    };
    // Numbered placeholders for owner and mailbox, then the filter's own in order.
    let numbered = |sql: &str| {
        let mut out = String::with_capacity(sql.len());
        let mut n = 2;
        for c in sql.chars() {
            if c == '?' {
                n += 1;
                out.push_str(&format!("?{n}"));
            } else {
                out.push(c);
            }
        }
        out
    };
    // Another account's messages are only ever searched within the shared mailbox itself.
    let confined = if owner == ctx.account.id { "" } else { "AND m.mailbox_id = ?2" };
    let conditions = format!("m.account_id = ?1 {confined} AND {} {thread}", numbered(&condition));
    // Listing one mailbox, newest first: the mailbox's date index yields the page directly
    // (`+` keeps SQLite from scanning the whole account through another index and sorting).
    let page_conditions = if mailbox.is_some() { format!("+{conditions}") } else { conditions.clone() };
    let bind_all = |sql: String| {
        let mut query = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql)).bind(owner).bind(mailbox);
        for value in &binds {
            query = match value {
                Bind::Int(n) => query.bind(*n),
                Bind::Text(text) => query.bind(text.clone()),
            };
        }
        query
    };
    let after = binds.len() + 3;
    let ids: Vec<i64> = bind_all(format!("SELECT m.id FROM messages m WHERE {page_conditions} ORDER BY m.internal_date DESC, m.id DESC LIMIT ?{after} OFFSET ?{}", after + 1))
        .bind(limit)
        .bind(position)
        .fetch_all(&ctx.app.db)
        .await?;
    let mut response = json!({
        "accountId": account_id(ctx.account),
        "queryState": ctx.state().await?,
        "canCalculateChanges": true,
        "position": position,
        "ids": ids.iter().map(|id| format!("m{id}")).collect::<Vec<_>>(),
    });
    if args.get("calculateTotal").and_then(Value::as_bool).unwrap_or(false) {
        // A plain folder listing in threads counts the threads with a message in the folder:
        // the same number as the general query, read from an index.
        let plain_folder = collapse && mailbox.is_some() && filter.len() == 1 && filter.contains_key("inMailbox");
        let total: i64 = if plain_folder {
            sqlx::query_scalar("SELECT COUNT(DISTINCT thread_id) FROM messages WHERE mailbox_id = ? AND account_id = ?").bind(mailbox).bind(owner).fetch_one(&ctx.app.db).await?
        } else {
            bind_all(format!("SELECT COUNT(*) FROM messages m WHERE {conditions}")).fetch_one(&ctx.app.db).await?
        };
        response["total"] = json!(total);
    }
    Ok(response)
}

fn since_state(args: &Map<String, Value>, key: &str) -> Result<i64, MethodError> {
    args.get(key)
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n >= 0)
        .ok_or_else(|| MethodError("cannotCalculateChanges", "unknown state".into()))
}

fn prefixed(prefix: char, ids: &[i64]) -> Vec<String> {
    ids.iter().map(|id| format!("{prefix}{id}")).collect()
}

/// `Email/changes`, `Mailbox/changes` and `Thread/changes` (RFC 8620 section 5.2).
pub async fn changes(ctx: &mut Context<'_>, args: &Map<String, Value>, kind: &str) -> MethodResult {
    let since = since_state(args, "sinceState")?;
    let max = args.get("maxChanges").and_then(Value::as_u64).unwrap_or(MAX_OBJECTS as u64).clamp(1, MAX_OBJECTS as u64) as usize;
    let log_kind = if kind == "mailbox" { "mailbox" } else { "email" };
    let set = ctx
        .app
        .store
        .changes_since(ctx.account.id, log_kind, since, max)
        .await?
        .ok_or_else(|| MethodError("cannotCalculateChanges", "the state is too old; refetch the data".into()))?;
    let (created, updated, destroyed) = match kind {
        "email" => (prefixed('m', &set.created), prefixed('m', &set.updated), prefixed('m', &set.destroyed)),
        "mailbox" => (prefixed('b', &set.created), prefixed('b', &set.updated), prefixed('b', &set.destroyed)),
        _ => {
            // A thread is created when all its emails are new, destroyed when none are left.
            let (mut created, mut updated, mut destroyed) = (Vec::new(), Vec::new(), Vec::new());
            for thread in &set.threads {
                let members: Vec<i64> = sqlx::query_scalar("SELECT id FROM messages WHERE account_id = ? AND thread_id = ?")
                    .bind(ctx.account.id)
                    .bind(thread)
                    .fetch_all(&ctx.app.db)
                    .await?;
                if members.is_empty() {
                    destroyed.push(*thread);
                } else if members.iter().all(|id| set.created.contains(id)) {
                    created.push(*thread);
                } else {
                    updated.push(*thread);
                }
            }
            (prefixed('t', &created), prefixed('t', &updated), prefixed('t', &destroyed))
        }
    };
    let mut response = json!({
        "accountId": account_id(ctx.account),
        "oldState": since.to_string(),
        "newState": set.new_state.to_string(),
        "hasMoreChanges": set.has_more,
        "created": created,
        "updated": updated,
        "destroyed": destroyed,
    });
    if kind == "mailbox" {
        response["updatedProperties"] = Value::Null;
    }
    Ok(response)
}

/// `Email/queryChanges`: how a query's result list changed since `sinceQueryState`.
pub async fn query_changes(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let since = since_state(args, "sinceQueryState")?;
    let set = ctx
        .app
        .store
        .changes_since(ctx.account.id, "email", since, usize::MAX)
        .await?
        .ok_or_else(|| MethodError("cannotCalculateChanges", "the query state is too old; rerun the query".into()))?;
    let mut window = args.clone();
    window.insert("position".into(), json!(0));
    window.insert("limit".into(), json!(QUERY_CHANGES_WINDOW));
    window.insert("calculateTotal".into(), json!(true));
    let current = query_inner(ctx, &window, QUERY_CHANGES_WINDOW).await?;
    let ids: Vec<&str> = current["ids"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    if current["total"].as_i64().unwrap_or(0) > QUERY_CHANGES_WINDOW {
        return Err(MethodError("cannotCalculateChanges", "the result list is too large; rerun the query".into()));
    }
    // Every email that changed is removed from the client's list and, if it still matches,
    // re-added at its current position (RFC 8620 section 5.6).
    let changed: Vec<String> = set.created.iter().chain(&set.updated).chain(&set.destroyed).map(|id| format!("m{id}")).collect();
    let added: Vec<Value> = ids
        .iter()
        .enumerate()
        .filter(|(_, id)| changed.iter().any(|c| c == *id))
        .map(|(index, id)| json!({ "id": id, "index": index }))
        .collect();
    let mut response = json!({
        "accountId": account_id(ctx.account),
        "oldQueryState": since.to_string(),
        "newQueryState": set.new_state.to_string(),
        "removed": changed,
        "added": added,
    });
    if args.get("calculateTotal").and_then(Value::as_bool).unwrap_or(false) {
        response["total"] = current["total"].clone();
    }
    Ok(response)
}

pub async fn thread_get(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let ids = args.get("ids").and_then(Value::as_array).ok_or_else(|| MethodError::invalid("ids is required"))?;
    if ids.len() > MAX_OBJECTS {
        return Err(MethodError("requestTooLarge", "too many ids".into()));
    }
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    for id in ids.iter().filter_map(Value::as_str) {
        let emails: Vec<i64> = match parse_id(id, 't') {
            Some(thread) => {
                let rows: Vec<(i64, i64, i64)> = sqlx::query_as("SELECT id, account_id, mailbox_id FROM messages WHERE thread_id = ? ORDER BY internal_date, id")
                    .bind(thread)
                    .fetch_all(&ctx.app.db)
                    .await?;
                // A thread in a shared mailbox shows only the messages in mailboxes the user
                // may read, not the owner's whole conversation.
                let mut readable: std::collections::HashMap<i64, bool> = std::collections::HashMap::new();
                let mut visible = Vec::new();
                for (email, owner, mailbox) in rows {
                    let allowed = if owner == ctx.account.id {
                        true
                    } else {
                        match readable.get(&mailbox) {
                            Some(known) => *known,
                            None => {
                                let allowed = ctx.mailbox(mailbox).await?.is_some_and(|(_, rights)| rights.contains('r'));
                                readable.insert(mailbox, allowed);
                                allowed
                            }
                        }
                    };
                    if allowed {
                        visible.push(email);
                    }
                }
                visible
            }
            None => Vec::new(),
        };
        if emails.is_empty() {
            not_found.push(id.to_owned());
        } else {
            list.push(json!({ "id": id, "emailIds": emails.iter().map(|e| format!("m{e}")).collect::<Vec<_>>() }));
        }
    }
    Ok(json!({ "accountId": account_id(ctx.account), "state": ctx.state().await?, "list": list, "notFound": not_found }))
}

/// Addresses the account may send from: its own, plus aliases that deliver to it.
async fn identities(app: &AppState, account: &Account) -> Result<Vec<String>, MethodError> {
    let mut out = vec![account.email.clone()];
    let aliases: Vec<(String, String)> = sqlx::query_as("SELECT source, destinations FROM aliases WHERE enabled = 1 AND destinations LIKE ? ESCAPE '\\'")
        .bind(like_pattern(&account.email))
        .fetch_all(&app.db)
        .await?;
    for (source, destinations) in aliases {
        let list: Vec<String> = serde_json::from_str(&destinations).unwrap_or_default();
        if list.iter().any(|d| d.eq_ignore_ascii_case(&account.email)) {
            out.push(source);
        }
    }
    Ok(out)
}

pub async fn identity_get(ctx: &mut Context<'_>, _args: &Map<String, Value>) -> MethodResult {
    // Identities the user configured, then any alias address without an entry of its own.
    let rows = crate::api::personal::identity_rows(ctx.app, ctx.account).await?;
    let mut list: Vec<Value> = rows
        .iter()
        .map(|row| {
            let reply_to = if row.reply_to.is_empty() { Value::Null } else { json!([{ "name": null, "email": row.reply_to }]) };
            json!({ "id": format!("i{}", row.id), "name": row.name, "email": row.email, "replyTo": reply_to, "bcc": null, "textSignature": "", "htmlSignature": row.signature_html, "mayDelete": row.id != 0 })
        })
        .collect();
    for email in identities(ctx.app, ctx.account).await? {
        if !rows.iter().any(|row| row.email == email) {
            list.push(json!({ "id": email, "name": ctx.account.display_name, "email": email, "replyTo": null, "bcc": null, "textSignature": "", "htmlSignature": "", "mayDelete": false }));
        }
    }
    Ok(json!({ "accountId": account_id(ctx.account), "state": "0", "list": list, "notFound": [] }))
}

fn builder_addresses(value: &Value) -> Result<Option<BuilderAddress<'static>>, String> {
    let Some(list) = value.as_array() else { return Ok(None) };
    let mut out = Vec::new();
    for item in list {
        let email = item["email"].as_str().ok_or("address entries need an email")?;
        let parsed = Address::parse(email).ok_or_else(|| format!("invalid address: {}", crate::util::sanitize_line(email)))?;
        let name = item["name"].as_str().map(crate::util::sanitize_line).filter(|n| !n.is_empty());
        out.push(BuilderAddress::new_address(name, parsed.to_string()));
    }
    Ok((!out.is_empty()).then(|| BuilderAddress::new_list(out)))
}

fn message_ids(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|list| list.iter().filter_map(Value::as_str).map(crate::util::sanitize_line).filter(|s| !s.is_empty() && !s.contains(['<', '>', ' '])).collect())
        .unwrap_or_default()
}

/// Loads a blob the account is entitled to read: one of its uploads (`u<hash>`), a message of
/// its own (`<hash>`), or a MIME part of such a message (`<hash>.<part>`).
pub async fn load_blob(app: &AppState, account: &Account, blob_id: &str) -> Result<Option<(Vec<u8>, String)>, ApiError> {
    if let Some(hash) = blob_id.strip_prefix('u') {
        let content_type: Option<String> = sqlx::query_scalar("SELECT content_type FROM uploads WHERE account_id = ? AND hash = ?")
            .bind(account.id)
            .bind(hash)
            .fetch_optional(&app.db)
            .await?;
        let Some(content_type) = content_type else { return Ok(None) };
        return Ok(Some((app.store.read_blob(hash).await?, content_type)));
    }
    let (hash, part) = match blob_id.split_once('.') {
        Some((hash, part)) => (hash, Some(part.parse::<usize>().map_err(|_| ApiError::NotFound)?)),
        None => (blob_id, None),
    };
    // The blob must be a message in a mailbox the account may read: its own, or a shared one.
    let mailboxes: Vec<i64> = sqlx::query_scalar("SELECT DISTINCT mailbox_id FROM messages WHERE blob_hash = ? ORDER BY account_id = ? DESC LIMIT 50")
        .bind(hash)
        .bind(account.id)
        .fetch_all(&app.db)
        .await?;
    let mut readable = false;
    for mailbox in mailboxes {
        if crate::sharing::mailbox(&app.db, account, mailbox).await?.is_some_and(|(_, rights)| rights.contains('r')) {
            readable = true;
            break;
        }
    }
    if !readable {
        return Ok(None);
    }
    let raw = app.store.read_blob(hash).await?;
    let Some(index) = part else { return Ok(Some((raw, "message/rfc822".into()))) };
    // Parts are numbered in the message as shown, which for S/MIME is the decrypted one.
    let (raw, _) = crate::smime::view(app, account.id, raw).await;
    let Some(parsed) = MessageParser::default().parse(&raw) else { return Ok(None) };
    let Some(part) = parsed.parts.get(index) else { return Ok(None) };
    let content_type = part_type(part, "application/octet-stream");
    Ok(Some((part.contents().to_vec(), content_type)))
}

/// Builds an RFC 5322 message from a JMAP Email object.
async fn build_message(ctx: &Context<'_>, spec: &Map<String, Value>) -> Result<Vec<u8>, Value> {
    let invalid = |msg: String| set_error("invalidProperties", msg);
    let field = |name: &str| spec.get(name).unwrap_or(&Value::Null);
    let mut builder = MessageBuilder::new();

    let from = builder_addresses(field("from")).map_err(invalid)?.unwrap_or_else(|| {
        let name = Some(ctx.account.display_name.clone()).filter(|n| !n.is_empty());
        BuilderAddress::new_address(name, ctx.account.email.clone())
    });
    builder = builder.from(from);
    if let Some(to) = builder_addresses(field("to")).map_err(invalid)? {
        builder = builder.to(to);
    }
    if let Some(cc) = builder_addresses(field("cc")).map_err(invalid)? {
        builder = builder.cc(cc);
    }
    if let Some(bcc) = builder_addresses(field("bcc")).map_err(invalid)? {
        builder = builder.bcc(bcc);
    }
    if let Some(reply_to) = builder_addresses(field("replyTo")).map_err(invalid)? {
        builder = builder.reply_to(reply_to);
    }
    // A read receipt request (RFC 8098), as the JMAP header property.
    if let Some(receipt) = builder_addresses(field("header:Disposition-Notification-To:asAddresses")).map_err(invalid)? {
        builder = builder.header("Disposition-Notification-To", mail_builder::headers::HeaderType::Address(receipt));
    }
    builder = builder.subject(crate::util::sanitize_line(field("subject").as_str().unwrap_or("")));
    let domain = ctx.account.email.rsplit_once('@').map_or("localhost", |(_, d)| d);
    builder = builder.message_id(format!("{}@{}", crate::util::random_token(), domain));
    let in_reply_to = message_ids(field("inReplyTo"));
    if !in_reply_to.is_empty() {
        builder = builder.in_reply_to(in_reply_to);
    }
    let references = message_ids(field("references"));
    if !references.is_empty() {
        builder = builder.references(references);
    }

    let body_value = |list: &str| -> Option<String> {
        let part_id = field(list).get(0)?.get("partId")?.as_str()?;
        Some(field("bodyValues").get(part_id)?.get("value")?.as_str()?.to_owned())
    };
    let (text, html) = (body_value("textBody"), body_value("htmlBody"));
    if let Some(html) = html {
        builder = builder.html_body(html);
    }
    builder = builder.text_body(text.unwrap_or_default());

    let mut total = 0usize;
    for attachment in field("attachments").as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let blob_id = attachment["blobId"].as_str().ok_or_else(|| invalid("attachments need a blobId".into()))?;
        let (data, stored_type) = load_blob(ctx.app, ctx.account, blob_id)
            .await
            .map_err(|_| set_error("serverFail", "could not read attachment"))?
            .ok_or_else(|| set_error("blobNotFound", format!("unknown blob {}", crate::util::sanitize_line(blob_id))))?;
        total += data.len();
        if total > ctx.app.rt().max_message_size {
            return Err(set_error("tooLarge", "the message exceeds the maximum size"));
        }
        let content_type = attachment["type"]
            .as_str()
            .filter(|t| t.len() <= 100 && t.parse::<mime::Mime>().is_ok())
            .map(str::to_owned)
            .unwrap_or(stored_type);
        let name: String = attachment["name"].as_str().map(crate::util::sanitize_line).filter(|n| !n.is_empty()).unwrap_or_else(|| "attachment".into());
        builder = match attachment["cid"].as_str().filter(|_| attachment["disposition"] == "inline") {
            Some(cid) => builder.inline(content_type, crate::util::sanitize_line(cid), data),
            None => builder.attachment(content_type, name, data),
        };
    }
    let mut raw = builder.write_to_vec().map_err(|_| set_error("serverFail", "could not build the message"))?;
    // S/MIME, when asked for: signed with the user's certificate, then encrypted to every
    // recipient and to the sender.
    let smime = field("smime");
    let (sign, encrypt) = (smime["sign"].as_bool() == Some(true), smime["encrypt"].as_bool() == Some(true));
    if sign || encrypt {
        let identity = crate::smime::identity(ctx.app, ctx.account.id).await.ok_or_else(|| set_error("invalidProperties", "add your S/MIME certificate in Settings first"))?;
        if sign {
            raw = crate::smime::sign(&raw, &identity).map_err(|e| set_error("serverFail", format!("signing failed: {e}")))?;
        }
        if encrypt {
            let mut emails: Vec<String> = Vec::new();
            for list in ["to", "cc", "bcc"] {
                for entry in field(list).as_array().into_iter().flatten() {
                    if let Some(email) = entry["email"].as_str() {
                        emails.push(email.to_ascii_lowercase());
                    }
                }
            }
            let known = crate::smime::certificates(ctx.app, ctx.account.id, &emails).await.map_err(|_| set_error("serverFail", "internal error"))?;
            let missing: Vec<&String> = emails.iter().filter(|e| !known.contains_key(*e)).collect();
            if !missing.is_empty() {
                return Err(set_error("invalidProperties", format!("no S/MIME certificate is known for {}", missing.iter().map(|e| e.as_str()).collect::<Vec<_>>().join(", "))));
            }
            let mut certificates: Vec<Vec<u8>> = known.into_values().collect();
            certificates.push(identity.certificate.clone());
            raw = crate::smime::encrypt(&raw, &certificates).map_err(|e| set_error("serverFail", format!("encryption failed: {e}")))?;
        }
    }
    if raw.len() > ctx.app.rt().max_message_size {
        return Err(set_error("tooLarge", "the message exceeds the maximum size"));
    }
    Ok(raw)
}

/// Reads the single target mailbox out of a `mailboxIds` object.
fn single_mailbox(value: &Value) -> Option<i64> {
    let map = value.as_object()?;
    let mut selected = map.iter().filter(|(_, v)| v.as_bool() == Some(true));
    let (id, _) = selected.next()?;
    if selected.next().is_some() {
        return None;
    }
    parse_id(id, 'b')
}

fn valid_keyword(keyword: &str) -> bool {
    !keyword.is_empty() && keyword.len() <= 100 && keyword.bytes().all(|b| b.is_ascii_graphic() && !b"(){]%*\"\\".contains(&b))
}

fn split_keywords(map: &Map<String, Value>) -> Result<(Flags, Vec<String>), Value> {
    let mut flags = Flags::default();
    let mut custom = Vec::new();
    for (keyword, value) in map {
        if value.as_bool() != Some(true) {
            continue;
        }
        let lower = keyword.to_ascii_lowercase();
        match lower.as_str() {
            "$seen" => flags.seen = true,
            "$answered" => flags.answered = true,
            "$flagged" => flags.flagged = true,
            "$draft" => flags.draft = true,
            _ if valid_keyword(&lower) => custom.push(lower),
            _ => return Err(set_error("invalidProperties", "invalid keyword")),
        }
    }
    if custom.len() > MAX_KEYWORDS {
        return Err(set_error("invalidProperties", "too many keywords"));
    }
    Ok((flags, custom))
}

pub(super) async fn apply_update(ctx: &Context<'_>, id: &str, patch: &Map<String, Value>) -> Result<(), Value> {
    let store = &ctx.app.store;
    let not_found = || set_error("notFound", "email not found");
    let fail = |err: StoreError| match err {
        StoreError::NotFound => set_error("notFound", "email or mailbox not found"),
        other => {
            tracing::error!(error = ?other, "email update failed");
            set_error("serverFail", "internal error")
        }
    };
    let message_id = parse_id(id, 'm').ok_or_else(not_found)?;
    let (message, rights) = ctx.message(message_id).await.map_err(|_| set_error("serverFail", "internal error"))?.ok_or_else(not_found)?;
    let owner = message.account_id;
    let forbidden = || set_error("forbidden", "you do not have the necessary rights on this mailbox");

    let Value::Object(mut keywords) = keywords_json(&message) else { unreachable!("keywords_json returns an object") };
    let mut keywords_changed = false;
    let mut target_mailbox = None;
    for (key, value) in patch {
        match key.as_str() {
            "keywords" => {
                keywords = value.as_object().cloned().ok_or_else(|| set_error("invalidProperties", "keywords must be an object"))?;
                keywords_changed = true;
            }
            "mailboxIds" => target_mailbox = Some(single_mailbox(value).ok_or_else(|| set_error("invalidProperties", "an email must be in exactly one mailbox"))?),
            _ => {
                if let Some(keyword) = key.strip_prefix("keywords/") {
                    if value.as_bool() == Some(true) {
                        keywords.insert(keyword.to_owned(), Value::Bool(true));
                    } else {
                        keywords.remove(keyword);
                    }
                    keywords_changed = true;
                } else if let Some(mailbox) = key.strip_prefix("mailboxIds/") {
                    if value.as_bool() == Some(true) {
                        target_mailbox = Some(parse_id(mailbox, 'b').ok_or_else(|| set_error("invalidProperties", "invalid mailbox id"))?);
                    }
                } else {
                    return Err(set_error("invalidProperties", format!("property {} cannot be updated", crate::util::sanitize_line(key))));
                }
            }
        }
    }
    if keywords_changed {
        let (flags, custom) = split_keywords(&keywords)?;
        // RFC 4314: the read state needs `s`, any other flag or label needs `w`.
        let seen_changed = flags.seen != message.seen;
        let mut old_custom: Vec<String> = serde_json::from_str(&message.keywords).unwrap_or_default();
        let mut new_custom = custom.clone();
        old_custom.sort();
        new_custom.sort();
        let other_changed = (flags.answered, flags.flagged, flags.draft) != (message.answered, message.flagged, message.draft) || old_custom != new_custom;
        if (seen_changed && !rights.contains('s')) || (other_changed && !rights.contains('w')) {
            return Err(forbidden());
        }
        store.set_flags_and_keywords(owner, message_id, Flags { deleted: message.deleted, ..flags }, &custom).await.map_err(fail)?;
        if owner == ctx.account.id {
            crate::bayes::train_on_keywords(ctx.app, owner, &message.blob_hash, &old_custom, &new_custom);
            crate::categories::train_on_keywords(ctx.app, owner, &message.blob_hash, &old_custom, &new_custom);
        }
    }
    if let Some(mailbox) = target_mailbox.filter(|target| *target != message.mailbox_id) {
        let (target, target_rights) = ctx.mailbox(mailbox).await.map_err(|_| set_error("serverFail", "internal error"))?.ok_or_else(|| set_error("notFound", "email or mailbox not found"))?;
        // Moving removes from the source and inserts into the target.
        if !(rights.contains('t') && rights.contains('e') && target_rights.contains('i')) {
            return Err(forbidden());
        }
        store.move_across(owner, message_id, target.account_id, target.id).await.map_err(|err| match err {
            StoreError::QuotaExceeded => set_error("overQuota", "mailbox quota exceeded"),
            other => fail(other),
        })?;
        // Spam training reflects the owner's own filing decisions only.
        if owner == target.account_id && owner == ctx.account.id {
            crate::bayes::train_on_move(ctx.app, owner, &message.blob_hash, message.mailbox_id, mailbox);
        }
    }
    Ok(())
}

pub async fn set(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let old_state = ctx.state().await?;
    let (mut created, mut not_created) = (Map::new(), Map::new());
    let (mut updated, mut not_updated) = (Map::new(), Map::new());
    let (mut destroyed, mut not_destroyed) = (Vec::new(), Map::new());

    if let Some(create) = args.get("create").and_then(Value::as_object) {
        for (creation_id, spec) in create {
            let result = async {
                let spec = spec.as_object().ok_or_else(|| set_error("invalidProperties", "expected an object"))?;
                let mailbox = spec.get("mailboxIds").and_then(single_mailbox).ok_or_else(|| set_error("invalidProperties", "an email must be in exactly one mailbox"))?;
                let empty = Map::new();
                let (flags, custom) = split_keywords(spec.get("keywords").and_then(Value::as_object).unwrap_or(&empty))?;
                let raw = build_message(ctx, spec).await?;
                let owner = match ctx.mailbox(mailbox).await.map_err(|_| set_error("serverFail", "internal error"))? {
                    Some((target, rights)) if rights.contains('i') => target.account_id,
                    Some(_) => return Err(set_error("forbidden", "you may not add messages to this mailbox")),
                    None => return Err(set_error("invalidProperties", "unknown mailbox")),
                };
                let appended = ctx.app.store.append(owner, mailbox, &raw, flags, None).await.map_err(|err| match err {
                    StoreError::NotFound => set_error("invalidProperties", "unknown mailbox"),
                    StoreError::QuotaExceeded => set_error("overQuota", "mailbox quota exceeded"),
                    other => {
                        tracing::error!(error = ?other, "email creation failed");
                        set_error("serverFail", "internal error")
                    }
                })?;
                if !custom.is_empty() {
                    let _ = ctx.app.store.set_flags_and_keywords(owner, appended.id, flags, &custom).await;
                }
                Ok::<_, Value>((appended, raw.len()))
            }
            .await;
            match result {
                Ok((appended, size)) => {
                    let id = format!("m{}", appended.id);
                    ctx.created.insert(creation_id.clone(), id.clone());
                    created.insert(creation_id.clone(), json!({ "id": id, "threadId": format!("t{}", appended.thread_id), "size": size }));
                }
                Err(err) => {
                    not_created.insert(creation_id.clone(), err);
                }
            }
        }
    }
    if let Some(update) = args.get("update").and_then(Value::as_object) {
        for (id, patch) in update {
            let real_id = ctx.resolve_id(id);
            let result = match patch.as_object() {
                Some(patch) => apply_update(ctx, &real_id, patch).await,
                None => Err(set_error("invalidPatch", "expected an object")),
            };
            match result {
                Ok(()) => updated.insert(id.clone(), Value::Null),
                Err(err) => not_updated.insert(id.clone(), err),
            };
        }
    }
    if let Some(destroy) = args.get("destroy").and_then(Value::as_array) {
        for id in destroy.iter().filter_map(Value::as_str) {
            let found = match parse_id(id, 'm') {
                Some(message_id) => ctx.message(message_id).await?,
                None => None,
            };
            let result = match found {
                Some((message, rights)) if rights.contains('t') && rights.contains('e') => ctx.app.store.delete_message(message.account_id, message.id).await,
                Some(_) => {
                    not_destroyed.insert(id.to_owned(), set_error("forbidden", "you may not delete messages in this mailbox"));
                    continue;
                }
                None => Err(StoreError::NotFound),
            };
            match result {
                Ok(()) => destroyed.push(id.to_owned()),
                Err(StoreError::NotFound) => {
                    not_destroyed.insert(id.to_owned(), set_error("notFound", "email not found"));
                }
                Err(err) => return Err(err.into()),
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

/// `Email/import` (RFC 8621 section 4.8): stores uploaded RFC 5322 messages as they are. The
/// web client uses it for messages it has to build itself, such as PGP/MIME.
pub async fn import(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let old_state = ctx.state().await?;
    let (mut created, mut not_created) = (Map::new(), Map::new());
    let emails = args.get("emails").and_then(Value::as_object).ok_or_else(|| MethodError::invalid("emails is required"))?;
    if emails.len() > MAX_OBJECTS {
        return Err(MethodError("requestTooLarge", "too many emails".into()));
    }
    for (creation_id, spec) in emails {
        let result = async {
            let blob_id = spec["blobId"].as_str().ok_or_else(|| set_error("invalidProperties", "blobId is required"))?;
            let mailbox = single_mailbox(&spec["mailboxIds"]).ok_or_else(|| set_error("invalidProperties", "an email must be in exactly one mailbox"))?;
            let empty = Map::new();
            let (flags, custom) = split_keywords(spec.get("keywords").and_then(Value::as_object).unwrap_or(&empty))?;
            // Only the user's own uploads can be imported, never a blob id guessed from elsewhere.
            if !blob_id.starts_with('u') {
                return Err(set_error("blobNotFound", "only uploaded blobs can be imported"));
            }
            let (raw, _) = load_blob(ctx.app, ctx.account, blob_id)
                .await
                .map_err(|_| set_error("serverFail", "could not read the blob"))?
                .ok_or_else(|| set_error("blobNotFound", "unknown blob"))?;
            if raw.len() > ctx.app.rt().max_message_size {
                return Err(set_error("tooLarge", "the message exceeds the maximum size"));
            }
            let parsed = MessageParser::default().parse_headers(&raw[..]);
            if parsed.is_none_or(|m| m.from().is_none()) {
                return Err(set_error("invalidEmail", "the blob is not an e-mail message"));
            }
            let owner = match ctx.mailbox(mailbox).await.map_err(|_| set_error("serverFail", "internal error"))? {
                Some((target, rights)) if rights.contains('i') => target.account_id,
                Some(_) => return Err(set_error("forbidden", "you may not add messages to this mailbox")),
                None => return Err(set_error("invalidProperties", "unknown mailbox")),
            };
            let appended = ctx.app.store.append(owner, mailbox, &raw, flags, None).await.map_err(|err| match err {
                StoreError::QuotaExceeded => set_error("overQuota", "mailbox quota exceeded"),
                other => {
                    tracing::error!(error = ?other, "email import failed");
                    set_error("serverFail", "internal error")
                }
            })?;
            if !custom.is_empty() {
                let _ = ctx.app.store.set_flags_and_keywords(owner, appended.id, flags, &custom).await;
            }
            Ok::<_, Value>((appended, raw.len()))
        }
        .await;
        match result {
            Ok((appended, size)) => {
                let id = format!("m{}", appended.id);
                ctx.created.insert(creation_id.clone(), id.clone());
                created.insert(creation_id.clone(), json!({ "id": id, "threadId": format!("t{}", appended.thread_id), "size": size }));
            }
            Err(err) => {
                not_created.insert(creation_id.clone(), err);
            }
        }
    }
    Ok(json!({ "accountId": account_id(ctx.account), "oldState": old_state, "newState": ctx.state().await?, "created": created, "notCreated": not_created }))
}

/// Removes the `Bcc` header so blind-copy recipients are not disclosed to anyone else.
pub fn strip_bcc(raw: &[u8]) -> Vec<u8> {
    let (headers, body) = raw.split_at(find_header_end(raw));
    let mut out = Vec::with_capacity(raw.len());
    let mut skipping = false;
    for line in headers.split_inclusive(|b| *b == b'\n') {
        if !matches!(line.first(), Some(b' ' | b'\t')) {
            skipping = line.len() >= 4 && line[..4].eq_ignore_ascii_case(b"bcc:");
        }
        if !skipping {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(body);
    out
}

/// What a submission sends: sender, recipients and the message without its Bcc header.
pub(super) async fn prepare_email(ctx: &Context<'_>, message_id: i64) -> Result<(Address, Vec<Address>, Vec<u8>), Value> {
    let message = ctx.app.store.message(ctx.account.id, message_id).await.map_err(|_| set_error("invalidProperties", "unknown emailId"))?;
    let raw = ctx.app.store.read_blob(&message.blob_hash).await.map_err(|_| set_error("serverFail", "message content is missing"))?;
    let parsed = MessageParser::default().parse(&raw).ok_or_else(|| set_error("invalidEmail", "the message cannot be parsed"))?;

    let sender = parsed
        .from()
        .and_then(|f| f.first())
        .and_then(|a| a.address())
        .and_then(Address::parse)
        .ok_or_else(|| set_error("invalidEmail", "the message has no valid From address"))?;
    let mut recipients: Vec<Address> = Vec::new();
    for list in [parsed.to(), parsed.cc(), parsed.bcc()].into_iter().flatten() {
        for entry in list.iter() {
            let address = entry.address().and_then(Address::parse).ok_or_else(|| set_error("invalidRecipients", "the message has an invalid recipient address"))?;
            if !recipients.contains(&address) {
                recipients.push(address);
            }
        }
    }
    if recipients.is_empty() {
        return Err(set_error("noRecipients", "the message has no recipients"));
    }
    Ok((sender, recipients, strip_bcc(&raw)))
}

/// Sends a stored email now.
pub(super) async fn send_email(ctx: &Context<'_>, message_id: i64) -> Result<(), Value> {
    let (sender, recipients, outgoing) = prepare_email(ctx, message_id).await?;
    let submission = Submission { account: ctx.account, sender: &sender, recipients: &recipients, raw: &outgoing, delegate: None, ip: ctx.ip };
    match submit::submit(ctx.app, submission).await {
        Outcome::Accepted(_) => Ok(()),
        // Strip the SMTP status code; the remainder is a user-presentable reason.
        Outcome::Rejected(reply) => Err(set_error("forbiddenToSend", reply.splitn(3, ' ').nth(2).unwrap_or(&reply))),
        Outcome::Deferred(_) => Err(set_error("serverFail", "the message could not be queued, try again later")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcc_header_is_removed_including_folded_lines() {
        let raw = b"From: a@example.org\r\nBcc: secret@example.org,\r\n\tother@example.org\r\nTo: b@example.org\r\nbcc: third@example.org\r\n\r\nBcc: this is body text\r\n";
        assert_eq!(strip_bcc(raw), b"From: a@example.org\r\nTo: b@example.org\r\n\r\nBcc: this is body text\r\n");
    }

    #[test]
    fn keyword_validation() {
        assert!(valid_keyword("work"));
        assert!(valid_keyword("$forwarded"));
        for bad in ["", "two words", "paren(", "star*", "quote\"", "new\nline"] {
            assert!(!valid_keyword(bad), "{bad:?}");
        }
    }

    #[test]
    fn mailbox_selection_requires_exactly_one() {
        assert_eq!(single_mailbox(&json!({ "b3": true })), Some(3));
        assert_eq!(single_mailbox(&json!({ "b3": true, "b4": false })), Some(3));
        assert_eq!(single_mailbox(&json!({ "b3": true, "b4": true })), None);
        assert_eq!(single_mailbox(&json!({})), None);
        assert_eq!(single_mailbox(&json!({ "x": true })), None);
    }
}
