//! Per-user inbox tools: blocked senders, label definitions, inbox categories and
//! unsubscribing from mailing lists.

use axum::{
    Json,
    extract::{Query, State},
};
use mail_parser::MessageParser;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{JsonResult, Session};
use crate::{
    app::AppState,
    categories,
    error::ApiError,
    smtp::submit::{self, Outcome, Submission},
    util::{Address, normalize_domain, now, sanitize_line},
};

const MAX_BLOCKED: i64 = 1000;
const MAX_LABELS: i64 = 200;

// --- Blocked senders -----------------------------------------------------------------------

/// Normalizes an entry of the block list: an address, or `@domain` for a whole domain.
pub fn normalize_blocked(input: &str) -> Option<String> {
    let input = input.trim();
    match input.strip_prefix('@') {
        Some(domain) => normalize_domain(domain).map(|domain| format!("@{domain}")),
        None => Address::parse(input).map(|address| address.to_string()),
    }
}

/// Whether mail from `sender` is blocked by the account, by address or by domain.
pub async fn is_blocked(db: &sqlx::SqlitePool, account_id: i64, sender: &str) -> sqlx::Result<bool> {
    let Some(address) = Address::parse(sender) else { return Ok(false) };
    let found: Option<i64> = sqlx::query_scalar("SELECT 1 FROM blocked_senders WHERE account_id = ? AND sender IN (?, ?) LIMIT 1")
        .bind(account_id)
        .bind(address.to_string())
        .bind(format!("@{}", address.domain))
        .fetch_optional(db)
        .await?;
    Ok(found.is_some())
}

/// What the user's personal spam filter has learned, and whether it is deciding yet.
pub async fn spam_filter(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let (spam, ham) = crate::bayes::counts(&state.db, session.account.id).await?;
    let enabled = state.rt().personal_spam_filter;
    Ok(Json(json!({
        "enabled": enabled,
        "spam": spam,
        "ham": ham,
        "needed": crate::bayes::MIN_LEARNED,
        "active": enabled && spam >= crate::bayes::MIN_LEARNED && ham >= crate::bayes::MIN_LEARNED,
    })))
}

/// Forgets what the personal spam filter learned.
pub async fn spam_filter_reset(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    crate::bayes::reset(&state.db, session.account.id).await?;
    crate::db::audit(&state.db, &session.account.email, "spam_filter.reset", "", "", "").await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn blocked_list(State(state): State<AppState>, session: Session) -> JsonResult<Vec<String>> {
    Ok(Json(sqlx::query_scalar("SELECT sender FROM blocked_senders WHERE account_id = ? ORDER BY sender").bind(session.account.id).fetch_all(&state.db).await?))
}

#[derive(Deserialize)]
pub struct SenderInput {
    sender: String,
}

pub async fn blocked_add(State(state): State<AppState>, session: Session, Json(input): Json<SenderInput>) -> JsonResult<Value> {
    let sender = normalize_blocked(&input.sender).ok_or_else(|| ApiError::bad("enter an e-mail address, or @domain for a whole domain"))?;
    if sender == session.account.email {
        return Err(ApiError::bad("you cannot block your own address"));
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocked_senders WHERE account_id = ?").bind(session.account.id).fetch_one(&state.db).await?;
    if count >= MAX_BLOCKED {
        return Err(ApiError::Conflict(format!("at most {MAX_BLOCKED} senders can be blocked")));
    }
    sqlx::query("INSERT OR IGNORE INTO blocked_senders (account_id, sender, created_at) VALUES (?, ?, ?)")
        .bind(session.account.id)
        .bind(&sender)
        .bind(now())
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "sender": sender })))
}

#[derive(Deserialize)]
pub struct SenderQuery {
    sender: String,
}

pub async fn blocked_remove(State(state): State<AppState>, session: Session, Query(query): Query<SenderQuery>) -> JsonResult<Value> {
    let sender = normalize_blocked(&query.sender).ok_or(ApiError::NotFound)?;
    let removed = sqlx::query("DELETE FROM blocked_senders WHERE account_id = ? AND sender = ?").bind(session.account.id).bind(sender).execute(&state.db).await?.rows_affected();
    if removed == 0 { Err(ApiError::NotFound) } else { Ok(Json(json!({ "ok": true }))) }
}

// --- Labels --------------------------------------------------------------------------------

/// Labels are keywords; the same alphabet as the web client's `normalizeLabel`.
pub fn valid_label(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 49
        && bytes.next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-'))
}

fn valid_color(color: &str) -> bool {
    color.is_empty() || (color.len() == 7 && color.starts_with('#') && color[1..].bytes().all(|b| b.is_ascii_hexdigit()))
}

// --- New-mail notifications ---------------------------------------------------------------

/// The newest unread message in the inbox, for the browser's new-mail notification. The
/// service worker asks with the session cookie alone: a GET that changes nothing, so it needs
/// no CSRF token. `account` is the JMAP account id, to match the push it answers.
pub async fn newest_unread(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let newest: Option<(String, String, String, String, i64)> = sqlx::query_as(
        "SELECT m.from_name, m.from_addr, m.subject, m.snippet, m.thread_id FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id
         WHERE m.account_id = ? AND b.role = 'inbox' AND m.seen = 0 AND m.deleted = 0 AND m.draft = 0
         ORDER BY m.internal_date DESC, m.id DESC LIMIT 1",
    )
    .bind(session.account.id)
    .fetch_optional(&state.db)
    .await?;
    let unread: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id WHERE m.account_id = ? AND b.role = 'inbox' AND m.seen = 0 AND m.deleted = 0 AND m.draft = 0",
    )
    .bind(session.account.id)
    .fetch_one(&state.db)
    .await?;
    let message = newest.map(|(name, address, subject, snippet, thread)| {
        json!({ "from": if name.is_empty() { address } else { name }, "subject": subject, "preview": snippet, "threadId": format!("t{thread}") })
    });
    Ok(Json(json!({ "account": format!("a{}", session.account.id), "unread": unread, "message": message })))
}

/// Every label of the account with its colour: the defined ones and those merely in use.
pub async fn label_details(State(state): State<AppState>, session: Session) -> JsonResult<Vec<Value>> {
    let defined: Vec<(String, String)> = sqlx::query_as("SELECT name, color FROM labels WHERE account_id = ?").bind(session.account.id).fetch_all(&state.db).await?;
    let mut out: Vec<(String, String)> = defined;
    for name in state.store.keywords(session.account.id).await? {
        if !out.iter().any(|(known, _)| *known == name) {
            out.push((name, String::new()));
        }
    }
    out.sort();
    Ok(Json(out.into_iter().map(|(name, color)| json!({ "name": name, "color": color })).collect()))
}

#[derive(Deserialize)]
pub struct LabelInput {
    name: String,
    #[serde(default)]
    color: String,
}

/// Defines a label (so it exists before it is first used) or changes its colour.
pub async fn label_put(State(state): State<AppState>, session: Session, Json(input): Json<LabelInput>) -> JsonResult<Value> {
    if !valid_label(&input.name) {
        return Err(ApiError::bad("label names may contain lowercase letters, digits, '-', '_' and '.'"));
    }
    if !valid_color(&input.color) {
        return Err(ApiError::bad("the colour must look like #rrggbb"));
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM labels WHERE account_id = ? AND name != ?").bind(session.account.id).bind(&input.name).fetch_one(&state.db).await?;
    if count >= MAX_LABELS {
        return Err(ApiError::Conflict(format!("at most {MAX_LABELS} labels can be defined")));
    }
    sqlx::query("INSERT INTO labels (account_id, name, color) VALUES (?, ?, ?) ON CONFLICT(account_id, name) DO UPDATE SET color = excluded.color")
        .bind(session.account.id)
        .bind(&input.name)
        .bind(input.color.to_ascii_lowercase())
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "name": input.name, "color": input.color.to_ascii_lowercase() })))
}

// --- Categories ----------------------------------------------------------------------------

/// Unread conversations per inbox category, for the badges on the category tabs.
pub async fn category_counts(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT COALESCE((SELECT k.keyword FROM message_keywords k WHERE k.message_id = m.id AND k.keyword >= '$cat_' AND k.keyword < '$cat`' LIMIT 1), '$cat_general') AS category,
                COUNT(DISTINCT m.thread_id)
         FROM messages m
         WHERE m.mailbox_id = (SELECT id FROM mailboxes WHERE account_id = ?1 AND role = 'inbox') AND m.account_id = ?1 AND m.seen = 0 GROUP BY category",
    )
    .bind(session.account.id)
    .fetch_all(&state.db)
    .await?;
    let mut out = Map::new();
    out.insert("general".into(), json!(0));
    for name in categories::NAMES {
        out.insert(name.into(), json!(0));
    }
    for (keyword, unread) in rows {
        if let Some(name) = keyword.strip_prefix(categories::PREFIX).filter(|name| categories::valid_name(name)) {
            out.insert(name.to_owned(), json!(unread));
        }
    }
    Ok(Json(Value::Object(out)))
}

/// What the inbox categories have learned from the user's corrections.
pub async fn category_learning(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let learned = categories::counts(&state.db, session.account.id).await?;
    let per_category: Map<String, Value> = categories::Category::ALL.into_iter().map(|c| (c.name().to_owned(), json!(learned.get(&c).copied().unwrap_or(0)))).collect();
    Ok(Json(json!({
        "learned": per_category,
        "total": learned.values().sum::<i64>(),
        "senders": categories::sender_count(&state.db, session.account.id).await?,
        "needed": categories::MIN_LEARNED,
    })))
}

/// Forgets what the inbox categories learned; the header rules alone sort new mail again.
pub async fn category_learning_reset(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    categories::reset(&state.db, session.account.id).await?;
    crate::db::audit(&state.db, &session.account.email, "categories.reset", "", "", "").await;
    Ok(Json(json!({ "ok": true })))
}

// --- Unsubscribe ---------------------------------------------------------------------------

/// What a message offers for unsubscribing (RFC 2369 and RFC 8058).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Unsubscribe {
    /// `https` address that accepts a one-click POST.
    pub one_click: Option<String>,
    /// `mailto:` target.
    pub mailto: Option<String>,
    /// A web page the reader has to visit.
    pub link: Option<String>,
}

impl Unsubscribe {
    pub fn is_empty(&self) -> bool {
        self.one_click.is_none() && self.mailto.is_none() && self.link.is_none()
    }

    /// What the client is told: which methods exist, never the addresses themselves.
    pub fn to_json(&self) -> Value {
        if self.is_empty() { Value::Null } else { json!({ "oneClick": self.one_click.is_some(), "mailto": self.mailto.is_some(), "link": self.link.is_some() }) }
    }
}

/// Reads the unsubscribe options from a message's `List-Unsubscribe` headers.
pub fn unsubscribe_options(raw: &[u8]) -> Unsubscribe {
    let Some(message) = MessageParser::default().parse_headers(raw) else { return Unsubscribe::default() };
    let Some(list) = message.header_raw("List-Unsubscribe") else { return Unsubscribe::default() };
    let one_click_declared = message.header_raw("List-Unsubscribe-Post").is_some_and(|value| value.to_ascii_lowercase().replace(char::is_whitespace, "").contains("list-unsubscribe=one-click"));
    let mut out = Unsubscribe::default();
    // The header is a comma-separated list of <uri> entries, possibly folded over lines.
    for part in list.split('<').skip(1) {
        let Some((uri, _)) = part.split_once('>') else { continue };
        let uri: String = uri.chars().filter(|c| !c.is_whitespace()).collect();
        let lower = uri.to_ascii_lowercase();
        if lower.starts_with("mailto:") && out.mailto.is_none() {
            out.mailto = Some(uri);
        } else if lower.starts_with("https://") && reqwest::Url::parse(&uri).is_ok() {
            // RFC 8058: one-click needs HTTPS and the sender's explicit declaration.
            if one_click_declared && out.one_click.is_none() {
                out.one_click = Some(uri);
            } else if out.link.is_none() {
                out.link = Some(uri);
            }
        } else if lower.starts_with("http://") && out.link.is_none() && reqwest::Url::parse(&uri).is_ok() {
            out.link = Some(uri);
        }
    }
    out
}

/// Splits a `mailto:` URI into the address and its `subject` and `body` parameters.
fn parse_mailto(uri: &str) -> Option<(Address, String, String)> {
    let rest = uri.get(7..)?;
    let (target, query) = rest.split_once('?').unwrap_or((rest, ""));
    let decode = |value: &str| -> String {
        let mut bytes = Vec::new();
        let mut input = value.bytes();
        while let Some(b) = input.next() {
            match b {
                b'%' => {
                    let hex: Vec<u8> = input.by_ref().take(2).collect();
                    match std::str::from_utf8(&hex).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                        Some(byte) => bytes.push(byte),
                        None => bytes.push(b'%'),
                    }
                }
                other => bytes.push(other),
            }
        }
        String::from_utf8_lossy(&bytes).into_owned()
    };
    // Only the first address: an unsubscribe request has exactly one destination.
    let address = Address::parse(decode(target).split(',').next()?)?;
    let (mut subject, mut body) = (String::from("unsubscribe"), String::new());
    for pair in query.split('&') {
        match pair.split_once('=') {
            Some((key, value)) if key.eq_ignore_ascii_case("subject") => subject = sanitize_line(&decode(value)),
            Some((key, value)) if key.eq_ignore_ascii_case("body") => body = decode(value).chars().filter(|c| !c.is_control() || *c == '\n').take(2000).collect(),
            _ => {}
        }
    }
    Some((address, subject, body))
}

#[derive(Deserialize)]
pub struct UnsubscribeRequest {
    /// JMAP id of the message, e.g. `m42`.
    email_id: String,
}

/// Unsubscribes from the list a message came from, using the best method the sender offers:
/// a one-click request made by the server, an e-mail sent on the user's behalf, or, failing
/// both, a link for the user to open.
pub async fn unsubscribe(State(state): State<AppState>, session: Session, Json(request): Json<UnsubscribeRequest>) -> JsonResult<Value> {
    let id = crate::jmap::parse_id(&request.email_id, 'm').ok_or(ApiError::NotFound)?;
    // Only for the user's own mail: the request is made (or the mail sent) in their name.
    let message = state.store.message(session.account.id, id).await?;
    let raw = state.store.read_blob(&message.blob_hash).await?;
    let options = unsubscribe_options(&raw);

    if let Some(url) = &options.one_click {
        let url = reqwest::Url::parse(url).map_err(|_| ApiError::bad("the unsubscribe address is invalid"))?;
        // The same rules as for remote images: public hosts only, the checked address is the
        // one connected to, and no redirects are followed for a state-changing request.
        let (host, addr) = super::mailboxes::public_target(&state, &url, &[443, 8443]).await?;
        let client = reqwest::Client::builder()
            .use_preconfigured_tls((*crate::smtp::client::tls_config(true)).clone())
            .resolve(&host, addr)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(anyhow::Error::from)?;
        let response = client.post(url).header("content-type", "application/x-www-form-urlencoded").header("user-agent", "unoMail").body("List-Unsubscribe=One-Click").send().await;
        let done = response.as_ref().is_ok_and(|r| r.status().is_success() || r.status().is_redirection());
        session.audit(&state, "mail.unsubscribed", &message.from_addr, if done { "one-click" } else { "one-click failed" }).await;
        if done {
            return Ok(Json(json!({ "method": "one-click" })));
        }
        // Fall through to the other methods when the sender's endpoint does not answer.
    }
    if let Some((target, subject, body)) = options.mailto.as_deref().and_then(parse_mailto) {
        let sender = Address::parse(&session.account.email).ok_or(ApiError::NotFound)?;
        let raw = format!(
            "From: <{}>\r\nTo: <{target}>\r\nSubject: {subject}\r\nAuto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}\r\n",
            session.account.email,
            body.replace('\n', "\r\n")
        );
        let submission = Submission { account: &session.account, sender: &sender, recipients: std::slice::from_ref(&target), raw: raw.as_bytes(), delegate: None, ip: session.ip };
        return match submit::submit(&state, submission).await {
            Outcome::Accepted(_) => {
                session.audit(&state, "mail.unsubscribed", &message.from_addr, "mail").await;
                Ok(Json(json!({ "method": "mail", "to": target.to_string() })))
            }
            Outcome::Rejected(reply) | Outcome::Deferred(reply) => Err(ApiError::bad(format!("the unsubscribe request could not be sent: {}", reply.splitn(3, ' ').nth(2).unwrap_or(&reply)))),
        };
    }
    match &options.link {
        Some(link) => Ok(Json(json!({ "method": "link", "url": link }))),
        None if options.one_click.is_some() => Err(ApiError::bad("the sender's unsubscribe service did not accept the request")),
        None => Err(ApiError::bad("this message does not offer a way to unsubscribe")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(headers: &str) -> Unsubscribe {
        unsubscribe_options(format!("From: a@b.example\r\n{headers}\r\n\r\nbody").as_bytes())
    }

    #[test]
    fn unsubscribe_headers() {
        let both = options("List-Unsubscribe: <mailto:leave@list.example?subject=unsubscribe>,\r\n <https://list.example/u/123>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click");
        assert_eq!(both.one_click.as_deref(), Some("https://list.example/u/123"));
        assert_eq!(both.mailto.as_deref(), Some("mailto:leave@list.example?subject=unsubscribe"));
        assert_eq!(both.to_json(), json!({ "oneClick": true, "mailto": true, "link": false }));

        // Without the sender's declaration an HTTPS address is only a page to visit.
        let page = options("List-Unsubscribe: <https://list.example/u/123>");
        assert_eq!((page.one_click.as_deref(), page.link.as_deref()), (None, Some("https://list.example/u/123")));
        // One-click is never done over plain HTTP.
        let plain = options("List-Unsubscribe: <http://list.example/u>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click");
        assert_eq!((plain.one_click.as_deref(), plain.link.as_deref()), (None, Some("http://list.example/u")));

        for none in ["Subject: x", "List-Unsubscribe: nothing useful", "List-Unsubscribe: <javascript:alert(1)>, <file:///etc/passwd>, <ftp://x.example/>"] {
            let found = options(none);
            assert!(found.is_empty(), "{none}: {found:?}");
            assert_eq!(found.to_json(), Value::Null);
        }
    }

    #[test]
    fn mailto_targets() {
        let (address, subject, body) = parse_mailto("mailto:Leave@List.example?subject=Unsubscribe%20me&body=list%3A%20news%0Aplease").unwrap();
        assert_eq!((address.to_string().as_str(), subject.as_str(), body.as_str()), ("leave@list.example", "Unsubscribe me", "list: news\nplease"));
        let (address, subject, _) = parse_mailto("mailto:leave@list.example").unwrap();
        assert_eq!((address.to_string().as_str(), subject.as_str()), ("leave@list.example", "unsubscribe"));
        // Header injection through the subject parameter is neutralised.
        let (_, subject, _) = parse_mailto("mailto:a@b.example?subject=x%0D%0ABcc:%20evil@x.example").unwrap();
        assert_eq!(subject, "xBcc: evil@x.example");
        assert!(parse_mailto("mailto:not-an-address").is_none());
        assert!(parse_mailto("mailto:").is_none());
    }

    #[test]
    fn block_list_entries_and_label_names() {
        assert_eq!(normalize_blocked(" Spammer@Shop.Example ").as_deref(), Some("spammer@shop.example"));
        assert_eq!(normalize_blocked("@Shop.Example").as_deref(), Some("@shop.example"));
        for bad in ["", "@", "@nodots", "no at sign", "a@b"] {
            assert_eq!(normalize_blocked(bad), None, "{bad:?}");
        }
        assert!(valid_label("work") && valid_label("2026_taxes.final") && valid_label("project-x"));
        for bad in ["", "$seen", "Work", "a b", "-x", "a/b", &"x".repeat(60)] {
            assert!(!valid_label(bad), "{bad:?}");
        }
        assert!(valid_color("") && valid_color("#1A2b3c") && !valid_color("red") && !valid_color("#12345") && !valid_color("#12345g"));
    }
}
