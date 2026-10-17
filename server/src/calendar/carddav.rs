//! CardDAV (RFC 6352): the address book of the web client for phones and mail programs.
//!
//! Every account has one address book. The contacts live in the same table the web client
//! uses, so both always show the same people. A card stored by a client is kept as it came;
//! when the web client later changes a field it knows (name, address, phone, organization,
//! notes), only that property of the card is rewritten and everything else - photos, postal
//! addresses, birthdays - stays.

// Handlers short-circuit with the finished error response; boxing it would buy nothing here.
#![allow(clippy::result_large_err)]

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use super::dav::{Hrefs, NAMESPACES, Query, Resource, SYNC_PREFIX, internal, matches_etag, multistatus, parse_query, percent_decode, precondition, status, xml_escape};
use crate::{
    app::AppState,
    auth::Account,
    util::{Address, sha256_hex},
};

const MAX_CARD_BYTES: usize = 1024 * 1024;
const MAX_CONTACTS: i64 = 5000;

#[derive(Debug, Clone, Default, sqlx::FromRow)]
struct Card {
    id: i64,
    name: String,
    email: String,
    phone: String,
    organization: String,
    notes: String,
    uid: String,
    dav_name: String,
    vcard: Option<String>,
}

const COLUMNS: &str = "id, name, email, phone, organization, notes, uid, dav_name, vcard";

// --- vCard -----------------------------------------------------------------------------------

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\n', "\\n").replace(',', "\\,").replace(';', "\\;")
}

fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n' | 'N') => out.push('\n'),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// The content lines of a card, unfolded.
fn lines(card: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in card.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        match raw.strip_prefix([' ', '\t']) {
            Some(rest) if !out.is_empty() => out.last_mut().expect("checked non-empty").push_str(rest),
            _ if raw.is_empty() => {}
            _ => out.push(raw.to_owned()),
        }
    }
    out
}

/// Upper-case property name of a content line, without group prefix and parameters.
fn name_of(line: &str) -> String {
    let head = line.split([':', ';']).next().unwrap_or("");
    head.rsplit('.').next().unwrap_or("").trim().to_ascii_uppercase()
}

fn value_of(line: &str) -> &str {
    line.split_once(':').map_or("", |(_, value)| value)
}

fn fold(line: &str, out: &mut String) {
    let mut width = 0;
    for c in line.chars() {
        if width + c.len_utf8() > 75 {
            out.push_str("\r\n ");
            width = 1;
        }
        out.push(c);
        width += c.len_utf8();
    }
    out.push_str("\r\n");
}

/// The fields the address book keeps in columns, as a card states them.
#[derive(Debug, Default, PartialEq, Eq)]
struct Fields {
    name: String,
    email: String,
    phone: String,
    organization: String,
    notes: String,
    uid: String,
}

fn extract(card: &str) -> Fields {
    let mut fields = Fields::default();
    let (mut structured, mut seen) = (String::new(), Vec::new());
    for line in lines(card) {
        let name = name_of(&line);
        let value = unescape(value_of(&line).trim());
        let first = !seen.contains(&name);
        match name.as_str() {
            "FN" if first => fields.name = value,
            // "Family;Given;Additional;Prefix;Suffix": used when a card has no formatted name.
            "N" if first => {
                let parts: Vec<&str> = value_of(&line).split(';').map(str::trim).collect();
                structured = [parts.get(3), parts.get(1), parts.get(2), parts.first(), parts.get(4)].into_iter().flatten().filter(|part| !part.is_empty()).map(|part| unescape(part)).collect::<Vec<_>>().join(" ");
            }
            "EMAIL" if first => fields.email = Address::parse(&value).map(|address| address.to_string()).unwrap_or_default(),
            "TEL" if first => fields.phone = value,
            "ORG" if first => fields.organization = value_of(&line).split(';').map(|part| unescape(part.trim())).filter(|part| !part.is_empty()).collect::<Vec<_>>().join(" "),
            "NOTE" if first => fields.notes = value,
            "UID" if first => fields.uid = value,
            _ => {}
        }
        seen.push(name);
    }
    if fields.name.is_empty() {
        fields.name = structured;
    }
    let limit = |text: &str, max: usize, multiline: bool| text.chars().filter(|c| !c.is_control() || (multiline && *c == '\n')).take(max).collect::<String>();
    Fields {
        name: limit(&fields.name, 200, false),
        email: fields.email,
        phone: limit(&fields.phone, 50, false),
        organization: limit(&fields.organization, 200, false),
        notes: limit(&fields.notes, 2000, true),
        uid: limit(&fields.uid, 255, false),
    }
}

fn structured_name(name: &str) -> String {
    // The last word is taken for the family name; good enough to sort by.
    match name.trim().rsplit_once(' ') {
        Some((given, family)) => format!("N:{};{};;;", escape(family), escape(given.trim())),
        None => format!("N:{};;;;", escape(name.trim())),
    }
}

/// The card of a contact as clients receive it.
fn render(card: &Card) -> String {
    let display = if !card.name.is_empty() { card.name.clone() } else if !card.email.is_empty() { card.email.clone() } else { "Unnamed".to_owned() };
    let Some(raw) = card.vcard.as_deref() else {
        let mut out = String::from("BEGIN:VCARD\r\nVERSION:3.0\r\nPRODID:-//unoMail//Contacts//EN\r\n");
        fold(&format!("UID:{}", escape(&card.uid)), &mut out);
        fold(&format!("FN:{}", escape(&display)), &mut out);
        fold(&structured_name(&display), &mut out);
        for (key, value) in [("EMAIL;TYPE=INTERNET", &card.email), ("TEL", &card.phone), ("ORG", &card.organization), ("NOTE", &card.notes)] {
            if !value.is_empty() {
                fold(&format!("{key}:{}", escape(value)), &mut out);
            }
        }
        out.push_str("END:VCARD\r\n");
        return out;
    };
    // Unchanged since the client stored it: byte for byte what it sent.
    let stated = extract(raw);
    let current = Fields { name: card.name.clone(), email: card.email.clone(), phone: card.phone.clone(), organization: card.organization.clone(), notes: card.notes.clone(), uid: stated.uid.clone() };
    if stated == current {
        return raw.to_owned();
    }
    // The web client changed something: rewrite just those properties.
    let mut body = lines(raw);
    let mut rewrite = |property: &str, replacement: Option<String>| {
        let position = body.iter().position(|line| name_of(line) == property);
        match (position, replacement) {
            (Some(index), Some(line)) => body[index] = line,
            (Some(index), None) => {
                body.remove(index);
            }
            (None, Some(line)) => {
                let end = body.iter().rposition(|line| name_of(line) == "END").unwrap_or(body.len());
                body.insert(end, line);
            }
            (None, None) => {}
        }
    };
    if stated.name != current.name {
        rewrite("FN", Some(format!("FN:{}", escape(&display))));
        rewrite("N", Some(structured_name(&display)));
    }
    let optional = |key: &str, value: &str| (!value.is_empty()).then(|| format!("{key}:{}", escape(value)));
    if stated.email != current.email {
        rewrite("EMAIL", optional("EMAIL;TYPE=INTERNET", &current.email));
    }
    if stated.phone != current.phone {
        rewrite("TEL", optional("TEL", &current.phone));
    }
    if stated.organization != current.organization {
        rewrite("ORG", optional("ORG", &current.organization));
    }
    if stated.notes != current.notes {
        rewrite("NOTE", optional("NOTE", &current.notes));
    }
    let mut out = String::new();
    for line in &body {
        fold(line, &mut out);
    }
    out
}

fn etag_of(text: &str) -> String {
    format!("\"{}\"", &sha256_hex(text.as_bytes())[..32])
}

fn valid_name(name: &str) -> bool {
    super::store::valid_object_name(name) && name.to_ascii_lowercase().ends_with(".vcf")
}

// --- Storage ---------------------------------------------------------------------------------

async fn sync_token(state: &AppState, account_id: i64) -> sqlx::Result<i64> {
    Ok(sqlx::query_scalar("SELECT sync_token FROM addressbooks WHERE account_id = ?").bind(account_id).fetch_optional(&state.db).await?.unwrap_or(1))
}

async fn cards(state: &AppState, account_id: i64, after: i64) -> sqlx::Result<Vec<Card>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {COLUMNS} FROM contacts WHERE account_id = ? AND modified > ? ORDER BY id"))).bind(account_id).bind(after).fetch_all(&state.db).await
}

async fn card(state: &AppState, account_id: i64, name: &str) -> sqlx::Result<Option<Card>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {COLUMNS} FROM contacts WHERE account_id = ? AND dav_name = ?"))).bind(account_id).bind(name).fetch_optional(&state.db).await
}

// --- Properties ------------------------------------------------------------------------------

const REPORTS: &str = "<D:supported-report-set><D:supported-report><D:report><CR:addressbook-query/></D:report></D:supported-report>\
<D:supported-report><D:report><CR:addressbook-multiget/></D:report></D:supported-report>\
<D:supported-report><D:report><D:sync-collection/></D:report></D:supported-report></D:supported-report-set>";

enum Target<'a> {
    Home,
    Book(i64),
    Card(&'a Card, String),
}

fn property(name: &str, target: &Target<'_>, hrefs: &Hrefs) -> Option<String> {
    let href = |value: String| format!("<D:href>{}</D:href>", xml_escape(&value));
    Some(match (name, target) {
        ("resourcetype", Target::Home) => "<D:resourcetype><D:collection/></D:resourcetype>".into(),
        ("resourcetype", Target::Book(_)) => "<D:resourcetype><D:collection/><CR:addressbook/></D:resourcetype>".into(),
        ("resourcetype", Target::Card(..)) => "<D:resourcetype/>".into(),
        ("displayname", Target::Home) => "<D:displayname>Address books</D:displayname>".into(),
        ("displayname", Target::Book(_)) => "<D:displayname>Contacts</D:displayname>".into(),
        ("current-user-principal", _) => format!("<D:current-user-principal>{}</D:current-user-principal>", href(hrefs.principal())),
        ("owner", _) => format!("<D:owner>{}</D:owner>", href(hrefs.principal())),
        ("current-user-privilege-set", _) => "<D:current-user-privilege-set><D:privilege><D:all/></D:privilege><D:privilege><D:read/></D:privilege><D:privilege><D:write/></D:privilege>\
<D:privilege><D:write-content/></D:privilege><D:privilege><D:bind/></D:privilege><D:privilege><D:unbind/></D:privilege></D:current-user-privilege-set>"
            .into(),
        ("supported-report-set", Target::Book(_)) => REPORTS.into(),
        ("supported-address-data", Target::Book(_)) => "<CR:supported-address-data><CR:address-data-type content-type=\"text/vcard\" version=\"3.0\"/><CR:address-data-type content-type=\"text/vcard\" version=\"4.0\"/></CR:supported-address-data>".into(),
        ("max-resource-size", Target::Book(_)) => format!("<CR:max-resource-size>{MAX_CARD_BYTES}</CR:max-resource-size>"),
        ("getctag", Target::Book(token)) => format!("<CS:getctag>{token}</CS:getctag>"),
        ("sync-token", Target::Book(token)) => format!("<D:sync-token>{SYNC_PREFIX}{token}</D:sync-token>"),
        ("getetag", Target::Card(_, text)) => format!("<D:getetag>{}</D:getetag>", xml_escape(&etag_of(text))),
        ("getcontenttype", Target::Card(..)) => "<D:getcontenttype>text/vcard; charset=utf-8</D:getcontenttype>".into(),
        ("getcontentlength", Target::Card(_, text)) => format!("<D:getcontentlength>{}</D:getcontentlength>", text.len()),
        ("address-data", Target::Card(_, text)) => format!("<CR:address-data>{}</CR:address-data>", xml_escape(text)),
        _ => return None,
    })
}

fn response_for(target: &Target<'_>, requested: &[String], hrefs: &Hrefs) -> String {
    let defaults: &[&str] = match target {
        Target::Home => &["resourcetype", "displayname", "current-user-principal"],
        Target::Book(_) => &["resourcetype", "displayname", "getctag", "sync-token", "supported-report-set", "supported-address-data", "current-user-privilege-set"],
        Target::Card(..) => &["resourcetype", "getetag", "getcontenttype", "getcontentlength"],
    };
    let names: Vec<String> = if requested.is_empty() { defaults.iter().map(|name| (*name).to_owned()).collect() } else { requested.to_vec() };
    let (mut found, mut missing) = (String::new(), String::new());
    for name in &names {
        match property(name, target, hrefs) {
            Some(xml) => found.push_str(&xml),
            None if !requested.is_empty() && !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') => missing.push_str(&format!("<D:{name}/>")),
            None => {}
        }
    }
    let location = match target {
        Target::Home => hrefs.address_home(),
        Target::Book(_) => hrefs.address_book(),
        Target::Card(card, _) => hrefs.card(&card.dav_name),
    };
    let mut out = format!("<D:response><D:href>{}</D:href>", xml_escape(&location));
    if !found.is_empty() || missing.is_empty() {
        out.push_str(&format!("<D:propstat><D:prop>{found}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>"));
    }
    if !missing.is_empty() {
        out.push_str(&format!("<D:propstat><D:prop>{missing}</D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>"));
    }
    out.push_str("</D:response>");
    out
}

fn card_response(card: &Card, props: &[String], hrefs: &Hrefs) -> String {
    response_for(&Target::Card(card, render(card)), props, hrefs)
}

fn gone(href: &str) -> String {
    format!("<D:response><D:href>{}</D:href><D:status>HTTP/1.1 404 Not Found</D:status></D:response>", xml_escape(href))
}

// --- Methods ---------------------------------------------------------------------------------

async fn report(state: &AppState, account: &Account, hrefs: &Hrefs, query: &Query) -> Result<Response, Response> {
    let mut out = String::new();
    match query.root.as_str() {
        "addressbook-multiget" => {
            for href in &query.hrefs {
                let name = href.rsplit('/').next().and_then(percent_decode).unwrap_or_default();
                match card(state, account.id, &name).await.map_err(internal)? {
                    Some(found) => out.push_str(&card_response(&found, &query.props, hrefs)),
                    None => out.push_str(&gone(href)),
                }
            }
        }
        "addressbook-query" => {
            // Filters are honoured as a plain search: a card matches when it contains any of the
            // texts asked for. (Clients synchronise everything and search on their own side.)
            let wanted: Vec<String> = query.matches.iter().map(|text| text.to_lowercase()).filter(|text| !text.is_empty()).collect();
            for found in cards(state, account.id, -1).await.map_err(internal)? {
                let text = render(&found);
                if wanted.is_empty() || wanted.iter().any(|needle| text.to_lowercase().contains(needle)) {
                    out.push_str(&response_for(&Target::Card(&found, text), &query.props, hrefs));
                }
            }
        }
        "sync-collection" => {
            let current = sync_token(state, account.id).await.map_err(internal)?;
            let token = match query.texts.get("sync-token").map(String::as_str).filter(|t| !t.is_empty()) {
                None => 0,
                Some(text) => match text.strip_prefix(SYNC_PREFIX).and_then(|n| n.parse::<i64>().ok()).filter(|n| (0..=current).contains(n)) {
                    Some(token) => token,
                    None => return Err(precondition(StatusCode::FORBIDDEN, "D:valid-sync-token")),
                },
            };
            for found in cards(state, account.id, token).await.map_err(internal)? {
                out.push_str(&card_response(&found, &query.props, hrefs));
            }
            if token > 0 {
                let removed: Vec<String> = sqlx::query_scalar("SELECT name FROM contact_tombstones WHERE account_id = ? AND modified > ? ORDER BY name").bind(account.id).bind(token).fetch_all(&state.db).await.map_err(internal)?;
                for name in removed {
                    out.push_str(&gone(&hrefs.card(&name)));
                }
            }
            out.push_str(&format!("<D:sync-token>{SYNC_PREFIX}{current}</D:sync-token>"));
        }
        _ => return Err(precondition(StatusCode::FORBIDDEN, "D:supported-report")),
    }
    Ok(multistatus(&out))
}

async fn put(state: &AppState, account: &Account, name: &str, headers: &HeaderMap, text: &str) -> Result<Response, Response> {
    let invalid = || (StatusCode::FORBIDDEN, [(header::CONTENT_TYPE, "application/xml; charset=utf-8")], format!("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:error {NAMESPACES}><CR:valid-address-data/></D:error>")).into_response();
    if !valid_name(name) || text.len() > MAX_CARD_BYTES {
        return Err(invalid());
    }
    let body = lines(text);
    let begins = body.iter().filter(|line| name_of(line) == "BEGIN").count();
    if begins != 1 || !body.first().is_some_and(|line| line.trim().eq_ignore_ascii_case("BEGIN:VCARD")) || !body.last().is_some_and(|line| line.trim().eq_ignore_ascii_case("END:VCARD")) {
        return Err(invalid());
    }
    let existing = card(state, account.id, name).await.map_err(internal)?;
    let etag = existing.as_ref().map(|found| etag_of(&render(found)));
    if matches_etag(headers.get(header::IF_MATCH), etag.as_deref()) == Some(false) || matches_etag(headers.get(header::IF_NONE_MATCH), etag.as_deref()) == Some(true) {
        return Err(status(StatusCode::PRECONDITION_FAILED));
    }
    let fields = extract(text);
    let now = crate::util::now();
    match &existing {
        Some(found) => {
            sqlx::query("UPDATE contacts SET name = ?, email = ?, phone = ?, organization = ?, notes = ?, vcard = ?, uid = CASE WHEN ? = '' THEN uid ELSE ? END, updated_at = ? WHERE id = ?")
                .bind(&fields.name)
                .bind(&fields.email)
                .bind(&fields.phone)
                .bind(&fields.organization)
                .bind(&fields.notes)
                .bind(text)
                .bind(&fields.uid)
                .bind(&fields.uid)
                .bind(now)
                .bind(found.id)
                .execute(&state.db)
                .await
                .map_err(internal)?;
        }
        None => {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contacts WHERE account_id = ?").bind(account.id).fetch_one(&state.db).await.map_err(internal)?;
            if count >= MAX_CONTACTS {
                return Err(status(StatusCode::INSUFFICIENT_STORAGE));
            }
            sqlx::query("INSERT INTO contacts (account_id, name, email, phone, organization, notes, uid, dav_name, vcard, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(account.id)
                .bind(&fields.name)
                .bind(&fields.email)
                .bind(&fields.phone)
                .bind(&fields.organization)
                .bind(&fields.notes)
                .bind(&fields.uid)
                .bind(name)
                .bind(text)
                .bind(now)
                .bind(now)
                .execute(&state.db)
                .await
                .map_err(internal)?;
        }
    }
    let stored = card(state, account.id, name).await.map_err(internal)?.ok_or_else(|| status(StatusCode::INTERNAL_SERVER_ERROR))?;
    let etag = HeaderValue::from_str(&etag_of(&render(&stored))).unwrap_or(HeaderValue::from_static("\"\""));
    Ok((if existing.is_none() { StatusCode::CREATED } else { StatusCode::NO_CONTENT }, [(header::ETAG, etag)]).into_response())
}

/// Serves everything below `/dav/addressbooks/<address>/`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle(state: &AppState, account: &Account, hrefs: &Hrefs, method: &str, resource: Resource, headers: &HeaderMap, depth: &str, text: &str) -> Result<Response, Response> {
    let query = || if text.trim().is_empty() { Ok(Query::default()) } else { parse_query(text).ok_or_else(|| status(StatusCode::BAD_REQUEST)) };
    match (method, resource) {
        ("PROPFIND", Resource::AddressHome) => {
            let query = query()?;
            let mut out = response_for(&Target::Home, &query.props, hrefs);
            if depth != "0" {
                out.push_str(&response_for(&Target::Book(sync_token(state, account.id).await.map_err(internal)?), &query.props, hrefs));
            }
            Ok(multistatus(&out))
        }
        ("PROPFIND", Resource::AddressBook) => {
            let query = query()?;
            let mut out = response_for(&Target::Book(sync_token(state, account.id).await.map_err(internal)?), &query.props, hrefs);
            if depth != "0" {
                for found in cards(state, account.id, -1).await.map_err(internal)? {
                    out.push_str(&card_response(&found, &query.props, hrefs));
                }
            }
            Ok(multistatus(&out))
        }
        ("PROPFIND", Resource::Card(name)) => {
            let found = card(state, account.id, &name).await.map_err(internal)?.ok_or_else(|| status(StatusCode::NOT_FOUND))?;
            Ok(multistatus(&card_response(&found, &query()?.props, hrefs)))
        }
        ("REPORT", Resource::AddressBook) => report(state, account, hrefs, &query()?).await,
        ("GET" | "HEAD", Resource::Card(name)) => {
            let found = card(state, account.id, &name).await.map_err(internal)?.ok_or_else(|| status(StatusCode::NOT_FOUND))?;
            let text = render(&found);
            let etag = HeaderValue::from_str(&etag_of(&text)).unwrap_or(HeaderValue::from_static("\"\""));
            let body = if method == "HEAD" { Body::empty() } else { Body::from(text) };
            Ok((StatusCode::OK, [(header::CONTENT_TYPE, HeaderValue::from_static("text/vcard; charset=utf-8")), (header::ETAG, etag)], body).into_response())
        }
        ("PUT", Resource::Card(name)) => put(state, account, &name, headers, text).await,
        ("DELETE", Resource::Card(name)) => {
            let found = card(state, account.id, &name).await.map_err(internal)?.ok_or_else(|| status(StatusCode::NOT_FOUND))?;
            if matches_etag(headers.get(header::IF_MATCH), Some(&etag_of(&render(&found)))) == Some(false) {
                return Err(status(StatusCode::PRECONDITION_FAILED));
            }
            sqlx::query("DELETE FROM contacts WHERE id = ?").bind(found.id).execute(&state.db).await.map_err(internal)?;
            Ok(status(StatusCode::NO_CONTENT))
        }
        _ => Err(status(StatusCode::METHOD_NOT_ALLOWED)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHONE: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:urn:uuid:1234\r\nFN:Anna Kowalska\r\nN:Kowalska;Anna;;;\r\nitem1.EMAIL;TYPE=work,pref:Anna@Partner.Example\r\nEMAIL;TYPE=home:anna@home.example\r\n\
TEL;TYPE=cell:+48 600 100 200\r\nORG:Partner Sp. z o.o.;Sales\r\nADR;TYPE=work:;;ul. Długa 1;Kraków;;31-000;Poland\r\nPHOTO;ENCODING=b;TYPE=JPEG:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n AAAAAAAA\r\nBDAY:19800101\r\nEND:VCARD\r\n";

    fn stored(raw: &str) -> Card {
        let fields = extract(raw);
        Card { id: 1, name: fields.name, email: fields.email, phone: fields.phone, organization: fields.organization, notes: fields.notes, uid: fields.uid, dav_name: "a.vcf".into(), vcard: Some(raw.to_owned()) }
    }

    #[test]
    fn cards_from_clients_are_read_and_returned_unchanged() {
        let fields = extract(PHONE);
        assert_eq!(fields, Fields { name: "Anna Kowalska".into(), email: "anna@partner.example".into(), phone: "+48 600 100 200".into(), organization: "Partner Sp. z o.o. Sales".into(), notes: String::new(), uid: "urn:uuid:1234".into() });
        assert_eq!(render(&stored(PHONE)), PHONE, "byte for byte");
        // No formatted name: built from the structured one. No usable address: none.
        let bare = extract("BEGIN:VCARD\nVERSION:3.0\nN:Nowak;Jan;;dr;\nEMAIL:not an address\nTEL:123\nEND:VCARD\n");
        assert_eq!((bare.name.as_str(), bare.email.as_str(), bare.phone.as_str()), ("dr Jan Nowak", "", "123"));
        assert_eq!(render(&stored("BEGIN:VCARD\nVERSION:3.0\nN:Nowak;Jan;;dr;\nEMAIL:not an address\nTEL:123\nEND:VCARD\n")), "BEGIN:VCARD\nVERSION:3.0\nN:Nowak;Jan;;dr;\nEMAIL:not an address\nTEL:123\nEND:VCARD\n");
    }

    #[test]
    fn edits_in_the_web_client_touch_only_what_changed() {
        let mut card = stored(PHONE);
        card.phone = "+48 600 999 999".into();
        card.notes = "Met in Kraków; likes tea".into();
        let text = render(&card);
        assert!(text.contains("TEL:+48 600 999 999\r\n") && text.contains("NOTE:Met in Kraków\\; likes tea\r\n"), "{text}");
        for kept in ["item1.EMAIL;TYPE=work,pref:Anna@Partner.Example\r\n", "EMAIL;TYPE=home:anna@home.example\r\n", "N:Kowalska;Anna;;;\r\n", "ADR;TYPE=work:", "BDAY:19800101\r\n", "PHOTO;ENCODING=b;TYPE=JPEG:", "UID:urn:uuid:1234\r\n", "VERSION:4.0\r\n"] {
            assert!(text.contains(kept), "{kept} in {text}");
        }
        assert!(text.ends_with("END:VCARD\r\n") && text.lines().all(|line| line.len() <= 75));
        assert_eq!(extract(&text).phone, "+48 600 999 999", "what is served says what the address book says");

        // A new name replaces both name properties; an emptied field loses its property.
        card.name = "Anna Nowak".into();
        card.organization = String::new();
        let text = render(&card);
        assert!(text.contains("FN:Anna Nowak\r\n") && text.contains("N:Nowak;Anna;;;\r\n") && !text.contains("ORG:") && !text.contains("Kowalska"), "{text}");
    }

    #[test]
    fn contacts_made_in_the_web_client_become_cards() {
        let card = Card { id: 7, name: "Jan Maria Nowak".into(), email: "jan@example.org".into(), phone: String::new(), organization: "ACME, Inc.".into(), notes: "line one\nline two".into(), uid: "abc".into(), dav_name: "abc.vcf".into(), vcard: None };
        let text = render(&card);
        assert_eq!(text, "BEGIN:VCARD\r\nVERSION:3.0\r\nPRODID:-//unoMail//Contacts//EN\r\nUID:abc\r\nFN:Jan Maria Nowak\r\nN:Nowak;Jan Maria;;;\r\nEMAIL;TYPE=INTERNET:jan@example.org\r\nORG:ACME\\, Inc.\r\nNOTE:line one\\nline two\r\nEND:VCARD\r\n");
        let back = extract(&text);
        assert_eq!((back.name.as_str(), back.email.as_str(), back.organization.as_str(), back.notes.as_str(), back.uid.as_str()), ("Jan Maria Nowak", "jan@example.org", "ACME, Inc.", "line one\nline two", "abc"));
        let nameless = render(&Card { email: "x@example.org".into(), uid: "u".into(), ..Default::default() });
        assert!(nameless.contains("FN:x@example.org\r\n"));
        assert!(valid_name("abc.vcf") && valid_name("A-1_b.VCF") && !valid_name("abc.ics") && !valid_name("../x.vcf") && !valid_name(".vcf"));
    }
}
