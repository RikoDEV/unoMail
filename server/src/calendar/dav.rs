//! CalDAV (RFC 4791) and CardDAV (RFC 6352, in [`super::carddav`]) over WebDAV (RFC 4918),
//! with collection synchronisation (RFC 6578).
//!
//! Layout, all below `/dav`:
//!
//! ```text
//! /dav/principals/<address>/              the user
//! /dav/calendars/<address>/               the user's calendar home
//! /dav/calendars/<address>/<calendar>/    one calendar
//! /dav/calendars/<address>/<calendar>/<name>.ics
//! /dav/addressbooks/<address>/            the user's address book home
//! /dav/addressbooks/<address>/contacts/   the address book
//! /dav/addressbooks/<address>/contacts/<name>.vcf
//! ```
//!
//! Calendars shared by colleagues appear in the user's own calendar home, as `shared-<id>`.
//!
//! Clients authenticate with HTTP Basic over TLS. Every request is confined to the
//! authenticated user's own tree.

// Handlers short-circuit with the finished error response; boxing it would buy nothing here.
#![allow(clippy::result_large_err)]

use std::{
    collections::HashMap,
    sync::LazyLock,
    time::Duration,
};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};

use super::{
    carddav, ical,
    store::{self, Access, Calendar, CalendarError, Object},
};
use crate::{
    api::PeerAddr,
    app::AppState,
    auth::{self, Account, AuthError, Protocol},
    expiring::Expiring,
    util::sha256_hex,
};

const MAX_BODY: usize = 2 * 1024 * 1024;
const AUTH_CACHE_TTL: Duration = Duration::from_secs(300);
pub(super) const SYNC_PREFIX: &str = "urn:unomail:sync:";
pub(super) const NAMESPACES: &str = r#"xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:CR="urn:ietf:params:xml:ns:carddav" xmlns:CS="http://calendarserver.org/ns/" xmlns:A="http://apple.com/ns/ical/""#;

// --- Authentication ------------------------------------------------------------------------

/// Verified credentials, so that the (deliberately slow) password hash is not recomputed for
/// every request of a synchronising client. Keyed by a hash of address and password; an entry
/// is only honoured while the credential is still what it was: the same password hash (and
/// still no second factor), or the same app password not revoked since.
static VERIFIED: LazyLock<Expiring<Verified>> = LazyLock::new(|| Expiring::new(AUTH_CACHE_TTL, 10_000));

/// Account id, and the password hash or app password that was verified.
type Verified = (i64, String);

async fn still_valid(state: &AppState, account: &Account, credential: &str) -> bool {
    match credential.strip_prefix("app:").and_then(|id| id.parse::<i64>().ok()) {
        Some(id) => sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM app_passwords WHERE id = ? AND account_id = ?").bind(id).bind(account.id).fetch_one(&state.db).await.is_ok_and(|n| n == 1),
        None => account.password_hash == credential && crate::twofactor::factors(&state.db, account.id).await.is_ok_and(|f| !f.enabled()),
    }
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Basic realm=\"unoMail\", charset=\"UTF-8\"")], "authentication required").into_response()
}

async fn authenticate(state: &AppState, headers: &HeaderMap, ip: std::net::IpAddr) -> Result<Account, Response> {
    let credentials = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic ").or_else(|| v.strip_prefix("basic ")))
        .and_then(|b64| STANDARD.decode(b64.trim()).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|pair| pair.split_once(':').map(|(user, password)| (user.trim().to_lowercase(), password.to_owned())));
    let Some((user, password)) = credentials else { return Err(unauthorized()) };
    let key = sha256_hex(format!("{user}\0{password}").as_bytes());
    let cached = VERIFIED.get(&key);
    if let Some((id, credential)) = cached
        && let Ok(Some(account)) = Account::in_enabled_domain(&state.db, id).await
        && account.enabled
        && Protocol::Dav.allowed_for(&account)
        && still_valid(state, &account, &credential).await
    {
        return Ok(account);
    }
    match auth::authenticate_with(&state.db, &state.limiter, &user, &password, ip, Protocol::Dav).await {
        Ok((account, credential)) => {
            let fingerprint = match credential {
                auth::Credential::Password => account.password_hash.clone(),
                auth::Credential::AppPassword(id) => format!("app:{id}"),
            };
            // A stale entry for the same credentials is replaced.
            VERIFIED.remove(&key);
            VERIFIED.insert(key, (account.id, fingerprint));
            Ok(account)
        }
        Err(AuthError::RateLimited) => Err((StatusCode::TOO_MANY_REQUESTS, "too many failed attempts").into_response()),
        Err(_) => Err(unauthorized()),
    }
}

// --- Paths ---------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Resource {
    Root,
    Principal,
    Home,
    Calendar(String),
    Item(String, String),
    AddressHome,
    AddressBook,
    Card(String),
}

pub(super) fn percent_decode(segment: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(segment.len());
    let mut input = segment.bytes();
    while let Some(b) = input.next() {
        if b == b'%' {
            let hex = [input.next()?, input.next()?];
            bytes.push(u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?);
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8(bytes).ok()
}

pub(super) fn percent_encode(segment: &str) -> String {
    segment.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~@+=".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// Resolves a request path to a resource of `account`. `Err(true)` means the path belongs to
/// somebody else, `Err(false)` that it does not exist.
fn resolve(path: &str, account: &Account) -> Result<Resource, bool> {
    let rest = path.strip_prefix("/dav").ok_or(false)?;
    let segments: Vec<String> = rest.split('/').filter(|s| !s.is_empty()).map(percent_decode).collect::<Option<_>>().ok_or(false)?;
    let own = |address: &str| if address.to_lowercase() == account.email { Ok(()) } else { Err(true) };
    match segments.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        [] => Ok(Resource::Root),
        ["principals"] | ["calendars"] | ["addressbooks"] => Ok(Resource::Root),
        ["addressbooks", address] => own(address).map(|()| Resource::AddressHome),
        ["addressbooks", address, "contacts"] => own(address).map(|()| Resource::AddressBook),
        ["addressbooks", address, "contacts", card] => own(address).map(|()| Resource::Card((*card).to_owned())),
        ["principals", address] => own(address).map(|()| Resource::Principal),
        ["calendars", address] => own(address).map(|()| Resource::Home),
        ["calendars", address, calendar] => own(address).map(|()| Resource::Calendar((*calendar).to_owned())),
        ["calendars", address, calendar, item] => own(address).map(|()| Resource::Item((*calendar).to_owned(), (*item).to_owned())),
        _ => Err(false),
    }
}

pub(super) struct Hrefs {
    address: String,
}

impl Hrefs {
    pub(super) fn principal(&self) -> String {
        format!("/dav/principals/{}/", self.address)
    }
    pub(super) fn address_home(&self) -> String {
        format!("/dav/addressbooks/{}/", self.address)
    }
    pub(super) fn address_book(&self) -> String {
        format!("{}contacts/", self.address_home())
    }
    pub(super) fn card(&self, name: &str) -> String {
        format!("{}{}", self.address_book(), percent_encode(name))
    }
    fn home(&self) -> String {
        format!("/dav/calendars/{}/", self.address)
    }
    fn calendar(&self, slug: &str) -> String {
        format!("{}{}/", self.home(), percent_encode(slug))
    }
    fn item(&self, slug: &str, name: &str) -> String {
        format!("{}{}", self.calendar(slug), percent_encode(name))
    }
}

// --- A minimal XML reader ------------------------------------------------------------------

/// Escapes text for use in XML content and attribute values.
pub fn xml_escape(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .map(|c| match c {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            other => other.to_string(),
        })
        .collect()
}

fn xml_unescape(text: &str) -> String {
    text.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&#13;", "\r").replace("&#10;", "\n").replace("&amp;", "&")
}

#[derive(Debug, PartialEq, Eq)]
enum Token {
    Open { name: String, attributes: Vec<(String, String)>, empty: bool },
    Close(String),
    Text(String),
}

/// Local part of a possibly prefixed XML name.
fn local(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_owned()
}

/// Splits a small XML document into tags and text. Namespace prefixes are dropped (the
/// element names used by CalDAV are unambiguous without them). Document type declarations
/// are skipped, never interpreted: there is no entity expansion to attack.
fn tokens(xml: &str) -> Option<Vec<Token>> {
    let mut out = Vec::new();
    let mut rest = xml;
    while !rest.is_empty() {
        let Some(open) = rest.find('<') else {
            break;
        };
        let text = &rest[..open];
        if !text.trim().is_empty() {
            out.push(Token::Text(xml_unescape(text)));
        }
        rest = &rest[open..];
        if let Some(after) = rest.strip_prefix("<!--") {
            rest = &after[after.find("-->")? + 3..];
        } else if let Some(after) = rest.strip_prefix("<![CDATA[") {
            let end = after.find("]]>")?;
            out.push(Token::Text(after[..end].to_owned()));
            rest = &after[end + 3..];
        } else if rest.starts_with("<?") || rest.starts_with("<!") {
            rest = &rest[rest.find('>')? + 1..];
        } else {
            let end = rest.find('>')?;
            let tag = &rest[1..end];
            rest = &rest[end + 1..];
            if let Some(name) = tag.strip_prefix('/') {
                out.push(Token::Close(local(name.trim())));
                continue;
            }
            let empty = tag.ends_with('/');
            let tag = tag.trim_end_matches('/');
            let (name, mut attribute_text) = tag.split_once(char::is_whitespace).unwrap_or((tag, ""));
            let mut attributes = Vec::new();
            while let Some((key, after)) = attribute_text.split_once('=') {
                let after = after.trim_start();
                let quote = after.chars().next().filter(|c| *c == '"' || *c == '\'')?;
                let close = after[1..].find(quote)?;
                attributes.push((local(key.trim()), xml_unescape(&after[1..=close])));
                attribute_text = &after[close + 2..];
            }
            out.push(Token::Open { name: local(name), attributes, empty });
        }
        if out.len() > 20_000 {
            return None;
        }
    }
    Some(out)
}

/// The parts of a request body the server acts on.
#[derive(Debug, Default)]
pub(super) struct Query {
    /// Name of the document element, e.g. `propfind` or `calendar-query`.
    pub(super) root: String,
    /// Names of the properties asked for (children of a `prop` element).
    pub(super) props: Vec<String>,
    pub(super) hrefs: Vec<String>,
    /// Text content of simple elements, by name (`displayname`, `sync-token`, ...).
    pub(super) texts: HashMap<String, String>,
    /// The texts of all `text-match` filters (CardDAV searches).
    pub(super) matches: Vec<String>,
    /// `start` and `end` of a `time-range` filter.
    time_range: Option<(Option<String>, Option<String>)>,
    /// Component named by the innermost `comp-filter`.
    component: Option<String>,
    /// Children of a `resourcetype` (extended MKCOL, RFC 5689).
    pub(super) resource_types: Vec<String>,
}

pub(super) fn parse_query(body: &str) -> Option<Query> {
    let mut query = Query::default();
    let mut stack: Vec<String> = Vec::new();
    for token in tokens(body)? {
        match token {
            Token::Open { name, attributes, empty } => {
                if stack.is_empty() {
                    query.root = name.clone();
                }
                // Only direct children of <prop> are property names; calendar-data may carry
                // sub-elements (<comp>, <expand>) that are not.
                if stack.last().is_some_and(|parent| parent == "prop") && !query.props.contains(&name) {
                    query.props.push(name.clone());
                }
                if stack.last().is_some_and(|parent| parent == "resourcetype") {
                    query.resource_types.push(name.clone());
                }
                let attribute = |key: &str| attributes.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
                match name.as_str() {
                    "time-range" => query.time_range = Some((attribute("start"), attribute("end"))),
                    "comp-filter" => {
                        if let Some(component) = attribute("name").filter(|n| n != "VCALENDAR") {
                            query.component = Some(component.to_ascii_uppercase());
                        }
                    }
                    _ => {}
                }
                if !empty {
                    stack.push(name);
                }
            }
            Token::Close(_) => {
                stack.pop();
            }
            Token::Text(text) => {
                if let Some(element) = stack.last() {
                    if element == "href" {
                        query.hrefs.push(text.trim().to_owned());
                    } else if element == "text-match" {
                        query.matches.push(text.trim().to_owned());
                    } else {
                        query.texts.insert(element.clone(), text.trim().to_owned());
                    }
                }
            }
        }
    }
    Some(query)
}

// --- Properties ----------------------------------------------------------------------------

enum Target<'a> {
    Root,
    Principal,
    Home,
    Calendar(&'a Access),
    Item(&'a Access, &'a Object),
}

const REPORTS: &str = "<D:supported-report><D:report><C:calendar-query/></D:report></D:supported-report>\
<D:supported-report><D:report><C:calendar-multiget/></D:report></D:supported-report>\
<D:supported-report><D:report><D:sync-collection/></D:report></D:supported-report>\
<D:supported-report><D:report><C:free-busy-query/></D:report></D:supported-report>";

const READ_ONLY: &str = "<D:current-user-privilege-set><D:privilege><D:read/></D:privilege><D:privilege><D:read-current-user-privilege-set/></D:privilege></D:current-user-privilege-set>";

/// Renders one property of a resource, or `None` when the resource does not have it.
fn property(name: &str, target: &Target<'_>, account: &Account, hrefs: &Hrefs) -> Option<String> {
    let href = |value: String| format!("<D:href>{}</D:href>", xml_escape(&value));
    Some(match (name, target) {
        ("resourcetype", Target::Principal) => "<D:resourcetype><D:principal/></D:resourcetype>".into(),
        ("resourcetype", Target::Root | Target::Home) => "<D:resourcetype><D:collection/></D:resourcetype>".into(),
        ("resourcetype", Target::Calendar(_)) => "<D:resourcetype><D:collection/><C:calendar/></D:resourcetype>".into(),
        ("resourcetype", Target::Item(..)) => "<D:resourcetype/>".into(),
        ("displayname", Target::Principal) => format!("<D:displayname>{}</D:displayname>", xml_escape(if account.display_name.is_empty() { &account.email } else { &account.display_name })),
        ("displayname", Target::Home) => "<D:displayname>Calendars</D:displayname>".into(),
        ("displayname", Target::Calendar(access)) => format!("<D:displayname>{}</D:displayname>", xml_escape(&access.title())),
        ("addressbook-home-set", Target::Principal) => format!("<CR:addressbook-home-set>{}</CR:addressbook-home-set>", href(hrefs.address_home())),
        // What is shared for reading only says so, and clients grey out their editing.
        ("current-user-privilege-set", Target::Calendar(access) | Target::Item(access, _)) if !access.writable => READ_ONLY.into(),
        ("current-user-principal", _) => format!("<D:current-user-principal>{}</D:current-user-principal>", href(hrefs.principal())),
        ("principal-URL", _) => format!("<D:principal-URL>{}</D:principal-URL>", href(hrefs.principal())),
        ("owner", Target::Home | Target::Calendar(_) | Target::Item(..)) => format!("<D:owner>{}</D:owner>", href(hrefs.principal())),
        ("current-user-privilege-set", _) => "<D:current-user-privilege-set><D:privilege><D:all/></D:privilege><D:privilege><D:read/></D:privilege><D:privilege><D:write/></D:privilege>\
<D:privilege><D:write-content/></D:privilege><D:privilege><D:bind/></D:privilege><D:privilege><D:unbind/></D:privilege></D:current-user-privilege-set>"
            .into(),
        ("calendar-home-set", Target::Principal) => format!("<C:calendar-home-set>{}</C:calendar-home-set>", href(hrefs.home())),
        ("calendar-user-address-set", Target::Principal) => format!("<C:calendar-user-address-set>{}</C:calendar-user-address-set>", href(format!("mailto:{}", account.email))),
        ("supported-report-set", Target::Calendar(_) | Target::Home) => format!("<D:supported-report-set>{REPORTS}</D:supported-report-set>"),
        ("supported-calendar-component-set", Target::Calendar(_)) => "<C:supported-calendar-component-set><C:comp name=\"VEVENT\"/><C:comp name=\"VTODO\"/></C:supported-calendar-component-set>".into(),
        ("calendar-description", Target::Calendar(access)) => format!("<C:calendar-description>{}</C:calendar-description>", xml_escape(&access.calendar.description)),
        ("calendar-color", Target::Calendar(access)) if !access.calendar.color.is_empty() => format!("<A:calendar-color>{}</A:calendar-color>", xml_escape(&access.calendar.color)),
        ("getctag", Target::Calendar(access)) => format!("<CS:getctag>{}</CS:getctag>", access.calendar.sync_token),
        ("sync-token", Target::Calendar(access)) => format!("<D:sync-token>{SYNC_PREFIX}{}</D:sync-token>", access.calendar.sync_token),
        // RFC 4331: the account's storage, which calendars share with mail.
        ("quota-used-bytes", Target::Home | Target::Calendar(_)) => format!("<D:quota-used-bytes>{}</D:quota-used-bytes>", account.used_bytes.max(0)),
        ("quota-available-bytes", Target::Home | Target::Calendar(_)) if account.quota_bytes > 0 => format!("<D:quota-available-bytes>{}</D:quota-available-bytes>", (account.quota_bytes - account.used_bytes).max(0)),
        ("max-resource-size", Target::Calendar(_)) => format!("<C:max-resource-size>{}</C:max-resource-size>", ical::MAX_OBJECT_BYTES),
        ("getetag", Target::Item(_, object)) => format!("<D:getetag>{}</D:getetag>", xml_escape(&object.etag)),
        ("getcontenttype", Target::Item(_, object)) => format!("<D:getcontenttype>text/calendar; charset=utf-8; component={}</D:getcontenttype>", object.component.to_ascii_lowercase()),
        ("getcontentlength", Target::Item(_, object)) => format!("<D:getcontentlength>{}</D:getcontentlength>", object.data.len()),
        ("calendar-data", Target::Item(_, object)) => format!("<C:calendar-data>{}</C:calendar-data>", xml_escape(&object.data)),
        _ => return None,
    })
}

/// The properties returned when a client asks for "all" of them.
fn default_props(target: &Target<'_>) -> Vec<String> {
    let names: &[&str] = match target {
        Target::Root => &["resourcetype", "current-user-principal"],
        Target::Principal => &["resourcetype", "displayname", "current-user-principal", "principal-URL", "calendar-home-set", "calendar-user-address-set", "addressbook-home-set"],
        Target::Home => &["resourcetype", "displayname", "current-user-principal", "owner"],
        Target::Calendar(_) => &["resourcetype", "displayname", "calendar-description", "calendar-color", "supported-calendar-component-set", "getctag", "sync-token", "owner", "current-user-privilege-set", "supported-report-set"],
        Target::Item(..) => &["resourcetype", "getetag", "getcontenttype", "getcontentlength"],
    };
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn href_of(target: &Target<'_>, hrefs: &Hrefs) -> String {
    match target {
        Target::Root => "/dav/".into(),
        Target::Principal => hrefs.principal(),
        Target::Home => hrefs.home(),
        Target::Calendar(access) => hrefs.calendar(&access.slug()),
        Target::Item(access, object) => hrefs.item(&access.slug(), &object.name),
    }
}

/// One `<D:response>` describing a resource: the properties found, and those asked for that
/// it does not have.
fn response_for(target: &Target<'_>, requested: &[String], account: &Account, hrefs: &Hrefs) -> String {
    let names = if requested.is_empty() { default_props(target) } else { requested.to_vec() };
    let (mut found, mut missing) = (String::new(), String::new());
    for name in &names {
        match property(name, target, account, hrefs) {
            Some(xml) => found.push_str(&xml),
            // Echo the name only if it is a plain XML name; anything else is simply skipped.
            None if !requested.is_empty() && !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') => missing.push_str(&format!("<D:{name}/>")),
            None => {}
        }
    }
    let mut out = format!("<D:response><D:href>{}</D:href>", xml_escape(&href_of(target, hrefs)));
    if !found.is_empty() || missing.is_empty() {
        out.push_str(&format!("<D:propstat><D:prop>{found}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>"));
    }
    if !missing.is_empty() {
        out.push_str(&format!("<D:propstat><D:prop>{missing}</D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>"));
    }
    out.push_str("</D:response>");
    out
}

pub(super) fn multistatus(inner: &str) -> Response {
    let body = format!("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus {NAMESPACES}>{inner}</D:multistatus>");
    (StatusCode::MULTI_STATUS, [(header::CONTENT_TYPE, "application/xml; charset=utf-8")], body).into_response()
}

pub(super) fn precondition(status: StatusCode, element: &str) -> Response {
    let body = format!("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:error {NAMESPACES}><{element}/></D:error>");
    (status, [(header::CONTENT_TYPE, "application/xml; charset=utf-8")], body).into_response()
}

pub(super) fn status(code: StatusCode) -> Response {
    code.into_response()
}

fn store_error(err: CalendarError) -> Response {
    match err {
        CalendarError::Invalid(message) => (StatusCode::FORBIDDEN, [(header::CONTENT_TYPE, "application/xml; charset=utf-8")], format!("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:error {NAMESPACES}><C:valid-calendar-data/><D:responsedescription>{}</D:responsedescription></D:error>", xml_escape(&message))).into_response(),
        CalendarError::UidConflict => precondition(StatusCode::CONFLICT, "C:no-uid-conflict"),
        CalendarError::Exists => status(StatusCode::METHOD_NOT_ALLOWED),
        CalendarError::Limit => status(StatusCode::INSUFFICIENT_STORAGE),
        CalendarError::Db(err) => {
            tracing::error!(%err, "calendar storage failed");
            status(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub(super) fn internal(err: sqlx::Error) -> Response {
    tracing::error!(%err, "calendar storage failed");
    status(StatusCode::INTERNAL_SERVER_ERROR)
}

// --- Methods -------------------------------------------------------------------------------

/// The whole calendar as one iCalendar stream (for export and read-only subscriptions).
pub fn export(calendar: &Calendar, objects: &[Object]) -> String {
    let mut merged = ical::Component {
        name: "VCALENDAR".into(),
        props: vec![
            ical::Property::new("VERSION", "2.0"),
            ical::Property::new("PRODID", "-//unoMail//Calendar//EN"),
            ical::Property::new("X-WR-CALNAME", ical::escape_text(&calendar.name)),
        ],
        children: Vec::new(),
    };
    let mut zones: Vec<String> = Vec::new();
    for object in objects {
        let Ok(parsed) = ical::parse(&object.data) else { continue };
        for child in parsed.children {
            // Time zone definitions are shared by many events: include each once.
            if child.name == "VTIMEZONE" {
                let id = child.value("TZID").unwrap_or("").to_owned();
                if zones.contains(&id) {
                    continue;
                }
                zones.push(id);
            }
            merged.children.push(child);
        }
    }
    merged.serialize()
}

async fn propfind(state: &AppState, account: &Account, hrefs: &Hrefs, resource: Resource, depth: &str, query: &Query) -> Result<Response, Response> {
    let props = &query.props;
    let children = depth != "0";
    let mut out = String::new();
    match resource {
        Resource::Root => out.push_str(&response_for(&Target::Root, props, account, hrefs)),
        Resource::Principal => out.push_str(&response_for(&Target::Principal, props, account, hrefs)),
        Resource::Home => {
            out.push_str(&response_for(&Target::Home, props, account, hrefs));
            if children {
                for access in store::accessible(&state.db, account).await.map_err(internal)? {
                    out.push_str(&response_for(&Target::Calendar(&access), props, account, hrefs));
                }
            }
        }
        Resource::Calendar(slug) => {
            let access = store::access_by_slug(&state.db, account, &slug).await.map_err(internal)?.ok_or_else(|| status(StatusCode::NOT_FOUND))?;
            out.push_str(&response_for(&Target::Calendar(&access), props, account, hrefs));
            if children {
                for object in store::objects(&state.db, access.calendar.id).await.map_err(internal)? {
                    out.push_str(&response_for(&Target::Item(&access, &object), props, account, hrefs));
                }
            }
        }
        Resource::Item(slug, name) => {
            let access = store::access_by_slug(&state.db, account, &slug).await.map_err(internal)?.ok_or_else(|| status(StatusCode::NOT_FOUND))?;
            let object = store::object(&state.db, access.calendar.id, &name).await.map_err(internal)?.ok_or_else(|| status(StatusCode::NOT_FOUND))?;
            out.push_str(&response_for(&Target::Item(&access, &object), props, account, hrefs));
        }
        Resource::AddressHome | Resource::AddressBook | Resource::Card(_) => unreachable!("address books are served by the CardDAV module"),
    }
    Ok(multistatus(&out))
}

/// The busy times of a calendar as a `VFREEBUSY` component (RFC 4791, section 7.10).
async fn free_busy(state: &AppState, calendar: &Calendar, from: i64, to: i64, zone: chrono_tz::Tz) -> Result<Response, Response> {
    let stamp = |at: i64| chrono::DateTime::from_timestamp(at, 0).map(|t| t.format("%Y%m%dT%H%M%SZ").to_string()).unwrap_or_default();
    let busy = store::busy(&state.db, std::slice::from_ref(calendar), from, to, zone).await.map_err(internal)?;
    let mut props = vec![ical::Property::new("DTSTAMP", stamp(crate::util::now())), ical::Property::new("DTSTART", stamp(from)), ical::Property::new("DTEND", stamp(to))];
    props.extend(busy.iter().map(|(start, end)| ical::Property { name: "FREEBUSY".into(), params: vec![("FBTYPE".into(), "BUSY".into())], value: format!("{}/{}", stamp(*start), stamp(*end)) }));
    let body = ical::Component {
        name: "VCALENDAR".into(),
        props: vec![ical::Property::new("VERSION", "2.0"), ical::Property::new("PRODID", "-//unoMail//Calendar//EN")],
        children: vec![ical::Component { name: "VFREEBUSY".into(), props, children: Vec::new() }],
    };
    Ok((StatusCode::OK, [(header::CONTENT_TYPE, "text/calendar; charset=utf-8")], body.serialize()).into_response())
}

async fn report(state: &AppState, account: &Account, hrefs: &Hrefs, calendar: &Access, query: &Query) -> Result<Response, Response> {
    let mut out = String::new();
    let zone = store::zone_of(&state.db, account.id).await;
    let (access, calendar) = (calendar, &calendar.calendar);
    let bound = |value: &Option<String>, fallback: i64| value.as_deref().and_then(|v| ical::moment(&ical::Property::new("DTSTART", v))).map_or(fallback, |m| m.at);
    match query.root.as_str() {
        "free-busy-query" => {
            let Some((Some(start), Some(end))) = &query.time_range else { return Err(status(StatusCode::BAD_REQUEST)) };
            let (from, to) = (bound(&Some(start.clone()), 0), bound(&Some(end.clone()), 0));
            if to <= from || to - from > 366 * 86400 {
                return Err(status(StatusCode::BAD_REQUEST));
            }
            return free_busy(state, calendar, from, to, zone).await;
        }
        "calendar-multiget" => {
            for href in &query.hrefs {
                let name = href.rsplit('/').next().and_then(percent_decode).unwrap_or_default();
                match store::object(&state.db, calendar.id, &name).await.map_err(internal)? {
                    Some(object) => out.push_str(&response_for(&Target::Item(access, &object), &query.props, account, hrefs)),
                    None => out.push_str(&format!("<D:response><D:href>{}</D:href><D:status>HTTP/1.1 404 Not Found</D:status></D:response>", xml_escape(href))),
                }
            }
        }
        "calendar-query" => {
            let objects = match &query.time_range {
                Some((start, end)) => {
                    let (from, to) = (bound(start, i64::MIN / 2), bound(end, i64::MAX / 2));
                    let candidates = store::in_range(&state.db, calendar.id, from, to, query.component.as_deref()).await.map_err(internal)?;
                    // The index is coarse for recurring events; confirm with the real expansion.
                    candidates.into_iter().filter(|object| object.component != "VEVENT" || !ical::occurrences(&object.data, from, to, zone).is_empty()).collect()
                }
                None => store::objects(&state.db, calendar.id).await.map_err(internal)?.into_iter().filter(|object| query.component.as_deref().is_none_or(|c| c == object.component)).collect::<Vec<_>>(),
            };
            for object in &objects {
                out.push_str(&response_for(&Target::Item(access, object), &query.props, account, hrefs));
            }
        }
        "sync-collection" => {
            let token = match query.texts.get("sync-token").map(String::as_str).filter(|t| !t.is_empty()) {
                None => 0,
                Some(text) => match text.strip_prefix(SYNC_PREFIX).and_then(|n| n.parse::<i64>().ok()).filter(|n| (0..=calendar.sync_token).contains(n)) {
                    Some(token) => token,
                    // A token this server never issued: the client must start over.
                    None => return Err(precondition(StatusCode::FORBIDDEN, "D:valid-sync-token")),
                },
            };
            let (changed, removed) = store::changes_since(&state.db, calendar.id, token).await.map_err(internal)?;
            for object in &changed {
                out.push_str(&response_for(&Target::Item(access, object), &query.props, account, hrefs));
            }
            // A first synchronisation has no use for the list of things that no longer exist.
            if token > 0 {
                for name in removed {
                    out.push_str(&format!("<D:response><D:href>{}</D:href><D:status>HTTP/1.1 404 Not Found</D:status></D:response>", xml_escape(&hrefs.item(&access.slug(), &name))));
                }
            }
            out.push_str(&format!("<D:sync-token>{SYNC_PREFIX}{}</D:sync-token>", calendar.sync_token));
        }
        _ => return Err(precondition(StatusCode::FORBIDDEN, "D:supported-report")),
    }
    Ok(multistatus(&out))
}

/// Compares an `If-Match` / `If-None-Match` header with the current entity tag.
pub(super) fn matches_etag(header: Option<&HeaderValue>, etag: Option<&str>) -> Option<bool> {
    let value = header?.to_str().ok()?;
    Some(match etag {
        None => false,
        Some(current) => value.trim() == "*" || value.split(',').any(|candidate| candidate.trim().trim_start_matches("W/") == current),
    })
}

async fn handle(state: &AppState, request: Request, ip: std::net::IpAddr) -> Result<Response, Response> {
    let method = request.method().clone();
    if method == Method::OPTIONS {
        return Ok((
            StatusCode::OK,
            [("dav", "1, 3, calendar-access, addressbook, extended-mkcol"), ("allow", "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, REPORT, MKCALENDAR, MKCOL"), ("accept-ranges", "bytes"), ("ms-author-via", "DAV")],
        )
            .into_response());
    }
    let account = authenticate(state, request.headers(), ip).await?;
    let hrefs = Hrefs { address: percent_encode(&account.email) };
    let path = request.uri().path().to_owned();
    let resource = resolve(&path, &account).map_err(|foreign| status(if foreign { StatusCode::FORBIDDEN } else { StatusCode::NOT_FOUND }))?;
    let headers = request.headers().clone();
    let depth = headers.get("depth").and_then(|v| v.to_str().ok()).unwrap_or("1").to_owned();
    let body = axum::body::to_bytes(request.into_body(), MAX_BODY).await.map_err(|_| status(StatusCode::PAYLOAD_TOO_LARGE))?;
    let text = String::from_utf8(body.to_vec()).map_err(|_| status(StatusCode::BAD_REQUEST))?;
    let query = || if text.trim().is_empty() { Ok(Query::default()) } else { parse_query(&text).ok_or_else(|| status(StatusCode::BAD_REQUEST)) };
    if matches!(resource, Resource::AddressHome | Resource::AddressBook | Resource::Card(_)) {
        return carddav::handle(state, &account, &hrefs, method.as_str(), resource, &headers, &depth, &text).await;
    }
    let account = &account;
    let find_calendar = |slug: String| async move { store::access_by_slug(&state.db, account, &slug).await.map_err(internal)?.ok_or_else(|| status(StatusCode::NOT_FOUND)) };
    // Calendars shared for reading cannot be written; those of others are never the user's to rename or delete.
    let writable = |access: Access| if access.writable { Ok(access) } else { Err(status(StatusCode::FORBIDDEN)) };
    let owned = |access: Access| if access.shared { Err(status(StatusCode::FORBIDDEN)) } else { Ok(access) };

    match (method.as_str(), resource) {
        ("PROPFIND", resource) => propfind(state, account, &hrefs, resource, &depth, &query()?).await,
        ("REPORT", Resource::Calendar(slug)) => report(state, account, &hrefs, &find_calendar(slug).await?, &query()?).await,
        ("REPORT", _) => Err(precondition(StatusCode::FORBIDDEN, "D:supported-report")),

        ("MKCALENDAR" | "MKCOL", Resource::Calendar(slug)) => {
            let query = query()?;
            // Extended MKCOL (RFC 5689) makes a calendar when the resource type says so.
            if method.as_str() == "MKCOL" && !query.resource_types.iter().any(|t| t == "calendar") {
                return Err(precondition(StatusCode::FORBIDDEN, "D:valid-resourcetype"));
            }
            let name = query.texts.get("displayname").filter(|n| !n.is_empty()).cloned().unwrap_or_else(|| slug.clone());
            let color = query.texts.get("calendar-color").cloned().unwrap_or_default();
            let description = query.texts.get("calendar-description").cloned().unwrap_or_default();
            // Colours arrive as #rrggbbaa from some clients; anything else is dropped, not refused.
            let color = if store::valid_color(&color) { color } else { String::new() };
            store::create(&state.db, account.id, &slug, &name, &color, &description).await.map_err(store_error)?;
            Ok(status(StatusCode::CREATED))
        }
        ("PROPPATCH", Resource::Calendar(slug)) => {
            let calendar = owned(find_calendar(slug).await?)?.calendar;
            let query = query()?;
            let color = query.texts.get("calendar-color").filter(|c| store::valid_color(c));
            store::update(&state.db, &calendar, query.texts.get("displayname").map(String::as_str), color.map(String::as_str), query.texts.get("calendar-description").map(String::as_str)).await.map_err(store_error)?;
            let props: String = query.props.iter().filter(|n| n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')).map(|n| format!("<D:{n}/>")).collect();
            Ok(multistatus(&format!("<D:response><D:href>{}</D:href><D:propstat><D:prop>{props}</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>", xml_escape(&hrefs.calendar(&calendar.slug)))))
        }

        ("GET" | "HEAD", Resource::Item(slug, name)) => {
            let calendar = find_calendar(slug).await?.calendar;
            let object = store::object(&state.db, calendar.id, &name).await.map_err(internal)?.ok_or_else(|| status(StatusCode::NOT_FOUND))?;
            let etag = HeaderValue::from_str(&object.etag).unwrap_or(HeaderValue::from_static("\"\""));
            let body = if method == Method::HEAD { Body::empty() } else { Body::from(object.data) };
            Ok((StatusCode::OK, [(header::CONTENT_TYPE, HeaderValue::from_static("text/calendar; charset=utf-8")), (header::ETAG, etag)], body).into_response())
        }
        ("GET" | "HEAD", Resource::Calendar(slug)) => {
            let calendar = find_calendar(slug).await?.calendar;
            let objects = store::objects(&state.db, calendar.id).await.map_err(internal)?;
            let body = if method == Method::HEAD { Body::empty() } else { Body::from(export(&calendar, &objects)) };
            Ok((StatusCode::OK, [(header::CONTENT_TYPE, "text/calendar; charset=utf-8")], body).into_response())
        }
        ("PUT", Resource::Item(slug, name)) => {
            let calendar = writable(find_calendar(slug).await?)?.calendar;
            let existing = store::object(&state.db, calendar.id, &name).await.map_err(internal)?;
            let etag = existing.as_ref().map(|o| o.etag.as_str());
            // Lost-update protection: the client states which version it is replacing.
            if matches_etag(headers.get(header::IF_MATCH), etag) == Some(false) || matches_etag(headers.get(header::IF_NONE_MATCH), etag) == Some(true) {
                return Err(status(StatusCode::PRECONDITION_FAILED));
            }
            let (object, created) = store::put_object(&state.db, &calendar, &name, &text).await.map_err(store_error)?;
            let etag = HeaderValue::from_str(&object.etag).unwrap_or(HeaderValue::from_static("\"\""));
            Ok((if created { StatusCode::CREATED } else { StatusCode::NO_CONTENT }, [(header::ETAG, etag)]).into_response())
        }
        ("DELETE", Resource::Item(slug, name)) => {
            let calendar = writable(find_calendar(slug).await?)?.calendar;
            let existing = store::object(&state.db, calendar.id, &name).await.map_err(internal)?.ok_or_else(|| status(StatusCode::NOT_FOUND))?;
            if matches_etag(headers.get(header::IF_MATCH), Some(&existing.etag)) == Some(false) {
                return Err(status(StatusCode::PRECONDITION_FAILED));
            }
            store::delete_object(&state.db, &calendar, &name).await.map_err(internal)?;
            Ok(status(StatusCode::NO_CONTENT))
        }
        ("DELETE", Resource::Calendar(slug)) => {
            store::delete(&state.db, &owned(find_calendar(slug).await?)?.calendar).await.map_err(internal)?;
            Ok(status(StatusCode::NO_CONTENT))
        }
        _ => Err(status(StatusCode::METHOD_NOT_ALLOWED)),
    }
}

/// Entry point for everything below `/dav`.
pub async fn serve(State(state): State<AppState>, request: Request) -> Response {
    let ip = request.extensions().get::<PeerAddr>().map_or(std::net::IpAddr::from([0, 0, 0, 0]), |peer| peer.0.ip());
    let method = request.method().clone();
    let (minimal, range) = preferences(request.headers());
    let mut response = match handle(&state, request, ip).await {
        Ok(response) | Err(response) => response,
    };
    if minimal && response.status() == StatusCode::MULTI_STATUS {
        response = without_missing(response).await;
    }
    if method == Method::GET && response.status() == StatusCode::OK {
        response.headers_mut().insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        if let Some(range) = range {
            response = ranged(response, &range).await;
        }
    }
    // Calendar data is personal: never cache it in shared caches.
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Whether the client prefers minimal multistatus answers (RFC 8144), and the byte range it asks for.
fn preferences(headers: &HeaderMap) -> (bool, Option<String>) {
    let text = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let minimal = text("prefer").is_some_and(|p| p.split(',').any(|p| p.trim().eq_ignore_ascii_case("return=minimal")));
    (minimal, text("range"))
}

/// Drops the `404 Not Found` propstats from a multistatus body.
async fn without_missing(response: Response) -> Response {
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else { return status(StatusCode::INTERNAL_SERVER_ERROR) };
    let text = String::from_utf8_lossy(&bytes);
    let mut out = String::with_capacity(text.len());
    let mut rest: &str = &text;
    while let Some(start) = rest.find("<D:propstat>") {
        let Some(len) = rest[start..].find("</D:propstat>") else { break };
        let end = start + len + "</D:propstat>".len();
        out.push_str(&rest[..start]);
        if !rest[start..end].contains("404 Not Found") {
            out.push_str(&rest[start..end]);
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.insert(header::HeaderName::from_static("preference-applied"), HeaderValue::from_static("return=minimal"));
    Response::from_parts(parts, Body::from(out))
}

/// Parses a single `bytes=a-b`, `bytes=a-` or `bytes=-n` range against a length.
fn byte_range(value: &str, len: usize) -> Option<(usize, usize)> {
    let spec = value.trim().strip_prefix("bytes=")?;
    if spec.contains(',') || len == 0 {
        return None;
    }
    let (from, to) = spec.split_once('-')?;
    let (start, end) = match (from.trim(), to.trim()) {
        ("", n) => (len.saturating_sub(n.parse().ok()?), len - 1),
        (a, "") => (a.parse().ok()?, len - 1),
        (a, b) => (a.parse().ok()?, b.parse::<usize>().ok()?.min(len - 1)),
    };
    (start <= end && start < len).then_some((start, end))
}

/// Serves a byte range of a successful GET (RFC 7233); several ranges get the whole body.
async fn ranged(response: Response, range: &str) -> Response {
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else { return status(StatusCode::INTERNAL_SERVER_ERROR) };
    parts.headers.remove(header::CONTENT_LENGTH);
    if !range.trim().starts_with("bytes=") || range.contains(',') {
        return Response::from_parts(parts, Body::from(bytes));
    }
    let Some((start, end)) = byte_range(range, bytes.len()) else {
        return (StatusCode::RANGE_NOT_SATISFIABLE, [(header::CONTENT_RANGE, format!("bytes */{}", bytes.len()))]).into_response();
    };
    parts.status = StatusCode::PARTIAL_CONTENT;
    if let Ok(value) = HeaderValue::from_str(&format!("bytes {start}-{end}/{}", bytes.len())) {
        parts.headers.insert(header::CONTENT_RANGE, value);
    }
    Response::from_parts(parts, Body::from(bytes.slice(start..=end)))
}

/// `/.well-known/caldav` and `/.well-known/carddav`: tell clients where the service lives (RFC 6764).
pub async fn well_known() -> Response {
    (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, "/dav/")]).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_ranges_are_parsed() {
        assert_eq!(byte_range("bytes=0-4", 10), Some((0, 4)));
        assert_eq!(byte_range("bytes=5-", 10), Some((5, 9)));
        assert_eq!(byte_range("bytes=-3", 10), Some((7, 9)));
        assert_eq!(byte_range("bytes=8-99", 10), Some((8, 9)));
        assert_eq!(byte_range("bytes=10-12", 10), None);
        assert_eq!(byte_range("items=0-1", 10), None);
    }

    #[test]
    fn xml_requests_are_read_without_trusting_them() {
        let body = r#"<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop><d:getetag/><c:calendar-data><c:comp name="VCALENDAR"/></c:calendar-data></d:prop>
  <!-- a comment -->
  <c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT">
    <c:time-range start="20261001T000000Z" end='20261101T000000Z'/>
  </c:comp-filter></c:comp-filter></c:filter>
</c:calendar-query>"#;
        let query = parse_query(body).unwrap();
        assert_eq!(query.root, "calendar-query");
        assert_eq!(query.props, ["getetag", "calendar-data"], "sub-elements of a property are not properties");
        assert_eq!(query.component.as_deref(), Some("VEVENT"));
        assert_eq!(query.time_range, Some((Some("20261001T000000Z".into()), Some("20261101T000000Z".into()))));

        let patch = parse_query("<D:propertyupdate xmlns:D=\"DAV:\"><D:set><D:prop><D:displayname>Work &amp; <![CDATA[<play>]]></D:displayname></D:prop></D:set></D:propertyupdate>").unwrap();
        assert_eq!(patch.props, ["displayname"]);
        // Entities other than the five predefined ones are never expanded.
        let hostile = parse_query("<D:propfind xmlns:D=\"DAV:\"><D:prop><D:displayname>&xxe;</D:displayname></D:prop></D:propfind>").unwrap();
        assert_eq!(hostile.texts.get("displayname").map(String::as_str), Some("&xxe;"));
        let multiget = parse_query("<C:calendar-multiget xmlns:D=\"DAV:\" xmlns:C=\"x\"><D:prop><D:getetag/></D:prop><D:href>/dav/calendars/a%40b/c/1.ics</D:href><D:href> /x/2.ics </D:href></C:calendar-multiget>").unwrap();
        assert_eq!(multiget.hrefs, ["/dav/calendars/a%40b/c/1.ics", "/x/2.ics"]);
        for broken in ["<unterminated", "<a b=c></a>", "<!-- never closed"] {
            assert!(parse_query(broken).is_none(), "{broken}");
        }
        assert_eq!(xml_escape("a<b>&\"c\"\u{0}"), "a&lt;b&gt;&amp;&quot;c&quot;");
    }

    #[test]
    fn paths_are_confined_to_the_authenticated_user() {
        let account = Account {
            id: 1,
            domain_id: 1,
            email: "józef@example.org".into(),
            display_name: String::new(),
            password_hash: String::new(),
            role: crate::auth::Role::User,
            quota_bytes: 0,
            used_bytes: 0,
            enabled: true,
            imap_enabled: true,
            pop3_enabled: true,
            smtp_enabled: true,
            outbound_blocked: false,
        };
        assert_eq!(resolve("/dav/", &account), Ok(Resource::Root));
        assert_eq!(resolve("/dav", &account), Ok(Resource::Root));
        assert_eq!(resolve("/dav/principals/J%C3%B3zef@Example.org/", &account), Ok(Resource::Principal), "addresses compare case-insensitively");
        assert_eq!(resolve("/dav/calendars/j%C3%B3zef%40example.org/work/", &account), Ok(Resource::Calendar("work".into())));
        assert_eq!(resolve("/dav/calendars/j%C3%B3zef%40example.org/work/a%20b.ics", &account), Ok(Resource::Item("work".into(), "a b.ics".into())));
        assert_eq!(resolve("/dav/calendars/someone-else@example.org/work/", &account), Err(true));
        assert_eq!(resolve("/dav/principals/someone-else@example.org/", &account), Err(true));
        assert_eq!(resolve("/dav/calendars/j%C3%B3zef%40example.org/a/b/c", &account), Err(false));
        assert_eq!(resolve("/dav/calendars/%ZZ/", &account), Err(false));
        assert_eq!(resolve("/dav/addressbooks/j%C3%B3zef@example.org/contacts/", &account), Ok(Resource::AddressBook));
        assert_eq!(resolve("/dav/addressbooks/j%C3%B3zef@example.org/contacts/a.vcf", &account), Ok(Resource::Card("a.vcf".into())));
        assert_eq!(resolve("/dav/addressbooks/j%C3%B3zef@example.org/other/", &account), Err(false));
        assert_eq!(resolve("/dav/addressbooks/someone-else@example.org/contacts/a.vcf", &account), Err(true));
        assert_eq!(resolve("/elsewhere", &account), Err(false));
        assert_eq!(percent_encode("józef@example.org"), "j%C3%B3zef@example.org");
        assert!(!store::valid_object_name("../secret.ics") && !store::valid_object_name("a/b.ics") && store::valid_object_name("3f2a-1@host.ics"));
    }

    #[test]
    fn entity_tags_guard_against_lost_updates() {
        let header = |value: &'static str| HeaderValue::from_static(value);
        assert_eq!(matches_etag(None, Some("\"a\"")), None);
        assert_eq!(matches_etag(Some(&header("\"a\"")), Some("\"a\"")), Some(true));
        assert_eq!(matches_etag(Some(&header("\"old\", W/\"a\"")), Some("\"a\"")), Some(true));
        assert_eq!(matches_etag(Some(&header("\"old\"")), Some("\"a\"")), Some(false));
        assert_eq!(matches_etag(Some(&header("*")), Some("\"a\"")), Some(true));
        assert_eq!(matches_etag(Some(&header("*")), None), Some(false), "nothing exists to match");
    }
}
