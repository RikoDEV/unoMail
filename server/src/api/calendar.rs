//! Calendars for the web client. The same data is served to calendar programs over CalDAV
//! (`crate::calendar::dav`); here recurring events are already expanded into occurrences.

use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use chrono_tz::Tz;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{JsonResult, Session};
use crate::{
    app::AppState,
    auth::Account,
    calendar::{
        dav, ical, scheduling,
        store::{self, Access, CalendarError, Object},
    },
    error::ApiError,
    util::Address,
};

/// Longest window of occurrences served in one request.
const MAX_WINDOW: i64 = 400 * 86400;
const MAX_IMPORT_EVENTS: usize = 5000;
const MAX_SHARES: usize = 50;

impl From<CalendarError> for ApiError {
    fn from(err: CalendarError) -> Self {
        match err {
            CalendarError::Invalid(message) => ApiError::bad(message),
            CalendarError::UidConflict | CalendarError::Exists => ApiError::Conflict(err.to_string()),
            CalendarError::Limit => ApiError::bad("the limit of calendars or events is reached"),
            CalendarError::Db(err) => err.into(),
        }
    }
}

/// A calendar the session may read; with `write`, one it may change.
async fn access_of(state: &AppState, session: &Session, id: i64, write: bool) -> Result<Access, ApiError> {
    let access = store::access_by_id(&state.db, &session.account, id).await?.ok_or(ApiError::NotFound)?;
    if write && !access.writable { Err(ApiError::Forbidden) } else { Ok(access) }
}

/// A calendar that belongs to the session's account (sharing and deleting are the owner's).
async fn own(state: &AppState, session: &Session, id: i64) -> Result<Access, ApiError> {
    let access = access_of(state, session, id, true).await?;
    if access.shared { Err(ApiError::Forbidden) } else { Ok(access) }
}

async fn object_of(state: &AppState, access: &Access, id: i64) -> Result<Object, ApiError> {
    store::object_by_id(&state.db, access.calendar.id, id).await?.ok_or(ApiError::NotFound)
}

/// The account whose calendar this is: events in it are organized in its name.
async fn owner_of(state: &AppState, session: &Session, access: &Access) -> Result<Account, ApiError> {
    if !access.shared {
        return Ok(session.account.clone());
    }
    Account::by_id(&state.db, access.calendar.account_id).await?.ok_or(ApiError::NotFound)
}

fn percent(segment: &str) -> String {
    segment.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~@".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// Mails what a change means for guests or the organizer; returns what could not be sent.
async fn notify(state: &AppState, session: &Session, owner: &Account, before: Option<&str>, after: Option<&str>) -> Vec<String> {
    let zone = store::zone_of(&state.db, owner.id).await;
    let messages = scheduling::messages(owner, before, after, zone);
    scheduling::send(state, owner, &session.account, &messages, session.ip).await
}

// --- Calendars -----------------------------------------------------------------------------

pub async fn list(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let base = state.cfg.public_url();
    let address = percent(&session.account.email);
    let calendars: Vec<Value> = store::accessible(&state.db, &session.account)
        .await?
        .iter()
        .map(|access| {
            let c = &access.calendar;
            json!({
                "id": c.id, "slug": access.slug(), "name": c.name, "color": c.color, "description": c.description,
                "shared": access.shared, "owner": access.owner, "writable": access.writable,
                "url": format!("{base}/dav/calendars/{address}/{}/", access.slug()),
            })
        })
        .collect();
    Ok(Json(json!({
        "calendars": calendars,
        // What a calendar program needs: the server address finds everything else by itself.
        "caldav": { "server": format!("{base}/dav/"), "home": format!("{base}/dav/calendars/{address}/"), "username": session.account.email },
        "carddav": { "server": format!("{base}/dav/"), "addressbook": format!("{base}/dav/addressbooks/{address}/contacts/") },
        "timezone": store::zone_of(&state.db, session.account.id).await.name(),
    })))
}

#[derive(Deserialize)]
pub struct CalendarInput {
    name: Option<String>,
    color: Option<String>,
    description: Option<String>,
}

fn checked(input: &CalendarInput) -> Result<(), ApiError> {
    if input.name.as_deref().is_some_and(|name| name.trim().is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control)) {
        return Err(ApiError::bad("enter a name of at most 100 characters"));
    }
    if input.color.as_deref().is_some_and(|color| !store::valid_color(color)) {
        return Err(ApiError::bad("the colour must look like #1a73e8"));
    }
    if input.description.as_deref().is_some_and(|text| text.chars().count() > 500) {
        return Err(ApiError::bad("the description is too long"));
    }
    Ok(())
}

pub async fn create(State(state): State<AppState>, session: Session, Json(input): Json<CalendarInput>) -> JsonResult<Value> {
    checked(&input)?;
    let name = input.name.as_deref().map(str::trim).ok_or_else(|| ApiError::bad("enter a name"))?;
    // The address of the calendar derives from its name; a number is added if it is taken.
    let base: String = name.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect::<String>().split('-').filter(|part| !part.is_empty()).collect::<Vec<_>>().join("-");
    let base: String = if base.is_empty() || base.starts_with("shared") { "calendar".into() } else { base.chars().take(48).collect() };
    let taken: Vec<String> = store::list(&state.db, session.account.id).await?.into_iter().map(|c| c.slug).collect();
    let slug = std::iter::once(base.clone()).chain((2..).map(|n| format!("{base}-{n}"))).find(|slug| !taken.contains(slug)).unwrap_or(base);
    let calendar = store::create(&state.db, session.account.id, &slug, name, input.color.as_deref().unwrap_or("#1a73e8"), input.description.as_deref().unwrap_or("").trim()).await?;
    Ok(Json(json!({ "id": calendar.id, "slug": calendar.slug })))
}

pub async fn update(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<CalendarInput>) -> JsonResult<Value> {
    checked(&input)?;
    let access = own(&state, &session, id).await?;
    store::update(&state.db, &access.calendar, input.name.as_deref().map(str::trim), input.color.as_deref(), input.description.as_deref().map(str::trim)).await?;
    Ok(Json(json!({ "ok": true })))
}

/// Deletes an own calendar with its events; for a calendar shared by somebody else, leaves it.
pub async fn delete(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    let access = access_of(&state, &session, id, false).await?;
    if access.shared {
        sqlx::query("DELETE FROM calendar_shares WHERE calendar_id = ? AND account_id = ?").bind(id).bind(session.account.id).execute(&state.db).await?;
        return Ok(Json(json!({ "ok": true })));
    }
    if store::list(&state.db, session.account.id).await?.len() <= 1 {
        return Err(ApiError::bad("the last calendar cannot be deleted"));
    }
    store::delete(&state.db, &access.calendar).await?;
    session.audit(&state, "calendar.deleted", &access.calendar.name, "").await;
    Ok(Json(json!({ "ok": true })))
}

// --- Sharing -------------------------------------------------------------------------------

pub async fn shares_get(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Vec<Value>> {
    let access = own(&state, &session, id).await?;
    Ok(Json(store::shares(&state.db, access.calendar.id).await?.into_iter().map(|(_, email, write)| json!({ "email": email, "write": write })).collect()))
}

#[derive(Deserialize)]
pub struct ShareInput {
    email: String,
    #[serde(default)]
    write: bool,
}

/// Replaces the list of colleagues a calendar is shared with. As with shared mail folders,
/// only accounts of the same domain can be named.
pub async fn shares_put(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<Vec<ShareInput>>) -> JsonResult<Value> {
    let access = own(&state, &session, id).await?;
    if input.len() > MAX_SHARES {
        return Err(ApiError::bad(format!("a calendar can be shared with at most {MAX_SHARES} people")));
    }
    let mut shares: Vec<(i64, bool)> = Vec::new();
    for share in &input {
        let address = Address::parse(share.email.trim()).ok_or_else(|| ApiError::bad("invalid e-mail address"))?.to_string();
        let colleague = Account::by_email(&state.db, &address).await?.filter(|a| a.domain_id == session.account.domain_id && a.enabled).ok_or_else(|| ApiError::bad(format!("{address} is not a mailbox of your domain")))?;
        if colleague.id == session.account.id {
            return Err(ApiError::bad("the calendar is yours already"));
        }
        shares.retain(|(id, _)| *id != colleague.id);
        shares.push((colleague.id, share.write));
    }
    store::set_shares(&state.db, access.calendar.id, &shares).await?;
    session.audit(&state, "calendar.shared", &access.calendar.name, &format!("{} people", shares.len())).await;
    Ok(Json(json!({ "ok": true })))
}

// --- Events --------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct Window {
    from: i64,
    to: i64,
}

fn checked_window(window: &Window, longest: i64) -> Result<(), ApiError> {
    if window.to <= window.from || window.to - window.from > longest { Err(ApiError::bad(format!("ask for a window of at most {} days", longest / 86400))) } else { Ok(()) }
}

/// Occurrences of all events the account can see inside a window, recurring events expanded.
pub async fn events(State(state): State<AppState>, session: Session, Query(window): Query<Window>) -> JsonResult<Vec<Value>> {
    checked_window(&window, MAX_WINDOW)?;
    let zone = store::zone_of(&state.db, session.account.id).await;
    let mut out = Vec::new();
    for access in store::accessible(&state.db, &session.account).await? {
        for object in store::in_range(&state.db, access.calendar.id, window.from, window.to, Some("VEVENT")).await? {
            let recurring = object.data.contains("RRULE") || object.data.contains("RDATE");
            for occurrence in ical::occurrences(&object.data, window.from, window.to, zone) {
                out.push(json!({
                    "id": object.id,
                    "calendar_id": access.calendar.id,
                    "start": occurrence.start,
                    "end": occurrence.end,
                    "all_day": occurrence.all_day,
                    "summary": occurrence.summary,
                    "location": occurrence.location,
                    "description": occurrence.description,
                    "recurring": recurring,
                    "recurrence_id": occurrence.recurrence_id,
                    "organizer": occurrence.organizer,
                    "attendees": occurrence.attendees,
                }));
            }
        }
    }
    out.sort_by_key(|event| event["start"].as_i64());
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct OccurrenceQuery {
    /// Start of one occurrence of a recurring event, as the series has it.
    occurrence: Option<i64>,
}

/// One event (or one occurrence of a series) in the form the editor works with.
pub async fn event(State(state): State<AppState>, session: Session, Path((id, object_id)): Path<(i64, i64)>, Query(query): Query<OccurrenceQuery>) -> JsonResult<Value> {
    let access = access_of(&state, &session, id, false).await?;
    let object = object_of(&state, &access, object_id).await?;
    let zone = store::zone_of(&state.db, session.account.id).await;
    let details = ical::describe_event(&object.data, zone, query.occurrence).ok_or_else(|| ApiError::bad("this entry cannot be edited here"))?;
    Ok(Json(json!({ "id": object.id, "calendar_id": access.calendar.id, "event": details })))
}

pub async fn event_create(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<ical::EventInput>) -> JsonResult<Value> {
    let access = access_of(&state, &session, id, true).await?;
    let owner = owner_of(&state, &session, &access).await?;
    let uid = format!("{}@{}", uuid::Uuid::new_v4(), state.cfg.hostname);
    let organizer = ical::Organizer { email: &owner.email, name: &owner.display_name };
    let data = ical::build_event(&uid, &input, Some(&organizer)).map_err(ApiError::bad)?;
    let (object, _) = store::put_object(&state.db, &access.calendar, &format!("{}.ics", uuid::Uuid::new_v4()), &data).await?;
    let problems = notify(&state, &session, &owner, None, Some(&data)).await;
    Ok(Json(json!({ "id": object.id, "calendar_id": access.calendar.id, "mail_problems": problems })))
}

#[derive(Deserialize)]
pub struct EventUpdate {
    #[serde(flatten)]
    event: ical::EventInput,
    /// Set to move the event to another calendar of the account.
    calendar_id: Option<i64>,
    /// Set to change one occurrence of a recurring event instead of the whole series.
    occurrence: Option<i64>,
}

pub async fn event_update(State(state): State<AppState>, session: Session, Path((id, object_id)): Path<(i64, i64)>, Json(input): Json<EventUpdate>) -> JsonResult<Value> {
    let access = access_of(&state, &session, id, true).await?;
    let object = object_of(&state, &access, object_id).await?;
    let owner = owner_of(&state, &session, &access).await?;
    let zone = store::zone_of(&state.db, session.account.id).await;
    let organizer = ical::Organizer { email: &owner.email, name: &owner.display_name };
    let data = match input.occurrence {
        Some(occurrence) => ical::override_occurrence(&object.data, occurrence, &input.event, zone),
        None => ical::update_event(&object.data, &input.event, Some(&organizer)),
    }
    .map_err(ApiError::bad)?;
    let target = match input.calendar_id.filter(|target| *target != access.calendar.id && input.occurrence.is_none()) {
        Some(target) => Some(access_of(&state, &session, target, true).await?),
        None => None,
    };
    let (saved, calendar_id) = match &target {
        // Moving between the calendars of different people would change whose event it is.
        Some(target) if target.calendar.account_id != access.calendar.account_id => return Err(ApiError::bad("an event cannot be moved into another person's calendar")),
        Some(target) => {
            let (moved, _) = store::put_object(&state.db, &target.calendar, &object.name, &data).await?;
            store::delete_object(&state.db, &access.calendar, &object.name).await?;
            (moved, target.calendar.id)
        }
        None => (store::put_object(&state.db, &access.calendar, &object.name, &data).await?.0, access.calendar.id),
    };
    let problems = notify(&state, &session, &owner, Some(&object.data), Some(&data)).await;
    Ok(Json(json!({ "id": saved.id, "calendar_id": calendar_id, "mail_problems": problems })))
}

/// Deletes an event, a to-do, or (with `occurrence`) one occurrence of a recurring event.
pub async fn event_delete(State(state): State<AppState>, session: Session, Path((id, object_id)): Path<(i64, i64)>, Query(removal): Query<OccurrenceQuery>) -> JsonResult<Value> {
    let access = access_of(&state, &session, id, true).await?;
    let object = object_of(&state, &access, object_id).await?;
    let owner = owner_of(&state, &session, &access).await?;
    let zone = store::zone_of(&state.db, session.account.id).await;
    let after = match removal.occurrence {
        Some(occurrence) => {
            let data = ical::exclude_occurrence(&object.data, occurrence, zone).map_err(ApiError::bad)?;
            store::put_object(&state.db, &access.calendar, &object.name, &data).await?;
            Some(data)
        }
        None => {
            store::delete_object(&state.db, &access.calendar, &object.name).await?;
            None
        }
    };
    let problems = notify(&state, &session, &owner, Some(&object.data), after.as_deref()).await;
    Ok(Json(json!({ "ok": true, "mail_problems": problems })))
}

// --- To-dos --------------------------------------------------------------------------------

pub async fn tasks(State(state): State<AppState>, session: Session) -> JsonResult<Vec<Value>> {
    let zone = store::zone_of(&state.db, session.account.id).await;
    let mut out = Vec::new();
    for access in store::accessible(&state.db, &session.account).await? {
        for object in store::objects(&state.db, access.calendar.id).await?.into_iter().filter(|object| object.component == "VTODO") {
            if let Some(task) = ical::describe_todo(&object.data, zone) {
                out.push(json!({ "id": object.id, "calendar_id": access.calendar.id, "summary": task.summary, "description": task.description, "due": task.due, "completed": task.completed }));
            }
        }
    }
    // Open tasks first, the most urgent on top; tasks without a date after those with one.
    out.sort_by_key(|task| (task["completed"].as_bool().unwrap_or(false), task["due"].as_str().is_none_or(str::is_empty), task["due"].as_str().unwrap_or("").to_owned(), task["id"].as_i64()));
    Ok(Json(out))
}

pub async fn task_create(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<ical::TodoInput>) -> JsonResult<Value> {
    let access = access_of(&state, &session, id, true).await?;
    let uid = format!("{}@{}", uuid::Uuid::new_v4(), state.cfg.hostname);
    let data = ical::build_todo(&uid, &input).map_err(ApiError::bad)?;
    let (object, _) = store::put_object(&state.db, &access.calendar, &format!("{}.ics", uuid::Uuid::new_v4()), &data).await?;
    Ok(Json(json!({ "id": object.id, "calendar_id": access.calendar.id })))
}

pub async fn task_update(State(state): State<AppState>, session: Session, Path((id, object_id)): Path<(i64, i64)>, Json(input): Json<ical::TodoInput>) -> JsonResult<Value> {
    let access = access_of(&state, &session, id, true).await?;
    let object = object_of(&state, &access, object_id).await?;
    let zone = store::zone_of(&state.db, session.account.id).await;
    let data = ical::update_todo(&object.data, &input, zone).map_err(ApiError::bad)?;
    store::put_object(&state.db, &access.calendar, &object.name, &data).await?;
    Ok(Json(json!({ "ok": true })))
}

// --- Reminders and free time ---------------------------------------------------------------

/// The reminders that fall due inside a (short) window, for the web client to announce.
pub async fn reminders(State(state): State<AppState>, session: Session, Query(window): Query<Window>) -> JsonResult<Vec<Value>> {
    checked_window(&window, 2 * 86400)?;
    let zone = store::zone_of(&state.db, session.account.id).await;
    // A reminder may come up to four weeks before its event, or after its start.
    let (from, to) = (window.from - 86400, window.to + ical::MAX_REMINDER_MINUTES * 60 + 86400);
    let mut out = Vec::new();
    for access in store::accessible(&state.db, &session.account).await?.into_iter().filter(|access| !access.shared) {
        for object in store::in_range(&state.db, access.calendar.id, from, to, Some("VEVENT")).await?.into_iter().filter(|object| object.data.contains("VALARM")) {
            for occurrence in ical::occurrences(&object.data, from, to, zone) {
                for at in occurrence.alarms.iter().filter(|at| (window.from..window.to).contains(*at)) {
                    out.push(json!({ "id": object.id, "calendar_id": access.calendar.id, "at": at, "start": occurrence.start, "all_day": occurrence.all_day, "summary": occurrence.summary, "location": occurrence.location }));
                }
            }
        }
    }
    out.sort_by_key(|reminder| reminder["at"].as_i64());
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct FreeBusyQuery {
    from: i64,
    to: i64,
    /// Comma-separated e-mail addresses.
    emails: String,
}

/// When colleagues are busy, without saying with what. Only mailboxes of the same domain
/// answer; for everybody else the times are simply unknown.
pub async fn freebusy(State(state): State<AppState>, session: Session, Query(query): Query<FreeBusyQuery>) -> JsonResult<Vec<Value>> {
    checked_window(&Window { from: query.from, to: query.to }, 62 * 86400)?;
    let mut out = Vec::new();
    for raw in query.emails.split(',').map(str::trim).filter(|email| !email.is_empty()).take(ical::MAX_ATTENDEES) {
        let address = Address::parse(raw).map(|address| address.to_string()).unwrap_or_else(|| raw.to_lowercase());
        let colleague = Account::by_email(&state.db, &address).await?.filter(|account| account.domain_id == session.account.domain_id && account.enabled);
        match colleague {
            Some(account) => {
                let calendars = store::list(&state.db, account.id).await?;
                let zone = store::zone_of(&state.db, account.id).await;
                let busy = store::busy(&state.db, &calendars, query.from, query.to, zone).await?;
                out.push(json!({ "email": address, "known": true, "busy": busy.iter().map(|(start, end)| json!({ "start": start, "end": end })).collect::<Vec<_>>() }));
            }
            None => out.push(json!({ "email": address, "known": false, "busy": [] })),
        }
    }
    Ok(Json(out))
}

// --- Invitations received by mail ----------------------------------------------------------

fn first_event(text: &str) -> Result<(ical::Component, String, String), ApiError> {
    let not_calendar = || ApiError::bad("this is not an invitation");
    let incoming = ical::parse(text).map_err(|_| not_calendar())?;
    let method = incoming.value("METHOD").unwrap_or("").trim().to_ascii_uppercase();
    let data = ical::split_objects(text).ok().and_then(|objects| objects.into_iter().next()).ok_or_else(not_calendar)?;
    let calendar = ical::parse(&data).map_err(|_| not_calendar())?;
    let event = ical::master(&calendar).filter(|event| event.name == "VEVENT").cloned().ok_or_else(not_calendar)?;
    Ok((event, method, data))
}

/// Describes calendar data attached to a message: what it is, and what the calendar already
/// knows about that event.
pub async fn invitation_inspect(State(state): State<AppState>, session: Session, body: Bytes) -> JsonResult<Value> {
    let text = String::from_utf8(body.to_vec()).map_err(|_| ApiError::bad("this is not an invitation"))?;
    let (event, method, data) = first_event(&text)?;
    let zone = store::zone_of(&state.db, session.account.id).await;
    let uid = event.value("UID").unwrap_or("").trim().to_owned();
    let stored = store::object_by_uid(&state.db, session.account.id, &uid).await?;
    let me = &session.account.email;
    let status_in = |text: &str| ical::parse(text).ok().and_then(|calendar| ical::master(&calendar).map(ical::attendees)).and_then(|list| list.into_iter().find(|a| &a.email == me)).map(|a| a.status);
    let first = ical::occurrences(&data, i64::MIN / 2, i64::MAX / 2, zone).into_iter().next();
    Ok(Json(json!({
        "method": method,
        "uid": uid,
        "summary": first.as_ref().map(|o| o.summary.clone()).unwrap_or_default(),
        "location": first.as_ref().map(|o| o.location.clone()).unwrap_or_default(),
        "start": first.as_ref().map(|o| o.start),
        "end": first.as_ref().map(|o| o.end),
        "all_day": first.as_ref().is_some_and(|o| o.all_day),
        "recurring": event.prop("RRULE").is_some(),
        "organizer": ical::organizer(&event),
        "attendees": ical::attendees(&event),
        "stored": stored.is_some(),
        // The answer already given (from the calendar), else what the invitation says.
        "my_status": stored.as_ref().and_then(|(_, object)| status_in(&object.data)).or_else(|| status_in(&data)),
        "own": ical::organizer(&event).as_deref() == Some(me.as_str()),
    })))
}

#[derive(Deserialize)]
pub struct Response_ {
    ics: String,
    /// `accepted`, `tentative` or `declined`.
    response: String,
    calendar_id: Option<i64>,
}

/// Answers an invitation: the event goes into the calendar (or leaves it, when declined) and
/// the organizer is told by mail.
pub async fn invitation_respond(State(state): State<AppState>, session: Session, Json(input): Json<Response_>) -> JsonResult<Value> {
    let status = match input.response.as_str() {
        "accepted" => "ACCEPTED",
        "tentative" => "TENTATIVE",
        "declined" => "DECLINED",
        _ => return Err(ApiError::bad("answer with accepted, tentative or declined")),
    };
    let (event, method, data) = first_event(&input.ics)?;
    let me = &session.account;
    if method != "REQUEST" || ical::organizer(&event).is_none_or(|organizer| organizer == me.email) {
        return Err(ApiError::bad("this is not an invitation that can be answered"));
    }
    // Note the answer on our copy. Invitations sent to an alias do not list this address: add it.
    let mut calendar = ical::parse(&data).map_err(ApiError::bad)?;
    for component in calendar.children.iter_mut().filter(|c| c.name == "VEVENT") {
        let mut found = false;
        for attendee in component.props.iter_mut().filter(|p| p.name == "ATTENDEE" && ical::address_of(p).as_deref() == Some(me.email.as_str())) {
            attendee.params.retain(|(key, _)| key != "PARTSTAT" && key != "RSVP");
            attendee.params.push(("PARTSTAT".into(), status.to_owned()));
            found = true;
        }
        if !found {
            component.props.push(ical::Property { name: "ATTENDEE".into(), params: vec![("PARTSTAT".into(), status.to_owned())], value: format!("mailto:{}", me.email) });
        }
        // Reminders chosen by the organizer are theirs, not ours.
        component.children.retain(|c| c.name != "VALARM");
    }
    let data = calendar.serialize();
    let uid = event.value("UID").unwrap_or("").trim().to_owned();
    let stored = store::object_by_uid(&state.db, me.id, &uid).await?;
    let mut object_id = None;
    match (&stored, status) {
        (Some((calendar, object)), "DECLINED") => {
            store::delete_object(&state.db, calendar, &object.name).await?;
        }
        (None, "DECLINED") => {}
        (Some((calendar, object)), _) => object_id = Some(store::put_object(&state.db, calendar, &object.name, &data).await?.0.id),
        (None, _) => {
            let target = match input.calendar_id {
                Some(id) => own(&state, &session, id).await?.calendar,
                None => store::list(&state.db, me.id).await?.into_iter().next().ok_or(ApiError::NotFound)?,
            };
            object_id = Some(store::put_object(&state.db, &target, &format!("{}.ics", uuid::Uuid::new_v4()), &data).await?.0.id);
        }
    }
    let reply: Vec<scheduling::Outgoing> = scheduling::reply(&event, me, status).into_iter().collect();
    let problems = scheduling::send(&state, me, me, &reply, session.ip).await;
    Ok(Json(json!({ "status": input.response, "id": object_id, "mail_problems": problems })))
}

// --- Import and export ---------------------------------------------------------------------

pub async fn export(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> Result<Response, ApiError> {
    let access = access_of(&state, &session, id, false).await?;
    let objects = store::objects(&state.db, access.calendar.id).await?;
    let mut response = dav::export(&access.calendar, &objects).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/calendar; charset=utf-8"));
    headers.insert(header::CONTENT_DISPOSITION, HeaderValue::from_str(&format!("attachment; filename=\"{}.ics\"", access.calendar.slug)).unwrap_or(HeaderValue::from_static("attachment")));
    Ok(response)
}

/// Imports an iCalendar file. Events already present (same UID) are replaced, so importing
/// the same file twice does not duplicate anything. Nobody is invited by an import.
pub async fn import(State(state): State<AppState>, session: Session, Path(id): Path<i64>, body: Bytes) -> JsonResult<Value> {
    let access = access_of(&state, &session, id, true).await?;
    let text = String::from_utf8(body.to_vec()).map_err(|_| ApiError::bad("the file is not valid UTF-8 text"))?;
    let objects = ical::split_objects(&text).map_err(|err| ApiError::bad(format!("not an iCalendar file: {err}")))?;
    if objects.len() > MAX_IMPORT_EVENTS {
        return Err(ApiError::bad("the file holds too many events"));
    }
    let existing = store::objects(&state.db, access.calendar.id).await?;
    let (mut imported, mut skipped) = (0, 0);
    for data in objects {
        let Ok(info) = ical::inspect(&data, Tz::UTC) else {
            skipped += 1;
            continue;
        };
        let name = existing.iter().find(|object| object.uid == info.uid).map_or_else(|| format!("{}.ics", uuid::Uuid::new_v4()), |object| object.name.clone());
        match store::put_object(&state.db, &access.calendar, &name, &data).await {
            Ok(_) => imported += 1,
            Err(CalendarError::Db(err)) => return Err(err.into()),
            Err(CalendarError::Limit) => return Err(CalendarError::Limit.into()),
            Err(_) => skipped += 1,
        }
    }
    Ok(Json(json!({ "imported": imported, "skipped": skipped })))
}
