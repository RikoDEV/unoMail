//! JMAP for Calendars (draft-ietf-jmap-calendars): Calendar/get|changes|set and
//! CalendarEvent/get|changes|query|set, with events in JSCalendar form (RFC 8984).
//!
//! These are the account's own calendars, the ones the web client and CalDAV use. An event
//! is read and written through the same model as the web client: title, description, one
//! location, start and duration, a recurrence rule, the people invited and one alert. Edits
//! change only those properties; everything else a calendar program stored stays. Overridden
//! occurrences of a series are kept but not shown, and to-dos are left to CalDAV.

use chrono::{NaiveDate, NaiveDateTime, TimeZone};
use chrono_tz::Tz;
use serde_json::{Map, Value, json};

use super::{
    Context, MAX_OBJECTS, MethodError, MethodResult, account_id,
    objects::{self, SetResult},
    parse_id, set_error,
};
use crate::calendar::{
    ical::{self, EventInput},
    scheduling,
    store::{self, Calendar, CalendarError, Object},
};

const LOCAL: &str = "%Y-%m-%dT%H:%M:%S";

// --- Calendars -------------------------------------------------------------------------------

fn calendar_json(calendar: &Calendar, default: bool) -> Value {
    json!({
        "id": format!("C{}", calendar.id),
        "name": calendar.name,
        "description": if calendar.description.is_empty() { Value::Null } else { json!(calendar.description) },
        "color": if calendar.color.is_empty() { Value::Null } else { json!(calendar.color) },
        "sortOrder": 0,
        "isSubscribed": true,
        "isVisible": true,
        "isDefault": default,
        "includeInAvailability": "all",
        "defaultAlertsWithTime": null,
        "defaultAlertsWithoutTime": null,
        "timeZone": null,
        "shareWith": null,
        "myRights": {
            "mayReadFreeBusy": true, "mayReadItems": true, "mayWriteAll": true, "mayWriteOwn": true,
            "mayUpdatePrivate": true, "mayRSVP": true, "mayAdmin": true, "mayDelete": true,
        },
    })
}

pub async fn calendar_get(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let calendars = store::list(&ctx.app.db, ctx.account.id).await?;
    let default = calendars.first().map(|c| c.id);
    let (mut list, mut not_found) = (Vec::new(), Vec::new());
    match objects::requested_ids(args)? {
        None => list.extend(calendars.iter().map(|c| objects::select(calendar_json(c, Some(c.id) == default), args))),
        Some(ids) => {
            for id in ids {
                match parse_id(&id, 'C').and_then(|n| calendars.iter().find(|c| c.id == n)) {
                    Some(c) => list.push(objects::select(calendar_json(c, Some(c.id) == default), args)),
                    None => not_found.push(id),
                }
            }
        }
    }
    Ok(json!({ "accountId": account_id(ctx.account), "state": objects::state(ctx, "Calendar").await?, "list": list, "notFound": not_found }))
}

pub async fn calendar_changes(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    objects::changes(ctx, args, "Calendar", 'C').await
}

fn calendar_error(err: CalendarError) -> Value {
    match err {
        CalendarError::Invalid(msg) => set_error("invalidProperties", msg),
        CalendarError::Limit => set_error("overQuota", "no more calendars can be added"),
        CalendarError::Exists | CalendarError::UidConflict => set_error("invalidProperties", err.to_string()),
        CalendarError::Db(err) => {
            tracing::error!(%err, "calendar operation failed");
            set_error("serverFail", "internal error")
        }
    }
}

/// Properties a client may send that only matter to it, or that every calendar here has.
const CALENDAR_PASSIVE: [&str; 11] =
    ["id", "sortOrder", "isSubscribed", "isVisible", "isDefault", "includeInAvailability", "defaultAlertsWithTime", "defaultAlertsWithoutTime", "timeZone", "shareWith", "myRights"];

/// Name, colour and description as given; `None` for one not given.
type CalendarFields = (Option<String>, Option<String>, Option<String>);

fn calendar_fields(spec: &Map<String, Value>) -> Result<CalendarFields, Value> {
    if let Some(key) = spec.keys().find(|k| !CALENDAR_PASSIVE.contains(&k.as_str()) && !matches!(k.as_str(), "name" | "color" | "description")) {
        return Err(set_error("invalidProperties", format!("{key} cannot be set")));
    }
    let text = |key: &str| match spec.get(key) {
        Some(Value::Null) => Ok(Some(String::new())),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        None => Ok(None),
        Some(_) => Err(set_error("invalidProperties", format!("{key} must be a string"))),
    };
    Ok((text("name")?, text("color")?, text("description")?))
}

pub async fn calendar_set(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    objects::check_size(args)?;
    let old_state = objects::state(ctx, "Calendar").await?;
    objects::check_state(args, &old_state)?;
    let db = &ctx.app.db;
    let mut result = SetResult::default();
    for (creation_id, spec) in args.get("create").and_then(Value::as_object).into_iter().flatten() {
        let outcome = async {
            let (name, color, description) = calendar_fields(spec.as_object().ok_or_else(|| set_error("invalidProperties", "a calendar must be an object"))?)?;
            let slug = uuid::Uuid::new_v4().to_string();
            store::create(db, ctx.account.id, &slug, name.as_deref().unwrap_or(""), color.as_deref().unwrap_or("#1a73e8"), description.as_deref().unwrap_or("")).await.map_err(calendar_error)
        }
        .await;
        match outcome {
            Ok(calendar) => {
                let id = format!("C{}", calendar.id);
                ctx.created.insert(creation_id.clone(), id.clone());
                result.created.insert(creation_id.clone(), json!({ "id": id, "isDefault": false, "myRights": calendar_json(&calendar, false)["myRights"] }));
            }
            Err(err) => {
                result.not_created.insert(creation_id.clone(), err);
            }
        }
    }
    for (id, patch) in args.get("update").and_then(Value::as_object).into_iter().flatten() {
        let outcome = async {
            let calendar = match parse_id(&ctx.resolve_id(id), 'C') {
                Some(n) => store::by_id(db, ctx.account.id, n).await.map_err(|e| calendar_error(e.into()))?,
                None => None,
            }
            .ok_or_else(|| set_error("notFound", "no such calendar"))?;
            let (name, color, description) = calendar_fields(patch.as_object().ok_or_else(|| set_error("invalidPatch", "the patch must be an object"))?)?;
            store::update(db, &calendar, name.as_deref(), color.as_deref(), description.as_deref()).await.map_err(calendar_error)
        }
        .await;
        match outcome {
            Ok(()) => result.updated.insert(id.clone(), Value::Null),
            Err(err) => result.not_updated.insert(id.clone(), err),
        };
    }
    let remove_events = args.get("onDestroyRemoveEvents").and_then(Value::as_bool).unwrap_or(false);
    for id in args.get("destroy").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
        let outcome = async {
            let calendar = match parse_id(&ctx.resolve_id(id), 'C') {
                Some(n) => store::by_id(db, ctx.account.id, n).await.map_err(|e| calendar_error(e.into()))?,
                None => None,
            }
            .ok_or_else(|| set_error("notFound", "no such calendar"))?;
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM calendar_objects WHERE calendar_id = ?").bind(calendar.id).fetch_one(db).await.map_err(|e| calendar_error(e.into()))?;
            if count > 0 && !remove_events {
                return Err(set_error("calendarHasEvent", "the calendar is not empty"));
            }
            store::delete(db, &calendar).await.map_err(|e| calendar_error(e.into()))
        }
        .await;
        match outcome {
            Ok(()) => result.destroyed.push(id.to_owned()),
            Err(err) => {
                result.not_destroyed.insert(id.to_owned(), err);
            }
        }
    }
    let new_state = objects::state(ctx, "Calendar").await?;
    Ok(result.into_response(ctx, old_state, new_state))
}

// --- Durations, times and recurrence rules ---------------------------------------------------

/// A JSCalendar (and iCalendar) duration from seconds, e.g. `P1DT2H30M`.
pub fn format_duration(secs: i64) -> String {
    let secs = secs.max(0);
    let (days, rest) = (secs / 86_400, secs % 86_400);
    let (hours, minutes, seconds) = (rest / 3600, rest % 3600 / 60, rest % 60);
    let mut out = String::from("P");
    if days > 0 {
        out.push_str(&format!("{days}D"));
    }
    if rest > 0 || days == 0 {
        out.push('T');
        if hours > 0 {
            out.push_str(&format!("{hours}H"));
        }
        if minutes > 0 {
            out.push_str(&format!("{minutes}M"));
        }
        if seconds > 0 || rest == 0 {
            out.push_str(&format!("{seconds}S"));
        }
    }
    out
}

/// `RRULE` text into a JSCalendar RecurrenceRule. Parts with no JSCalendar equivalent make
/// the rule unrepresentable (`None`).
pub fn rule_to_json(rule: &str, zone: Option<Tz>) -> Option<Value> {
    let mut out = Map::new();
    out.insert("@type".into(), json!("RecurrenceRule"));
    let numbers = |value: &str| value.split(',').map(|n| n.trim().parse::<i64>().ok()).collect::<Option<Vec<i64>>>();
    for part in rule.split(';').filter(|p| !p.is_empty()) {
        let (key, value) = part.split_once('=')?;
        match key.to_ascii_uppercase().as_str() {
            "FREQ" => out.insert("frequency".into(), json!(value.to_ascii_lowercase())),
            "INTERVAL" => out.insert("interval".into(), json!(value.parse::<u32>().ok()?)),
            "COUNT" => out.insert("count".into(), json!(value.parse::<u32>().ok()?)),
            "WKST" => out.insert("firstDayOfWeek".into(), json!(value.to_ascii_lowercase())),
            "UNTIL" => {
                let local = if let Some(date) = value.strip_suffix('Z') {
                    let at = NaiveDateTime::parse_from_str(date, "%Y%m%dT%H%M%S").ok()?.and_utc();
                    match zone {
                        Some(zone) => at.with_timezone(&zone).naive_local(),
                        None => at.naive_utc(),
                    }
                } else if value.len() == 8 {
                    NaiveDate::parse_from_str(value, "%Y%m%d").ok()?.and_hms_opt(0, 0, 0)?
                } else {
                    NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%S").ok()?
                };
                out.insert("until".into(), json!(local.format(LOCAL).to_string()))
            }
            "BYDAY" => {
                let mut days = Vec::new();
                for day in value.split(',') {
                    let day = day.trim().to_ascii_lowercase();
                    let (nth, name) = day.split_at(day.len().checked_sub(2)?);
                    let mut entry = json!({ "@type": "NDay", "day": name });
                    if !nth.is_empty() {
                        entry["nthOfPeriod"] = json!(nth.trim_start_matches('+').parse::<i32>().ok()?);
                    }
                    days.push(entry);
                }
                out.insert("byDay".into(), json!(days))
            }
            "BYMONTHDAY" => out.insert("byMonthDay".into(), json!(numbers(value)?)),
            "BYYEARDAY" => out.insert("byYearDay".into(), json!(numbers(value)?)),
            "BYWEEKNO" => out.insert("byWeekNo".into(), json!(numbers(value)?)),
            "BYHOUR" => out.insert("byHour".into(), json!(numbers(value)?)),
            "BYMINUTE" => out.insert("byMinute".into(), json!(numbers(value)?)),
            "BYSECOND" => out.insert("bySecond".into(), json!(numbers(value)?)),
            "BYSETPOS" => out.insert("bySetPosition".into(), json!(numbers(value)?)),
            "BYMONTH" => out.insert("byMonth".into(), json!(numbers(value)?.iter().map(i64::to_string).collect::<Vec<_>>())),
            _ => return None,
        };
    }
    out.contains_key("frequency").then_some(Value::Object(out))
}

/// A JSCalendar RecurrenceRule as `RRULE` text. `UNTIL` is given in UTC when the event has
/// a time zone, as RFC 5545 requires.
pub fn rule_from_json(rule: &Value, zone: Option<Tz>, all_day: bool) -> Result<String, String> {
    let rule = rule.as_object().ok_or("a recurrence rule must be an object")?;
    let mut parts = Vec::new();
    let frequency = rule.get("frequency").and_then(Value::as_str).ok_or("a recurrence rule needs a frequency")?;
    if !matches!(frequency, "yearly" | "monthly" | "weekly" | "daily" | "hourly" | "minutely" | "secondly") {
        return Err("unknown recurrence frequency".into());
    }
    parts.push(format!("FREQ={}", frequency.to_ascii_uppercase()));
    let numbers = |key: &str| -> Result<Option<String>, String> {
        match rule.get(key) {
            None => Ok(None),
            Some(Value::Array(items)) => items.iter().map(|n| n.as_i64().map(|n| n.to_string()).or_else(|| n.as_str().filter(|s| s.parse::<i64>().is_ok()).map(str::to_owned))).collect::<Option<Vec<_>>>().map(|v| Some(v.join(","))).ok_or_else(|| format!("{key} must list numbers")),
            Some(_) => Err(format!("{key} must be a list")),
        }
    };
    for (key, value) in rule {
        match key.as_str() {
            "@type" | "frequency" => {}
            "rscale" if value.as_str().is_some_and(|s| s.eq_ignore_ascii_case("gregorian")) => {}
            "skip" if value.as_str() == Some("omit") => {}
            "interval" => parts.push(format!("INTERVAL={}", value.as_u64().filter(|n| *n > 0).ok_or("invalid interval")?)),
            "count" => parts.push(format!("COUNT={}", value.as_u64().filter(|n| *n > 0).ok_or("invalid count")?)),
            "firstDayOfWeek" => parts.push(format!("WKST={}", weekday(value.as_str().ok_or("invalid firstDayOfWeek")?)?)),
            "until" => {
                let local = NaiveDateTime::parse_from_str(value.as_str().ok_or("invalid until")?, LOCAL).map_err(|_| "invalid until")?;
                parts.push(match zone {
                    _ if all_day => format!("UNTIL={}", local.format("%Y%m%d")),
                    Some(zone) => format!("UNTIL={}", zone.from_local_datetime(&local).earliest().ok_or("invalid until")?.naive_utc().format("%Y%m%dT%H%M%SZ")),
                    None => format!("UNTIL={}", local.format("%Y%m%dT%H%M%S")),
                });
            }
            "byDay" => {
                let mut days = Vec::new();
                for day in value.as_array().ok_or("byDay must be a list")? {
                    let name = weekday(day["day"].as_str().ok_or("byDay needs days")?)?;
                    match day.get("nthOfPeriod").and_then(Value::as_i64) {
                        Some(nth) if nth != 0 && nth.abs() <= 53 => days.push(format!("{nth}{name}")),
                        Some(_) => return Err("invalid nthOfPeriod".into()),
                        None => days.push(name.to_owned()),
                    }
                }
                parts.push(format!("BYDAY={}", days.join(",")));
            }
            "byMonthDay" | "byYearDay" | "byWeekNo" | "byHour" | "byMinute" | "bySecond" | "bySetPosition" | "byMonth" => {
                let ical = match key.as_str() {
                    "byMonthDay" => "BYMONTHDAY",
                    "byYearDay" => "BYYEARDAY",
                    "byWeekNo" => "BYWEEKNO",
                    "byHour" => "BYHOUR",
                    "byMinute" => "BYMINUTE",
                    "bySecond" => "BYSECOND",
                    "bySetPosition" => "BYSETPOS",
                    _ => "BYMONTH",
                };
                if let Some(list) = numbers(key)?.filter(|l| !l.is_empty()) {
                    parts.push(format!("{ical}={list}"));
                }
            }
            other => return Err(format!("the recurrence rule property {other} is not supported")),
        }
    }
    Ok(parts.join(";"))
}

fn weekday(day: &str) -> Result<&'static str, String> {
    Ok(match day.to_ascii_lowercase().as_str() {
        "mo" => "MO",
        "tu" => "TU",
        "we" => "WE",
        "th" => "TH",
        "fr" => "FR",
        "sa" => "SA",
        "su" => "SU",
        _ => return Err(format!("unknown day {day}")),
    })
}

fn participant_id(email: &str) -> String {
    crate::util::sha256_hex(email.as_bytes())[..12].to_owned()
}

// --- Events ----------------------------------------------------------------------------------

/// An event as JSCalendar, from its stored object.
fn event_json(object: &Object, calendar_id: i64, zone: Tz) -> Option<Value> {
    let input = ical::describe_event(&object.data, zone, None)?;
    let parsed = ical::parse(&object.data).ok()?;
    let main = ical::master(&parsed)?;
    let (start, duration) = if input.all_day {
        let first = NaiveDate::parse_from_str(&input.start, "%Y-%m-%d").ok()?;
        let last = NaiveDate::parse_from_str(&input.end, "%Y-%m-%d").ok()?;
        (first.and_hms_opt(0, 0, 0)?, format!("P{}D", (last - first).num_days() + 1))
    } else {
        let first = NaiveDateTime::parse_from_str(&input.start, "%Y-%m-%dT%H:%M").ok()?;
        let last = NaiveDateTime::parse_from_str(&input.end, "%Y-%m-%dT%H:%M").ok()?;
        (first, format_duration((last - first).num_seconds()))
    };
    let event_zone: Option<Tz> = (!input.all_day).then(|| input.timezone.parse().ok()).flatten();
    let mut event = json!({
        "@type": "Event",
        "id": format!("E{}", object.id),
        "calendarIds": { format!("C{calendar_id}"): true },
        "uid": object.uid,
        "title": input.summary,
        "description": input.description,
        "start": start.format(LOCAL).to_string(),
        "duration": duration,
        "timeZone": event_zone.map(|z| z.name().to_owned()),
        "showWithoutTime": input.all_day,
        "isDraft": false,
        "sequence": main.value("SEQUENCE").and_then(|s| s.trim().parse::<u32>().ok()).unwrap_or(0),
        "status": main.value("STATUS").map_or("confirmed".to_owned(), |s| s.trim().to_ascii_lowercase()),
        "freeBusyStatus": if main.value("TRANSP").is_some_and(|t| t.trim().eq_ignore_ascii_case("TRANSPARENT")) { "free" } else { "busy" },
        "recurrenceRules": null,
        "locations": null,
        "participants": null,
        "alerts": null,
        "useDefaultAlerts": false,
    });
    if !input.location.is_empty() {
        event["locations"] = json!({ "l1": { "@type": "Location", "name": input.location } });
    }
    if !input.rrule.is_empty() {
        // A rule JSCalendar cannot express is left out; the event still reads as a series start.
        event["recurrenceRules"] = rule_to_json(&input.rrule, event_zone).map_or(Value::Null, |rule| json!([rule]));
    }
    if let Some(minutes) = input.reminder.flatten() {
        event["alerts"] = json!({ "a1": { "@type": "Alert", "trigger": { "@type": "OffsetTrigger", "offset": format!("-{}", format_duration(minutes * 60)), "relativeTo": "start" }, "action": "display" } });
    }
    let guests = ical::attendees(main);
    if let Some(organizer) = ical::organizer(main) {
        let mut participants = Map::new();
        participants.insert(participant_id(&organizer), json!({ "@type": "Participant", "email": organizer, "sendTo": { "imip": format!("mailto:{organizer}") }, "roles": { "owner": true } }));
        for guest in guests.iter().filter(|g| g.email != organizer) {
            let mut entry = json!({ "@type": "Participant", "email": guest.email, "sendTo": { "imip": format!("mailto:{}", guest.email) }, "roles": { "attendee": true }, "participationStatus": guest.status });
            if !guest.name.is_empty() {
                entry["name"] = json!(guest.name);
            }
            participants.insert(participant_id(&guest.email), entry);
        }
        event["participants"] = Value::Object(participants);
        event["replyTo"] = json!({ "imip": format!("mailto:{organizer}") });
    }
    Some(event)
}

/// Properties of a JSCalendar event that are read but not kept apart from the model above:
/// a client may send them back unchanged.
const EVENT_PASSIVE: [&str; 13] = ["@type", "id", "uid", "isDraft", "sequence", "status", "freeBusyStatus", "useDefaultAlerts", "replyTo", "prodId", "created", "updated", "method"];

/// The web client's model of an event from JSCalendar. `floating` is the zone used for an
/// event without one.
fn event_input(event: &Value, floating: Tz) -> Result<EventInput, Value> {
    let invalid = |property: &str, why: String| json!({ "type": "invalidProperties", "description": why, "properties": [property] });
    let map = event.as_object().ok_or_else(|| set_error("invalidProperties", "an event must be an object"))?;
    const KNOWN: [&str; 11] = ["calendarIds", "title", "description", "start", "duration", "timeZone", "showWithoutTime", "recurrenceRules", "locations", "participants", "alerts"];
    if let Some(key) = map.keys().find(|k| !KNOWN.contains(&k.as_str()) && !EVENT_PASSIVE.contains(&k.as_str())) {
        return Err(invalid(key, format!("{key} is not supported")));
    }
    let all_day = event["showWithoutTime"].as_bool().unwrap_or(false);
    let start = NaiveDateTime::parse_from_str(event["start"].as_str().ok_or_else(|| invalid("start", "an event needs a start".into()))?, LOCAL).map_err(|_| invalid("start", "start must be a local date-time".into()))?;
    let duration = match event.get("duration").and_then(Value::as_str) {
        Some(text) => ical::duration_secs(text).filter(|secs| *secs >= 0).ok_or_else(|| invalid("duration", "invalid duration".into()))?,
        None => 0,
    };
    let zone: Option<Tz> = match event.get("timeZone") {
        None | Some(Value::Null) => None,
        Some(Value::String(name)) => Some(name.parse().map_err(|_| invalid("timeZone", "unknown time zone".into()))?),
        Some(_) => return Err(invalid("timeZone", "timeZone must be a string".into())),
    };
    let (start_text, end_text) = if all_day {
        let days = ((duration + 86_399) / 86_400).max(1);
        (start.format("%Y-%m-%d").to_string(), (start.date() + chrono::Duration::days(days - 1)).format("%Y-%m-%d").to_string())
    } else {
        (start.format(LOCAL).to_string(), (start + chrono::Duration::seconds(duration)).format(LOCAL).to_string())
    };
    let rrule = match event.get("recurrenceRules") {
        None | Some(Value::Null) => String::new(),
        Some(Value::Array(rules)) if rules.is_empty() => String::new(),
        Some(Value::Array(rules)) if rules.len() == 1 => rule_from_json(&rules[0], zone.or(Some(floating)), all_day).map_err(|why| invalid("recurrenceRules", why))?,
        Some(_) => return Err(invalid("recurrenceRules", "one recurrence rule at most".into())),
    };
    let location = match event.get("locations").and_then(Value::as_object) {
        Some(locations) if locations.len() > 1 => return Err(invalid("locations", "one location at most".into())),
        Some(locations) => locations.values().next().and_then(|l| l["name"].as_str()).unwrap_or("").to_owned(),
        None => String::new(),
    };
    let mut attendees = Vec::new();
    for participant in event.get("participants").and_then(Value::as_object).into_iter().flat_map(|p| p.values()) {
        if participant["roles"]["owner"].as_bool() == Some(true) {
            continue;
        }
        let address = participant["email"].as_str().or_else(|| participant["sendTo"]["imip"].as_str().map(|a| a.trim_start_matches("mailto:")));
        attendees.push(address.ok_or_else(|| invalid("participants", "every participant needs an e-mail address".into()))?.to_owned());
    }
    let mut reminder = None;
    for alert in event.get("alerts").and_then(Value::as_object).into_iter().flat_map(|a| a.values()) {
        let trigger = &alert["trigger"];
        let offset = trigger["offset"].as_str().and_then(ical::duration_secs).filter(|_| trigger["relativeTo"].as_str().is_none_or(|r| r == "start"));
        match offset {
            Some(secs) if secs <= 0 => {
                reminder.get_or_insert(-secs / 60);
            }
            _ => return Err(invalid("alerts", "alerts are supported as a time before the start".into())),
        }
    }
    Ok(EventInput {
        // The web client's model needs a title; JSCalendar does not.
        summary: event["title"].as_str().filter(|t| !t.trim().is_empty()).unwrap_or("Untitled event").to_owned(),
        description: event["description"].as_str().unwrap_or("").to_owned(),
        location,
        start: start_text,
        end: end_text,
        all_day,
        timezone: zone.unwrap_or(floating).name().to_owned(),
        rrule,
        attendees,
        reminder: Some(reminder),
    })
}

/// The one calendar named by `calendarIds`.
async fn target_calendar(ctx: &Context<'_>, event: &Value) -> Result<Calendar, Value> {
    let ids = event["calendarIds"].as_object().filter(|ids| ids.len() == 1).ok_or_else(|| json!({ "type": "invalidProperties", "description": "an event belongs to exactly one calendar", "properties": ["calendarIds"] }))?;
    let id = ids.keys().next().expect("one entry");
    let calendar = match parse_id(&ctx.resolve_id(id), 'C') {
        Some(n) => store::by_id(&ctx.app.db, ctx.account.id, n).await.map_err(|e| calendar_error(e.into()))?,
        None => None,
    };
    calendar.ok_or_else(|| json!({ "type": "invalidProperties", "description": "no such calendar", "properties": ["calendarIds"] }))
}

/// The account's event `E<id>` and its calendar.
async fn find_event(ctx: &Context<'_>, id: &str) -> Result<Option<(Calendar, Object)>, MethodError> {
    let Some(object_id) = parse_id(&ctx.resolve_id(id), 'E') else { return Ok(None) };
    let calendar_id: Option<i64> =
        sqlx::query_scalar("SELECT o.calendar_id FROM calendar_objects o JOIN calendars c ON c.id = o.calendar_id WHERE o.id = ? AND c.account_id = ? AND o.component = 'VEVENT'")
            .bind(object_id)
            .bind(ctx.account.id)
            .fetch_optional(&ctx.app.db)
            .await?;
    let Some(calendar_id) = calendar_id else { return Ok(None) };
    let Some(calendar) = store::by_id(&ctx.app.db, ctx.account.id, calendar_id).await? else { return Ok(None) };
    Ok(store::object_by_id(&ctx.app.db, calendar_id, object_id).await?.map(|object| (calendar, object)))
}

pub async fn event_get(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let zone = store::zone_of(&ctx.app.db, ctx.account.id).await;
    let (mut list, mut not_found) = (Vec::new(), Vec::new());
    match objects::requested_ids(args)? {
        None => {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM calendar_objects o JOIN calendars c ON c.id = o.calendar_id WHERE c.account_id = ? AND o.component = 'VEVENT'")
                .bind(ctx.account.id)
                .fetch_one(&ctx.app.db)
                .await?;
            if count > MAX_OBJECTS as i64 {
                return Err(MethodError("requestTooLarge", "too many events; use CalendarEvent/query".into()));
            }
            for calendar in store::list(&ctx.app.db, ctx.account.id).await? {
                for object in store::objects(&ctx.app.db, calendar.id).await?.iter().filter(|o| o.component == "VEVENT") {
                    if let Some(event) = event_json(object, calendar.id, zone) {
                        list.push(objects::select(event, args));
                    }
                }
            }
        }
        Some(ids) => {
            for id in ids {
                match find_event(ctx, &id).await?.and_then(|(calendar, object)| event_json(&object, calendar.id, zone)) {
                    Some(event) => list.push(objects::select(event, args)),
                    None => not_found.push(id),
                }
            }
        }
    }
    Ok(json!({ "accountId": account_id(ctx.account), "state": objects::state(ctx, "CalendarEvent").await?, "list": list, "notFound": not_found }))
}

pub async fn event_changes(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    objects::changes(ctx, args, "CalendarEvent", 'E').await
}

fn utc_date(value: &Value, key: &str) -> Result<Option<i64>, MethodError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).map(|t| Some(t.unix_timestamp())).map_err(|_| MethodError::invalid(format!("{key} must be a UTCDate"))),
        Some(_) => Err(MethodError::invalid(format!("{key} must be a UTCDate"))),
    }
}

enum Bind {
    Number(i64),
    Text(String),
}

/// CalendarEvent/query: by calendar, time range and text, sorted by start, uid or update.
pub async fn event_query(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let filter = args.get("filter").cloned().unwrap_or(Value::Null);
    if filter.get("operator").is_some() {
        return Err(MethodError("unsupportedFilter", "combine conditions in one filter object".into()));
    }
    let mut conditions = vec!["c.account_id = ?".to_owned(), "o.component = 'VEVENT'".to_owned()];
    let mut binds: Vec<Bind> = Vec::new();
    if let Some(map) = filter.as_object() {
        for key in map.keys() {
            if !matches!(key.as_str(), "inCalendar" | "after" | "before" | "text" | "title" | "description" | "location" | "uid") {
                return Err(MethodError("unsupportedFilter", format!("events cannot be filtered by {key}")));
            }
        }
    }
    let like = |text: &str| format!("%{}%", text.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
    if let Some(calendar) = filter.get("inCalendar").and_then(Value::as_str) {
        conditions.push("o.calendar_id = ?".into());
        binds.push(Bind::Number(parse_id(&ctx.resolve_id(calendar), 'C').unwrap_or(0)));
    }
    // The index is coarse (computed in the owner's zone); a day of margin errs on the side of
    // including an event.
    if let Some(after) = utc_date(&filter, "after")? {
        conditions.push("(o.last_end IS NULL OR o.last_end > ?)".into());
        binds.push(Bind::Number(after - 86_400));
    }
    if let Some(before) = utc_date(&filter, "before")? {
        conditions.push("o.first_start < ?".into());
        binds.push(Bind::Number(before + 86_400));
    }
    for (key, column) in [("title", "o.summary"), ("text", "o.data"), ("description", "o.data"), ("location", "o.data")] {
        if let Some(text) = filter.get(key).and_then(Value::as_str) {
            conditions.push(format!("{column} LIKE ? ESCAPE '\\'"));
            binds.push(Bind::Text(like(text)));
        }
    }
    if let Some(uid) = filter.get("uid").and_then(Value::as_str) {
        conditions.push("o.uid = ?".into());
        binds.push(Bind::Text(uid.to_owned()));
    }
    let mut order = Vec::new();
    for comparator in args.get("sort").and_then(Value::as_array).into_iter().flatten() {
        let column = match comparator["property"].as_str() {
            Some("start") => "o.first_start",
            Some("uid") => "o.uid",
            Some("updated") => "o.modified",
            Some("created") => "o.id",
            _ => return Err(MethodError("unsupportedSort", "events sort by start, uid, created or updated".into())),
        };
        order.push(format!("{column} {}", if comparator["isAscending"].as_bool().unwrap_or(true) { "ASC" } else { "DESC" }));
    }
    order.push("o.id".into());
    let sql = format!("SELECT o.id FROM calendar_objects o JOIN calendars c ON c.id = o.calendar_id WHERE {} ORDER BY {}", conditions.join(" AND "), order.join(", "));
    let mut query = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql)).bind(ctx.account.id);
    for bind in binds {
        query = match bind {
            Bind::Number(n) => query.bind(n),
            Bind::Text(t) => query.bind(t),
        };
    }
    let all = query.fetch_all(&ctx.app.db).await?;
    let total = all.len();
    let position = args.get("position").and_then(Value::as_i64).unwrap_or(0);
    let position = if position < 0 { total.saturating_sub(position.unsigned_abs() as usize) } else { (position as usize).min(total) };
    let limit = args.get("limit").and_then(Value::as_u64).map_or(MAX_OBJECTS, |l| (l as usize).min(MAX_OBJECTS));
    let ids: Vec<String> = all.iter().skip(position).take(limit).map(|id| format!("E{id}")).collect();
    Ok(json!({
        "accountId": account_id(ctx.account),
        "queryState": objects::state(ctx, "CalendarEvent").await?,
        "canCalculateChanges": false,
        "position": position,
        "ids": ids,
        "total": total,
    }))
}

/// Mails invitations, updates or cancellations when the client asked for them.
async fn schedule(ctx: &Context<'_>, send: bool, before: Option<&str>, after: Option<&str>) {
    if !send {
        return;
    }
    let zone = store::zone_of(&ctx.app.db, ctx.account.id).await;
    let messages = scheduling::messages(ctx.account, before, after, zone);
    for problem in scheduling::send(ctx.app, ctx.account, ctx.account, &messages, ctx.ip).await {
        tracing::info!(problem, "a scheduling message was not sent");
    }
}

pub async fn event_set(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    objects::check_size(args)?;
    let old_state = objects::state(ctx, "CalendarEvent").await?;
    objects::check_state(args, &old_state)?;
    let send = args.get("sendSchedulingMessages").and_then(Value::as_bool).unwrap_or(false);
    let zone = store::zone_of(&ctx.app.db, ctx.account.id).await;
    let organizer = ical::Organizer { email: &ctx.account.email, name: &ctx.account.display_name };
    let db = &ctx.app.db;
    let mut result = SetResult::default();
    let store_error = |err: CalendarError| match err {
        CalendarError::UidConflict => set_error("invalidProperties", "another event in this calendar already uses this uid"),
        other => calendar_error(other),
    };

    for (creation_id, event) in args.get("create").and_then(Value::as_object).into_iter().flatten() {
        let outcome = async {
            let calendar = target_calendar(ctx, event).await?;
            let input = event_input(event, zone)?;
            let uid = match event.get("uid").and_then(Value::as_str) {
                Some(uid) if uid.is_empty() || uid.len() > 255 || uid.chars().any(char::is_control) => return Err(json!({ "type": "invalidProperties", "description": "invalid uid", "properties": ["uid"] })),
                Some(uid) => uid.to_owned(),
                None => format!("{}@{}", uuid::Uuid::new_v4(), ctx.app.cfg.hostname),
            };
            let data = ical::build_event(&uid, &input, Some(&organizer)).map_err(|why| set_error("invalidProperties", why))?;
            let (object, _) = store::put_object(db, &calendar, &format!("{}.ics", uuid::Uuid::new_v4()), &data).await.map_err(store_error)?;
            schedule(ctx, send, None, Some(&data)).await;
            Ok((object, uid))
        }
        .await;
        match outcome {
            Ok((object, uid)) => {
                let id = format!("E{}", object.id);
                ctx.created.insert(creation_id.clone(), id.clone());
                result.created.insert(creation_id.clone(), json!({ "id": id, "uid": uid }));
            }
            Err(err) => {
                result.not_created.insert(creation_id.clone(), err);
            }
        }
    }

    for (id, patch) in args.get("update").and_then(Value::as_object).into_iter().flatten() {
        let outcome = async {
            let patch = patch.as_object().ok_or_else(|| set_error("invalidPatch", "the patch must be an object"))?;
            let (calendar, object) = find_event(ctx, id).await.map_err(|_| set_error("serverFail", "internal error"))?.ok_or_else(|| set_error("notFound", "no such event"))?;
            let mut event = event_json(&object, calendar.id, zone).ok_or_else(|| set_error("forbidden", "this event cannot be edited here"))?;
            objects::apply_patch(&mut event, patch).map_err(|why| set_error("invalidPatch", why))?;
            if event["uid"].as_str() != Some(object.uid.as_str()) {
                return Err(json!({ "type": "invalidProperties", "description": "the uid cannot be changed", "properties": ["uid"] }));
            }
            let input = event_input(&event, zone)?;
            let data = ical::update_event(&object.data, &input, Some(&organizer)).map_err(|why| set_error("invalidProperties", why))?;
            let target = target_calendar(ctx, &event).await?;
            if target.id == calendar.id {
                store::put_object(db, &calendar, &object.name, &data).await.map_err(store_error)?;
            } else {
                // The event keeps its id (and resource name) in its new calendar.
                store::put_object(db, &calendar, &object.name, &data).await.map_err(store_error)?;
                store::move_object(db, &calendar, &target, &object.name).await.map_err(store_error)?;
            }
            schedule(ctx, send, Some(&object.data), Some(&data)).await;
            Ok::<_, Value>(())
        }
        .await;
        match outcome {
            Ok(_) => result.updated.insert(id.clone(), Value::Null),
            Err(err) => result.not_updated.insert(id.clone(), err),
        };
    }

    for id in args.get("destroy").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
        let outcome = async {
            let (calendar, object) = find_event(ctx, id).await.map_err(|_| set_error("serverFail", "internal error"))?.ok_or_else(|| set_error("notFound", "no such event"))?;
            store::delete_object(db, &calendar, &object.name).await.map_err(|e| calendar_error(e.into()))?;
            schedule(ctx, send, Some(&object.data), None).await;
            Ok::<_, Value>(())
        }
        .await;
        match outcome {
            Ok(()) => result.destroyed.push(id.to_owned()),
            Err(err) => {
                result.not_destroyed.insert(id.to_owned(), err);
            }
        }
    }
    let new_state = objects::state(ctx, "CalendarEvent").await?;
    Ok(result.into_response(ctx, old_state, new_state))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(format_duration(0), "PT0S");
        assert_eq!(format_duration(3600), "PT1H");
        assert_eq!(format_duration(90 * 60), "PT1H30M");
        assert_eq!(format_duration(86_400), "P1D");
        assert_eq!(format_duration(86_400 + 7200), "P1DT2H");
        for secs in [0, 59, 3600, 86_400 * 3 + 61] {
            assert_eq!(ical::duration_secs(&format_duration(secs)), Some(secs));
        }
    }

    #[test]
    fn recurrence_rules_round_trip() {
        let zone: Tz = "Europe/Warsaw".parse().unwrap();
        for rule in ["FREQ=WEEKLY;BYDAY=MO,WE", "FREQ=MONTHLY;BYDAY=-1FR;COUNT=5", "FREQ=YEARLY;BYMONTH=3;BYMONTHDAY=1;INTERVAL=2"] {
            let json = rule_to_json(rule, Some(zone)).unwrap();
            let back = rule_from_json(&json, Some(zone), false).unwrap();
            let mut a: Vec<&str> = rule.split(';').collect();
            let mut b: Vec<&str> = back.split(';').collect();
            a.sort_unstable();
            b.sort_unstable();
            assert_eq!(a, b, "{rule}");
        }
        // UNTIL in UTC is read in the event's zone and written back in UTC.
        let json = rule_to_json("FREQ=DAILY;UNTIL=20261231T230000Z", Some(zone)).unwrap();
        assert_eq!(json["until"], "2027-01-01T00:00:00");
        assert_eq!(rule_from_json(&json, Some(zone), false).unwrap(), "FREQ=DAILY;UNTIL=20261231T230000Z");
        assert!(rule_to_json("FREQ=DAILY;X-NAME=1", None).is_none());
        assert!(rule_from_json(&json!({ "frequency": "daily", "rscale": "hebrew" }), None, false).is_err());
        assert!(rule_from_json(&json!({ "frequency": "sometimes" }), None, false).is_err());
    }

    #[test]
    fn events_become_the_web_client_model() {
        let zone: Tz = "Europe/Warsaw".parse().unwrap();
        let event = json!({
            "@type": "Event", "calendarIds": { "C1": true }, "title": "Standup", "start": "2026-10-19T09:00:00", "duration": "PT15M",
            "timeZone": "Europe/Warsaw", "recurrenceRules": [{ "@type": "RecurrenceRule", "frequency": "weekly", "byDay": [{ "day": "mo" }] }],
            "locations": { "x": { "name": "Room 1" } }, "alerts": { "a": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT10M" } } },
            "participants": { "o": { "email": "me@example.org", "roles": { "owner": true } }, "g": { "email": "guest@example.org", "roles": { "attendee": true } } },
        });
        let input = event_input(&event, Tz::UTC).unwrap();
        assert_eq!((input.start.as_str(), input.end.as_str(), input.timezone.as_str()), ("2026-10-19T09:00:00", "2026-10-19T09:15:00", "Europe/Warsaw"));
        assert_eq!((input.rrule.as_str(), input.location.as_str(), input.reminder), ("FREQ=WEEKLY;BYDAY=MO", "Room 1", Some(Some(10))));
        assert_eq!(input.attendees, vec!["guest@example.org".to_owned()]);

        let all_day = event_input(&json!({ "start": "2026-12-24T00:00:00", "duration": "P3D", "showWithoutTime": true, "title": "Holidays" }), zone).unwrap();
        assert_eq!((all_day.start.as_str(), all_day.end.as_str(), all_day.all_day), ("2026-12-24", "2026-12-26", true));

        assert_eq!(event_input(&json!({ "start": "2026-12-24T00:00:00", "virtualLocations": {} }), zone).unwrap_err()["properties"], json!(["virtualLocations"]));
        assert!(event_input(&json!({ "start": "tomorrow" }), zone).is_err());
        assert!(event_input(&json!({ "start": "2026-12-24T00:00:00", "alerts": { "a": { "trigger": { "@type": "AbsoluteTrigger", "when": "2026-12-23T00:00:00Z" } } } }), zone).is_err());
    }

    #[test]
    fn stored_events_read_as_jscalendar() {
        let input = EventInput { summary: "Lunch".into(), start: "2026-10-19T12:00".into(), end: "2026-10-19T13:30".into(), timezone: "Europe/Warsaw".into(), reminder: Some(Some(5)), ..Default::default() };
        let data = ical::build_event("uid-1", &input, None).unwrap();
        let object = Object { id: 3, calendar_id: 1, name: "x.ics".into(), uid: "uid-1".into(), etag: String::new(), data, component: "VEVENT".into(), summary: "Lunch".into(), first_start: None, last_end: None, modified: 1 };
        let event = event_json(&object, 1, Tz::UTC).unwrap();
        assert_eq!(event["start"], "2026-10-19T12:00:00");
        assert_eq!(event["duration"], "PT1H30M");
        assert_eq!(event["timeZone"], "Europe/Warsaw");
        assert_eq!(event["alerts"]["a1"]["trigger"]["offset"], "-PT5M");
        // What is read can be written back unchanged.
        let again = event_input(&event, Tz::UTC).unwrap();
        assert_eq!((again.start.as_str(), again.end.as_str(), again.reminder), ("2026-10-19T12:00:00", "2026-10-19T13:30:00", Some(Some(5))));
    }
}
