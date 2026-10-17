//! iCalendar (RFC 5545) as far as the calendar needs it: a lossless component tree, the facts
//! about an object that the server indexes, expansion of recurring events into occurrences,
//! and building or editing events on behalf of the web client.
//!
//! Objects stored through CalDAV are kept byte for byte; the tree is only used to read them
//! and, when the web client edits an event, to change a few properties while everything a
//! calendar program put there (alarms, attendees, vendor extensions) stays in place.

use chrono::{Duration, NaiveDate, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;

/// Upper bound on the occurrences taken from one recurring event per request.
const MAX_OCCURRENCES: u16 = 750;
pub const MAX_OBJECT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    /// Upper-case name, e.g. `DTSTART`.
    pub name: String,
    /// Parameters with upper-case names, e.g. `("TZID", "Europe/Warsaw")`.
    pub params: Vec<(String, String)>,
    /// The raw (still escaped) value.
    pub value: String,
}

impl Property {
    pub fn new(name: &str, value: impl Into<String>) -> Self {
        Property { name: name.to_owned(), params: Vec::new(), value: value.into() }
    }

    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    fn write(&self, out: &mut String) {
        let mut line = self.name.clone();
        for (key, value) in &self.params {
            // Parameter values with separators must be quoted; quotes themselves cannot occur.
            let value = value.replace('"', "");
            if value.contains([':', ';', ',']) {
                line.push_str(&format!(";{key}=\"{value}\""));
            } else {
                line.push_str(&format!(";{key}={value}"));
            }
        }
        line.push(':');
        line.push_str(&self.value);
        fold_into(out, &line);
    }
}

/// Appends one content line folded to at most 75 octets per physical line.
fn fold_into(out: &mut String, line: &str) {
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Component {
    pub name: String,
    pub props: Vec<Property>,
    pub children: Vec<Component>,
}

impl Component {
    pub fn prop(&self, name: &str) -> Option<&Property> {
        self.props.iter().find(|p| p.name == name)
    }

    pub fn value(&self, name: &str) -> Option<&str> {
        self.prop(name).map(|p| p.value.as_str())
    }

    /// Replaces every property of that name with one new property (or removes it).
    pub fn set(&mut self, property: Option<Property>, name: &str) {
        let position = self.props.iter().position(|p| p.name == name);
        self.props.retain(|p| p.name != name);
        if let Some(property) = property {
            self.props.insert(position.unwrap_or(self.props.len()).min(self.props.len()), property);
        }
    }

    fn write(&self, out: &mut String) {
        out.push_str(&format!("BEGIN:{}\r\n", self.name));
        for property in &self.props {
            property.write(out);
        }
        for child in &self.children {
            child.write(out);
        }
        out.push_str(&format!("END:{}\r\n", self.name));
    }

    pub fn serialize(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }
}

/// Splits a content line into name, parameters and value, honouring quoted parameter values.
fn parse_line(line: &str) -> Option<Property> {
    let mut quoted = false;
    let mut colon = None;
    for (index, c) in line.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ':' if !quoted => {
                colon = Some(index);
                break;
            }
            _ => {}
        }
    }
    let colon = colon?;
    let (head, value) = (&line[..colon], &line[colon + 1..]);
    let mut parts: Vec<String> = Vec::new();
    let (mut current, mut quoted) = (String::new(), false);
    for c in head.chars() {
        match c {
            '"' => quoted = !quoted,
            ';' if !quoted => parts.push(std::mem::take(&mut current)),
            other => current.push(other),
        }
    }
    parts.push(current);
    let name = parts.first()?.trim().to_ascii_uppercase();
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') {
        return None;
    }
    let params = parts[1..].iter().filter_map(|part| part.split_once('=').map(|(key, value)| (key.trim().to_ascii_uppercase(), value.to_owned()))).collect();
    Some(Property { name, params, value: value.to_owned() })
}

/// Parses an iCalendar stream into its top-level `VCALENDAR` component.
pub fn parse(text: &str) -> Result<Component, String> {
    // Unfold: a line starting with a space or tab continues the previous one.
    let mut lines: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        match raw.strip_prefix([' ', '\t']) {
            Some(rest) if !lines.is_empty() => lines.last_mut().expect("checked non-empty").push_str(rest),
            _ if raw.is_empty() => {}
            _ => lines.push(raw.to_owned()),
        }
    }
    let mut stack: Vec<Component> = Vec::new();
    let mut root: Option<Component> = None;
    for line in &lines {
        let property = parse_line(line).ok_or_else(|| "malformed content line".to_owned())?;
        match property.name.as_str() {
            "BEGIN" => {
                if stack.len() >= 8 {
                    return Err("components are nested too deeply".into());
                }
                stack.push(Component { name: property.value.trim().to_ascii_uppercase(), ..Default::default() });
            }
            "END" => {
                let done = stack.pop().ok_or("END without BEGIN")?;
                if done.name != property.value.trim().to_ascii_uppercase() {
                    return Err("mismatched BEGIN and END".into());
                }
                match stack.last_mut() {
                    Some(parent) => parent.children.push(done),
                    None if root.is_none() => root = Some(done),
                    None => return Err("more than one top-level component".into()),
                }
            }
            _ => stack.last_mut().ok_or("property outside a component")?.props.push(property),
        }
    }
    if !stack.is_empty() {
        return Err("unterminated component".into());
    }
    let root = root.ok_or("no calendar data")?;
    if root.name != "VCALENDAR" { Err("the top-level component must be VCALENDAR".into()) } else { Ok(root) }
}

pub fn escape_text(value: &str) -> String {
    value.replace('\\', "\\\\").replace(';', "\\;").replace(',', "\\,").replace("\r\n", "\\n").replace(['\n', '\r'], "\\n")
}

pub fn unescape_text(value: &str) -> String {
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

/// A point in time as written in a `DTSTART`-like property.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Moment {
    /// Seconds since the epoch (UTC). For all-day values: midnight UTC of that day.
    pub at: i64,
    pub all_day: bool,
}

fn parse_date(value: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(value.get(..8)?, "%Y%m%d").ok()
}

/// Interprets a DATE or DATE-TIME value. Times without a zone ("floating") are wall-clock
/// times wherever the reader is, so they are read in `zone`, the reader's own time zone; so
/// are times in a zone this server does not know.
pub fn moment_in(property: &Property, zone: Tz) -> Option<Moment> {
    let value = property.value.trim();
    if property.param("VALUE") == Some("DATE") || (value.len() == 8 && !value.contains('T')) {
        return Some(Moment { at: parse_date(value)?.and_hms_opt(0, 0, 0)?.and_utc().timestamp(), all_day: true });
    }
    let naive = NaiveDateTime::parse_from_str(value.trim_end_matches('Z'), "%Y%m%dT%H%M%S").ok()?;
    let at = if value.ends_with('Z') {
        naive.and_utc().timestamp()
    } else {
        let zone = property.param("TZID").and_then(|tzid| tzid.parse::<Tz>().ok()).unwrap_or(zone);
        zone.from_local_datetime(&naive).earliest().map_or(naive.and_utc().timestamp(), |local| local.timestamp())
    };
    Some(Moment { at, all_day: false })
}

/// [`moment_in`] for values that are known to carry their zone (or to be in UTC).
pub fn moment(property: &Property) -> Option<Moment> {
    moment_in(property, Tz::UTC)
}

/// Parses an RFC 5545 DURATION such as `PT1H30M`, `P1D` or `P2W` into seconds.
pub fn duration_secs(value: &str) -> Option<i64> {
    let value = value.trim();
    let (sign, rest) = match value.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, value.strip_prefix('+').unwrap_or(value)),
    };
    let rest = rest.strip_prefix('P')?;
    let (mut total, mut number, mut time) = (0i64, String::new(), false);
    for c in rest.chars() {
        match c {
            'T' => time = true,
            '0'..='9' => number.push(c),
            unit => {
                let n: i64 = number.parse().ok()?;
                number.clear();
                total += n * match (unit, time) {
                    ('W', false) => 7 * 86400,
                    ('D', false) => 86400,
                    ('H', true) => 3600,
                    ('M', true) => 60,
                    ('S', true) => 1,
                    _ => return None,
                };
            }
        }
    }
    number.is_empty().then_some(sign * total)
}

/// Start and end (exclusive) of an event or to-do component.
fn span(component: &Component, zone: Tz) -> Option<(Moment, i64)> {
    let start = component.prop("DTSTART").or_else(|| component.prop("DUE")).and_then(|p| moment_in(p, zone))?;
    let end = match component.prop("DTEND").or_else(|| component.prop("DUE")).and_then(|p| moment_in(p, zone)) {
        Some(end) => end.at,
        None => match component.value("DURATION").and_then(duration_secs) {
            Some(seconds) => start.at + seconds,
            // RFC 5545: an all-day event without an end lasts one day, a timed one no time.
            None => start.at + if start.all_day { 86400 } else { 0 },
        },
    };
    Some((start, end.max(start.at)))
}

// --- People ---------------------------------------------------------------------------------

/// Somebody invited to an event.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Attendee {
    pub email: String,
    pub name: String,
    /// Participation status in lower case: `needs-action`, `accepted`, `tentative` or `declined`.
    pub status: String,
}

/// The e-mail address in an `ORGANIZER` or `ATTENDEE` property, in lower case.
pub fn address_of(property: &Property) -> Option<String> {
    let value = property.value.trim();
    let address = match value.get(..7) {
        Some(scheme) if scheme.eq_ignore_ascii_case("mailto:") => &value[7..],
        _ => value,
    };
    let address = address.trim().to_lowercase();
    (address.contains('@') && address.len() <= 320 && !address.chars().any(|c| c.is_whitespace() || c.is_control())).then_some(address)
}

pub fn organizer(component: &Component) -> Option<String> {
    component.prop("ORGANIZER").and_then(address_of)
}

pub fn attendees(component: &Component) -> Vec<Attendee> {
    component
        .props
        .iter()
        .filter(|p| p.name == "ATTENDEE")
        .filter_map(|p| {
            Some(Attendee {
                email: address_of(p)?,
                name: p.param("CN").unwrap_or("").chars().filter(|c| !c.is_control()).take(200).collect(),
                status: p.param("PARTSTAT").unwrap_or("NEEDS-ACTION").to_ascii_lowercase(),
            })
        })
        .collect()
}

/// The main event (or to-do) of a calendar object: the one that is not an overridden instance.
pub fn master(calendar: &Component) -> Option<&Component> {
    items(calendar).find(|c| c.prop("RECURRENCE-ID").is_none()).or_else(|| items(calendar).next())
}

/// What the server needs to know about a stored calendar object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    pub uid: String,
    /// `VEVENT` or `VTODO`.
    pub component: String,
    pub summary: String,
    /// Start of the first occurrence, if the object has a time at all.
    pub first_start: Option<i64>,
    /// End of the last occurrence; `None` when the object recurs without an end.
    pub last_end: Option<i64>,
}

fn items(calendar: &Component) -> impl Iterator<Item = &Component> {
    calendar.children.iter().filter(|c| c.name == "VEVENT" || c.name == "VTODO")
}

/// Validates an object for storage and extracts the indexed facts. A calendar object holds
/// exactly one event or to-do (possibly with overridden instances), all sharing one UID.
pub fn inspect(text: &str, zone: Tz) -> Result<ObjectInfo, String> {
    if text.len() > MAX_OBJECT_BYTES {
        return Err("the calendar object is too large".into());
    }
    let calendar = parse(text)?;
    let master = master(&calendar).ok_or("the object contains no event or to-do")?;
    let uid = master.value("UID").map(str::trim).filter(|uid| !uid.is_empty()).ok_or("the event has no UID")?.to_owned();
    if uid.len() > 255 || uid.chars().any(char::is_control) {
        return Err("invalid UID".into());
    }
    if items(&calendar).any(|c| c.name != master.name || c.value("UID").map(str::trim) != Some(uid.as_str())) {
        return Err("all components of one object must share the same UID and type".into());
    }
    let all = occurrences_of(&calendar, i64::MIN / 2, i64::MAX / 2, zone);
    let unbounded = all.limited;
    Ok(ObjectInfo {
        uid,
        component: master.name.clone(),
        summary: unescape_text(master.value("SUMMARY").unwrap_or("")).chars().filter(|c| !c.is_control()).take(300).collect(),
        first_start: all.list.iter().map(|o| o.start).min(),
        last_end: if unbounded { None } else { all.list.iter().map(|o| o.end).max() },
    })
}

/// One concrete occurrence of an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occurrence {
    pub start: i64,
    pub end: i64,
    pub all_day: bool,
    pub summary: String,
    pub location: String,
    pub description: String,
    /// Set for occurrences of a recurring event: the start it has (or would have) in the series.
    pub recurrence_id: Option<i64>,
    pub organizer: String,
    pub attendees: Vec<Attendee>,
    /// The moments at which the event's reminders are due.
    pub alarms: Vec<i64>,
    /// Whether the time counts as taken (not marked as free, not cancelled).
    pub busy: bool,
}

pub struct Expanded {
    pub list: Vec<Occurrence>,
    /// True when the series was cut off (it recurs forever or exceeds the limit).
    pub limited: bool,
}

fn text_of(component: &Component, name: &str, max: usize) -> String {
    unescape_text(component.value(name).unwrap_or("")).chars().filter(|c| !c.is_control() || *c == '\n').take(max).collect()
}

/// When the reminders of a component are due for an occurrence from `start` to `end`.
fn alarm_times(component: &Component, start: i64, end: i64, zone: Tz) -> Vec<i64> {
    component
        .children
        .iter()
        .filter(|c| c.name == "VALARM")
        .filter_map(|alarm| {
            let trigger = alarm.prop("TRIGGER")?;
            match duration_secs(&trigger.value) {
                Some(offset) => Some(if trigger.param("RELATED").is_some_and(|related| related.eq_ignore_ascii_case("END")) { end } else { start } + offset),
                None => moment_in(trigger, zone).map(|at| at.at),
            }
        })
        .take(10)
        .collect()
}

fn occurrence(component: &Component, start: i64, length: i64, all_day: bool, recurrence_id: Option<i64>, zone: Tz) -> Occurrence {
    let is = |name: &str, value: &str| component.value(name).is_some_and(|v| v.trim().eq_ignore_ascii_case(value));
    Occurrence {
        start,
        end: start + length,
        all_day,
        summary: text_of(component, "SUMMARY", 300),
        location: text_of(component, "LOCATION", 300),
        description: text_of(component, "DESCRIPTION", 5000),
        recurrence_id,
        organizer: organizer(component).unwrap_or_default(),
        attendees: attendees(component),
        alarms: alarm_times(component, start, start + length, zone),
        busy: !is("TRANSP", "TRANSPARENT") && !is("STATUS", "CANCELLED"),
    }
}

/// Rewrites a date or time property into the form the recurrence library expects: all-day
/// values become UTC times, zoned values keep their zone, floating ones get the reader's.
fn rule_line(property: &Property, all_day: bool, zone: Tz) -> Option<String> {
    let convert = |value: &str| -> Option<String> {
        let value = value.trim();
        if all_day || (value.len() == 8 && !value.contains('T')) {
            return Some(format!("{}T000000Z", value.get(..8)?));
        }
        Some(value.to_owned())
    };
    let values: Vec<String> = property.value.split(',').filter_map(convert).collect();
    let zone = property.param("TZID").and_then(|tzid| tzid.parse::<Tz>().ok()).unwrap_or(zone);
    if values.iter().all(|value| value.ends_with('Z')) {
        return Some(format!("{}:{}", property.name, values.join(",")));
    }
    if zone == Tz::UTC {
        let values: Vec<String> = values.into_iter().map(|v| if v.ends_with('Z') { v } else { format!("{v}Z") }).collect();
        return Some(format!("{}:{}", property.name, values.join(",")));
    }
    // One zone per line: a stray UTC value among local ones is rewritten into that zone.
    let values: Vec<String> = values
        .into_iter()
        .filter_map(|v| match v.strip_suffix('Z') {
            Some(utc) => Some(NaiveDateTime::parse_from_str(utc, "%Y%m%dT%H%M%S").ok()?.and_utc().with_timezone(&zone).format("%Y%m%dT%H%M%S").to_string()),
            None => Some(v),
        })
        .collect();
    Some(format!("{};TZID={}:{}", property.name, zone.name(), values.join(",")))
}

/// The start times of a recurring component between `from` and `to`.
fn recurrence_starts(master: &Component, start: Moment, from: i64, to: i64, zone: Tz) -> Option<(Vec<i64>, bool)> {
    let dtstart = master.prop("DTSTART")?;
    let mut lines = vec![rule_line(dtstart, start.all_day, zone)?];
    for property in &master.props {
        match property.name.as_str() {
            "RRULE" => {
                // UNTIL must be of the same kind as DTSTART: a UTC time in every case here.
                let rule: Vec<String> = property
                    .value
                    .split(';')
                    .map(|part| match part.split_once('=') {
                        Some((key, until)) if key.eq_ignore_ascii_case("UNTIL") => {
                            let until = until.trim();
                            if until.len() == 8 { format!("UNTIL={until}T235959Z") } else if until.ends_with('Z') { format!("UNTIL={until}") } else { format!("UNTIL={until}Z") }
                        }
                        _ => part.to_owned(),
                    })
                    .collect();
                lines.push(format!("RRULE:{}", rule.join(";")));
            }
            "EXDATE" | "RDATE" => lines.extend(rule_line(property, start.all_day, zone)),
            _ => {}
        }
    }
    let set: rrule::RRuleSet = lines.join("\n").parse().ok()?;
    let bound = |seconds: i64| Utc.timestamp_opt(seconds.clamp(-62_000_000_000, 250_000_000_000), 0).single().map(|t| t.with_timezone(&rrule::Tz::UTC));
    let result = set.after(bound(from)?).before(bound(to)?).all(MAX_OCCURRENCES);
    Some((result.dates.iter().map(|date| date.timestamp()).collect(), result.limited))
}

fn occurrences_of(calendar: &Component, from: i64, to: i64, zone: Tz) -> Expanded {
    let mut list = Vec::new();
    let mut limited = false;
    let overrides: Vec<(&Component, i64)> = items(calendar).filter_map(|c| Some((c, moment_in(c.prop("RECURRENCE-ID")?, zone)?.at))).collect();
    for master in items(calendar).filter(|c| c.prop("RECURRENCE-ID").is_none()) {
        let Some((start, end)) = span(master, zone) else { continue };
        let length = end - start.at;
        let recurring = master.prop("RRULE").is_some() || master.prop("RDATE").is_some();
        if !recurring {
            if start.at < to && end.max(start.at + 1) > from {
                list.push(occurrence(master, start.at, length, start.all_day, None, zone));
            }
            continue;
        }
        match recurrence_starts(master, start, from.saturating_sub(length), to, zone) {
            Some((starts, cut)) => {
                limited |= cut;
                for at in starts {
                    // An overridden instance is described by its own component instead.
                    if !overrides.iter().any(|(_, id)| *id == at) && at < to && at + length.max(1) > from {
                        list.push(occurrence(master, at, length, start.all_day, Some(at), zone));
                    }
                }
            }
            // A rule the library cannot read: show at least the first occurrence.
            None => {
                if start.at < to && end.max(start.at + 1) > from {
                    list.push(occurrence(master, start.at, length, start.all_day, Some(start.at), zone));
                }
            }
        }
    }
    for (component, id) in overrides {
        if component.value("STATUS").is_some_and(|status| status.eq_ignore_ascii_case("CANCELLED")) {
            continue;
        }
        if let Some((start, end)) = span(component, zone)
            && start.at < to
            && end.max(start.at + 1) > from
        {
            list.push(occurrence(component, start.at, end - start.at, start.all_day, Some(id), zone));
        }
    }
    list.sort_by_key(|o| o.start);
    Expanded { list, limited }
}

/// The occurrences of a stored object that overlap the window `[from, to)`.
pub fn occurrences(text: &str, from: i64, to: i64, zone: Tz) -> Vec<Occurrence> {
    parse(text).map(|calendar| occurrences_of(&calendar, from, to, zone).list).unwrap_or_default()
}

// --- Events from the web client -------------------------------------------------------------

pub const MAX_ATTENDEES: usize = 50;
/// Longest lead time of a reminder set in the web client: four weeks, in minutes.
pub const MAX_REMINDER_MINUTES: i64 = 28 * 24 * 60;

/// An event as the web client describes it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EventInput {
    pub summary: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub location: String,
    /// Local wall-clock time `YYYY-MM-DDTHH:MM`, or `YYYY-MM-DD` for all-day events.
    pub start: String,
    /// End, exclusive for timed events; for all-day events the last day (inclusive).
    pub end: String,
    #[serde(default)]
    pub all_day: bool,
    /// IANA time zone of the wall-clock times, e.g. `Europe/Warsaw`.
    #[serde(default)]
    pub timezone: String,
    /// Recurrence rule without the `RRULE:` prefix, e.g. `FREQ=WEEKLY;BYDAY=MO,WE`.
    #[serde(default)]
    pub rrule: String,
    /// E-mail addresses of the people invited.
    #[serde(default)]
    pub attendees: Vec<String>,
    /// Minutes before the start at which to remind, `null` for no reminder. A client that
    /// does not send the field at all leaves the alarms of the event as they are.
    #[serde(default, deserialize_with = "explicit")]
    pub reminder: Option<Option<i64>>,
}

/// Tells a field that is `null` (`Some(None)`) from one that is absent (`None`).
fn explicit<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<Option<i64>>, D::Error> {
    serde::Deserialize::deserialize(deserializer).map(Some)
}

/// The account on whose behalf an event is written: it becomes the organizer when people
/// are invited.
#[derive(Debug, Clone, Copy)]
pub struct Organizer<'a> {
    pub email: &'a str,
    pub name: &'a str,
}

/// The properties derived from validated web input: DTSTART, DTEND and the optional RRULE.
fn timing(input: &EventInput) -> Result<(Property, Property, Option<Property>), String> {
    let (mut start, mut end) = (Property::new("DTSTART", ""), Property::new("DTEND", ""));
    if input.all_day {
        let first = NaiveDate::parse_from_str(&input.start, "%Y-%m-%d").map_err(|_| "invalid start date")?;
        let last = NaiveDate::parse_from_str(&input.end, "%Y-%m-%d").map_err(|_| "invalid end date")?;
        if last < first {
            return Err("the event ends before it starts".into());
        }
        // iCalendar's end date is exclusive.
        start.value = first.format("%Y%m%d").to_string();
        end.value = (last + Duration::days(1)).format("%Y%m%d").to_string();
        for property in [&mut start, &mut end] {
            property.params.push(("VALUE".into(), "DATE".into()));
        }
    } else {
        let zone: Tz = input.timezone.parse().map_err(|_| "unknown time zone")?;
        let parse = |value: &str| NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M").or_else(|_| NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S"));
        let (first, last) = (parse(&input.start).map_err(|_| "invalid start time")?, parse(&input.end).map_err(|_| "invalid end time")?);
        if last < first {
            return Err("the event ends before it starts".into());
        }
        for (property, value) in [(&mut start, first), (&mut end, last)] {
            if zone == Tz::UTC {
                property.value = value.format("%Y%m%dT%H%M%SZ").to_string();
            } else {
                property.value = value.format("%Y%m%dT%H%M%S").to_string();
                property.params.push(("TZID".into(), zone.name().to_owned()));
            }
        }
    }
    let rule = input.rrule.trim().trim_start_matches("RRULE:").to_ascii_uppercase();
    let rule = if rule.is_empty() {
        None
    } else {
        if rule.len() > 300 || !rule.bytes().all(|b| b.is_ascii_alphanumeric() || b"=;,+-".contains(&b)) || !rule.starts_with("FREQ=") {
            return Err("invalid recurrence rule".into());
        }
        // Let the recurrence library have the last word on whether the rule makes sense.
        let probe = Component { name: "VEVENT".into(), props: vec![start.clone(), Property::new("RRULE", rule.clone())], children: Vec::new() };
        let at = moment(&start).ok_or("invalid start")?;
        recurrence_starts(&probe, at, at.at, at.at + 86400, Tz::UTC).ok_or("invalid recurrence rule")?;
        Some(Property::new("RRULE", rule))
    };
    Ok((start, end, rule))
}

fn stamp() -> String {
    Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

/// Rewrites the guest list. Guests that stay keep their answer; `me` becomes the organizer.
fn set_attendees(event: &mut Component, wanted: &[String], me: &Organizer<'_>) -> Result<(), String> {
    // An invitation from somebody else: the guest list is the organizer's to change.
    if organizer(event).is_some_and(|address| address != me.email) {
        return Ok(());
    }
    let mut emails: Vec<String> = Vec::new();
    for raw in wanted {
        let address = crate::util::Address::parse(raw.trim()).ok_or_else(|| format!("“{}” is not an e-mail address", raw.chars().filter(|c| !c.is_control()).take(80).collect::<String>()))?.to_string().to_lowercase();
        if address != me.email && !emails.contains(&address) {
            emails.push(address);
        }
    }
    if emails.len() > MAX_ATTENDEES {
        return Err(format!("at most {MAX_ATTENDEES} people can be invited"));
    }
    let existing: Vec<Property> = event.props.iter().filter(|p| p.name == "ATTENDEE").cloned().collect();
    event.props.retain(|p| p.name != "ATTENDEE" && p.name != "ORGANIZER");
    if emails.is_empty() {
        return Ok(());
    }
    let mut organizer = Property::new("ORGANIZER", format!("mailto:{}", me.email));
    let name: String = me.name.chars().filter(|c| !c.is_control()).take(100).collect();
    if !name.trim().is_empty() {
        organizer.params.push(("CN".into(), name.trim().to_owned()));
    }
    event.props.push(organizer);
    for email in emails {
        let invited = existing.iter().find(|p| address_of(p).as_deref() == Some(email.as_str())).cloned().unwrap_or_else(|| Property {
            name: "ATTENDEE".into(),
            params: [("CUTYPE", "INDIVIDUAL"), ("ROLE", "REQ-PARTICIPANT"), ("PARTSTAT", "NEEDS-ACTION"), ("RSVP", "TRUE")].into_iter().map(|(k, v)| (k.to_owned(), v.to_owned())).collect(),
            value: format!("mailto:{email}"),
        });
        event.props.push(invited);
    }
    Ok(())
}

/// The reminder of an event as the web client offers it: minutes before the start.
fn reminder_of(event: &Component) -> Option<i64> {
    let trigger = event.children.iter().find(|c| c.name == "VALARM")?.prop("TRIGGER")?;
    if trigger.param("RELATED").is_some_and(|related| related.eq_ignore_ascii_case("END")) {
        return None;
    }
    duration_secs(&trigger.value).filter(|offset| *offset <= 0).map(|offset| -offset / 60)
}

/// Sets the reminder. Alarms are only rewritten when the choice differs from what is there,
/// so the more elaborate alarms of calendar programs survive an edit of something else.
fn set_reminder(event: &mut Component, wanted: Option<Option<i64>>) -> Result<(), String> {
    let Some(minutes) = wanted else { return Ok(()) };
    if minutes.is_some_and(|m| !(0..=MAX_REMINDER_MINUTES).contains(&m)) {
        return Err("a reminder can be set up to four weeks ahead".into());
    }
    if reminder_of(event) == minutes {
        return Ok(());
    }
    event.children.retain(|c| c.name != "VALARM");
    if let Some(minutes) = minutes {
        event.children.push(Component {
            name: "VALARM".into(),
            props: vec![Property::new("ACTION", "DISPLAY"), Property::new("DESCRIPTION", "Reminder"), Property::new("TRIGGER", format!("-PT{minutes}M"))],
            children: Vec::new(),
        });
    }
    Ok(())
}

fn apply(event: &mut Component, input: &EventInput, organizer: Option<&Organizer<'_>>) -> Result<(), String> {
    let summary: String = input.summary.trim().chars().filter(|c| !c.is_control()).take(300).collect();
    if summary.is_empty() {
        return Err("the event needs a title".into());
    }
    if input.description.len() > 20_000 || input.location.chars().count() > 300 {
        return Err("the description or location is too long".into());
    }
    let (start, end, rule) = timing(input)?;
    event.set(Some(Property::new("SUMMARY", escape_text(&summary))), "SUMMARY");
    let optional = |name: &str, value: &str| (!value.trim().is_empty()).then(|| Property::new(name, escape_text(value.trim())));
    event.set(optional("DESCRIPTION", &input.description), "DESCRIPTION");
    event.set(optional("LOCATION", &input.location), "LOCATION");
    event.set(Some(start), "DTSTART");
    // The end is always written as DTEND; a DURATION would contradict it.
    event.set(None, "DURATION");
    event.set(Some(end), "DTEND");
    event.set(rule, "RRULE");
    if let Some(me) = organizer {
        set_attendees(event, &input.attendees, me)?;
    }
    set_reminder(event, input.reminder)?;
    event.set(Some(Property::new("LAST-MODIFIED", stamp())), "LAST-MODIFIED");
    event.set(Some(Property::new("DTSTAMP", stamp())), "DTSTAMP");
    Ok(())
}

fn bump_sequence(event: &mut Component) {
    let sequence = event.value("SEQUENCE").and_then(|s| s.trim().parse::<u32>().ok()).unwrap_or(0);
    event.set(Some(Property::new("SEQUENCE", (sequence + 1).to_string())), "SEQUENCE");
}

fn describe_component(event: &Component, zone: Tz, moved: Option<(i64, i64)>) -> Option<EventInput> {
    let start_property = event.prop("DTSTART")?;
    let start = moment_in(start_property, zone)?;
    let (from, to) = match moved {
        Some(span) => span,
        None => span(event, zone).map(|(start, end)| (start.at, end))?,
    };
    // Shown in the zone the event was written in; floating times in the reader's.
    let zone = if start_property.value.trim().ends_with('Z') { Tz::UTC } else { start_property.param("TZID").and_then(|tzid| tzid.parse::<Tz>().ok()).unwrap_or(zone) };
    let (first, last) = if start.all_day {
        let day = |at: i64| Utc.timestamp_opt(at, 0).single().map(|t| t.format("%Y-%m-%d").to_string());
        // The stored end is exclusive; the client works with the last day of the event.
        (day(from)?, day((to - 86400).max(from))?)
    } else {
        let local = |at: i64| zone.timestamp_opt(at, 0).single().map(|t| t.format("%Y-%m-%dT%H:%M").to_string());
        (local(from)?, local(to)?)
    };
    let own = organizer(event);
    Some(EventInput {
        summary: text_of(event, "SUMMARY", 300),
        description: text_of(event, "DESCRIPTION", 20_000),
        location: text_of(event, "LOCATION", 300),
        start: first,
        end: last,
        all_day: start.all_day,
        timezone: zone.name().to_owned(),
        rrule: event.value("RRULE").unwrap_or("").trim().to_owned(),
        attendees: attendees(event).into_iter().map(|a| a.email).filter(|email| Some(email) != own.as_ref()).collect(),
        reminder: Some(reminder_of(event)),
    })
}

fn main_event(calendar: &Component) -> Option<usize> {
    calendar.children.iter().position(|c| c.name == "VEVENT" && c.prop("RECURRENCE-ID").is_none())
}

fn override_index(calendar: &Component, recurrence_id: i64, zone: Tz) -> Option<usize> {
    calendar.children.iter().position(|c| c.name == "VEVENT" && c.prop("RECURRENCE-ID").and_then(|p| moment_in(p, zone)).is_some_and(|id| id.at == recurrence_id))
}

/// An event of a stored object in the form the web client edits (the inverse of
/// [`build_event`]): the main event, or with `recurrence_id` one occurrence of a series.
/// Wall-clock times are given in the zone the event was written in.
pub fn describe_event(text: &str, zone: Tz, recurrence_id: Option<i64>) -> Option<EventInput> {
    let calendar = parse(text).ok()?;
    let main = &calendar.children[main_event(&calendar)?];
    let Some(id) = recurrence_id else { return describe_component(main, zone, None) };
    if let Some(index) = override_index(&calendar, id, zone) {
        return describe_component(&calendar.children[index], zone, None).map(|event| EventInput { rrule: String::new(), ..event });
    }
    let (start, end) = span(main, zone)?;
    describe_component(main, zone, Some((id, id + (end - start.at)))).map(|event| EventInput { rrule: String::new(), ..event })
}

/// Builds a new calendar object for an event entered in the web client.
pub fn build_event(uid: &str, input: &EventInput, organizer: Option<&Organizer<'_>>) -> Result<String, String> {
    let mut event = Component { name: "VEVENT".into(), props: vec![Property::new("UID", uid), Property::new("SEQUENCE", "0")], children: Vec::new() };
    apply(&mut event, input, organizer)?;
    let calendar = Component {
        name: "VCALENDAR".into(),
        props: vec![Property::new("VERSION", "2.0"), Property::new("PRODID", "-//unoMail//Calendar//EN"), Property::new("CALSCALE", "GREGORIAN")],
        children: vec![event],
    };
    Ok(calendar.serialize())
}

/// Applies an edit from the web client to an existing object. Only the edited properties of
/// the main event change; alarms, attendees and anything else are kept. Overridden instances
/// are dropped when the timing changes, because they refer to times of the old series; the
/// guests are then asked again.
pub fn update_event(existing: &str, input: &EventInput, organizer: Option<&Organizer<'_>>) -> Result<String, String> {
    let mut calendar = parse(existing)?;
    let index = main_event(&calendar).ok_or("the object has no editable event")?;
    let timing = |event: &Component| (event.prop("DTSTART").cloned(), event.prop("DTEND").cloned(), event.prop("RRULE").cloned());
    let before = timing(&calendar.children[index]);
    apply(&mut calendar.children[index], input, organizer)?;
    let event = &mut calendar.children[index];
    bump_sequence(event);
    let after = timing(event);
    if before != after {
        if organizer.is_some_and(|me| self::organizer(event).as_deref() == Some(me.email)) {
            for attendee in event.props.iter_mut().filter(|p| p.name == "ATTENDEE") {
                attendee.params.retain(|(key, _)| key != "PARTSTAT");
                attendee.params.push(("PARTSTAT".into(), "NEEDS-ACTION".into()));
            }
        }
        if (&before.0, &before.2) != (&after.0, &after.2) {
            event.set(None, "EXDATE");
            calendar.children.retain(|c| c.prop("RECURRENCE-ID").is_none());
        }
    }
    Ok(calendar.serialize())
}

/// A property naming the moment `at` in the same form as `model` (the start of the series):
/// a date for all-day events, UTC, or a wall-clock time in the model's zone.
fn stamp_like(model: &Property, name: &str, at: i64, zone: Tz) -> Option<Property> {
    let time = Utc.timestamp_opt(at, 0).single()?;
    let mut property = Property::new(name, "");
    if moment_in(model, zone)?.all_day {
        property.params.push(("VALUE".into(), "DATE".into()));
        property.value = time.format("%Y%m%d").to_string();
    } else if model.value.trim().ends_with('Z') {
        property.value = time.format("%Y%m%dT%H%M%SZ").to_string();
    } else {
        let named = model.param("TZID").and_then(|tzid| Some((tzid, tzid.parse::<Tz>().ok()?)));
        property.value = time.with_timezone(&named.map_or(zone, |(_, zone)| zone)).format("%Y%m%dT%H%M%S").to_string();
        if let Some((tzid, _)) = named {
            property.params.push(("TZID".into(), tzid.to_owned()));
        }
    }
    Some(property)
}

/// Removes one occurrence from a recurring event by excluding its date from the series.
pub fn exclude_occurrence(existing: &str, occurrence_start: i64, zone: Tz) -> Result<String, String> {
    let mut calendar = parse(existing)?;
    calendar.children.retain(|c| c.prop("RECURRENCE-ID").and_then(|p| moment_in(p, zone)).is_none_or(|id| id.at != occurrence_start));
    let event = calendar.children.iter_mut().find(|c| c.name == "VEVENT" && c.prop("RECURRENCE-ID").is_none()).ok_or("the object has no event")?;
    let start = event.prop("DTSTART").cloned().ok_or("the event has no start")?;
    event.props.push(stamp_like(&start, "EXDATE", occurrence_start, zone).ok_or("invalid occurrence")?);
    bump_sequence(event);
    Ok(calendar.serialize())
}

/// Changes one occurrence of a recurring event, leaving the rest of the series as it is: the
/// occurrence gets a component of its own that overrides what the rule says.
pub fn override_occurrence(existing: &str, recurrence_id: i64, input: &EventInput, zone: Tz) -> Result<String, String> {
    let mut calendar = parse(existing)?;
    let main = calendar.children[main_event(&calendar).ok_or("the object has no editable event")?].clone();
    let model = main.prop("DTSTART").ok_or("the event has no start")?;
    let mut instance = match override_index(&calendar, recurrence_id, zone) {
        Some(index) => calendar.children.remove(index),
        None => {
            if !occurrences_of(&calendar, recurrence_id, recurrence_id + 1, zone).list.iter().any(|o| o.recurrence_id == Some(recurrence_id)) {
                return Err("the event has no such occurrence".into());
            }
            let mut copy = main.clone();
            copy.props.retain(|p| !matches!(p.name.as_str(), "RRULE" | "EXDATE" | "RDATE"));
            let after_uid = copy.props.iter().position(|p| p.name == "UID").map_or(0, |index| index + 1);
            copy.props.insert(after_uid, stamp_like(model, "RECURRENCE-ID", recurrence_id, zone).ok_or("invalid occurrence")?);
            copy
        }
    };
    // The guest list belongs to the series; a single occurrence does not repeat.
    apply(&mut instance, &EventInput { rrule: String::new(), ..input.clone() }, None)?;
    bump_sequence(&mut instance);
    calendar.children.push(instance);
    Ok(calendar.serialize())
}

// --- To-dos ----------------------------------------------------------------------------------

/// A to-do as the web client describes it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TodoInput {
    pub summary: String,
    #[serde(default)]
    pub description: String,
    /// The day it is due, `YYYY-MM-DD`; empty for no date.
    #[serde(default)]
    pub due: String,
    #[serde(default)]
    pub completed: bool,
}

pub fn describe_todo(text: &str, zone: Tz) -> Option<TodoInput> {
    let calendar = parse(text).ok()?;
    let todo = calendar.children.iter().find(|c| c.name == "VTODO" && c.prop("RECURRENCE-ID").is_none())?;
    let due = todo.prop("DUE").and_then(|p| moment_in(p, zone)).and_then(|due| {
        let at = Utc.timestamp_opt(due.at, 0).single()?;
        Some(if due.all_day { at.format("%Y-%m-%d").to_string() } else { at.with_timezone(&zone).format("%Y-%m-%d").to_string() })
    });
    let done = todo.value("STATUS").is_some_and(|status| status.trim().eq_ignore_ascii_case("COMPLETED")) || todo.prop("COMPLETED").is_some();
    Some(TodoInput { summary: text_of(todo, "SUMMARY", 300), description: text_of(todo, "DESCRIPTION", 20_000), due: due.unwrap_or_default(), completed: done })
}

fn apply_todo(todo: &mut Component, input: &TodoInput, zone: Tz) -> Result<(), String> {
    let summary: String = input.summary.trim().chars().filter(|c| !c.is_control()).take(300).collect();
    if summary.is_empty() {
        return Err("the task needs a title".into());
    }
    if input.description.len() > 20_000 {
        return Err("the description is too long".into());
    }
    todo.set(Some(Property::new("SUMMARY", escape_text(&summary))), "SUMMARY");
    todo.set((!input.description.trim().is_empty()).then(|| Property::new("DESCRIPTION", escape_text(input.description.trim()))), "DESCRIPTION");
    // A due time set by a calendar program is kept as long as the day stays the same.
    let current = todo.prop("DUE").and_then(|p| moment_in(p, zone)).and_then(|due| {
        let at = Utc.timestamp_opt(due.at, 0).single()?;
        Some(if due.all_day { at.format("%Y-%m-%d").to_string() } else { at.with_timezone(&zone).format("%Y-%m-%d").to_string() })
    });
    if current.as_deref().unwrap_or("") != input.due.trim() {
        let due = match input.due.trim() {
            "" => None,
            day => {
                let date = NaiveDate::parse_from_str(day, "%Y-%m-%d").map_err(|_| "invalid due date")?;
                Some(Property { name: "DUE".into(), params: vec![("VALUE".into(), "DATE".into())], value: date.format("%Y%m%d").to_string() })
            }
        };
        todo.set(due, "DUE");
    }
    let was_done = todo.value("STATUS").is_some_and(|status| status.trim().eq_ignore_ascii_case("COMPLETED"));
    if input.completed != was_done {
        todo.set(Some(Property::new("STATUS", if input.completed { "COMPLETED" } else { "NEEDS-ACTION" })), "STATUS");
        todo.set(input.completed.then(|| Property::new("COMPLETED", stamp())), "COMPLETED");
        todo.set(Some(Property::new("PERCENT-COMPLETE", if input.completed { "100" } else { "0" })), "PERCENT-COMPLETE");
    }
    todo.set(Some(Property::new("LAST-MODIFIED", stamp())), "LAST-MODIFIED");
    todo.set(Some(Property::new("DTSTAMP", stamp())), "DTSTAMP");
    Ok(())
}

pub fn build_todo(uid: &str, input: &TodoInput) -> Result<String, String> {
    let mut todo = Component { name: "VTODO".into(), props: vec![Property::new("UID", uid), Property::new("SEQUENCE", "0")], children: Vec::new() };
    apply_todo(&mut todo, input, Tz::UTC)?;
    let calendar = Component {
        name: "VCALENDAR".into(),
        props: vec![Property::new("VERSION", "2.0"), Property::new("PRODID", "-//unoMail//Calendar//EN"), Property::new("CALSCALE", "GREGORIAN")],
        children: vec![todo],
    };
    Ok(calendar.serialize())
}

pub fn update_todo(existing: &str, input: &TodoInput, zone: Tz) -> Result<String, String> {
    let mut calendar = parse(existing)?;
    let todo = calendar.children.iter_mut().find(|c| c.name == "VTODO" && c.prop("RECURRENCE-ID").is_none()).ok_or("the object has no task")?;
    apply_todo(todo, input, zone)?;
    bump_sequence(todo);
    Ok(calendar.serialize())
}

/// Splits a stream holding several events (an exported calendar, an invitation) into one
/// object per UID, each a complete VCALENDAR ready to be stored.
pub fn split_objects(text: &str) -> Result<Vec<String>, String> {
    let calendar = parse(text)?;
    let mut uids: Vec<String> = Vec::new();
    for item in items(&calendar) {
        let uid = item.value("UID").map(str::trim).unwrap_or("").to_owned();
        if !uid.is_empty() && !uids.contains(&uid) {
            uids.push(uid);
        }
    }
    let shell: Vec<Property> = calendar.props.iter().filter(|p| p.name != "METHOD").cloned().collect();
    Ok(uids
        .into_iter()
        .map(|uid| {
            let children = calendar.children.iter().filter(|c| c.name == "VTIMEZONE" || ((c.name == "VEVENT" || c.name == "VTODO") && c.value("UID").map(str::trim) == Some(uid.as_str()))).cloned().collect();
            Component { name: "VCALENDAR".into(), props: shell.clone(), children }.serialize()
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Most tests do not care about floating times: read them as UTC.
    fn inspect(text: &str) -> Result<ObjectInfo, String> {
        super::inspect(text, Tz::UTC)
    }

    fn occurrences(text: &str, from: i64, to: i64) -> Vec<Occurrence> {
        super::occurrences(text, from, to, Tz::UTC)
    }

    fn build_event(uid: &str, input: &EventInput) -> Result<String, String> {
        super::build_event(uid, input, None)
    }

    fn update_event(existing: &str, input: &EventInput) -> Result<String, String> {
        super::update_event(existing, input, None)
    }

    const ME: Organizer<'static> = Organizer { email: "bob@example.org", name: "Bob Example" };

    fn at(text: &str) -> i64 {
        NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M").unwrap().and_utc().timestamp()
    }

    const MEETING: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nBEGIN:VEVENT\r\nUID:meeting-1@example.org\r\nDTSTAMP:20261001T000000Z\r\n\
DTSTART;TZID=Europe/Warsaw:20261013T100000\r\nDTEND;TZID=Europe/Warsaw:20261013T113000\r\nSUMMARY:Planning\\, part 1\r\nLOCATION:Room 4\r\n\
DESCRIPTION:Agenda:\\n- budget\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn parsing_keeps_everything_and_serialising_round_trips() {
        let calendar = parse(MEETING).unwrap();
        assert_eq!(calendar.children.len(), 1);
        let event = &calendar.children[0];
        assert_eq!(event.prop("DTSTART").unwrap().param("TZID"), Some("Europe/Warsaw"));
        assert_eq!(event.children[0].name, "VALARM");
        assert_eq!(calendar.serialize(), MEETING);

        // Folded lines, quoted parameters and bare LF line endings are understood.
        let folded = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:x\nATTENDEE;CN=\"Doe; John: Jr\";ROLE=CHAIR:mailto:john@example.org\nSUMMARY:A very long\n  title\nEND:VEVENT\nEND:VCALENDAR\n";
        let parsed = parse(folded).unwrap();
        let event = &parsed.children[0];
        assert_eq!(event.value("SUMMARY"), Some("A very long title"));
        assert_eq!(event.prop("ATTENDEE").unwrap().param("CN"), Some("Doe; John: Jr"));
        assert!(parsed.serialize().contains("ATTENDEE;CN=\"Doe; John: Jr\";ROLE=CHAIR:mailto:john@example.org\r\n"));

        let long = Property::new("DESCRIPTION", "ż".repeat(100));
        let mut out = String::new();
        long.write(&mut out);
        assert!(out.lines().all(|line| line.len() <= 75), "lines are folded on character boundaries");
        assert_eq!(parse(&format!("BEGIN:VCALENDAR\r\n{out}END:VCALENDAR\r\n")).unwrap().value("DESCRIPTION"), Some("ż".repeat(100).as_str()));

        for bad in ["", "hello", "BEGIN:VEVENT\nEND:VEVENT\n", "BEGIN:VCALENDAR\nBEGIN:VEVENT\nEND:VCALENDAR\n", "BEGIN:VCALENDAR\nEND:VCALENDAR\nBEGIN:VCALENDAR\nEND:VCALENDAR\n", "BEGIN:VCALENDAR\nno colon here\nEND:VCALENDAR\n"] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn objects_are_validated_and_indexed() {
        let info = inspect(MEETING).unwrap();
        assert_eq!((info.uid.as_str(), info.component.as_str(), info.summary.as_str()), ("meeting-1@example.org", "VEVENT", "Planning, part 1"));
        // 10:00 in Warsaw is 08:00 UTC in October (summer time).
        assert_eq!((info.first_start, info.last_end), (Some(at("2026-10-13 08:00")), Some(at("2026-10-13 09:30"))));

        let todo = "BEGIN:VCALENDAR\nBEGIN:VTODO\nUID:t1\nSUMMARY:Pay invoice\nDUE;VALUE=DATE:20261020\nEND:VTODO\nEND:VCALENDAR\n";
        assert_eq!(inspect(todo).unwrap().component, "VTODO");
        let forever = MEETING.replace("SUMMARY:", "RRULE:FREQ=DAILY\r\nSUMMARY:");
        assert_eq!(inspect(&forever).unwrap().last_end, None, "an endless series has no last end");
        let counted = MEETING.replace("SUMMARY:", "RRULE:FREQ=DAILY;COUNT=3\r\nSUMMARY:");
        assert_eq!(inspect(&counted).unwrap().last_end, Some(at("2026-10-15 09:30")));

        for bad in [
            "BEGIN:VCALENDAR\nEND:VCALENDAR\n".to_owned(),
            MEETING.replace("UID:meeting-1@example.org\r\n", ""),
            MEETING.replace("END:VEVENT", "END:VEVENT\r\nBEGIN:VEVENT\r\nUID:another\r\nDTSTART:20261014T100000Z\r\nEND:VEVENT"),
            format!("BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:x\nDESCRIPTION:{}\nEND:VEVENT\nEND:VCALENDAR\n", "x".repeat(MAX_OBJECT_BYTES)),
        ] {
            assert!(inspect(&bad).is_err(), "{}", &bad[..bad.len().min(80)]);
        }
    }

    #[test]
    fn durations_and_moments() {
        assert_eq!(duration_secs("PT1H30M"), Some(5400));
        assert_eq!(duration_secs("P1DT12H"), Some(129_600));
        assert_eq!(duration_secs("P2W"), Some(1_209_600));
        assert_eq!(duration_secs("-PT15M"), Some(-900));
        for bad in ["", "1H", "PT", "P1H", "PT5X", "PT5"] {
            assert_eq!(duration_secs(bad), if bad == "PT" { Some(0) } else { None }, "{bad:?}");
        }
        let date = Property { name: "DTSTART".into(), params: vec![("VALUE".into(), "DATE".into())], value: "20261013".into() };
        assert_eq!(moment(&date), Some(Moment { at: at("2026-10-13 00:00"), all_day: true }));
        assert_eq!(moment(&Property::new("DTSTART", "20261013T100000Z")).unwrap().at, at("2026-10-13 10:00"));
        let unknown_zone = Property { name: "DTSTART".into(), params: vec![("TZID".into(), "Mars/Olympus".into())], value: "20261013T100000".into() };
        assert_eq!(moment(&unknown_zone).unwrap().at, at("2026-10-13 10:00"), "unknown zones are read as UTC");
        assert_eq!(moment(&Property::new("DTSTART", "garbage")), None);
    }

    #[test]
    fn recurring_events_expand_with_time_zones_exceptions_and_overrides() {
        // Weekly on Tuesdays, 10:00 Warsaw time, across the end of summer time.
        let weekly = MEETING.replace("SUMMARY:", "RRULE:FREQ=WEEKLY;COUNT=4\r\nSUMMARY:");
        let all = occurrences(&weekly, at("2026-10-01 00:00"), at("2026-12-01 00:00"));
        let starts: Vec<i64> = all.iter().map(|o| o.start).collect();
        assert_eq!(starts, [at("2026-10-13 08:00"), at("2026-10-20 08:00"), at("2026-10-27 09:00"), at("2026-11-03 09:00")], "the wall-clock time stays 10:00 after the clocks change");
        assert!(all.iter().all(|o| o.end - o.start == 5400 && o.recurrence_id == Some(o.start) && o.summary == "Planning, part 1"));

        // A window returns only what overlaps it.
        assert_eq!(occurrences(&weekly, at("2026-10-20 00:00"), at("2026-10-21 00:00")).len(), 1);
        assert_eq!(occurrences(&weekly, at("2026-10-20 09:00"), at("2026-10-20 09:10")).len(), 1, "an event in progress overlaps the window");
        assert!(occurrences(&weekly, at("2027-01-01 00:00"), at("2027-02-01 00:00")).is_empty());

        // One date excluded, one instance moved and renamed.
        let changed = weekly.replace("SUMMARY:Planning", "EXDATE;TZID=Europe/Warsaw:20261020T100000\r\nSUMMARY:Planning").replace(
            "END:VEVENT\r\nEND:VCALENDAR",
            "END:VEVENT\r\nBEGIN:VEVENT\r\nUID:meeting-1@example.org\r\nRECURRENCE-ID;TZID=Europe/Warsaw:20261027T100000\r\nDTSTART;TZID=Europe/Warsaw:20261028T140000\r\nDTEND;TZID=Europe/Warsaw:20261028T150000\r\nSUMMARY:Planning (moved)\r\nEND:VEVENT\r\nEND:VCALENDAR",
        );
        let list = occurrences(&changed, at("2026-10-01 00:00"), at("2026-12-01 00:00"));
        let described: Vec<(i64, &str)> = list.iter().map(|o| (o.start, o.summary.as_str())).collect();
        assert_eq!(described, [(at("2026-10-13 08:00"), "Planning, part 1"), (at("2026-10-28 13:00"), "Planning (moved)"), (at("2026-11-03 09:00"), "Planning, part 1")]);
        assert_eq!(list[1].recurrence_id, Some(at("2026-10-27 09:00")));
        assert!(inspect(&changed).is_ok());

        // All-day yearly event with an UNTIL date; a rule the library rejects still shows once.
        let birthday = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:b1\nDTSTART;VALUE=DATE:20200229\nRRULE:FREQ=YEARLY;UNTIL=20281231\nSUMMARY:Leap day\nEND:VEVENT\nEND:VCALENDAR\n";
        let days = occurrences(birthday, at("2020-01-01 00:00"), at("2030-01-01 00:00"));
        assert_eq!(days.iter().map(|o| o.start).collect::<Vec<_>>(), [at("2020-02-29 00:00"), at("2024-02-29 00:00"), at("2028-02-29 00:00")]);
        assert!(days.iter().all(|o| o.all_day && o.end - o.start == 86400));
        let broken = MEETING.replace("SUMMARY:", "RRULE:FREQ=SOMETIMES\r\nSUMMARY:");
        assert_eq!(occurrences(&broken, at("2026-10-01 00:00"), at("2026-12-01 00:00")).len(), 1);
        // An endless daily series is cut off rather than expanded forever.
        let endless = MEETING.replace("SUMMARY:", "RRULE:FREQ=DAILY\r\nSUMMARY:");
        assert_eq!(occurrences(&endless, at("2026-01-01 00:00"), at("2100-01-01 00:00")).len(), MAX_OCCURRENCES as usize);
    }

    fn input() -> EventInput {
        EventInput { summary: "Lunch; with Ann, maybe".into(), description: "Bring\nthe report".into(), location: "Café".into(), start: "2026-10-14T12:30".into(), end: "2026-10-14T13:30".into(), all_day: false, timezone: "Europe/Warsaw".into(), rrule: String::new(), ..Default::default() }
    }

    #[test]
    fn events_from_the_web_client_are_built_and_validated() {
        let built = build_event("abc@unomail", &input()).unwrap();
        assert!(built.contains("DTSTART;TZID=Europe/Warsaw:20261014T123000\r\n") && built.contains("SUMMARY:Lunch\\; with Ann\\, maybe\r\n") && built.contains("DESCRIPTION:Bring\\nthe report\r\n"));
        let info = inspect(&built).unwrap();
        assert_eq!((info.uid.as_str(), info.first_start), ("abc@unomail", Some(at("2026-10-14 10:30"))));
        let seen = occurrences(&built, at("2026-10-14 00:00"), at("2026-10-15 00:00"));
        assert_eq!((seen[0].summary.as_str(), seen[0].description.as_str(), seen[0].location.as_str()), ("Lunch; with Ann, maybe", "Bring\nthe report", "Café"));

        // All-day: the end day entered is inclusive, the stored one exclusive.
        let holiday = build_event("h", &EventInput { all_day: true, start: "2026-12-24".into(), end: "2026-12-26".into(), ..input() }).unwrap();
        assert!(holiday.contains("DTSTART;VALUE=DATE:20261224\r\n") && holiday.contains("DTEND;VALUE=DATE:20261227\r\n"));
        let weekly = build_event("w", &EventInput { rrule: "freq=weekly;byday=mo,we;count=4".into(), ..input() }).unwrap();
        assert!(weekly.contains("RRULE:FREQ=WEEKLY;BYDAY=MO,WE;COUNT=4\r\n"));
        assert_eq!(occurrences(&weekly, at("2026-10-01 00:00"), at("2026-12-01 00:00")).len(), 4);
        let utc = build_event("u", &EventInput { timezone: "UTC".into(), ..input() }).unwrap();
        assert!(utc.contains("DTSTART:20261014T123000Z\r\n"));

        for bad in [
            EventInput { summary: "  ".into(), ..input() },
            EventInput { start: "yesterday".into(), ..input() },
            EventInput { end: "2026-10-14T11:00".into(), ..input() },
            EventInput { timezone: "Mars/Olympus".into(), ..input() },
            EventInput { rrule: "FREQ=WEEKLY\r\nATTENDEE:mailto:evil@x.example".into(), ..input() },
            EventInput { rrule: "BYDAY=MO".into(), ..input() },
            EventInput { rrule: "FREQ=SOMETIMES".into(), ..input() },
            EventInput { all_day: true, start: "2026-12-24".into(), end: "2026-12-20".into(), ..input() },
        ] {
            assert!(build_event("x", &bad).is_err(), "{bad:?}");
        }
        // A title cannot smuggle in extra properties.
        let injected = build_event("i", &EventInput { summary: "Hi\r\nATTENDEE:mailto:evil@x.example".into(), ..input() }).unwrap();
        assert!(!injected.contains("\r\nATTENDEE"));
    }

    #[test]
    fn edits_keep_what_other_programs_stored() {
        let edited = update_event(MEETING, &EventInput { summary: "Planning, final".into(), start: "2026-10-13T11:00".into(), end: "2026-10-13T12:00".into(), ..input() }).unwrap();
        assert!(edited.contains("BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nEND:VALARM"), "the reminder survives");
        assert!(edited.contains("SUMMARY:Planning\\, final\r\n") && edited.contains("DTSTART;TZID=Europe/Warsaw:20261013T110000\r\n") && edited.contains("SEQUENCE:1\r\n"));
        assert!(edited.contains("UID:meeting-1@example.org") && edited.contains("PRODID:-//Test//EN"));
        assert_eq!(inspect(&edited).unwrap().first_start, Some(at("2026-10-13 09:00")));

        // Removing one occurrence of a series.
        let weekly = MEETING.replace("SUMMARY:", "RRULE:FREQ=WEEKLY;COUNT=3\r\nSUMMARY:");
        let without = exclude_occurrence(&weekly, at("2026-10-20 08:00"), Tz::UTC).unwrap();
        assert!(without.contains("EXDATE;TZID=Europe/Warsaw:20261020T100000\r\n"), "written like the start of the series");
        assert_eq!(occurrences(&without, at("2026-10-01 00:00"), at("2026-12-01 00:00")).iter().map(|o| o.start).collect::<Vec<_>>(), [at("2026-10-13 08:00"), at("2026-10-27 09:00")]);
    }

    #[test]
    fn a_stream_with_several_events_is_split_per_event() {
        let export = "BEGIN:VCALENDAR\nVERSION:2.0\nMETHOD:PUBLISH\nBEGIN:VTIMEZONE\nTZID:Europe/Warsaw\nEND:VTIMEZONE\nBEGIN:VEVENT\nUID:a\nDTSTART:20261013T100000Z\nEND:VEVENT\n\
BEGIN:VEVENT\nUID:b\nDTSTART:20261014T100000Z\nRRULE:FREQ=DAILY;COUNT=2\nEND:VEVENT\nBEGIN:VEVENT\nUID:b\nRECURRENCE-ID:20261015T100000Z\nDTSTART:20261015T120000Z\nEND:VEVENT\nEND:VCALENDAR\n";
        let objects = split_objects(export).unwrap();
        assert_eq!(objects.len(), 2);
        assert_eq!(inspect(&objects[0]).unwrap().uid, "a");
        assert!(objects[1].matches("BEGIN:VEVENT").count() == 2 && objects[1].contains("BEGIN:VTIMEZONE") && !objects[1].contains("METHOD"));
        assert!(split_objects("BEGIN:VCALENDAR\nEND:VCALENDAR\n").unwrap().is_empty());
    }

    #[test]
    fn times_without_a_zone_are_wall_clock_times_of_the_reader() {
        let floating = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:f1\nDTSTART:20261013T100000\nDTEND:20261013T110000\nRRULE:FREQ=WEEKLY;COUNT=3\nEXDATE:20261020T100000\nSUMMARY:Ten o'clock\nEND:VEVENT\nEND:VCALENDAR\n";
        let warsaw: Tz = "Europe/Warsaw".parse().unwrap();
        let new_york: Tz = "America/New_York".parse().unwrap();
        // Across the end of summer time the event stays at ten on the reader's clock.
        assert_eq!(super::occurrences(floating, 0, i64::MAX / 4, warsaw).iter().map(|o| o.start).collect::<Vec<_>>(), [at("2026-10-13 08:00"), at("2026-10-27 09:00")]);
        assert_eq!(super::occurrences(floating, 0, i64::MAX / 4, new_york).iter().map(|o| o.start).collect::<Vec<_>>(), [at("2026-10-13 14:00"), at("2026-10-27 14:00")]);
        assert_eq!(occurrences(floating, 0, i64::MAX / 4)[0].start, at("2026-10-13 10:00"));
        assert_eq!(super::inspect(floating, warsaw).unwrap().first_start, Some(at("2026-10-13 08:00")));
        let described = describe_event(floating, warsaw, None).unwrap();
        assert_eq!((described.start.as_str(), described.timezone.as_str()), ("2026-10-13T10:00", "Europe/Warsaw"));
        // Excluding and overriding an occurrence write floating times again.
        let without = exclude_occurrence(floating, at("2026-10-13 08:00"), warsaw).unwrap();
        assert!(without.contains("EXDATE:20261013T100000\r\n"), "{without}");
        assert_eq!(super::occurrences(&without, 0, i64::MAX / 4, warsaw).len(), 1);
        // A zone the server does not know is treated the same way.
        let outlook = floating.replace("DTSTART:", "DTSTART;TZID=Central European Standard Time:");
        assert_eq!(super::occurrences(&outlook, 0, i64::MAX / 4, warsaw)[0].start, at("2026-10-13 08:00"));
    }

    #[test]
    fn guests_and_reminders() {
        let invited = EventInput { attendees: vec!["Carol@Example.org".into(), "bob@example.org".into(), "carol@example.org".into(), "dan@remote.example".into()], reminder: Some(Some(30)), ..input() };
        let built = super::build_event("g1", &invited, Some(&ME)).unwrap();
        assert!(built.contains("ORGANIZER;CN=Bob Example:mailto:bob@example.org\r\n"), "{built}");
        let event = parse(&built).unwrap().children.remove(0);
        assert_eq!(attendees(&event).iter().map(|a| (a.email.as_str(), a.status.as_str())).collect::<Vec<_>>(), [("carol@example.org", "needs-action"), ("dan@remote.example", "needs-action")], "no duplicates, not the organizer");
        assert!(built.contains("BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Reminder\r\nTRIGGER:-PT30M\r\nEND:VALARM"));
        let seen = occurrences(&built, 0, i64::MAX / 4);
        assert_eq!(seen[0].alarms, [at("2026-10-14 10:00")], "half an hour before 12:30 in Warsaw");
        assert_eq!(seen[0].organizer, "bob@example.org");
        let described = describe_event(&built, Tz::UTC, None).unwrap();
        assert_eq!((described.attendees.clone(), described.reminder), (vec!["carol@example.org".to_owned(), "dan@remote.example".to_owned()], Some(Some(30))));
        assert_eq!(described, EventInput { attendees: described.attendees.clone(), ..invited.clone() }, "the editor gets back what was entered");

        // An answer survives an edit of the title, but not a change of the time.
        // (Long lines are folded: unfold before editing the text.)
        let accepted = built.replace("\r\n ", "").replace("PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:carol", "PARTSTAT=ACCEPTED;RSVP=TRUE:mailto:carol");
        let renamed = super::update_event(&accepted, &EventInput { summary: "Renamed".into(), ..described.clone() }, Some(&ME)).unwrap();
        assert_eq!(attendees(&parse(&renamed).unwrap().children[0])[0].status, "accepted");
        let moved = super::update_event(&accepted, &EventInput { start: "2026-10-15T12:30".into(), end: "2026-10-15T13:30".into(), ..described.clone() }, Some(&ME)).unwrap();
        assert_eq!(attendees(&parse(&moved).unwrap().children[0])[0].status, "needs-action");
        // Removing everyone removes the organizer too; removing the reminder removes the alarm.
        let alone = super::update_event(&accepted, &EventInput { attendees: Vec::new(), reminder: Some(None), ..described.clone() }, Some(&ME)).unwrap();
        assert!(!alone.contains("ORGANIZER") && !alone.contains("ATTENDEE") && !alone.contains("VALARM"), "{alone}");

        // Somebody else's invitation: the guest list is not ours to change.
        let foreign = accepted.replace("mailto:bob@example.org", "mailto:boss@example.org");
        let edited = super::update_event(&foreign, &EventInput { attendees: vec!["eve@example.org".into()], ..described.clone() }, Some(&ME)).unwrap();
        assert!(edited.contains("mailto:boss@example.org") && edited.contains("mailto:carol@example.org") && !edited.contains("eve@"));

        // Alarms of calendar programs that the editor cannot express are left alone.
        let fancy = MEETING.replace("TRIGGER:-PT15M", "TRIGGER;VALUE=DATE-TIME:20261013T070000Z");
        assert_eq!(occurrences(&fancy, 0, i64::MAX / 4)[0].alarms, [at("2026-10-13 07:00")]);
        let kept = update_event(&fancy, &describe_event(&fancy, Tz::UTC, None).unwrap()).unwrap();
        assert!(kept.contains("TRIGGER;VALUE=DATE-TIME:20261013T070000Z"));
        // A client that says nothing about reminders changes none; an explicit "none" removes them.
        let silent: EventInput = serde_json::from_str(r#"{"summary":"S","start":"2026-10-13T10:00","end":"2026-10-13T11:00","timezone":"UTC"}"#).unwrap();
        assert_eq!(silent.reminder, None);
        assert!(update_event(MEETING, &silent).unwrap().contains("TRIGGER:-PT15M"));
        let none: EventInput = serde_json::from_str(r#"{"summary":"S","start":"2026-10-13T10:00","end":"2026-10-13T11:00","timezone":"UTC","reminder":null}"#).unwrap();
        assert_eq!(none.reminder, Some(None));
        assert!(!update_event(MEETING, &none).unwrap().contains("VALARM"));

        for bad in [EventInput { attendees: vec!["not an address".into()], ..input() }, EventInput { attendees: (0..51).map(|n| format!("p{n}@example.org")).collect(), ..input() }, EventInput { reminder: Some(Some(-5)), ..input() }, EventInput { reminder: Some(Some(MAX_REMINDER_MINUTES + 1)), ..input() }] {
            assert!(super::build_event("x", &bad, Some(&ME)).is_err());
        }
        // A display name cannot smuggle in parameters or properties.
        let sneaky = Organizer { email: "bob@example.org", name: "Bob\";X=\"1\r\nATTENDEE:mailto:evil@x.example" };
        let built = super::build_event("s", &invited, Some(&sneaky)).unwrap();
        assert_eq!(parse(&built).unwrap().children[0].props.iter().filter(|p| p.name == "ATTENDEE").count(), 2);
        assert!(!built.contains("evil@x.example\r\n") || !attendees(&parse(&built).unwrap().children[0]).iter().any(|a| a.email.contains("evil")));
    }

    #[test]
    fn one_occurrence_of_a_series_can_be_changed() {
        let weekly = MEETING.replace("SUMMARY:", "RRULE:FREQ=WEEKLY;COUNT=3\r\nSUMMARY:");
        let second = at("2026-10-20 08:00");
        let shown = describe_event(&weekly, Tz::UTC, Some(second)).unwrap();
        assert_eq!((shown.start.as_str(), shown.end.as_str(), shown.rrule.as_str()), ("2026-10-20T10:00", "2026-10-20T11:30", ""));

        let changed = override_occurrence(&weekly, second, &EventInput { summary: "Planning (moved)".into(), start: "2026-10-21T15:00".into(), end: "2026-10-21T16:00".into(), ..shown.clone() }, Tz::UTC).unwrap();
        assert!(changed.contains("RECURRENCE-ID;TZID=Europe/Warsaw:20261020T100000\r\n"), "{changed}");
        assert_eq!(changed.matches("RRULE").count(), 1, "the override does not repeat");
        let list = occurrences(&changed, 0, i64::MAX / 4);
        assert_eq!(list.iter().map(|o| (o.start, o.summary.as_str())).collect::<Vec<_>>(), [(at("2026-10-13 08:00"), "Planning, part 1"), (at("2026-10-21 13:00"), "Planning (moved)"), (at("2026-10-27 09:00"), "Planning, part 1")]);
        assert_eq!(list[1].recurrence_id, Some(second));
        assert_eq!(list[1].alarms, [at("2026-10-21 12:45")], "the reminder of the series is inherited");
        assert!(inspect(&changed).is_ok());

        // Changing it again replaces the override; the editor sees the changed values.
        assert_eq!(describe_event(&changed, Tz::UTC, Some(second)).unwrap().summary, "Planning (moved)");
        let again = override_occurrence(&changed, second, &EventInput { summary: "Third version".into(), ..shown.clone() }, Tz::UTC).unwrap();
        assert_eq!(again.matches("BEGIN:VEVENT").count(), 2);
        assert_eq!(occurrences(&again, 0, i64::MAX / 4)[1].summary, "Third version");
        // Deleting the changed occurrence removes the override and excludes the date.
        let gone = exclude_occurrence(&again, second, Tz::UTC).unwrap();
        assert_eq!(occurrences(&gone, 0, i64::MAX / 4).len(), 2);
        assert_eq!(gone.matches("BEGIN:VEVENT").count(), 1);

        assert!(override_occurrence(&weekly, at("2026-10-21 08:00"), &shown, Tz::UTC).is_err(), "not an occurrence of the series");
        assert!(override_occurrence(MEETING, at("2026-10-14 08:00"), &shown, Tz::UTC).is_err());
    }

    #[test]
    fn to_dos() {
        let built = build_todo("t1", &TodoInput { summary: "Pay the invoice".into(), description: "Before the trip".into(), due: "2026-10-20".into(), completed: false }).unwrap();
        assert!(built.contains("BEGIN:VTODO") && built.contains("DUE;VALUE=DATE:20261020\r\n") && !built.contains("COMPLETED"));
        assert_eq!(inspect(&built).unwrap().component, "VTODO");
        let described = describe_todo(&built, Tz::UTC).unwrap();
        assert_eq!(described, TodoInput { summary: "Pay the invoice".into(), description: "Before the trip".into(), due: "2026-10-20".into(), completed: false });

        let done = update_todo(&built, &TodoInput { completed: true, ..described.clone() }, Tz::UTC).unwrap();
        assert!(done.contains("STATUS:COMPLETED\r\n") && done.contains("PERCENT-COMPLETE:100\r\n") && done.contains("\r\nCOMPLETED:"));
        assert!(describe_todo(&done, Tz::UTC).unwrap().completed);
        let reopened = update_todo(&done, &TodoInput { due: String::new(), ..described.clone() }, Tz::UTC).unwrap();
        assert!(reopened.contains("STATUS:NEEDS-ACTION") && !reopened.contains("\r\nCOMPLETED:") && !reopened.contains("DUE"));

        // A due time from a calendar program survives edits that keep the day.
        let phone = "BEGIN:VCALENDAR\nBEGIN:VTODO\nUID:t2\nSUMMARY:Call\nDUE;TZID=Europe/Warsaw:20261020T170000\nBEGIN:VALARM\nACTION:DISPLAY\nTRIGGER:-PT1H\nEND:VALARM\nEND:VTODO\nEND:VCALENDAR\n";
        let warsaw: Tz = "Europe/Warsaw".parse().unwrap();
        assert_eq!(describe_todo(phone, warsaw).unwrap().due, "2026-10-20");
        let renamed = update_todo(phone, &TodoInput { summary: "Call back".into(), due: "2026-10-20".into(), ..Default::default() }, warsaw).unwrap();
        assert!(renamed.contains("DUE;TZID=Europe/Warsaw:20261020T170000") && renamed.contains("BEGIN:VALARM") && renamed.contains("SUMMARY:Call back"));
        for bad in [TodoInput { summary: " ".into(), ..Default::default() }, TodoInput { summary: "x".into(), due: "soon".into(), ..Default::default() }] {
            assert!(build_todo("x", &bad).is_err());
        }
        assert!(update_todo(MEETING, &described, Tz::UTC).is_err(), "an event is not a task");
    }
}
