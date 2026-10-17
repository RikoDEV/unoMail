//! Invitations by mail (iMIP, RFC 6047 with the iTIP methods of RFC 5546).
//!
//! When an event with guests is created, changed or deleted in the web client, the guests are
//! told by mail; when a guest answers, the answer is mailed to the organizer. Incoming answers
//! and cancellations are applied to the stored event on delivery. Invitations themselves are
//! never added on their own: the recipient decides.
//!
//! Calendar programs connected over CalDAV send their own mail, as they do with any server
//! that does not announce scheduling of its own; what arrives is processed here all the same.

use chrono::{TimeZone, Utc};
use chrono_tz::Tz;
use mail_builder::{
    MessageBuilder,
    headers::content_type::ContentType,
    mime::{BodyPart, MimePart},
};
use mail_parser::{MessageParser, MimeHeaders, PartType};

use super::{
    ical::{self, Component, Property},
    store,
};
use crate::{
    app::App,
    auth::Account,
    smtp::submit::{self, Outcome, Submission},
    util::{Address, random_token, sanitize_line},
};

/// One scheduling message to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub method: &'static str,
    pub to: Vec<String>,
    pub subject: String,
    pub text: String,
    pub ics: String,
}

fn stamp() -> String {
    Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

/// Guests the server tells: everyone but the organizer, unless a program said it does that itself.
fn guests(event: &Component, me: &str) -> Vec<String> {
    event
        .props
        .iter()
        .filter(|p| p.name == "ATTENDEE" && !p.param("SCHEDULE-AGENT").is_some_and(|agent| agent.eq_ignore_ascii_case("CLIENT") || agent.eq_ignore_ascii_case("NONE")))
        .filter_map(ical::address_of)
        .filter(|address| address != me)
        .collect()
}

/// Everything about an object that guests need to hear about when it changes.
fn substance(calendar: &Component) -> Vec<String> {
    const NAMES: [&str; 11] = ["RECURRENCE-ID", "DTSTART", "DTEND", "DURATION", "RRULE", "EXDATE", "RDATE", "SUMMARY", "LOCATION", "DESCRIPTION", "STATUS"];
    calendar.children.iter().filter(|c| c.name == "VEVENT").flat_map(|event| event.props.iter().filter(|p| NAMES.contains(&p.name.as_str())).map(|p| format!("{}:{}", p.name, p.value))).collect()
}

/// "Tue 13 Oct 2026, 12:30 (Europe/Warsaw)", or the day for an all-day event.
fn when(event: &Component, zone: Tz) -> String {
    let Some(property) = event.prop("DTSTART") else { return String::new() };
    let Some(start) = ical::moment_in(property, zone) else { return String::new() };
    let Some(utc) = Utc.timestamp_opt(start.at, 0).single() else { return String::new() };
    if start.all_day {
        return utc.format("%a %-d %b %Y").to_string();
    }
    let zone = if property.value.trim().ends_with('Z') { Tz::UTC } else { property.param("TZID").and_then(|tzid| tzid.parse::<Tz>().ok()).unwrap_or(zone) };
    format!("{} ({})", utc.with_timezone(&zone).format("%a %-d %b %Y, %H:%M"), zone.name())
}

fn title(event: &Component) -> String {
    let summary: String = ical::unescape_text(event.value("SUMMARY").unwrap_or("")).chars().filter(|c| !c.is_control()).take(200).collect();
    if summary.trim().is_empty() { "(no title)".into() } else { summary }
}

fn shell(method: &str, children: Vec<Component>) -> Component {
    Component { name: "VCALENDAR".into(), props: vec![Property::new("VERSION", "2.0"), Property::new("PRODID", "-//unoMail//Calendar//EN"), Property::new("METHOD", method)], children }
}

/// The invitation as mailed: the whole object without the organizer's private reminders.
fn request(calendar: &Component) -> String {
    let mut out = calendar.clone();
    out.props.retain(|p| p.name != "METHOD");
    out.props.push(Property::new("METHOD", "REQUEST"));
    for event in &mut out.children {
        event.children.retain(|c| c.name != "VALARM");
    }
    out.serialize()
}

/// The few properties that identify an event in a reply or cancellation.
fn skeleton(event: &Component) -> Component {
    let mut out = Component { name: "VEVENT".into(), props: Vec::new(), children: Vec::new() };
    for name in ["UID", "RECURRENCE-ID", "SEQUENCE", "DTSTART", "DTEND", "DURATION", "SUMMARY", "ORGANIZER"] {
        out.props.extend(event.prop(name).cloned());
    }
    out.props.push(Property::new("DTSTAMP", stamp()));
    out
}

fn cancellation(event: &Component, recipients: &[String]) -> String {
    let mut out = skeleton(event);
    let sequence = event.value("SEQUENCE").and_then(|s| s.trim().parse::<u32>().ok()).unwrap_or(0);
    out.set(Some(Property::new("SEQUENCE", (sequence + 1).to_string())), "SEQUENCE");
    out.props.extend(recipients.iter().map(|address| Property::new("ATTENDEE", format!("mailto:{address}"))));
    out.props.push(Property::new("STATUS", "CANCELLED"));
    shell("CANCEL", vec![out]).serialize()
}

/// The answer of `me` to the organizer of `event`. `status` is a PARTSTAT value.
pub fn reply(event: &Component, me: &Account, status: &str) -> Option<Outgoing> {
    let organizer = ical::organizer(event).filter(|address| *address != me.email)?;
    let mut out = skeleton(event);
    let mut attendee = Property::new("ATTENDEE", format!("mailto:{}", me.email));
    attendee.params.push(("PARTSTAT".into(), status.to_ascii_uppercase()));
    let name: String = me.display_name.chars().filter(|c| !c.is_control()).take(100).collect();
    if !name.trim().is_empty() {
        attendee.params.push(("CN".into(), name.trim().to_owned()));
    }
    out.props.push(attendee);
    let (word, sentence) = match status.to_ascii_uppercase().as_str() {
        "ACCEPTED" => ("Accepted", "has accepted the invitation"),
        "TENTATIVE" => ("Maybe", "may attend"),
        _ => ("Declined", "has declined the invitation"),
    };
    let who = if me.display_name.trim().is_empty() { me.email.clone() } else { sanitize_line(&me.display_name) };
    Some(Outgoing { method: "REPLY", to: vec![organizer], subject: format!("{word}: {}", title(event)), text: format!("{who} {sentence}: {}", title(event)), ics: shell("REPLY", vec![out]).serialize() })
}

/// What has to be mailed after an object in a calendar of `me` changed from `before` to
/// `after` (`None`: it did not exist, or was deleted).
pub fn messages(me: &Account, before: Option<&str>, after: Option<&str>, zone: Tz) -> Vec<Outgoing> {
    let parse = |text: Option<&str>| text.and_then(|text| ical::parse(text).ok()).filter(|calendar| ical::master(calendar).is_some_and(|event| event.name == "VEVENT"));
    let (before, after) = (parse(before), parse(after));
    let main = |calendar: &Option<Component>| calendar.as_ref().and_then(|calendar| ical::master(calendar).cloned());
    let (old, new) = (main(&before), main(&after));
    let mine = |event: &Option<Component>| event.as_ref().is_some_and(|event| ical::organizer(event).as_deref() == Some(me.email.as_str()));
    let mut out = Vec::new();

    // As the organizer: invite, update, cancel.
    let old_guests = if mine(&old) { old.as_ref().map(|event| guests(event, &me.email)).unwrap_or_default() } else { Vec::new() };
    match (&after, &new) {
        (Some(calendar), Some(event)) if mine(&new) => {
            let now = guests(event, &me.email);
            let changed = before.as_ref().is_none_or(|previous| !mine(&old) || substance(previous) != substance(calendar));
            let invite: Vec<String> = if changed { now.clone() } else { now.iter().filter(|address| !old_guests.contains(address)).cloned().collect() };
            if !invite.is_empty() {
                let verb = if before.is_some() && mine(&old) && changed { "Updated invitation" } else { "Invitation" };
                let mut text = format!("{} invites you to: {}\nWhen: {}\n", if me.display_name.trim().is_empty() { me.email.clone() } else { sanitize_line(&me.display_name) }, title(event), when(event, zone));
                let location = ical::unescape_text(event.value("LOCATION").unwrap_or(""));
                if !location.trim().is_empty() {
                    text.push_str(&format!("Where: {}\n", sanitize_line(&location)));
                }
                text.push_str("\nOpen the attached invitation in your calendar to answer.\n");
                out.push(Outgoing { method: "REQUEST", to: invite, subject: format!("{verb}: {} ({})", title(event), when(event, zone)), text, ics: request(calendar) });
            }
            let removed: Vec<String> = old_guests.iter().filter(|address| !now.contains(address)).cloned().collect();
            if !removed.is_empty() {
                out.push(Outgoing { method: "CANCEL", subject: format!("Cancelled: {}", title(event)), text: format!("You are no longer invited to: {}\n", title(event)), ics: cancellation(event, &removed), to: removed });
            }
        }
        _ => {
            if let Some(event) = old.as_ref().filter(|_| !old_guests.is_empty()) {
                out.push(Outgoing { method: "CANCEL", subject: format!("Cancelled: {} ({})", title(event), when(event, zone)), text: format!("This event was cancelled: {}\n", title(event)), ics: cancellation(event, &old_guests), to: old_guests.clone() });
            }
        }
    }

    // As a guest: removing an event one had not declined tells the organizer.
    if let (Some(event), None) = (&old, &new)
        && !mine(&old)
        && ical::attendees(event).iter().any(|attendee| attendee.email == me.email && attendee.status != "declined")
    {
        out.extend(reply(event, me, "DECLINED"));
    }
    out
}

fn build_mail(me: &Account, delegate: Option<&Account>, message: &Outgoing) -> Vec<u8> {
    let domain = me.email.rsplit_once('@').map_or("localhost", |(_, domain)| domain);
    let calendar_type = |kind: &'static str| ContentType::new(kind).attribute("charset", "utf-8").attribute("method", message.method);
    let body = MimePart::new(
        ContentType::new("multipart/mixed"),
        BodyPart::Multipart(vec![
            MimePart::new(
                ContentType::new("multipart/alternative"),
                BodyPart::Multipart(vec![MimePart::new(ContentType::new("text/plain").attribute("charset", "utf-8"), message.text.as_str()), MimePart::new(calendar_type("text/calendar"), message.ics.as_str())]),
            ),
            MimePart::new(ContentType::new("application/ics").attribute("name", "invite.ics"), message.ics.as_bytes()).attachment("invite.ics"),
        ]),
    );
    let address = |account: &Account| match sanitize_line(&account.display_name) {
        name if name.is_empty() => mail_builder::headers::address::Address::new_address(None::<String>, account.email.clone()),
        name => mail_builder::headers::address::Address::new_address(Some(name), account.email.clone()),
    };
    let mut builder = MessageBuilder::new().from(address(me));
    // Written by someone else in the owner's name: the Sender field says who (RFC 5322 3.6.2).
    if let Some(delegate) = delegate.filter(|d| d.id != me.id) {
        builder = builder.sender(address(delegate));
    }
    builder
        .to(message.to.clone())
        .subject(sanitize_line(&message.subject))
        .message_id(format!("{}@{domain}", random_token()))
        .body(body)
        .write_to_vec()
        .unwrap_or_default()
}

/// Mails scheduling messages on behalf of `me`, written by `author` (`me` itself, or a
/// colleague with write access to its calendar). Returns what could not be sent, in words fit
/// for the user; the calendar itself is never rolled back because of mail.
pub async fn send(app: &App, me: &Account, author: &Account, messages: &[Outgoing], ip: std::net::IpAddr) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(sender) = Address::parse(&me.email) else { return problems };
    for message in messages {
        let recipients: Vec<Address> = message.to.iter().filter_map(|address| Address::parse(address)).collect();
        if recipients.is_empty() {
            continue;
        }
        let delegate = (author.id != me.id).then_some(author);
        let raw = build_mail(me, delegate, message);
        match submit::submit(app, Submission { account: me, sender: &sender, recipients: &recipients, raw: &raw, delegate, ip }).await {
            Outcome::Accepted(_) => {}
            Outcome::Rejected(reply) | Outcome::Deferred(reply) => problems.push(reply.splitn(3, ' ').nth(2).unwrap_or(&reply).to_owned()),
        }
    }
    problems
}

/// The calendar data carried by a message, if any: an invitation, an answer, a cancellation.
pub fn calendar_part(raw: &[u8]) -> Option<String> {
    let message = MessageParser::default().parse(raw)?;
    message.parts.iter().find_map(|part| {
        let kind = part.content_type()?;
        let named_ics = part.attachment_name().is_some_and(|name| name.to_ascii_lowercase().ends_with(".ics"));
        let is_calendar = (kind.ctype().eq_ignore_ascii_case("text") && kind.subtype().is_some_and(|sub| sub.eq_ignore_ascii_case("calendar"))) || named_ics;
        let text = match &part.body {
            PartType::Text(text) | PartType::Html(text) if is_calendar => text.to_string(),
            PartType::Binary(bytes) | PartType::InlineBinary(bytes) if is_calendar => String::from_utf8(bytes.to_vec()).ok()?,
            _ => return None,
        };
        (text.len() <= ical::MAX_OBJECT_BYTES && text.contains("BEGIN:VCALENDAR")).then_some(text)
    })
}

/// Applies an answer or a cancellation that arrived by mail from `author` (the address in the
/// message's From header) to the calendars of an account. Anything else is left for the user.
pub async fn process_incoming(app: &App, account_id: i64, author: &str, raw: &[u8]) {
    // Cheap test first: most mail carries no calendar data.
    if !raw.windows(8).any(|window| window.eq_ignore_ascii_case(b"calendar")) && !raw.windows(4).any(|window| window.eq_ignore_ascii_case(b".ics")) {
        return;
    }
    let Some(text) = calendar_part(raw) else { return };
    let Ok(incoming) = ical::parse(&text) else { return };
    let method = incoming.value("METHOD").unwrap_or("").trim().to_ascii_uppercase();
    let Some(event) = incoming.children.iter().find(|c| c.name == "VEVENT") else { return };
    let Some(uid) = event.value("UID").map(str::trim).filter(|uid| !uid.is_empty()) else { return };
    let author = author.trim().to_lowercase();
    let Ok(Some(me)) = Account::by_id(&app.db, account_id).await else { return };
    let Ok(Some((calendar, object))) = store::object_by_uid(&app.db, me.id, uid).await else { return };
    let Ok(mut stored) = ical::parse(&object.data) else { return };
    let zone = store::zone_of(&app.db, me.id).await;
    let organizer = ical::master(&stored).and_then(ical::organizer);
    let occurrence = event.prop("RECURRENCE-ID").and_then(|p| ical::moment_in(p, zone)).map(|id| id.at);

    let result = match method.as_str() {
        // A guest answered: note it on the organizer's copy. Only the sender's own answer counts.
        "REPLY" if organizer.as_deref() == Some(me.email.as_str()) => {
            let Some(status) = event.props.iter().filter(|p| p.name == "ATTENDEE").find(|p| ical::address_of(p).as_deref() == Some(author.as_str())).and_then(|p| p.param("PARTSTAT")).map(str::to_ascii_uppercase) else { return };
            if !["ACCEPTED", "DECLINED", "TENTATIVE", "NEEDS-ACTION"].contains(&status.as_str()) {
                return;
            }
            let mut changed = false;
            for component in stored.children.iter_mut().filter(|c| c.name == "VEVENT") {
                let id = component.prop("RECURRENCE-ID").and_then(|p| ical::moment_in(p, zone)).map(|id| id.at);
                // An answer to the series applies to all of it; one to an occurrence only there.
                if occurrence.is_some() && id != occurrence {
                    continue;
                }
                for attendee in component.props.iter_mut().filter(|p| p.name == "ATTENDEE" && ical::address_of(p).as_deref() == Some(author.as_str())) {
                    attendee.params.retain(|(key, _)| key != "PARTSTAT" && key != "RSVP");
                    attendee.params.push(("PARTSTAT".into(), status.clone()));
                    changed = true;
                }
            }
            if !changed {
                return;
            }
            store::put_object(&app.db, &calendar, &object.name, &stored.serialize()).await.map(|_| ())
        }
        // The organizer called it off: remove the event, or the one occurrence.
        "CANCEL" if organizer.as_deref() == Some(author.as_str()) && author != me.email => match occurrence {
            Some(at) => match ical::exclude_occurrence(&object.data, at, zone) {
                Ok(data) => store::put_object(&app.db, &calendar, &object.name, &data).await.map(|_| ()),
                Err(_) => return,
            },
            None => store::delete_object(&app.db, &calendar, &object.name).await.map(|_| ()).map_err(Into::into),
        },
        // An update of an invitation that is already in the calendar replaces it; the answer
        // given before stands unless the organizer asks again.
        "REQUEST" if organizer.as_deref() == Some(author.as_str()) && author != me.email => {
            let sequence = |component: Option<&Component>| component.and_then(|c| c.value("SEQUENCE")).and_then(|s| s.trim().parse::<u32>().ok()).unwrap_or(0);
            if sequence(Some(event)) < sequence(ical::master(&stored)) {
                return;
            }
            let Some(data) = ical::split_objects(&text).ok().and_then(|objects| objects.into_iter().next()) else { return };
            store::put_object(&app.db, &calendar, &object.name, &data).await.map(|_| ())
        }
        _ => return,
    };
    if let Err(err) = result {
        tracing::warn!(%err, account = %me.email, "could not apply a calendar message");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(email: &str, name: &str) -> Account {
        Account {
            id: 1,
            domain_id: 1,
            email: email.into(),
            display_name: name.into(),
            password_hash: String::new(),
            role: crate::auth::Role::User,
            quota_bytes: 0,
            used_bytes: 0,
            enabled: true,
            imap_enabled: true,
            pop3_enabled: true,
            smtp_enabled: true,
            outbound_blocked: false,
        }
    }

    fn event(extra: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//T//EN\r\nBEGIN:VEVENT\r\nUID:e1\r\nSEQUENCE:2\r\nDTSTART;TZID=Europe/Warsaw:20261013T123000\r\nDTEND;TZID=Europe/Warsaw:20261013T133000\r\nSUMMARY:Lunch\r\n\
ORGANIZER:mailto:bob@example.org\r\n{extra}BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    }

    const CAROL: &str = "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:carol@example.org\r\n";
    const DAN: &str = "ATTENDEE;PARTSTAT=ACCEPTED:mailto:dan@remote.example\r\n";

    #[test]
    fn the_organizer_invites_updates_and_cancels() {
        let bob = account("bob@example.org", "Bob Example");
        let both = event(&format!("{CAROL}{DAN}"));

        let invited = messages(&bob, None, Some(&both), Tz::UTC);
        assert_eq!(invited.len(), 1);
        assert_eq!((invited[0].method, invited[0].to.clone()), ("REQUEST", vec!["carol@example.org".to_owned(), "dan@remote.example".to_owned()]));
        assert_eq!(invited[0].subject, "Invitation: Lunch (Tue 13 Oct 2026, 12:30 (Europe/Warsaw))");
        assert!(invited[0].ics.contains("METHOD:REQUEST") && !invited[0].ics.contains("VALARM"), "private reminders are not mailed");

        // Nothing the guests care about changed: nobody is bothered.
        assert!(messages(&bob, Some(&both), Some(&both.replace("TRIGGER:-PT5M", "TRIGGER:-PT1H")), Tz::UTC).is_empty());
        // A new guest alone gets the invitation; a removed one a cancellation.
        let only_carol = event(CAROL);
        let added = messages(&bob, Some(&only_carol), Some(&both), Tz::UTC);
        assert_eq!((added.len(), added[0].method, added[0].to.clone()), (1, "REQUEST", vec!["dan@remote.example".to_owned()]));
        let removed = messages(&bob, Some(&both), Some(&only_carol), Tz::UTC);
        assert_eq!((removed.len(), removed[0].method, removed[0].to.clone()), (1, "CANCEL", vec!["dan@remote.example".to_owned()]));
        assert!(removed[0].ics.contains("METHOD:CANCEL") && removed[0].ics.contains("SEQUENCE:3") && removed[0].ics.contains("STATUS:CANCELLED"));
        // A new time goes to everyone.
        let moved = messages(&bob, Some(&both), Some(&both.replace("T123000", "T140000")), Tz::UTC);
        assert_eq!((moved[0].method, moved[0].to.len()), ("REQUEST", 2));
        assert!(moved[0].subject.starts_with("Updated invitation: Lunch"));
        // Deleting the event, or uninviting everybody, cancels it for all.
        for after in [None, Some(event(""))] {
            let cancelled = messages(&bob, Some(&both), after.as_deref(), Tz::UTC);
            assert_eq!((cancelled.len(), cancelled[0].method, cancelled[0].to.len()), (1, "CANCEL", 2));
        }
        // Guests a calendar program takes care of itself are left to it.
        let client = event("ATTENDEE;SCHEDULE-AGENT=CLIENT:mailto:carol@example.org\r\n");
        assert!(messages(&bob, None, Some(&client), Tz::UTC).is_empty());
        // Events without guests, and to-dos, never cause mail.
        assert!(messages(&bob, None, Some(&event("")), Tz::UTC).is_empty());
        assert!(messages(&bob, Some(&event("")), None, Tz::UTC).is_empty());
    }

    #[test]
    fn a_guest_answers() {
        let carol = account("carol@example.org", "Carol");
        let invitation = event(&format!("{CAROL}{DAN}"));
        // Carol is not the organizer: storing or changing her copy invites nobody.
        assert!(messages(&carol, None, Some(&invitation), Tz::UTC).is_empty());
        // Deleting it declines.
        let declined = messages(&carol, Some(&invitation), None, Tz::UTC);
        assert_eq!((declined.len(), declined[0].method, declined[0].to.clone()), (1, "REPLY", vec!["bob@example.org".to_owned()]));
        assert!(declined[0].ics.contains("ATTENDEE;PARTSTAT=DECLINED;CN=Carol:mailto:carol@example.org") && !declined[0].ics.contains("dan@"), "only her own answer: {}", declined[0].ics);
        // ... unless she had declined already.
        assert!(messages(&carol, Some(&invitation.replace("PARTSTAT=NEEDS-ACTION:mailto:carol", "PARTSTAT=DECLINED:mailto:carol")), None, Tz::UTC).is_empty());

        let parsed = ical::parse(&invitation).unwrap();
        let accepted = reply(&parsed.children[0], &carol, "accepted").unwrap();
        assert_eq!(accepted.subject, "Accepted: Lunch");
        assert!(accepted.ics.contains("METHOD:REPLY") && accepted.ics.contains("UID:e1") && accepted.ics.contains("PARTSTAT=ACCEPTED"));
        assert!(reply(&parsed.children[0], &account("bob@example.org", ""), "accepted").is_none(), "the organizer does not answer himself");
    }

    #[test]
    fn mail_carries_the_invitation_twice() {
        let bob = account("bob@example.org", "Bob \"The Boss\"\r\nBcc: evil@x.example");
        let message = Outgoing { method: "REQUEST", to: vec!["carol@example.org".into()], subject: "Invitation: Żurek\r\nBcc: evil@x.example".into(), text: "Come.".into(), ics: event(CAROL) };
        let raw = build_mail(&bob, None, &message);
        let text = String::from_utf8_lossy(&raw).into_owned();
        assert!(!text.lines().any(|line| line.to_ascii_lowercase().starts_with("bcc:")), "{text}");
        let parsed = MessageParser::default().parse(&raw).unwrap();
        assert_eq!(parsed.to().unwrap().first().unwrap().address(), Some("carol@example.org"));
        let kinds: Vec<String> = parsed.parts.iter().filter_map(|part| part.content_type().map(|kind| format!("{}/{}", kind.ctype(), kind.subtype().unwrap_or("")))).collect();
        assert_eq!(kinds, ["multipart/mixed", "multipart/alternative", "text/plain", "text/calendar", "application/ics"]);
        assert!(text.contains("method=REQUEST") || text.contains("method=\"REQUEST\""));
        assert_eq!(calendar_part(&raw).as_deref(), Some(message.ics.as_str()));
        assert_eq!(calendar_part(b"From: a@b\r\nSubject: calendar\r\n\r\nNo data here, only the word calendar.\r\n"), None);
    }
}
