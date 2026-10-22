//! Invitations by mail, shared calendars, free/busy, to-dos, reminders, single occurrences of
//! a series, floating times, and the address book over CardDAV.

mod common;

use axum::{
    Extension,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use base64::Engine;
use common::{Api, Client, PASSWORD, Sink, TestEnv};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use unomail::{calendar::scheduling::calendar_part, smtp::queue};

struct Dav {
    api: Api,
    authorization: String,
}

struct DavReply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    text: String,
}

impl Dav {
    fn new(env: &TestEnv, user: &str) -> Self {
        Dav { api: Api::new(env), authorization: format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{PASSWORD}"))) }
    }

    async fn send(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> DavReply {
        let mut request = Request::builder().method(Method::from_bytes(method.as_bytes()).unwrap()).uri(path).header(header::AUTHORIZATION, &self.authorization);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let router = self.api.router.clone().layer(Extension(unomail::api::PeerAddr(self.api.peer)));
        let response = router.oneshot(request.body(Body::from(body.to_owned())).unwrap()).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        DavReply { status: parts.status, headers: parts.headers, text: String::from_utf8_lossy(&bytes).into_owned() }
    }
}

fn at(text: &str) -> i64 {
    chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M").unwrap().and_utc().timestamp()
}

fn window(from: &str, to: &str) -> String {
    format!("/api/me/calendars/events?from={}&to={}", at(from), at(to))
}

async fn personal(api: &Api) -> i64 {
    api.get("/api/me/calendars").await.body["calendars"][0]["id"].as_i64().unwrap()
}

/// The subjects of the messages in a mailbox, with the calendar data each carries.
fn calendar_mail(messages: &[String]) -> Vec<(String, String)> {
    messages
        .iter()
        .filter_map(|raw| {
            let subject = raw.lines().find_map(|line| line.strip_prefix("Subject: ")).unwrap_or("").to_owned();
            Some((subject, calendar_part(raw.as_bytes())?))
        })
        .collect()
}

fn status_of(event: &Value, email: &str) -> String {
    event["attendees"].as_array().unwrap().iter().find(|a| a["email"] == email).map(|a| a["status"].as_str().unwrap().to_owned()).unwrap_or_else(|| "absent".into())
}

#[tokio::test]
async fn guests_are_invited_by_mail_and_their_answers_come_back() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    let bob_account = env.account("bob@example.org").await;
    let carol_account = env.account("carol@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let carol = Api::logged_in(&env, "carol@example.org").await;
    let bobs = personal(&bob).await;
    let october = window("2026-10-01 00:00", "2026-11-01 00:00");

    // Bob invites a colleague and somebody elsewhere.
    let lunch = json!({ "summary": "Lunch", "location": "Canteen", "start": "2026-10-13T12:00", "end": "2026-10-13T13:00", "timezone": "UTC", "attendees": ["carol@example.org", "Dan@Remote.Example"], "reminder": 10 });
    let created = bob.post(&format!("/api/me/calendars/{bobs}/events"), lunch.clone()).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    assert_eq!(created.body["mail_problems"], json!([]));
    let lunch_id = created.body["id"].as_i64().unwrap();
    queue::process_due(&env.app).await;

    let invitations = calendar_mail(&env.inbox(&carol_account).await);
    assert_eq!(invitations.len(), 1);
    assert!(invitations[0].0.starts_with("Invitation: Lunch (Tue 13 Oct 2026, 12:00"), "{}", invitations[0].0);
    let invitation = invitations[0].1.clone();
    assert!(invitation.contains("METHOD:REQUEST") && invitation.contains("ORGANIZER:mailto:bob@example.org") && !invitation.contains("VALARM"), "{invitation}");
    let remote = sink.received();
    assert_eq!(remote.len(), 1);
    assert_eq!((remote[0].from.as_str(), remote[0].to.as_str()), ("bob@example.org", "dan@remote.example"));
    assert!(calendar_part(remote[0].data.as_bytes()).unwrap().contains("METHOD:REQUEST"));
    let uid = invitation.lines().find_map(|line| line.strip_prefix("UID:")).unwrap().trim().to_owned();

    // Nothing lands in Carol's calendar by itself; she looks at the invitation and accepts.
    assert_eq!(carol.get(&october).await.body, json!([]));
    let seen = carol.raw(Method::POST, "/api/me/calendars/invitations/inspect", invitation.clone().into_bytes(), "text/calendar").await;
    assert_eq!(seen.status, StatusCode::OK, "{}", seen.text);
    assert_eq!((seen.body["method"].clone(), seen.body["summary"].clone(), seen.body["organizer"].clone(), seen.body["my_status"].clone(), seen.body["stored"].clone()), (json!("REQUEST"), json!("Lunch"), json!("bob@example.org"), json!("needs-action"), json!(false)));
    assert_eq!(seen.body["start"], at("2026-10-13 12:00"));
    assert_eq!(carol.post("/api/me/calendars/invitations/respond", json!({ "ics": invitation, "response": "perhaps" })).await.status, StatusCode::BAD_REQUEST);
    let answer = carol.post("/api/me/calendars/invitations/respond", json!({ "ics": invitation, "response": "accepted" })).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text);
    let hers = carol.get(&october).await.body;
    assert_eq!((hers.as_array().unwrap().len(), hers[0]["summary"].clone(), hers[0]["organizer"].clone(), status_of(&hers[0], "carol@example.org")), (1, json!("Lunch"), json!("bob@example.org"), "accepted".to_owned()));
    assert_eq!(carol.raw(Method::POST, "/api/me/calendars/invitations/inspect", invitation.clone().into_bytes(), "text/calendar").await.body["my_status"], "accepted");
    assert_eq!(carol.get(&format!("/api/me/calendars/reminders?from={}&to={}", at("2026-10-13 00:00"), at("2026-10-14 00:00"))).await.body, json!([]), "the organizer's reminder is not hers");

    // Her answer is mailed to Bob, and his copy of the event notes it without his doing.
    queue::process_due(&env.app).await;
    let replies = calendar_mail(&env.inbox(&bob_account).await);
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].0, "Accepted: Lunch");
    assert!(replies[0].1.contains("METHOD:REPLY") && replies[0].1.contains("PARTSTAT=ACCEPTED"));
    let his = bob.get(&october).await.body;
    assert_eq!((status_of(&his[0], "carol@example.org"), status_of(&his[0], "dan@remote.example")), ("accepted".to_owned(), "needs-action".to_owned()));

    // An answer from outside arrives by SMTP. Only the sender's own answer counts.
    let reply = |from: &str, attendee: &str, status: &str| {
        format!("From: {from}\r\nTo: bob@example.org\r\nSubject: Re: Lunch\r\nMIME-Version: 1.0\r\nContent-Type: text/calendar; method=REPLY; charset=utf-8\r\n\r\nBEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REPLY\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20261001T000000Z\r\nORGANIZER:mailto:bob@example.org\r\nATTENDEE;PARTSTAT={status}:mailto:{attendee}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
    };
    let mut smtp = Client::smtp(env.mx).await;
    assert!(smtp.send_mail("mallory@remote.example", &["bob@example.org"], &reply("mallory@remote.example", "dan@remote.example", "DECLINED")).await.starts_with("250"));
    assert_eq!(status_of(&bob.get(&october).await.body[0], "dan@remote.example"), "needs-action", "nobody answers for somebody else");
    assert!(smtp.send_mail("mallory@remote.example", &["bob@example.org"], &reply("mallory@remote.example", "mallory@remote.example", "ACCEPTED")).await.starts_with("250"));
    assert_eq!(status_of(&bob.get(&october).await.body[0], "mallory@remote.example"), "absent", "nobody invites themselves");
    assert!(smtp.send_mail("dan@remote.example", &["bob@example.org"], &reply("Dan <Dan@Remote.Example>", "dan@remote.example", "TENTATIVE")).await.starts_with("250"));
    assert_eq!(status_of(&bob.get(&october).await.body[0], "dan@remote.example"), "tentative");

    // The editor shows the guests; a guest cannot change the list of somebody else's event.
    let details = bob.get(&format!("/api/me/calendars/{bobs}/events/{lunch_id}")).await.body["event"].clone();
    assert_eq!((details["attendees"].clone(), details["reminder"].clone()), (json!(["carol@example.org", "dan@remote.example"]), json!(10)));
    let carols = personal(&carol).await;
    let her_copy = hers[0]["id"].as_i64().unwrap();
    let mut meddling = carol.get(&format!("/api/me/calendars/{carols}/events/{her_copy}")).await.body["event"].clone();
    meddling["attendees"] = json!(["eve@example.org"]);
    assert_eq!(carol.put(&format!("/api/me/calendars/{carols}/events/{her_copy}"), meddling).await.status, StatusCode::OK);
    assert_eq!(status_of(&carol.get(&october).await.body[0], "eve@example.org"), "absent");
    queue::process_due(&env.app).await;
    assert_eq!(sink.received().len(), 1, "a guest's edit mails nobody");

    // Bob moves the lunch: everybody hears, the answers are open again, Carol's copy follows.
    let mut moved = details.clone();
    moved["start"] = json!("2026-10-14T12:00");
    moved["end"] = json!("2026-10-14T13:00");
    assert_eq!(bob.put(&format!("/api/me/calendars/{bobs}/events/{lunch_id}"), moved.clone()).await.body["mail_problems"], json!([]));
    queue::process_due(&env.app).await;
    let updates = calendar_mail(&env.inbox(&carol_account).await);
    assert!(updates.last().unwrap().0.starts_with("Updated invitation: Lunch (Wed 14 Oct 2026"), "{:?}", updates.last().unwrap().0);
    assert_eq!(sink.received().len(), 2);
    let his = bob.get(&october).await.body;
    assert_eq!((his[0]["start"].clone(), status_of(&his[0], "carol@example.org"), status_of(&his[0], "dan@remote.example")), (json!(at("2026-10-14 12:00")), "needs-action".to_owned(), "needs-action".to_owned()));
    let hers = carol.get(&october).await.body;
    assert_eq!((hers.as_array().unwrap().len(), hers[0]["start"].clone(), status_of(&hers[0], "carol@example.org")), (1, json!(at("2026-10-14 12:00")), "needs-action".to_owned()));

    // Only a reminder changes: nobody is bothered.
    let mut quiet = moved.clone();
    quiet["reminder"] = json!(30);
    bob.put(&format!("/api/me/calendars/{bobs}/events/{lunch_id}"), quiet.clone()).await;
    queue::process_due(&env.app).await;
    assert_eq!((sink.received().len(), calendar_mail(&env.inbox(&carol_account).await).len()), (2, 2));

    // Dan is uninvited: he alone gets a cancellation.
    let mut smaller = quiet.clone();
    smaller["attendees"] = json!(["carol@example.org"]);
    bob.put(&format!("/api/me/calendars/{bobs}/events/{lunch_id}"), smaller).await;
    queue::process_due(&env.app).await;
    let remote = sink.received();
    assert_eq!(remote.len(), 3);
    let cancel = calendar_part(remote[2].data.as_bytes()).unwrap();
    assert!(cancel.contains("METHOD:CANCEL") && cancel.contains("STATUS:CANCELLED") && cancel.contains(&format!("UID:{uid}")), "{cancel}");
    assert_eq!(calendar_mail(&env.inbox(&carol_account).await).len(), 2);

    // Bob deletes the event: Carol is told and it leaves her calendar.
    assert_eq!(bob.delete(&format!("/api/me/calendars/{bobs}/events/{lunch_id}")).await.body["mail_problems"], json!([]));
    queue::process_due(&env.app).await;
    let last = calendar_mail(&env.inbox(&carol_account).await).pop().unwrap();
    assert!(last.0.starts_with("Cancelled: Lunch") && last.1.contains("METHOD:CANCEL"), "{}", last.0);
    assert_eq!(carol.get(&october).await.body, json!([]));
    assert_eq!(sink.received().len(), 3, "Dan was no longer a guest");
    assert_eq!(carol.raw(Method::POST, "/api/me/calendars/invitations/inspect", last.1.into_bytes(), "text/calendar").await.body["method"], "CANCEL");

    // Declining: nothing is stored, the organizer learns of it. Accepting and then deleting
    // the event declines too.
    let dinner = json!({ "summary": "Dinner", "start": "2026-10-20T18:00", "end": "2026-10-20T20:00", "timezone": "UTC", "attendees": ["carol@example.org"] });
    bob.post(&format!("/api/me/calendars/{bobs}/events"), dinner).await;
    queue::process_due(&env.app).await;
    let invitation = calendar_mail(&env.inbox(&carol_account).await).pop().unwrap().1;
    assert_eq!(carol.post("/api/me/calendars/invitations/respond", json!({ "ics": invitation, "response": "declined" })).await.status, StatusCode::OK);
    assert_eq!(carol.get(&october).await.body, json!([]));
    queue::process_due(&env.app).await;
    assert_eq!(status_of(&bob.get(&october).await.body[0], "carol@example.org"), "declined");
    assert_eq!(calendar_mail(&env.inbox(&bob_account).await).pop().unwrap().0, "Declined: Dinner");
    let accepted = carol.post("/api/me/calendars/invitations/respond", json!({ "ics": invitation, "response": "tentative" })).await;
    let her_copy = accepted.body["id"].as_i64().unwrap();
    queue::process_due(&env.app).await;
    assert_eq!(status_of(&bob.get(&october).await.body[0], "carol@example.org"), "tentative");
    assert_eq!(carol.delete(&format!("/api/me/calendars/{carols}/events/{her_copy}")).await.status, StatusCode::OK);
    queue::process_due(&env.app).await;
    assert_eq!(status_of(&bob.get(&october).await.body[0], "carol@example.org"), "declined");

    // What cannot be answered is refused: one's own invitation, and things that are none.
    let own = calendar_mail(&env.inbox(&carol_account).await)[0].1.clone();
    assert_eq!(bob.post("/api/me/calendars/invitations/respond", json!({ "ics": own, "response": "accepted" })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(carol.post("/api/me/calendars/invitations/respond", json!({ "ics": "hello", "response": "accepted" })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(carol.raw(Method::POST, "/api/me/calendars/invitations/inspect", b"hello".to_vec(), "text/calendar").await.status, StatusCode::BAD_REQUEST);
    assert_eq!(bob.post(&format!("/api/me/calendars/{bobs}/events"), json!({ "summary": "x", "start": "2026-10-20T18:00", "end": "2026-10-20T20:00", "timezone": "UTC", "attendees": ["nonsense"] })).await.status, StatusCode::BAD_REQUEST);

    // A guest knows the UID of Bob's dinner. An invitation of their own under that UID cannot
    // remove or replace the event Bob organizes.
    let forged = invitation.replace("ORGANIZER:mailto:bob@example.org", "ORGANIZER:mailto:mallory@remote.example");
    assert_ne!(forged, invitation);
    for response in ["declined", "accepted"] {
        assert_eq!(bob.post("/api/me/calendars/invitations/respond", json!({ "ics": forged, "response": response })).await.status, StatusCode::CONFLICT, "{response}");
    }
    let dinner = &bob.get(&october).await.body[0];
    assert_eq!((dinner["summary"].as_str(), dinner["organizer"].as_str()), (Some("Dinner"), Some("bob@example.org")), "{dinner}");
}

#[tokio::test]
async fn calendars_are_shared_with_colleagues() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.domain("other.example").await;
    for address in ["bob@example.org", "carol@example.org", "dave@example.org", "eve@other.example"] {
        env.account(address).await;
    }
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let carol = Api::logged_in(&env, "carol@example.org").await;
    let dave = Api::logged_in(&env, "dave@example.org").await;
    let team = bob.post("/api/me/calendars", json!({ "name": "Team", "color": "#188038" })).await.body["id"].as_i64().unwrap();
    let planning = json!({ "summary": "Planning", "start": "2026-10-13T10:00", "end": "2026-10-13T11:00", "timezone": "UTC" });
    let planning_id = bob.post(&format!("/api/me/calendars/{team}/events"), planning.clone()).await.body["id"].as_i64().unwrap();
    let october = window("2026-10-01 00:00", "2026-11-01 00:00");

    // Only colleagues of the same domain, and only by the owner.
    for bad in [json!([{ "email": "eve@other.example" }]), json!([{ "email": "nobody@example.org" }]), json!([{ "email": "bob@example.org" }]), json!([{ "email": "not an address" }])] {
        assert_eq!(bob.put(&format!("/api/me/calendars/{team}/shares"), bad.clone()).await.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert_eq!(carol.put(&format!("/api/me/calendars/{team}/shares"), json!([{ "email": "carol@example.org", "write": true }])).await.status, StatusCode::NOT_FOUND);
    assert_eq!(bob.put(&format!("/api/me/calendars/{team}/shares"), json!([{ "email": "Carol@Example.org" }, { "email": "dave@example.org", "write": true }])).await.status, StatusCode::OK);
    assert_eq!(bob.get(&format!("/api/me/calendars/{team}/shares")).await.body, json!([{ "email": "carol@example.org", "write": false }, { "email": "dave@example.org", "write": true }]));

    // Carol reads; she cannot write, share on, rename or see Bob's other calendar.
    let listed = carol.get("/api/me/calendars").await.body["calendars"].clone();
    let shared = listed.as_array().unwrap().iter().find(|c| c["shared"] == true).unwrap().clone();
    assert_eq!((shared["id"].clone(), shared["name"].clone(), shared["owner"].clone(), shared["writable"].clone(), shared["slug"].clone()), (json!(team), json!("Team"), json!("bob@example.org"), json!(false), json!(format!("shared-{team}"))));
    assert_eq!(listed.as_array().unwrap().len(), 2);
    assert_eq!(carol.get(&october).await.body[0]["summary"], "Planning");
    assert_eq!(carol.get(&format!("/api/me/calendars/{team}/events/{planning_id}")).await.status, StatusCode::OK);
    assert_eq!(carol.post(&format!("/api/me/calendars/{team}/events"), planning.clone()).await.status, StatusCode::FORBIDDEN);
    assert_eq!(carol.put(&format!("/api/me/calendars/{team}/events/{planning_id}"), planning.clone()).await.status, StatusCode::FORBIDDEN);
    assert_eq!(carol.delete(&format!("/api/me/calendars/{team}/events/{planning_id}")).await.status, StatusCode::FORBIDDEN);
    assert_eq!(carol.patch(&format!("/api/me/calendars/{team}"), json!({ "name": "Mine" })).await.status, StatusCode::FORBIDDEN);
    assert_eq!(carol.get(&format!("/api/me/calendars/{team}/shares")).await.status, StatusCode::FORBIDDEN);
    assert_eq!(carol.raw(Method::POST, &format!("/api/me/calendars/{team}/import"), b"BEGIN:VCALENDAR\nEND:VCALENDAR\n".to_vec(), "text/calendar").await.status, StatusCode::FORBIDDEN);
    assert_eq!(carol.get(&format!("/api/me/calendars/{team}/export")).await.status, StatusCode::OK);
    let bobs_private = personal(&bob).await;
    assert_eq!(carol.get(&format!("/api/me/calendars/{bobs_private}/export")).await.status, StatusCode::NOT_FOUND);

    // Dave may write; what he adds is Bob's. He cannot move it into his own calendar.
    let added = dave.post(&format!("/api/me/calendars/{team}/events"), json!({ "summary": "Retro", "start": "2026-10-14T10:00", "end": "2026-10-14T11:00", "timezone": "UTC" })).await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.text);
    let retro = added.body["id"].as_i64().unwrap();
    assert_eq!(bob.get(&october).await.body.as_array().unwrap().len(), 2);
    let mut steal = dave.get(&format!("/api/me/calendars/{team}/events/{retro}")).await.body["event"].clone();
    steal["calendar_id"] = json!(personal(&dave).await);
    assert_eq!(dave.put(&format!("/api/me/calendars/{team}/events/{retro}"), steal).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(dave.patch(&format!("/api/me/calendars/{team}"), json!({ "name": "Mine" })).await.status, StatusCode::FORBIDDEN);

    // Calendar programs see the shared calendar in their own home, with the right privileges.
    let carol_dav = Dav::new(&env, "carol@example.org");
    let home = carol_dav.send("PROPFIND", "/dav/calendars/carol@example.org/", &[("depth", "1")], "").await;
    let shared_path = format!("/dav/calendars/carol@example.org/shared-{team}/");
    assert!(home.text.contains(&shared_path) && home.text.contains("<D:displayname>Team (bob@example.org)</D:displayname>"), "{}", home.text);
    let props = carol_dav.send("PROPFIND", &shared_path, &[("depth", "1")], r#"<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-privilege-set/><d:getetag/></d:prop></d:propfind>"#).await;
    assert!(props.text.contains("<D:read/>") && !props.text.contains("<D:write/>") && props.text.contains(".ics"), "{}", props.text);
    let event = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:dav-1\r\nDTSTAMP:20261001T000000Z\r\nDTSTART:20261015T100000Z\r\nDURATION:PT1H\r\nSUMMARY:From a program\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    assert_eq!(carol_dav.send("PUT", &format!("{shared_path}dav-1.ics"), &[], event).await.status, StatusCode::FORBIDDEN);
    assert_eq!(carol_dav.send("DELETE", &shared_path, &[], "").await.status, StatusCode::FORBIDDEN);
    assert_eq!(carol_dav.send("PROPPATCH", &shared_path, &[], r#"<d:propertyupdate xmlns:d="DAV:"><d:set><d:prop><d:displayname>Mine</d:displayname></d:prop></d:set></d:propertyupdate>"#).await.status, StatusCode::FORBIDDEN);
    assert_eq!(carol_dav.send("MKCALENDAR", "/dav/calendars/carol@example.org/shared-999/", &[], "").await.status, StatusCode::FORBIDDEN, "the prefix is reserved");
    let dave_dav = Dav::new(&env, "dave@example.org");
    let dave_path = format!("/dav/calendars/dave@example.org/shared-{team}/");
    assert_eq!(dave_dav.send("PUT", &format!("{dave_path}dav-1.ics"), &[], event).await.status, StatusCode::CREATED);
    assert_eq!(dave_dav.send("DELETE", &dave_path, &[], "").await.status, StatusCode::FORBIDDEN, "the calendar itself stays Bob's");
    assert!(carol_dav.send("GET", &format!("{shared_path}dav-1.ics"), &[], "").await.text.contains("From a program"));
    assert_eq!(Dav::new(&env, "eve@other.example").send("PROPFIND", &format!("/dav/calendars/eve@other.example/shared-{team}/"), &[], "").await.status, StatusCode::NOT_FOUND);

    // Free/busy over CalDAV: times, no titles.
    let busy = carol_dav.send("REPORT", &shared_path, &[], r#"<c:free-busy-query xmlns:c="urn:ietf:params:xml:ns:caldav"><c:time-range start="20261013T000000Z" end="20261016T000000Z"/></c:free-busy-query>"#).await;
    assert_eq!(busy.status, StatusCode::OK);
    assert!(busy.headers[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/calendar"));
    assert!(busy.text.contains("BEGIN:VFREEBUSY") && busy.text.contains("FREEBUSY;FBTYPE=BUSY:20261013T100000Z/20261013T110000Z") && busy.text.matches("FREEBUSY;").count() == 3 && !busy.text.contains("Planning"), "{}", busy.text);

    // Leaving a shared calendar, and withdrawing a share.
    assert_eq!(carol.delete(&format!("/api/me/calendars/{team}")).await.status, StatusCode::OK);
    assert_eq!(carol.get("/api/me/calendars").await.body["calendars"].as_array().unwrap().len(), 1);
    assert_eq!(bob.get(&format!("/api/me/calendars/{team}/shares")).await.body, json!([{ "email": "dave@example.org", "write": true }]));
    assert_eq!(carol_dav.send("PROPFIND", &shared_path, &[], "").await.status, StatusCode::NOT_FOUND);
    assert_eq!(bob.put(&format!("/api/me/calendars/{team}/shares"), json!([])).await.status, StatusCode::OK);
    assert_eq!(dave.get(&format!("/api/me/calendars/{team}/events/{retro}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(bob.get(&october).await.body.as_array().unwrap().len(), 3, "the events stay with the owner");
}

#[tokio::test]
async fn free_time_tasks_reminders_and_single_occurrences() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.domain("other.example").await;
    for address in ["bob@example.org", "carol@example.org", "eve@other.example"] {
        env.account(address).await;
    }
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let carol = Api::logged_in(&env, "carol@example.org").await;
    let bobs = personal(&bob).await;
    let carols = personal(&carol).await;
    let event = |summary: &str, start: &str, end: &str| json!({ "summary": summary, "start": start, "end": end, "timezone": "UTC" });

    // Free/busy: colleagues answer with merged times and nothing else; others are unknown.
    for (start, end) in [("2026-10-13T09:00", "2026-10-13T10:00"), ("2026-10-13T09:30", "2026-10-13T11:00"), ("2026-10-13T14:00", "2026-10-13T15:00")] {
        carol.post(&format!("/api/me/calendars/{carols}/events"), event("Secret meeting", start, end)).await;
    }
    let free = bob.get(&format!("/api/me/calendars/freebusy?from={}&to={}&emails=Carol@example.org,eve@other.example,ghost@example.org", at("2026-10-13 00:00"), at("2026-10-14 00:00"))).await;
    assert_eq!(free.status, StatusCode::OK, "{}", free.text);
    assert_eq!(free.body[0], json!({ "email": "carol@example.org", "known": true, "busy": [{ "start": at("2026-10-13 09:00"), "end": at("2026-10-13 11:00") }, { "start": at("2026-10-13 14:00"), "end": at("2026-10-13 15:00") }] }));
    assert_eq!((free.body[1]["known"].clone(), free.body[2]["known"].clone()), (json!(false), json!(false)));
    assert!(!free.text.contains("Secret"));
    assert_eq!(bob.get("/api/me/calendars/freebusy?from=0&to=999999999&emails=carol@example.org").await.status, StatusCode::BAD_REQUEST);

    // To-dos: made here, completed here, and the same objects a calendar program sees.
    let task = bob.post(&format!("/api/me/calendars/{bobs}/tasks"), json!({ "summary": "Pay the invoice", "due": "2026-10-20" })).await;
    assert_eq!(task.status, StatusCode::OK, "{}", task.text);
    let task_id = task.body["id"].as_i64().unwrap();
    bob.post(&format!("/api/me/calendars/{bobs}/tasks"), json!({ "summary": "Some day" })).await;
    let dav = Dav::new(&env, "bob@example.org");
    let phone = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTODO\r\nUID:phone-task\r\nDTSTAMP:20261001T000000Z\r\nSUMMARY:Call the bank\r\nDUE;VALUE=DATE:20261015\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
    assert_eq!(dav.send("PUT", "/dav/calendars/bob@example.org/personal/phone-task.ics", &[], phone).await.status, StatusCode::CREATED);
    let tasks = bob.get("/api/me/calendars/tasks").await.body;
    assert_eq!(tasks.as_array().unwrap().iter().map(|t| (t["summary"].as_str().unwrap(), t["due"].as_str().unwrap(), t["completed"].as_bool().unwrap())).collect::<Vec<_>>(), [("Call the bank", "2026-10-15", false), ("Pay the invoice", "2026-10-20", false), ("Some day", "", false)]);
    assert_eq!(bob.put(&format!("/api/me/calendars/{bobs}/tasks/{task_id}"), json!({ "summary": "Pay the invoice", "due": "2026-10-20", "completed": true })).await.status, StatusCode::OK);
    let tasks = bob.get("/api/me/calendars/tasks").await.body;
    assert_eq!((tasks[2]["summary"].clone(), tasks[2]["completed"].clone()), (json!("Pay the invoice"), json!(true)), "done tasks sink to the bottom");
    let todos = dav.send("REPORT", "/dav/calendars/bob@example.org/personal/", &[], r#"<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-data/></d:prop><c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VTODO"/></c:comp-filter></c:filter></c:calendar-query>"#).await;
    assert!(todos.text.contains("STATUS:COMPLETED") && todos.text.matches("BEGIN:VTODO").count() == 3, "{}", todos.text);
    assert_eq!(bob.post(&format!("/api/me/calendars/{bobs}/tasks"), json!({ "summary": " " })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(carol.put(&format!("/api/me/calendars/{bobs}/tasks/{task_id}"), json!({ "summary": "x" })).await.status, StatusCode::NOT_FOUND);
    assert_eq!(bob.delete(&format!("/api/me/calendars/{bobs}/events/{task_id}")).await.status, StatusCode::OK);
    assert_eq!(bob.get("/api/me/calendars/tasks").await.body.as_array().unwrap().len(), 2);
    assert_eq!(bob.get(&window("2026-10-01 00:00", "2026-11-01 00:00")).await.body, json!([]), "tasks are not events");

    // Reminders: due times inside the window asked for.
    let mut standup = event("Stand-up", "2026-10-05T09:00", "2026-10-05T09:15");
    standup["rrule"] = json!("FREQ=DAILY;COUNT=5");
    standup["reminder"] = json!(15);
    let standup_id = bob.post(&format!("/api/me/calendars/{bobs}/events"), standup).await.body["id"].as_i64().unwrap();
    let due = bob.get(&format!("/api/me/calendars/reminders?from={}&to={}", at("2026-10-06 00:00"), at("2026-10-07 00:00"))).await.body;
    assert_eq!(due, json!([{ "id": standup_id, "calendar_id": bobs, "at": at("2026-10-06 08:45"), "start": at("2026-10-06 09:00"), "all_day": false, "summary": "Stand-up", "location": "" }]));
    assert_eq!(bob.get(&format!("/api/me/calendars/reminders?from={}&to={}", at("2026-10-06 08:46"), at("2026-10-06 09:30"))).await.body, json!([]));
    assert_eq!(bob.get("/api/me/calendars/reminders?from=0&to=999999999").await.status, StatusCode::BAD_REQUEST);

    // One occurrence of the series is moved and renamed; the others stay.
    let third = at("2026-10-07 09:00");
    let shown = bob.get(&format!("/api/me/calendars/{bobs}/events/{standup_id}?occurrence={third}")).await.body["event"].clone();
    assert_eq!((shown["start"].clone(), shown["rrule"].clone()), (json!("2026-10-07T09:00"), json!("")));
    let mut changed = shown.clone();
    changed["summary"] = json!("Stand-up (late)");
    changed["start"] = json!("2026-10-07T11:00");
    changed["end"] = json!("2026-10-07T11:15");
    changed["occurrence"] = json!(third);
    assert_eq!(bob.put(&format!("/api/me/calendars/{bobs}/events/{standup_id}"), changed).await.status, StatusCode::OK);
    let week = bob.get(&window("2026-10-05 00:00", "2026-10-10 00:00")).await.body;
    assert_eq!(week.as_array().unwrap().iter().map(|e| (e["start"].as_i64().unwrap(), e["summary"].as_str().unwrap())).collect::<Vec<_>>(), [(at("2026-10-05 09:00"), "Stand-up"), (at("2026-10-06 09:00"), "Stand-up"), (at("2026-10-07 11:00"), "Stand-up (late)"), (at("2026-10-08 09:00"), "Stand-up"), (at("2026-10-09 09:00"), "Stand-up")]);
    assert_eq!(week[2]["recurrence_id"], third);
    assert_eq!(bob.get(&format!("/api/me/calendars/{bobs}/events/{standup_id}?occurrence={third}")).await.body["event"]["summary"], "Stand-up (late)");
    assert_eq!(bob.get(&format!("/api/me/calendars/reminders?from={}&to={}", at("2026-10-07 00:00"), at("2026-10-08 00:00"))).await.body[0]["at"], at("2026-10-07 10:45"), "the reminder moves along");
    let mut nowhere = shown.clone();
    nowhere["occurrence"] = json!(at("2026-10-07 10:00"));
    assert_eq!(bob.put(&format!("/api/me/calendars/{bobs}/events/{standup_id}"), nowhere).await.status, StatusCode::BAD_REQUEST);
    // Deleting the changed occurrence leaves four.
    assert_eq!(bob.delete(&format!("/api/me/calendars/{bobs}/events/{standup_id}?occurrence={third}")).await.status, StatusCode::OK);
    assert_eq!(bob.get(&window("2026-10-05 00:00", "2026-10-10 00:00")).await.body.as_array().unwrap().len(), 4);

    // Times that name no zone are wall-clock times in the reader's own zone.
    let floating = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:floating\r\nDTSTAMP:20261001T000000Z\r\nDTSTART:20261020T100000\r\nDTEND:20261020T110000\r\nSUMMARY:Ten o'clock\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    assert_eq!(dav.send("PUT", "/dav/calendars/bob@example.org/personal/floating.ics", &[], floating).await.status, StatusCode::CREATED);
    let day = window("2026-10-20 00:00", "2026-10-21 00:00");
    assert_eq!(bob.get(&day).await.body[0]["start"], at("2026-10-20 10:00"), "without a known zone: UTC");
    assert_eq!(bob.get("/api/me/calendars").await.body["timezone"], "UTC");
    assert_eq!(bob.put("/api/me/preferences", json!({ "timezone": "Europe/Warsaw" })).await.status, StatusCode::OK);
    assert_eq!(bob.get("/api/me/calendars").await.body["timezone"], "Europe/Warsaw");
    assert_eq!(bob.get(&day).await.body[0]["start"], at("2026-10-20 08:00"));
    let range = |start: &str, end: &str| format!(r#"<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/></d:prop><c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT"><c:time-range start="{start}" end="{end}"/></c:comp-filter></c:comp-filter></c:filter></c:calendar-query>"#);
    assert!(dav.send("REPORT", "/dav/calendars/bob@example.org/personal/", &[], &range("20261020T080000Z", "20261020T083000Z")).await.text.contains("floating.ics"));
    assert!(!dav.send("REPORT", "/dav/calendars/bob@example.org/personal/", &[], &range("20261020T093000Z", "20261020T103000Z")).await.text.contains("floating.ics"));
}

#[tokio::test]
async fn the_address_book_synchronises_over_carddav() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account("carol@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let dav = Dav::new(&env, "bob@example.org");
    const BOOK: &str = "/dav/addressbooks/bob@example.org/contacts/";

    // Discovery.
    assert_eq!(dav.send("PROPFIND", "/.well-known/carddav", &[], "").await.headers[header::LOCATION], "/dav/");
    assert!(dav.send("OPTIONS", "/dav/", &[], "").await.headers["dav"].to_str().unwrap().contains("addressbook"));
    let principal = dav.send("PROPFIND", "/dav/principals/bob@example.org/", &[("depth", "0")], r#"<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav"><d:prop><c:addressbook-home-set/></d:prop></d:propfind>"#).await;
    assert!(principal.text.contains("<CR:addressbook-home-set><D:href>/dav/addressbooks/bob@example.org/</D:href>"), "{}", principal.text);
    let home = dav.send("PROPFIND", "/dav/addressbooks/bob@example.org/", &[("depth", "1")], "").await;
    assert!(home.text.contains(BOOK) && home.text.contains("<CR:addressbook/>"), "{}", home.text);

    // A contact made in the web client is a card.
    let anna = bob.post("/api/me/contacts", json!({ "name": "Anna Kowalska", "email": "anna@partner.example", "organization": "Partner" })).await.body;
    let listing = dav.send("PROPFIND", BOOK, &[("depth", "1")], r#"<d:propfind xmlns:d="DAV:"><d:prop><d:getetag/></d:prop></d:propfind>"#).await;
    let href = listing.text.split("<D:href>").filter_map(|part| part.split('<').next()).find(|href| href.ends_with(".vcf")).unwrap().to_owned();
    let card = dav.send("GET", &href, &[], "").await;
    assert!(card.headers[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/vcard"));
    assert!(card.text.contains("FN:Anna Kowalska\r\n") && card.text.contains("EMAIL;TYPE=INTERNET:anna@partner.example\r\n") && card.text.contains("ORG:Partner\r\n") && card.text.contains("N:Kowalska;Anna;;;"), "{}", card.text);
    let etag = card.headers[header::ETAG].to_str().unwrap().to_owned();

    // A phone stores cards: with a photo and two addresses, and one without any address.
    let jan = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:jan-1\r\nFN:Jan Nowak\r\nN:Nowak;Jan;;;\r\nEMAIL;TYPE=WORK:jan@work.example\r\nEMAIL;TYPE=HOME:jan@home.example\r\nTEL;TYPE=CELL:+48 600 100 200\r\nBDAY:1980-01-01\r\nPHOTO;ENCODING=b;TYPE=JPEG:AAAA\r\nEND:VCARD\r\n";
    let put = dav.send("PUT", &format!("{BOOK}jan-1.vcf"), &[("if-none-match", "*")], jan).await;
    assert_eq!(put.status, StatusCode::CREATED, "{}", put.text);
    assert_eq!(dav.send("PUT", &format!("{BOOK}jan-1.vcf"), &[("if-none-match", "*")], jan).await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(dav.send("GET", &format!("{BOOK}jan-1.vcf"), &[], "").await.text, jan, "kept byte for byte");
    let plumber = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:plumber\r\nFN:Plumber\r\nTEL:112\r\nEND:VCARD\r\n";
    assert_eq!(dav.send("PUT", &format!("{BOOK}plumber.vcf"), &[], plumber).await.status, StatusCode::CREATED);
    // The same address twice is fine for a phone.
    assert_eq!(dav.send("PUT", &format!("{BOOK}twin.vcf"), &[], &jan.replace("jan-1", "twin")).await.status, StatusCode::CREATED);
    for (name, body) in [("bad.vcf", "hello"), ("two.vcf", &format!("{jan}{jan}") as &str), ("wrong.txt", jan), ("..%2Fx.vcf", jan)] {
        assert_eq!(dav.send("PUT", &format!("{BOOK}{name}"), &[], body).await.status, StatusCode::FORBIDDEN, "{name}");
    }

    // The web client shows them, and its suggestions skip the one without an address.
    let contacts = bob.get("/api/me/contacts").await.body;
    let names: Vec<&str> = contacts.as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["Anna Kowalska", "Jan Nowak", "Jan Nowak", "Plumber"]);
    let jan_row = contacts.as_array().unwrap().iter().find(|c| c["name"] == "Jan Nowak").unwrap().clone();
    assert_eq!((jan_row["email"].clone(), jan_row["phone"].clone()), (json!("jan@work.example"), json!("+48 600 100 200")));
    let suggested = bob.get("/api/me/contacts/suggest?q=plumb").await;
    assert!(!suggested.text.contains("Plumber"), "{}", suggested.text);
    // In the web client an address stays unique among its own entries.
    assert_eq!(bob.post("/api/me/contacts", json!({ "name": "Other Anna", "email": "anna@partner.example" })).await.status, StatusCode::CONFLICT);

    // Synchronisation: a first full pass, then only what changed.
    let sync = |token: &str| format!(r#"<d:sync-collection xmlns:d="DAV:"><d:sync-token>{token}</d:sync-token><d:sync-level>1</d:sync-level><d:prop><d:getetag/></d:prop></d:sync-collection>"#);
    let token_in = |text: &str| text.split("<D:sync-token>").nth(1).unwrap().split('<').next().unwrap().to_owned();
    let first = dav.send("REPORT", BOOK, &[], &sync("")).await;
    assert_eq!(first.text.matches(".vcf</D:href>").count(), 4, "{}", first.text);
    let token = token_in(&first.text);
    assert!(!dav.send("REPORT", BOOK, &[], &sync(&token)).await.text.contains(".vcf"));

    // An edit in the web client reaches the phone, and keeps what the phone stored.
    let id = jan_row["id"].as_i64().unwrap();
    assert_eq!(bob.put(&format!("/api/me/contacts/{id}"), json!({ "name": "Jan Nowak", "email": "jan@work.example", "phone": "+48 600 999 999", "notes": "Prefers calls" })).await.status, StatusCode::OK);
    assert_eq!(bob.delete(&format!("/api/me/contacts/{}", anna["id"])).await.status, StatusCode::OK);
    let changed = dav.send("REPORT", BOOK, &[], &sync(&token)).await;
    assert!(changed.text.contains("jan-1.vcf</D:href><D:propstat>") && !changed.text.contains("plumber.vcf"), "{}", changed.text);
    assert!(changed.text.contains(&format!("{href}</D:href><D:status>HTTP/1.1 404")), "the deletion is reported: {}", changed.text);
    assert_ne!(token_in(&changed.text), token);
    let edited = dav.send("GET", &format!("{BOOK}jan-1.vcf"), &[], "").await.text;
    assert!(edited.contains("TEL:+48 600 999 999\r\n") && edited.contains("NOTE:Prefers calls\r\n"), "{edited}");
    for kept in ["EMAIL;TYPE=WORK:jan@work.example", "EMAIL;TYPE=HOME:jan@home.example", "BDAY:1980-01-01", "PHOTO;ENCODING=b;TYPE=JPEG:AAAA", "UID:jan-1", "N:Nowak;Jan;;;"] {
        assert!(edited.contains(kept), "{kept} in {edited}");
    }
    assert_eq!(dav.send("GET", &href, &[], "").await.status, StatusCode::NOT_FOUND);
    assert_eq!(dav.send("REPORT", BOOK, &[], &sync("urn:unomail:sync:99999")).await.status, StatusCode::FORBIDDEN);

    // The phone changes and deletes; entity tags guard both.
    let stale = dav.send("PUT", &format!("{BOOK}plumber.vcf"), &[("if-match", &etag)], &plumber.replace("112", "997")).await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    let current = dav.send("GET", &format!("{BOOK}plumber.vcf"), &[], "").await.headers[header::ETAG].to_str().unwrap().to_owned();
    assert_eq!(dav.send("PUT", &format!("{BOOK}plumber.vcf"), &[("if-match", &current)], &plumber.replace("112", "997")).await.status, StatusCode::NO_CONTENT);
    assert_eq!(bob.get("/api/me/contacts?q=Plumber").await.body[0]["phone"], "997");
    assert_eq!(dav.send("DELETE", &format!("{BOOK}plumber.vcf"), &[("if-match", &current)], "").await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(dav.send("DELETE", &format!("{BOOK}plumber.vcf"), &[], "").await.status, StatusCode::NO_CONTENT);
    assert_eq!(bob.get("/api/me/contacts?q=Plumber").await.body, json!([]));

    // Reports: several cards at once, and a search.
    let multiget = dav.send("REPORT", BOOK, &[], &format!(r#"<c:addressbook-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav"><d:prop><d:getetag/><c:address-data/></d:prop><d:href>{BOOK}jan-1.vcf</d:href><d:href>{BOOK}gone.vcf</d:href></c:addressbook-multiget>"#)).await;
    assert!(multiget.text.contains("FN:Jan Nowak") && multiget.text.contains("gone.vcf</D:href><D:status>HTTP/1.1 404"), "{}", multiget.text);
    let search = dav.send("REPORT", BOOK, &[], r#"<c:addressbook-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav"><d:prop><c:address-data/></d:prop><c:filter><c:prop-filter name="EMAIL"><c:text-match>HOME.example</c:text-match></c:prop-filter></c:filter></c:addressbook-query>"#).await;
    assert_eq!(search.text.matches("<D:response>").count(), 2, "{}", search.text);
    assert_eq!(dav.send("REPORT", BOOK, &[], r#"<c:addressbook-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav"><d:prop><d:getetag/></d:prop><c:filter><c:prop-filter name="FN"><c:text-match>nobody</c:text-match></c:prop-filter></c:filter></c:addressbook-query>"#).await.text.matches("<D:response>").count(), 0);

    // Groups made in the web client keep their members through all of this.
    let group = bob.post("/api/me/contact-groups", json!({ "name": "Friends" })).await.body["id"].as_i64().unwrap();
    assert_eq!(bob.put(&format!("/api/me/contact-groups/{group}/members"), json!({ "contact_ids": [id] })).await.status, StatusCode::OK);
    assert_eq!(bob.get(&format!("/api/me/contact-groups/{group}/members")).await.body, json!([id]));

    // Somebody else's address book is out of reach, and an account can still be deleted.
    let carol = Dav::new(&env, "carol@example.org");
    for (method, path) in [("PROPFIND", BOOK.to_owned()), ("GET", format!("{BOOK}jan-1.vcf")), ("PUT", format!("{BOOK}planted.vcf")), ("DELETE", format!("{BOOK}jan-1.vcf")), ("REPORT", BOOK.to_owned())] {
        assert_eq!(carol.send(method, &path, &[], jan).await.status, StatusCode::FORBIDDEN, "{method} {path}");
    }
    assert!(!carol.send("REPORT", "/dav/addressbooks/carol@example.org/contacts/", &[], &format!(r#"<c:addressbook-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav"><d:prop><c:address-data/></d:prop><d:href>{BOOK}jan-1.vcf</d:href></c:addressbook-multiget>"#)).await.text.contains("Jan"));
    sqlx::query("DELETE FROM accounts WHERE email = 'bob@example.org'").execute(&env.app.db).await.unwrap();
    let left: i64 = sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM contacts) + (SELECT COUNT(*) FROM contact_tombstones) + (SELECT COUNT(*) FROM addressbooks)").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(left, 0);
}
