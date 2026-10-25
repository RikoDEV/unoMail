//! Calendars: the CalDAV protocol as calendar programs speak it, and the web client's API.

mod common;

use axum::{
    Extension,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use base64::Engine;
use common::{Api, PASSWORD, TestEnv};
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

struct Dav {
    api: Api,
    authorization: Option<String>,
}

struct DavReply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    text: String,
}

impl Dav {
    fn new(env: &TestEnv, user: &str, password: &str) -> Self {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        Dav { api: Api::new(env), authorization: Some(format!("Basic {token}")) }
    }

    async fn send(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> DavReply {
        let mut request = Request::builder().method(Method::from_bytes(method.as_bytes()).unwrap()).uri(path);
        if let Some(authorization) = &self.authorization {
            request = request.header(header::AUTHORIZATION, authorization);
        }
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

fn event(uid: &str, summary: &str, start: &str, extra: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20261001T000000Z\r\nDTSTART:{start}\r\nDURATION:PT1H\r\nSUMMARY:{summary}\r\n{extra}END:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

const HOME: &str = "/dav/calendars/bob@example.org/";

#[tokio::test]
async fn a_calendar_program_discovers_and_synchronises_a_calendar() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let dav = Dav::new(&env, "bob@example.org", PASSWORD);

    // Discovery: well-known address, then principal, then the calendar home.
    let hint = dav.send("PROPFIND", "/.well-known/caldav", &[], "").await;
    assert_eq!(hint.status, StatusCode::MOVED_PERMANENTLY);
    assert_eq!(hint.headers[header::LOCATION], "/dav/");
    let options = dav.send("OPTIONS", "/dav/", &[], "").await;
    assert!(options.headers["dav"].to_str().unwrap().contains("calendar-access"));

    let root = dav.send("PROPFIND", "/dav/", &[("depth", "0")], r#"<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>"#).await;
    assert_eq!(root.status, StatusCode::MULTI_STATUS);
    assert!(root.text.contains("<D:href>/dav/principals/bob@example.org/</D:href>"), "{}", root.text);
    let principal = dav.send("PROPFIND", "/dav/principals/bob@example.org/", &[("depth", "0")], r#"<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-home-set/><d:nonsense/></d:prop></d:propfind>"#).await;
    assert!(principal.text.contains(&format!("<C:calendar-home-set><D:href>{HOME}</D:href>")), "{}", principal.text);
    assert!(principal.text.contains("<D:nonsense/>") && principal.text.contains("404 Not Found"), "unknown properties are reported as missing");

    // Every account starts with one calendar.
    let home = dav.send("PROPFIND", HOME, &[("depth", "1")], "").await;
    assert!(home.text.contains(&format!("{HOME}personal/")) && home.text.contains("<C:calendar/>"), "{}", home.text);
    assert!(home.text.contains("<D:displayname>Personal</D:displayname>"));

    // A second one, created by the client.
    let made = dav
        .send("MKCALENDAR", &format!("{HOME}work/"), &[], r#"<c:mkcalendar xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav" xmlns:a="http://apple.com/ns/ical/"><d:set><d:prop><d:displayname>Work &amp; travel</d:displayname><a:calendar-color>#ff0000ff</a:calendar-color></d:prop></d:set></c:mkcalendar>"#)
        .await;
    assert_eq!(made.status, StatusCode::CREATED, "{}", made.text);
    assert_eq!(dav.send("MKCALENDAR", &format!("{HOME}work/"), &[], "").await.status, StatusCode::METHOD_NOT_ALLOWED, "it exists already");
    let work = format!("{HOME}work/");
    let listed = dav.send("PROPFIND", &work, &[("depth", "0")], "").await;
    assert!(listed.text.contains("Work &amp; travel") && listed.text.contains("#ff0000ff"), "{}", listed.text);

    // Storing events.
    let put = dav.send("PUT", &format!("{work}one.ics"), &[("if-none-match", "*")], &event("one@test", "First", "20261013T100000Z", "")).await;
    assert_eq!(put.status, StatusCode::CREATED, "{}", put.text);
    let etag = put.headers[header::ETAG].to_str().unwrap().to_owned();
    assert_eq!(dav.send("PUT", &format!("{work}one.ics"), &[("if-none-match", "*")], &event("one@test", "First", "20261013T100000Z", "")).await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(dav.send("PUT", &format!("{work}two.ics"), &[], &event("two@test", "Weekly", "20261005T090000Z", "RRULE:FREQ=WEEKLY\r\n")).await.status, StatusCode::CREATED);
    // The same event cannot live twice in a calendar, and rubbish is refused.
    assert_eq!(dav.send("PUT", &format!("{work}copy.ics"), &[], &event("one@test", "Copy", "20261013T100000Z", "")).await.status, StatusCode::CONFLICT);
    assert_eq!(dav.send("PUT", &format!("{work}bad.ics"), &[], "not a calendar").await.status, StatusCode::FORBIDDEN);
    assert_eq!(dav.send("PUT", &format!("{work}..%2Fescape.ics"), &[], &event("x@test", "X", "20261013T100000Z", "")).await.status, StatusCode::FORBIDDEN);

    let got = dav.send("GET", &format!("{work}one.ics"), &[], "").await;
    assert_eq!(got.text, event("one@test", "First", "20261013T100000Z", ""), "objects are kept byte for byte");
    assert_eq!(got.headers[header::ETAG].to_str().unwrap(), etag);
    assert_eq!(got.headers[header::CACHE_CONTROL], "no-store");
    // Byte ranges (RFC 7233).
    let part = dav.send("GET", &format!("{work}one.ics"), &[("range", "bytes=0-14")], "").await;
    assert_eq!((part.status, part.text.as_str()), (StatusCode::PARTIAL_CONTENT, "BEGIN:VCALENDAR"));
    assert_eq!(dav.send("GET", &format!("{work}one.ics"), &[("range", "bytes=99999-")], "").await.status, StatusCode::RANGE_NOT_SATISFIABLE);
    // Prefer: return=minimal (RFC 8144) leaves out the missing properties; quotas (RFC 4331).
    let minimal = dav.send("PROPFIND", &work, &[("depth", "0"), ("prefer", "return=minimal")], r#"<d:propfind xmlns:d="DAV:"><d:prop><d:displayname/><d:nonsense/><d:quota-used-bytes/></d:prop></d:propfind>"#).await;
    assert!(minimal.text.contains("<D:quota-used-bytes>") && !minimal.text.contains("nonsense"), "{}", minimal.text);
    assert_eq!(minimal.headers["preference-applied"], "return=minimal");
    // Extended MKCOL (RFC 5689) makes calendars too, and nothing else.
    let mkcol = r#"<d:mkcol xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:set><d:prop><d:resourcetype><d:collection/><c:calendar/></d:resourcetype><d:displayname>Made by MKCOL</d:displayname></d:prop></d:set></d:mkcol>"#;
    assert_eq!(dav.send("MKCOL", &format!("{HOME}mkcol/"), &[], mkcol).await.status, StatusCode::CREATED);
    assert_eq!(dav.send("MKCOL", &format!("{HOME}plain/"), &[], "").await.status, StatusCode::FORBIDDEN);
    assert!(dav.send("PROPFIND", &format!("{HOME}mkcol/"), &[("depth", "0")], "").await.text.contains("Made by MKCOL"));

    // Updating needs the current version.
    let stale = dav.send("PUT", &format!("{work}one.ics"), &[("if-match", "\"stale\"")], &event("one@test", "Renamed", "20261013T100000Z", "")).await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    let updated = dav.send("PUT", &format!("{work}one.ics"), &[("if-match", &etag)], &event("one@test", "Renamed", "20261013T100000Z", "")).await;
    assert_eq!(updated.status, StatusCode::NO_CONTENT);
    assert_ne!(updated.headers[header::ETAG].to_str().unwrap(), etag);

    // Listing with entity tags, as clients do to find what changed.
    let listing = dav.send("PROPFIND", &work, &[("depth", "1")], r#"<d:propfind xmlns:d="DAV:"><d:prop><d:getetag/></d:prop></d:propfind>"#).await;
    assert!(listing.text.contains(&format!("{work}one.ics")) && listing.text.contains(&format!("{work}two.ics")), "{}", listing.text);

    // Time-range query: the weekly series reaches into November, the single event does not.
    let query = |start: &str, end: &str| {
        format!(
            r#"<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/><c:calendar-data/></d:prop><c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT"><c:time-range start="{start}" end="{end}"/></c:comp-filter></c:comp-filter></c:filter></c:calendar-query>"#
        )
    };
    let october = dav.send("REPORT", &work, &[("depth", "1")], &query("20261012T000000Z", "20261019T000000Z")).await;
    assert_eq!(october.status, StatusCode::MULTI_STATUS);
    assert!(october.text.contains("one.ics") && october.text.contains("two.ics") && october.text.contains("SUMMARY:Renamed"), "{}", october.text);
    let november = dav.send("REPORT", &work, &[("depth", "1")], &query("20261102T000000Z", "20261103T000000Z")).await;
    assert!(!november.text.contains("one.ics") && november.text.contains("two.ics"), "{}", november.text);
    let before = dav.send("REPORT", &work, &[("depth", "1")], &query("20260901T000000Z", "20260902T000000Z")).await;
    assert!(!before.text.contains(".ics"), "{}", before.text);

    let multiget = dav
        .send("REPORT", &work, &[], &format!(r#"<c:calendar-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-data/></d:prop><d:href>{work}two.ics</d:href><d:href>{work}gone.ics</d:href></c:calendar-multiget>"#))
        .await;
    assert!(multiget.text.contains("SUMMARY:Weekly") && multiget.text.contains("gone.ics</D:href><D:status>HTTP/1.1 404"), "{}", multiget.text);

    // Incremental synchronisation.
    let sync = |token: &str| format!(r#"<d:sync-collection xmlns:d="DAV:"><d:sync-token>{token}</d:sync-token><d:sync-level>1</d:sync-level><d:prop><d:getetag/></d:prop></d:sync-collection>"#);
    let token_in = |text: &str| text.split("<D:sync-token>").nth(1).unwrap().split('<').next().unwrap().to_owned();
    let first = dav.send("REPORT", &work, &[], &sync("")).await;
    assert!(first.text.contains("one.ics") && first.text.contains("two.ics"), "{}", first.text);
    let token = token_in(&first.text);
    let idle = dav.send("REPORT", &work, &[], &sync(&token)).await;
    assert!(!idle.text.contains(".ics"), "nothing changed: {}", idle.text);
    assert_eq!(token_in(&idle.text), token);

    assert_eq!(dav.send("DELETE", &format!("{work}one.ics"), &[("if-match", "\"stale\"")], "").await.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(dav.send("DELETE", &format!("{work}one.ics"), &[], "").await.status, StatusCode::NO_CONTENT);
    assert_eq!(dav.send("PUT", &format!("{work}three.ics"), &[], &event("three@test", "Third", "20261020T100000Z", "")).await.status, StatusCode::CREATED);
    let changed = dav.send("REPORT", &work, &[], &sync(&token)).await;
    assert!(changed.text.contains("three.ics") && !changed.text.contains("two.ics"), "{}", changed.text);
    assert!(changed.text.contains(&format!("{work}one.ics</D:href><D:status>HTTP/1.1 404")), "removals are reported: {}", changed.text);
    assert_ne!(token_in(&changed.text), token);
    assert_eq!(dav.send("REPORT", &work, &[], &sync("urn:unomail:sync:999999")).await.status, StatusCode::FORBIDDEN, "a token from the future");
    assert_eq!(dav.send("GET", &format!("{work}one.ics"), &[], "").await.status, StatusCode::NOT_FOUND);

    // Renaming through PROPPATCH; the whole calendar as one file; deleting the calendar.
    let patch = dav.send("PROPPATCH", &work, &[], r#"<d:propertyupdate xmlns:d="DAV:"><d:set><d:prop><d:displayname>Office</d:displayname></d:prop></d:set></d:propertyupdate>"#).await;
    assert_eq!(patch.status, StatusCode::MULTI_STATUS);
    assert!(dav.send("PROPFIND", &work, &[("depth", "0")], "").await.text.contains("<D:displayname>Office</D:displayname>"));
    let whole = dav.send("GET", &work, &[], "").await;
    assert!(whole.text.contains("SUMMARY:Weekly") && whole.text.contains("SUMMARY:Third") && whole.text.matches("BEGIN:VCALENDAR").count() == 1, "{}", whole.text);
    assert_eq!(dav.send("DELETE", &work, &[], "").await.status, StatusCode::NO_CONTENT);
    assert_eq!(dav.send("PROPFIND", &work, &[], "").await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn calendars_are_private_and_need_the_password() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account("carol@example.org").await;
    let bob = Dav::new(&env, "bob@example.org", PASSWORD);
    let carol = Dav::new(&env, "carol@example.org", PASSWORD);
    assert_eq!(bob.send("PUT", &format!("{HOME}personal/secret.ics"), &[], &event("secret@test", "Secret", "20261013T100000Z", "")).await.status, StatusCode::CREATED);

    // Without or with wrong credentials nothing is revealed, whether or not the path exists.
    let anonymous = Dav { api: Api::new(&env), authorization: None };
    for path in ["/dav/", HOME, "/dav/calendars/bob@example.org/personal/secret.ics", "/dav/calendars/nobody@example.org/"] {
        let reply = anonymous.send("PROPFIND", path, &[], "").await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{path}");
        assert!(reply.headers[header::WWW_AUTHENTICATE].to_str().unwrap().starts_with("Basic"));
    }
    assert_eq!(Dav::new(&env, "bob@example.org", "wrong").send("GET", &format!("{HOME}personal/secret.ics"), &[], "").await.status, StatusCode::UNAUTHORIZED);

    // Another user is refused everywhere in Bob's tree.
    for (method, path) in [
        ("PROPFIND", HOME.to_owned()),
        ("PROPFIND", "/dav/principals/bob@example.org/".to_owned()),
        ("GET", format!("{HOME}personal/secret.ics")),
        ("PUT", format!("{HOME}personal/planted.ics")),
        ("DELETE", format!("{HOME}personal/secret.ics")),
        ("DELETE", format!("{HOME}personal/")),
        ("MKCALENDAR", format!("{HOME}mine/")),
        ("REPORT", format!("{HOME}personal/")),
    ] {
        let reply = carol.send(method, &path, &[], &event("planted@test", "Planted", "20261013T100000Z", "")).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{method} {path}");
        assert!(!reply.text.contains("Secret"));
    }
    // A multiget cannot reach into another calendar by naming its address.
    let reach = carol
        .send("REPORT", "/dav/calendars/carol@example.org/personal/", &[], &format!(r#"<c:calendar-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-data/></d:prop><d:href>{HOME}personal/secret.ics</d:href></c:calendar-multiget>"#))
        .await;
    assert!(!reach.text.contains("Secret") && reach.text.contains("404"), "{}", reach.text);
    assert_eq!(bob.send("GET", &format!("{HOME}personal/secret.ics"), &[], "").await.status, StatusCode::OK, "untouched");

    // A changed password locks out a client that still sends the old one, cached or not.
    let api = Api::logged_in(&env, "bob@example.org").await;
    assert_eq!(api.post("/api/auth/password", json!({ "current_password": PASSWORD, "new_password": "a brand new long passphrase" })).await.status, StatusCode::OK);
    assert_eq!(bob.send("PROPFIND", HOME, &[], "").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(Dav::new(&env, "bob@example.org", "a brand new long passphrase").send("PROPFIND", HOME, &[], "").await.status, StatusCode::MULTI_STATUS);

    // Guessing passwords over CalDAV runs into the same limiter as every other protocol.
    let mut limited = false;
    for attempt in 0..12 {
        let reply = Dav::new(&env, "carol@example.org", &format!("guess-{attempt}")).send("PROPFIND", "/dav/", &[], "").await;
        limited |= reply.status == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(limited, "repeated failures are throttled");
}

#[tokio::test]
async fn the_web_client_manages_calendars_and_events() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account("carol@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let at = |text: &str| chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M").unwrap().and_utc().timestamp();

    assert_eq!(Api::new(&env).get("/api/me/calendars").await.status, StatusCode::UNAUTHORIZED);
    let listing = api.get("/api/me/calendars").await.body;
    assert_eq!(listing["calendars"].as_array().unwrap().len(), 1);
    let personal = listing["calendars"][0]["id"].as_i64().unwrap();
    assert!(listing["caldav"]["home"].as_str().unwrap().ends_with("/dav/calendars/bob@example.org/"));
    assert!(listing["calendars"][0]["url"].as_str().unwrap().ends_with("/dav/calendars/bob@example.org/personal/"));

    for bad in [json!({ "name": "" }), json!({ "name": "x", "color": "red" }), json!({ "color": "#112233" })] {
        assert_eq!(api.post("/api/me/calendars", bad.clone()).await.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let work = api.post("/api/me/calendars", json!({ "name": "Work & Travel", "color": "#d93025" })).await.body;
    assert_eq!(work["slug"], "work-travel");
    assert_eq!(api.post("/api/me/calendars", json!({ "name": "Work, travel" })).await.body["slug"], "work-travel-2", "addresses stay unique");
    let work = work["id"].as_i64().unwrap();
    assert_eq!(api.patch(&format!("/api/me/calendars/{work}"), json!({ "name": "Office", "color": "#188038" })).await.status, StatusCode::OK);
    let names: Vec<String> = api.get("/api/me/calendars").await.body["calendars"].as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap().to_owned()).collect();
    assert!(names.contains(&"Office".to_owned()) && names.contains(&"Personal".to_owned()), "{names:?}");

    // A timed event in a time zone, and what is refused.
    let lunch = json!({ "summary": "Lunch", "location": "Canteen", "description": "With Anna", "start": "2026-10-13T12:00", "end": "2026-10-13T13:00", "timezone": "Europe/Warsaw" });
    let created = api.post(&format!("/api/me/calendars/{personal}/events"), lunch.clone()).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let lunch_id = created.body["id"].as_i64().unwrap();
    for (field, value) in [("summary", json!("  ")), ("end", json!("2026-10-13T11:00")), ("timezone", json!("Mars/Olympus")), ("start", json!("yesterday")), ("rrule", json!("FREQ=WEEKLY\r\nATTENDEE:mailto:x@y")), ("rrule", json!("NONSENSE"))] {
        let mut bad = lunch.clone();
        bad[field] = value;
        assert_eq!(api.post(&format!("/api/me/calendars/{personal}/events"), bad).await.status, StatusCode::BAD_REQUEST, "{field}");
    }
    let window = |from: &str, to: &str| format!("/api/me/calendars/events?from={}&to={}", at(from), at(to));
    let day = api.get(&window("2026-10-13 00:00", "2026-10-14 00:00")).await.body;
    assert_eq!(day.as_array().unwrap().len(), 1, "{day}");
    assert_eq!(day[0]["summary"], "Lunch");
    assert_eq!(day[0]["start"], at("2026-10-13 10:00"), "12:00 in Warsaw is 10:00 UTC in summer time");
    assert_eq!(day[0]["end"], at("2026-10-13 11:00"));
    assert_eq!(day[0]["recurring"], false);
    assert_eq!(api.get("/api/me/calendars/events?from=0&to=99999999999").await.status, StatusCode::BAD_REQUEST, "the window is bounded");

    // An all-day event over two days and a weekly series.
    api.post(&format!("/api/me/calendars/{work}/events"), json!({ "summary": "Conference", "start": "2026-10-20", "end": "2026-10-21", "all_day": true })).await;
    let standup = api.post(&format!("/api/me/calendars/{work}/events"), json!({ "summary": "Stand-up", "start": "2026-10-05T09:00", "end": "2026-10-05T09:15", "timezone": "UTC", "rrule": "FREQ=WEEKLY;COUNT=6" })).await.body["id"].as_i64().unwrap();
    let month = api.get(&window("2026-10-01 00:00", "2026-11-01 00:00")).await.body;
    let of = |list: &serde_json::Value, summary: &str| list.as_array().unwrap().iter().filter(|e| e["summary"] == summary).cloned().collect::<Vec<_>>();
    assert_eq!(of(&month, "Stand-up").len(), 4, "5, 12, 19 and 26 October");
    assert!(of(&month, "Stand-up").iter().all(|e| e["recurring"] == true && e["calendar_id"] == work));
    let conference = &of(&month, "Conference")[0];
    assert_eq!((conference["all_day"].clone(), conference["start"].clone(), conference["end"].clone()), (json!(true), json!(at("2026-10-20 00:00")), json!(at("2026-10-22 00:00"))));

    // Editing: the form gets back what was entered.
    let details = api.get(&format!("/api/me/calendars/{personal}/events/{lunch_id}")).await.body;
    assert_eq!(details["event"], json!({ "summary": "Lunch", "location": "Canteen", "description": "With Anna", "start": "2026-10-13T12:00", "end": "2026-10-13T13:00", "all_day": false, "timezone": "Europe/Warsaw", "rrule": "", "attendees": [], "reminder": null }));
    let mut later = lunch.clone();
    later["summary"] = json!("Late lunch");
    later["start"] = json!("2026-10-13T14:00");
    later["end"] = json!("2026-10-13T15:00");
    later["calendar_id"] = json!(work);
    let moved = api.put(&format!("/api/me/calendars/{personal}/events/{lunch_id}"), later).await;
    assert_eq!(moved.status, StatusCode::OK, "{}", moved.text);
    assert_eq!(moved.body["calendar_id"], work);
    let day = api.get(&window("2026-10-13 00:00", "2026-10-14 00:00")).await.body;
    assert_eq!((day.as_array().unwrap().len(), day[0]["summary"].clone(), day[0]["start"].clone(), day[0]["calendar_id"].clone()), (1, json!("Late lunch"), json!(at("2026-10-13 12:00")), json!(work)));

    // Removing one occurrence keeps the rest of the series.
    let gone = at("2026-10-12 09:00");
    assert_eq!(api.delete(&format!("/api/me/calendars/{work}/events/{standup}?occurrence={gone}")).await.status, StatusCode::OK);
    let starts: Vec<i64> = of(&api.get(&window("2026-10-01 00:00", "2026-11-01 00:00")).await.body, "Stand-up").iter().map(|e| e["start"].as_i64().unwrap()).collect();
    assert_eq!(starts, [at("2026-10-05 09:00"), at("2026-10-19 09:00"), at("2026-10-26 09:00")]);

    // What the web client stores is what a calendar program reads, and the other way round.
    let dav = Dav::new(&env, "bob@example.org", PASSWORD);
    let listing = dav.send("REPORT", "/dav/calendars/bob@example.org/work-travel/", &[], r#"<c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-data/></d:prop><c:filter><c:comp-filter name="VCALENDAR"/></c:filter></c:calendar-query>"#).await;
    assert!(listing.text.contains("SUMMARY:Stand-up") && listing.text.contains("EXDATE:20261012T090000Z") && listing.text.contains("SUMMARY:Late lunch"), "{}", listing.text);
    assert_eq!(dav.send("PUT", "/dav/calendars/bob@example.org/personal/phone.ics", &[], &event("phone@test", "From the phone", "20261014T080000Z", "BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT10M\r\nEND:VALARM\r\n")).await.status, StatusCode::CREATED);
    let phone = of(&api.get(&window("2026-10-14 00:00", "2026-10-15 00:00")).await.body, "From the phone");
    assert_eq!(phone.len(), 1);
    // Editing it in the browser keeps what the phone put there.
    let phone_id = phone[0]["id"].as_i64().unwrap();
    let edit = json!({ "summary": "Renamed in the browser", "start": "2026-10-14T08:00", "end": "2026-10-14T09:00", "timezone": "UTC" });
    assert_eq!(api.put(&format!("/api/me/calendars/{personal}/events/{phone_id}"), edit).await.status, StatusCode::OK);
    let kept = dav.send("GET", "/dav/calendars/bob@example.org/personal/phone.ics", &[], "").await.text;
    assert!(kept.contains("SUMMARY:Renamed in the browser") && kept.contains("BEGIN:VALARM") && kept.contains("UID:phone@test"), "{kept}");

    // Export and import; importing twice does not duplicate.
    let exported = api.get(&format!("/api/me/calendars/{work}/export")).await;
    assert!(exported.headers[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/calendar"));
    assert!(exported.headers[header::CONTENT_DISPOSITION].to_str().unwrap().contains("work-travel.ics"));
    assert_eq!(exported.text.matches("BEGIN:VEVENT").count(), 3, "{}", exported.text);
    let spare = api.post("/api/me/calendars", json!({ "name": "Spare" })).await.body["id"].as_i64().unwrap();
    for _ in 0..2 {
        let imported = api.raw(Method::POST, &format!("/api/me/calendars/{spare}/import"), exported.bytes.clone(), "text/calendar").await;
        assert_eq!(imported.body, json!({ "imported": 3, "skipped": 0 }), "{}", imported.text);
    }
    assert_eq!(api.raw(Method::POST, &format!("/api/me/calendars/{spare}/import"), b"hello".to_vec(), "text/calendar").await.status, StatusCode::BAD_REQUEST);
    assert_eq!(of(&api.get(&window("2026-10-01 00:00", "2026-11-01 00:00")).await.body, "Conference").len(), 2, "once in each calendar");

    // Nothing of this is reachable for another account.
    let carol = Api::logged_in(&env, "carol@example.org").await;
    assert_eq!(carol.get(&window("2026-10-01 00:00", "2026-11-01 00:00")).await.body, json!([]));
    assert_eq!(carol.get(&format!("/api/me/calendars/{work}/events/{standup}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(carol.get(&format!("/api/me/calendars/{work}/export")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(carol.post(&format!("/api/me/calendars/{work}/events"), lunch.clone()).await.status, StatusCode::NOT_FOUND);
    assert_eq!(carol.patch(&format!("/api/me/calendars/{work}"), json!({ "name": "Mine now" })).await.status, StatusCode::NOT_FOUND);
    assert_eq!(carol.delete(&format!("/api/me/calendars/{work}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(carol.delete(&format!("/api/me/calendars/{work}/events/{standup}")).await.status, StatusCode::NOT_FOUND);
    let own = carol.get("/api/me/calendars").await.body["calendars"][0]["id"].as_i64().unwrap();
    assert_eq!(carol.get(&format!("/api/me/calendars/{own}/events/{standup}")).await.status, StatusCode::NOT_FOUND, "an event id of someone else in one's own calendar");

    // Deleting: an event, a calendar with its events, but never the last calendar.
    assert_eq!(api.delete(&format!("/api/me/calendars/{work}/events/{standup}")).await.status, StatusCode::OK);
    assert!(of(&api.get(&window("2026-10-01 00:00", "2026-11-01 00:00")).await.body, "Stand-up").len() == 3, "the imported copy in Spare remains");
    assert_eq!(api.delete(&format!("/api/me/calendars/{work}")).await.status, StatusCode::OK);
    assert_eq!(carol.delete(&format!("/api/me/calendars/{own}")).await.status, StatusCode::BAD_REQUEST);
    // Deleting the account removes its calendars.
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM calendar_objects").fetch_one(&env.app.db).await.unwrap();
    assert!(before > 0);
    sqlx::query("DELETE FROM accounts WHERE email = 'bob@example.org'").execute(&env.app.db).await.unwrap();
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM calendar_objects").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(after, 0);
}
