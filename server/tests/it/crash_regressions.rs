//! Input that used to take the whole server down (release builds abort on a panic), and failures
//! that used to lose mail.

use crate::common;

use common::{Api, Client, TestEnv, message};
use serde_json::json;
use tokio::net::TcpListener;
use unomail::{imap, managesieve, smtp, util::Address};

const FROM: &str = "carol@remote.example";
const TO: &str = "bob@example.org";

async fn with_bob() -> (TestEnv, unomail::auth::Account) {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account(TO).await;
    (env, bob)
}

#[tokio::test]
async fn header_names_with_multibyte_characters_are_accepted() {
    let (env, bob) = with_bob().await;
    // Byte 7, and byte 2, fall inside the "é".
    for header in ["abcdefé: x", "aé: x"] {
        let mut smtp = Client::smtp(env.mx).await;
        let reply = smtp.send_mail(FROM, &[TO], &format!("{header}\r\n{}", message(FROM, TO, "hello", "body"))).await;
        assert!(reply.starts_with("250"), "{header}: {reply}");
    }
    assert_eq!(env.inbox(&bob).await.len(), 2);
}

#[tokio::test]
async fn sieve_survives_long_multibyte_captures_and_extreme_dates() {
    let (env, _bob) = with_bob().await;
    let api = Api::logged_in(&env, TO).await;
    let script = r#"require ["variables", "date", "fileinto"];
        if header :matches "subject" "*" { set "s" "${1}"; }
        if date :zone "+1400" "date" "year" "9999" { fileinto "Edge"; }
    "#;
    assert!(api.put("/api/me/sieve", json!({ "script": script, "active": true })).await.status.is_success());

    // Three-byte characters at an offset that puts byte 4000 inside one of them.
    let subject = format!("x{}", "語".repeat(1400));
    let mut smtp = Client::smtp(env.mx).await;
    assert!(smtp.send_mail(FROM, &[TO], &message(FROM, TO, &subject, "body")).await.starts_with("250"));

    let dated = format!("Date: Fri, 31 Dec 9999 23:59:59 -1400\r\n{}", message(FROM, TO, "edge", "body"));
    let mut smtp = Client::smtp(env.mx).await;
    assert!(smtp.send_mail(FROM, &[TO], &dated).await.starts_with("250"));
}

#[tokio::test]
async fn a_notify_address_with_a_multibyte_escape_does_not_panic() {
    let (env, _bob) = with_bob().await;
    let api = Api::logged_in(&env, TO).await;
    let script = "require \"enotify\";\nnotify \"mailto:%aż@x.example\";\n";
    // Accepted or refused, but answered.
    let reply = api.put("/api/me/sieve", json!({ "script": script, "active": false })).await;
    assert!(reply.status.is_success() || reply.status.is_client_error(), "{}", reply.status);
}

#[tokio::test]
async fn an_impossible_event_duration_is_refused() {
    let (env, _bob) = with_bob().await;
    let api = Api::logged_in(&env, TO).await;
    let account = api.jmap_account().await;
    let calendars = api.jmap(json!([["Calendar/get", { "accountId": account }, "0"]])).await;
    let calendar = calendars[0][1]["list"][0]["id"].as_str().unwrap().to_owned();
    for (duration, all_day) in [("PT9000000000000000S", false), ("P9000000000000D", true), ("P99999999999999999999D", false)] {
        let reply = api
            .jmap(json!([["CalendarEvent/set", { "accountId": account, "create": { "e": {
                "calendarIds": { &calendar: true }, "title": "long", "start": "2026-01-01T00:00:00", "duration": duration, "showWithoutTime": all_day,
            } } }, "0"]]))
            .await;
        assert_eq!(reply[0][1]["notCreated"]["e"]["type"], "invalidProperties", "{duration}: {reply}");
    }
}

#[tokio::test]
async fn imap_commands_cannot_grow_without_limit() {
    let env = TestEnv::start().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(imap::serve(env.app.clone(), listener));
    let mut client = Client::connect_tls(addr).await;
    client.read_line().await.unwrap();
    let chunk = format!(" {{1024+}}\r\n{}", "x".repeat(1024));
    client.send_raw(b"a NOOP").await;
    // 63 literals fit in the 64 KiB allowed before sign-in; announcing the next one ends it.
    for _ in 0..63 {
        client.send_raw(chunk.as_bytes()).await;
    }
    client.send_raw(b" {1024+}\r\n").await;
    assert_eq!(client.read_line().await.as_deref(), Some("* BYE command too large"));
}

#[tokio::test]
async fn managesieve_commands_cannot_grow_without_limit() {
    let env = TestEnv::start().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(managesieve::serve(env.app.clone(), listener));
    let mut client = Client::connect(addr).await;
    let chunk = format!(" {{1024+}}\r\n{}", "x".repeat(1024));
    client.send_raw(b"NOOP").await;
    for _ in 0..100 {
        client.send_raw(chunk.as_bytes()).await;
    }
    // The greeting and any reply come first, then the connection ends.
    let mut closed = false;
    for _ in 0..50 {
        if client.read_line().await.is_none() {
            closed = true;
            break;
        }
    }
    assert!(closed);
}

/// The blob's file, turned into something that exists but cannot be read.
fn break_blob(env: &TestEnv, hash: &str) {
    let path = env.app.cfg.data_dir.join("blobs").join(&hash[..2]).join(&hash[2..4]).join(hash);
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
}

#[tokio::test]
async fn storage_trouble_keeps_queued_mail_and_lost_content_is_reported() {
    let (env, bob) = with_bob().await;
    let raw = message(TO, "dave@remote.example", "queued", "body");
    let hash = env.app.store.put_blob(raw.as_bytes()).await.unwrap();
    let recipient = Address::parse("dave@remote.example").unwrap();
    smtp::delivery::enqueue(&env.app, TO, &recipient, &hash, raw.len(), None).await.unwrap();

    // The storage cannot be read: the entry waits for another try.
    break_blob(&env, &hash);
    smtp::queue::process_due(&env.app).await;
    let (status, attempts): (String, i64) = sqlx::query_as("SELECT status, attempts FROM queue").fetch_one(&env.app.db).await.unwrap();
    assert_eq!((status.as_str(), attempts), ("queued", 1));

    // The content is really gone: the entry ends, and the sender is told.
    let path = env.app.cfg.data_dir.join("blobs").join(&hash[..2]).join(&hash[2..4]).join(&hash);
    std::fs::remove_dir(&path).unwrap();
    sqlx::query("UPDATE queue SET next_attempt_at = 0").execute(&env.app.db).await.unwrap();
    smtp::queue::process_due(&env.app).await;
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM queue").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(left, 0);
    let inbox = env.inbox(&bob).await;
    assert!(inbox.iter().any(|m| m.contains("the message content was lost")), "{inbox:?}");
}


#[test]
fn an_answer_about_one_occurrence_keeps_the_series() {
    let event = |extra: &str, title: &str| format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:x\r\nBEGIN:VEVENT\r\nUID:u\r\nDTSTAMP:20260101T000000Z\r\nDTSTART:20260101T100000Z\r\n{extra}SUMMARY:{title}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n");
    let series = event("RRULE:FREQ=DAILY\r\n", "series");
    let single = event("RECURRENCE-ID:20260103T100000Z\r\n", "moved");
    let merged = unomail::calendar::ical::merge_occurrences(&series, &single).unwrap();
    assert!(merged.contains("RRULE:FREQ=DAILY") && merged.contains("SUMMARY:series") && merged.contains("SUMMARY:moved"), "{merged}");
    let again = unomail::calendar::ical::merge_occurrences(&merged, &single).unwrap();
    assert_eq!(again.matches("SUMMARY:moved").count(), 1);
}

#[tokio::test]
async fn a_redirect_to_a_colleague_on_this_server_arrives() {
    let (env, bob) = with_bob().await;
    let carol = env.account("carol@example.org").await;
    let api = Api::logged_in(&env, TO).await;
    let script = "require \"copy\";\nredirect \"carol@example.org\";\n";
    assert!(api.put("/api/me/sieve", json!({ "script": script, "active": true })).await.status.is_success());
    let mut client = Client::smtp(env.mx).await;
    assert!(client.send_mail(FROM, &[TO], &message(FROM, TO, "passed on", "body")).await.starts_with("250"));
    smtp::queue::process_due(&env.app).await;
    assert_eq!(env.inbox(&carol).await.len(), 1, "the colleague has it");
    assert_eq!(env.inbox(&bob).await.len(), 0);
}

#[tokio::test]
async fn labelled_conversations_stay_listed_when_a_reply_has_no_label() {
    let (env, bob) = with_bob().await;
    let api = Api::logged_in(&env, TO).await;
    let account = api.jmap_account().await;
    let first = "From: carol@remote.example\r\nTo: bob@example.org\r\nSubject: talk\r\nMessage-ID: <one@remote.example>\r\n\r\nfirst\r\n".to_owned();
    let second = "From: carol@remote.example\r\nTo: bob@example.org\r\nSubject: Re: talk\r\nMessage-ID: <two@remote.example>\r\nIn-Reply-To: <one@remote.example>\r\n\r\nsecond\r\n".to_owned();
    let mut client = Client::smtp(env.mx).await;
    assert!(client.send_mail(FROM, &[TO], &first).await.starts_with("250"));
    let listed = api.jmap(json!([["Email/query", { "accountId": account }, "q"]])).await;
    let labelled = listed[0][1]["ids"][0].as_str().unwrap().to_owned();
    api.jmap(json!([["Email/set", { "accountId": account, "update": { &labelled: { "keywords/work": true } } }, "u"]])).await;
    let mut client = Client::smtp(env.mx).await;
    assert!(client.send_mail(FROM, &[TO], &second).await.starts_with("250"));
    assert_eq!(env.inbox(&bob).await.len(), 2);

    let found = api.jmap(json!([["Email/query", { "accountId": account, "filter": { "hasKeyword": "work" }, "collapseThreads": true, "calculateTotal": true }, "q"]])).await;
    assert_eq!(found[0][1]["ids"], json!([labelled]));
    assert_eq!(found[0][1]["total"], 1);
}
#[tokio::test]
async fn changes_in_a_shared_mailbox_reach_those_it_is_shared_with() {
    let (env, owner) = with_bob().await;
    let carol = env.account("carol@example.org").await;
    let inbox = env.app.store.mailbox_by_role(owner.id, "inbox").await.unwrap().unwrap();
    sqlx::query("INSERT INTO mailbox_acl (mailbox_id, grantee_id, rights) VALUES (?, ?, 'lr')").bind(inbox.id).bind(carol.id).execute(&env.app.db).await.unwrap();
    let before = env.app.store.account_state(carol.id).await.unwrap();

    let mut client = Client::smtp(env.mx).await;
    assert!(client.send_mail(FROM, &[TO], &message(FROM, TO, "for all", "body")).await.starts_with("250"));
    let after = env.app.store.account_state(carol.id).await.unwrap();
    assert!(after > before, "the state moves");
    let changes = env.app.store.changes_since(carol.id, "email", before, 100).await.unwrap().unwrap();
    assert_eq!(changes.created.len(), 1, "{changes:?}");

    // What the owner keeps elsewhere stays out of it.
    let archive = env.app.store.mailbox_by_role(owner.id, "archive").await.unwrap().unwrap();
    env.app.store.append(owner.id, archive.id, b"From: a@b.example\r\nSubject: private\r\n\r\nx\r\n", Default::default(), None).await.unwrap();
    let changes = env.app.store.changes_since(carol.id, "email", after, 100).await.unwrap().unwrap();
    assert!(changes.created.is_empty(), "{changes:?}");
}

/// A LIST pattern is answered in one pass: it cannot be used to occupy a worker by making the
/// matcher explore every split point of a long mailbox name.
#[tokio::test]
async fn a_pathological_list_pattern_does_not_hold_the_connection() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(imap::serve(env.app.clone(), listener));
    let mut client = Client::connect_tls(addr).await;
    client.read_line().await;

    async fn until(client: &mut Client, tag: &str) -> String {
        let mut out = String::new();
        loop {
            let line = client.read_line().await.expect("connection closed");
            out.push_str(&line);
            out.push('\n');
            if line.starts_with(&format!("{tag} ")) {
                return out;
            }
        }
    }

    client.send_raw(format!("a1 LOGIN bob@example.org \"{}\"\r\n", common::PASSWORD).as_bytes()).await;
    assert!(until(&mut client, "a1").await.contains("a1 OK"));
    let name = "a".repeat(200);
    client.send_raw(format!("a2 CREATE {name}\r\n").as_bytes()).await;
    assert!(until(&mut client, "a2").await.contains("a2 OK"));

    let started = std::time::Instant::now();
    client.send_raw(b"a3 LIST \"\" \"*a*a*a*a*a*a*a*b\"\r\n").await;
    let reply = tokio::time::timeout(std::time::Duration::from_secs(5), until(&mut client, "a3"))
        .await
        .expect("LIST must answer instead of backtracking");
    assert!(reply.contains("a3 OK"), "{reply}");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}
