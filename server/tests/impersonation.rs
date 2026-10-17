//! Ways for one user to pose as another or to make the server work against its users: relay
//! identities for local addresses, ambiguous authors, Sieve redirect loops, spoofed calendar
//! messages, delegated invitations, scheduled sends of locked accounts and sign-ins that were
//! revoked while a connection stayed open.

mod common;

use axum::http::StatusCode;
use common::{Api, Client, PASSWORD, Sink, TestEnv, message};
use serde_json::json;
use unomail::{
    auth::{Credential, Grant, Protocol},
    db::Direction,
    smtp::{
        delivery::{self, LocalDelivery},
        queue,
    },
};

async fn submission(env: &TestEnv, user: &str) -> Client {
    let mut c = Client::smtp(env.submission).await;
    c.starttls().await;
    c.cmd("EHLO laptop").await;
    assert!(c.auth_plain(user, PASSWORD).await.starts_with("235"));
    c
}

/// The reply to a mail transaction that may be refused anywhere.
async fn try_send(c: &mut Client, from: &str, to: &str, data: &str) -> String {
    let reply = c.cmd(&format!("MAIL FROM:<{from}>")).await;
    if !reply.starts_with("250") {
        return reply;
    }
    let reply = c.cmd(&format!("RCPT TO:<{to}>")).await;
    if !reply.starts_with("250") {
        return reply;
    }
    assert!(c.cmd("DATA").await.starts_with("354"));
    c.send_raw(data.as_bytes()).await;
    c.cmd(".").await
}

#[tokio::test]
async fn relay_identities_cannot_claim_addresses_hosted_here() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let carol = env.account("carol@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;

    // Bob cannot make the CEO's address his by naming a server (this one, say) to send through.
    let server = json!({ "host": "127.0.0.1", "port": env.mx.port(), "security": "none", "username": "" });
    let refused = api.post("/api/me/identities", json!({ "email": "carol@example.org", "smtp": server })).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.text);
    let external = api.post("/api/me/identities", json!({ "email": "bob@elsewhere.example", "smtp": { "host": "127.0.0.1", "port": sink.addr.port(), "security": "none" } })).await;
    assert_eq!(external.status, StatusCode::OK, "{}", external.text);

    // One stored before this rule existed is ignored.
    sqlx::query("INSERT INTO identities (account_id, name, email, reply_to, is_default, smtp_host, smtp_port, smtp_security, smtp_username, smtp_password, created_at) VALUES (?, '', 'carol@example.org', '', 0, '127.0.0.1', ?, 'none', '', '', 0)")
        .bind(bob.id)
        .bind(i64::from(env.mx.port()))
        .execute(&env.app.db)
        .await
        .unwrap();
    let mut c = submission(&env, "bob@example.org").await;
    let reply = try_send(&mut c, "carol@example.org", "dave@remote.example", &message("carol@example.org", "dave@remote.example", "Wire", "x")).await;
    assert!(reply.starts_with("550"), "{reply}");

    // A relay identity does not ride along as a second author of mail this server signs.
    for from in ["bob@example.org, carol@example.org", "bob@example.org, bob@elsewhere.example", "bob@elsewhere.example, bob@example.org"] {
        let reply = try_send(&mut c, "bob@example.org", "carol@example.org", &message(from, "carol@example.org", "Hi", "x")).await;
        assert!(reply.starts_with("550"), "{from}: {reply}");
    }
    assert!(env.inbox(&carol).await.is_empty());

    // The identity on its own still works, through its own server.
    let reply = try_send(&mut c, "bob@elsewhere.example", "carol@example.org", &message("bob@elsewhere.example", "carol@example.org", "Hi", "x")).await;
    assert!(reply.starts_with("250"), "{reply}");
    queue::process_due(&env.app).await;
    assert_eq!(sink.received().len(), 1);
}

#[tokio::test]
async fn messages_with_two_authors_are_refused() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let carol = env.account("carol@example.org").await;

    // Checks and signatures read one From field, mail clients may show the other.
    let mut c = submission(&env, "bob@example.org").await;
    let doubled = "From: carol@example.org\r\nFrom: bob@example.org\r\nTo: carol@example.org\r\nSubject: Hi\r\n\r\nx\r\n";
    let reply = try_send(&mut c, "bob@example.org", "carol@example.org", doubled).await;
    assert!(reply.starts_with("550"), "{reply}");
    let senders = "From: bob@example.org\r\nSender: bob@example.org\r\nsender : carol@example.org\r\nTo: carol@example.org\r\nSubject: Hi\r\n\r\nx\r\n";
    let reply = try_send(&mut c, "bob@example.org", "carol@example.org", senders).await;
    assert!(reply.starts_with("550"), "{reply}");
    assert!(env.inbox(&carol).await.is_empty());

    let mut mx = Client::smtp(env.mx).await;
    let inbound = "From: ceo@bank.example\r\nFrom: x@attacker.example\r\nTo: bob@example.org\r\nSubject: Urgent\r\n\r\nx\r\n";
    let reply = try_send(&mut mx, "x@attacker.example", "bob@example.org", inbound).await;
    assert!(reply.starts_with("550"), "{reply}");
    // A From in a folded header or in the body is not a second author.
    let fine = "From: x@partner.example\r\nSubject: about\r\n From: y@example.net\r\n\r\nFrom: z@example.net\r\n";
    assert!(try_send(&mut mx, "x@partner.example", "bob@example.org", fine).await.starts_with("250"));
    assert_eq!(env.inbox(&bob).await.len(), 1);
}

#[tokio::test]
async fn sieve_redirects_do_not_loop_and_count_as_sending() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let script = r#"require ["copy"]; redirect :copy "bob+1@example.org"; redirect :copy "Bob+2@Example.org"; redirect :copy "bob@example.org"; redirect :copy "out@remote.example";"#;
    assert_eq!(api.put("/api/me/sieve", json!({ "script": script, "active": true })).await.status, StatusCode::OK);

    // Copies to the mailbox itself, under any of its addresses, would come back and multiply.
    let mut mx = Client::smtp(env.mx).await;
    assert!(mx.send_mail("x@remote.example", &["bob@example.org"], &message("x@remote.example", "bob@example.org", "Hello", "x")).await.starts_with("250"));
    queue::process_due(&env.app).await;
    let sent = sink.received();
    assert_eq!(sent.iter().map(|m| m.to.as_str()).collect::<Vec<_>>(), ["out@remote.example"]);
    assert!(sent[0].data.contains("Delivered-To: bob@example.org"), "the copy says where it has been");
    let counted: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(recipients), 0) FROM outbound_stats WHERE account_id = ?").bind(bob.id).fetch_one(&env.app.db).await.unwrap();
    assert_eq!(counted, 1, "redirects count against the sending limits");

    // A message that was here before (a loop through another mailbox) is kept, not sent on.
    let returning = format!("Delivered-To: <BOB@example.org>\r\n{}", message("x@remote.example", "bob@example.org", "Back again", "x"));
    assert!(mx.send_mail("x@remote.example", &["bob@example.org"], &returning).await.starts_with("250"));
    queue::process_due(&env.app).await;
    assert_eq!(sink.received().len(), 1);
    assert_eq!(env.inbox(&bob).await.len(), 2);

    // An account that may not send any more forwards nothing either.
    sqlx::query("UPDATE accounts SET outbound_blocked = 1 WHERE id = ?").bind(bob.id).execute(&env.app.db).await.unwrap();
    assert!(mx.send_mail("x@remote.example", &["bob@example.org"], &message("x@remote.example", "bob@example.org", "Third", "x")).await.starts_with("250"));
    queue::process_due(&env.app).await;
    assert_eq!(sink.received().len(), 1);
    assert_eq!(env.inbox(&bob).await.len(), 3);
}

#[tokio::test]
async fn calendar_messages_change_nothing_unless_their_author_is_verified() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let carol_account = env.account("carol@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let carol = Api::logged_in(&env, "carol@example.org").await;
    let bobs = bob.get("/api/me/calendars").await.body["calendars"][0]["id"].as_i64().unwrap();
    let lunch = json!({ "summary": "Lunch", "start": "2026-10-13T12:00", "end": "2026-10-13T13:00", "timezone": "UTC", "attendees": ["carol@example.org"] });
    assert_eq!(bob.post(&format!("/api/me/calendars/{bobs}/events"), lunch).await.status, StatusCode::OK);
    queue::process_due(&env.app).await;
    let invitation = env.inbox(&carol_account).await.into_iter().find_map(|raw| unomail::calendar::scheduling::calendar_part(raw.as_bytes())).unwrap();
    assert_eq!(carol.post("/api/me/calendars/invitations/respond", json!({ "ics": invitation, "response": "accepted" })).await.status, StatusCode::OK);
    let october = "/api/me/calendars/events?from=1790000000&to=1793000000";
    assert_eq!(carol.get(october).await.body.as_array().unwrap().len(), 1);

    // Anybody can write "From: bob@example.org" on a cancellation.
    let cancel = invitation.replace("METHOD:REQUEST", "METHOD:CANCEL");
    let raw = format!("From: bob@example.org\r\nTo: carol@example.org\r\nSubject: Cancelled\r\nMIME-Version: 1.0\r\nContent-Type: text/calendar; method=CANCEL; charset=utf-8\r\n\r\n{cancel}");
    let deliver = |author_verified: bool| LocalDelivery {
        account_id: carol_account.id,
        recipient: "carol@example.org",
        sender: "bob@example.org",
        raw: raw.as_bytes(),
        junk: false,
        remote: "203.0.113.9",
        direction: Direction::Inbound,
        author_verified,
    };
    delivery::deliver_local(&env.app, deliver(false)).await.unwrap();
    assert_eq!(carol.get(october).await.body.as_array().unwrap().len(), 1, "a spoofed cancellation is left for Carol to judge");
    delivery::deliver_local(&env.app, deliver(true)).await.unwrap();
    assert_eq!(carol.get(october).await.body, json!([]), "the organizer's own cancellation applies");
}

#[tokio::test]
async fn invitations_from_a_shared_calendar_name_who_wrote_them() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let dave = env.account("dave@example.org").await;
    let bob_api = Api::logged_in(&env, "bob@example.org").await;
    let dave_api = Api::logged_in(&env, "dave@example.org").await;
    let team = bob_api.post("/api/me/calendars", json!({ "name": "Team" })).await.body["id"].as_i64().unwrap();
    assert_eq!(bob_api.put(&format!("/api/me/calendars/{team}/shares"), json!([{ "email": "dave@example.org", "write": true }])).await.status, StatusCode::OK);

    let event = json!({ "summary": "Offsite", "start": "2026-10-13T12:00", "end": "2026-10-13T13:00", "timezone": "UTC", "attendees": ["partner@remote.example"] });
    let created = dave_api.post(&format!("/api/me/calendars/{team}/events"), event).await;
    assert_eq!(created.body["mail_problems"], json!([]), "{}", created.text);
    queue::process_due(&env.app).await;
    let sent = sink.received();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].data.contains("From: <bob@example.org>\r\nSender: <dave@example.org>\r\n"), "{}", sent[0].data);
    let db = env.app.db.clone();
    let counted = |id: i64| {
        let db = db.clone();
        async move { sqlx::query_scalar::<_, i64>("SELECT COALESCE(SUM(messages), 0) FROM outbound_stats WHERE account_id = ?").bind(id).fetch_one(&db).await.unwrap() }
    };
    assert_eq!((counted(bob.id).await, counted(dave.id).await), (0, 1), "the writer's sending limits pay for it");
}

#[tokio::test]
async fn scheduled_mail_of_a_locked_or_reset_account_is_not_sent() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    env.account_with("admin@example.org", unomail::auth::Role::SuperAdmin, None).await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let admin_api = Api::logged_in(&env, "admin@example.org").await;

    let schedule = |subject: &'static str| {
        let api = api.clone();
        async move {
            let account = api.jmap_account().await;
            let boxes = api.jmap(json!([["Mailbox/get", { "accountId": account }, "0"]])).await[0][1]["list"].clone();
            let drafts = boxes.as_array().unwrap().iter().find(|m| m["role"] == "drafts").unwrap()["id"].as_str().unwrap().to_owned();
            let reply = api
                .jmap(json!([
                    ["Email/set", { "accountId": account, "create": { "d": { "mailboxIds": { &drafts: true }, "from": [{ "email": "bob@example.org" }], "to": [{ "email": "x@remote.example" }], "subject": subject, "bodyValues": { "t": { "value": "hi" } }, "textBody": [{ "partId": "t" }] } } }, "c"],
                    ["EmailSubmission/set", { "accountId": account, "create": { "s": { "emailId": "#d", "envelope": { "mailFrom": { "email": "bob@example.org", "parameters": { "HOLDFOR": "3600" } }, "rcptTo": [{ "email": "x@remote.example" }] } } } }, "s"],
                ]))
                .await;
            assert!(reply[1][1]["created"]["s"].is_object(), "{reply}");
        }
    };
    let release = || async {
        sqlx::query("UPDATE email_submissions SET send_at = unixepoch() - 1 WHERE undo_status = 'pending'").execute(&env.app.db).await.unwrap();
        unomail::jmap::submission::release_due(&env.app).await;
        queue::process_due(&env.app).await;
    };

    schedule("Normal").await;
    release().await;
    assert_eq!(sink.received().len(), 1, "scheduled mail goes out when it is due");

    // Disabled: nothing goes out.
    schedule("While disabled").await;
    sqlx::query("UPDATE accounts SET enabled = 0 WHERE id = ?").bind(bob.id).execute(&env.app.db).await.unwrap();
    release().await;
    assert_eq!(sink.received().len(), 1);
    let status: String = sqlx::query_scalar("SELECT undo_status FROM email_submissions ORDER BY id DESC LIMIT 1").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(status, "canceled");
    sqlx::query("UPDATE accounts SET enabled = 1 WHERE id = ?").bind(bob.id).execute(&env.app.db).await.unwrap();

    // An administrator's password reset calls off what was scheduled (by an intruder, perhaps).
    schedule("Before the reset").await;
    let reset = admin_api.patch(&format!("/api/accounts/{}", bob.id), json!({ "password": "a brand new password 123" })).await;
    assert_eq!(reset.status, StatusCode::OK, "{}", reset.text);
    release().await;
    assert_eq!(sink.received().len(), 1);
}

#[tokio::test]
async fn protocol_sign_ins_end_with_the_credential_they_used() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let db = &env.app.db;

    let password = Grant::new(&bob, Protocol::Imap, Some(Credential::Password));
    let token = Grant::new(&bob, Protocol::Imap, None);
    assert!(password.valid(db).await && token.valid(db).await);

    // A new password ends the sessions opened with the old one.
    sqlx::query("UPDATE accounts SET password_hash = 'changed' WHERE id = ?").bind(bob.id).execute(db).await.unwrap();
    assert!(!password.valid(db).await);
    assert!(token.valid(db).await, "the identity provider vouches for tokens");

    // A revoked app password ends its sessions.
    sqlx::query("INSERT INTO app_passwords (id, account_id, name, hash, scopes, created_at) VALUES (7, ?, 'phone', 'h', 'imap', 0)").bind(bob.id).execute(db).await.unwrap();
    let app_password = Grant::new(&bob, Protocol::Imap, Some(Credential::AppPassword(7)));
    assert!(app_password.valid(db).await);
    sqlx::query("DELETE FROM app_passwords WHERE id = 7").execute(db).await.unwrap();
    assert!(!app_password.valid(db).await);

    // So does disabling the mailbox, its domain or the protocol.
    let fresh = |account: &unomail::auth::Account| Grant::new(account, Protocol::Imap, None);
    sqlx::query("UPDATE accounts SET imap_enabled = 0 WHERE id = ?").bind(bob.id).execute(db).await.unwrap();
    assert!(!fresh(&bob).valid(db).await);
    assert!(Grant::new(&bob, Protocol::Smtp, None).valid(db).await);
    sqlx::query("UPDATE domains SET enabled = 0").execute(db).await.unwrap();
    assert!(!Grant::new(&bob, Protocol::Smtp, None).valid(db).await);
}
