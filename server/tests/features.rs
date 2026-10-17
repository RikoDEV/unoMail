//! Out-of-office replies, client auto-configuration and server diagnostics.

mod common;

use axum::http::{Method, StatusCode};
use common::{Api, Client, Sink, TestEnv, message};
use serde_json::json;
use unomail::{auth::Role, smtp::queue};

#[tokio::test]
async fn vacation_replies_once_per_sender_and_never_to_automated_mail() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let carol = env.account("carol@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;

    assert_eq!(api.get("/api/me/vacation").await.body["enabled"], false);
    for bad in [
        json!({ "enabled": true, "subject": "", "body": "", "starts_at": null, "ends_at": null, "interval_days": 7 }),
        json!({ "enabled": true, "subject": "x", "body": "away", "starts_at": 200, "ends_at": 100, "interval_days": 7 }),
        json!({ "enabled": true, "subject": "x", "body": "away", "starts_at": null, "ends_at": null, "interval_days": 0 }),
        json!({ "enabled": true, "subject": "a\r\nBcc: evil@x.example", "body": "away", "starts_at": null, "ends_at": null, "interval_days": 7 }),
    ] {
        assert_eq!(api.put("/api/me/vacation", bad).await.status, StatusCode::BAD_REQUEST);
    }
    let saved = api
        .put("/api/me/vacation", json!({ "enabled": true, "subject": "Out of office", "body": "Back on Monday.", "starts_at": null, "ends_at": null, "interval_days": 7 }))
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);

    let mut c = Client::smtp(env.mx).await;
    let personal = message("alice@remote.example", "bob@example.org", "Are you there?", "ping");
    assert!(c.send_mail("alice@remote.example", &["bob@example.org"], &personal).await.starts_with("250"));
    // Second message from the same sender within the interval: no second reply.
    assert!(c.send_mail("alice@remote.example", &["bob@example.org"], &personal).await.starts_with("250"));
    // Automated mail, bounces, list mail and blind copies are never answered.
    let list = format!("List-Id: <news.remote.example>\r\n{}", message("news@remote.example", "bob@example.org", "Newsletter", "x"));
    assert!(c.send_mail("news@remote.example", &["bob@example.org"], &list).await.starts_with("250"));
    let auto = format!("Auto-Submitted: auto-replied\r\n{}", message("dave@remote.example", "bob@example.org", "Auto", "x"));
    assert!(c.send_mail("dave@remote.example", &["bob@example.org"], &auto).await.starts_with("250"));
    assert!(c.send_mail("", &["bob@example.org"], &message("MAILER-DAEMON@remote.example", "bob@example.org", "Bounce", "x")).await.starts_with("250"));
    let bcc = message("erin@remote.example", "someone-else@example.org", "Blind copy", "x");
    assert!(c.send_mail("erin@remote.example", &["bob@example.org"], &bcc).await.starts_with("250"));

    assert_eq!(env.inbox(&bob).await.len(), 6, "every message is still delivered");
    queue::process_due(&env.app).await;
    let replies = sink.received();
    assert_eq!(replies.len(), 1, "exactly one autoreply: {:?}", replies.iter().map(|r| &r.to).collect::<Vec<_>>());
    let reply = &replies[0];
    assert_eq!(reply.to, "alice@remote.example");
    assert_eq!(reply.from, "", "null envelope sender prevents loops");
    assert!(reply.data.contains("Subject: Out of office") && reply.data.contains("Back on Monday."));
    assert!(reply.data.contains("Auto-Submitted: auto-replied") && reply.data.contains("In-Reply-To: <"));

    // Local correspondents get the reply straight into their inbox.
    let carol_api = Api::logged_in(&env, "carol@example.org").await;
    let account = carol_api.jmap_account().await;
    let boxes = carol_api.jmap(json!([["Mailbox/get", { "accountId": account }, "0"]])).await[0][1]["list"].clone();
    let drafts = boxes.as_array().unwrap().iter().find(|m| m["role"] == "drafts").unwrap()["id"].as_str().unwrap().to_owned();
    let sent = carol_api
        .jmap(json!([
            ["Email/set", { "accountId": account, "create": { "d": { "mailboxIds": { &drafts: true }, "to": [{ "email": "bob@example.org" }], "subject": "Lunch?", "bodyValues": { "t": { "value": "hi" } }, "textBody": [{ "partId": "t" }] } } }, "c"],
            ["EmailSubmission/set", { "accountId": account, "create": { "s": { "emailId": "#d" } } }, "s"],
        ]))
        .await;
    assert!(sent[1][1]["created"]["s"].is_object(), "{sent}");
    let carol_inbox = env.inbox(&carol).await;
    assert_eq!(carol_inbox.len(), 1);
    assert!(carol_inbox[0].starts_with("Return-Path: <>\r\n") && carol_inbox[0].contains("Back on Monday."));

    // Outside the configured date range nothing is sent.
    api.put("/api/me/vacation", json!({ "enabled": true, "subject": "", "body": "Away", "starts_at": 1, "ends_at": 2, "interval_days": 7 })).await;
    assert!(c.send_mail("frank@remote.example", &["bob@example.org"], &message("frank@remote.example", "bob@example.org", "Hello", "x")).await.starts_with("250"));
    queue::process_due(&env.app).await;
    assert_eq!(sink.received().len(), 1);
}

#[tokio::test]
async fn mail_clients_can_discover_their_settings() {
    let env = TestEnv::start().await;
    let api = Api::new(&env);

    let thunderbird = api.get("/mail/config-v1.1.xml?emailaddress=bob@example.org").await;
    assert_eq!(thunderbird.status, StatusCode::OK);
    assert!(thunderbird.text.contains("<domain>example.org</domain>"));
    assert!(thunderbird.text.contains("<hostname>mail.test.example</hostname><port>993</port><socketType>SSL</socketType>"));
    assert!(api.get("/.well-known/autoconfig/mail/config-v1.1.xml").await.text.contains("<incomingServer type=\"imap\">"));
    // Hostile input is not reflected into the document.
    let injected = api.get("/mail/config-v1.1.xml?emailaddress=%3Cscript%3E@x%22%3E").await;
    assert!(!injected.text.contains("<script>") && injected.text.contains("<domain>mail.test.example</domain>"));

    let request = "<Autodiscover><Request><EMailAddress>bob@example.org</EMailAddress></Request></Autodiscover>";
    let outlook = api.send(Method::POST, "/autodiscover/autodiscover.xml", None, &[("content-type", "text/xml")]).await;
    assert_eq!(outlook.status, StatusCode::BAD_REQUEST, "an address is required");
    let router = api.router.clone();
    let response = {
        use axum::{Extension, body::Body, http::Request};
        use http_body_util::BodyExt;
        use tower::ServiceExt;
        let req = Request::builder().method(Method::POST).uri("/Autodiscover/Autodiscover.xml").body(Body::from(request)).unwrap();
        let res = router.layer(Extension(unomail::api::PeerAddr(api.peer))).oneshot(req).await.unwrap();
        String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    };
    assert!(response.contains("<Type>IMAP</Type><Server>mail.test.example</Server><Port>993</Port>"), "{response}");
    assert!(response.contains("<LoginName>bob@example.org</LoginName>"));

    let apple = api.get("/email.mobileconfig?email=bob@example.org").await;
    assert_eq!(apple.status, StatusCode::OK);
    assert_eq!(apple.headers["content-type"], "application/x-apple-aspen-config");
    assert!(apple.text.contains("<key>IncomingMailServerHostName</key><string>mail.test.example</string>"));
    assert_eq!(api.get("/email.mobileconfig?email=nonsense").await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.get("/email.mobileconfig").await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn server_diagnostics_report() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    env.account("bob@example.org").await;
    assert_eq!(Api::logged_in(&env, "bob@example.org").await.get("/api/diagnostics/server").await.status, StatusCode::FORBIDDEN);

    let report = Api::logged_in(&env, "admin@example.org").await.get("/api/diagnostics/server").await;
    assert_eq!(report.status, StatusCode::OK, "{}", report.text);
    assert_eq!(report.body["hostname"], "mail.test.example");
    assert_eq!(report.body["ports"].as_array().unwrap().len(), 8);
    assert_eq!(report.body["outbound_port_25"], "unknown", "no resolver in tests");
    assert_eq!(report.body["rspamd"], "warning", "the filter is not configured in tests");
    assert!(report.body["score"].as_u64().unwrap() <= 100);
}
