//! Server settings that change how mail is handled: spam and virus checks per direction, the
//! spam subject mark, quarantine of misbehaving connections, the From check, privacy of
//! submitted mail, the default route and how secrets are kept.

mod common;

use std::sync::Arc;

use axum::{Router, http::StatusCode, routing::post};
use common::{Api, Client, PASSWORD, Sink, TestEnv, message};
use serde_json::json;
use unomail::{auth::Role, settings::Runtime, util::Address};

/// Changes runtime settings the way the admin panel does, without going through HTTP.
fn configure(env: &TestEnv, change: impl FnOnce(&mut Runtime)) {
    let mut runtime = (*env.app.rt()).clone();
    change(&mut runtime);
    env.app.settings.store(Arc::new(runtime));
}

async fn submission(env: &TestEnv, user: &str) -> Client {
    let mut c = Client::smtp(env.submission).await;
    c.starttls().await;
    assert!(c.auth_plain(user, PASSWORD).await.starts_with("235"));
    c
}

/// A content filter that gives every message the same verdict.
async fn fake_rspamd(action: &'static str, score: f64) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/checkv2", post(move || async move { axum::Json(json!({ "action": action, "score": score, "required_score": 15.0, "symbols": {} })) }));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn spam_and_virus_checks_can_be_switched_off_per_direction() {
    // Both scanners configured but unreachable: whatever they would check is deferred.
    let env = TestEnv::start_with(|cfg| {
        cfg.rspamd_url = Some("http://127.0.0.1:9".into());
        cfg.clamav_addr = Some("127.0.0.1:9".into());
    })
    .await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let inbound = message("a@remote.example", "bob@example.org", "In", "x");
    let outbound = message("bob@example.org", "bob@example.org", "Out", "x");

    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail("a@remote.example", &["bob@example.org"], &inbound).await.starts_with("451"));
    configure(&env, |rt| rt.antivirus_inbound = false);
    assert!(c.send_mail("a@remote.example", &["bob@example.org"], &inbound).await.starts_with("451"), "the spam check still runs");
    configure(&env, |rt| rt.spam_check_inbound = false);
    assert!(c.send_mail("a@remote.example", &["bob@example.org"], &inbound).await.starts_with("250"));

    // Outgoing mail has its own switches.
    let mut s = submission(&env, "bob@example.org").await;
    assert!(s.send_mail("bob@example.org", &["bob@example.org"], &outbound).await.starts_with("451"));
    configure(&env, |rt| {
        rt.antivirus_outbound = false;
        rt.spam_check_outbound = false;
    });
    assert!(s.send_mail("bob@example.org", &["bob@example.org"], &outbound).await.starts_with("250"));
    assert_eq!(env.inbox(&bob).await.len(), 2);
}

#[tokio::test]
async fn spam_gets_a_subject_mark_from_the_chosen_score() {
    let rspamd = fake_rspamd("no action", 7.5).await;
    let env = TestEnv::start_with(move |cfg| cfg.rspamd_url = Some(rspamd)).await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let mut c = Client::smtp(env.mx).await;

    // Off by default.
    assert!(c.send_mail("a@remote.example", &["bob@example.org"], &message("a@remote.example", "bob@example.org", "First", "x")).await.starts_with("250"));
    configure(&env, |rt| {
        rt.spam_subject_enabled = true;
        rt.spam_subject_score = 7.0;
        rt.spam_subject_prefix = "[Spam?]".into();
    });
    assert!(c.send_mail("a@remote.example", &["bob@example.org"], &message("a@remote.example", "bob@example.org", "Second", "x")).await.starts_with("250"));
    // A score below the threshold is left alone.
    configure(&env, |rt| rt.spam_subject_score = 8.0);
    assert!(c.send_mail("a@remote.example", &["bob@example.org"], &message("a@remote.example", "bob@example.org", "Third", "x")).await.starts_with("250"));

    let inbox = env.inbox(&bob).await;
    let subject = |text: &str| inbox.iter().find(|m| m.contains(text)).unwrap().lines().find(|l| l.starts_with("Subject:")).unwrap().to_owned();
    assert_eq!(subject("First"), "Subject: First");
    assert_eq!(subject("Second"), "Subject: [Spam?] Second");
    assert_eq!(subject("Third"), "Subject: Third");
}

#[tokio::test]
async fn mail_from_misbehaving_connections_can_be_quarantined() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;

    // Probing for addresses: three unknown recipients before the real one.
    let probe = |subject: &'static str| {
        let mx = env.mx;
        async move {
            let mut c = Client::smtp(mx).await;
            c.cmd("EHLO prober.example").await;
            c.cmd("MAIL FROM:<x@remote.example>").await;
            for guess in ["admin", "info", "sales"] {
                assert!(c.cmd(&format!("RCPT TO:<{guess}@example.org>")).await.starts_with("550"));
            }
            assert!(c.cmd("RCPT TO:<bob@example.org>").await.starts_with("250"));
            assert!(c.cmd("DATA").await.starts_with("354"));
            assert!(c.cmd(&format!("{}.", message("x@remote.example", "bob@example.org", subject, "x"))).await.starts_with("250"));
        }
    };
    probe("Before").await;
    assert_eq!(env.inbox(&bob).await.len(), 1, "off by default");

    configure(&env, |rt| rt.quarantine_misbehaving = true);
    probe("After").await;
    let junk = env.mailbox(&bob, "junk").await;
    assert_eq!(junk.len(), 1);
    assert!(junk[0].contains("Subject: After"));
    // The address now has a bad record, so even a polite connection from it is quarantined…
    let polite = |subject: &'static str| message("friend@remote.example", "bob@example.org", subject, "x");
    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail("friend@remote.example", &["bob@example.org"], &polite("Same address")).await.starts_with("250"));
    assert!(env.mailbox(&bob, "junk").await.iter().any(|m| m.contains("Subject: Same address")));
    // …while one from an address without a record is delivered normally.
    sqlx::query("DELETE FROM ip_karma").execute(&env.app.db).await.unwrap();
    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail("friend@remote.example", &["bob@example.org"], &polite("Polite")).await.starts_with("250"));
    assert!(env.inbox(&bob).await.iter().any(|m| m.contains("Subject: Polite")));
}

#[tokio::test]
async fn the_from_check_and_privacy_of_submitted_mail() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    env.account("carol@example.org").await;
    let mut s = submission(&env, "carol@example.org").await;
    let raw = |subject: &str, from: &str| format!("From: {from}\r\nTo: bob@example.org\r\nSubject: {subject}\r\nX-Mailer: Thing 2.0\r\nUser-Agent: Mozilla/5.0 (secret OS)\r\n\r\nHello\r\n");

    // Strict by default: the From header must be the sender's own.
    assert!(s.send_mail("carol@example.org", &["bob@example.org"], &raw("Forged", "bob@example.org")).await.starts_with("550 5.7.1 From header rejected"));
    assert!(s.send_mail("carol@example.org", &["bob@example.org"], &raw("Default", "carol@example.org")).await.starts_with("250"));
    configure(&env, |rt| {
        rt.strict_from_check = false;
        rt.privacy_remove_x_headers = true;
        rt.privacy_remove_user_agent = true;
        rt.privacy_hide_client_ip = false;
    });
    assert!(s.send_mail("carol@example.org", &["bob@example.org"], &raw("Loose", "bob@example.org")).await.starts_with("250"));

    let inbox = env.inbox(&bob).await;
    let default = inbox.iter().find(|m| m.contains("Subject: Default")).unwrap();
    assert!(default.contains("X-Mailer: Thing 2.0") && default.contains("User-Agent: Mozilla"), "kept by default");
    assert!(default.contains("Received: from localhost (localhost [127.0.0.1])"), "the client's address is hidden by default");
    let loose = inbox.iter().find(|m| m.contains("Subject: Loose")).unwrap();
    assert!(!loose.contains("X-Mailer") && !loose.contains("User-Agent"), "{loose}");
    assert!(loose.contains("Received: from [127.0.0.1] ([127.0.0.1])"), "{loose}");
}

#[tokio::test]
async fn outgoing_mail_follows_the_default_route() {
    let sink = Sink::start().await;
    let env = TestEnv::start().await;
    let recipient = Address::parse("someone@remote.example").unwrap();
    // Entered but switched off: not used (the test domain has no mail server, so delivery fails).
    configure(&env, |rt| rt.default_route = sink.relay());
    assert!(unomail::smtp::client::deliver(&env.app, "bob@example.org", &recipient, b"Subject: Direct\r\n\r\nx\r\n").await.is_err());
    assert!(sink.received().is_empty());
    // Switched on, without signing in: a smarthost.
    configure(&env, |rt| rt.default_route_enabled = true);
    let reply = unomail::smtp::client::deliver(&env.app, "bob@example.org", &recipient, b"Subject: Routed\r\n\r\nx\r\n").await.unwrap();
    assert!(reply.contains("Ok"), "{reply}");
    let received = sink.received();
    assert_eq!(received.len(), 1);
    assert!(received[0].data.contains("Subject: Routed"));
}

#[tokio::test]
async fn the_default_route_password_is_kept_sealed() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let admin = Api::logged_in(&env, "admin@example.org").await;

    let before = admin.get("/api/settings").await.body;
    assert_eq!(before["values"]["dnsbl_zones"], json!([]), "tests run without blocklists");
    assert_eq!(before["secrets_set"]["default_route_password"], false);
    let saved = admin.patch("/api/settings", json!({ "default_route": "smtp.example.com:587", "default_route_username": "relay-user", "default_route_password": "hunter2-long" })).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.body["values"]["default_route_password"], "", "never sent back");
    assert_eq!(saved.body["secrets_set"]["default_route_password"], true);
    assert!(!saved.text.contains("hunter2"));
    // Stored sealed, readable by the server.
    let stored = env.app.rt().default_route_password.clone();
    assert!(!stored.contains("hunter2") && !stored.is_empty());
    assert_eq!(env.app.secrets.open(&stored).as_deref(), Some("hunter2-long"));
    let audit: String = sqlx::query_scalar("SELECT detail FROM audit_log WHERE action = 'settings.updated'").fetch_one(&env.app.db).await.unwrap();
    assert!(audit.contains("default_route_password=(changed)") && !audit.contains("hunter2"), "{audit}");

    for bad in [json!({ "default_route": "nowhere" }), json!({ "spam_subject_prefix": "" }), json!({ "log_retention_days": 0 }), json!({ "default_route_password": 5 })] {
        assert_eq!(admin.patch("/api/settings", bad.clone()).await.status, StatusCode::BAD_REQUEST, "{bad}");
    }
}
