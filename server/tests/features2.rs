//! Sieve filtering, DMARC reports, runtime settings, mailbox import, log viewers and the
//! certificate fallback path.

mod common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::{Api, Client, PASSWORD, Sink, TestEnv, message};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use unomail::{auth::Role, smtp::queue};

const REPORT: &str = r#"<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>bigmail.example</org_name><email>dmarc@bigmail.example</email><report_id>r-1</report_id>
    <date_range><begin>BEGIN</begin><end>END</end></date_range></report_metadata>
  <policy_published><domain>example.org</domain><p>quarantine</p></policy_published>
  <record><row><source_ip>203.0.113.10</source_ip><count>40</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.org</header_from></identifiers><auth_results><spf><domain>example.org</domain><result>pass</result></spf></auth_results></record>
  <record><row><source_ip>198.51.100.66</source_ip><count>7</count>
    <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.org</header_from></identifiers><auth_results><spf><domain>x.example</domain><result>fail</result></spf></auth_results></record>
</feedback>"#;

fn report(id: &str, domain: &str) -> String {
    let now = unomail::util::now();
    REPORT.replace("BEGIN", &(now - 86400).to_string()).replace("END", &now.to_string()).replace("r-1", id).replace("<domain>example.org</domain><p>", &format!("<domain>{domain}</domain><p>"))
}

async fn admin_env() -> (TestEnv, Api) {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let api = Api::logged_in(&env, "admin@example.org").await;
    (env, api)
}

async fn upload(api: &Api, path: &str, body: Vec<u8>) -> (StatusCode, Value) {
    use axum::{Extension, body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("cookie", api.cookie.clone().unwrap())
        .header("x-csrf-token", api.csrf.clone().unwrap())
        .body(Body::from(body))
        .unwrap();
    let response = api.router.clone().layer(Extension(unomail::api::PeerAddr(api.peer))).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn wait_for_job(api: &Api, account: i64) -> Value {
    for _ in 0..100 {
        let jobs = api.get(&format!("/api/accounts/{account}/import")).await.body;
        if jobs[0]["status"] != "running" {
            return jobs[0].clone();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("import did not finish");
}

#[tokio::test]
async fn sieve_scripts_file_flag_redirect_and_discard_mail() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;

    assert_eq!(api.get("/api/me/sieve").await.body, json!({ "name": "main", "script": "", "active": false }));
    let invalid = api.put("/api/me/sieve", json!({ "script": "require \"fileinto\";\nfileinto \"Work\"", "active": true })).await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid.body["error"]["message"], "line 2: expected ';'");
    assert_eq!(api.put("/api/me/sieve", json!({ "script": "x".repeat(70_000), "active": true })).await.status, StatusCode::BAD_REQUEST);

    let script = r#"
        require ["fileinto", "mailbox", "imap4flags", "copy"];
        if header :contains "subject" "invoice" { fileinto :create "Finance/Invoices"; stop; }
        if address :is "from" "boss@corp.example" { addflag ["\\Flagged", "important"]; keep; stop; }
        if header :contains "subject" "forward me" { redirect :copy "archive@elsewhere.example"; }
        if header :is "subject" "unwanted" { discard; }
    "#;
    assert_eq!(api.put("/api/me/sieve", json!({ "script": script, "active": true })).await.status, StatusCode::OK);

    let mut c = Client::smtp(env.mx).await;
    for (from, subject) in [("shop@remote.example", "Your INVOICE 42"), ("boss@corp.example", "Meeting"), ("x@remote.example", "Please forward me"), ("x@remote.example", "unwanted"), ("x@remote.example", "Plain")] {
        assert!(c.send_mail(from, &["bob@example.org"], &message(from, "bob@example.org", subject, "body")).await.starts_with("250"), "{subject}");
    }

    let folder = env.app.store.mailbox_by_name(bob.id, "Finance/Invoices").await.unwrap().expect("fileinto :create makes the folder");
    assert_eq!(env.app.store.messages_in(folder.id).await.unwrap().len(), 1);
    let inbox = env.app.store.mailbox_by_role(bob.id, "inbox").await.unwrap().unwrap();
    let messages = env.app.store.messages_in(inbox.id).await.unwrap();
    let subjects: Vec<&str> = messages.iter().map(|m| m.subject.as_str()).collect();
    // The first is the server's note that the filter forwards mail outside.
    assert_eq!(subjects, ["Your mail is now forwarded to another address", "Meeting", "Please forward me", "Plain"], "discarded and filed mail is not in the inbox");
    assert!(messages[1].flagged && messages[1].keywords.contains("important"));
    assert_eq!(api.get("/api/me/labels").await.body, json!(["important"]));

    queue::process_due(&env.app).await;
    let forwarded = sink.received();
    assert_eq!(forwarded.len(), 1);
    assert_eq!(forwarded[0].to, "archive@elsewhere.example");
    assert!(forwarded[0].from.starts_with("SRS0="), "redirects use an SRS sender: {}", forwarded[0].from);
    let discarded: String = sqlx::query_scalar("SELECT status FROM delivery_log WHERE detail LIKE 'discarded%'").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(discarded, "discarded");

    // An inactive script does nothing.
    api.put("/api/me/sieve", json!({ "script": script, "active": false })).await;
    assert!(c.send_mail("x@remote.example", &["bob@example.org"], &message("x@remote.example", "bob@example.org", "unwanted", "x")).await.starts_with("250"));
    assert_eq!(env.app.store.messages_in(inbox.id).await.unwrap().len(), 5, "saving the same forward again tells nobody");
}

#[tokio::test]
async fn sieve_extensions_edit_headers_file_by_use_track_duplicates_notify_and_reject() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let carol = env.account("carol@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let script = r#"
        require ["editheader", "fileinto", "special-use", "duplicate", "enotify", "reject", "variables", "relational", "subaddress", "envelope"];
        if header :contains "subject" "go away" { reject "No, thank you."; stop; }
        addheader "X-Filtered-By" "bob's script";
        if duplicate { fileinto "Dupes"; stop; }
        if header :contains "subject" "spammy" { fileinto :specialuse "\\Junk" "Spam folder"; stop; }
        if header :contains "subject" "urgent" { notify :importance "1" :message "Urgent mail" "mailto:carol@example.org"; }
        if envelope :detail "to" "lists" { fileinto "Lists"; }
    "#;
    let saved = api.put("/api/me/sieve", json!({ "script": script, "active": true })).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    let dupes = env.app.store.create_mailbox(bob.id, "Dupes").await.unwrap();
    let lists = env.app.store.create_mailbox(bob.id, "Lists").await.unwrap();

    let mail = |id: &str, subject: &str| format!("From: ann@remote.example\r\nTo: bob@example.org\r\nSubject: {subject}\r\nMessage-ID: <{id}@remote.example>\r\n\r\nHello\r\n");
    let mut c = Client::smtp(env.mx).await;
    for (rcpt, id, subject) in [
        ("bob@example.org", "a1", "First"),
        ("bob@example.org", "a1", "First again"),
        ("bob@example.org", "a2", "spammy offer"),
        ("bob@example.org", "a3", "urgent: call me"),
        ("bob+lists@example.org", "a4", "List mail"),
        ("bob@example.org", "a5", "go away"),
    ] {
        assert!(c.send_mail("ann@remote.example", &[rcpt], &mail(id, subject)).await.starts_with("250"), "{subject}");
    }

    let subjects = |mailbox: i64| {
        let store = env.app.store.clone();
        async move { store.messages_in(mailbox).await.unwrap().into_iter().map(|m| m.subject).collect::<Vec<_>>() }
    };
    let inbox = env.app.store.mailbox_by_role(bob.id, "inbox").await.unwrap().unwrap();
    assert_eq!(subjects(inbox.id).await, ["First", "urgent: call me"], "duplicates, junk, lists and rejected mail are elsewhere");
    let junk = env.app.store.mailbox_by_role(bob.id, "junk").await.unwrap().unwrap();
    assert_eq!(subjects(junk.id).await, ["spammy offer"], ":specialuse finds the Junk mailbox whatever its name");
    assert!(env.app.store.mailbox_by_name(bob.id, "Spam folder").await.unwrap().is_none());
    assert_eq!(subjects(dupes.id).await, ["First again"], "the second copy of a message is a duplicate");
    assert_eq!(subjects(lists.id).await, ["List mail"], ":detail of the recipient address");

    // The added header is part of what was stored.
    let first = &env.inbox(&bob).await[0];
    assert!(first.contains("X-Filtered-By: bob's script"), "{first}");

    // The notification reached Carol, marked as automatic.
    let notes = env.inbox(&carol).await;
    assert_eq!(notes.len(), 1);
    assert!(notes[0].contains("Auto-Submitted: auto-notified") && notes[0].contains("Subject: Urgent mail") && notes[0].contains("Importance: high"), "{}", notes[0]);

    // The duplicate was tracked, and the rejected message is logged as such.
    let tracked: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sieve_duplicates WHERE account_id = ?").bind(bob.id).fetch_one(&env.app.db).await.unwrap();
    assert!(tracked >= 1);
    let rejected: String = sqlx::query_scalar("SELECT detail FROM delivery_log WHERE status = 'rejected' ORDER BY id DESC LIMIT 1").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(rejected, "rejected by the mailbox filter");
}

#[tokio::test]
async fn sieve_forwarding_outside_is_announced_and_can_be_switched_off() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    env.account("carol@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let inbox = env.app.store.mailbox_by_role(bob.id, "inbox").await.unwrap().unwrap();

    // Forwarding to a colleague on this server is not announced; a new outside address is,
    // even when the same filter also discards everything (the note does not pass through it).
    let local = r#"redirect "carol@example.org";"#;
    assert_eq!(api.put("/api/me/sieve", json!({ "script": local, "active": true })).await.status, StatusCode::OK);
    assert!(env.app.store.messages_in(inbox.id).await.unwrap().is_empty());
    let script = r#"require ["copy", "variables"]; redirect :copy "drop@attacker.example"; if header :matches "subject" "*" { redirect "${1}@elsewhere.example"; } discard;"#;
    assert_eq!(api.put("/api/me/sieve", json!({ "script": script, "active": true })).await.status, StatusCode::OK);
    let notes = env.app.store.messages_in(inbox.id).await.unwrap();
    assert_eq!(notes.len(), 1);
    let note = String::from_utf8(env.app.store.read_blob(&notes[0].blob_hash).await.unwrap()).unwrap();
    assert!(note.contains("drop@attacker.example") && note.contains("${1}@elsewhere.example"), "{note}");

    // With forwarding outside switched off, nothing leaves.
    let mut runtime = (*env.app.rt()).clone();
    runtime.sieve_external_redirect = false;
    env.app.settings.store(std::sync::Arc::new(runtime));
    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail("x@remote.example", &["bob@example.org"], &message("x@remote.example", "bob@example.org", "hello", "x")).await.starts_with("250"));
    queue::process_due(&env.app).await;
    assert!(sink.received().is_empty());
}

#[tokio::test]
async fn dmarc_reports_are_ingested_summarised_and_scoped() {
    let (env, api) = admin_env().await;
    env.domain("other.example").await;
    env.account("dana@example.org").await;
    api.put("/api/domains/1/admins", json!({ "emails": ["dana@example.org"] })).await;

    let (status, body) = upload(&api, "/api/dmarc/reports", report("r-1", "example.org").into_bytes()).await;
    assert_eq!((status, &body), (StatusCode::OK, &json!({ "stored": true, "domain": "example.org", "records": 2 })));
    let (_, duplicate) = upload(&api, "/api/dmarc/reports", report("r-1", "example.org").into_bytes()).await;
    assert_eq!(duplicate["duplicate"], true);
    assert_eq!(upload(&api, "/api/dmarc/reports", report("r-2", "not-hosted.example").into_bytes()).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(upload(&api, "/api/dmarc/reports", b"<html>nope</html>".to_vec()).await.0, StatusCode::BAD_REQUEST);
    upload(&api, "/api/dmarc/reports", report("r-3", "other.example").into_bytes()).await;

    // A report arriving by mail (gzip attachment) is picked up automatically.
    use base64::Engine;
    use std::io::Write;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(report("r-mail", "example.org").as_bytes()).unwrap();
    let attachment = base64::engine::general_purpose::STANDARD.encode(gz.finish().unwrap());
    let mail = format!(
        "From: noreply-dmarc@bigmail.example\r\nTo: dmarc@example.org\r\nSubject: Report Domain: example.org Submitter: bigmail.example Report-ID: r-mail\r\n\
MIME-Version: 1.0\r\nContent-Type: application/gzip; name=\"report.xml.gz\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"report.xml.gz\"\r\n\r\n{attachment}\r\n"
    );
    env.alias("dmarc@example.org", &["admin@example.org"]).await;
    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail("noreply-dmarc@bigmail.example", &["dmarc@example.org"], &mail).await.starts_with("250"));

    let overview = api.get("/api/dmarc").await.body;
    let example = overview["domains"].as_array().unwrap().iter().find(|d| d["domain"] == "example.org").unwrap();
    assert_eq!((example["reports"].as_i64(), example["messages"].as_i64(), example["passed"].as_i64(), example["quarantined"].as_i64()), (Some(2), Some(94), Some(80), Some(14)));
    assert_eq!(overview["domains"].as_array().unwrap().len(), 2);
    assert_eq!(overview["sources"][0]["source_ip"], "203.0.113.10");
    let report_id = overview["reports"].as_array().unwrap().iter().find(|r| r["domain"] == "other.example").unwrap()["id"].as_i64().unwrap();
    assert_eq!(api.get(&format!("/api/dmarc/reports/{report_id}")).await.body["records"].as_array().unwrap().len(), 2);

    // Delegated administrators see their own domains only and cannot upload.
    let dana = Api::logged_in(&env, "dana@example.org").await;
    let scoped = dana.get("/api/dmarc").await.body;
    assert_eq!(scoped["domains"].as_array().unwrap().len(), 1);
    assert!(scoped["reports"].as_array().unwrap().iter().all(|r| r["domain"] == "example.org"));
    assert_eq!(dana.get(&format!("/api/dmarc/reports/{report_id}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(upload(&dana, "/api/dmarc/reports", report("r-9", "example.org").into_bytes()).await.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn feedback_reports_are_stored_and_failure_reports_sent_when_enabled() {
    use mail_auth::report::{Feedback, FeedbackType};
    use unomail::security::feedback::{Kind, PendingReport};
    let (env, api) = admin_env().await;

    // A complaint from a feedback loop about mail from a hosted domain.
    let complaint = Feedback::new(FeedbackType::Abuse)
        .with_source_ip("192.0.2.9".parse().unwrap())
        .with_reported_domain("example.org")
        .with_headers("From: news@example.org\r\nSubject: Weekly news\r\n");
    let mut raw = Vec::new();
    complaint.write_rfc5322(("FBL", "fbl@isp.example"), "abuse@example.org", "Complaint", &mut raw).unwrap();
    assert!(unomail::security::feedback::ingest_mail(&env.app, &raw, "isp.example").await);
    assert!(!unomail::security::feedback::ingest_mail(&env.app, b"Subject: hi\r\n\r\nnot a report", "isp.example").await);
    let overview = api.get("/api/dmarc").await.body;
    assert_eq!(overview["feedback"][0]["type"], "abuse");
    assert_eq!(overview["feedback"][0]["reporter"], "isp.example");
    assert_eq!(overview["feedback"][0]["subject"], "Weekly news");

    // Failure reports: off by default, then sent with the recipients redacted.
    let pending = [PendingReport { kind: Kind::Spf, domain: "remote.example".into(), addresses: vec!["spf-reports@remote.example".into()] }];
    let message = b"From: x@remote.example\r\nTo: bob@example.org\r\nSubject: Spoofed\r\n\r\nbody";
    unomail::security::feedback::send(&env.app, &pending, "192.0.2.1".parse().unwrap(), "x@remote.example", "bob@example.org", message, "Authentication-Results: mail; spf=fail").await;
    let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM queue WHERE recipient = 'spf-reports@remote.example'").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(queued, 0, "failure reports are off by default");
    assert_eq!(api.patch("/api/settings", json!({ "auth_failure_reports": true })).await.status, StatusCode::OK);
    unomail::security::feedback::send(&env.app, &pending, "192.0.2.1".parse().unwrap(), "x@remote.example", "bob@example.org", message, "Authentication-Results: mail; spf=fail").await;
    let hash: String = sqlx::query_scalar("SELECT blob_hash FROM queue WHERE recipient = 'spf-reports@remote.example'").fetch_one(&env.app.db).await.unwrap();
    let report = String::from_utf8(env.app.store.read_blob(&hash).await.unwrap()).unwrap();
    assert!(report.contains("feedback-report") && report.contains("Auth-Failure: spf"), "{report}");
    assert!(report.contains("To: redacted@example.org") && !report.contains("bob@example.org"), "{report}");
    // At most one an hour per domain.
    unomail::security::feedback::send(&env.app, &pending, "192.0.2.1".parse().unwrap(), "x@remote.example", "bob@example.org", message, "").await;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM queue WHERE recipient = 'spf-reports@remote.example'").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn runtime_settings_apply_immediately_and_strict_tls_can_be_enforced() {
    let (env, api) = admin_env().await;
    env.account("bob@example.org").await;
    assert_eq!(Api::logged_in(&env, "bob@example.org").await.get("/api/settings").await.status, StatusCode::FORBIDDEN);

    let settings = api.get("/api/settings").await.body;
    assert_eq!(settings["values"]["smtp_require_tls"], false);
    assert_eq!(settings["overridden"], json!([]));
    for bad in [json!({ "max_recipients": 0 }), json!({ "nonsense": 1 }), json!({ "dnsbl_zones": ["bad zone"] }), json!({ "max_recipients": "x" })] {
        assert_eq!(api.patch("/api/settings", bad).await.status, StatusCode::BAD_REQUEST);
    }

    let mut c = Client::smtp(env.mx).await;
    assert!(c.cmd("MAIL FROM:<a@remote.example>").await.starts_with("250"));
    assert!(c.cmd("RSET").await.starts_with("250"));

    let changed = api.patch("/api/settings", json!({ "smtp_require_tls": true, "max_recipients": 1 })).await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.text);
    assert_eq!(changed.body["values"]["smtp_require_tls"], true);
    // The already open connection is affected too: no restart, no reconnect.
    assert!(c.cmd("MAIL FROM:<a@remote.example>").await.starts_with("530 5.7.0 Must issue a STARTTLS"));
    c.starttls().await;
    assert!(c.cmd("MAIL FROM:<a@remote.example>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<bob@example.org>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<admin@example.org>").await.starts_with("452"), "the new recipient limit applies");

    // Overrides persist; null resets to the environment default.
    assert_eq!(unomail::settings::load(&env.app.db, &env.app.cfg).await.unwrap().max_recipients, 1);
    let reset = api.patch("/api/settings", json!({ "smtp_require_tls": null, "max_recipients": null })).await;
    assert_eq!(reset.body["overridden"], json!([]));
    assert_eq!(reset.body["values"]["max_recipients"], reset.body["defaults"]["max_recipients"]);
    let audited: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'settings.updated'").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(audited, 2);
}

#[tokio::test]
async fn mailboxes_can_be_imported_over_imap_and_from_a_maildir() {
    let (env, api) = admin_env().await;
    let source = env.account("old@example.org").await;
    let target = env.account("new@example.org").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(unomail::imap::serve(env.app.clone(), listener));

    // Source mailbox: two inbox messages (one read), one in a custom folder.
    let mut c = Client::smtp(env.mx).await;
    for subject in ["First", "Second"] {
        assert!(c.send_mail("a@remote.example", &["old@example.org"], &message("a@remote.example", "old@example.org", subject, "x")).await.starts_with("250"));
    }
    let inbox = env.app.store.mailbox_by_role(source.id, "inbox").await.unwrap().unwrap();
    let first = env.app.store.messages_in(inbox.id).await.unwrap()[0].id;
    env.app.store.set_flags_and_keywords(source.id, first, unomail::store::Flags { seen: true, ..Default::default() }, &["project".to_owned()]).await.unwrap();
    let folder = env.app.store.create_mailbox(source.id, "Projekte/Zürich").await.unwrap();
    env.app.store.append(source.id, folder.id, b"Subject: Filed\r\nMessage-ID: <filed@x>\r\n\r\nbody", Default::default(), Some(1_700_000_000)).await.unwrap();

    let request = json!({ "kind": "imap", "host": "127.0.0.1", "port": port, "username": "old@example.org", "password": PASSWORD, "allow_invalid_certificate": true });
    let started = api.post(&format!("/api/accounts/{}/import", target.id), request.clone()).await;
    assert_eq!(started.status, StatusCode::OK, "{}", started.text);
    let job = wait_for_job(&api, target.id).await;
    assert_eq!((job["status"].as_str(), job["imported"].as_i64()), (Some("completed"), Some(3)), "{job}");
    assert!(!job.to_string().contains(PASSWORD), "credentials are never stored");

    let target_inbox = env.app.store.mailbox_by_role(target.id, "inbox").await.unwrap().unwrap();
    let imported = env.app.store.messages_in(target_inbox.id).await.unwrap();
    assert_eq!(imported.iter().map(|m| m.subject.as_str()).collect::<Vec<_>>(), ["First", "Second"]);
    assert!(imported[0].seen && imported[0].keywords.contains("project") && !imported[1].seen, "flags and keywords survive");
    let copied = env.app.store.mailbox_by_name(target.id, "Projekte/Zürich").await.unwrap().expect("folders are recreated");
    assert_eq!(env.app.store.messages_in(copied.id).await.unwrap()[0].internal_date, 1_700_000_000, "dates are preserved");

    // Running it again imports nothing new.
    api.post(&format!("/api/accounts/{}/import", target.id), request).await;
    let again = wait_for_job(&api, target.id).await;
    assert_eq!((again["imported"].as_i64(), again["skipped"].as_i64()), (Some(0), Some(3)));

    // Wrong credentials fail cleanly.
    api.post(&format!("/api/accounts/{}/import", target.id), json!({ "kind": "imap", "host": "127.0.0.1", "port": port, "username": "old@example.org", "password": "wrong", "allow_invalid_certificate": true })).await;
    let failed = wait_for_job(&api, target.id).await;
    assert_eq!(failed["status"], "failed");
    assert_eq!(failed["error"], "the remote server rejected the credentials");

    // Maildir ingestion from the server's import directory. The "!" info separator is the
    // variant used on file systems that cannot store ":" (this suite also runs on Windows).
    let maildir = env.app.cfg.data_dir.join("import").join("legacy");
    for dir in ["cur", "new", ".Sent/cur", ".Work.Reports/cur"] {
        std::fs::create_dir_all(maildir.join(dir)).unwrap();
    }
    std::fs::write(maildir.join("cur/1.host!2,S"), "Subject: Old read\r\nMessage-ID: <m1@old>\r\n\r\nx").unwrap();
    std::fs::write(maildir.join("new/2.host"), "Subject: Old unread\r\nMessage-ID: <m2@old>\r\n\r\nx").unwrap();
    std::fs::write(maildir.join(".Sent/cur/3.host!2,RS"), "Subject: Old sent\r\nMessage-ID: <m3@old>\r\n\r\nx").unwrap();
    std::fs::write(maildir.join(".Work.Reports/cur/4.host!2,F"), "Subject: Report\r\nMessage-ID: <m4@old>\r\n\r\nx").unwrap();
    let started = api.post(&format!("/api/accounts/{}/import", target.id), json!({ "kind": "maildir", "path": "legacy" })).await;
    assert_eq!(started.status, StatusCode::OK, "{}", started.text);
    let job = wait_for_job(&api, target.id).await;
    assert_eq!((job["status"].as_str(), job["imported"].as_i64()), (Some("completed"), Some(4)), "{job}");
    let sent = env.app.store.mailbox_by_role(target.id, "sent").await.unwrap().unwrap();
    let sent_messages = env.app.store.messages_in(sent.id).await.unwrap();
    assert!(sent_messages[0].answered && sent_messages[0].seen);
    assert!(env.app.store.mailbox_by_name(target.id, "Work/Reports").await.unwrap().is_some());
    assert_eq!(env.app.store.messages_in(target_inbox.id).await.unwrap().len(), 4);
    for bad in ["../..", "/etc", "missing", "legacy/../../x"] {
        assert_eq!(api.post(&format!("/api/accounts/{}/import", target.id), json!({ "kind": "maildir", "path": bad })).await.status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn import_is_restricted_for_delegated_administrators() {
    let (env, admin) = admin_env().await;
    env.account("dana@example.org").await;
    let peer = env.account("peer@example.org").await;
    env.domain("other.example").await;
    let foreign = env.account("x@other.example").await;
    admin.put("/api/domains/1/admins", json!({ "emails": ["dana@example.org"] })).await;
    let dana = Api::logged_in(&env, "dana@example.org").await;
    let imap = |extra: Value| {
        let mut body = json!({ "kind": "imap", "host": "127.0.0.1", "port": 9, "username": "u", "password": "p" });
        body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        body
    };

    // Not into mailboxes of other domains, not from the server's disk, not without TLS checks.
    assert_eq!(dana.post(&format!("/api/accounts/{}/import", foreign.id), imap(json!({}))).await.status, StatusCode::NOT_FOUND);
    assert_eq!(dana.post(&format!("/api/accounts/{}/import", peer.id), json!({ "kind": "maildir", "path": "x" })).await.status, StatusCode::FORBIDDEN);
    assert_eq!(dana.post(&format!("/api/accounts/{}/import", peer.id), imap(json!({ "allow_invalid_certificate": true }))).await.status, StatusCode::FORBIDDEN);
    // Internal addresses are off limits: the import cannot be used to probe the local network.
    assert_eq!(dana.post(&format!("/api/accounts/{}/import", peer.id), imap(json!({}))).await.status, StatusCode::OK);
    let job = wait_for_job(&dana, peer.id).await;
    assert_eq!((job["status"].as_str(), job["error"].as_str()), (Some("failed"), Some("importing from private or internal addresses is not allowed")));
    let ordinary = Api::logged_in(&env, "peer@example.org").await;
    assert_eq!(ordinary.get(&format!("/api/accounts/{}/import", peer.id)).await.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn log_viewers_expose_system_logs_and_streams_to_the_right_roles() {
    let (env, api) = admin_env().await;
    env.account("bob@example.org").await;
    unomail::logstream::record_system("WARN", "unomail::test", "viewer-marker-123 something happened");
    let logs = api.get("/api/logs/system?q=viewer-marker-123").await;
    assert_eq!(logs.status, StatusCode::OK);
    assert_eq!(logs.body[0]["level"], "WARN");
    assert!(api.get("/api/logs/system?q=no-such-entry-anywhere").await.body.as_array().unwrap().is_empty());

    let bob = Api::logged_in(&env, "bob@example.org").await;
    for path in ["/api/logs/system", "/api/logs/stream?kind=system", "/api/logs/stream?kind=audit", "/api/logs/stream?kind=delivery"] {
        assert_eq!(bob.get(path).await.status, StatusCode::FORBIDDEN, "{path}");
    }
    assert_eq!(api.get("/api/logs/stream?kind=bogus").await.status, StatusCode::BAD_REQUEST);

    // Entries are published to the live stream as they are written.
    let mut receiver = unomail::logstream::subscribe();
    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail("a@remote.example", &["bob@example.org"], &message("a@remote.example", "bob@example.org", "stream-marker", "x")).await.starts_with("250"));
    let mut found = false;
    while let Ok(Ok(event)) = tokio::time::timeout(Duration::from_secs(2), receiver.recv()).await {
        if event.kind == "delivery" && event.entry["recipient"] == "bob@example.org" && event.entry["status"] == "delivered" {
            assert!(event.entry["id"].as_i64().unwrap() > 0);
            found = true;
            break;
        }
    }
    assert!(found, "delivery events reach the live stream");
}

#[tokio::test]
async fn unusable_stored_certificate_falls_back_to_a_working_self_signed_one() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = unomail::config::Config::for_tests(dir.path().to_path_buf());
    let first_id;
    {
        let app = unomail::app::App::new(cfg.clone(), None).await.unwrap();
        first_id = app.tls.info().id;
        // Corrupt the stored key, as a failed disk or a bad manual edit would.
        sqlx::query("UPDATE certificates SET key_pem = 'garbage'").execute(&app.db).await.unwrap();
        app.db.close().await;
    }
    let app = unomail::app::App::new(cfg, None).await.unwrap();
    let info = app.tls.info();
    assert_eq!(info.kind, unomail::tls::CertKind::SelfSigned);
    assert_ne!(info.id, first_id, "a fresh certificate replaces the unusable one");

    // TLS listeners still come up and complete handshakes with the fallback certificate.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(unomail::smtp::server::serve(app.clone(), unomail::smtp::server::Mode::Smtps, listener));
    let mut c = Client::connect_tls(addr).await;
    assert!(c.read_reply().await.starts_with("220 "));
    assert!(c.cmd("EHLO client.example.net").await.contains("AUTH PLAIN LOGIN"));
}

#[tokio::test]
async fn acme_http_challenge_handler_serves_only_pending_tokens() {
    let env = TestEnv::start().await;
    let api = Api::new(&env);
    assert_eq!(api.get("/.well-known/acme-challenge/unknown-token").await.status, StatusCode::NOT_FOUND);
    env.app.tls.http_challenges.lock().insert("tok_123".into(), "tok_123.thumbprint".into());

    let served = api.get("/.well-known/acme-challenge/tok_123").await;
    assert_eq!((served.status, served.text.as_str()), (StatusCode::OK, "tok_123.thumbprint"));
    assert_eq!(served.headers["content-type"], "text/plain");
    // The redirecting plain-HTTP listener answers challenges itself instead of redirecting.
    let redirecting = Api { router: unomail::api::redirect_router(env.app.clone()), ..api.clone() };
    assert_eq!(redirecting.get("/.well-known/acme-challenge/tok_123").await.text, "tok_123.thumbprint");
    assert_eq!(redirecting.get("/mail").await.status, StatusCode::PERMANENT_REDIRECT);
    // Redirects keep only Host names this server answers for.
    env.domain("example.org").await;
    let location = |host: &'static str| {
        let redirecting = &redirecting;
        async move { redirecting.send(axum::http::Method::GET, "/mail", None, &[("host", host)]).await.headers["location"].to_str().unwrap().to_owned() }
    };
    let own = env.app.cfg.hostname.clone();
    assert!(location("evil.example").await.starts_with(&format!("https://{own}")), "not sent to someone else's site");
    assert!(location("webmail.example.org").await.starts_with("https://webmail.example.org"));
    for probe in ["/.well-known/acme-challenge/../../api/auth/me", "/.well-known/acme-challenge/tok_123/extra", "/.well-known/acme-challenge/"] {
        assert_ne!(api.get(probe).await.text, "tok_123.thumbprint", "{probe}");
    }
    env.app.tls.http_challenges.lock().clear();
    assert_eq!(api.get("/.well-known/acme-challenge/tok_123").await.status, StatusCode::NOT_FOUND, "tokens disappear once the order is done");
}

#[tokio::test]
async fn sieve_includes_variables_and_vacation_work_end_to_end() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;

    // A library script, included by the active one.
    let library = "require [\"fileinto\", \"mailbox\", \"variables\", \"regex\"];\nif header :regex \"subject\" \"^\\\\[([a-z]+)\\\\]\" { set :upperfirst \"team\" \"${1}\"; fileinto :create \"Teams/${team}\"; stop; }";
    assert_eq!(api.put("/api/me/sieve", json!({ "name": "teams", "script": library, "active": false })).await.status, StatusCode::OK);
    let missing = api.put("/api/me/sieve", json!({ "name": "main", "script": "require \"include\"; include \"nope\";", "active": true })).await;
    assert_eq!(missing.body["error"]["message"], "line 1: included script \"nope\" does not exist");
    let main = "require [\"include\", \"vacation\"];\ninclude :personal \"teams\";\nvacation :days 2 :subject \"Away (filter)\" \"Back soon.\";";
    assert_eq!(api.put("/api/me/sieve", json!({ "name": "main", "script": main, "active": true })).await.status, StatusCode::OK);
    assert_eq!(api.put("/api/me/sieve", json!({ "name": "../evil", "script": "keep;", "active": false })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.get("/api/me/sieve/scripts").await.body, json!([{ "name": "main", "active": true }, { "name": "teams", "active": false }]));
    assert_eq!(api.get("/api/me/sieve?name=teams").await.body["script"], library);

    let mut c = Client::smtp(env.mx).await;
    for subject in ["[design] New mockups", "Hello Bob", "Hello again"] {
        assert!(c.send_mail("alice@remote.example", &["bob@example.org"], &message("alice@remote.example", "bob@example.org", subject, "x")).await.starts_with("250"));
    }
    let folder = env.app.store.mailbox_by_name(bob.id, "Teams/Design").await.unwrap().expect("folder named from a regex capture");
    assert_eq!(env.app.store.messages_in(folder.id).await.unwrap().len(), 1);
    assert_eq!(env.inbox(&bob).await.len(), 2);

    // The vacation action replied once (the filed message stopped before reaching it).
    queue::process_due(&env.app).await;
    let replies = sink.received();
    assert_eq!(replies.len(), 1, "one reply per sender within :days");
    assert!(replies[0].data.contains("Subject: Away (filter)") && replies[0].data.contains("Back soon.") && replies[0].data.contains("Auto-Submitted: auto-replied"));
    assert_eq!(replies[0].from, "");

    // Activating another script deactivates the first; deleting works; a script that is
    // still included elsewhere keeps the including script from compiling later only on save.
    assert_eq!(api.put("/api/me/sieve", json!({ "name": "teams", "script": library, "active": true })).await.status, StatusCode::OK);
    assert_eq!(api.get("/api/me/sieve/scripts").await.body, json!([{ "name": "main", "active": false }, { "name": "teams", "active": true }]));
    assert_eq!(api.delete("/api/me/sieve?name=main").await.status, StatusCode::OK);
    assert_eq!(api.delete("/api/me/sieve?name=main").await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn labels_can_be_renamed_and_deleted() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let eve = env.account("eve@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    for (account, label) in [(&bob, "work"), (&bob, "work"), (&eve, "work")] {
        let inbox = env.app.store.mailbox_by_role(account.id, "inbox").await.unwrap().unwrap();
        let appended = env.app.store.append(account.id, inbox.id, b"Subject: x\r\n\r\ny", Default::default(), None).await.unwrap();
        env.app.store.set_flags_and_keywords(account.id, appended.id, Default::default(), &[label.to_owned(), "other".to_owned()]).await.unwrap();
    }
    let renamed = api.post("/api/me/labels/rename", json!({ "from": "Work", "to": "Projects" })).await;
    assert_eq!(renamed.body, json!({ "changed": 2 }));
    assert_eq!(api.get("/api/me/labels").await.body, json!(["other", "projects"]));
    assert_eq!(api.post("/api/me/labels/rename", json!({ "from": "projects", "to": "bad name" })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.post("/api/me/labels/rename", json!({ "from": "projects", "to": "$seen" })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.delete("/api/me/labels?name=other").await.body, json!({ "changed": 2 }));
    assert_eq!(api.get("/api/me/labels").await.body, json!(["projects"]));
    // Another account's labels are untouched.
    assert_eq!(env.app.store.keywords(eve.id).await.unwrap(), ["other", "work"]);
}

#[tokio::test]
async fn global_sieve_scripts_and_mime_vacation_replies() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let bob = env.account("bob@example.org").await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;

    // Only administrators manage global scripts; they are validated like any other.
    let policy = "require [\"fileinto\", \"mailbox\"];\nif header :contains \"subject\" \"[external]\" { fileinto :create \"External\"; }";
    assert_eq!(api.put("/api/sieve/global", json!({ "name": "policy", "script": policy })).await.status, StatusCode::FORBIDDEN);
    assert_eq!(api.get("/api/sieve/global").await.status, StatusCode::FORBIDDEN);
    assert_eq!(admin.put("/api/sieve/global", json!({ "name": "policy", "script": "keep" })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(admin.put("/api/sieve/global", json!({ "name": "policy", "script": "require \"include\"; include :personal \"main\";" })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(admin.put("/api/sieve/global", json!({ "name": "policy", "script": policy })).await.status, StatusCode::OK);
    assert_eq!(admin.get("/api/sieve/global").await.body, json!([{ "name": "policy", "script": policy }]));

    let missing = api.put("/api/me/sieve", json!({ "script": "require \"include\"; include :global \"nope\";", "active": true })).await;
    assert_eq!(missing.body["error"]["message"], "line 1: included script \"nope\" does not exist");
    let script = "require [\"include\", \"vacation\"];\ninclude :global \"policy\";\nvacation :mime :subject \"Away\" \"Content-Type: text/html; charset=utf-8\n\n<p>Back <b>Monday</b>.</p>\";";
    assert_eq!(api.put("/api/me/sieve", json!({ "script": script, "active": true })).await.status, StatusCode::OK);
    let forged = "require \"vacation\"; vacation :mime \"Bcc: spy@remote.example\nContent-Type: text/plain\n\nhi\";";
    let refused = api.put("/api/me/sieve", json!({ "name": "x", "script": forged, "active": false })).await;
    assert!(refused.body["error"]["message"].as_str().unwrap().ends_with("only Content-* headers are allowed in a :mime reason"), "{}", refused.text);

    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail("alice@remote.example", &["bob@example.org"], &message("alice@remote.example", "bob@example.org", "[external] Hello", "x")).await.starts_with("250"));
    assert!(env.app.store.mailbox_by_name(bob.id, "External").await.unwrap().is_some(), "the global script ran for the user");
    queue::process_due(&env.app).await;
    let replies = sink.received();
    assert_eq!(replies.len(), 1);
    assert!(replies[0].data.contains("Content-Type: text/html; charset=utf-8\r\n\r\n<p>Back <b>Monday</b>.</p>"), "{}", replies[0].data);
    assert!(replies[0].data.contains("Auto-Submitted: auto-replied") && replies[0].data.contains("Subject: Away"));

    // Removing a global script that users still include does not break their mail delivery.
    assert_eq!(admin.delete("/api/sieve/global?name=policy").await.status, StatusCode::OK);
    assert_eq!(admin.delete("/api/sieve/global?name=policy").await.status, StatusCode::NOT_FOUND);
    assert!(c.send_mail("carol@remote.example", &["bob@example.org"], &message("carol@remote.example", "bob@example.org", "After removal", "x")).await.starts_with("250"));
    assert!(env.inbox(&bob).await.iter().any(|m| m.contains("Subject: After removal")));
}

#[tokio::test]
async fn imap_starttls_port_and_import_through_it() {
    let (env, api) = admin_env().await;
    let source = env.account("old@example.org").await;
    let target = env.account("new@example.org").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(unomail::imap::serve_starttls(env.app.clone(), listener));
    let inbox = env.app.store.mailbox_by_role(source.id, "inbox").await.unwrap().unwrap();
    env.app.store.append(source.id, inbox.id, b"Subject: Over STARTTLS\r\nMessage-ID: <s1@x>\r\n\r\nbody", Default::default(), None).await.unwrap();

    // Before the upgrade nothing but STARTTLS is possible; credentials are refused.
    let mut c = Client::connect(addr).await;
    assert_eq!(c.read_line().await.unwrap(), "* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] mail.test.example IMAP4rev1 ready");
    c.send_raw(format!("a1 LOGIN old@example.org \"{PASSWORD}\"\r\n").as_bytes()).await;
    assert_eq!(c.read_line().await.unwrap(), "a1 BAD [PRIVACYREQUIRED] issue STARTTLS first");
    c.send_raw(b"a2 SELECT INBOX\r\n").await;
    assert!(c.read_line().await.unwrap().starts_with("a2 BAD [PRIVACYREQUIRED]"));
    c.send_raw(b"a3 STARTTLS\r\n").await;
    assert!(c.read_line().await.unwrap().starts_with("a3 OK"));
    c.upgrade().await;
    c.send_raw(format!("a4 LOGIN old@example.org \"{PASSWORD}\"\r\n").as_bytes()).await;
    assert!(c.read_line().await.unwrap().starts_with("a4 OK"), "after the upgrade the session works normally");

    // Commands pipelined behind STARTTLS are never executed.
    let mut c = Client::connect(addr).await;
    c.read_line().await.unwrap();
    c.send_raw(format!("b1 STARTTLS\r\nb2 LOGIN old@example.org \"{PASSWORD}\"\r\n").as_bytes()).await;
    assert!(c.read_line().await.unwrap().starts_with("b1 BAD"));
    assert!(c.is_closed().await);

    let request = json!({ "kind": "imap", "host": "127.0.0.1", "port": addr.port(), "security": "starttls", "username": "old@example.org", "password": PASSWORD, "allow_invalid_certificate": true });
    assert_eq!(api.post(&format!("/api/accounts/{}/import", target.id), request).await.status, StatusCode::OK);
    let job = wait_for_job(&api, target.id).await;
    assert_eq!((job["status"].as_str(), job["imported"].as_i64()), (Some("completed"), Some(1)), "{job}");
    assert!(env.inbox(&target).await[0].contains("Subject: Over STARTTLS"));

    let bad = json!({ "kind": "imap", "host": "127.0.0.1", "security": "none", "username": "u", "password": "p" });
    assert_eq!(api.post(&format!("/api/accounts/{}/import", target.id), bad).await.status, StatusCode::BAD_REQUEST, "plaintext imports are not offered");
}
