//! End-to-end SMTP tests against a running server: inbound delivery, submission, the outbound
//! queue, and the abuse/attack cases the server must withstand.

mod common;

use common::{Api, Client, PASSWORD, Sink, TestEnv, message};
use unomail::{
    security::dkim::{self, Algorithm},
    smtp::{delivery, queue},
};

#[tokio::test]
async fn inbound_mail_is_delivered_to_the_inbox() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;

    let mut c = Client::smtp(env.mx).await;
    let reply = c
        .send_mail("alice@remote.example", &["bob@example.org"], &message("alice@remote.example", "bob@example.org", "Hi", "Hello Bob\r\n..leading dot"))
        .await;
    assert!(reply.starts_with("250 2.0.0 Ok: queued as "), "{reply}");
    assert!(c.cmd("QUIT").await.starts_with("221"));

    let inbox = env.inbox(&bob).await;
    assert_eq!(inbox.len(), 1);
    let stored = &inbox[0];
    assert!(stored.starts_with("Return-Path: <alice@remote.example>\r\nDelivered-To: bob@example.org\r\nReceived: from client.example.net ([127.0.0.1])"));
    assert!(stored.contains("Subject: Hi\r\n"));
    assert!(stored.contains("Hello Bob\r\n.leading dot\r\n"), "dot-stuffing is undone: {stored}");

    let (status, direction): (String, String) =
        sqlx::query_as("SELECT status, direction FROM delivery_log WHERE recipient = 'bob@example.org'").fetch_one(&env.app.db).await.unwrap();
    assert_eq!((status.as_str(), direction.as_str()), ("delivered", "inbound"));
}

#[tokio::test]
async fn mx_port_is_not_an_open_relay_and_hides_user_enumeration_commands() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;

    let mut c = Client::smtp(env.mx).await;
    assert!(c.cmd("MAIL FROM:<alice@remote.example>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<victim@elsewhere.example>").await.starts_with("554 5.7.1"), "relaying must be refused");
    assert!(c.cmd("RCPT TO:<nobody@example.org>").await.starts_with("550 5.1.1"));
    assert!(c.cmd("RCPT TO:<not an address>").await.starts_with("501"));
    assert!(c.cmd("DATA").await.starts_with("554"), "DATA without recipients is refused");
    assert!(c.cmd("VRFY bob").await.starts_with("502"));
    assert!(c.cmd("EXPN staff").await.starts_with("502"));
    // Authentication is never offered to (or accepted from) unauthenticated MX peers.
    assert!(c.cmd("AUTH PLAIN AGEAYg==").await.starts_with("503"));
    assert!(!c.cmd("EHLO client.example.net").await.contains("AUTH"));
}

#[tokio::test]
async fn helo_is_validated_on_the_mx_port() {
    let env = TestEnv::start().await;
    let mut c = Client::connect(env.mx).await;
    c.read_reply().await;
    assert!(c.cmd("MAIL FROM:<a@remote.example>").await.starts_with("503"), "HELO is required first");
    assert!(c.cmd("EHLO").await.starts_with("501"));
    assert!(c.cmd("EHLO not_a_domain").await.starts_with("501"));
    assert!(c.cmd("HELO localhost").await.starts_with("501"));
    assert!(c.cmd("EHLO [192.0.2.7]").await.starts_with("250"));
    assert!(c.cmd("HELO mx.remote.example").await.starts_with("250 "));
}

#[tokio::test]
async fn aliases_catch_all_and_subaddressing() {
    let env = TestEnv::start().await;
    let domain_id = env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let carol = env.account("carol@example.org").await;
    env.alias("team@example.org", &["bob@example.org", "carol@example.org"]).await;

    let mut c = Client::smtp(env.mx).await;
    let msg = message("a@remote.example", "team@example.org", "Team", "to the team");
    assert!(c.send_mail("a@remote.example", &["team@example.org"], &msg).await.starts_with("250"));
    assert!(c.send_mail("a@remote.example", &["bob+lists@example.org"], &msg).await.starts_with("250"));
    assert_eq!(env.inbox(&bob).await.len(), 2);
    assert_eq!(env.inbox(&carol).await.len(), 1);

    assert!(c.cmd("MAIL FROM:<a@remote.example>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<anything@example.org>").await.starts_with("550"));
    assert!(c.cmd("RSET").await.starts_with("250"));
    sqlx::query("UPDATE domains SET catch_all = 'carol@example.org' WHERE id = ?").bind(domain_id).execute(&env.app.db).await.unwrap();
    assert!(c.send_mail("a@remote.example", &["anything@example.org"], &msg).await.starts_with("250"));
    assert_eq!(env.inbox(&carol).await.len(), 2);
}

#[tokio::test]
async fn smtp_smuggling_with_bare_newlines_is_rejected() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;

    for payload in [
        // Bare-LF end-of-data followed by a smuggled second transaction.
        "Subject: one\r\n\r\nbody\n.\nMAIL FROM:<admin@example.org>\nRCPT TO:<bob@example.org>\nDATA\nSubject: smuggled\n\nx\r\n",
        "Subject: one\r\n\r\nbody\r\n.\rMAIL FROM:<admin@example.org>\r\n",
        "Subject: one\r\n\r\nline with bare \r carriage return\r\n",
    ] {
        let mut c = Client::smtp(env.mx).await;
        let reply = c.send_mail("alice@remote.example", &["bob@example.org"], payload).await;
        assert!(reply.starts_with("554 5.6.0"), "{payload:?} -> {reply}");
        // The connection is still in sync: the smuggled commands were consumed as data.
        assert!(c.cmd("NOOP").await.starts_with("250"));
    }
    assert!(env.inbox(&bob).await.is_empty());
}

#[tokio::test]
async fn message_size_and_recipient_limits() {
    let env = TestEnv::start_with(|cfg| {
        cfg.max_message_size = 2048;
        cfg.max_recipients = 2;
    })
    .await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    env.account("carol@example.org").await;
    env.account("dave@example.org").await;

    let mut c = Client::smtp(env.mx).await;
    assert!(c.cmd("MAIL FROM:<a@remote.example> SIZE=999999").await.starts_with("552"));
    assert!(c.cmd("MAIL FROM:<a@remote.example> SIZE=abc").await.starts_with("552"));
    assert!(c.cmd("MAIL FROM:<a@remote.example> EVIL=1").await.starts_with("555"));

    let big = format!("Subject: big\r\n\r\n{}\r\n", "x".repeat(70).repeat(60).replace("xxxxxxxxxx", "xxxxxxxxx\r\n"));
    assert!(c.send_mail("a@remote.example", &["bob@example.org"], &big).await.starts_with("552 5.3.4"));
    assert!(env.inbox(&bob).await.is_empty());

    assert!(c.cmd("MAIL FROM:<a@remote.example>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<bob@example.org>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<carol@example.org>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<dave@example.org>").await.starts_with("452"));
}

#[tokio::test]
async fn mailbox_quota_defers_delivery() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account_with("bob@example.org", unomail::auth::Role::User, Some(600)).await;
    let mut c = Client::smtp(env.mx).await;
    let msg = message("a@remote.example", "bob@example.org", "Quota", &"y".repeat(200));
    assert!(c.send_mail("a@remote.example", &["bob@example.org"], &msg).await.starts_with("250"));
    assert!(c.send_mail("a@remote.example", &["bob@example.org"], &msg).await.starts_with("452 4.2.2"));
    assert_eq!(env.inbox(&bob).await.len(), 1);
}

#[tokio::test]
async fn too_many_errors_close_the_connection() {
    let env = TestEnv::start().await;
    let mut c = Client::smtp(env.mx).await;
    for _ in 0..10 {
        assert!(c.cmd("BOGUS").await.starts_with("500"));
    }
    assert!(c.read_reply().await.starts_with("421"));
    assert!(c.is_closed().await);
}

#[tokio::test]
async fn submission_requires_tls_and_authentication() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;

    let mut c = Client::connect(env.submission).await;
    c.read_reply().await;
    let ehlo = c.cmd("EHLO laptop").await;
    assert!(ehlo.contains("STARTTLS") && !ehlo.contains("AUTH"), "AUTH must not be offered in plaintext: {ehlo}");
    assert!(c.auth_plain("bob@example.org", PASSWORD).await.starts_with("538"), "credentials are refused without TLS");
    assert!(c.cmd("MAIL FROM:<bob@example.org>").await.starts_with("530"));

    c.starttls().await;
    assert!(c.cmd("EHLO laptop").await.contains("AUTH PLAIN LOGIN"));
    assert!(c.cmd("MAIL FROM:<bob@example.org>").await.starts_with("530"), "TLS alone is not enough");
    assert!(c.auth_plain("bob@example.org", "wrong password").await.starts_with("535"));
    assert!(c.auth_plain("nobody@example.org", PASSWORD).await.starts_with("535"));
    assert!(c.cmd("AUTH CRAM-MD5").await.starts_with("504"));
    assert!(c.cmd("AUTH PLAIN !!!notbase64").await.starts_with("501"));
    assert!(c.auth_plain("bob@example.org", PASSWORD).await.starts_with("235"));
    assert!(c.cmd("MAIL FROM:<bob@example.org>").await.starts_with("250"));
}

#[tokio::test]
async fn starttls_command_injection_is_refused() {
    let env = TestEnv::start().await;
    let mut c = Client::smtp(env.submission).await;
    // Commands pipelined in the same packet as STARTTLS must never be executed.
    c.send_raw(b"STARTTLS\r\nEHLO injected.example\r\n").await;
    assert!(c.read_reply().await.starts_with("501"));
    assert!(c.is_closed().await);
}

#[tokio::test]
async fn auth_login_and_implicit_tls() {
    use base64::Engine;
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;

    let mut c = Client::connect_tls(env.smtps).await;
    assert!(c.read_reply().await.starts_with("220 "));
    let ehlo = c.cmd("EHLO laptop").await;
    assert!(ehlo.contains("AUTH PLAIN LOGIN") && !ehlo.contains("STARTTLS"), "{ehlo}");
    assert_eq!(c.cmd("AUTH LOGIN").await, "334 VXNlcm5hbWU6");
    assert_eq!(c.cmd(&b64("bob@example.org")).await, "334 UGFzc3dvcmQ6");
    assert!(c.cmd(&b64(PASSWORD)).await.starts_with("235"));
    assert!(c.cmd("AUTH LOGIN").await.starts_with("503"), "re-authentication is not allowed");

    let mut c = Client::connect_tls(env.smtps).await;
    c.read_reply().await;
    c.cmd("EHLO laptop").await;
    assert!(c.cmd("AUTH PLAIN").await.starts_with("334"));
    assert!(c.cmd("*").await.starts_with("501"), "client can cancel the exchange");
}

#[tokio::test]
async fn repeated_login_failures_lock_the_account() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;

    let mut c = Client::smtp(env.submission).await;
    c.starttls().await;
    for _ in 0..5 {
        assert!(c.auth_plain("bob@example.org", "guess").await.starts_with("535"));
    }
    // Even the correct password is refused while the lockout is active.
    assert!(c.auth_plain("bob@example.org", PASSWORD).await.starts_with("454"));
    assert!(c.is_closed().await);

    let failures: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'login.failed' AND actor = 'bob@example.org'")
        .fetch_one(&env.app.db)
        .await
        .unwrap();
    assert_eq!(failures, 5);
}

async fn submission_client(env: &TestEnv, user: &str) -> Client {
    let mut c = Client::smtp(env.submission).await;
    c.starttls().await;
    assert!(c.auth_plain(user, PASSWORD).await.starts_with("235"));
    c
}

#[tokio::test]
async fn users_cannot_send_as_someone_else() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let carol = env.account("carol@example.org").await;
    env.alias("sales@example.org", &["bob@example.org"]).await;

    let mut c = submission_client(&env, "bob@example.org").await;
    assert!(c.cmd("MAIL FROM:<carol@example.org>").await.starts_with("550 5.7.1"), "envelope spoofing");
    assert!(c.cmd("MAIL FROM:<>").await.starts_with("550 5.7.1"), "users may not send bounces");

    // Valid envelope, forged header From.
    let forged = message("carol@example.org", "carol@example.org", "Forged", "pretending to be carol");
    assert!(c.send_mail("bob@example.org", &["carol@example.org"], &forged).await.starts_with("550 5.7.1 From header"));
    let no_from = "Subject: no author\r\n\r\nbody\r\n";
    assert!(c.send_mail("bob@example.org", &["carol@example.org"], no_from).await.starts_with("550 5.6.0"));
    assert!(env.inbox(&carol).await.is_empty());

    // Sending through an alias that delivers to the user is allowed.
    let via_alias = message("Sales <sales@example.org>", "carol@example.org", "Offer", "legit");
    assert!(c.send_mail("sales@example.org", &["carol@example.org"], &via_alias).await.starts_with("250"));
    let inbox = env.inbox(&carol).await;
    assert_eq!(inbox.len(), 1);
    // The submitter's address is not disclosed: the client is recorded as localhost.
    assert!(inbox[0].contains("Received: from localhost (localhost [127.0.0.1])") && inbox[0].contains("by mail.test.example with ESMTPSA"), "{}", inbox[0]);
    assert!(c.cmd("MAIL FROM:<bob@example.org>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<ghost@example.org>").await.starts_with("550 5.1.1"));
    let _ = bob;
}

#[tokio::test]
async fn outbound_mail_is_signed_queued_and_delivered() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    let domain_id = env.domain("example.org").await;
    env.account("bob@example.org").await;
    dkim::create_key(&env.app.db, domain_id, "s1", Algorithm::Ed25519).await.unwrap();

    let mut c = submission_client(&env, "bob@example.org").await;
    let msg = "From: bob@example.org\r\nTo: friend@remote.example\r\nSubject: Outbound\r\n\r\nline one\r\n..dotted\r\n";
    assert!(c.send_mail("bob@example.org", &["friend@remote.example"], msg).await.starts_with("250"));

    let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM queue").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(queued, 1);
    assert_eq!(queue::process_due(&env.app).await, 1);

    let received = sink.received();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].from, "bob@example.org");
    assert_eq!(received[0].to, "friend@remote.example");
    let data = &received[0].data;
    assert!(data.contains("DKIM-Signature:") && data.contains("d=example.org") && data.contains("s=s1"), "{data}");
    assert!(data.contains("\r\nDate: ") && data.contains("\r\nMessage-ID: <"), "missing headers are added before signing");
    assert!(data.ends_with("line one\r\n.dotted\r\n"), "{data}");

    let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM queue").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(queued, 0);
    let delivered: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM delivery_log WHERE direction = 'outbound' AND status = 'delivered'")
        .fetch_one(&env.app.db)
        .await
        .unwrap();
    assert_eq!(delivered, 1);
}

#[tokio::test]
async fn permanent_failures_bounce_and_temporary_failures_are_retried() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;

    let mut c = submission_client(&env, "bob@example.org").await;
    let msg = message("bob@example.org", "x@remote.example", "Will fail", "secret body");
    assert!(c.send_mail("bob@example.org", &["reject@remote.example", "defer@remote.example"], &msg).await.starts_with("250"));
    assert_eq!(queue::process_due(&env.app).await, 2);
    assert!(sink.received().is_empty());

    let inbox = env.inbox(&bob).await;
    assert_eq!(inbox.len(), 1, "exactly one bounce, for the permanent failure");
    let bounce = &inbox[0];
    assert!(bounce.starts_with("Return-Path: <>\r\n"));
    assert!(bounce.contains("Final-Recipient: rfc822; reject@remote.example"));
    assert!(bounce.contains("550 5.1.1 No such user here"));
    assert!(bounce.contains("Subject: Will fail") && !bounce.contains("secret body"));

    let (recipient, attempts, status, next, last_error): (String, i64, String, i64, String) =
        sqlx::query_as("SELECT recipient, attempts, status, next_attempt_at, last_error FROM queue").fetch_one(&env.app.db).await.unwrap();
    assert_eq!((recipient.as_str(), attempts, status.as_str()), ("defer@remote.example", 1, "queued"));
    assert!(next > unomail::util::now() + 30, "retry is scheduled in the future");
    assert!(last_error.contains("451"));
    assert_eq!(queue::process_due(&env.app).await, 0, "not due yet");

    // Once the entry expires, a further temporary failure bounces it.
    sqlx::query("UPDATE queue SET next_attempt_at = 0, expires_at = 0").execute(&env.app.db).await.unwrap();
    assert_eq!(queue::process_due(&env.app).await, 1);
    assert_eq!(env.inbox(&bob).await.len(), 2);
    let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM queue").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(queued, 0, "bounces to a null sender are never bounced again");
}

#[tokio::test]
async fn forwarded_mail_uses_srs_and_bounces_find_their_way_back() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    env.alias("fwd@example.org", &["someone@faraway.example"]).await;

    let mut c = Client::smtp(env.mx).await;
    let msg = message("alice@remote.example", "fwd@example.org", "Forward me", "hello");
    assert!(c.send_mail("alice@remote.example", &["fwd@example.org"], &msg).await.starts_with("250"));
    queue::process_due(&env.app).await;

    let received = sink.received();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].to, "someone@faraway.example");
    let srs_sender = received[0].from.clone();
    assert!(srs_sender.starts_with("SRS0=") && srs_sender.ends_with("=remote.example=alice@example.org"), "{srs_sender}");

    // A bounce addressed to the SRS address is routed to the original sender...
    let bounce = message("MAILER-DAEMON@faraway.example", &srs_sender, "Undeliverable", "bounced");
    assert!(c.send_mail("", &[&srs_sender], &bounce).await.starts_with("250"));
    queue::process_due(&env.app).await;
    let received = sink.received();
    assert_eq!(received.len(), 2);
    assert_eq!(received[1].to, "alice@remote.example");

    // ...but a forged SRS address is not a relay.
    let forged = srs_sender.replace("=alice@", "=mallory@");
    assert!(c.cmd("MAIL FROM:<>").await.starts_with("250"));
    assert!(c.cmd(&format!("RCPT TO:<{forged}>")).await.starts_with("550"));
}

#[tokio::test]
async fn accounts_exceeding_the_sending_limit_are_blocked() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| {
        cfg.outbound_relay = Some(relay);
        cfg.outbound_max_messages_per_hour = 2;
    })
    .await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;

    let mut c = submission_client(&env, "bob@example.org").await;
    let msg = message("bob@example.org", "x@remote.example", "Spam run", "buy now");
    for _ in 0..2 {
        assert!(c.send_mail("bob@example.org", &["x@remote.example"], &msg).await.starts_with("250"));
    }
    assert!(c.send_mail("bob@example.org", &["x@remote.example"], &msg).await.starts_with("550 5.7.1 This account is blocked"));
    // The block persists for new connections until an administrator lifts it.
    let mut c = submission_client(&env, "bob@example.org").await;
    assert!(c.send_mail("bob@example.org", &["x@remote.example"], &msg).await.starts_with("550 5.7.1"));

    let (blocked, reason): (bool, String) =
        sqlx::query_as("SELECT outbound_blocked, outbound_blocked_reason FROM accounts WHERE email = 'bob@example.org'")
            .fetch_one(&env.app.db)
            .await
            .unwrap();
    assert!(blocked && reason.contains("limit exceeded"));
    let audited: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'account.outbound_blocked'")
        .fetch_one(&env.app.db)
        .await
        .unwrap();
    assert_eq!(audited, 1);
    let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM queue").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(queued, 2);
}

#[tokio::test]
async fn greylisting_defers_first_contact_only() {
    let env = TestEnv::start_with(|cfg| cfg.greylist_delay_secs = 60).await;
    let ip = "203.0.113.10".parse().unwrap();
    assert!(!delivery::greylist_pass(&env.app, ip, None, "a@remote.example", "bob@example.org").await.unwrap());
    assert!(!delivery::greylist_pass(&env.app, ip, None, "a@remote.example", "bob@example.org").await.unwrap(), "retry too early");
    // A different triplet has its own timer.
    assert!(!delivery::greylist_pass(&env.app, ip, None, "other@remote.example", "bob@example.org").await.unwrap());

    sqlx::query("UPDATE greylist SET first_seen = first_seen - 120").execute(&env.app.db).await.unwrap();
    // Another host in the same /24 retrying counts as the same sender.
    let neighbour = "203.0.113.77".parse().unwrap();
    assert!(delivery::greylist_pass(&env.app, neighbour, None, "a@remote.example", "bob@example.org").await.unwrap());
    assert!(delivery::greylist_pass(&env.app, ip, None, "a@remote.example", "bob@example.org").await.unwrap(), "known triplets pass immediately");
}

#[tokio::test]
async fn disabled_accounts_and_domains_stop_receiving_and_sending() {
    let env = TestEnv::start().await;
    let domain_id = env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;

    sqlx::query("UPDATE accounts SET smtp_enabled = 0 WHERE id = ?").bind(bob.id).execute(&env.app.db).await.unwrap();
    let mut c = Client::smtp(env.submission).await;
    c.starttls().await;
    assert!(c.auth_plain("bob@example.org", PASSWORD).await.starts_with("535"), "SMTP access disabled for the mailbox");

    sqlx::query("UPDATE accounts SET enabled = 0 WHERE id = ?").bind(bob.id).execute(&env.app.db).await.unwrap();
    let mut c = Client::smtp(env.mx).await;
    assert!(c.cmd("MAIL FROM:<a@remote.example>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<bob@example.org>").await.starts_with("550"));

    sqlx::query("UPDATE accounts SET enabled = 1 WHERE id = ?").bind(bob.id).execute(&env.app.db).await.unwrap();
    sqlx::query("UPDATE domains SET enabled = 0 WHERE id = ?").bind(domain_id).execute(&env.app.db).await.unwrap();
    assert!(c.cmd("RCPT TO:<bob@example.org>").await.starts_with("554"), "a disabled domain is no longer local");
}

#[tokio::test]
async fn unreachable_content_filter_defers_mail_instead_of_skipping_the_scan() {
    // Nothing listens on the discard port: the filter is configured but down.
    let env = TestEnv::start_with(|cfg| cfg.rspamd_url = Some("http://127.0.0.1:9".into())).await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let mut c = Client::smtp(env.mx).await;
    let msg = message("a@remote.example", "bob@example.org", "Unscanned", "x");
    assert!(c.send_mail("a@remote.example", &["bob@example.org"], &msg).await.starts_with("451 4.7.1 Content filter"));
    assert!(env.inbox(&bob).await.is_empty());
    let mut c = submission_client(&env, "bob@example.org").await;
    let own = message("bob@example.org", "x@remote.example", "Outbound", "x");
    assert!(c.send_mail("bob@example.org", &["x@remote.example"], &own).await.starts_with("451 4.7.1"));

    // Operators can opt into availability over filtering.
    let env = TestEnv::start_with(|cfg| {
        cfg.rspamd_url = Some("http://127.0.0.1:9".into());
        cfg.rspamd_fail_open = true;
    })
    .await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail("a@remote.example", &["bob@example.org"], &msg).await.starts_with("250"));
    assert_eq!(env.inbox(&bob).await.len(), 1);
}

#[tokio::test]
async fn whole_message_virus_scan_rejects_infected_mail_and_fails_closed() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // A stand-in clamd speaking INSTREAM: reports a virus when the stream contains "EICAR".
    let clamd = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = clamd.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = clamd.accept().await {
            tokio::spawn(async move {
                let mut command = [0u8; 10];
                socket.read_exact(&mut command).await.unwrap();
                assert_eq!(&command, b"zINSTREAM\0");
                let mut data = Vec::new();
                loop {
                    let mut len = [0u8; 4];
                    socket.read_exact(&mut len).await.unwrap();
                    let len = u32::from_be_bytes(len) as usize;
                    if len == 0 {
                        break;
                    }
                    let mut chunk = vec![0u8; len];
                    socket.read_exact(&mut chunk).await.unwrap();
                    data.extend_from_slice(&chunk);
                }
                let reply: &[u8] = if data.starts_with(b"X5O!P%@AP") { b"stream: Eicar-Signature FOUND\0" } else { b"stream: OK\0" };
                let _ = socket.write_all(reply).await;
            });
        }
    });

    let scanner = addr.clone();
    let env = TestEnv::start_with(move |cfg| cfg.clamav_addr = Some(scanner)).await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let mut c = Client::smtp(env.mx).await;
    let clean = message("a@remote.example", "bob@example.org", "Clean", "nothing here");
    // The signature only as plain body text: found by the per-part scan, not the whole-message one.
    let infected = message("a@remote.example", "bob@example.org", "Hi", "X5O!P%@AP[4 EICAR-STANDARD-ANTIVIRUS-TEST-FILE");
    let mentions = message("a@remote.example", "bob@example.org", "FYI", "The test string starts with X5O!P%@AP, as you know.");
    assert!(c.send_mail("a@remote.example", &["bob@example.org"], &clean).await.starts_with("250"));
    assert_eq!(c.send_mail("a@remote.example", &["bob@example.org"], &infected).await, "554 5.7.1 Message rejected: it contains a virus");
    assert!(c.send_mail("a@remote.example", &["bob@example.org"], &mentions).await.starts_with("250"), "merely mentioning it is fine");
    assert_eq!(env.inbox(&bob).await.len(), 2);
    let detail: String = sqlx::query_scalar("SELECT detail FROM delivery_log WHERE status = 'rejected'").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(detail, "virus detected: Eicar-Signature");
    // Outgoing mail from users is scanned too.
    let mut s = submission_client(&env, "bob@example.org").await;
    let outgoing = message("bob@example.org", "x@remote.example", "Fwd", "X5O!P%@AP[4 EICAR payload");
    assert!(s.send_mail("bob@example.org", &["x@remote.example"], &outgoing).await.starts_with("554 5.7.1 Message rejected: it contains a virus"));

    // A configured scanner that is down defers mail instead of letting it through unscanned.
    let env = TestEnv::start_with(|cfg| cfg.clamav_addr = Some("127.0.0.1:9".into())).await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail("a@remote.example", &["bob@example.org"], &clean).await.starts_with("451 4.7.1 Content filter"));
}

#[tokio::test]
async fn internationalized_addresses() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    let jozef = env.account("józef@example.org").await;
    env.alias("zażółć@example.org", &["józef@example.org"]).await;

    // Receiving: advertised, and required for non-ASCII addresses.
    let mut c = Client::smtp(env.mx).await;
    assert!(c.cmd("EHLO remote.example").await.contains("SMTPUTF8"));
    assert!(c.cmd("MAIL FROM:<ann@remote.example>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<józef@example.org>").await.starts_with("553 5.6.7"), "the transaction did not announce SMTPUTF8");
    assert!(c.cmd("RSET").await.starts_with("250"));
    assert!(c.cmd("MAIL FROM:<żaneta@remote.example>").await.starts_with("553 5.6.7"));
    assert!(c.cmd("MAIL FROM:<żaneta@remote.example> SMTPUTF8").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<JÓZEF@example.org>").await.starts_with("250"), "matching ignores case in any script");
    assert!(c.cmd("RCPT TO:<zażółć@example.org>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<nieznany.żółw@example.org>").await.starts_with("550"));
    assert!(c.cmd("DATA").await.starts_with("354"));
    c.send_raw("From: Żaneta <żaneta@remote.example>\r\nTo: józef@example.org\r\nSubject: Zażółć gęślą jaźń\r\n\r\nCześć\r\n.\r\n".as_bytes()).await;
    assert!(c.read_reply().await.starts_with("250"));
    let inbox = env.inbox(&jozef).await;
    assert_eq!(inbox.len(), 2, "once directly and once through the alias");
    assert!(inbox[0].contains("Return-Path: <żaneta@remote.example>") && inbox[0].contains("Subject: Zażółć gęślą jaźń"));

    // The account signs in with its internationalized address on every protocol.
    let api = Api::logged_in(&env, "JÓZEF@example.org").await;
    assert_eq!(api.get("/api/auth/me").await.body["account"]["email"], "józef@example.org");
    let mut c = Client::smtp(env.submission).await;
    c.cmd("EHLO client.example").await;
    c.starttls().await;
    c.cmd("EHLO client.example").await;
    assert!(c.auth_plain("józef@example.org", PASSWORD).await.starts_with("235"));

    // Sending: internationalized addresses cannot be expressed to a server without the
    // extension, so the message bounces instead of being mangled.
    async fn send(c: &mut Client) {
        assert!(c.cmd("MAIL FROM:<józef@example.org> SMTPUTF8").await.starts_with("250"));
        assert!(c.cmd("RCPT TO:<zoë@remote.example>").await.starts_with("250"));
        assert!(c.cmd("DATA").await.starts_with("354"));
        c.send_raw("From: józef@example.org\r\nTo: zoë@remote.example\r\nSubject: hello\r\n\r\nhi\r\n.\r\n".as_bytes()).await;
        assert!(c.read_reply().await.starts_with("250"));
    }
    send(&mut c).await;
    queue::process_due(&env.app).await;
    assert!(sink.received().is_empty());
    let bounce = env.inbox(&jozef).await.into_iter().find(|m| m.contains("Undelivered Mail Returned to Sender")).expect("a bounce for the undeliverable recipient");
    assert!(bounce.contains("does not support internationalized addresses"));

    // A server that supports it receives the message with the addresses intact.
    sink.smtputf8.store(true, std::sync::atomic::Ordering::Relaxed);
    send(&mut c).await;
    queue::process_due(&env.app).await;
    let received = sink.received();
    assert_eq!(received.len(), 1);
    assert_eq!((received[0].from.as_str(), received[0].to.as_str()), ("józef@example.org", "zoë@remote.example"));
}

#[tokio::test]
async fn overlong_command_lines_end_the_session() {
    let env = TestEnv::start().await;
    let mut c = Client::smtp(env.mx).await;
    // Longer than any command may be: refused and disconnected, never buffered without bound.
    c.send_raw(format!("MAIL FROM:<{}@example.org>\r\n", "a".repeat(64 * 1024)).as_bytes()).await;
    // The refusal may be lost to the reset when the client is still sending; either way the
    // server answers 500 or nothing, and hangs up.
    if let Some(line) = c.read_line().await {
        assert!(line.starts_with("500 5.5.2 Line too long"), "{line}");
        assert!(c.is_closed().await);
    }
}

fn with_attachment(from: &str, to: &str, name: &str) -> String {
    format!(
        "From: {from}\r\nTo: {to}\r\nSubject: Invoice\r\nDate: Thu, 15 Oct 2026 10:00:00 +0000\r\nMessage-ID: <{name}@test>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\nPlease see the attachment.\r\n--b1\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAAEAAAA\r\n--b1--\r\n"
    )
}

#[tokio::test]
async fn executable_attachments_are_refused_in_both_directions() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    env.account("carol@example.org").await;

    let mut c = Client::smtp(env.mx).await;
    let reply = c.send_mail("alice@remote.example", &["bob@example.org"], &with_attachment("alice@remote.example", "bob@example.org", "Invoice.pdf.exe")).await;
    assert!(reply.starts_with("552 5.7.0 Message refused: it contains an executable attachment (Invoice.pdf.exe)"), "{reply}");
    let reply = c.send_mail("alice@remote.example", &["bob@example.org"], &with_attachment("alice@remote.example", "bob@example.org", "Invoice.pdf")).await;
    assert!(reply.starts_with("250"), "ordinary attachments are fine: {reply}");
    assert_eq!(env.inbox(&bob).await.len(), 1);
    let (status, detail): (String, String) =
        sqlx::query_as("SELECT status, detail FROM delivery_log WHERE status = 'rejected'").fetch_one(&env.app.db).await.unwrap();
    assert_eq!((status.as_str(), detail.as_str()), ("rejected", "executable attachment: Invoice.pdf.exe"));

    // Users cannot send them either.
    let mut s = submission_client(&env, "bob@example.org").await;
    let reply = s.send_mail("bob@example.org", &["carol@example.org"], &with_attachment("bob@example.org", "carol@example.org", "tool.scr")).await;
    assert!(reply.starts_with("552 5.7.0"), "{reply}");

    // The administrator can switch the policy off.
    let relaxed = unomail::settings::Runtime { block_executable_attachments: false, ..(*env.app.rt()).clone() };
    env.app.settings.store(std::sync::Arc::new(relaxed));
    let reply = c.send_mail("alice@remote.example", &["bob@example.org"], &with_attachment("alice@remote.example", "bob@example.org", "setup.exe")).await;
    assert!(reply.starts_with("250"), "{reply}");
    assert_eq!(env.inbox(&bob).await.len(), 2);
}

#[tokio::test]
async fn greylisting_follows_spf_authorised_senders_across_networks() {
    let env = TestEnv::start_with(|cfg| cfg.greylist_delay_secs = 60).await;
    let (first, elsewhere) = ("203.0.113.10".parse().unwrap(), "2001:db8:4860::1".parse().unwrap());
    assert!(!delivery::greylist_pass(&env.app, first, Some("Gmail.example"), "a@gmail.example", "bob@example.org").await.unwrap());
    sqlx::query("UPDATE greylist SET first_seen = first_seen - 120").execute(&env.app.db).await.unwrap();
    // The retry comes from another of the domain's hosts, over IPv6.
    assert!(delivery::greylist_pass(&env.app, elsewhere, Some("gmail.example"), "a@gmail.example", "bob@example.org").await.unwrap());
    // Once through, the domain's other senders (and per-message bounce addresses) pass at once.
    assert!(delivery::greylist_pass(&env.app, first, Some("gmail.example"), "bounce-1234@gmail.example", "bob@example.org").await.unwrap());
    // Without SPF the network still counts.
    assert!(!delivery::greylist_pass(&env.app, elsewhere, None, "a@gmail.example", "bob@example.org").await.unwrap());
}

#[tokio::test]
async fn requiretls_is_offered_over_tls_and_never_downgraded() {
    // The sink offers no STARTTLS: a REQUIRETLS message must not go there.
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;

    let mut plain = Client::smtp(env.mx).await;
    let ehlo = plain.cmd("EHLO peer.example").await;
    assert!(!ehlo.contains("REQUIRETLS"), "only offered on encrypted sessions: {ehlo}");
    assert!(plain.cmd("MAIL FROM:<a@remote.example> REQUIRETLS").await.starts_with("530"));

    let mut c = submission_client(&env, "bob@example.org").await;
    assert!(c.cmd("EHLO laptop").await.contains("REQUIRETLS"));
    assert!(c.cmd("MAIL FROM:<bob@example.org> REQUIRETLS").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<friend@remote.example>").await.starts_with("250"));
    assert!(c.cmd("DATA").await.starts_with("354"));
    assert!(c.cmd("From: bob@example.org\r\nTo: friend@remote.example\r\nSubject: Secret\r\n\r\nonly over TLS\r\n.").await.starts_with("250"));
    let flagged: i64 = sqlx::query_scalar("SELECT require_tls FROM queue").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(flagged, 1);
    assert_eq!(queue::process_due(&env.app).await, 1);
    assert!(sink.received().is_empty(), "the message was not handed over without TLS");
    let error: Option<String> = sqlx::query_scalar("SELECT last_error FROM queue").fetch_one(&env.app.db).await.unwrap();
    assert!(error.unwrap_or_default().contains("STARTTLS"));

    // Without REQUIRETLS the same route takes it.
    sqlx::query("DELETE FROM queue").execute(&env.app.db).await.unwrap();
    let mut c = submission_client(&env, "bob@example.org").await;
    assert!(c.send_mail("bob@example.org", &["friend@remote.example"], "From: bob@example.org\r\nTo: friend@remote.example\r\nSubject: Open\r\n\r\nx\r\n").await.starts_with("250"));
    assert_eq!(queue::process_due(&env.app).await, 1);
    assert_eq!(sink.received().len(), 1);
}
