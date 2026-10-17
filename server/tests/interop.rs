//! Getting along with other mail servers as the standards describe them: 7-bit-only servers,
//! servers without EHLO, servers whose STARTTLS is broken, relays naming the submitter with
//! `AUTH=`, and domains that do not exist.

mod common;

use std::sync::atomic::Ordering;

use common::{Client, PASSWORD, Sink, TestEnv};
use unomail::smtp::queue;

const UTF8_MESSAGE: &str = "From: bob@example.org\r\nTo: x@remote.example\r\nSubject: Hello\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nZażółć gęślą jaźń\r\n";

async fn env_with(sink: &Sink) -> TestEnv {
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env
}

async fn send(env: &TestEnv, message: &str) {
    let mut c = Client::smtp(env.submission).await;
    c.starttls().await;
    c.cmd("EHLO laptop").await;
    assert!(c.auth_plain("bob@example.org", PASSWORD).await.starts_with("235"));
    assert!(c.send_mail("bob@example.org", &["x@remote.example"], message).await.starts_with("250"));
    queue::process_due(&env.app).await;
}

#[tokio::test]
async fn eight_bit_mail_is_announced_or_converted() {
    let sink = Sink::start().await;
    let env = env_with(&sink).await;

    send(&env, UTF8_MESSAGE).await;
    let modern = sink.received().pop().expect("delivered");
    assert!(modern.params.contains("BODY=8BITMIME"), "{}", modern.params);
    assert!(modern.data.contains("Zażółć"));

    // A server without 8BITMIME gets quoted-printable.
    sink.quirks.seven_bit.store(true, Ordering::Relaxed);
    send(&env, UTF8_MESSAGE).await;
    let old = sink.received().pop().expect("delivered");
    assert!(!old.params.contains("BODY="), "{}", old.params);
    assert!(old.data.is_ascii(), "{}", old.data);
    assert!(old.data.contains("Content-Transfer-Encoding: quoted-printable\r\n\r\nZa=C5=BC=C3=B3=C5=82=C4=87 g=C4=99=C5=9Bl=C4=85 ja=C5=BA=C5=84\r\n"), "{}", old.data);
    assert!(!old.data.contains("8bit"));

    // Plain ASCII mail is sent as it is, without a BODY parameter.
    send(&env, &common::message("bob@example.org", "x@remote.example", "Plain", "hello")).await;
    assert!(!sink.received().pop().unwrap().params.contains("BODY="));
    assert_eq!(sink.received().len(), 3);
}

#[tokio::test]
async fn servers_without_ehlo_are_greeted_with_helo() {
    let sink = Sink::start().await;
    sink.quirks.no_ehlo.store(true, Ordering::Relaxed);
    let env = env_with(&sink).await;
    send(&env, &common::message("bob@example.org", "x@remote.example", "Old server", "hello")).await;
    assert_eq!(sink.received().len(), 1, "delivered after falling back to HELO");
}

#[tokio::test]
async fn broken_starttls_falls_back_to_plain_delivery() {
    let sink = Sink::start().await;
    sink.quirks.broken_tls.store(true, Ordering::Relaxed);
    let env = env_with(&sink).await;
    send(&env, &common::message("bob@example.org", "x@remote.example", "Broken TLS", "hello")).await;
    assert_eq!(sink.received().len(), 1, "delivered without encryption, as to a server that offers none");
    let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM queue").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(queued, 0);
}

#[tokio::test]
async fn broken_starttls_is_not_bypassed_when_encryption_is_required() {
    let sink = Sink::start().await;
    sink.quirks.broken_tls.store(true, Ordering::Relaxed);
    let env = env_with(&sink).await;
    let mut settings = (**env.app.settings.load()).clone();
    settings.outbound_require_tls = true;
    env.app.settings.store(std::sync::Arc::new(settings));
    send(&env, &common::message("bob@example.org", "x@remote.example", "Must be secret", "hello")).await;
    assert!(sink.received().is_empty());
    let (attempts, last_error): (i64, String) = sqlx::query_as("SELECT attempts, last_error FROM queue").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(attempts, 1, "kept for another try");
    assert!(last_error.contains("TLS"), "{last_error}");
}

#[tokio::test]
async fn submitters_may_name_themselves_with_the_auth_parameter() {
    let sink = Sink::start().await;
    let env = env_with(&sink).await;
    let mut c = Client::smtp(env.submission).await;
    c.starttls().await;
    c.cmd("EHLO relay.example.org").await;
    assert!(c.auth_plain("bob@example.org", PASSWORD).await.starts_with("235"));
    assert!(c.cmd("MAIL FROM:<bob@example.org> AUTH=<>").await.starts_with("250"));
    assert!(c.cmd("RSET").await.starts_with("250"));
    assert!(c.cmd("MAIL FROM:<bob@example.org> AUTH=bob+40example.org").await.starts_with("250"));
    assert!(c.cmd("RSET").await.starts_with("250"));
    assert!(c.cmd("MAIL FROM:<bob@example.org> AUTH=bad+zz").await.starts_with("501"));

    // Port 25 offers no AUTH, so the parameter is unknown there.
    let mut mx = Client::smtp(env.mx).await;
    assert!(mx.cmd("MAIL FROM:<x@remote.example> AUTH=<>").await.starts_with("555"));
}

/// `cargo test --test interop -- --ignored`: needs the Internet.
#[tokio::test]
#[ignore = "needs the Internet"]
async fn live_mail_exchanger_lookups() {
    use unomail::dns::mail_exchangers;
    let resolver = mail_auth::MessageAuthenticator::new_cloudflare_tls().unwrap();
    assert_eq!(mail_exchangers(&resolver, "no-such-domain-7f3c9a1e.com").await.unwrap(), None, "NXDOMAIN: the domain does not exist");
    assert_eq!(mail_exchangers(&resolver, "www.wikipedia.org").await.unwrap(), Some(Vec::new()), "a name without MX records exists");
    let gmail = mail_exchangers(&resolver, "gmail.com").await.unwrap().unwrap();
    assert!(gmail.windows(2).all(|pair| pair[0].0 <= pair[1].0), "{gmail:?}");
}
