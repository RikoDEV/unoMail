//! Delivery status notifications (RFC 3461) and BDAT chunking (RFC 3030).

mod common;

use common::{Client, PASSWORD, Sink, TestEnv, message};
use unomail::smtp::queue;

async fn submission_client(env: &TestEnv, user: &str) -> Client {
    let mut c = Client::smtp(env.submission).await;
    c.starttls().await;
    assert!(c.auth_plain(user, PASSWORD).await.starts_with("235"));
    c
}

async fn send_with(c: &mut Client, mail: &str, rcpts: &[&str], msg: &str) -> String {
    let reply = c.cmd(mail).await;
    assert!(reply.starts_with("250"), "{mail}: {reply}");
    for rcpt in rcpts {
        let reply = c.cmd(rcpt).await;
        assert!(reply.starts_with("250"), "{rcpt}: {reply}");
    }
    assert!(c.cmd("DATA").await.starts_with("354"));
    c.send_raw(msg.as_bytes()).await;
    c.cmd(".").await
}

#[tokio::test]
async fn senders_choose_which_notifications_they_get() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    env.account("carol@example.org").await;

    let mut c = submission_client(&env, "bob@example.org").await;
    let ehlo = c.cmd("EHLO client.example.net").await;
    assert!(ehlo.contains("250-DSN") && ehlo.contains("CHUNKING"), "{ehlo}");

    // Malformed parameters are refused.
    assert!(c.cmd("MAIL FROM:<bob@example.org> RET=BODY").await.starts_with("501"));
    assert!(c.cmd("MAIL FROM:<bob@example.org> ENVID=a=b").await.starts_with("501"));
    assert!(c.cmd("MAIL FROM:<bob@example.org> RET=HDRS ENVID=QQ314159").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<carol@example.org> NOTIFY=NEVER,SUCCESS").await.starts_with("501"));
    assert!(c.cmd("RCPT TO:<carol@example.org> ORCPT=x400;thing").await.starts_with("501"));
    assert!(c.cmd("RCPT TO:<carol@example.org> FOO=bar").await.starts_with("555"));
    assert!(c.cmd("RSET").await.starts_with("250"));

    // NOTIFY=SUCCESS for a local mailbox: a "delivered" report with the envelope id.
    let msg = message("bob@example.org", "carol@example.org", "Did it arrive?", "body");
    let reply = send_with(&mut c, "MAIL FROM:<bob@example.org> ENVID=QQ314159", &["RCPT TO:<carol@example.org> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;carol@example.org"], &msg).await;
    assert!(reply.starts_with("250"), "{reply}");
    let inbox = env.inbox(&bob).await;
    assert_eq!(inbox.len(), 1, "{inbox:?}");
    assert!(inbox[0].contains("Original-Envelope-Id: QQ314159\r\n"), "{}", inbox[0]);
    assert!(inbox[0].contains("Action: delivered\r\nStatus: 2.0.0\r\n"), "{}", inbox[0]);

    // NOTIFY=NEVER: a permanent failure is not reported. Default: it is.
    let msg = message("bob@example.org", "x@remote.example", "Quiet", "body");
    let reply = send_with(&mut c, "MAIL FROM:<bob@example.org>", &["RCPT TO:<reject-quiet@remote.example> NOTIFY=NEVER", "RCPT TO:<reject-loud@remote.example>"], &msg).await;
    assert!(reply.starts_with("250"), "{reply}");
    queue::process_due(&env.app).await;
    let inbox = env.inbox(&bob).await;
    assert_eq!(inbox.len(), 2, "one bounce only");
    assert!(inbox[1].contains("Final-Recipient: rfc822; reject-loud@remote.example"));

    // A receiver without DSN support: we report "relayed" ourselves, with the full message
    // when asked for it.
    let msg = message("bob@example.org", "friend@remote.example", "Relayed", "the whole body");
    send_with(&mut c, "MAIL FROM:<bob@example.org> RET=FULL", &["RCPT TO:<friend@remote.example> NOTIFY=SUCCESS"], &msg).await;
    queue::process_due(&env.app).await;
    let inbox = env.inbox(&bob).await;
    assert_eq!(inbox.len(), 3);
    assert!(inbox[2].contains("Action: relayed\r\n") && inbox[2].contains("the whole body"), "{}", inbox[2]);
    let params = sink.received().last().unwrap().params.clone();
    assert!(params.starts_with("SIZE=") && !params.contains("NOTIFY") && !params.contains("RET"), "nothing passed to a server without DSN: {params}");

    // A receiver with DSN support takes the request over, and nothing comes from us.
    sink.dsn.store(true, std::sync::atomic::Ordering::Relaxed);
    let msg = message("bob@example.org", "friend@remote.example", "Passed on", "body");
    send_with(&mut c, "MAIL FROM:<bob@example.org> RET=HDRS ENVID=abc", &["RCPT TO:<friend@remote.example> NOTIFY=SUCCESS,DELAY"], &msg).await;
    queue::process_due(&env.app).await;
    assert_eq!(env.inbox(&bob).await.len(), 3);
    let params = sink.received().last().unwrap().params.clone();
    assert!(params.ends_with(" RET=HDRS ENVID=abc NOTIFY=DELAY,SUCCESS ORCPT=rfc822;friend@remote.example"), "{params}");

    // NOTIFY=DELAY: told once that delivery is still being retried.
    sink.dsn.store(false, std::sync::atomic::Ordering::Relaxed);
    let msg = message("bob@example.org", "defer@remote.example", "Slow", "body");
    send_with(&mut c, "MAIL FROM:<bob@example.org>", &["RCPT TO:<defer@remote.example> NOTIFY=DELAY,FAILURE"], &msg).await;
    queue::process_due(&env.app).await;
    assert_eq!(env.inbox(&bob).await.len(), 3, "not after the first attempt");
    for _ in 0..2 {
        sqlx::query("UPDATE queue SET next_attempt_at = 0, created_at = created_at - 5 * 3600").execute(&env.app.db).await.unwrap();
        queue::process_due(&env.app).await;
    }
    let inbox = env.inbox(&bob).await;
    assert_eq!(inbox.len(), 4, "once");
    assert!(inbox[3].contains("Action: delayed\r\n") && inbox[3].contains("Subject: Delayed Mail"), "{}", inbox[3]);
}

#[tokio::test]
async fn messages_can_arrive_in_chunks() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;

    let mut c = Client::smtp(env.mx).await;
    // BDAT before a transaction: the chunk is still read, so the session stays usable.
    c.send_raw(b"BDAT 5\r\nhello").await;
    assert!(c.read_reply().await.starts_with("503"));

    assert!(c.cmd("MAIL FROM:<alice@remote.example>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<bob@example.org>").await.starts_with("250"));
    let msg = message("alice@remote.example", "bob@example.org", "In pieces", "first part\r\nsecond part");
    let (head, tail) = msg.split_at(msg.len() / 2);
    c.send_raw(format!("BDAT {}\r\n{head}", head.len()).as_bytes()).await;
    assert_eq!(c.read_reply().await, format!("250 2.0.0 {} octets received", head.len()));
    assert!(c.cmd("DATA").await.starts_with("503"), "no switching to DATA");
    c.send_raw(format!("BDAT {} LAST\r\n{tail}", tail.len()).as_bytes()).await;
    assert!(c.read_reply().await.starts_with("250 2.0.0 Ok: queued"));
    let inbox = env.inbox(&bob).await;
    assert_eq!(inbox.len(), 1);
    assert!(inbox[0].contains("Subject: In pieces") && inbox[0].ends_with("first part\r\nsecond part\r\n"), "{}", inbox[0]);

    // Dots and binary-looking content arrive untouched; bare line feeds do not pass.
    assert!(c.cmd("MAIL FROM:<alice@remote.example>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<bob@example.org>").await.starts_with("250"));
    let bad = "Subject: smuggled\r\n\r\nline\n.\nMAIL FROM:<x@y>\r\n";
    c.send_raw(format!("BDAT {} LAST\r\n{bad}", bad.len()).as_bytes()).await;
    assert!(c.read_reply().await.starts_with("554 5.6.0"));
    assert_eq!(env.inbox(&bob).await.len(), 1);

    assert!(c.cmd("MAIL FROM:<alice@remote.example>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<bob@example.org>").await.starts_with("250"));
    let dotted = "Subject: dots\r\n\r\n.\r\n..leading\r\n";
    c.send_raw(format!("BDAT {} LAST\r\n{dotted}", dotted.len()).as_bytes()).await;
    assert!(c.read_reply().await.starts_with("250"));
    assert!(env.inbox(&bob).await[1].ends_with("\r\n.\r\n..leading\r\n"));

    // A syntax error leaves the stream unreadable: the connection is closed.
    c.send_raw(b"BDAT lots\r\n").await;
    assert!(c.read_reply().await.starts_with("501"));
    assert!(c.is_closed().await);
}

#[tokio::test]
async fn unauthenticated_senders_cannot_turn_notices_into_backscatter() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account_with("tiny@example.org", unomail::auth::Role::User, Some(10)).await;

    // A remote client names a third party as its return path and asks for the full message
    // back on success: nothing is sent there (SPF could not vouch for the sender).
    let mut mx = Client::smtp(env.mx).await;
    let spam = message("victim@remote.example", "bob@example.org", "Cheap watches", "BUY NOW at evil.example");
    let reply = send_with(&mut mx, "MAIL FROM:<victim@remote.example> RET=FULL", &["RCPT TO:<bob@example.org> NOTIFY=SUCCESS"], &spam).await;
    assert!(reply.starts_with("250"), "{reply}");
    queue::process_due(&env.app).await;
    assert!(sink.received().is_empty(), "no notice to the claimed sender: {:?}", sink.received());

    // A failure notice (mailbox full) goes out, but with the headers only.
    let reply = send_with(&mut mx, "MAIL FROM:<victim@remote.example> RET=FULL", &["RCPT TO:<tiny@example.org> NOTIFY=FAILURE"], &spam).await;
    assert!(reply.starts_with("250") || reply.starts_with("452"), "{reply}");
    queue::process_due(&env.app).await;
    for notice in sink.received() {
        assert!(!notice.data.contains("BUY NOW"), "the message body is not reflected: {}", notice.data);
    }
}
