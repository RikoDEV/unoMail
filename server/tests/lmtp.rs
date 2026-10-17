//! LMTP (RFC 2033): delivery handed over by a front mail server, one reply per recipient.

mod common;

use common::{Client, TestEnv, message};
use tokio::net::TcpListener;
use unomail::smtp::server::{self, Mode};

#[tokio::test]
async fn each_recipient_gets_its_own_reply() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    env.account_with("tiny@example.org", unomail::auth::Role::User, Some(10)).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server::serve(env.app.clone(), Mode::Lmtp, listener));

    let mut c = Client::connect(addr).await;
    assert!(c.read_reply().await.starts_with("220 mail.test.example LMTP"));
    assert!(c.cmd("EHLO front.example.net").await.starts_with("500"), "LMTP greets with LHLO");
    let lhlo = c.cmd("LHLO front.example.net").await;
    assert!(lhlo.starts_with("250") && !lhlo.contains("AUTH"), "{lhlo}");
    assert!(c.cmd("MAIL FROM:<alice@remote.example>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<bob@example.org>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<tiny@example.org>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<someone@elsewhere.example>").await.starts_with("554"), "no relaying");
    assert!(c.cmd("DATA").await.starts_with("354"));
    c.send_raw(message("alice@remote.example", "bob@example.org", "Via LMTP", "handed over").as_bytes()).await;
    c.send_raw(b".\r\n").await;
    assert!(c.read_reply().await.starts_with("250"), "bob");
    assert!(c.read_reply().await.starts_with("452"), "tiny is over quota");
    assert!(env.inbox(&bob).await[0].contains("Subject: Via LMTP"));
    assert!(c.cmd("QUIT").await.starts_with("221"));
}
