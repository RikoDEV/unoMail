//! ManageSieve (RFC 5804): managing filter scripts from mail programs.

mod common;

use base64::Engine;
use common::{Client, PASSWORD, TestEnv, message};
use tokio::net::TcpListener;

/// Reads lines up to and including the final OK / NO / BYE.
async fn response(c: &mut Client) -> String {
    let mut out = String::new();
    loop {
        let line = c.read_line().await.expect("connection closed");
        out.push_str(&line);
        out.push('\n');
        if line.starts_with("OK") || line.starts_with("NO") || line.starts_with("BYE") {
            return out;
        }
    }
}

async fn cmd(c: &mut Client, command: &str) -> String {
    c.send_raw(format!("{command}\r\n").as_bytes()).await;
    response(c).await
}

#[tokio::test]
async fn scripts_are_managed_over_managesieve() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(unomail::managesieve::serve(env.app.clone(), listener));

    let mut c = Client::connect(addr).await;
    let greeting = response(&mut c).await;
    assert!(greeting.contains("\"STARTTLS\"") && greeting.contains("\"SASL\" \"\"") && greeting.contains("fileinto"), "{greeting}");
    assert!(greeting.contains("\"MAXREDIRECTS\" \"5\""), "scripts may redirect, as many times as the filter allows: {greeting}");
    let token = base64::engine::general_purpose::STANDARD.encode(format!("\0bob@example.org\0{PASSWORD}"));
    assert!(cmd(&mut c, &format!("AUTHENTICATE \"PLAIN\" \"{token}\"")).await.starts_with("NO (ENCRYPT-NEEDED)"));
    assert!(cmd(&mut c, "LISTSCRIPTS").await.starts_with("NO"));

    assert!(cmd(&mut c, "STARTTLS").await.starts_with("OK"));
    c.upgrade().await;
    let after = response(&mut c).await;
    assert!(after.contains("\"SASL\" \"PLAIN\"") && !after.contains("STARTTLS"), "{after}");
    let wrong = base64::engine::general_purpose::STANDARD.encode("\0bob@example.org\0nope");
    assert!(cmd(&mut c, &format!("AUTHENTICATE \"PLAIN\" \"{wrong}\"")).await.starts_with("NO"));
    assert!(cmd(&mut c, &format!("AUTHENTICATE \"PLAIN\" \"{token}\"")).await.starts_with("OK"));

    let script = "require [\"fileinto\", \"mailbox\"];\r\nif header :contains \"subject\" \"invoice\" {\r\n  fileinto :create \"Bills\";\r\n}\r\n";
    assert!(cmd(&mut c, "HAVESPACE \"bills\" 500").await.starts_with("OK"));
    assert!(cmd(&mut c, "HAVESPACE \"bills\" 999999999").await.starts_with("NO (QUOTA/MAXSIZE)"));
    let broken = "if header :contains \"subject\" {\r\n";
    let refused = cmd(&mut c, &format!("CHECKSCRIPT {{{}+}}\r\n{broken}", broken.len())).await;
    assert!(refused.starts_with("NO") && refused.contains("line"), "{refused}");
    assert!(cmd(&mut c, &format!("PUTSCRIPT \"bills\" {{{}+}}\r\n{script}", script.len())).await.starts_with("OK"));
    assert_eq!(cmd(&mut c, "LISTSCRIPTS").await, "\"bills\"\nOK \"LISTSCRIPTS completed\"\n");
    assert!(cmd(&mut c, "SETACTIVE \"missing\"").await.starts_with("NO (NONEXISTENT)"));
    assert!(cmd(&mut c, "SETACTIVE \"bills\"").await.starts_with("OK"));
    assert!(cmd(&mut c, "LISTSCRIPTS").await.starts_with("\"bills\" ACTIVE\n"));
    let fetched = cmd(&mut c, "GETSCRIPT \"bills\"").await;
    assert!(fetched.starts_with(&format!("{{{}}}\n", script.len())) && fetched.contains("fileinto :create \"Bills\""), "{fetched}");

    // The active script files incoming mail.
    let mut smtp = Client::smtp(env.mx).await;
    let msg = message("shop@remote.example", "bob@example.org", "Your invoice", "pay");
    assert!(smtp.send_mail("shop@remote.example", &["bob@example.org"], &msg).await.starts_with("250"));
    let bills = env.app.store.mailbox_by_name(bob.id, "Bills").await.unwrap().expect("created by the script");
    assert_eq!(env.app.store.messages_in(bills.id).await.unwrap().len(), 1);

    assert!(cmd(&mut c, "DELETESCRIPT \"bills\"").await.starts_with("NO (ACTIVE)"));
    assert!(cmd(&mut c, "RENAMESCRIPT \"bills\" \"invoices\"").await.starts_with("OK"));
    assert!(cmd(&mut c, "SETACTIVE \"\"").await.starts_with("OK"));
    assert!(cmd(&mut c, "DELETESCRIPT \"invoices\"").await.starts_with("OK"));
    assert_eq!(cmd(&mut c, "LISTSCRIPTS").await, "OK \"LISTSCRIPTS completed\"\n");
    assert!(cmd(&mut c, "LOGOUT").await.starts_with("OK"));
    assert!(c.is_closed().await);
}
