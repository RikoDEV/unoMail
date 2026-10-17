//! IMAP extensions: QUOTA, ESEARCH, SORT, THREAD, LIST-STATUS and COMPRESS=DEFLATE.

mod common;

use common::{Client, PASSWORD, TestEnv, message};
use tokio::net::TcpListener;
use unomail::imap;

async fn setup() -> (TestEnv, std::net::SocketAddr) {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account_with("bob@example.org", unomail::auth::Role::User, Some(10 * 1024 * 1024)).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(imap::serve(env.app.clone(), listener));
    (env, addr)
}

async fn deliver(env: &TestEnv, from: &str, subject: &str, body: &str) {
    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail(from, &["bob@example.org"], &message(from, "bob@example.org", subject, body)).await.starts_with("250"));
}

async fn cmd(c: &mut Client, tag: &str, command: &str) -> String {
    c.send_raw(format!("{tag} {command}\r\n").as_bytes()).await;
    let mut out = String::new();
    loop {
        let line = c.read_line().await.expect("connection closed");
        out.push_str(&line);
        out.push('\n');
        if line.starts_with(&format!("{tag} ")) {
            return out;
        }
    }
}

async fn login(addr: std::net::SocketAddr) -> Client {
    let mut c = Client::connect_tls(addr).await;
    let greeting = c.read_line().await.unwrap();
    for capability in ["QUOTA", "SORT", "THREAD=REFERENCES", "ESEARCH", "LIST-STATUS", "COMPRESS=DEFLATE"] {
        assert!(greeting.contains(capability), "{capability} missing: {greeting}");
    }
    assert!(cmd(&mut c, "l", &format!("LOGIN bob@example.org \"{PASSWORD}\"")).await.contains("l OK"));
    c
}

#[tokio::test]
async fn quota_search_sort_thread_and_list_status() {
    let (env, addr) = setup().await;
    deliver(&env, "carol@remote.example", "Budget", "numbers").await;
    deliver(&env, "alice@remote.example", "Re: Budget", "more numbers, a longer message body here").await;
    deliver(&env, "dave@remote.example", "Holidays", "beach").await;
    let mut c = login(addr).await;

    let quota = cmd(&mut c, "q1", "GETQUOTAROOT INBOX").await;
    assert!(quota.contains("* QUOTAROOT \"INBOX\" \"\"") || quota.contains("* QUOTAROOT INBOX \"\""), "{quota}");
    assert!(quota.contains("(STORAGE ") && quota.contains(" 10240)"), "{quota}");
    assert!(cmd(&mut c, "q2", "GETQUOTA \"\"").await.contains("* QUOTA \"\" (STORAGE "));
    assert!(cmd(&mut c, "q3", "SETQUOTA \"\" (STORAGE 1)").await.contains("q3 NO"));

    let list = cmd(&mut c, "l1", "LIST \"\" \"*\" RETURN (STATUS (MESSAGES UNSEEN))").await;
    assert!(list.contains("* STATUS \"INBOX\" (MESSAGES 3 UNSEEN 3)") || list.contains("* STATUS INBOX (MESSAGES 3 UNSEEN 3)"), "{list}");
    assert!(list.contains("(MESSAGES 0 UNSEEN 0)"), "other mailboxes too: {list}");

    assert!(cmd(&mut c, "s", "SELECT INBOX").await.contains("s OK"));
    let esearch = cmd(&mut c, "e1", "SEARCH RETURN (MIN MAX COUNT ALL) ALL").await;
    assert!(esearch.contains("* ESEARCH (TAG \"e1\") MIN 1 MAX 3 COUNT 3 ALL 1:3"), "{esearch}");
    let esearch = cmd(&mut c, "e2", "UID SEARCH RETURN (COUNT) SUBJECT budget").await;
    assert!(esearch.contains("* ESEARCH (TAG \"e2\") UID COUNT 2"), "{esearch}");
    assert!(cmd(&mut c, "e3", "SEARCH RETURN () SUBJECT nothing-like-this").await.contains("* ESEARCH (TAG \"e3\")\n"));

    assert!(cmd(&mut c, "o1", "SORT (FROM) UTF-8 ALL").await.contains("* SORT 2 1 3"), "alice, carol, dave");
    assert!(cmd(&mut c, "o2", "SORT (REVERSE SIZE) UTF-8 ALL").await.contains("* SORT 2 "));
    assert!(cmd(&mut c, "o3", "SORT (SUBJECT ARRIVAL) UTF-8 ALL").await.contains("* SORT 1 2 3"), "budget twice, then holidays");
    assert!(cmd(&mut c, "o4", "SORT (SUBJECT) KOI8-R ALL").await.contains("BADCHARSET"));

    let thread = cmd(&mut c, "t1", "THREAD ORDEREDSUBJECT UTF-8 ALL").await;
    assert!(thread.contains("* THREAD (1 2)(3)"), "{thread}");
    assert!(cmd(&mut c, "t2", "THREAD REFERENCES UTF-8 ALL").await.contains("* THREAD "));
}

#[tokio::test]
async fn sessions_can_be_compressed() {
    let (env, addr) = setup().await;
    deliver(&env, "carol@remote.example", "Squeezed", "hello").await;
    let mut c = login(addr).await;
    assert!(cmd(&mut c, "z", "COMPRESS DEFLATE").await.contains("z OK"));

    let mut compress = flate2::Compress::new(flate2::Compression::default(), false);
    let mut inflate = flate2::Decompress::new(false);
    let mut send = |text: &str| {
        let mut out = Vec::with_capacity(text.len() + 64);
        compress.compress_vec(text.as_bytes(), &mut out, flate2::FlushCompress::Sync).unwrap();
        out
    };
    c.send_raw(&send("a SELECT INBOX\r\nb FETCH 1 (BODY[HEADER.FIELDS (SUBJECT)])\r\nc COMPRESS DEFLATE\r\n")).await;
    let mut text = String::new();
    while !text.contains("c NO") {
        let data = c.read_raw().await;
        let mut out = Vec::with_capacity(64 * 1024);
        inflate.decompress_vec(&data, &mut out, flate2::FlushDecompress::Sync).unwrap();
        text.push_str(&String::from_utf8_lossy(&out));
    }
    assert!(text.contains("a OK") && text.contains("Subject: Squeezed"), "{text}");
    assert!(text.contains("c NO [COMPRESSIONACTIVE]"), "{text}");
}

#[tokio::test]
async fn imap4rev2_names_searches_status_and_binary() {
    let (env, addr) = setup().await;
    let raw = "From: carol@remote.example\r\nTo: bob@example.org\r\nSubject: Report\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8gYmluYXJ5\r\n--b--\r\n";
    let mut smtp = Client::smtp(env.mx).await;
    assert!(smtp.send_mail("carol@remote.example", &["bob@example.org"], raw).await.starts_with("250"));
    let mut c = login(addr).await;
    assert!(cmd(&mut c, "c", "CAPABILITY").await.contains("IMAP4rev2"));
    assert!(cmd(&mut c, "e", "ENABLE IMAP4rev2").await.contains("* ENABLED IMAP4rev2"));

    // Mailbox names are UTF-8 now, not modified UTF-7.
    assert!(cmd(&mut c, "m", "CREATE \"Sprawy różne\"").await.contains("m OK"));
    let list = cmd(&mut c, "l", "LIST \"\" \"Spr*\"").await;
    // Quoted or as a literal; either way UTF-8, not "&AXM-".
    assert!(list.contains("Sprawy różne") && !list.contains("&"), "{list}");
    let subscribed = cmd(&mut c, "ls", "LIST (SUBSCRIBED) \"\" \"INBOX\"").await;
    assert!(subscribed.contains("* LIST (") && subscribed.contains("\\Subscribed"), "{subscribed}");

    let status = cmd(&mut c, "st", "STATUS INBOX (MESSAGES SIZE DELETED)").await;
    assert!(status.contains("MESSAGES 1") && status.contains("DELETED 0") && status.contains("SIZE "), "{status}");

    let select = cmd(&mut c, "s", "SELECT INBOX").await;
    assert!(!select.contains("RECENT"), "{select}");
    assert!(select.contains("* LIST () \"/\" \"INBOX\"") || select.contains("* LIST () \"/\" INBOX"), "{select}");
    let reselect = cmd(&mut c, "s2", "EXAMINE INBOX").await;
    assert!(reselect.contains("* OK [CLOSED]"), "{reselect}");

    let search = cmd(&mut c, "f", "SEARCH ALL").await;
    assert!(search.contains("* ESEARCH (TAG \"f\") ALL 1"), "{search}");

    let binary = cmd(&mut c, "b", "FETCH 1 (BINARY.SIZE[2] BINARY.PEEK[2])").await;
    assert!(binary.contains("BINARY.SIZE[2] 12"), "{binary}");
    assert!(binary.contains("BINARY[2] ~{12}") && binary.contains("hello binary"), "{binary}");
    assert!(cmd(&mut c, "b2", "FETCH 1 BINARY[1.HEADER]").await.contains("b2 BAD"));

    // literal8 is accepted where a literal is.
    c.send_raw(b"a APPEND INBOX ~{20+}\r\nSubject: x\r\n\r\nbody\r\n\r\n").await;
    let mut appended = String::new();
    while let Some(line) = c.read_line().await {
        appended.push_str(&line);
        if line.starts_with("a ") {
            break;
        }
    }
    assert!(appended.contains("a OK"), "{appended}");
}
