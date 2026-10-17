//! IMAP CONDSTORE, QRESYNC and international mailbox names.

mod common;

use common::{Client, PASSWORD, TestEnv, message};
use tokio::net::TcpListener;
use unomail::imap;

async fn setup() -> (TestEnv, std::net::SocketAddr) {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(imap::serve(env.app.clone(), listener));
    (env, addr)
}

async fn deliver(env: &TestEnv, subject: &str) {
    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail("alice@remote.example", &["bob@example.org"], &message("alice@remote.example", "bob@example.org", subject, "x")).await.starts_with("250"));
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
    assert!(c.read_line().await.unwrap().contains("CONDSTORE QRESYNC"));
    assert!(cmd(&mut c, "l", &format!("LOGIN bob@example.org \"{PASSWORD}\"")).await.contains("l OK"));
    c
}

fn value_after(text: &str, marker: &str) -> i64 {
    let rest = &text[text.find(marker).unwrap_or_else(|| panic!("{marker} not in {text}")) + marker.len()..];
    rest.chars().take_while(char::is_ascii_digit).collect::<String>().parse().unwrap()
}

#[tokio::test]
async fn condstore_tracks_modification_sequences() {
    let (env, addr) = setup().await;
    deliver(&env, "One").await;
    deliver(&env, "Two").await;
    let mut c = login(addr).await;

    let select = cmd(&mut c, "a1", "SELECT INBOX (CONDSTORE)").await;
    let base = value_after(&select, "[HIGHESTMODSEQ ");
    assert!(base >= 2, "{select}");
    assert!(cmd(&mut c, "a2", "STATUS INBOX (HIGHESTMODSEQ)").await.contains(&format!("(HIGHESTMODSEQ {base})")));
    let fetch = cmd(&mut c, "a3", "FETCH 1:2 (UID MODSEQ)").await;
    assert!(fetch.contains("* 1 FETCH (UID 1 MODSEQ (") && fetch.contains("* 2 FETCH (UID 2 MODSEQ ("), "{fetch}");
    assert!(cmd(&mut c, "a4", &format!("FETCH 1:* (FLAGS) (CHANGEDSINCE {base})")).await.trim().starts_with("a4 OK"), "nothing changed yet");

    // A flag change bumps the mod-sequence and is visible to CHANGEDSINCE and SEARCH MODSEQ.
    let store = cmd(&mut c, "b1", "STORE 2 +FLAGS (\\Flagged)").await;
    let after = value_after(&store, "MODSEQ (");
    assert!(after > base, "{store}");
    let changed = cmd(&mut c, "b2", &format!("UID FETCH 1:* (FLAGS) (CHANGEDSINCE {base})")).await;
    assert!(changed.contains("* 2 FETCH (UID 2 FLAGS (\\Flagged) MODSEQ (") && !changed.contains("* 1 FETCH"), "{changed}");
    let search = cmd(&mut c, "b3", &format!("SEARCH MODSEQ {after}")).await;
    assert!(search.contains(&format!("* SEARCH 2 (MODSEQ {after})")), "{search}");

    // Conditional STORE refuses to overwrite a change the client has not seen.
    let conflict = cmd(&mut c, "c1", &format!("STORE 1:2 (UNCHANGEDSINCE {base}) +FLAGS (\\Seen)")).await;
    assert!(conflict.contains("c1 OK [MODIFIED 2]"), "{conflict}");
    assert!(conflict.contains("* 1 FETCH (FLAGS (\\Seen) MODSEQ ("), "{conflict}");
    let flags = cmd(&mut c, "c2", "FETCH 2 (FLAGS)").await;
    assert!(flags.contains("FLAGS (\\Flagged)") && !flags.contains("\\Seen"), "{flags}");
    assert!(cmd(&mut c, "c3", "UID STORE 2 (UNCHANGEDSINCE 999999) +FLAGS.SILENT (\\Seen)").await.contains("c3 OK UID STORE completed"));
    assert!(cmd(&mut c, "c4", "STORE 1 (BOGUS 1) +FLAGS (\\Seen)").await.contains("c4 BAD"));
    assert!(cmd(&mut c, "c5", "FETCH 1 (FLAGS) (CHANGEDSINCE x)").await.contains("c5 BAD"));
}

#[tokio::test]
async fn qresync_resynchronizes_a_reconnecting_client() {
    let (env, addr) = setup().await;
    for subject in ["One", "Two", "Three"] {
        deliver(&env, subject).await;
    }
    let mut c = login(addr).await;
    let select = cmd(&mut c, "a1", "SELECT INBOX").await;
    let (validity, cached) = (value_after(&select, "[UIDVALIDITY "), value_after(&select, "[HIGHESTMODSEQ "));
    assert!(cmd(&mut c, "a2", "SELECT INBOX (QRESYNC (1 1))").await.contains("a2 BAD"), "must be enabled first");
    cmd(&mut c, "a3", "LOGOUT").await;

    // While the client is offline: one message is deleted, one flagged, one arrives.
    let mut other = login(addr).await;
    cmd(&mut other, "b1", "SELECT INBOX").await;
    cmd(&mut other, "b2", "STORE 1 +FLAGS (\\Deleted)").await;
    cmd(&mut other, "b3", "EXPUNGE").await;
    cmd(&mut other, "b4", "STORE 1 +FLAGS (\\Flagged)").await;
    deliver(&env, "Four").await;

    let mut c = login(addr).await;
    assert!(cmd(&mut c, "c1", "ENABLE QRESYNC").await.contains("* ENABLED QRESYNC"));
    let resync = cmd(&mut c, "c2", &format!("SELECT INBOX (QRESYNC ({validity} {cached}))")).await;
    assert!(resync.contains("* 3 EXISTS"), "{resync}");
    assert!(resync.contains("* VANISHED (EARLIER) 1"), "{resync}");
    assert!(resync.contains("* 1 FETCH (UID 2 FLAGS (\\Flagged) MODSEQ ("), "{resync}");
    assert!(resync.contains("* 3 FETCH (UID 4 FLAGS () MODSEQ ("), "{resync}");
    assert!(!resync.contains("FETCH (UID 3 "), "unchanged messages are not resent: {resync}");
    // A stale UIDVALIDITY means the cache is useless: no incremental data is sent.
    let stale = cmd(&mut c, "c3", &format!("SELECT INBOX (QRESYNC ({} {cached}))", validity + 1)).await;
    assert!(!stale.contains("VANISHED") && !stale.contains("FETCH"), "{stale}");
    let known = cmd(&mut c, "c4", &format!("SELECT INBOX (QRESYNC ({validity} {cached} 2:3))")).await;
    assert!(!known.contains("VANISHED") && known.contains("UID 2") && !known.contains("UID 4"), "known-uids restricts the report: {known}");

    // With QRESYNC enabled, live expunges arrive as VANISHED, and UID FETCH can ask for them.
    cmd(&mut other, "d1", "STORE 2 +FLAGS (\\Deleted)").await;
    cmd(&mut other, "d2", "EXPUNGE").await;
    let noop = cmd(&mut c, "d3", "NOOP").await;
    assert!(noop.contains("* VANISHED 3") && !noop.contains("EXPUNGE"), "{noop}");
    let vanished = cmd(&mut c, "d4", &format!("UID FETCH 1:* (FLAGS) (CHANGEDSINCE {cached} VANISHED)")).await;
    assert!(vanished.contains("* VANISHED (EARLIER) 1,3"), "{vanished}");
    assert!(cmd(&mut c, "d5", "UID FETCH 1:* (FLAGS) (VANISHED)").await.contains("d5 BAD"));
}

#[tokio::test]
async fn mailbox_names_use_modified_utf7_on_the_wire() {
    let (env, addr) = setup().await;
    let mut c = login(addr).await;
    assert!(cmd(&mut c, "a1", "CREATE \"Entw&APw-rfe/R&-D\"").await.contains("a1 OK"));
    let account: i64 = sqlx::query_scalar("SELECT id FROM accounts WHERE email = 'bob@example.org'").fetch_one(&env.app.db).await.unwrap();
    assert!(env.app.store.mailbox_by_name(account, "Entwürfe/R&D").await.unwrap().is_some(), "stored as UTF-8");

    let list = cmd(&mut c, "a2", "LIST \"\" \"Entw*\"").await;
    assert!(list.contains("\"Entw&APw-rfe/R&-D\""), "{list}");
    assert!(cmd(&mut c, "a3", "SELECT \"Entw&APw-rfe/R&-D\"").await.contains("a3 OK"));
    assert!(cmd(&mut c, "a4", "STATUS \"Entw&APw-rfe/R&-D\" (MESSAGES)").await.contains("* STATUS \"Entw&APw-rfe/R&-D\" (MESSAGES 0)"));
    assert!(cmd(&mut c, "a5", "RENAME \"Entw&APw-rfe/R&-D\" \"&ZeVnLIqe-\"").await.contains("a5 OK"));
    assert!(env.app.store.mailbox_by_name(account, "日本語").await.unwrap().is_some());
    assert!(cmd(&mut c, "a6", "DELETE \"&ZeVnLIqe-\"").await.contains("a6 OK"));
}

#[tokio::test]
async fn search_reads_the_index_and_other_sessions_follow_changes() {
    let (env, addr) = setup().await;
    // The body is base64-encoded: matching the raw bytes would never find its words.
    let encoded = "From: Alice <alice@remote.example>\r\nTo: bob@example.org\r\nSubject: Quarterly plan\r\nMessage-ID: <plan-1@remote.example>\r\n\
MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\nVGhlIHNlY3JldCBidWRnZXQgaXMgcmVhZHku\r\n";
    let mut smtp = Client::smtp(env.mx).await;
    assert!(smtp.send_mail("alice@remote.example", &["bob@example.org"], encoded).await.starts_with("250"));
    deliver(&env, "Lunch").await;

    let mut a = login(addr).await;
    assert!(cmd(&mut a, "s0", "SELECT INBOX").await.contains("* 2 EXISTS"));
    assert!(cmd(&mut a, "s1", "SEARCH BODY \"secret budget\"").await.contains("* SEARCH 1\n"), "decoded body text");
    assert!(cmd(&mut a, "s2", "SEARCH TEXT quarterly").await.contains("* SEARCH 1\n"), "subject counts for TEXT");
    assert!(cmd(&mut a, "s3", "SEARCH BODY quarterly").await.contains("* SEARCH\n"), "but not for BODY");
    assert!(cmd(&mut a, "s4", "SEARCH FROM alice SUBJECT plan").await.contains("* SEARCH 1\n"));
    assert!(cmd(&mut a, "s5", "SEARCH NOT BODY secret").await.contains("* SEARCH 2\n"));
    assert!(cmd(&mut a, "s6", "SEARCH HEADER Message-ID plan-1@remote.example").await.contains("* SEARCH 1\n"), "headers the index lacks come from the file");
    assert!(cmd(&mut a, "s7", "SEARCH OR SUBJECT lunch BODY secret").await.contains("* SEARCH 1 2\n"));

    // Another session's changes reach this one, and nothing is repeated once reported.
    let mut b = login(addr).await;
    cmd(&mut b, "b0", "SELECT INBOX").await;
    assert!(cmd(&mut b, "b1", "STORE 1 +FLAGS (\\Seen)").await.contains("b1 OK"));
    let noop = cmd(&mut a, "n1", "NOOP").await;
    assert!(noop.contains("* 1 FETCH (FLAGS (\\Seen) UID 1)"), "{noop}");
    deliver(&env, "Third").await;
    let noop = cmd(&mut a, "n2", "NOOP").await;
    assert!(noop.contains("* 3 EXISTS") && !noop.contains("FETCH"), "{noop}");
    assert!(cmd(&mut b, "b2", "STORE 2 +FLAGS (\\Deleted)").await.contains("b2 OK"));
    assert!(cmd(&mut b, "b3", "EXPUNGE").await.contains("b3 OK"));
    let noop = cmd(&mut a, "n3", "NOOP").await;
    assert!(noop.contains("* 2 EXPUNGE") && !noop.contains("EXISTS"), "{noop}");
    assert_eq!(cmd(&mut a, "n4", "NOOP").await.lines().count(), 1, "nothing new to report");
    assert!(cmd(&mut a, "s8", "SEARCH ALL").await.contains("* SEARCH 1 2\n"));
}
