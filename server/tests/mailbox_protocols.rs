//! IMAP and POP3 tests against a running server.

mod common;

use common::{Client, PASSWORD, TestEnv, message};
use tokio::net::TcpListener;
use unomail::{auth::Account, imap, pop3};

struct Servers {
    env: TestEnv,
    imap: std::net::SocketAddr,
    pop3: std::net::SocketAddr,
    bob: Account,
}

async fn setup() -> Servers {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let imap_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pop3_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (imap, pop3) = (imap_listener.local_addr().unwrap(), pop3_listener.local_addr().unwrap());
    tokio::spawn(imap::serve(env.app.clone(), imap_listener));
    tokio::spawn(pop3::serve(env.app.clone(), pop3_listener));
    Servers { env, imap, pop3, bob }
}

async fn deliver(env: &TestEnv, to: &str, subject: &str, body: &str) {
    let mut c = Client::smtp(env.mx).await;
    let reply = c.send_mail("alice@remote.example", &[to], &message("Alice <alice@remote.example>", to, subject, body)).await;
    assert!(reply.starts_with("250"), "{reply}");
}

/// Sends a tagged IMAP command and returns everything up to and including the tagged reply.
async fn imap_cmd(c: &mut Client, tag: &str, command: &str) -> String {
    c.send_raw(format!("{tag} {command}\r\n").as_bytes()).await;
    imap_until(c, tag).await
}

async fn imap_until(c: &mut Client, tag: &str) -> String {
    let mut out = String::new();
    loop {
        let line = c.read_line().await.expect("connection closed while waiting for the tagged reply");
        out.push_str(&line);
        out.push('\n');
        if line.starts_with(&format!("{tag} ")) {
            return out;
        }
    }
}

async fn imap_login(servers: &Servers, user: &str) -> Client {
    let mut c = Client::connect_tls(servers.imap).await;
    let greeting = c.read_line().await.unwrap();
    assert!(greeting.starts_with("* OK [CAPABILITY IMAP4rev1"), "{greeting}");
    let reply = imap_cmd(&mut c, "a0", &format!("LOGIN {user} \"{PASSWORD}\"")).await;
    assert!(reply.contains("a0 OK"), "{reply}");
    c
}

#[tokio::test]
async fn imap_requires_authentication_and_limits_guessing() {
    let s = setup().await;
    let mut c = Client::connect_tls(s.imap).await;
    c.read_line().await.unwrap();
    assert!(imap_cmd(&mut c, "a1", "SELECT INBOX").await.contains("a1 BAD authenticate first"));
    assert!(imap_cmd(&mut c, "a2", "LIST \"\" *").await.contains("a2 BAD"));
    assert!(imap_cmd(&mut c, "a3", "CAPABILITY").await.contains("* CAPABILITY IMAP4rev1"));
    assert!(imap_cmd(&mut c, "a4", "AUTHENTICATE CRAM-MD5").await.contains("a4 NO"));
    for tag in ["b1", "b2"] {
        assert!(imap_cmd(&mut c, tag, "LOGIN bob@example.org wrong-password").await.contains("NO [AUTHENTICATIONFAILED]"));
    }
    assert!(imap_cmd(&mut c, "b3", "LOGIN nobody@example.org whatever").await.contains("b3 NO [AUTHENTICATIONFAILED]"));
    assert!(c.is_closed().await, "the connection is dropped after repeated failures");

    // SASL PLAIN with an initial response, and per-mailbox protocol toggle.
    use base64::Engine;
    let token = base64::engine::general_purpose::STANDARD.encode(format!("\0bob@example.org\0{PASSWORD}"));
    let mut c = Client::connect_tls(s.imap).await;
    c.read_line().await.unwrap();
    assert!(imap_cmd(&mut c, "c1", &format!("AUTHENTICATE PLAIN {token}")).await.contains("c1 OK"));
    assert!(imap_cmd(&mut c, "c2", "LOGIN bob@example.org x").await.contains("c2 BAD already authenticated"));
    assert!(imap_cmd(&mut c, "c3", "LOGOUT").await.contains("* BYE"));

    sqlx::query("UPDATE accounts SET imap_enabled = 0 WHERE id = ?").bind(s.bob.id).execute(&s.env.app.db).await.unwrap();
    let mut c = Client::connect_tls(s.imap).await;
    c.read_line().await.unwrap();
    assert!(imap_cmd(&mut c, "d1", &format!("LOGIN bob@example.org \"{PASSWORD}\"")).await.contains("d1 NO"), "IMAP access disabled for the mailbox");
}

#[tokio::test]
async fn imap_listing_fetching_flags_and_search() {
    let s = setup().await;
    deliver(&s.env, "bob@example.org", "First message", "alpha body").await;
    deliver(&s.env, "bob@example.org", "Second message", "beta body with keyword").await;
    let mut c = imap_login(&s, "bob@example.org").await;

    let list = imap_cmd(&mut c, "a1", "LIST \"\" \"*\"").await;
    for expected in ["\"INBOX\"", "(\\HasNoChildren \\Sent) \"/\" \"Sent\"", "\\Trash", "\\Junk", "\\Drafts", "\\Archive"] {
        assert!(list.contains(expected), "{expected} missing in {list}");
    }
    assert!(imap_cmd(&mut c, "a2", "LIST \"\" \"\"").await.contains("* LIST (\\Noselect) \"/\" \"\""));
    assert!(imap_cmd(&mut c, "a3", "STATUS INBOX (MESSAGES UNSEEN UIDNEXT)").await.contains("* STATUS \"INBOX\" (MESSAGES 2 UNSEEN 2 UIDNEXT 3)"));

    let select = imap_cmd(&mut c, "a4", "SELECT inbox").await;
    assert!(select.contains("* 2 EXISTS") && select.contains("[UIDVALIDITY ") && select.contains("[UNSEEN 1]") && select.contains("a4 OK [READ-WRITE]"), "{select}");

    let fetch = imap_cmd(&mut c, "a5", "FETCH 1:* (UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE BODYSTRUCTURE)").await;
    assert!(fetch.contains("* 1 FETCH (UID 1 ") && fetch.contains("* 2 FETCH (UID 2 "), "{fetch}");
    assert!(fetch.contains("\"First message\" ((\"Alice\" NIL \"alice\" \"remote.example\"))"), "{fetch}");
    assert!(fetch.contains("BODYSTRUCTURE (\"TEXT\" \"PLAIN\""), "{fetch}");
    assert!(fetch.contains("FLAGS ()"), "{fetch}");

    // PEEK leaves the message unread; a plain BODY[] fetch marks it as seen.
    let peek = imap_cmd(&mut c, "a6", "UID FETCH 1 (BODY.PEEK[HEADER.FIELDS (Subject)])").await;
    assert!(peek.contains("BODY[HEADER.FIELDS (SUBJECT)] {26}") && peek.contains("Subject: First message") && !peek.contains("\\Seen"), "{peek}");
    let body = imap_cmd(&mut c, "a7", "FETCH 1 BODY[TEXT]").await;
    assert!(body.contains("alpha body") && body.contains("FLAGS (\\Seen)"), "{body}");
    let partial = imap_cmd(&mut c, "a8", "FETCH 2 BODY.PEEK[TEXT]<0.4>").await;
    assert!(partial.contains("BODY[TEXT]<0> {4}") && partial.contains("beta"), "{partial}");

    assert!(imap_cmd(&mut c, "b1", "SEARCH UNSEEN").await.contains("* SEARCH 2\n"));
    assert!(imap_cmd(&mut c, "b2", "SEARCH SUBJECT \"first\"").await.contains("* SEARCH 1\n"));
    assert!(imap_cmd(&mut c, "b3", "UID SEARCH BODY keyword").await.contains("* SEARCH 2\n"));
    assert!(imap_cmd(&mut c, "b4", "SEARCH OR SUBJECT first SUBJECT second").await.contains("* SEARCH 1 2\n"));
    assert!(imap_cmd(&mut c, "b5", "SEARCH NOT FROM alice").await.contains("* SEARCH\n"));
    assert!(imap_cmd(&mut c, "b6", "SEARCH CHARSET UTF-8 ALL").await.contains("* SEARCH 1 2\n"));
    assert!(imap_cmd(&mut c, "b7", "SEARCH CHARSET KOI8-R ALL").await.contains("b7 NO [BADCHARSET"));
    assert!(imap_cmd(&mut c, "b8", "SEARCH BOGUSKEY").await.contains("b8 BAD"));

    let store = imap_cmd(&mut c, "c1", "STORE 2 +FLAGS (\\Flagged work)").await;
    assert!(store.contains("* 2 FETCH (FLAGS (\\Flagged work))"), "{store}");
    assert!(imap_cmd(&mut c, "c2", "SEARCH KEYWORD work").await.contains("* SEARCH 2\n"));
    assert!(imap_cmd(&mut c, "c3", "STORE 2 -FLAGS.SILENT (work)").await.trim().starts_with("c3 OK"));
    assert!(imap_cmd(&mut c, "c4", "STORE 2 +FLAGS (\\Bogus)").await.contains("c4 BAD"));

    // Copy and move with UIDPLUS response codes.
    assert!(imap_cmd(&mut c, "d1", "COPY 1 Archive").await.contains("d1 OK [COPYUID "));
    assert!(imap_cmd(&mut c, "d2", "COPY 1 NoSuchFolder").await.contains("d2 NO [TRYCREATE]"));
    let moved = imap_cmd(&mut c, "d3", "UID MOVE 2 Trash").await;
    assert!(moved.contains("* 2 EXPUNGE") && moved.contains("d3 OK [COPYUID "), "{moved}");
    assert_eq!(s.env.mailbox(&s.bob, "trash").await.len(), 1);
    assert_eq!(s.env.mailbox(&s.bob, "archive").await.len(), 1);

    // Delete + expunge.
    assert!(imap_cmd(&mut c, "e1", "STORE 1 +FLAGS (\\Deleted)").await.contains("\\Deleted"));
    let expunge = imap_cmd(&mut c, "e2", "EXPUNGE").await;
    assert!(expunge.contains("* 1 EXPUNGE") && expunge.contains("e2 OK"), "{expunge}");
    assert!(s.env.inbox(&s.bob).await.is_empty());
    assert!(imap_cmd(&mut c, "e3", "FETCH 1 FLAGS").await.trim().starts_with("e3 OK"), "nothing left to fetch");
    assert!(imap_cmd(&mut c, "e4", "FETCH 1 (BOGUS)").await.contains("e4 BAD"));
    assert!(imap_cmd(&mut c, "e5", "FETCH 1 BODY[9.BOGUS]").await.contains("e5 BAD"));
}

#[tokio::test]
async fn imap_append_folders_and_literals() {
    let s = setup().await;
    let mut c = imap_login(&s, "bob@example.org").await;
    let msg = "From: bob@example.org\r\nSubject: Saved draft\r\n\r\ndraft body\r\n";

    // Synchronizing literal: the server asks for the data.
    c.send_raw(format!("a1 APPEND Drafts (\\Draft \\Seen) \"05-Oct-2026 10:00:00 +0000\" {{{}}}\r\n", msg.len()).as_bytes()).await;
    assert!(c.read_line().await.unwrap().starts_with("+ "));
    c.send_raw(format!("{msg}\r\n").as_bytes()).await;
    assert!(imap_until(&mut c, "a1").await.contains("a1 OK [APPENDUID "));
    // Non-synchronizing literal (LITERAL+).
    c.send_raw(format!("a2 APPEND Drafts {{{}+}}\r\n{msg}\r\n", msg.len()).as_bytes()).await;
    assert!(imap_until(&mut c, "a2").await.contains("a2 OK [APPENDUID "));
    let drafts = s.env.mailbox(&s.bob, "drafts").await;
    assert_eq!(drafts, [msg, msg]);
    let select = imap_cmd(&mut c, "a3", "EXAMINE Drafts").await;
    assert!(select.contains("* 2 EXISTS") && select.contains("a3 OK [READ-ONLY]"), "{select}");
    assert!(imap_cmd(&mut c, "a4", "FETCH 1 (FLAGS INTERNALDATE)").await.contains("FETCH (INTERNALDATE \"05-Oct-2026 10:00:00 +0000\" FLAGS (\\Seen \\Draft))"));
    assert!(imap_cmd(&mut c, "a5", "STORE 1 +FLAGS (\\Deleted)").await.contains("a5 NO"), "read-only mailbox");
    assert!(!imap_cmd(&mut c, "a6", "FETCH 2 BODY[]").await.contains("FLAGS ()"), "EXAMINE never sets \\Seen");

    assert!(imap_cmd(&mut c, "b1", "CREATE \"Work/Reports\"").await.contains("b1 OK"));
    assert!(imap_cmd(&mut c, "b2", "CREATE \"Work/Reports\"").await.contains("b2 NO"));
    assert!(imap_cmd(&mut c, "b3", "CREATE \"bad%name\"").await.contains("b3 NO"));
    assert!(imap_cmd(&mut c, "b4", "RENAME \"Work/Reports\" Reports").await.contains("b4 OK"));
    assert!(imap_cmd(&mut c, "b5", "LIST \"\" \"%\"").await.contains("\"Reports\""));
    assert!(imap_cmd(&mut c, "b6", "DELETE INBOX").await.contains("b6 NO"), "system folders cannot be deleted");
    assert!(imap_cmd(&mut c, "b7", "DELETE Reports").await.contains("b7 OK"));
    assert!(imap_cmd(&mut c, "b8", "UNSUBSCRIBE Junk").await.contains("b8 OK"));
    assert!(!imap_cmd(&mut c, "b9", "LSUB \"\" \"*\"").await.contains("\"Junk\""));

    // A mailbox name sent as a literal cannot smuggle a second command or forge responses.
    let evil = "x\r\nz9 OK forged";
    c.send_raw(format!("c1 CREATE {{{}+}}\r\n{evil}\r\n", evil.len()).as_bytes()).await;
    let reply = imap_until(&mut c, "c1").await;
    assert!(reply.trim() == "c1 NO invalid mailbox name", "{reply}");

    // Oversized literals are refused before any data is read.
    c.send_raw(b"d1 CREATE {99999999}\r\n").await;
    assert!(c.read_line().await.unwrap().starts_with("* BYE"));
    assert!(c.is_closed().await);

    let mut c = imap_login(&s, "bob@example.org").await;
    c.send_raw(b"e1 APPEND Drafts {99999999}\r\n").await;
    assert!(c.read_line().await.unwrap().starts_with("* BYE"), "APPEND is bounded by the message size limit");
    let mut c = imap_login(&s, "bob@example.org").await;
    c.send_raw(b"f1 LOGIN \"unterminated\r\n").await;
    assert_eq!(c.read_line().await.unwrap(), "* BAD invalid command syntax");
}

#[tokio::test]
async fn imap_idle_and_concurrent_sessions() {
    let s = setup().await;
    deliver(&s.env, "bob@example.org", "Existing", "x").await;
    let mut first = imap_login(&s, "bob@example.org").await;
    let mut second = imap_login(&s, "bob@example.org").await;
    assert!(imap_cmd(&mut first, "a1", "SELECT INBOX").await.contains("* 1 EXISTS"));
    assert!(imap_cmd(&mut second, "a1", "SELECT INBOX").await.contains("* 1 EXISTS"));

    // IDLE pushes new mail as it arrives.
    first.send_raw(b"a2 IDLE\r\n").await;
    assert!(first.read_line().await.unwrap().starts_with("+ "));
    deliver(&s.env, "bob@example.org", "Fresh", "y").await;
    assert_eq!(first.read_line().await.unwrap(), "* 2 EXISTS");
    first.send_raw(b"DONE\r\n").await;
    assert!(imap_until(&mut first, "a2").await.contains("a2 OK IDLE completed"));

    // Changes made by one session are reported to the other on its next command.
    assert!(imap_cmd(&mut first, "a3", "STORE 1 +FLAGS (\\Deleted \\Seen)").await.contains("a3 OK"));
    let noop = imap_cmd(&mut second, "a2", "NOOP").await;
    assert!(noop.contains("* 2 EXISTS") && noop.contains("* 1 FETCH (FLAGS (\\Seen \\Deleted) UID 1)"), "{noop}");
    assert!(imap_cmd(&mut first, "a4", "CLOSE").await.contains("a4 OK"), "CLOSE expunges silently");
    let noop = imap_cmd(&mut second, "a3", "NOOP").await;
    assert!(noop.contains("* 1 EXPUNGE"), "{noop}");
    // Sequence numbers were renumbered: message 1 is now the fresh one.
    assert!(imap_cmd(&mut second, "a4", "FETCH 1 (ENVELOPE)").await.contains("\"Fresh\""));
}

#[tokio::test]
async fn imap_accounts_are_isolated() {
    let s = setup().await;
    s.env.account("eve@example.org").await;
    deliver(&s.env, "bob@example.org", "For Bob", "private").await;
    let mut eve = imap_login(&s, "eve@example.org").await;
    assert!(imap_cmd(&mut eve, "a1", "SELECT INBOX").await.contains("* 0 EXISTS"));
    assert!(imap_cmd(&mut eve, "a2", "UID FETCH 1:* (BODY.PEEK[])").await.trim().starts_with("a2 OK"));
    assert!(imap_cmd(&mut eve, "a3", "SEARCH ALL").await.contains("* SEARCH\n"));
    for name in ["../bob@example.org/INBOX", "bob@example.org/INBOX", "#shared/bob", "INBOX/../../x"] {
        assert!(imap_cmd(&mut eve, "a4", &format!("SELECT \"{name}\"")).await.contains("a4 NO"), "{name}");
    }
    assert!(imap_cmd(&mut eve, "a5", "STATUS INBOX (MESSAGES)").await.contains("(MESSAGES 0)"));
}

async fn pop3_cmd(c: &mut Client, command: &str) -> String {
    c.send_raw(format!("{command}\r\n").as_bytes()).await;
    c.read_line().await.unwrap()
}

async fn pop3_multi(c: &mut Client, command: &str) -> Vec<String> {
    c.send_raw(format!("{command}\r\n").as_bytes()).await;
    let mut lines = Vec::new();
    loop {
        let line = c.read_line().await.unwrap();
        if line == "." || (lines.is_empty() && line.starts_with("-ERR")) {
            if line != "." {
                lines.push(line);
            }
            return lines;
        }
        lines.push(line);
    }
}

async fn pop3_login(s: &Servers, user: &str) -> Client {
    let mut c = Client::connect_tls(s.pop3).await;
    assert!(c.read_line().await.unwrap().starts_with("+OK"));
    assert!(pop3_cmd(&mut c, &format!("USER {user}")).await.starts_with("+OK"));
    assert!(pop3_cmd(&mut c, &format!("PASS {PASSWORD}")).await.starts_with("+OK"));
    c
}

#[tokio::test]
async fn pop3_session() {
    let s = setup().await;
    deliver(&s.env, "bob@example.org", "One", "first line\r\n..leading dot\r\nthird line").await;
    deliver(&s.env, "bob@example.org", "Two", "second message").await;

    let mut c = Client::connect_tls(s.pop3).await;
    assert!(c.read_line().await.unwrap().starts_with("+OK mail.test.example POP3"));
    assert!(pop3_cmd(&mut c, "STAT").await.starts_with("-ERR"), "authentication is required");
    assert!(pop3_cmd(&mut c, "PASS x").await.starts_with("-ERR"), "USER must come first");
    assert!(pop3_multi(&mut c, "CAPA").await.contains(&"UIDL".to_owned()));
    // Unknown users get the same prompt as real ones.
    assert!(pop3_cmd(&mut c, "USER nobody@example.org").await.starts_with("+OK"));
    assert!(pop3_cmd(&mut c, "PASS whatever-password").await.starts_with("-ERR [AUTH]"));
    assert!(pop3_cmd(&mut c, "USER bob@example.org").await.starts_with("+OK"));
    assert!(pop3_cmd(&mut c, "PASS wrong-password").await.starts_with("-ERR [AUTH]"));

    let mut c = pop3_login(&s, "bob@example.org").await;
    let stat = pop3_cmd(&mut c, "STAT").await;
    assert!(stat.starts_with("+OK 2 "), "{stat}");
    let list = pop3_multi(&mut c, "LIST").await;
    assert_eq!(list.len(), 3);
    assert!(list[1].starts_with("1 ") && list[2].starts_with("2 "));
    let uidl = pop3_multi(&mut c, "UIDL").await;
    assert_eq!(uidl.len(), 3);
    assert!(pop3_cmd(&mut c, "LIST 3").await.starts_with("-ERR"));
    assert!(pop3_cmd(&mut c, "LIST 0").await.starts_with("-ERR"));
    assert!(pop3_cmd(&mut c, "RETR abc").await.starts_with("-ERR"));

    let retr = pop3_multi(&mut c, "RETR 1").await;
    assert!(retr[0].starts_with("+OK"));
    assert!(retr.contains(&"Subject: One".to_owned()));
    assert!(retr.contains(&"..leading dot".to_owned()), "lines starting with a dot are byte-stuffed: {retr:?}");
    let top = pop3_multi(&mut c, "TOP 1 1").await;
    assert!(top.contains(&"first line".to_owned()) && !top.contains(&"third line".to_owned()), "{top:?}");

    // Deletions only take effect at QUIT, and RSET undoes them.
    assert!(pop3_cmd(&mut c, "DELE 1").await.starts_with("+OK"));
    assert!(pop3_cmd(&mut c, "DELE 1").await.starts_with("-ERR"));
    assert!(pop3_cmd(&mut c, "RETR 1").await.starts_with("-ERR"));
    assert!(pop3_cmd(&mut c, "STAT").await.starts_with("+OK 1 "));
    assert!(pop3_cmd(&mut c, "RSET").await.starts_with("+OK"));
    assert!(pop3_cmd(&mut c, "DELE 2").await.starts_with("+OK"));
    assert_eq!(s.env.inbox(&s.bob).await.len(), 2);
    assert!(pop3_cmd(&mut c, "QUIT").await.starts_with("+OK"));
    let inbox = s.env.inbox(&s.bob).await;
    assert_eq!(inbox.len(), 1);
    assert!(inbox[0].contains("Subject: One"));

    // A dropped connection (no QUIT) deletes nothing.
    let mut c = pop3_login(&s, "bob@example.org").await;
    assert!(pop3_cmd(&mut c, "DELE 1").await.starts_with("+OK"));
    drop(c);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(s.env.inbox(&s.bob).await.len(), 1);

    sqlx::query("UPDATE accounts SET pop3_enabled = 0 WHERE id = ?").bind(s.bob.id).execute(&s.env.app.db).await.unwrap();
    let mut c = Client::connect_tls(s.pop3).await;
    c.read_line().await.unwrap();
    pop3_cmd(&mut c, "USER bob@example.org").await;
    assert!(pop3_cmd(&mut c, &format!("PASS {PASSWORD}")).await.starts_with("-ERR"), "POP3 access disabled for the mailbox");
}
