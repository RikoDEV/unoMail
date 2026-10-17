//! The personal spam filter: reporting spam teaches it, correspondents and replies teach it
//! what is wanted, and once trained it files new spam into Junk.

mod common;

use std::time::Duration;

use common::{Api, Client, PASSWORD, TestEnv, message};
use serde_json::{Value, json};

fn spam(i: usize) -> String {
    message(
        "Prize Desk <winner@lottery.example>",
        "bob@example.org",
        &format!("You won {i} million dollars"),
        &format!("Congratulations winner! Claim your prize at https://claim.lottery.example/{i} today. Urgent transfer fee required, reply with your bank details."),
    )
}

fn ham(i: usize) -> String {
    message(
        "Anna <anna@partner.example>",
        "bob@example.org",
        &format!("Project meeting notes {i}"),
        &format!("Hi Bob, here are the notes from our project meeting number {i}. Let us review the schedule and the budget tomorrow afternoon."),
    )
}

async fn deliver(env: &TestEnv, sender: &str, raw: &str) {
    let mut c = Client::smtp(env.mx).await;
    let reply = c.send_mail(sender, &["bob@example.org"], raw).await;
    assert!(reply.starts_with("250"), "{reply}");
}

async fn mailbox(api: &Api, account: &str, role: &str) -> String {
    let list = api.jmap(json!([["Mailbox/get", { "accountId": account }, "0"]])).await[0][1]["list"].clone();
    list.as_array().unwrap().iter().find(|m| m["role"] == role).unwrap()["id"].as_str().unwrap().to_owned()
}

async fn ids_in(api: &Api, account: &str, mailbox: &str) -> Vec<String> {
    let found = api.jmap(json!([["Email/query", { "accountId": account, "filter": { "inMailbox": mailbox }, "limit": 100 }, "q"]])).await;
    found[0][1]["ids"].as_array().unwrap().iter().map(|id| id.as_str().unwrap().to_owned()).collect()
}

async fn filter_state(api: &Api) -> Value {
    api.get("/api/me/spam-filter").await.body
}

/// Training runs in the background; waits until the counts reach the expected values.
async fn wait_for(api: &Api, spam: i64, ham: i64) {
    for _ in 0..200 {
        let state = filter_state(api).await;
        if state["spam"] == spam && state["ham"] == ham {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("filter did not reach {spam}/{ham}: {}", filter_state(api).await);
}

#[tokio::test]
async fn reports_train_the_personal_filter_which_then_files_spam_away() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;
    let (inbox, junk) = (mailbox(&api, &account, "inbox").await, mailbox(&api, &account, "junk").await);
    let state = filter_state(&api).await;
    assert_eq!((state["enabled"].as_bool(), state["active"].as_bool(), state["needed"].as_i64()), (Some(true), Some(false), Some(10)));

    // Ten spam messages arrive in the inbox and are reported (moved to Junk).
    for i in 0..10 {
        deliver(&env, "winner@lottery.example", &spam(i)).await;
    }
    let reported = ids_in(&api, &account, &inbox).await;
    assert_eq!(reported.len(), 10, "nothing is filtered before training");
    let update: serde_json::Map<String, Value> = reported.iter().map(|id| (id.clone(), json!({ "mailboxIds": { junk.clone(): true } }))).collect();
    let moved = api.jmap(json!([["Email/set", { "accountId": account, "update": update }, "u"]])).await;
    assert_eq!(moved[0][1]["updated"].as_object().unwrap().len(), 10, "{moved}");
    wait_for(&api, 10, 0).await;

    // Mail from someone in the address book is wanted: it teaches the filter right away.
    assert!(api.post("/api/me/contacts", json!({ "name": "Anna", "email": "anna@partner.example" })).await.status.is_success());
    for i in 0..9 {
        deliver(&env, "anna@partner.example", &ham(i)).await;
    }
    wait_for(&api, 10, 9).await;
    assert!(!filter_state(&api).await["active"].as_bool().unwrap());

    // "Not spam": one reported message goes back to the inbox and counts as ham instead.
    let back = &reported[0];
    api.jmap(json!([["Email/set", { "accountId": account, "update": { back: { "mailboxIds": { inbox.clone(): true } } } }, "u"]])).await;
    wait_for(&api, 9, 10).await;
    // Reporting it again moves it back.
    api.jmap(json!([["Email/set", { "accountId": account, "update": { back: { "mailboxIds": { junk.clone(): true } } } }, "u"]])).await;
    wait_for(&api, 10, 9).await;

    // A reply marks the message replied to as wanted (here: a newsletter from a stranger).
    deliver(&env, "news@weekly.example", &message("Weekly <news@weekly.example>", "bob@example.org", "Weekly digest", "This week in the project: new release, meeting schedule and budget review.")).await;
    let newsletter_id: String = sqlx::query_scalar("SELECT message_id FROM messages WHERE subject = 'Weekly digest'").fetch_one(&env.app.db).await.unwrap();
    let mut submission = Client::smtp(env.submission).await;
    submission.starttls().await;
    assert!(submission.auth_plain("bob@example.org", PASSWORD).await.starts_with("235"));
    let reply = format!("From: bob@example.org\r\nTo: news@weekly.example\r\nSubject: Re: Weekly digest\r\nIn-Reply-To: <{}>\r\n\r\nThanks!\r\n", newsletter_id.trim_matches(['<', '>']));
    assert!(submission.send_mail("bob@example.org", &["news@weekly.example"], &reply).await.starts_with("250"));
    wait_for(&api, 10, 10).await;
    assert!(filter_state(&api).await["active"].as_bool().unwrap());
    // Writing to someone makes them a correspondent.
    let known: Vec<String> = sqlx::query_scalar("SELECT address FROM correspondents").fetch_all(&env.app.db).await.unwrap();
    assert_eq!(known, ["news@weekly.example"]);

    // Trained: new spam goes to Junk, new wanted mail from a stranger stays in the inbox.
    let junk_before = ids_in(&api, &account, &junk).await.len();
    deliver(&env, "winner@lottery.example", &spam(77)).await;
    assert_eq!(ids_in(&api, &account, &junk).await.len(), junk_before + 1);
    let detail: String = sqlx::query_scalar("SELECT detail FROM delivery_log WHERE status = 'junk' ORDER BY id DESC LIMIT 1").fetch_one(&env.app.db).await.unwrap();
    assert!(detail.starts_with("filed as spam by the recipient's filter"), "{detail}");
    let inbox_before = ids_in(&api, &account, &inbox).await.len();
    deliver(&env, "carol@other.example", &message("Carol <carol@other.example>", "bob@example.org", "Budget review meeting", "Hi Bob, can we move the project meeting about the schedule and budget to tomorrow afternoon?")).await;
    assert_eq!(ids_in(&api, &account, &inbox).await.len(), inbox_before + 1);

    // Correspondents are never filed away by the filter, whatever they write.
    deliver(&env, "anna@partner.example", &message("Anna <anna@partner.example>", "bob@example.org", "You won a million dollars", "Congratulations winner! Claim your prize, urgent transfer fee, bank details.")).await;
    assert_eq!(ids_in(&api, &account, &inbox).await.len(), inbox_before + 2);

    // Other users are not affected by Bob's training.
    env.account("dave@example.org").await;
    let dave = Api::logged_in(&env, "dave@example.org").await;
    assert_eq!(filter_state(&dave).await["spam"], 0);

    // Bob can make it forget everything.
    assert!(api.delete("/api/me/spam-filter").await.status.is_success());
    let state = filter_state(&api).await;
    assert_eq!((state["spam"].as_i64(), state["ham"].as_i64(), state["active"].as_bool()), (Some(0), Some(0), Some(false)));
    let _ = bob;
}

/// Sends an IMAP command and returns everything up to its tagged reply.
async fn tagged(c: &mut Client, tag: &str, command: &str) -> String {
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

#[tokio::test]
async fn imap_junk_keywords_and_copies_train_the_filter() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    for i in 0..3 {
        deliver(&env, "winner@lottery.example", &spam(i)).await;
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(unomail::imap::serve(env.app.clone(), listener));
    let mut imap = Client::connect_tls(addr).await;
    imap.read_line().await;
    assert!(tagged(&mut imap, "a1", &format!("LOGIN bob@example.org \"{PASSWORD}\"")).await.contains("a1 OK"));
    assert!(tagged(&mut imap, "a2", "SELECT INBOX").await.contains("a2 OK"));
    // Thunderbird and Apple Mail mark spam with a keyword.
    assert!(tagged(&mut imap, "a3", "STORE 1 +FLAGS ($Junk)").await.contains("a3 OK"));
    wait_for(&api, 1, 0).await;
    // Setting it again does not count twice; $NotJunk changes the verdict.
    assert!(tagged(&mut imap, "a4", "STORE 1 FLAGS ($NotJunk)").await.contains("a4 OK"));
    wait_for(&api, 0, 1).await;
    // Some clients report spam by copying into Junk.
    assert!(tagged(&mut imap, "a5", "COPY 2 Junk").await.contains("a5 OK"));
    wait_for(&api, 1, 1).await;
    assert!(tagged(&mut imap, "a6", "MOVE 3 Junk").await.contains("a6 OK"));
    wait_for(&api, 2, 1).await;
}

#[tokio::test]
async fn the_administrator_can_turn_the_filter_off() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let off = unomail::settings::Runtime { personal_spam_filter: false, ..(*env.app.rt()).clone() };
    env.app.settings.store(std::sync::Arc::new(off));
    assert_eq!(filter_state(&api).await["enabled"], false);
    assert_eq!(unomail::bayes::judge(&env.app, 1, "x@y.example", spam(1).as_bytes()).await, unomail::bayes::Verdict::Undecided);
}
