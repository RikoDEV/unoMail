//! Searching mail: full text, per field, combined with AND / OR / NOT, by date, size and
//! attachment, and the attachment list the message list shows.

mod common;

use common::{Api, Client, TestEnv};
use serde_json::{Value, json};

async fn deliver(env: &TestEnv, raw: &str) {
    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail("sender@remote.example", &["bob@example.org"], raw).await.starts_with("250"));
}

async fn subjects(api: &Api, filter: Value) -> Vec<String> {
    let account = api.jmap_account().await;
    let reply = api
        .jmap(json!([
            ["Email/query", { "accountId": account, "filter": filter }, "q"],
            ["Email/get", { "accountId": account, "#ids": { "resultOf": "q", "name": "Email/query", "path": "/ids" }, "properties": ["subject"] }, "g"],
        ]))
        .await;
    assert_eq!(reply[0][0], "Email/query", "{reply}");
    let mut list: Vec<String> = reply[1][1]["list"].as_array().unwrap().iter().map(|e| e["subject"].as_str().unwrap().to_owned()).collect();
    list.sort();
    list
}

const REPORT: &str = "From: Anna Kowalska <anna@partner.example>\r\nTo: bob@example.org\r\nCc: Carol Example <carol@example.org>\r\nSubject: Quarterly report\r\nDate: Mon, 05 Oct 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello Bob,\r\n\r\nthe numbers for the third quarter look good. Za\u{17c}\u{f3}\u{142}\u{107} g\u{119}\u{15b}l\u{105} ja\u{17a}\u{144}.\r\n\r\n\
--b\r\nContent-Type: application/pdf; name=\"report-q3.pdf\"\r\nContent-Disposition: attachment; filename=\"report-q3.pdf\"\r\n\r\nJVBERi0x\r\n--b--\r\n";

fn simple(from: &str, subject: &str, body: &str) -> String {
    format!("From: {from}\r\nTo: bob@example.org\r\nSubject: {subject}\r\nDate: Mon, 05 Oct 2026 10:00:00 +0000\r\n\r\n{body}\r\n")
}

#[tokio::test]
async fn searching_finds_words_wherever_they_are() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    deliver(&env, REPORT).await;
    // The word is far down the body, beyond what the summary keeps.
    deliver(&env, &simple("Jan Nowak <jan@remote.example>", "Long letter", &format!("{}\r\nThe secret word is pineapple.", "Filler text. ".repeat(100)))).await;
    deliver(&env, &simple("newsletter@shop.example", "Autumn sale", "Everything must go, 30% off.")).await;
    let all = ["Autumn sale", "Long letter", "Quarterly report"];

    assert_eq!(subjects(&api, json!({ "text": "pineapple" })).await, ["Long letter"], "the whole body is searched");
    assert_eq!(subjects(&api, json!({ "text": "pine" })).await, ["Long letter"], "words match by their beginning");
    assert_eq!(subjects(&api, json!({ "text": "gesla jazn" })).await, ["Quarterly report"], "accents do not matter");
    assert_eq!(subjects(&api, json!({ "text": "QUARTER numbers" })).await, ["Quarterly report"], "every word, in any order and case");
    assert!(subjects(&api, json!({ "text": "quarter pineapple" })).await.is_empty());
    assert_eq!(subjects(&api, json!({ "text": "report-q3.pdf" })).await, ["Quarterly report"], "attachment names count");
    assert_eq!(subjects(&api, json!({ "text": "%" })).await, Vec::<String>::new(), "wildcards are literal");
    assert_eq!(subjects(&api, json!({ "text": "30%" })).await, ["Autumn sale"]);

    // One field at a time.
    assert_eq!(subjects(&api, json!({ "from": "anna" })).await, ["Quarterly report"]);
    assert_eq!(subjects(&api, json!({ "from": "anna@partner.example" })).await, ["Quarterly report"]);
    assert_eq!(subjects(&api, json!({ "from": "Kowalska" })).await, ["Quarterly report"], "the display name counts");
    assert!(subjects(&api, json!({ "from": "carol" })).await.is_empty(), "Carol only received it");
    assert_eq!(subjects(&api, json!({ "cc": "carol@example.org" })).await, ["Quarterly report"]);
    assert_eq!(subjects(&api, json!({ "to": "bob" })).await, all);
    assert_eq!(subjects(&api, json!({ "subject": "sale" })).await, ["Autumn sale"]);
    assert!(subjects(&api, json!({ "subject": "pineapple" })).await.is_empty());
    assert_eq!(subjects(&api, json!({ "body": "pineapple" })).await, ["Long letter"]);
    assert_eq!(subjects(&api, json!({ "attachmentName": "report" })).await, ["Quarterly report"]);
    assert_eq!(subjects(&api, json!({ "hasAttachment": true })).await, ["Quarterly report"]);

    // Combined.
    assert_eq!(subjects(&api, json!({ "operator": "OR", "conditions": [{ "from": "anna" }, { "subject": "sale" }] })).await, ["Autumn sale", "Quarterly report"]);
    assert_eq!(subjects(&api, json!({ "operator": "NOT", "conditions": [{ "text": "sale" }, { "text": "pineapple" }] })).await, ["Quarterly report"]);
    assert_eq!(subjects(&api, json!({ "operator": "AND", "conditions": [{ "to": "bob" }, { "operator": "NOT", "conditions": [{ "hasAttachment": true }] }] })).await, ["Autumn sale", "Long letter"]);
    assert_eq!(subjects(&api, json!({ "from": "jan", "text": "pineapple" })).await, ["Long letter"], "conditions of one object all apply");

    // Size, date and folder.
    assert_eq!(subjects(&api, json!({ "minSize": 1300 })).await, ["Long letter"]);
    assert_eq!(subjects(&api, json!({ "maxSize": 1300 })).await, ["Autumn sale", "Quarterly report"]);
    assert_eq!(subjects(&api, json!({ "after": "2000-01-01T00:00:00Z" })).await, all, "received now");
    assert!(subjects(&api, json!({ "before": "2000-01-01T00:00:00Z" })).await.is_empty());
    let inbox = format!("b{}", env.app.store.mailbox_by_role(bob.id, "inbox").await.unwrap().unwrap().id);
    assert!(subjects(&api, json!({ "inMailboxOtherThan": [inbox] })).await.is_empty());
    assert_eq!(subjects(&api, json!({ "operator": "AND", "conditions": [{ "inMailbox": inbox }, { "text": "sale" }] })).await, ["Autumn sale"]);

    // Refused: unknown conditions and operators, wrong types, absurd nesting.
    let account = api.jmap_account().await;
    let mut deep = json!({ "text": "x" });
    for _ in 0..10 {
        deep = json!({ "operator": "AND", "conditions": [deep] });
    }
    for bad in [json!({ "header": ["X"] }), json!({ "operator": "XOR", "conditions": [] }), json!({ "minSize": "big" }), json!({ "before": "yesterday" }), json!({ "from": 42 }), json!({ "operator": "AND" }), deep] {
        let reply = api.jmap(json!([["Email/query", { "accountId": account, "filter": bad }, "q"]])).await;
        assert_eq!(reply[0][1]["type"], "unsupportedFilter", "{bad}");
    }
}

#[tokio::test]
async fn the_list_shows_attachments_without_opening_messages() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    deliver(&env, REPORT).await;
    deliver(&env, &simple("a@remote.example", "Plain", "no files")).await;
    let account = api.jmap_account().await;
    let reply = api
        .jmap(json!([
            ["Email/query", { "accountId": account }, "q"],
            ["Email/get", { "accountId": account, "#ids": { "resultOf": "q", "name": "Email/query", "path": "/ids" }, "properties": ["subject", "attachments"] }, "g"],
        ]))
        .await;
    let list = reply[1][1]["list"].as_array().unwrap();
    let report = list.iter().find(|e| e["subject"] == "Quarterly report").unwrap();
    assert_eq!(report["attachments"].as_array().unwrap().len(), 1);
    assert_eq!((report["attachments"][0]["name"].clone(), report["attachments"][0]["type"].clone()), (json!("report-q3.pdf"), json!("application/pdf")));
    assert!(report.get("bodyValues").is_none() && report.get("textBody").is_none(), "the body is not parsed for this");
    // The part can be downloaded as listed.
    let blob = report["attachments"][0]["blobId"].as_str().unwrap();
    let file = api.get(&format!("/jmap/download/{account}/{blob}/report-q3.pdf")).await;
    assert_eq!(file.bytes, b"JVBERi0x");
    assert_eq!(list.iter().find(|e| e["subject"] == "Plain").unwrap()["attachments"], json!([]));
    // The same list as the full message has it.
    let full = api.jmap(json!([["Email/get", { "accountId": account, "ids": [report["id"]] }, "g"]])).await;
    assert_eq!(full[0][1]["list"][0]["attachments"], report["attachments"]);
}

#[tokio::test]
async fn mail_stored_before_the_index_is_found_and_indexed_in_the_background() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    deliver(&env, &simple("old@remote.example", "From the old days", &format!("{}\r\nThe password hint is aubergine.", "Filler text. ".repeat(100)))).await;
    // As if it had been stored before the index existed.
    sqlx::query("DELETE FROM message_text").execute(&env.app.db).await.unwrap();
    sqlx::query("DELETE FROM message_extras").execute(&env.app.db).await.unwrap();

    assert_eq!(subjects(&api, json!({ "subject": "old days" })).await, ["From the old days"], "the summary columns stand in");
    assert!(subjects(&api, json!({ "text": "aubergine" })).await.is_empty(), "the full body is not known yet");
    unomail::search::backfill(env.app.clone()).await;
    assert_eq!(subjects(&api, json!({ "text": "aubergine" })).await, ["From the old days"]);
    // Copies of a message share one index entry, which goes with the content.
    let entries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM message_extras").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(entries, 1);
    sqlx::query("DELETE FROM messages").execute(&env.app.db).await.unwrap();
    sqlx::query("UPDATE blobs SET created_at = 0").execute(&env.app.db).await.unwrap();
    env.app.store.gc_blobs().await.unwrap();
    let left: i64 = sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM message_extras) + (SELECT COUNT(*) FROM message_text)").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(left, 0);
}
