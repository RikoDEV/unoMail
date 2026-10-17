//! Blocked senders, inbox categories, label definitions and unsubscribing.

mod common;

use axum::http::StatusCode;
use common::{Api, Client, Sink, TestEnv, message};
use serde_json::{Value, json};
use unomail::{auth::Account, smtp::queue};

async fn deliver(env: &TestEnv, from: &str, to: &str, headers: &str, subject: &str) {
    let mut c = Client::smtp(env.mx).await;
    let raw = format!("{headers}{}", message(from, to, subject, "body"));
    assert!(c.send_mail(from, &[to], &raw).await.starts_with("250"), "{subject}");
}

async fn subjects(api: &Api, filter: Value) -> Vec<String> {
    let account = api.jmap_account().await;
    let reply = api
        .jmap(json!([
            ["Email/query", { "accountId": account, "filter": filter }, "q"],
            ["Email/get", { "accountId": account, "#ids": { "resultOf": "q", "name": "Email/query", "path": "/ids" }, "properties": ["subject"] }, "g"],
        ]))
        .await;
    let mut list: Vec<String> = reply[1][1]["list"].as_array().unwrap().iter().map(|e| e["subject"].as_str().unwrap().to_owned()).collect();
    list.sort();
    list
}

async fn mailbox_id(env: &TestEnv, account: &Account, role: &str) -> String {
    format!("b{}", env.app.store.mailbox_by_role(account.id, role).await.unwrap().unwrap().id)
}

#[tokio::test]
async fn blocked_senders_go_to_junk_without_the_sender_noticing() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let carol = env.account("carol@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;

    for bad in ["", "not an address", "@", "@nodots"] {
        assert_eq!(api.post("/api/me/blocked-senders", json!({ "sender": bad })).await.status, StatusCode::BAD_REQUEST, "{bad:?}");
    }
    assert_eq!(api.post("/api/me/blocked-senders", json!({ "sender": "bob@example.org" })).await.status, StatusCode::BAD_REQUEST, "not oneself");
    assert_eq!(api.post("/api/me/blocked-senders", json!({ "sender": " Pest@Remote.Example " })).await.body, json!({ "sender": "pest@remote.example" }));
    assert_eq!(api.post("/api/me/blocked-senders", json!({ "sender": "@Spam.Example" })).await.body, json!({ "sender": "@spam.example" }));
    api.post("/api/me/blocked-senders", json!({ "sender": "pest@remote.example" })).await;
    assert_eq!(api.get("/api/me/blocked-senders").await.body, json!(["@spam.example", "pest@remote.example"]));

    // The sending server gets the usual "accepted": it cannot tell that it is blocked.
    deliver(&env, "pest@remote.example", "bob@example.org", "", "From the pest").await;
    deliver(&env, "anyone@spam.example", "bob@example.org", "", "From the spam domain").await;
    deliver(&env, "friend@remote.example", "bob@example.org", "", "From a friend").await;
    // A blocked author hiding behind another envelope sender is caught by the From header.
    let mut c = Client::smtp(env.mx).await;
    assert!(c.send_mail("bounce@mailer.example", &["bob@example.org"], &message("pest@remote.example", "bob@example.org", "Via a mailer", "x")).await.starts_with("250"));
    // The block list is personal.
    deliver(&env, "pest@remote.example", "carol@example.org", "", "To Carol").await;

    let junk = env.mailbox(&bob, "junk").await;
    assert_eq!(junk.len(), 3);
    assert!(junk.iter().all(|m| m.contains("From the pest") || m.contains("From the spam domain") || m.contains("Via a mailer")));
    let inbox = env.inbox(&bob).await;
    assert_eq!(inbox.len(), 1);
    assert!(inbox[0].contains("From a friend"));
    assert_eq!(env.inbox(&carol).await.len(), 1);
    let detail: String = sqlx::query_scalar("SELECT detail FROM delivery_log WHERE status = 'junk' LIMIT 1").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(detail, "sender blocked by the recipient");

    // Unblocking restores normal delivery.
    assert_eq!(api.delete("/api/me/blocked-senders?sender=pest%40remote.example").await.status, StatusCode::OK);
    assert_eq!(api.delete("/api/me/blocked-senders?sender=pest%40remote.example").await.status, StatusCode::NOT_FOUND);
    deliver(&env, "pest@remote.example", "bob@example.org", "", "Forgiven").await;
    assert_eq!(env.inbox(&bob).await.len(), 2);
    let carol_api = Api::logged_in(&env, "carol@example.org").await;
    assert_eq!(carol_api.get("/api/me/blocked-senders").await.body, json!([]));
}

#[tokio::test]
async fn incoming_mail_is_sorted_into_inbox_categories() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let inbox = mailbox_id(&env, &bob, "inbox").await;

    deliver(&env, "anna@partner.example", "bob@example.org", "", "Lunch on Thursday?").await;
    deliver(&env, "news@shop.example", "bob@example.org", "List-Unsubscribe: <https://shop.example/u>\r\n", "30% off everything").await;
    deliver(&env, "invitations@linkedin.com", "bob@example.org", "", "You have a new invitation").await;
    deliver(&env, "no-reply@bank.example", "bob@example.org", "", "Your statement is ready").await;
    deliver(&env, "dev@lists.example", "bob@example.org", "List-Id: <dev.lists.example>\r\nList-Post: <mailto:dev@lists.example>\r\n", "[dev] New API").await;

    let in_category = |name: &'static str| {
        let (api, inbox) = (&api, inbox.clone());
        async move { subjects(api, json!({ "inMailbox": inbox, "category": name })).await }
    };
    assert_eq!(in_category("general").await, ["Lunch on Thursday?"]);
    assert_eq!(in_category("offers").await, ["30% off everything"]);
    assert_eq!(in_category("communities").await, ["You have a new invitation"]);
    assert_eq!(in_category("notifications").await, ["Your statement is ready"]);
    assert_eq!(in_category("forums").await, ["[dev] New API"]);
    assert_eq!(subjects(&api, json!({ "inMailbox": inbox })).await.len(), 5, "without the filter everything is listed");
    let account = api.jmap_account().await;
    let bad = api.jmap(json!([["Email/query", { "accountId": account, "filter": { "category": "spam" } }, "q"]])).await;
    assert_eq!(bad[0][1]["type"], "unsupportedFilter");

    assert_eq!(api.get("/api/me/categories").await.body, json!({ "general": 1, "offers": 1, "communities": 1, "notifications": 1, "forums": 1 }));
    // Categories are not labels: they do not show up among the user's labels.
    assert_eq!(api.get("/api/me/labels").await.body, json!([]));
    assert_eq!(api.get("/api/me/label-details").await.body, json!([]));

    // The user can move a conversation to another category; reading it lowers the unread count.
    let reply = api.jmap(json!([["Email/query", { "accountId": account, "filter": { "inMailbox": inbox, "category": "offers" } }, "q"]])).await;
    let id = reply[0][1]["ids"][0].as_str().unwrap().to_owned();
    let moved = api.jmap(json!([["Email/set", { "accountId": account, "update": { &id: { "keywords/$cat_offers": null, "keywords/$cat_notifications": true, "keywords/$seen": true } } }, "u"]])).await;
    assert!(moved[0][1]["updated"].get(&id).is_some(), "{moved}");
    assert!(in_category("offers").await.is_empty());
    assert_eq!(in_category("notifications").await.len(), 2);
    assert_eq!(api.get("/api/me/categories").await.body, json!({ "general": 1, "offers": 0, "communities": 1, "notifications": 1, "forums": 1 }));

    // Junk is not categorised.
    api.post("/api/me/blocked-senders", json!({ "sender": "@shop.example" })).await;
    deliver(&env, "news@shop.example", "bob@example.org", "List-Unsubscribe: <https://shop.example/u>\r\n", "Another sale").await;
    let junk = env.app.store.mailbox_by_role(bob.id, "junk").await.unwrap().unwrap();
    assert_eq!(env.app.store.messages_in(junk.id).await.unwrap()[0].keywords, "[]");
}

#[tokio::test]
async fn inbox_categories_learn_from_the_user() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;
    let inbox = mailbox_id(&env, &bob, "inbox").await;
    let in_category = |name: &'static str| {
        let (api, inbox) = (&api, inbox.clone());
        async move { subjects(api, json!({ "inMailbox": inbox, "category": name })).await }
    };

    assert_eq!(api.get("/api/me/categories/learning").await.body["total"], 0);
    deliver(&env, "news@shop.example", "bob@example.org", "List-Unsubscribe: <https://shop.example/u>\r\n", "Shop news 1").await;
    assert_eq!(in_category("offers").await, ["Shop news 1"]);

    // The user wants this shop's mail in General.
    let reply = api.jmap(json!([["Email/query", { "accountId": account, "filter": { "inMailbox": inbox, "category": "offers" } }, "q"]])).await;
    let id = reply[0][1]["ids"][0].as_str().unwrap().to_owned();
    api.jmap(json!([["Email/set", { "accountId": account, "update": { &id: { "keywords/$cat_offers": null } } }, "u"]])).await;
    // Training runs in the background.
    for _ in 0..100 {
        if api.get("/api/me/categories/learning").await.body["total"] == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let learning = api.get("/api/me/categories/learning").await.body;
    assert_eq!(learning["learned"]["general"], 1, "{learning}");
    assert_eq!(learning["senders"], 1);

    deliver(&env, "news@shop.example", "bob@example.org", "List-Unsubscribe: <https://shop.example/u>\r\n", "Shop news 2").await;
    assert_eq!(in_category("general").await, ["Shop news 1", "Shop news 2"]);
    // Other senders are still sorted by the rules.
    deliver(&env, "deals@other.example", "bob@example.org", "List-Unsubscribe: <https://other.example/u>\r\n", "Other deals").await;
    assert_eq!(in_category("offers").await, ["Other deals"]);

    // Forgetting brings the rules back.
    assert_eq!(api.delete("/api/me/categories/learning").await.status, StatusCode::OK);
    assert_eq!(api.get("/api/me/categories/learning").await.body["total"], 0);
    deliver(&env, "news@shop.example", "bob@example.org", "List-Unsubscribe: <https://shop.example/u>\r\n", "Shop news 3").await;
    assert_eq!(in_category("offers").await, ["Other deals", "Shop news 3"]);
}

#[tokio::test]
async fn labels_can_be_defined_coloured_renamed_and_deleted() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    env.account("carol@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;

    for bad in [json!({ "name": "Work" }), json!({ "name": "$seen" }), json!({ "name": "a b" }), json!({ "name": "" }), json!({ "name": "work", "color": "red" }), json!({ "name": "work", "color": "#12345" })] {
        assert_eq!(api.put("/api/me/label-details", bad.clone()).await.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    // A label exists as soon as it is defined, before any message carries it.
    assert_eq!(api.put("/api/me/label-details", json!({ "name": "work", "color": "#1A73E8" })).await.body, json!({ "name": "work", "color": "#1a73e8" }));
    assert_eq!(api.put("/api/me/label-details", json!({ "name": "travel" })).await.status, StatusCode::OK);
    assert_eq!(api.get("/api/me/labels").await.body, json!(["travel", "work"]));

    // A label that only exists on a message is listed too, without a colour.
    let inbox = env.app.store.mailbox_by_role(bob.id, "inbox").await.unwrap().unwrap();
    let appended = env.app.store.append(bob.id, inbox.id, b"Subject: x\r\n\r\nx", Default::default(), None).await.unwrap();
    env.app.store.set_flags_and_keywords(bob.id, appended.id, Default::default(), &["work".into(), "receipts".into(), "$cat_offers".into()]).await.unwrap();
    assert_eq!(
        api.get("/api/me/label-details").await.body,
        json!([{ "name": "receipts", "color": "" }, { "name": "travel", "color": "" }, { "name": "work", "color": "#1a73e8" }])
    );

    // Changing the colour, renaming (the colour moves along) and deleting.
    assert_eq!(api.put("/api/me/label-details", json!({ "name": "work", "color": "#d93025" })).await.status, StatusCode::OK);
    assert_eq!(api.post("/api/me/labels/rename", json!({ "from": "work", "to": "office" })).await.body, json!({ "changed": 1 }));
    let details = api.get("/api/me/label-details").await.body;
    assert_eq!(details, json!([{ "name": "office", "color": "#d93025" }, { "name": "receipts", "color": "" }, { "name": "travel", "color": "" }]));
    assert_eq!(api.delete("/api/me/labels?name=office").await.body, json!({ "changed": 1 }));
    assert_eq!(api.delete("/api/me/labels?name=travel").await.body, json!({ "changed": 0 }), "an unused label is simply forgotten");
    assert_eq!(api.get("/api/me/labels").await.body, json!(["receipts"]));
    assert_eq!(env.app.store.message(bob.id, appended.id).await.unwrap().keywords, "[\"receipts\",\"$cat_offers\"]", "the category survives label changes");

    let carol = Api::logged_in(&env, "carol@example.org").await;
    assert_eq!(carol.get("/api/me/label-details").await.body, json!([]));
}

#[tokio::test]
async fn unsubscribing_uses_what_the_sender_offers() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    env.account("carol@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;
    let inbox = mailbox_id(&env, &bob, "inbox").await;

    deliver(&env, "news@list.example", "bob@example.org", "List-Unsubscribe: <mailto:leave@list.example?subject=Unsubscribe%20bob&body=list%3A%20news>,\r\n <https://list.example/u/1>\r\n", "By mail").await;
    deliver(&env, "ads@shop.example", "bob@example.org", "List-Unsubscribe: <https://shop.example/preferences>\r\n", "By link").await;
    // A one-click endpoint that does not answer: the server falls back to the mail method.
    deliver(&env, "x@oneclick.example", "bob@example.org", "List-Unsubscribe: <https://127.0.0.1:1/u>, <mailto:off@oneclick.example>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n", "One click").await;
    deliver(&env, "anna@partner.example", "bob@example.org", "", "Personal").await;

    let reply = api
        .jmap(json!([
            ["Email/query", { "accountId": account, "filter": { "inMailbox": inbox } }, "q"],
            ["Email/get", { "accountId": account, "#ids": { "resultOf": "q", "name": "Email/query", "path": "/ids" }, "properties": ["subject", "unsubscribe"] }, "g"],
        ]))
        .await;
    let emails = reply[1][1]["list"].as_array().unwrap().clone();
    let find = |subject: &str| emails.iter().find(|e| e["subject"] == subject).unwrap().clone();
    // The client learns which methods exist, not the sender's addresses.
    assert_eq!(find("By mail")["unsubscribe"], json!({ "oneClick": false, "mailto": true, "link": true }));
    assert_eq!(find("By link")["unsubscribe"], json!({ "oneClick": false, "mailto": false, "link": true }));
    assert_eq!(find("One click")["unsubscribe"], json!({ "oneClick": true, "mailto": true, "link": false }));
    assert_eq!(find("Personal")["unsubscribe"], Value::Null);
    let id = |subject: &str| find(subject)["id"].as_str().unwrap().to_owned();

    let by_mail = api.post("/api/me/unsubscribe", json!({ "email_id": id("By mail") })).await;
    assert_eq!(by_mail.body, json!({ "method": "mail", "to": "leave@list.example" }), "{}", by_mail.text);
    let one_click = api.post("/api/me/unsubscribe", json!({ "email_id": id("One click") })).await;
    assert_eq!(one_click.body, json!({ "method": "mail", "to": "off@oneclick.example" }), "{}", one_click.text);
    queue::process_due(&env.app).await;
    let sent = sink.received();
    assert_eq!(sent.len(), 2);
    let request = sent.iter().find(|m| m.to == "leave@list.example").unwrap();
    assert_eq!(request.from, "bob@example.org");
    assert!(request.data.contains("Subject: Unsubscribe bob\r\n") && request.data.contains("\r\n\r\nlist: news\r\n"), "{}", request.data);
    assert!(request.data.contains("DKIM-Signature") || request.data.contains("From: <bob@example.org>"));

    assert_eq!(api.post("/api/me/unsubscribe", json!({ "email_id": id("By link") })).await.body, json!({ "method": "link", "url": "https://shop.example/preferences" }));
    assert_eq!(api.post("/api/me/unsubscribe", json!({ "email_id": id("Personal") })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.post("/api/me/unsubscribe", json!({ "email_id": "m999999" })).await.status, StatusCode::NOT_FOUND);
    // Nobody can unsubscribe (or send mail) on another user's behalf.
    let carol = Api::logged_in(&env, "carol@example.org").await;
    assert_eq!(carol.post("/api/me/unsubscribe", json!({ "email_id": id("By mail") })).await.status, StatusCode::NOT_FOUND);
    assert_eq!(sink.received().len(), 2);
}

#[tokio::test]
async fn newest_unread_message_for_notifications() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let empty = api.get("/api/me/newest-unread").await;
    assert_eq!(empty.status, StatusCode::OK);
    assert_eq!(empty.body, json!({ "account": format!("a{}", bob.id), "unread": 0, "message": null }));

    deliver(&env, "ann@remote.example", "bob@example.org", "", "First").await;
    deliver(&env, "carl@remote.example", "bob@example.org", "", "Second").await;
    queue::process_due(&env.app).await;
    let newest = api.get("/api/me/newest-unread").await.body;
    assert_eq!(newest["unread"], 2, "{newest}");
    assert_eq!((newest["message"]["subject"].clone(), newest["message"]["from"].clone()), (json!("Second"), json!("carl@remote.example")));
    assert!(newest["message"]["threadId"].as_str().unwrap().starts_with('t'));

    // Read mail no longer counts.
    sqlx::query("UPDATE messages SET seen = 1 WHERE subject = 'Second'").execute(&env.app.db).await.unwrap();
    assert_eq!(api.get("/api/me/newest-unread").await.body["message"]["subject"], "First");
}
