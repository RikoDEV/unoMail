//! JMAP tests: the mail API used by the web client.

mod common;

use axum::http::{Method, StatusCode};
use common::{Api, Client, PASSWORD, Sink, TestEnv, message};
use serde_json::{Value, json};
use unomail::smtp::queue;

async fn deliver(env: &TestEnv, to: &str, subject: &str, body: &str) {
    let mut c = Client::smtp(env.mx).await;
    let reply = c.send_mail("alice@remote.example", &[to], &message("Alice <alice@remote.example>", to, subject, body)).await;
    assert!(reply.starts_with("250"), "{reply}");
}

fn mailbox_id(mailboxes: &Value, role: &str) -> String {
    mailboxes.as_array().unwrap().iter().find(|m| m["role"] == role).unwrap()["id"].as_str().unwrap().to_owned()
}

async fn mailboxes(api: &Api, account: &str) -> Value {
    api.jmap(json!([["Mailbox/get", { "accountId": account }, "0"]])).await[0][1]["list"].clone()
}

#[tokio::test]
async fn session_requires_authentication_and_supports_basic_auth() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let anonymous = Api::new(&env);
    assert_eq!(anonymous.get("/.well-known/jmap").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(anonymous.post("/jmap/api", json!({ "methodCalls": [] })).await.status, StatusCode::UNAUTHORIZED);

    use base64::Engine;
    let basic = |password: &str| format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("bob@example.org:{password}")));
    let ok = anonymous.send(Method::GET, "/.well-known/jmap", None, &[("authorization", &basic(PASSWORD))]).await;
    assert_eq!(ok.status, StatusCode::OK);
    assert_eq!(ok.body["username"], "bob@example.org");
    assert_eq!(ok.body["apiUrl"], "/jmap/api");
    let bad = anonymous.send(Method::GET, "/.well-known/jmap", None, &[("authorization", &basic("wrong"))]).await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    assert!(bad.headers.get("www-authenticate").is_none(), "browsers must never be prompted to cache Basic credentials");

    // Cookie sessions need the CSRF token for API calls.
    let mut bob = Api::logged_in(&env, "bob@example.org").await;
    bob.csrf = None;
    assert_eq!(bob.post("/jmap/api", json!({ "methodCalls": [] })).await.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn reading_mail_threads_flags_and_moves() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    deliver(&env, "bob@example.org", "First topic", "first body").await;
    deliver(&env, "bob@example.org", "Second topic", "second body with needle").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;

    let boxes = mailboxes(&api, &account).await;
    assert_eq!(boxes.as_array().unwrap().len(), 6);
    let inbox = mailbox_id(&boxes, "inbox");
    let trash = mailbox_id(&boxes, "trash");
    let inbox_info = boxes.as_array().unwrap().iter().find(|m| m["role"] == "inbox").unwrap();
    assert_eq!((inbox_info["totalEmails"].as_i64(), inbox_info["unreadEmails"].as_i64()), (Some(2), Some(2)));

    // Query + get chained with a result reference, as the web client does.
    let responses = api
        .jmap(json!([
            ["Email/query", { "accountId": account, "filter": { "inMailbox": inbox }, "collapseThreads": true, "calculateTotal": true, "limit": 10 }, "q"],
            ["Email/get", { "accountId": account, "#ids": { "resultOf": "q", "name": "Email/query", "path": "/ids" },
                            "properties": ["threadId", "subject", "from", "preview", "keywords", "receivedAt", "mailboxIds"] }, "g"],
        ]))
        .await;
    assert_eq!(responses[0][1]["total"], 2);
    let list = responses[1][1]["list"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0]["subject"], "Second topic", "newest first");
    assert_eq!(list[0]["from"], json!([{ "name": "Alice", "email": "alice@remote.example" }]));
    assert_eq!(list[0]["preview"], "second body with needle");
    assert_eq!(list[0]["keywords"], json!({}));
    assert!(list[0].get("bodyValues").is_none(), "bodies are not loaded for list views");
    let email_id = list[0]["id"].as_str().unwrap().to_owned();
    let thread_id = list[0]["threadId"].as_str().unwrap().to_owned();

    let search = api.jmap(json!([["Email/query", { "accountId": account, "filter": { "text": "needle" } }, "s"]])).await;
    assert_eq!(search[0][1]["ids"], json!([email_id]));
    let wildcard = api.jmap(json!([["Email/query", { "accountId": account, "filter": { "text": "%" } }, "s"]])).await;
    assert_eq!(wildcard[0][1]["ids"], json!([]), "search terms are literal");
    let unsupported = api.jmap(json!([["Email/query", { "accountId": account, "filter": { "header": ["X-Thing"] } }, "s"]])).await;
    assert_eq!(unsupported[0][1]["type"], "unsupportedFilter");

    let full = api
        .jmap(json!([
            ["Thread/get", { "accountId": account, "ids": [thread_id] }, "t"],
            ["Email/get", { "accountId": account, "#ids": { "resultOf": "t", "name": "Thread/get", "path": "/list/*/emailIds" } }, "g"],
        ]))
        .await;
    let email = &full[1][1]["list"][0];
    let part = email["textBody"][0]["partId"].as_str().unwrap();
    assert_eq!(email["bodyValues"][part]["value"].as_str().unwrap().trim_end(), "second body with needle");
    assert_eq!(email["to"], json!([{ "name": null, "email": "bob@example.org" }]));

    let updated = api
        .jmap(json!([["Email/set", { "accountId": account, "update": { &email_id: { "keywords/$seen": true, "keywords/$flagged": true, "keywords/work": true } } }, "u"]]))
        .await;
    assert_eq!(updated[0][1]["updated"], json!({ &email_id: null }), "{updated}");
    let after = api.jmap(json!([["Email/get", { "accountId": account, "ids": [email_id], "properties": ["keywords"] }, "g"]])).await;
    assert_eq!(after[0][1]["list"][0]["keywords"], json!({ "$seen": true, "$flagged": true, "work": true }));
    let unread = api.jmap(json!([["Email/query", { "accountId": account, "filter": { "inMailbox": inbox, "notKeyword": "$seen" } }, "q"]])).await;
    assert_eq!(unread[0][1]["ids"].as_array().unwrap().len(), 1);

    let moved = api.jmap(json!([["Email/set", { "accountId": account, "update": { &email_id: { "mailboxIds": { &trash: true } } } }, "u"]])).await;
    assert_eq!(moved[0][1]["updated"], json!({ &email_id: null }));
    let boxes = mailboxes(&api, &account).await;
    let count = |role: &str| boxes.as_array().unwrap().iter().find(|m| m["role"] == role).unwrap()["totalEmails"].as_i64().unwrap();
    assert_eq!((count("inbox"), count("trash")), (1, 1));

    let destroyed = api.jmap(json!([["Email/set", { "accountId": account, "destroy": [email_id, "m99999", "garbage"] }, "d"]])).await;
    assert_eq!(destroyed[0][1]["destroyed"], json!([email_id]));
    assert_eq!(destroyed[0][1]["notDestroyed"].as_object().unwrap().len(), 2);

    let bad = api
        .jmap(json!([
            ["Email/set", { "accountId": account, "update": { "m1": { "subject": "rewritten" } } }, "a"],
            ["Nope/get", { "accountId": account }, "b"],
            ["Email/get", { "accountId": "a999", "ids": [] }, "c"],
            ["Email/changes", { "accountId": account, "sinceState": "999999999" }, "d"],
            ["Core/echo", { "hello": true }, "e"],
        ]))
        .await;
    assert_eq!(bad[0][1]["notUpdated"]["m1"]["type"], "invalidProperties");
    assert_eq!(bad[1][1]["type"], "unknownMethod");
    assert_eq!(bad[2][1]["type"], "accountNotFound");
    assert_eq!(bad[3][1]["type"], "cannotCalculateChanges");
    assert_eq!(bad[4], json!(["Core/echo", { "hello": true }, "e"]));
}

#[tokio::test]
async fn users_cannot_reach_each_others_mail() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account("eve@example.org").await;
    deliver(&env, "bob@example.org", "Private", "for bob only").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let eve = Api::logged_in(&env, "eve@example.org").await;
    let (bob_account, eve_account) = (bob.jmap_account().await, eve.jmap_account().await);
    assert_ne!(bob_account, eve_account);

    let bob_inbox = mailbox_id(&mailboxes(&bob, &bob_account).await, "inbox");
    let ids = bob.jmap(json!([["Email/query", { "accountId": bob_account, "filter": { "inMailbox": bob_inbox } }, "q"]])).await[0][1]["ids"].clone();
    let email_id = ids[0].as_str().unwrap().to_owned();
    let bob_email = bob.jmap(json!([["Email/get", { "accountId": bob_account, "ids": [email_id] }, "g"]])).await[0][1]["list"][0].clone();
    let (blob_id, thread_id) = (bob_email["blobId"].as_str().unwrap(), bob_email["threadId"].as_str().unwrap());

    // Using Bob's account id is refused outright...
    let cross = eve.jmap(json!([["Email/get", { "accountId": bob_account, "ids": [email_id] }, "g"]])).await;
    assert_eq!(cross[0][1]["type"], "accountNotFound");
    // ...and Bob's object ids mean nothing inside Eve's account.
    let probes = eve
        .jmap(json!([
            ["Email/get", { "accountId": eve_account, "ids": [email_id] }, "a"],
            ["Thread/get", { "accountId": eve_account, "ids": [thread_id] }, "b"],
            ["Email/query", { "accountId": eve_account, "filter": { "inMailbox": bob_inbox } }, "c"],
            ["Email/set", { "accountId": eve_account, "update": { &email_id: { "keywords/$seen": true } }, "destroy": [email_id] }, "d"],
            ["Mailbox/get", { "accountId": eve_account, "ids": [bob_inbox] }, "e"],
            ["Mailbox/set", { "accountId": eve_account, "update": { &bob_inbox: { "name": "pwned" } }, "destroy": [bob_inbox], "onDestroyRemoveEmails": true }, "f"],
            ["EmailSubmission/set", { "accountId": eve_account, "create": { "s": { "emailId": email_id } } }, "g"],
        ]))
        .await;
    assert_eq!(probes[0][1]["notFound"], json!([email_id]));
    assert_eq!(probes[1][1]["notFound"], json!([thread_id]));
    assert_eq!(probes[2][1]["ids"], json!([]));
    assert_eq!(probes[3][1]["notUpdated"][&email_id]["type"], "notFound");
    assert_eq!(probes[3][1]["notDestroyed"][&email_id]["type"], "notFound");
    assert_eq!(probes[4][1]["notFound"], json!([bob_inbox]));
    assert_eq!(probes[5][1]["notUpdated"][&bob_inbox]["type"], "notFound");
    assert_eq!(probes[5][1]["notDestroyed"][&bob_inbox]["type"], "notFound");
    assert!(probes[6][1]["notCreated"]["s"].is_object());

    // Moving her own mail into Bob's mailbox, or attaching Bob's blobs, is impossible too.
    deliver(&env, "eve@example.org", "Hers", "x").await;
    let eve_inbox = mailbox_id(&mailboxes(&eve, &eve_account).await, "inbox");
    let own = eve.jmap(json!([["Email/query", { "accountId": eve_account, "filter": { "inMailbox": eve_inbox } }, "q"]])).await[0][1]["ids"][0].clone();
    let own = own.as_str().unwrap();
    let moved = eve.jmap(json!([["Email/set", { "accountId": eve_account, "update": { own: { "mailboxIds": { &bob_inbox: true } } } }, "m"]])).await;
    assert_eq!(moved[0][1]["notUpdated"][own]["type"], "notFound");
    let steal = eve
        .jmap(json!([["Email/set", { "accountId": eve_account, "create": { "x": { "mailboxIds": { &eve_inbox: true }, "subject": "loot", "attachments": [{ "blobId": blob_id, "name": "bob.eml" }] } } }, "c"]]))
        .await;
    assert_eq!(steal[0][1]["notCreated"]["x"]["type"], "blobNotFound");

    for path in [
        format!("/jmap/download/{eve_account}/{blob_id}/mail.eml"),
        format!("/jmap/download/{bob_account}/{blob_id}/mail.eml"),
        format!("/jmap/download/{eve_account}/{blob_id}.0/part"),
        format!("/jmap/download/{eve_account}/..%2F..%2Funomail.db/x"),
    ] {
        assert_eq!(eve.get(&path).await.status, StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(bob.get(&format!("/jmap/download/{bob_account}/{blob_id}/mail.eml")).await.status, StatusCode::OK);
    assert_eq!(eve.send(Method::POST, &format!("/jmap/upload/{bob_account}"), Some(json!({})), &[]).await.status, StatusCode::NOT_FOUND);

    // Nothing of the above altered Bob's mailbox.
    let still = bob.jmap(json!([["Email/get", { "accountId": bob_account, "ids": [email_id], "properties": ["keywords", "subject"] }, "g"]])).await;
    assert_eq!(still[0][1]["list"][0]["keywords"], json!({}));
}

#[tokio::test]
async fn composing_and_sending_with_attachment_and_bcc() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let carol = env.account("carol@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;
    let boxes = mailboxes(&api, &account).await;
    let (drafts, sent) = (mailbox_id(&boxes, "drafts"), mailbox_id(&boxes, "sent"));

    let upload = api.send(Method::POST, &format!("/jmap/upload/{account}"), Some(json!({ "report": [1, 2, 3] })), &[]).await;
    assert_eq!(upload.status, StatusCode::CREATED, "{}", upload.text);
    let blob = upload.body["blobId"].as_str().unwrap().to_owned();

    let identities = api.jmap(json!([["Identity/get", { "accountId": account }, "i"]])).await;
    assert_eq!(identities[0][1]["list"][0]["email"], "bob@example.org");

    let email = json!({
        "mailboxIds": { &drafts: true },
        "keywords": { "$draft": true, "$seen": true },
        "from": [{ "name": "Bob", "email": "bob@example.org" }],
        "to": [{ "name": "Friend", "email": "friend@remote.example" }],
        "cc": [{ "email": "carol@example.org" }],
        "bcc": [{ "email": "hidden@remote.example" }],
        "subject": "Quarterly report\r\nX-Injected: yes",
        "bodyValues": { "t": { "value": "Plain text body" }, "h": { "value": "<p>HTML <b>body</b></p>" } },
        "textBody": [{ "partId": "t", "type": "text/plain" }],
        "htmlBody": [{ "partId": "h", "type": "text/html" }],
        "attachments": [{ "blobId": blob, "name": "report.json", "type": "application/json" }],
    });
    let responses = api
        .jmap(json!([
            ["Email/set", { "accountId": account, "create": { "draft": email } }, "c"],
            ["EmailSubmission/set", {
                "accountId": account,
                "create": { "send": { "emailId": "#draft", "identityId": "bob@example.org" } },
                "onSuccessUpdateEmail": { "#send": { "mailboxIds": { &sent: true }, "keywords/$draft": null } },
            }, "s"],
        ]))
        .await;
    assert!(responses[0][1]["created"]["draft"]["id"].is_string(), "{responses}");
    assert!(responses[1][1]["created"]["send"].is_object(), "{responses}");
    let email_id = responses[0][1]["created"]["draft"]["id"].as_str().unwrap().to_owned();

    // The stored copy moved to Sent, keeps Bcc and lost its draft flag.
    let stored = api.jmap(json!([["Email/get", { "accountId": account, "ids": [email_id] }, "g"]])).await[0][1]["list"][0].clone();
    assert_eq!(stored["mailboxIds"], json!({ &sent: true }));
    assert_eq!(stored["keywords"], json!({ "$seen": true }));
    assert_eq!(stored["bcc"][0]["email"], "hidden@remote.example");
    assert_eq!(stored["subject"], "Quarterly reportX-Injected: yes", "CRLF in the subject cannot add headers");
    assert_eq!(stored["attachments"][0]["name"], "report.json");
    assert_eq!(stored["hasAttachment"], true);
    let attachment = api.get(&format!("/jmap/download/{account}/{}/report.json", stored["attachments"][0]["blobId"].as_str().unwrap())).await;
    assert_eq!(attachment.body, json!({ "report": [1, 2, 3] }));
    assert_eq!(attachment.headers["content-type"], "application/octet-stream", "attachments are never rendered in our origin");
    assert!(attachment.headers["content-disposition"].to_str().unwrap().starts_with("attachment"));

    // Local recipient got it directly; remote recipients (including Bcc) through the queue.
    let carol_inbox = env.inbox(&carol).await;
    assert_eq!(carol_inbox.len(), 1);
    assert!(!carol_inbox[0].to_ascii_lowercase().contains("bcc:"), "Bcc is not disclosed to other recipients");
    assert!(!carol_inbox[0].contains("hidden@remote.example"));
    queue::process_due(&env.app).await;
    let received = sink.received();
    let mut recipients: Vec<&str> = received.iter().map(|m| m.to.as_str()).collect();
    recipients.sort();
    assert_eq!(recipients, ["friend@remote.example", "hidden@remote.example"]);
    assert!(received.iter().all(|m| m.from == "bob@example.org" && !m.data.contains("hidden@remote.example")));
    assert!(received[0].data.contains("multipart/") && received[0].data.contains("report.json"));

    // Sending as someone else is refused by the same rules as SMTP submission.
    let spoof = json!({ "mailboxIds": { &drafts: true }, "from": [{ "email": "carol@example.org" }], "to": [{ "email": "friend@remote.example" }], "subject": "spoof", "bodyValues": { "t": { "value": "x" } }, "textBody": [{ "partId": "t" }] });
    let refused = api
        .jmap(json!([
            ["Email/set", { "accountId": account, "create": { "d": spoof } }, "c"],
            ["EmailSubmission/set", { "accountId": account, "create": { "s": { "emailId": "#d" } } }, "s"],
        ]))
        .await;
    assert_eq!(refused[1][1]["notCreated"]["s"]["type"], "forbiddenToSend", "{refused}");
    assert_eq!(sink.received().len(), 2);

    let invalid = api
        .jmap(json!([["Email/set", { "accountId": account, "create": {
            "a": { "mailboxIds": { &drafts: true }, "to": [{ "email": "not an address" }] },
            "b": { "mailboxIds": {}, "subject": "nowhere" },
            "c": { "mailboxIds": { "b99999": true }, "subject": "unknown mailbox" },
        } }, "c"]]))
        .await;
    assert_eq!(invalid[0][1]["notCreated"].as_object().unwrap().len(), 3, "{invalid}");
}

#[tokio::test]
async fn folders_can_be_created_renamed_and_deleted() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    deliver(&env, "bob@example.org", "Keep", "x").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;
    let inbox = mailbox_id(&mailboxes(&api, &account).await, "inbox");

    let created = api.jmap(json!([["Mailbox/set", { "accountId": account, "create": { "n": { "name": "Projects" }, "bad": { "name": "a%b" }, "dup": { "name": "INBOX" } } }, "c"]])).await;
    let folder = created[0][1]["created"]["n"]["id"].as_str().unwrap().to_owned();
    assert_eq!(created[0][1]["notCreated"].as_object().unwrap().len(), 2);

    let email = api.jmap(json!([["Email/query", { "accountId": account, "filter": { "inMailbox": inbox } }, "q"]])).await[0][1]["ids"][0].as_str().unwrap().to_owned();
    api.jmap(json!([["Email/set", { "accountId": account, "update": { &email: { "mailboxIds": { &folder: true } } } }, "m"]])).await;

    let changes = api
        .jmap(json!([
            ["Mailbox/set", { "accountId": account, "update": { &folder: { "name": "Work" }, &inbox: { "name": "Renamed" } } }, "r"],
            ["Mailbox/set", { "accountId": account, "destroy": [folder, inbox] }, "d"],
        ]))
        .await;
    assert_eq!(changes[0][1]["updated"], json!({ &folder: null }));
    assert_eq!(changes[0][1]["notUpdated"][&inbox]["type"], "invalidProperties", "system folders cannot be renamed");
    assert_eq!(changes[1][1]["notDestroyed"][&folder]["type"], "mailboxHasEmail");
    assert!(changes[1][1]["notDestroyed"][&inbox].is_object());

    let removed = api.jmap(json!([["Mailbox/set", { "accountId": account, "destroy": [folder], "onDestroyRemoveEmails": true }, "d"]])).await;
    assert_eq!(removed[0][1]["destroyed"], json!([folder]));
    let used: i64 = sqlx::query_scalar("SELECT used_bytes FROM accounts WHERE email = 'bob@example.org'").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(used, 0, "quota is released with the folder");
}

#[tokio::test]
async fn request_limits_and_malformed_input() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;

    let too_many: Vec<Value> = (0..33).map(|i| json!(["Core/echo", {}, i.to_string()])).collect();
    assert_eq!(api.post("/jmap/api", json!({ "methodCalls": too_many })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.post("/jmap/api", json!({ "nope": true })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.post("/jmap/api", json!({ "methodCalls": [["Core/echo"]] })).await.status, StatusCode::BAD_REQUEST);

    let ids: Vec<String> = (0..501).map(|i| format!("m{i}")).collect();
    let big = api.jmap(json!([["Email/get", { "accountId": account, "ids": ids }, "g"]])).await;
    assert_eq!(big[0][1]["type"], "requestTooLarge");
    let injection = api.jmap(json!([["Email/get", { "accountId": account, "ids": ["m1 OR 1=1", "m1; DROP TABLE messages", "../../x"] }, "g"]])).await;
    assert_eq!(injection[0][1]["notFound"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn changes_and_query_changes_report_incremental_updates() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    deliver(&env, "bob@example.org", "Old", "x").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;
    let inbox = mailbox_id(&mailboxes(&api, &account).await, "inbox");

    let first = api.jmap(json!([["Email/query", { "accountId": account, "filter": { "inMailbox": inbox } }, "q"], ["Email/get", { "accountId": account, "ids": [] }, "g"]])).await;
    assert_eq!(first[0][1]["canCalculateChanges"], true);
    let query_state = first[0][1]["queryState"].as_str().unwrap().to_owned();
    let state = first[1][1]["state"].as_str().unwrap().to_owned();
    let old_id = first[0][1]["ids"][0].as_str().unwrap().to_owned();
    assert_eq!(api.get("/jmap/session").await.body["state"], state);

    // Nothing happened yet.
    let none = api.jmap(json!([["Email/changes", { "accountId": account, "sinceState": state }, "c"]])).await;
    assert_eq!(none[0][1]["created"], json!([]));
    assert_eq!(none[0][1]["newState"], state);

    deliver(&env, "bob@example.org", "New", "y").await;
    api.jmap(json!([["Email/set", { "accountId": account, "update": { &old_id: { "keywords/$seen": true, "keywords/project-x": true } } }, "u"]])).await;

    let changes = api
        .jmap(json!([
            ["Email/changes", { "accountId": account, "sinceState": state }, "e"],
            ["Mailbox/changes", { "accountId": account, "sinceState": state }, "m"],
            ["Thread/changes", { "accountId": account, "sinceState": state }, "t"],
            ["Email/queryChanges", { "accountId": account, "filter": { "inMailbox": inbox }, "sinceQueryState": query_state, "calculateTotal": true }, "q"],
        ]))
        .await;
    assert_eq!(changes[0][1]["created"].as_array().unwrap().len(), 1);
    assert_eq!(changes[0][1]["updated"], json!([old_id]));
    assert_eq!(changes[0][1]["destroyed"], json!([]));
    assert_eq!(changes[0][1]["hasMoreChanges"], false);
    let new_id = changes[0][1]["created"][0].as_str().unwrap().to_owned();
    assert_eq!(changes[1][1]["updated"], json!([inbox]));
    assert_eq!(changes[2][1]["created"].as_array().unwrap().len(), 1, "{changes}");
    assert_eq!(changes[2][1]["updated"].as_array().unwrap().len(), 1);
    assert_eq!(changes[3][1]["total"], 2);
    assert_eq!(changes[3][1]["added"], json!([{ "id": new_id, "index": 0 }, { "id": old_id, "index": 1 }]));
    let new_state = changes[0][1]["newState"].as_str().unwrap().to_owned();
    assert_ne!(new_state, state);

    // Labels (custom keywords) are queryable.
    let labelled = api
        .jmap(json!([
            ["Email/query", { "accountId": account, "filter": { "hasKeyword": "project-x" } }, "a"],
            ["Email/query", { "accountId": account, "filter": { "inMailbox": inbox, "notKeyword": "project-x" } }, "b"],
        ]))
        .await;
    assert_eq!(labelled[0][1]["ids"], json!([old_id]));
    assert_eq!(labelled[1][1]["ids"], json!([new_id]));

    api.jmap(json!([["Email/set", { "accountId": account, "destroy": [new_id] }, "d"]])).await;
    let after = api
        .jmap(json!([
            ["Email/changes", { "accountId": account, "sinceState": new_state }, "e"],
            ["Email/changes", { "accountId": account, "sinceState": state }, "f"],
            ["Email/changes", { "accountId": account, "sinceState": state, "maxChanges": 1 }, "g"],
            ["Email/changes", { "accountId": account, "sinceState": "not-a-state" }, "h"],
        ]))
        .await;
    assert_eq!(after[0][1]["destroyed"], json!([new_id]));
    assert_eq!(after[1][1]["created"], json!([]), "created and destroyed since the old state cancels out");
    assert_eq!(after[1][1]["updated"], json!([old_id]));
    assert_eq!(after[2][1]["hasMoreChanges"], true);
    assert_eq!(after[3][1]["type"], "cannotCalculateChanges");
}

#[tokio::test]
async fn avatar_sources_come_in_one_batch() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account("carol@example.org").await;
    deliver(&env, "bob@example.org", "One", "x").await;
    deliver(&env, "bob@example.org", "Two", "y").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;
    let ids = api.jmap(json!([["Email/query", { "accountId": account }, "q"]])).await[0][1]["ids"].clone();
    let list: Vec<&str> = ids.as_array().unwrap().iter().map(|id| id.as_str().unwrap()).collect();
    let reply = api.get(&format!("/jmap/avatars/{account}?ids={},m999999,bogus", list.join(","))).await;
    assert_eq!(reply.status, StatusCode::OK);
    // Mail delivered from a private address is not verified: no picture, and every id is answered.
    for id in list.iter().copied().chain(["m999999", "bogus"]) {
        assert_eq!(reply.body[id], "none", "{id}: {}", reply.body);
    }
    // Another account's messages are not looked at.
    let carol = Api::logged_in(&env, "carol@example.org").await;
    assert_eq!(carol.get(&format!("/jmap/avatars/{account}?ids={}", list[0])).await.status, StatusCode::NOT_FOUND);
}
