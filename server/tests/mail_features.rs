//! Scheduled and undoable sending, snoozing and read receipts.

mod common;

use common::{Api, Client, TestEnv, message};
use serde_json::{Value, json};

fn mailbox_id(mailboxes: &Value, role: &str) -> String {
    mailboxes.as_array().unwrap().iter().find(|m| m["role"] == role).unwrap()["id"].as_str().unwrap().to_owned()
}

async fn mailboxes(api: &Api, account: &str) -> Value {
    api.jmap(json!([["Mailbox/get", { "accountId": account }, "0"]])).await[0][1]["list"].clone()
}

async fn draft(api: &Api, account: &str, drafts: &str, subject: &str) -> String {
    let created = api
        .jmap(json!([["Email/set", { "accountId": account, "create": { "d": {
            "mailboxIds": { drafts: true }, "keywords": { "$draft": true, "$seen": true },
            "from": [{ "email": "bob@example.org" }], "to": [{ "email": "carol@example.org" }],
            "subject": subject, "bodyValues": { "t": { "value": "hello" } }, "textBody": [{ "partId": "t", "type": "text/plain" }],
        } } }, "0"]]))
        .await;
    created[0][1]["created"]["d"]["id"].as_str().unwrap_or_else(|| panic!("{created}")).to_owned()
}

#[tokio::test]
async fn sending_can_wait_and_be_undone() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let carol = env.account("carol@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;
    let session = api.get("/jmap/session").await.body;
    assert_eq!(session["capabilities"]["urn:ietf:params:jmap:submission"]["maxDelayedSend"], 30 * 86_400);
    let boxes = mailboxes(&api, &account).await;
    let (drafts, sent) = (mailbox_id(&boxes, "drafts"), mailbox_id(&boxes, "sent"));
    let move_to_sent = json!({ "#s": { "mailboxIds": { &sent: true }, "keywords/$draft": null } });

    // Held for a minute: nothing goes out, the draft is marked scheduled.
    let email = draft(&api, &account, &drafts, "Later").await;
    let held = api.jmap(json!([["EmailSubmission/set", { "accountId": account, "create": { "s": { "emailId": email, "envelope": { "mailFrom": { "email": "bob@example.org", "parameters": { "HOLDFOR": "60" } }, "rcptTo": [{ "email": "carol@example.org" }] } } }, "onSuccessUpdateEmail": move_to_sent }, "0"]])).await;
    let submission = held[0][1]["created"]["s"].clone();
    assert_eq!(submission["undoStatus"], "pending", "{held}");
    let submission_id = submission["id"].as_str().unwrap().to_owned();
    // Within the undo window it already looks sent.
    let got = api.jmap(json!([["Email/get", { "accountId": account, "ids": [email], "properties": ["keywords", "mailboxIds"] }, "0"]])).await;
    assert_eq!(got[0][1]["list"][0]["keywords"]["$scheduled"], true);
    assert!(got[0][1]["list"][0]["mailboxIds"][&sent].as_bool().unwrap(), "{got}");
    let pending = api.jmap(json!([["EmailSubmission/query", { "accountId": account, "filter": { "undoStatus": "pending" } }, "0"]])).await;
    assert_eq!(pending[0][1]["ids"], json!([submission_id]));

    // Undo: it stays a draft.
    let undone = api.jmap(json!([["EmailSubmission/set", { "accountId": account, "update": { &submission_id: { "undoStatus": "canceled" } } }, "0"]])).await;
    assert!(undone[0][1]["updated"].as_object().unwrap().contains_key(&submission_id), "{undone}");
    unomail::jmap::submission::release_due(&env.app).await;
    assert!(env.inbox(&carol).await.is_empty());
    let got = api.jmap(json!([["Email/get", { "accountId": account, "ids": [email], "properties": ["keywords", "mailboxIds"] }, "0"]])).await;
    assert!(got[0][1]["list"][0]["keywords"].get("$scheduled").is_none());
    assert_eq!(got[0][1]["list"][0]["keywords"]["$draft"], true, "a draft again");
    assert!(got[0][1]["list"][0]["mailboxIds"][&drafts].as_bool().unwrap(), "back in Drafts: {got}");

    // Scheduled for later: it waits in Drafts.
    let email = draft(&api, &account, &drafts, "Tomorrow").await;
    let later = api.jmap(json!([["EmailSubmission/set", { "accountId": account, "create": { "s": { "emailId": email, "envelope": { "mailFrom": { "email": "bob@example.org", "parameters": { "HOLDFOR": "3600" } }, "rcptTo": [] } } }, "onSuccessUpdateEmail": move_to_sent }, "0"]])).await;
    let later_id = later[0][1]["created"]["s"]["id"].as_str().unwrap().to_owned();
    let got = api.jmap(json!([["Email/get", { "accountId": account, "ids": [email], "properties": ["mailboxIds"] }, "0"]])).await;
    assert!(got[0][1]["list"][0]["mailboxIds"][&drafts].as_bool().unwrap());
    api.jmap(json!([["EmailSubmission/set", { "accountId": account, "destroy": [later_id] }, "0"]])).await;

    // Scheduled for a moment that has come: sent, then moved to Sent.
    let email = draft(&api, &account, &drafts, "Scheduled").await;
    let scheduled = api.jmap(json!([["EmailSubmission/set", { "accountId": account, "create": { "s": { "emailId": email, "envelope": { "mailFrom": { "email": "bob@example.org", "parameters": { "HOLDFOR": 1 } }, "rcptTo": [] } } }, "onSuccessUpdateEmail": move_to_sent }, "0"]])).await;
    let submission_id = scheduled[0][1]["created"]["s"]["id"].as_str().unwrap().to_owned();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    unomail::jmap::submission::release_due(&env.app).await;
    let inbox = env.inbox(&carol).await;
    assert_eq!(inbox.len(), 1);
    assert!(inbox[0].contains("Subject: Scheduled"));
    let got = api.jmap(json!([["Email/get", { "accountId": account, "ids": [email], "properties": ["keywords", "mailboxIds"] }, "0"]])).await;
    assert!(got[0][1]["list"][0]["mailboxIds"][&sent].as_bool().unwrap(), "{got}");
    let late = api.jmap(json!([["EmailSubmission/set", { "accountId": account, "update": { &submission_id: { "undoStatus": "canceled" } } }, "0"]])).await;
    assert_eq!(late[0][1]["notUpdated"][&submission_id]["type"], "cannotUnsend");
    let too_far = api.jmap(json!([["EmailSubmission/set", { "accountId": account, "create": { "s": { "emailId": email, "envelope": { "mailFrom": { "email": "bob@example.org", "parameters": { "HOLDUNTIL": "2099-01-01T00:00:00Z" } }, "rcptTo": [] } } } }, "0"]])).await;
    assert_eq!(too_far[0][1]["notCreated"]["s"]["type"], "invalidProperties");
}

#[tokio::test]
async fn snoozed_mail_comes_back_on_top_and_unread() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let mut smtp = Client::smtp(env.mx).await;
    assert!(smtp.send_mail("alice@remote.example", &["bob@example.org"], &message("alice@remote.example", "bob@example.org", "Deal with later", "x")).await.starts_with("250"));
    let inbox = env.app.store.mailbox_by_role(bob.id, "inbox").await.unwrap().unwrap();
    let message_id = env.app.store.messages_in(inbox.id).await.unwrap()[0].id;
    env.app.store.set_flags(bob.id, message_id, unomail::store::Flags { seen: true, ..Default::default() }).await.unwrap();

    let until = unomail::util::now() + 3600;
    assert_eq!(api.post("/api/me/snoozes", json!({ "email_ids": [format!("m{message_id}")], "until": unomail::util::now() - 5 })).await.status, axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(api.post("/api/me/snoozes", json!({ "email_ids": [format!("m{message_id}")], "until": until })).await.status, axum::http::StatusCode::OK);
    assert!(env.app.store.messages_in(inbox.id).await.unwrap().is_empty());
    let snoozed = env.app.store.mailbox_by_role(bob.id, "snoozed").await.unwrap().expect("a Snoozed folder");
    assert_eq!(snoozed.name, "Snoozed");
    assert_eq!(api.get("/api/me/snoozes").await.body, json!([{ "email_id": format!("m{message_id}"), "until": until }]));

    // Not yet due.
    unomail::snooze::wake_due(&env.app).await;
    assert!(env.app.store.messages_in(inbox.id).await.unwrap().is_empty());
    sqlx::query("UPDATE snoozes SET until = 0").execute(&env.app.db).await.unwrap();
    unomail::snooze::wake_due(&env.app).await;
    let back = env.app.store.messages_in(inbox.id).await.unwrap();
    assert_eq!(back.len(), 1);
    assert!(!back[0].seen, "unread again");
    assert!(back[0].internal_date >= unomail::util::now() - 5, "on top of the inbox");
    assert_eq!(api.get("/api/me/snoozes").await.body, json!([]));
}

#[tokio::test]
async fn read_receipts_go_out_once_when_asked_for() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let alice = env.account("alice@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;
    assert!(api.get("/jmap/session").await.body["capabilities"]["urn:ietf:params:jmap:mdn"].is_object());
    let mut mx = Client::smtp(env.mx).await;
    let mail = "From: Alice <alice@example.org>\r\nTo: bob@example.org\r\nSubject: Did you read it?\r\nMessage-ID: <q1@example.org>\r\nDisposition-Notification-To: Alice <alice@example.org>\r\n\r\nPlease confirm.\r\n";
    assert!(mx.send_mail("alice@example.org", &["bob@example.org"], mail).await.starts_with("250"));
    let inbox = env.app.store.mailbox_by_role(bob.id, "inbox").await.unwrap().unwrap();
    let email = format!("m{}", env.app.store.messages_in(inbox.id).await.unwrap()[0].id);
    let got = api.jmap(json!([["Email/get", { "accountId": account, "ids": [email], "properties": ["receiptRequestedBy"] }, "0"]])).await;
    assert_eq!(got[0][1]["list"][0]["receiptRequestedBy"], "alice@example.org");

    let sent = api.jmap(json!([["MDN/send", { "accountId": account, "identityId": "i1", "send": { "r": { "forEmailId": email, "disposition": { "actionMode": "manual-action", "sendingMode": "mdn-sent-manually", "type": "displayed" } } } }, "0"]])).await;
    assert!(sent[0][1]["sent"]["r"].is_object(), "{sent}");
    let receipt = env.inbox(&alice).await.pop().unwrap();
    assert!(receipt.contains("report-type=disposition-notification") && receipt.contains("Subject: Read: Did you read it?"), "{receipt}");
    assert!(receipt.contains("Original-Message-ID: <q1@example.org>") && receipt.contains("Disposition: manual-action/MDN-sent-manually; displayed"));
    let got = api.jmap(json!([["Email/get", { "accountId": account, "ids": [email], "properties": ["keywords"] }, "0"]])).await;
    assert_eq!(got[0][1]["list"][0]["keywords"]["$mdnsent"], true);
    let again = api.jmap(json!([["MDN/send", { "accountId": account, "identityId": "i1", "send": { "r": { "forEmailId": email, "disposition": {} } } }, "0"]])).await;
    assert_eq!(again[0][1]["notSent"]["r"]["type"], "mdnAlreadySent");

    // A message whose receipt address is someone other than its sender: no automatic receipt.
    let mail = "From: Spammer <spam@example.org>\r\nTo: bob@example.org\r\nSubject: Buy now\r\nDisposition-Notification-To: victim@remote.example\r\n\r\nx\r\n";
    let reply = mx.send_mail("spam@example.org", &["bob@example.org"], mail).await;
    assert!(reply.starts_with("250"), "{reply}");
    let email = format!("m{}", env.app.store.messages_in(inbox.id).await.unwrap().iter().map(|m| m.id).max().unwrap());
    let got = api.jmap(json!([["Email/get", { "accountId": account, "ids": [email], "properties": ["receiptRequestedBy", "receiptAutomaticAllowed"] }, "0"]])).await;
    assert_eq!(got[0][1]["list"][0]["receiptAutomaticAllowed"], false);
    let automatic = api.jmap(json!([["MDN/send", { "accountId": account, "identityId": "i1", "send": { "r": { "forEmailId": email, "disposition": { "actionMode": "automatic-action", "sendingMode": "mdn-sent-automatically", "type": "displayed" } } } }, "0"]])).await;
    assert_eq!(automatic[0][1]["notSent"]["r"]["type"], "forbidden", "{automatic}");
}
