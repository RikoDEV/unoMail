//! Web mail features: sender identities, the address book, response templates, preferences,
//! folder export/import, the remote image proxy and the extension points.

mod common;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::http::{Method, StatusCode};
use common::{Api, Sink, TestEnv};
use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use unomail::{auth::Role, smtp::queue};

async fn env_with_bob() -> (TestEnv, Api) {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    (env, api)
}

/// A one-shot HTTP server that answers every request with the given response and records what
/// it was sent.
async fn http_server(response: Vec<u8>) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen = requests.clone();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let (response, seen) = (response.clone(), seen.clone());
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = tcp.read(&mut chunk).await.unwrap_or(0);
                    request.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&request).into_owned();
                    let Some(head_end) = text.find("\r\n\r\n") else {
                        if n == 0 {
                            return;
                        }
                        continue;
                    };
                    let length: usize = text.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v| v.trim().parse().ok())).unwrap_or(0);
                    if request.len() >= head_end + 4 + length || n == 0 {
                        seen.lock().push(text);
                        break;
                    }
                }
                let _ = tcp.write_all(&response).await;
                let _ = tcp.shutdown().await;
            });
        }
    });
    (addr, requests)
}

fn http_response(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    out.extend_from_slice(body);
    out
}

async fn send_as(api: &Api, from: Value, to: &str, subject: &str) -> Value {
    let account = api.jmap_account().await;
    let boxes = api.jmap(json!([["Mailbox/get", { "accountId": account }, "0"]])).await[0][1]["list"].clone();
    let drafts = boxes.as_array().unwrap().iter().find(|m| m["role"] == "drafts").unwrap()["id"].as_str().unwrap().to_owned();
    api.jmap(json!([
        ["Email/set", { "accountId": account, "create": { "d": { "mailboxIds": { &drafts: true }, "from": from, "to": [{ "email": to }], "subject": subject, "bodyValues": { "t": { "value": "hi" } }, "textBody": [{ "partId": "t" }] } } }, "c"],
        ["EmailSubmission/set", { "accountId": account, "create": { "s": { "emailId": "#d" } } }, "s"],
    ]))
    .await
}

#[tokio::test]
async fn identities_are_limited_to_owned_addresses_unless_they_bring_their_own_server() {
    let sink = Sink::start().await;
    let (env, api) = env_with_bob().await;
    env.account("carol@example.org").await;
    env.alias("sales@example.org", &["bob@example.org"]).await;

    // The account's own address is its primary identity, there from the start.
    let list = api.get("/api/me/identities").await.body;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!((list[0]["email"].as_str(), list[0]["primary"].as_bool(), list[0]["is_default"].as_bool()), (Some("bob@example.org"), Some(true), Some(true)));
    let primary_id = list[0]["id"].as_i64().unwrap();
    assert!(primary_id > 0, "the primary identity is stored like any other");
    assert_eq!(api.delete(&format!("/api/me/identities/{primary_id}")).await.status, StatusCode::BAD_REQUEST, "and cannot be deleted");
    let moved = api.put(&format!("/api/me/identities/{primary_id}"), json!({ "name": "Bob", "email": "sales@example.org" })).await;
    assert_eq!(moved.status, StatusCode::BAD_REQUEST, "its address is the account's own");

    let sales = api.post("/api/me/identities", json!({ "name": "Sales Team", "email": "Sales@Example.org", "reply_to": "bob@example.org", "is_default": true })).await;
    assert_eq!(sales.status, StatusCode::OK, "{}", sales.text);
    assert_eq!(sales.body["email"], "sales@example.org");
    // Somebody else's address cannot be claimed, and neither can an arbitrary outside one.
    for foreign in ["carol@example.org", "ceo@elsewhere.example"] {
        let refused = api.post("/api/me/identities", json!({ "email": foreign })).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{foreign}");
    }
    for bad in [json!({ "email": "not an address" }), json!({ "email": "bob@example.org", "reply_to": "nope" })] {
        assert_ne!(api.post("/api/me/identities", bad.clone()).await.status, StatusCode::OK, "{bad}");
    }
    let list = api.get("/api/me/identities").await.body;
    assert_eq!(list.as_array().unwrap().len(), 2);
    assert_eq!((list[0]["email"].as_str(), list[1]["is_default"].as_bool()), (Some("sales@example.org"), Some(false)), "the default identity comes first");

    // One address may have several identities: another name, without touching the primary one.
    let support = api.post("/api/me/identities", json!({ "name": "Bob · Support", "email": "bob@example.org", "reply_to": "sales@example.org" })).await;
    assert_eq!(support.status, StatusCode::OK, "{}", support.text);
    let list = api.get("/api/me/identities").await.body;
    assert_eq!(list.as_array().unwrap().len(), 3);
    let primary = list.as_array().unwrap().iter().find(|identity| identity["primary"] == true).unwrap();
    assert_eq!((primary["id"].as_i64(), primary["name"].as_str()), (Some(primary_id), Some("")), "the primary identity keeps its name");
    let support_id = support.body["id"].as_i64().unwrap();
    assert_eq!(api.delete(&format!("/api/me/identities/{support_id}")).await.status, StatusCode::OK);

    // The addresses this account can send from without a server of its own.
    let addresses = api.get("/api/me/identities/addresses").await.body;
    assert_eq!(addresses, json!([{ "email": "bob@example.org", "kind": "own" }, { "email": "sales@example.org", "kind": "alias" }]));

    // JMAP clients see the same identities, with the signature chosen for new messages.
    let signature = api.post("/api/me/signatures", json!({ "name": "Sales", "html": "<p>-- <br>Sales</p>" })).await.body;
    let chosen = api.put("/api/me/signatures/defaults", json!({ "identity_id": sales.body["id"], "new_signature_id": signature["id"], "reply_signature_id": null })).await;
    assert_eq!(chosen.status, StatusCode::OK, "{}", chosen.text);
    let account = api.jmap_account().await;
    let identities = api.jmap(json!([["Identity/get", { "accountId": account }, "i"]])).await[0][1]["list"].clone();
    assert_eq!(identities[0]["htmlSignature"], "<p>-- <br>Sales</p>");
    assert_eq!(identities[0]["replyTo"][0]["email"], "bob@example.org");

    // Sending as the alias works and is delivered locally; sending as a stranger does not.
    let sent = send_as(&api, json!([{ "name": "Sales Team", "email": "sales@example.org" }]), "carol@example.org", "Offer").await;
    assert!(sent[1][1]["created"]["s"].is_object(), "{sent}");
    let carol = unomail::auth::Account::by_email(&env.app.db, "carol@example.org").await.unwrap().unwrap();
    assert!(env.inbox(&carol).await[0].contains("From: \"Sales Team\" <sales@example.org>"));
    let forged = send_as(&api, json!([{ "email": "ceo@elsewhere.example" }]), "carol@example.org", "Forged").await;
    assert_eq!(forged[1][1]["notCreated"]["s"]["type"], "forbiddenToSend", "{forged}");

    // An identity with its own SMTP server: any address, relayed through that server only.
    let external = json!({ "name": "Bob at Elsewhere", "email": "bob@elsewhere.example", "smtp": { "host": "127.0.0.1", "port": sink.addr.port(), "security": "none", "username": "", "password": "s3cret" } });
    let created = api.post("/api/me/identities", external).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    assert_eq!(created.body["smtp"], json!({ "host": "127.0.0.1", "port": sink.addr.port(), "security": "none", "username": "", "has_password": true }));
    assert!(!created.text.contains("s3cret"), "the password is never returned");
    let stored: String = sqlx::query_scalar("SELECT smtp_password FROM identities WHERE email = 'bob@elsewhere.example'").fetch_one(&env.app.db).await.unwrap();
    assert!(stored.starts_with("v1:") && !stored.contains("s3cret"), "the password is encrypted at rest");

    let relayed = send_as(&api, json!([{ "email": "bob@elsewhere.example" }]), "carol@example.org", "Via my provider").await;
    assert!(relayed[1][1]["created"]["s"].is_object(), "{relayed}");
    queue::process_due(&env.app).await;
    let received = sink.received();
    assert_eq!(received.len(), 1, "even the local recipient is reached through the identity's server");
    assert_eq!((received[0].from.as_str(), received[0].to.as_str()), ("bob@elsewhere.example", "carol@example.org"));
    assert!(!received[0].data.contains("DKIM-Signature"), "the other provider signs its own mail");
    assert_eq!(env.inbox(&carol).await.len(), 1, "nothing was delivered directly");

    // Editing keeps the stored password.
    let id = created.body["id"].as_i64().unwrap();
    let edited = api.put(&format!("/api/me/identities/{id}"), json!({ "email": "bob@elsewhere.example", "smtp": { "host": "127.0.0.1", "port": sink.addr.port(), "security": "none" } })).await;
    assert_eq!(edited.body["smtp"]["has_password"], true, "{}", edited.text);
    // A second identity with that address shares its server, password included.
    let twin = api.post("/api/me/identities", json!({ "name": "Bob privately", "email": "bob@elsewhere.example" })).await;
    assert_eq!(twin.status, StatusCode::OK, "{}", twin.text);
    assert_eq!((twin.body["smtp"]["host"].as_str(), twin.body["smtp"]["has_password"].as_bool()), (Some("127.0.0.1"), Some(true)));
    // Sending as the address works while any of its identities remains; then it stops.
    assert_eq!(api.delete(&format!("/api/me/identities/{id}")).await.status, StatusCode::OK);
    let still = send_as(&api, json!([{ "email": "bob@elsewhere.example" }]), "carol@example.org", "Still").await;
    assert!(still[1][1]["created"]["s"].is_object(), "{still}");
    let twin_id = twin.body["id"].as_i64().unwrap();
    assert_eq!(api.delete(&format!("/api/me/identities/{twin_id}")).await.status, StatusCode::OK);
    let after = send_as(&api, json!([{ "email": "bob@elsewhere.example" }]), "carol@example.org", "Again").await;
    assert_eq!(after[1][1]["notCreated"]["s"]["type"], "forbiddenToSend");

    // Identities are private to their account.
    let carol_api = Api::logged_in(&env, "carol@example.org").await;
    assert_eq!(carol_api.get("/api/me/identities").await.body.as_array().unwrap().len(), 1);
    let sales_id = sales.body["id"].as_i64().unwrap();
    assert_eq!(carol_api.delete(&format!("/api/me/identities/{sales_id}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(carol_api.put(&format!("/api/me/identities/{sales_id}"), json!({ "email": "carol@example.org" })).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn signatures_are_named_and_chosen_per_identity() {
    let (env, api) = env_with_bob().await;
    env.account("carol@example.org").await;
    let primary = api.get("/api/me/identities").await.body[0]["id"].as_i64().unwrap();
    let key = primary.to_string();
    let empty = api.get("/api/me/signatures").await.body;
    assert_eq!(empty, json!({ "signatures": [], "defaults": { &key: { "new_signature_id": null, "reply_signature_id": null } } }), "the primary identity is listed from the start");

    for bad in [json!({ "name": "" }), json!({ "name": "Long", "html": "x".repeat(300_000) })] {
        assert_eq!(api.post("/api/me/signatures", bad.clone()).await.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let full = api.post("/api/me/signatures", json!({ "name": "Full", "html": "<p>Bob<br><b>Example Org</b></p>" })).await.body;
    let short = api.post("/api/me/signatures", json!({ "name": "Short", "html": "<p>B.</p>" })).await.body;
    assert_eq!(api.post("/api/me/signatures", json!({ "name": "Short" })).await.status, StatusCode::CONFLICT, "names are unique");
    let (full_id, short_id) = (full["id"].as_i64().unwrap(), short["id"].as_i64().unwrap());

    // New messages and replies can use different signatures.
    let chosen = api.put("/api/me/signatures/defaults", json!({ "identity_id": primary, "new_signature_id": full_id, "reply_signature_id": short_id })).await;
    assert_eq!(chosen.status, StatusCode::OK, "{}", chosen.text);
    let listed = api.get("/api/me/signatures").await.body;
    assert_eq!(listed["signatures"].as_array().unwrap().len(), 2);
    assert_eq!(listed["defaults"][&key], json!({ "new_signature_id": full_id, "reply_signature_id": short_id }));
    assert_eq!(api.get("/api/me/identities").await.body[0]["signature_html"], "<p>Bob<br><b>Example Org</b></p>");

    // Only one's own identities and signatures.
    let carol = Api::logged_in(&env, "carol@example.org").await;
    let carol_primary = carol.get("/api/me/identities").await.body[0]["id"].as_i64().unwrap();
    assert_eq!(api.put("/api/me/signatures/defaults", json!({ "identity_id": carol_primary, "new_signature_id": full_id })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(carol.put("/api/me/signatures/defaults", json!({ "identity_id": carol_primary, "new_signature_id": full_id })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(carol.put(&format!("/api/me/signatures/{full_id}"), json!({ "name": "Mine" })).await.status, StatusCode::NOT_FOUND);
    assert_eq!(carol.delete(&format!("/api/me/signatures/{full_id}")).await.status, StatusCode::NOT_FOUND);

    // Editing changes what the identity sends; deleting leaves it without a signature.
    assert_eq!(api.put(&format!("/api/me/signatures/{full_id}"), json!({ "name": "Full", "html": "<p>Bob</p>" })).await.status, StatusCode::OK);
    assert_eq!(api.get("/api/me/identities").await.body[0]["signature_html"], "<p>Bob</p>");
    assert_eq!(api.delete(&format!("/api/me/signatures/{full_id}")).await.status, StatusCode::OK);
    assert_eq!(api.get("/api/me/signatures").await.body["defaults"][&key], json!({ "new_signature_id": null, "reply_signature_id": short_id }));
    assert_eq!(api.get("/api/me/identities").await.body[0]["signature_html"], "");
}

#[tokio::test]
async fn identity_servers_must_be_encrypted_and_public_outside_test_mode() {
    let env = TestEnv::start_with(|cfg| cfg.identity_relay_allow_private = false).await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let plain = api.post("/api/me/identities", json!({ "email": "bob@elsewhere.example", "smtp": { "host": "smtp.elsewhere.example", "port": 25, "security": "none" } })).await;
    assert_eq!(plain.status, StatusCode::BAD_REQUEST, "credentials are never sent in the clear");

    // A server on a private address is accepted as configuration but never contacted.
    let internal = api.post("/api/me/identities", json!({ "email": "bob@elsewhere.example", "smtp": { "host": "127.0.0.1", "port": 9, "security": "starttls" } })).await;
    assert_eq!(internal.status, StatusCode::OK, "{}", internal.text);
    let relay = unomail::smtp::client::Relay::load(&env.app, internal.body["id"].as_i64().unwrap()).await.unwrap().unwrap();
    let rcpt = unomail::util::Address::parse("x@remote.example").unwrap();
    let err = unomail::smtp::client::deliver_via(&env.app, &relay, "bob@elsewhere.example", &rcpt, b"Subject: x\r\n\r\nx").await.unwrap_err();
    assert_eq!(err, unomail::smtp::client::SendError::Permanent("the SMTP server resolves to a private address".into()));
}

#[tokio::test]
async fn address_book_with_groups_vcards_and_suggestions() {
    let (env, api) = env_with_bob().await;
    env.account("carol@example.org").await;
    env.domain("other.example").await;
    env.account("carl@other.example").await;

    let ann = api.post("/api/me/contacts", json!({ "name": "Ann Example", "email": "Ann@Remote.example", "phone": "+48 600", "organization": "ACME", "notes": "met at\nthe fair" })).await;
    assert_eq!(ann.status, StatusCode::OK, "{}", ann.text);
    assert_eq!((ann.body["email"].as_str(), ann.body["notes"].as_str()), (Some("ann@remote.example"), Some("met at\nthe fair")));
    assert_eq!(api.post("/api/me/contacts", json!({ "email": "ann@remote.example" })).await.status, StatusCode::CONFLICT);
    for bad in [json!({ "email": "nope" }), json!({ "email": "x@remote.example", "pgp_key": "not a key" }), json!({ "email": "x@remote.example", "name": "n".repeat(300) })] {
        assert_eq!(api.post("/api/me/contacts", bad.clone()).await.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let carl = api.post("/api/me/contacts", json!({ "name": "Carl", "email": "carl@remote.example" })).await.body;
    let (ann_id, carl_id) = (ann.body["id"].as_i64().unwrap(), carl["id"].as_i64().unwrap());
    let renamed = api.put(&format!("/api/me/contacts/{ann_id}"), json!({ "name": "Ann E.", "email": "ann@remote.example" })).await;
    assert_eq!((renamed.status, renamed.body["name"].as_str(), renamed.body["phone"].as_str()), (StatusCode::OK, Some("Ann E."), Some("")));

    // Groups.
    let team = api.post("/api/me/contact-groups", json!({ "name": "Team" })).await.body;
    let team_id = team["id"].as_i64().unwrap();
    assert_eq!(api.post("/api/me/contact-groups", json!({ "name": "Team" })).await.status, StatusCode::CONFLICT);
    let members = api.put(&format!("/api/me/contact-groups/{team_id}/members"), json!({ "contact_ids": [ann_id, carl_id, 99_999] })).await;
    assert_eq!(members.body["members"], 2, "unknown contacts are ignored");
    assert_eq!(api.get("/api/me/contact-groups").await.body, json!([{ "id": team_id, "name": "Team", "members": 2 }]));
    assert_eq!(api.get(&format!("/api/me/contacts?group={team_id}")).await.body.as_array().unwrap().len(), 2);
    assert_eq!(api.get("/api/me/contacts?q=carl").await.body.as_array().unwrap().len(), 1);

    // Suggestions: the group, matching contacts, and colleagues from the same domain only.
    let suggestions = api.get("/api/me/contacts/suggest?q=team").await.body;
    assert_eq!(suggestions[0]["source"], "group");
    assert_eq!(suggestions[0]["members"].as_array().unwrap().len(), 2);
    let suggestions = api.get("/api/me/contacts/suggest?q=car").await.body;
    let found: Vec<(&str, &str)> = suggestions.as_array().unwrap().iter().map(|s| (s["source"].as_str().unwrap(), s["email"].as_str().unwrap())).collect();
    assert_eq!(found, [("contact", "carl@remote.example"), ("directory", "carol@example.org")], "accounts of other domains are not disclosed");
    assert_eq!(api.get("/api/me/contacts/suggest?q=%25").await.body, json!([]), "wildcards are matched literally");
    assert_eq!(api.get("/api/me/contacts/suggest?q=").await.body, json!([]));

    // vCard export and import.
    let exported = api.get("/api/me/contacts/export").await;
    assert_eq!(exported.headers["content-type"], "text/vcard; charset=utf-8");
    assert!(exported.text.contains("FN:Ann E.\r\nEMAIL;TYPE=INTERNET:ann@remote.example\r\n"));
    let carol_api = Api::logged_in(&env, "carol@example.org").await;
    let imported = carol_api.raw(Method::POST, "/api/me/contacts/import", format!("{}BEGIN:VCARD\r\nFN:Broken\r\nEMAIL:not-an-address\r\nEND:VCARD\r\n", exported.text).into_bytes(), "text/vcard").await;
    assert_eq!(imported.body, json!({ "imported": 2, "skipped": 1 }), "{}", imported.text);
    let again = carol_api.raw(Method::POST, "/api/me/contacts/import", exported.text.clone().into_bytes(), "text/vcard").await;
    assert_eq!(again.body, json!({ "imported": 0, "skipped": 2 }), "importing twice does not duplicate contacts");

    // Address books are private: Carol cannot touch Bob's contacts or groups.
    assert_eq!(carol_api.delete(&format!("/api/me/contacts/{ann_id}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(carol_api.put(&format!("/api/me/contacts/{ann_id}"), json!({ "email": "x@remote.example" })).await.status, StatusCode::NOT_FOUND);
    assert_eq!(carol_api.put(&format!("/api/me/contact-groups/{team_id}/members"), json!({ "contact_ids": [] })).await.status, StatusCode::NOT_FOUND);
    assert_eq!(carol_api.get(&format!("/api/me/contact-groups/{team_id}/members")).await.body, json!([]));

    // Deleting a contact removes it from its groups; deleting a group keeps the contacts.
    assert_eq!(api.delete(&format!("/api/me/contacts/{carl_id}")).await.status, StatusCode::OK);
    assert_eq!(api.get("/api/me/contact-groups").await.body[0]["members"], 1);
    assert_eq!(api.delete(&format!("/api/me/contact-groups/{team_id}")).await.status, StatusCode::OK);
    assert_eq!(api.get("/api/me/contacts").await.body.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn templates_preferences_and_pgp_keys() {
    let (env, api) = env_with_bob().await;
    env.account("carol@example.org").await;
    let carol = Api::logged_in(&env, "carol@example.org").await;

    let created = api.post("/api/me/templates", json!({ "name": "Thanks", "subject": "Thank you", "html": "<p>Thank you for your message.</p>" })).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let id = created.body["id"].as_i64().unwrap();
    assert_eq!(api.post("/api/me/templates", json!({ "name": "Thanks" })).await.status, StatusCode::CONFLICT);
    assert_eq!(api.post("/api/me/templates", json!({ "name": " " })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.put(&format!("/api/me/templates/{id}"), json!({ "name": "Thanks a lot", "html": "<p>Cheers</p>" })).await.status, StatusCode::OK);
    assert_eq!(api.get("/api/me/templates").await.body[0]["name"], "Thanks a lot");
    assert_eq!(carol.get("/api/me/templates").await.body, json!([]));
    assert_eq!(carol.delete(&format!("/api/me/templates/{id}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(api.delete(&format!("/api/me/templates/{id}")).await.status, StatusCode::OK);

    assert_eq!(api.get("/api/me/preferences").await.body, json!({}));
    let prefs = json!({ "skin": "ocean", "spell_lang": "pl", "image_senders": ["news@remote.example"] });
    assert_eq!(api.put("/api/me/preferences", prefs.clone()).await.status, StatusCode::OK);
    assert_eq!(api.get("/api/me/preferences").await.body, prefs);
    assert_eq!(carol.get("/api/me/preferences").await.body, json!({}));
    assert_eq!(api.put("/api/me/preferences", json!(["not", "an", "object"])).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.put("/api/me/preferences", json!({ "blob": "x".repeat(20_000) })).await.status, StatusCode::BAD_REQUEST);

    // PGP: the public key is published to other users of the server, the protected private
    // key is only ever returned to its owner.
    assert_eq!(api.get("/api/me/pgp").await.body, Value::Null);
    let public = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEZ...\n-----END PGP PUBLIC KEY BLOCK-----";
    let private = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nxYYEZ...\n-----END PGP PRIVATE KEY BLOCK-----";
    assert_eq!(api.put("/api/me/pgp", json!({ "public_key": "nope" })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.put("/api/me/pgp", json!({ "public_key": public, "private_key": "plain secret" })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.put("/api/me/pgp", json!({ "public_key": public, "private_key": private })).await.status, StatusCode::OK);
    assert_eq!(api.get("/api/me/pgp").await.body["private_key"], private);
    let lookup = carol.get("/api/me/pgp/lookup?emails=bob@example.org,nobody@example.org,garbage").await;
    assert_eq!(lookup.body, json!({ "bob@example.org": public }));
    assert!(!lookup.text.contains("PRIVATE"));
    // A key stored with a contact takes precedence over the published one.
    let contact_key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\ncontact\n-----END PGP PUBLIC KEY BLOCK-----";
    carol.post("/api/me/contacts", json!({ "email": "bob@example.org", "pgp_key": contact_key })).await;
    assert_eq!(carol.get("/api/me/pgp/lookup?emails=bob@example.org").await.body["bob@example.org"], contact_key);
    assert_eq!(api.delete("/api/me/pgp").await.status, StatusCode::OK);
    assert_eq!(api.get("/api/me/pgp").await.body, Value::Null);
}

#[tokio::test]
async fn folders_are_exported_and_imported_as_mbox() {
    let (env, api) = env_with_bob().await;
    let bob = unomail::auth::Account::by_email(&env.app.db, "bob@example.org").await.unwrap().unwrap();
    let carol = env.account("carol@example.org").await;
    let inbox = env.app.store.mailbox_by_role(bob.id, "inbox").await.unwrap().unwrap();
    for (n, body) in ["first\r\nFrom the top\r\n", "second\r\n"].iter().enumerate() {
        let raw = format!("From: ann@remote.example\r\nSubject: Message {n}\r\nMessage-ID: <m{n}@remote.example>\r\nDate: Mon, 05 Oct 2026 10:00:00 +0000\r\n\r\n{body}");
        env.app.store.append(bob.id, inbox.id, raw.as_bytes(), Default::default(), None).await.unwrap();
    }

    let exported = api.get(&format!("/api/me/mailboxes/{}/export", inbox.id)).await;
    assert_eq!(exported.status, StatusCode::OK);
    assert_eq!(exported.headers["content-disposition"], "attachment; filename=\"INBOX.mbox\"");
    assert_eq!(exported.text.matches("\nFrom ann@remote.example ").count() + 1, 2);
    assert!(exported.text.contains("\n>From the top\n"), "body lines that look like separators are quoted");

    // Other users cannot export or import into the folder.
    let carol_api = Api::logged_in(&env, "carol@example.org").await;
    assert_eq!(carol_api.get(&format!("/api/me/mailboxes/{}/export", inbox.id)).await.status, StatusCode::NOT_FOUND);
    assert_eq!(carol_api.raw(Method::POST, &format!("/api/me/mailboxes/{}/import", inbox.id), exported.bytes.clone(), "application/mbox").await.status, StatusCode::NOT_FOUND);

    // Importing into Carol's own archive restores both messages, exactly once.
    let archive = env.app.store.mailbox_by_role(carol.id, "archive").await.unwrap().unwrap();
    let path = format!("/api/me/mailboxes/{}/import", archive.id);
    let imported = carol_api.raw(Method::POST, &path, exported.bytes.clone(), "application/mbox").await;
    assert_eq!(imported.body, json!({ "imported": 2, "skipped": 0 }), "{}", imported.text);
    assert_eq!(carol_api.raw(Method::POST, &path, exported.bytes.clone(), "application/mbox").await.body, json!({ "imported": 0, "skipped": 2 }));
    let restored = env.mailbox(&carol, "archive").await;
    assert!(restored[0].ends_with("\r\n\r\nfirst\r\nFrom the top\r\n"), "{:?}", restored[0]);

    // A single .eml file works too; things that are not mail are refused.
    let eml = b"From: dan@remote.example\r\nSubject: Single\r\nMessage-ID: <single@remote.example>\r\n\r\nbody\r\n".to_vec();
    assert_eq!(carol_api.raw(Method::POST, &path, eml, "message/rfc822").await.body, json!({ "imported": 1, "skipped": 0 }));
    assert_eq!(carol_api.raw(Method::POST, &path, b"\x00\x01binary junk".to_vec(), "application/octet-stream").await.body, json!({ "imported": 0, "skipped": 1 }));
    assert_eq!(carol_api.raw(Method::POST, &path, Vec::new(), "message/rfc822").await.status, StatusCode::BAD_REQUEST);
    assert_eq!(env.mailbox(&carol, "archive").await.len(), 3);
}

#[tokio::test]
async fn remote_images_are_fetched_by_the_server_and_only_if_they_are_images() {
    let (_env, api) = env_with_bob().await;
    let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR-not-a-real-image".to_vec();
    let (image, requests) = http_server(http_response("200 OK", "image/png", &png)).await;
    let (html, _) = http_server(http_response("200 OK", "image/png", b"<html><script>alert(1)</script></html>")).await;
    let (redirect, _) = http_server(format!("HTTP/1.1 302 Found\r\nLocation: http://{image}/final.png\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()).await;
    let proxy = |target: String| format!("/api/me/image-proxy?url={}", target.replace(':', "%3A").replace('/', "%2F").replace(' ', "%20"));

    let fetched = api.get(&proxy(format!("http://{image}/logo.png"))).await;
    assert_eq!(fetched.status, StatusCode::OK, "{}", fetched.text);
    assert_eq!(fetched.bytes, png);
    assert_eq!(fetched.headers["content-type"], "image/png");
    assert_eq!(fetched.headers["content-security-policy"], "default-src 'none'; sandbox");
    let request = requests.lock()[0].to_ascii_lowercase();
    assert!(!request.contains("cookie:") && !request.contains("referer:"), "nothing about the reader is passed on: {request}");

    assert_eq!(api.get(&proxy(format!("http://{redirect}/r"))).await.bytes, png, "redirects are followed and re-checked");
    assert_eq!(api.get(&proxy(format!("http://{html}/x.png"))).await.status, StatusCode::BAD_REQUEST, "the content must really be an image");
    for bad in ["file:///etc/passwd", "ftp://example.org/x.png", "javascript:alert(1)", "http://user:pw@example.org/x.png", "not a url"] {
        assert_eq!(api.get(&proxy(bad.to_owned())).await.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert_eq!(Api::new(&_env).get(&proxy(format!("http://{image}/logo.png"))).await.status, StatusCode::UNAUTHORIZED, "the proxy is for signed-in users only");
}

#[tokio::test]
async fn the_image_proxy_refuses_internal_addresses() {
    let env = TestEnv::start_with(|cfg| cfg.allow_private_destinations = false).await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let (image, requests) = http_server(http_response("200 OK", "image/png", b"\x89PNG....")).await;
    for target in [format!("http://{image}/x.png"), "http://127.0.0.1/x.png".into(), "http://localhost/x.png".into(), "http://169.254.169.254/latest/meta-data".into(), "http://[::1]/x.png".into(), "http://10.0.0.1:22/".into()] {
        let reply = api.get(&format!("/api/me/image-proxy?url={}", target.replace(':', "%3A").replace('/', "%2F"))).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{target}");
    }
    assert!(requests.lock().is_empty(), "no connection was ever made");
}

#[tokio::test]
async fn webhooks_are_signed_and_administrator_only() {
    let (env, bob) = env_with_bob().await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let (receiver, requests) = http_server(http_response("200 OK", "text/plain", b"ok")).await;
    let url = format!("http://127.0.0.1:{}/hook", receiver.port());

    assert_eq!(bob.get("/api/webhooks").await.status, StatusCode::FORBIDDEN);
    assert_eq!(bob.post("/api/webhooks", json!({ "url": url, "events": ["message.received"] })).await.status, StatusCode::FORBIDDEN);
    for bad in [json!({ "url": "http://remote.example/hook", "events": ["message.received"] }), json!({ "url": url, "events": [] }), json!({ "url": url, "events": ["everything"] }), json!({ "url": "nope", "events": ["message.sent"] })] {
        assert_eq!(admin.post("/api/webhooks", bad.clone()).await.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let created = admin.post("/api/webhooks", json!({ "url": url, "events": ["message.received"] })).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let secret = created.body["secret"].as_str().unwrap().to_owned();
    let listed = admin.get("/api/webhooks").await;
    assert!(!listed.text.contains(&secret), "the signing secret is shown only once");

    let mut c = common::Client::smtp(env.mx).await;
    assert!(c.send_mail("ann@remote.example", &["bob@example.org"], &common::message("ann@remote.example", "bob@example.org", "Top secret subject", "secret body")).await.starts_with("250"));
    for _ in 0..100 {
        if !requests.lock().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let request = requests.lock()[0].clone();
    let (head, body) = request.split_once("\r\n\r\n").unwrap();
    let event: Value = serde_json::from_str(body).unwrap();
    assert_eq!((event["event"].as_str(), event["data"]["recipient"].as_str(), event["data"]["sender"].as_str()), (Some("message.received"), Some("bob@example.org"), Some("ann@remote.example")));
    assert!(!body.contains("secret body") && !body.contains("Top secret subject"), "notifications carry no message content");
    let expected = hex::encode(unomail::util::hmac_sha256(secret.as_bytes(), body.as_bytes()));
    assert!(head.to_ascii_lowercase().contains(&format!("x-unomail-signature: sha256={expected}")), "{head}");

    // Events the hook did not subscribe to are not sent; the test button always is.
    let id = created.body["id"].as_i64().unwrap();
    assert_eq!(admin.post(&format!("/api/webhooks/{id}/test"), json!({})).await.body, json!({ "status": "HTTP 200" }));
    assert_eq!(admin.get("/api/webhooks").await.body["webhooks"][0]["last_status"], "HTTP 200");
    assert_eq!(admin.delete(&format!("/api/webhooks/{id}")).await.status, StatusCode::OK);
    assert_eq!(admin.post(&format!("/api/webhooks/{id}/test"), json!({})).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn skins() {
    let (env, bob) = env_with_bob().await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let admin = Api::logged_in(&env, "admin@example.org").await;

    let ocean = json!({ "id": "ocean", "name": "Ocean", "mode": "dark", "primary": "#0061a4", "radius": 6, "density": "compact" });
    assert_eq!(bob.put("/api/skins", json!([ocean])).await.status, StatusCode::FORBIDDEN);
    assert_eq!(admin.put("/api/skins", json!([{ "id": "evil", "name": "Evil", "css": "body{}" }])).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(admin.put("/api/skins", json!([ocean, ocean])).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(admin.put("/api/skins", json!([ocean])).await.status, StatusCode::OK);
    assert_eq!(bob.get("/api/skins").await.body, json!([ocean]), "every user can pick an installed skin");
}

#[tokio::test]
async fn ldap_settings_are_validated_and_never_leak_the_bind_password() {
    let (env, bob) = env_with_bob().await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    assert_eq!(bob.get("/api/ldap").await.status, StatusCode::FORBIDDEN);
    assert_eq!(admin.get("/api/ldap").await.body, Value::Null);

    let config = json!({ "enabled": true, "url": "ldap://127.0.0.1:1", "base_dn": "dc=example,dc=org", "bind_dn": "cn=reader,dc=example,dc=org", "password": "bind-secret" });
    let saved = admin.put("/api/ldap", config.clone()).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    assert_eq!(saved.body["has_password"], true);
    assert_eq!(saved.body["filter"], unomail::ldap::DEFAULT_FILTER);
    assert!(!admin.get("/api/ldap").await.text.contains("bind-secret"));
    let stored: String = sqlx::query_scalar("SELECT value FROM settings WHERE key = 'ldap.config'").fetch_one(&env.app.db).await.unwrap();
    assert!(!stored.contains("bind-secret"), "the bind password is encrypted at rest");
    for bad in [json!({ "enabled": true, "url": "http://x", "base_dn": "dc=x" }), json!({ "enabled": true, "url": "ldap://x", "base_dn": "" }), json!({ "enabled": true, "url": "ldap://x", "base_dn": "dc=x", "filter": "(cn=*)" })] {
        assert_eq!(admin.put("/api/ldap", bad.clone()).await.status, StatusCode::BAD_REQUEST, "{bad}");
    }

    // An unreachable directory is reported by the test button and never breaks suggestions.
    let mut probe = config.clone();
    probe["query"] = json!("ann");
    probe.as_object_mut().unwrap().remove("password");
    let tested = admin.post("/api/ldap/test", probe).await;
    assert_eq!(tested.body["ok"], false, "{}", tested.text);
    assert_eq!(bob.get("/api/me/contacts/suggest?q=ann").await.status, StatusCode::OK);
}
