//! S/MIME: importing a certificate, sending signed and encrypted mail, reading it.

mod common;

use axum::http::StatusCode;
use base64::Engine;
use common::{Api, TestEnv};
use p12_keystore::{Certificate, KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain};
use rsa::pkcs8::EncodePrivateKey;
use serde_json::{Value, json};

/// A PKCS #12 file with a fresh self-signed certificate for `email`.
fn p12(email: &str, password: &str) -> Vec<u8> {
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let pkcs8 = key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let pair = rcgen::KeyPair::try_from(pkcs8.as_slice()).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::Rfc822Name(email.try_into().unwrap())];
    params.distinguished_name.push(rcgen::DnType::CommonName, email);
    let cert = params.self_signed(&pair).unwrap();
    let mut store = KeyStore::new();
    store.add_entry("key", KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(b"1".to_vec(), PrivateKey::from_der(&pkcs8).unwrap(), [Certificate::from_der(cert.der()).unwrap()])));
    store.writer(password).write().unwrap()
}

async fn send(api: &Api, from: &str, to: &str, subject: &str, smime: Value) -> Value {
    let account = api.jmap_account().await;
    let boxes = api.jmap(json!([["Mailbox/get", { "accountId": account }, "0"]])).await[0][1]["list"].clone();
    let role = |r: &str| boxes.as_array().unwrap().iter().find(|m| m["role"] == r).unwrap()["id"].as_str().unwrap().to_owned();
    let (drafts, sent) = (role("drafts"), role("sent"));
    api.jmap(json!([
        ["Email/set", { "accountId": account, "create": { "d": {
            "mailboxIds": { &drafts: true }, "from": [{ "email": from }], "to": [{ "email": to }], "subject": subject, "smime": smime,
            "bodyValues": { "t": { "value": "The secret is 42." } }, "textBody": [{ "partId": "t", "type": "text/plain" }],
        } } }, "c"],
        ["EmailSubmission/set", { "accountId": account, "create": { "s": { "emailId": "#d" } }, "onSuccessUpdateEmail": { "#s": { "mailboxIds": { &sent: true } } } }, "s"],
    ]))
    .await
}

async fn latest(api: &Api) -> Value {
    let account = api.jmap_account().await;
    let ids = api.jmap(json!([["Email/query", { "accountId": account, "sort": [{ "property": "receivedAt", "isAscending": false }] }, "q"]])).await[0][1]["ids"].clone();
    api.jmap(json!([["Email/get", { "accountId": account, "ids": [ids[0]], "fetchTextBodyValues": true }, "g"]])).await[0][1]["list"][0].clone()
}

#[tokio::test]
async fn signed_and_encrypted_mail_round_trip() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    env.account("alice@example.org").await;
    let bob_api = Api::logged_in(&env, "bob@example.org").await;
    let alice_api = Api::logged_in(&env, "alice@example.org").await;
    let b64 = |d: &[u8]| base64::engine::general_purpose::STANDARD.encode(d);

    assert_eq!(bob_api.get("/api/me/smime").await.body["certificate"], Value::Null);
    let bob_p12 = p12("bob@example.org", "secret");
    assert_eq!(bob_api.put("/api/me/smime", json!({ "file": b64(&bob_p12), "password": "wrong" })).await.status, StatusCode::BAD_REQUEST);
    let others = p12("eve@example.org", "x");
    assert!(bob_api.put("/api/me/smime", json!({ "file": b64(&others), "password": "x" })).await.text.contains("not for bob@example.org"));
    let imported = bob_api.put("/api/me/smime", json!({ "file": b64(&bob_p12), "password": "secret" })).await;
    assert_eq!(imported.status, StatusCode::OK, "{}", imported.text);
    assert_eq!(imported.body["certificate"]["emails"], json!(["bob@example.org"]));
    assert_eq!(alice_api.put("/api/me/smime", json!({ "file": b64(&p12("alice@example.org", "pw")), "password": "pw" })).await.status, StatusCode::OK);

    // Encrypting needs the recipient's certificate, known only from their signed mail.
    let refused = send(&bob_api, "bob@example.org", "alice@example.org", "Too early", json!({ "encrypt": true })).await;
    assert!(refused[0][1]["notCreated"]["d"]["description"].as_str().unwrap().contains("no S/MIME certificate is known for alice@example.org"), "{refused}");

    // Bob signs; Alice sees a good signature, and now has Bob's certificate.
    let signed = send(&bob_api, "bob@example.org", "alice@example.org", "Signed", json!({ "sign": true })).await;
    assert!(signed[1][1]["created"]["s"].is_object(), "{signed}");
    let received = latest(&alice_api).await;
    assert_eq!(received["smime"]["signature"]["status"], "untrusted", "self-signed: {}", received["smime"]);
    assert_eq!(received["smime"]["signature"]["matches_sender"], true);
    let lookup = alice_api.get("/api/me/smime/lookup?emails=bob@example.org,carol@example.org").await;
    assert_eq!(lookup.body, json!(["bob@example.org"]));

    // Alice encrypts to Bob: stored as ciphertext, shown decrypted to Bob.
    let encrypted = send(&alice_api, "alice@example.org", "bob@example.org", "Encrypted", json!({ "sign": true, "encrypt": true })).await;
    assert!(encrypted[1][1]["created"]["s"].is_object(), "{encrypted}");
    let stored = env.inbox(&bob).await.pop().unwrap();
    assert!(stored.contains("application/pkcs7-mime") && !stored.contains("The secret is 42"), "{stored}");
    let shown = latest(&bob_api).await;
    assert_eq!(shown["smime"]["encrypted"], true);
    assert_eq!(shown["smime"]["decrypted"], true);
    assert_eq!(shown["smime"]["signature"]["matches_sender"], true, "{}", shown["smime"]);
    let text_part = shown["textBody"][0]["partId"].as_str().unwrap();
    assert!(shown["bodyValues"][text_part]["value"].as_str().unwrap().contains("The secret is 42"), "{shown}");
    // Alice's own copy in Sent stays readable to her.
    let account = alice_api.jmap_account().await;
    let sent_copy = alice_api.jmap(json!([["Email/query", { "accountId": account, "filter": { "text": "Encrypted" } }, "q"]])).await[0][1]["ids"].clone();
    assert!(!sent_copy.as_array().unwrap().is_empty());

    assert_eq!(bob_api.delete("/api/me/smime").await.status, StatusCode::OK);
    let without_key = latest(&bob_api).await;
    assert_eq!(without_key["smime"]["decrypted"], false);
    assert!(without_key["smime"]["problem"].as_str().unwrap().contains("Add your certificate"));
}

#[tokio::test]
async fn certificates_from_unauthenticated_senders_are_not_collected() {
    use rsa::pkcs8::DecodePrivateKey;
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("alice@example.org").await;
    let alice_api = Api::logged_in(&env, "alice@example.org").await;

    // An impostor makes a certificate for bob@bank.example and forges a signed message from him.
    let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let pkcs8 = key.to_pkcs8_der().unwrap().as_bytes().to_vec();
    let pair = rcgen::KeyPair::try_from(pkcs8.as_slice()).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![rcgen::SanType::Rfc822Name("bob@bank.example".try_into().unwrap())];
    let cert = params.self_signed(&pair).unwrap();
    let identity = unomail::smime::Identity { certificate: cert.der().to_vec(), chain: Vec::new(), key: rsa::RsaPrivateKey::from_pkcs8_der(&pkcs8).unwrap() };
    let forged = unomail::smime::sign(b"From: bob@bank.example\r\nTo: alice@example.org\r\nSubject: Our new key\r\nContent-Type: text/plain\r\n\r\nPlease use this.\r\n", &identity).unwrap();
    let mut smtp = common::Client::smtp(env.mx).await;
    assert!(smtp.send_mail("bob@bank.example", &["alice@example.org"], &String::from_utf8(forged).unwrap()).await.starts_with("250"));

    // The signature is shown (as unverified), but the key is not kept for encrypting to bob.
    let shown = latest(&alice_api).await;
    assert_eq!(shown["smime"]["signature"]["status"], "untrusted");
    assert_eq!(alice_api.get("/api/me/smime/lookup?emails=bob@bank.example").await.body, json!([]));
}
