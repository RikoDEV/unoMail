//! What the reader is told about a message: sender authentication, encryption, virus findings,
//! and the sender's picture (Gravatar; brand logos are covered by the unit tests of BIMI).

mod common;

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::http::{Method, StatusCode, header};
use common::{Api, Client, TestEnv, message};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Stores a raw message in the inbox as an import would, and returns its JMAP id.
async fn import(env: &TestEnv, api: &Api, email: &str, raw: &str) -> String {
    let account = api.jmap_account().await;
    let owner = unomail::auth::Account::by_email(&env.app.db, email).await.unwrap().unwrap();
    let inbox = env.app.store.mailbox_by_role(owner.id, "inbox").await.unwrap().unwrap().id;
    let upload = api.raw(Method::POST, &format!("/jmap/upload/{account}"), raw.as_bytes().to_vec(), "message/rfc822").await;
    assert_eq!(upload.status, StatusCode::CREATED, "{}", upload.text);
    let reply = api.jmap(json!([["Email/import", { "accountId": account, "emails": { "e": { "blobId": upload.body["blobId"], "mailboxIds": { format!("b{inbox}"): true } } } }, "i"]])).await;
    reply[0][1]["created"]["e"]["id"].as_str().unwrap_or_else(|| panic!("{reply}")).to_owned()
}

async fn security(api: &Api, id: &str) -> Value {
    let account = api.jmap_account().await;
    let reply = api.jmap(json!([["Email/get", { "accountId": account, "ids": [id], "properties": ["subject", "security"] }, "g"]])).await;
    reply[0][1]["list"][0]["security"].clone()
}

/// The id of the message with a given subject, wherever it is filed.
async fn id_by_subject(api: &Api, subject: &str) -> String {
    let account = api.jmap_account().await;
    let reply = api
        .jmap(json!([
            ["Email/query", { "accountId": account }, "q"],
            ["Email/get", { "accountId": account, "#ids": { "resultOf": "q", "name": "Email/query", "path": "/ids" }, "properties": ["subject"] }, "g"],
        ]))
        .await;
    let list = reply[1][1]["list"].as_array().unwrap();
    list.iter().find(|email| email["subject"] == subject).unwrap_or_else(|| panic!("no message with subject {subject}: {reply}"))["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn the_reader_learns_how_a_message_was_authenticated() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account("carol@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let host = env.app.cfg.hostname.clone();
    let stored = |results: &str| format!("Received: from out.partner.example ([203.0.113.9])\r\n\tby {host} with ESMTPS id abc; Tue, 13 Oct 2026 10:00:00 +0000\r\nAuthentication-Results: {host}; {results}\r\nFrom: Anna <anna@partner.example>\r\nTo: bob@example.org\r\nSubject: Report\r\n\r\nHello\r\n");

    let genuine = import(&env, &bob, "bob@example.org", &stored("dkim=pass header.d=partner.example header.s=s1; spf=pass smtp.mailfrom=bounces@mail.partner.example; dmarc=pass header.from=partner.example")).await;
    let seen = security(&bob, &genuine).await;
    assert_eq!(seen, json!({ "origin": "remote", "verdict": "verified", "spf": "pass", "dkim": "pass", "dmarc": "pass", "mailed_by": "mail.partner.example", "signed_by": ["partner.example"], "from_domain": "partner.example", "tls": true, "virus": null, "problems": [] }));

    let spoofed = import(&env, &bob, "bob@example.org", &stored("dkim=none; spf=fail smtp.mailfrom=anna@partner.example; dmarc=fail header.from=partner.example")).await;
    let seen = security(&bob, &spoofed).await;
    assert_eq!((seen["verdict"].clone(), seen["problems"].as_array().unwrap().len()), (json!("failed"), 2), "{seen}");
    assert!(seen["problems"][0].as_str().unwrap().starts_with("DMARC:"));

    // Mail between users of this server: sent by a signed-in user, nothing to warn about.
    let carol = Api::logged_in(&env, "carol@example.org").await;
    let account = carol.jmap_account().await;
    let drafts = env.app.store.mailbox_by_role(unomail::auth::Account::by_email(&env.app.db, "carol@example.org").await.unwrap().unwrap().id, "drafts").await.unwrap().unwrap().id;
    let sent = carol
        .jmap(json!([
            ["Email/set", { "accountId": account, "create": { "d": { "mailboxIds": { format!("b{drafts}"): true }, "to": [{ "email": "bob@example.org" }], "subject": "From a colleague", "bodyValues": { "t": { "value": "Hi" } }, "textBody": [{ "partId": "t", "type": "text/plain" }] } } }, "c"],
            ["EmailSubmission/set", { "accountId": account, "create": { "s": { "emailId": "#d" } } }, "s"],
        ]))
        .await;
    assert!(sent[1][1]["created"]["s"].is_object(), "{sent}");
    unomail::smtp::queue::process_due(&env.app).await;
    let internal = security(&bob, &id_by_subject(&bob, "From a colleague").await).await;
    assert_eq!((internal["origin"].clone(), internal["verdict"].clone(), internal["problems"].clone()), (json!("submitted"), json!("internal"), json!([])), "{internal}");

    // A sender cannot bring its own verdicts: what arrives by SMTP claiming to be this
    // server's findings is removed, and the message is judged by what the server did find.
    let forged = format!("Authentication-Results: {host}; dmarc=pass header.from=bank.example\r\nX-Virus-Status: Clean\r\n{}", message("ceo@bank.example", "bob@example.org", "Urgent", "wire the money"));
    let mut smtp = Client::smtp(env.mx).await;
    assert!(smtp.send_mail("ceo@bank.example", &["bob@example.org"], &forged).await.starts_with("250"));
    let raw = env.inbox(&unomail::auth::Account::by_email(&env.app.db, "bob@example.org").await.unwrap().unwrap()).await.into_iter().find(|raw| raw.contains("Subject: Urgent")).unwrap();
    assert!(!raw.contains("dmarc=pass") && !raw.contains("X-Virus-Status"), "{raw}");
    let seen = security(&bob, &id_by_subject(&bob, "Urgent").await).await;
    assert_eq!((seen["origin"].clone(), seen["dmarc"].clone(), seen["tls"].clone()), (json!("remote"), Value::Null, json!(false)), "{seen}");
    assert_ne!(seen["verdict"], "verified");
}

#[tokio::test]
async fn a_virus_can_be_quarantined_with_a_warning_instead_of_refused() {
    // A stand-in clamd speaking INSTREAM: reports a virus when the stream starts with the test string.
    let clamd = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let scanner = clamd.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = clamd.accept().await {
            tokio::spawn(async move {
                let mut command = [0u8; 10];
                if socket.read_exact(&mut command).await.is_err() {
                    return;
                }
                let mut data = Vec::new();
                loop {
                    let mut len = [0u8; 4];
                    if socket.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let len = u32::from_be_bytes(len) as usize;
                    if len == 0 {
                        break;
                    }
                    let mut chunk = vec![0u8; len];
                    if socket.read_exact(&mut chunk).await.is_err() {
                        return;
                    }
                    data.extend_from_slice(&chunk);
                }
                let reply: &[u8] = if data.starts_with(b"X5O!P%@AP") { b"stream: Eicar-Signature FOUND\0" } else { b"stream: OK\0" };
                let _ = socket.write_all(reply).await;
            });
        }
    });

    let env = TestEnv::start_with(move |cfg| {
        cfg.clamav_addr = Some(scanner);
        cfg.virus_quarantine = true;
    })
    .await;
    env.domain("example.org").await;
    let bob_account = env.account("bob@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let mut smtp = Client::smtp(env.mx).await;
    let infected = message("a@remote.example", "bob@example.org", "Invoice", "X5O!P%@AP[4 EICAR-STANDARD-ANTIVIRUS-TEST-FILE");
    assert!(smtp.send_mail("a@remote.example", &["bob@example.org"], &infected).await.starts_with("250"), "accepted for quarantine");
    assert!(smtp.send_mail("a@remote.example", &["bob@example.org"], &message("a@remote.example", "bob@example.org", "Clean", "nothing")).await.starts_with("250"));

    // Out of the inbox, into Junk, and marked.
    assert_eq!(env.inbox(&bob_account).await.len(), 1);
    let junk = env.mailbox(&bob_account, "junk").await;
    assert_eq!(junk.len(), 1);
    assert!(junk[0].contains("X-Virus-Status: Infected (Eicar-Signature)\r\n"), "{}", junk[0]);
    let account = bob.jmap_account().await;
    let junk_id = env.app.store.mailbox_by_role(bob_account.id, "junk").await.unwrap().unwrap().id;
    let listed = bob.jmap(json!([["Email/query", { "accountId": account, "filter": { "inMailbox": format!("b{junk_id}") } }, "q"]])).await;
    let seen = security(&bob, listed[0][1]["ids"][0].as_str().unwrap()).await;
    assert_eq!(seen["virus"], "Eicar-Signature");
    assert_eq!(seen["problems"][0], "The virus scanner found malware in this message: Eicar-Signature");
    // The clean message carries no such mark.
    assert_eq!(security(&bob, &id_by_subject(&bob, "Clean").await).await["virus"], Value::Null);
}

#[tokio::test]
async fn senders_get_their_gravatar_through_the_server() {
    // A stand-in Gravatar: a tiny PNG for one address hash, 404 for all others.
    let known = unomail::util::sha256_hex(b"anna@partner.example");
    let png: Vec<u8> = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4];
    let hits = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/avatar", listener.local_addr().unwrap());
    let (counter, picture) = (hits.clone(), png.clone());
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let (counter, picture, known) = (counter.clone(), picture.clone(), known.clone());
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 2048];
                let read = socket.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
                counter.fetch_add(1, Ordering::SeqCst);
                let response = if request.starts_with(&format!("GET /avatar/{known}?s=96&d=404")) {
                    let mut out = format!("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", picture.len()).into_bytes();
                    out.extend_from_slice(&picture);
                    out
                } else {
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
                };
                let _ = socket.write_all(&response).await;
            });
        }
    });

    let env = TestEnv::start_with(move |cfg| {
        cfg.gravatar_url = Some(base);
        cfg.allow_private_destinations = true;
    })
    .await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account("carol@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let account = bob.jmap_account().await;
    let host = env.app.cfg.hostname.clone();
    let stored = |from: &str, results: &str| format!("Received: from x ([203.0.113.9])\r\n\tby {host} with ESMTPS id abc; Tue, 13 Oct 2026 10:00:00 +0000\r\nAuthentication-Results: {host}; {results}\r\nFrom: {from}\r\nTo: bob@example.org\r\nSubject: Hi\r\n\r\nHello\r\n");
    let passed = "dkim=pass header.d=partner.example; spf=pass smtp.mailfrom=anna@partner.example; dmarc=pass header.from=partner.example";

    let genuine = import(&env, &bob, "bob@example.org", &stored("Anna <Anna@Partner.Example>", passed)).await;
    let picture = bob.get(&format!("/jmap/avatar/{account}/{genuine}")).await;
    assert_eq!(picture.status, StatusCode::OK);
    assert_eq!(picture.bytes, png);
    assert_eq!(picture.headers[header::CONTENT_TYPE], "image/png");
    assert!(picture.headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap().contains("sandbox"));
    assert_eq!(bob.get(&format!("/jmap/avatar/{account}/{genuine}?info=1")).await.body, json!({ "source": "gravatar", "verified": false, "detail": "" }));
    let asked = hits.load(Ordering::SeqCst);
    assert_eq!(asked, 1, "the second request was answered from the server's copy");

    // No picture on file: remembered too.
    let other = import(&env, &bob, "bob@example.org", &stored("jan@partner.example", passed)).await;
    assert_eq!(bob.get(&format!("/jmap/avatar/{account}/{other}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(bob.get(&format!("/jmap/avatar/{account}/{other}?info=1")).await.body["source"], "none");
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    // A message that failed authentication gets no picture, whoever it claims to be from:
    // the service is not even asked.
    let spoofed = import(&env, &bob, "bob@example.org", &stored("anna@partner.example", "dkim=none; spf=fail smtp.mailfrom=anna@partner.example; dmarc=fail header.from=partner.example")).await;
    assert_eq!(bob.get(&format!("/jmap/avatar/{account}/{spoofed}")).await.status, StatusCode::NOT_FOUND);
    let unchecked = import(&env, &bob, "bob@example.org", "From: anna@partner.example\r\nSubject: Imported\r\n\r\nx\r\n").await;
    assert_eq!(bob.get(&format!("/jmap/avatar/{account}/{unchecked}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(hits.load(Ordering::SeqCst), 2);

    // Pictures are reached through one's own messages only.
    let carol = Api::logged_in(&env, "carol@example.org").await;
    let carols = carol.jmap_account().await;
    assert_eq!(carol.get(&format!("/jmap/avatar/{carols}/{genuine}")).await.status, StatusCode::NOT_FOUND);
    assert_ne!(carol.get(&format!("/jmap/avatar/{account}/{genuine}")).await.status, StatusCode::OK);
    assert_ne!(Api::new(&env).get(&format!("/jmap/avatar/{account}/{genuine}")).await.status, StatusCode::OK);
    assert_eq!(bob.get(&format!("/jmap/avatar/{account}/nonsense")).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn gravatar_can_be_turned_off() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let account = bob.jmap_account().await;
    let host = env.app.cfg.hostname.clone();
    let raw = format!("Authentication-Results: {host}; dkim=pass header.d=x.example; spf=pass smtp.mailfrom=a@x.example; dmarc=pass header.from=x.example\r\nFrom: a@x.example\r\nSubject: Hi\r\n\r\nx\r\n");
    let id = import(&env, &bob, "bob@example.org", &raw).await;
    assert_eq!(bob.get(&format!("/jmap/avatar/{account}/{id}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(bob.get(&format!("/jmap/avatar/{account}/{id}?info=1")).await.body["source"], "none");
}
