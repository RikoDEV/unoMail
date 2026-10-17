//! JMAP push: subscriptions delivered as Web Push, and JMAP over WebSocket (RFC 8887).

mod common;

use std::sync::Arc;

use axum::{Router, body::Bytes, extract::State, http::HeaderMap};
use base64::Engine;
use common::{Api, Client, PASSWORD, TestEnv, message};
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use ring::{aead, agreement, hkdf, rand::SystemRandom};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};

type Received = Arc<Mutex<Vec<(HeaderMap, Vec<u8>)>>>;

async fn push_service() -> (String, Received) {
    let received: Received = Arc::default();
    let router = Router::new()
        .fallback(|State(store): State<Received>, headers: HeaderMap, body: Bytes| async move {
            store.lock().push((headers, body.to_vec()));
            axum::http::StatusCode::CREATED
        })
        .with_state(received.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}/push"), received)
}

async fn wait_for(received: &Received, count: usize) -> Vec<(HeaderMap, Vec<u8>)> {
    for _ in 0..100 {
        if received.lock().len() >= count {
            return received.lock().clone();
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("expected {count} push messages, got {}", received.lock().len());
}

struct Len(usize);
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}
fn expand(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm).expand(&[info], Len(len)).unwrap().fill(&mut out).unwrap();
    out
}

#[tokio::test]
async fn push_subscriptions_are_verified_and_notified() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    tokio::spawn(unomail::jmap::push::run(env.app.clone()));
    let api = Api::logged_in(&env, "bob@example.org").await;
    let session = api.get("/jmap/session").await.body;
    let vapid = session["capabilities"]["urn:ietf:params:jmap:webpush-vapid"]["applicationServerKey"].as_str().unwrap().to_owned();
    assert_eq!(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&vapid).unwrap().len(), 65);
    assert_eq!(session["capabilities"]["urn:ietf:params:jmap:websocket"]["supportsPush"], true);

    let (url, received) = push_service().await;
    // A plain subscription: messages arrive as JSON.
    let created = api.jmap(json!([["PushSubscription/set", { "create": { "s": { "deviceClientId": "phone", "url": url, "types": ["Email"] } } }, "0"]])).await;
    let id = created[0][1]["created"]["s"]["id"].as_str().unwrap().to_owned();
    let pushed = wait_for(&received, 1).await;
    let verification: Value = serde_json::from_slice(&pushed[0].1).unwrap();
    assert_eq!(verification["@type"], "PushVerification");
    assert!(pushed[0].0["authorization"].to_str().unwrap().starts_with("vapid t="));
    let wrong = api.jmap(json!([["PushSubscription/set", { "update": { id.clone(): { "verificationCode": "nope" } } }, "0"]])).await;
    assert!(wrong[0][1]["notUpdated"][&id].is_object());

    // Nothing is pushed before verification.
    let mut smtp = Client::smtp(env.mx).await;
    let mail = message("alice@remote.example", "bob@example.org", "Hi", "x");
    assert!(smtp.send_mail("alice@remote.example", &["bob@example.org"], &mail).await.starts_with("250"));
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    assert_eq!(received.lock().len(), 1);

    let ok = api.jmap(json!([["PushSubscription/set", { "update": { id.clone(): { "verificationCode": verification["verificationCode"] } } }, "0"]])).await;
    assert!(ok[0][1]["updated"].as_object().unwrap().contains_key(&id), "{ok}");
    let listed = api.jmap(json!([["PushSubscription/get", {}, "0"]])).await;
    assert_eq!(listed[0][1]["list"][0]["deviceClientId"], "phone");
    assert!(listed[0][1]["list"][0].get("url").is_none(), "the URL is never shown again");
    assert!(smtp.send_mail("alice@remote.example", &["bob@example.org"], &mail).await.starts_with("250"));
    let pushed = wait_for(&received, 2).await;
    let change: Value = serde_json::from_slice(&pushed[1].1).unwrap();
    assert_eq!(change["@type"], "StateChange");
    assert!(change["changed"].as_object().unwrap().values().next().unwrap()["Email"].is_string());
    assert!(change["changed"].as_object().unwrap().values().next().unwrap()["EmailDelivery"].is_string(), "a new message: {change}");

    // A browser subscription: the message is encrypted for the browser's key.
    let rng = SystemRandom::new();
    let browser = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
    let public = browser.compute_public_key().unwrap().as_ref().to_vec();
    let auth = [7u8; 16];
    let b64 = |d: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d);
    let created = api.jmap(json!([["PushSubscription/set", { "create": { "b": { "deviceClientId": "browser", "url": url, "keys": { "p256dh": b64(&public), "auth": b64(&auth) } } } }, "0"]])).await;
    assert!(created[0][1]["created"]["b"]["id"].is_string(), "{created}");
    let pushed = wait_for(&received, 3).await;
    let (headers, body) = &pushed[2];
    assert_eq!(headers["content-encoding"], "aes128gcm");
    let (salt, rest) = body.split_at(16);
    let server_key = &rest[5..70];
    let secret = agreement::agree_ephemeral(browser, &agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, server_key), |s| s.to_vec()).unwrap();
    let ikm = expand(&auth, &secret, &[b"WebPush: info\0".as_slice(), &public, server_key].concat(), 32);
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &expand(salt, &ikm, b"Content-Encoding: aes128gcm\0", 16)).unwrap());
    let mut data = rest[70..].to_vec();
    let plain = key.open_in_place(aead::Nonce::try_assume_unique_for_key(&expand(salt, &ikm, b"Content-Encoding: nonce\0", 12)).unwrap(), aead::Aad::empty(), &mut data).unwrap();
    let verification: Value = serde_json::from_slice(&plain[..plain.len() - 1]).unwrap();
    assert_eq!(verification["@type"], "PushVerification");

    let destroyed = api.jmap(json!([["PushSubscription/set", { "destroy": [id] }, "0"]])).await;
    assert_eq!(destroyed[0][1]["destroyed"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn jmap_over_websocket_with_push() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = unomail::api::router(env.app.clone());
    tokio::spawn(async move { axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap() });

    let basic = base64::engine::general_purpose::STANDARD.encode(format!("bob@example.org:{PASSWORD}"));
    let connect = |origin: Option<&'static str>| {
        let mut request = format!("ws://{addr}/jmap/ws").into_client_request().unwrap();
        request.headers_mut().insert("authorization", format!("Basic {basic}").parse().unwrap());
        request.headers_mut().insert("sec-websocket-protocol", "jmap".parse().unwrap());
        if let Some(origin) = origin {
            request.headers_mut().insert("origin", origin.parse().unwrap());
        }
        tokio_tungstenite::connect_async(request)
    };
    assert!(connect(Some("https://evil.example")).await.is_err(), "other sites may not connect with the user's credentials");
    let (mut ws, response) = connect(None).await.unwrap();
    assert_eq!(response.headers()["sec-websocket-protocol"], "jmap");

    ws.send(tungstenite::Message::Text(json!({ "@type": "Request", "id": "r1", "using": ["urn:ietf:params:jmap:core"], "methodCalls": [["Core/echo", { "hello": true }, "c1"]] }).to_string().into())).await.unwrap();
    let reply = read(&mut ws).await;
    assert_eq!((reply["@type"].clone(), reply["requestId"].clone(), reply["methodResponses"][0][1]["hello"].clone()), (json!("Response"), json!("r1"), json!(true)));
    ws.send(tungstenite::Message::Text("{not json".into())).await.unwrap();
    assert_eq!(read(&mut ws).await["type"], "urn:ietf:params:jmap:error:notJSON");

    ws.send(tungstenite::Message::Text(json!({ "@type": "WebSocketPushEnable", "dataTypes": null }).to_string().into())).await.unwrap();
    let mut smtp = Client::smtp(env.mx).await;
    let mail = message("alice@remote.example", "bob@example.org", "Hi", "x");
    assert!(smtp.send_mail("alice@remote.example", &["bob@example.org"], &mail).await.starts_with("250"));
    let change = read(&mut ws).await;
    assert_eq!(change["@type"], "StateChange");
    assert!(change["pushState"].is_string());
}

async fn read(ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>) -> Value {
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(10), ws.next()).await.expect("no message").unwrap().unwrap() {
            tungstenite::Message::Text(text) => return serde_json::from_str(&text).unwrap(),
            _ => continue,
        }
    }
}
