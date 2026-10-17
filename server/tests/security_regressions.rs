//! Bounded regressions for authorization lifetimes and JMAP expansion limits.
mod common;
use common::{Api, TestEnv};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

#[tokio::test]
async fn jmap_reference_expansion_is_limited_before_large_allocations() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let mut calls = vec![json!(["Core/echo", {"seed": "x".repeat(1024)}, "0"])];
    for i in 1..=13 {
        let reference = json!({"resultOf": (i-1).to_string(), "name": "Core/echo", "path": ""});
        calls.push(json!(["Core/echo", {"#left": reference, "#right": reference}, i.to_string()]));
    }
    let reply = api.post("/jmap/api", json!({"methodCalls": calls})).await;
    assert!(reply.bytes.len() < 4 * 1024 * 1024);
    assert!(reply.status == 400 || reply.text.contains("tooLarge"), "{}", reply.text.len());
}

#[tokio::test]
async fn revoked_session_closes_websocket_and_stream() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let account = env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = unomail::api::router(env.app.clone());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let mut request = format!("ws://{addr}/jmap/ws").into_client_request().unwrap();
    request.headers_mut().insert("cookie", api.cookie.as_ref().unwrap().parse().unwrap());
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    let token = api.cookie.as_ref().unwrap().split_once('=').unwrap().1;
    let auth = unomail::api::LiveAuth::Session(unomail::util::sha256_hex(token.as_bytes()));
    let stream = unomail::api::guard_stream(env.app.clone(), auth, futures_util::stream::iter([1, 2]));
    futures_util::pin_mut!(stream);
    assert_eq!(stream.next().await, Some(1));
    sqlx::query("DELETE FROM sessions WHERE account_id = ?").bind(account.id).execute(&env.app.db).await.unwrap();
    assert_eq!(stream.next().await, None);
    let request = json!({"@type": "Request", "methodCalls": [["Mailbox/get", {"accountId": format!("a{}", account.id)}, "0"]]});
    let _ = ws.send(Message::Text(request.to_string().into())).await;
    let reply = tokio::time::timeout(std::time::Duration::from_secs(3), ws.next()).await.unwrap();
    assert!(!matches!(reply, Some(Ok(Message::Text(_)))), "revoked connection must not return data");
}

#[tokio::test]
async fn ipv6_addresses_share_connection_allowance() {
    let env = TestEnv::start().await;
    let guards: Vec<_> = (0..unomail::app::MAX_CONNECTIONS_PER_IP).map(|i| {
        env.app.accept_connection(format!("2001:db8:1:2::{i:x}").parse().unwrap()).unwrap()
    }).collect();
    assert!(env.app.accept_connection("2001:db8:1:2::ffff".parse().unwrap()).is_none());
    assert!(env.app.accept_connection("2001:db8:1:3::1".parse().unwrap()).is_some());
    drop(guards);
}
