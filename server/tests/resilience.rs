//! Staying responsive when others are slow or greedy: the delivery queue with a slow receiving
//! server, uploads that are too big or too many, and webhook receivers that fail.

mod common;

use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use axum::http::{Method, StatusCode};
use common::{Api, Client, Sink, TestEnv, message};
use parking_lot::Mutex;
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use unomail::{
    smtp::{delivery, queue},
    util::Address,
};

async fn wait_for(mut done: impl FnMut() -> bool, seconds: u64) -> bool {
    for _ in 0..seconds * 20 {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    done()
}

#[tokio::test]
async fn each_domain_gets_only_its_share_of_the_delivery_slots() {
    let env = TestEnv::start().await;
    let hash = env.app.store.put_blob(b"Subject: x\r\n\r\nx\r\n").await.unwrap();
    for i in 0..10 {
        delivery::enqueue(&env.app, "a@example.org", &Address::parse(&format!("u{i}@busy.example")).unwrap(), &hash, 16, None).await.unwrap();
    }
    for i in 0..2 {
        delivery::enqueue(&env.app, "a@example.org", &Address::parse(&format!("u{i}@quiet.example")).unwrap(), &hash, 16, None).await.unwrap();
    }
    let claimed = queue::claim(&env.app, 20).await.unwrap();
    assert_eq!(claimed.len(), queue::MAX_PARALLEL_PER_DOMAIN as usize + 2, "four for the busy domain, both for the quiet one");
    assert!(queue::claim(&env.app, 20).await.unwrap().is_empty(), "the busy domain's share is taken while those are under way");
}

#[tokio::test]
async fn a_slow_server_does_not_hold_up_other_mail() {
    let sink = Sink::start().await;
    sink.quirks.slow.store(true, Ordering::Relaxed);
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    let hash = env.app.store.put_blob(message("a@example.org", "x@remote.example", "Hi", "x").as_bytes()).await.unwrap();
    tokio::spawn(queue::run(env.app.clone()));

    // This one keeps a delivery slot busy for a minute.
    delivery::enqueue(&env.app, "a@example.org", &Address::parse("slow@tarpit.example").unwrap(), &hash, 64, None).await.unwrap();
    let mut started = false;
    for _ in 0..100 {
        let status: Option<String> = sqlx::query_scalar("SELECT status FROM queue").fetch_optional(&env.app.db).await.unwrap();
        if status.as_deref() == Some("sending") {
            started = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(started, "the slow delivery started");
    // Mail queued after it goes out at once.
    delivery::enqueue(&env.app, "a@example.org", &Address::parse("fast@elsewhere.example").unwrap(), &hash, 64, None).await.unwrap();
    assert!(wait_for(|| sink.received().iter().any(|m| m.to == "fast@elsewhere.example"), 10).await, "the second message was not held up");
}

#[tokio::test]
async fn uploads_are_limited_in_size_and_in_what_may_wait() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account_with("bob@example.org", unomail::auth::Role::User, Some(3_000_000)).await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;
    let upload = |data: Vec<u8>| {
        let api = api.clone();
        let path = format!("/jmap/upload/{account}");
        async move { api.raw(Method::POST, &path, data, "application/octet-stream").await.status }
    };

    // Larger than a message may be: refused without being kept.
    let limit = env.app.rt().max_message_size;
    assert_eq!(upload(vec![b'x'; limit + 1]).await, StatusCode::PAYLOAD_TOO_LARGE);

    // Uploads waiting to be sent count against the free space of the mailbox.
    let piece = |n: u8| vec![n; 900_000];
    for n in 0..3 {
        assert_eq!(upload(piece(n)).await, StatusCode::CREATED);
    }
    assert_eq!(upload(piece(9)).await, StatusCode::CONFLICT, "a fourth would not fit in the 3 MB quota");
    assert_eq!(upload(piece(1)).await, StatusCode::CREATED, "the same file again takes no more room");
}

/// A web server answering 503 to the first request and 200 afterwards; records the bodies.
async fn flaky_receiver() -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = tcp.read(&mut chunk).await.unwrap_or(0);
                    request.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&request).into_owned();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let length: usize = text.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v| v.trim().parse().ok())).unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                    if n == 0 {
                        return;
                    }
                }
                let first = {
                    let mut log = log.lock();
                    log.push(String::from_utf8_lossy(&request).into_owned());
                    log.len() == 1
                };
                let status = if first { "503 Service Unavailable" } else { "200 OK" };
                let _ = tcp.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await;
            });
        }
    });
    (addr, seen)
}

#[tokio::test]
async fn webhook_notifications_are_tried_again_when_the_receiver_fails() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account_with("admin@example.org", unomail::auth::Role::SuperAdmin, None).await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let (receiver, requests) = flaky_receiver().await;
    let created = admin.post("/api/webhooks", json!({ "url": format!("http://{receiver}/hook"), "events": ["message.received"] })).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);

    let mut mx = Client::smtp(env.mx).await;
    assert!(mx.send_mail("ann@remote.example", &["bob@example.org"], &message("ann@remote.example", "bob@example.org", "Hi", "x")).await.starts_with("250"));
    assert!(wait_for(|| requests.lock().len() >= 2, 15).await, "the event was sent again after the 503");
    let bodies: Vec<String> = requests.lock().iter().map(|r| r.split_once("\r\n\r\n").unwrap().1.to_owned()).collect();
    assert_eq!(bodies[0], bodies[1], "the same notification, unchanged");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(requests.lock().len(), 2, "no further tries once it was taken");
}
