//! Reporting password guessers to AbuseIPDB (UNOMAIL_ABUSEIPDB_REPORT).

mod common;

use std::{collections::HashMap, sync::Arc};

use axum::{Router, extract::RawQuery, http::HeaderMap, routing::post};
use common::TestEnv;
use parking_lot::Mutex;
use unomail::{auth::Protocol, security::reputation};

/// A stand-in for the AbuseIPDB API that records the reports it gets (query, key).
async fn fake_abuseipdb() -> (String, Arc<Mutex<Vec<(String, String)>>>) {
    let reports = Arc::new(Mutex::new(Vec::new()));
    let seen = reports.clone();
    let app = Router::new().route(
        "/api/v2/report",
        post(move |headers: HeaderMap, RawQuery(query): RawQuery| async move {
            let key = headers.get("Key").and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
            seen.lock().push((query.unwrap_or_default(), key));
            "{}"
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, reports)
}

async fn fail_logins(env: &TestEnv, ip: &str, times: usize) {
    for i in 0..times {
        let user = format!("guess{i}@example.org");
        assert!(unomail::auth::authenticate(&env.app.db, &env.app.limiter, &user, "wrong", ip.parse().unwrap(), Protocol::Imap).await.is_err());
    }
}

#[tokio::test]
async fn password_guessers_are_reported_once() {
    let (url, reports) = fake_abuseipdb().await;
    let env = TestEnv::start_with(|cfg| {
        cfg.abuseipdb_key = Some("test-key".into());
        cfg.abuseipdb_url = url;
        cfg.abuseipdb_report = true;
    })
    .await;
    let mut reported = HashMap::new();

    fail_logins(&env, "62.60.134.132", 2).await;
    reputation::report_pending(&env.app, &mut reported).await;
    assert!(reports.lock().is_empty(), "a couple of typos are not reported");

    fail_logins(&env, "62.60.134.132", 4).await;
    // Private addresses are never reported, however much they guess.
    fail_logins(&env, "10.0.0.5", 6).await;
    reputation::report_pending(&env.app, &mut reported).await;
    let sent = reports.lock().clone();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].1, "test-key");
    assert!(sent[0].0.contains("ip=62.60.134.132") && sent[0].0.contains("categories=18") && sent[0].0.contains("imap"), "{}", sent[0].0);
    assert!(!sent[0].0.contains("guess0"), "the accounts tried are not disclosed");
}
