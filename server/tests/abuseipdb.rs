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

#[tokio::test]
async fn smtp_abuse_is_reported_with_every_reason_in_one_report() {
    let (url, reports) = fake_abuseipdb().await;
    let env = TestEnv::start_with(|cfg| {
        cfg.abuseipdb_key = Some("test-key".into());
        cfg.abuseipdb_url = url;
        cfg.abuseipdb_report = true;
    })
    .await;
    let spammer = "62.60.134.133".parse().unwrap();
    reputation::report_abuse(&env.app, spammer, reputation::Abuse::SpamTrap);
    reputation::report_abuse(&env.app, spammer, reputation::Abuse::RelayProbe);
    reputation::report_abuse(&env.app, spammer, reputation::Abuse::SpamTrap);
    fail_logins(&env, "62.60.134.133", 6).await;
    reputation::report_abuse(&env.app, "192.168.1.9".parse().unwrap(), reputation::Abuse::Spam);
    let mut reported = HashMap::new();
    reputation::report_pending(&env.app, &mut reported).await;
    let sent = reports.lock().clone();
    assert_eq!(sent.len(), 1, "one report per address, none for private ones: {sent:?}");
    let query = &sent[0].0;
    assert!(query.contains("ip=62.60.134.133") && query.contains("categories=18%2C11%2C15"), "{query}");
    assert!(query.contains("spam+trap") && query.contains("relay"), "{query}");

    // Within the reporting interval the address is not reported again.
    reputation::report_abuse(&env.app, spammer, reputation::Abuse::Spam);
    reputation::report_pending(&env.app, &mut reported).await;
    assert_eq!(reports.lock().len(), 1);
}

#[tokio::test]
async fn garbage_sessions_phishing_and_web_scanners_are_reported() {
    let (url, reports) = fake_abuseipdb().await;
    let env = TestEnv::start_with(|cfg| {
        cfg.abuseipdb_key = Some("test-key".into());
        cfg.abuseipdb_url = url;
        cfg.abuseipdb_report = true;
    })
    .await;
    let scanner = "62.60.134.134".parse().unwrap();
    // Two probes are not yet a scan; the third is. Paths of this server never count.
    for path in ["/wp-login.php", "/.env", "/admin/mailboxes", "/api/auth/me"] {
        unomail::security::web_probes::note(&env.app, scanner, path);
    }
    let mut reported = HashMap::new();
    reputation::report_pending(&env.app, &mut reported).await;
    assert!(reports.lock().is_empty(), "{:?}", reports.lock());
    unomail::security::web_probes::note(&env.app, scanner, "/phpmyadmin/index.php");
    unomail::security::web_probes::note(&env.app, scanner, "/xmlrpc.php");

    let garbage = "62.60.134.135".parse().unwrap();
    reputation::report_abuse(&env.app, garbage, reputation::Abuse::ProtocolGarbage(reputation::Service::Imap));
    let phisher = "62.60.134.136".parse().unwrap();
    reputation::report_abuse(&env.app, phisher, reputation::Abuse::Phishing);
    reputation::report_pending(&env.app, &mut reported).await;

    let sent = reports.lock().clone();
    assert_eq!(sent.len(), 3, "{sent:?}");
    let query = |ip: &str| sent.iter().find(|(q, _)| q.contains(&format!("ip={ip}&"))).map(|(q, _)| q.clone()).unwrap();
    assert!(query("62.60.134.134").contains("categories=21%2C19") && query("62.60.134.134").contains("scanning"), "{}", query("62.60.134.134"));
    assert!(query("62.60.134.135").contains("categories=14%2C15") && query("62.60.134.135").contains("IMAP"), "{}", query("62.60.134.135"));
    assert!(query("62.60.134.136").contains("categories=7%2C11"), "{}", query("62.60.134.136"));
}
