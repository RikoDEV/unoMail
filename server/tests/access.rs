//! SMTP blacklist/whitelist, karma, the dashboard's live activity view and the spam filter
//! settings API.

mod common;

use std::{net::IpAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use common::{Api, Client, TestEnv, message};
use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::{io::AsyncReadExt, net::TcpListener};
use unomail::{
    auth::Role,
    security::access::{self, Verdict},
};

async fn admin_env() -> (TestEnv, Api, Api) {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    (env, admin, bob)
}

/// The greeting (or refusal) a new SMTP connection receives.
async fn greeting(env: &TestEnv) -> String {
    let mut tcp = tokio::net::TcpStream::connect(env.mx).await.unwrap();
    let mut buf = vec![0u8; 512];
    let n = tcp.read(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf[..n]).trim().to_owned()
}

#[tokio::test]
async fn blacklist_and_whitelist_rules() {
    let (env, admin, bob) = admin_env().await;
    assert!(greeting(&env).await.starts_with("220 "));

    // Only super administrators manage the lists, and input is validated.
    assert_eq!(bob.get("/api/smtp-access/rules").await.status, StatusCode::FORBIDDEN);
    assert_eq!(bob.post("/api/smtp-access/rules", json!({ "list": "whitelist", "network": "127.0.0.1" })).await.status, StatusCode::FORBIDDEN);
    for bad in [
        json!({ "list": "greylist", "network": "127.0.0.1" }),
        json!({ "list": "blacklist", "network": "not an address" }),
        json!({ "list": "blacklist", "network": "0.0.0.0/0" }),
        json!({ "list": "blacklist", "network": "10.0.0.0/7" }),
        json!({ "list": "blacklist", "network": "127.0.0.1", "priority": 5000 }),
        json!({ "list": "blacklist", "network": "127.0.0.1", "description": "x".repeat(300) }),
    ] {
        assert_eq!(admin.post("/api/smtp-access/rules", bad.clone()).await.status, StatusCode::BAD_REQUEST, "{bad}");
    }

    // A blacklisted network is refused at connect, on every SMTP port, effective immediately.
    let created = admin.post("/api/smtp-access/rules", json!({ "list": "blacklist", "network": "127.0.0.99/8", "description": "Test\r\nblock" })).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let block = created.body["id"].as_i64().unwrap();
    assert_eq!(admin.post("/api/smtp-access/rules", json!({ "list": "blacklist", "network": "127.0.0.0/8" })).await.status, StatusCode::CONFLICT);
    assert_eq!(greeting(&env).await, "554 5.7.1 Service unavailable; client host [127.0.0.1] is blocked");
    let mut tcp = tokio::net::TcpStream::connect(env.submission).await.unwrap();
    let mut buf = vec![0u8; 128];
    let n = tcp.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("554 5.7.1"));

    let rules = admin.get("/api/smtp-access/rules").await.body;
    assert_eq!(rules.as_array().unwrap().len(), 1);
    let rule = &rules[0];
    assert_eq!((rule["network"].as_str(), rule["list"].as_str(), rule["hits"].as_i64(), rule["description"].as_str()), (Some("127.0.0.0/8"), Some("blacklist"), Some(2), Some("Testblock")));
    assert!(rule["last_seen"].is_i64() && rule["rdns"].is_null());

    // A more specific whitelist entry is an exception inside the blocked range.
    let allow = admin.post("/api/smtp-access/rules", json!({ "list": "whitelist", "network": "127.0.0.1", "description": "monitoring" })).await.body["id"].as_i64().unwrap();
    assert!(greeting(&env).await.starts_with("220 "));
    // Priority outranks specificity.
    assert_eq!(admin.put(&format!("/api/smtp-access/rules/{block}"), json!({ "list": "blacklist", "network": "127.0.0.0/8", "priority": 10 })).await.status, StatusCode::OK);
    assert!(greeting(&env).await.starts_with("554 "));
    assert_eq!(admin.put(&format!("/api/smtp-access/rules/{allow}"), json!({ "list": "whitelist", "network": "127.0.0.1", "priority": 20 })).await.status, StatusCode::OK);
    assert!(greeting(&env).await.starts_with("220 "));
    let listed = admin.get("/api/smtp-access/rules").await.body;
    assert_eq!(listed[0]["network"], "127.0.0.1", "single addresses are shown without a prefix length, highest priority first");

    assert_eq!(admin.delete(&format!("/api/smtp-access/rules/{allow}")).await.status, StatusCode::OK);
    assert!(greeting(&env).await.starts_with("554 "));
    assert_eq!(admin.delete(&format!("/api/smtp-access/rules/{block}")).await.status, StatusCode::OK);
    assert_eq!(admin.delete(&format!("/api/smtp-access/rules/{block}")).await.status, StatusCode::NOT_FOUND);
    assert!(greeting(&env).await.starts_with("220 "));
}

#[tokio::test]
async fn daily_statistics_count_connections_and_mail() {
    let (env, admin, bob) = admin_env().await;
    assert_eq!(bob.get("/api/dashboard/daily").await.status, StatusCode::FORBIDDEN);

    assert!(greeting(&env).await.starts_with("220 "));
    let block = admin.post("/api/smtp-access/rules", json!({ "list": "blacklist", "network": "127.0.0.1" })).await.body["id"].as_i64().unwrap();
    assert!(greeting(&env).await.starts_with("554 "));
    admin.delete(&format!("/api/smtp-access/rules/{block}")).await;

    // One message delivered, one quarantined (its sender is blocked by Bob).
    bob.post("/api/me/blocked-senders", json!({ "sender": "pest@remote.example" })).await;
    for (from, subject) in [("friend@remote.example", "Hello"), ("pest@remote.example", "Buy now")] {
        let mut c = Client::smtp(env.mx).await;
        assert!(c.send_mail(from, &["bob@example.org"], &message(from, "bob@example.org", subject, "x")).await.starts_with("250"));
    }

    let days = admin.get("/api/dashboard/daily?days=7").await.body["days"].clone();
    let days = days.as_array().unwrap();
    assert_eq!(days.len(), 7, "every day of the range, oldest first");
    assert!(days[..6].iter().all(|day| day["connections_valid"] == 0 && day["delivered_local"] == 0));
    let today = &days[6];
    assert_eq!(today["date"].as_str().unwrap().len(), 10);
    // Counted in memory until written, and shown either way.
    let expected = json!({ "date": today["date"], "connections_valid": 3, "connections_blocked": 1, "connections_limited": 0, "delivered_local": 1, "delivered_remote": 0, "bounced": 0, "quarantined": 1, "discarded": 0 });
    assert_eq!(today, &expected);
    unomail::dailystats::flush(&env.app).await;
    assert_eq!(&admin.get("/api/dashboard/daily?days=1").await.body["days"][0], &expected);
}

#[tokio::test]
async fn karma_follows_behaviour_and_blacklists_repeat_offenders() {
    let (env, admin, bob) = admin_env().await;

    // Real traffic: an unknown recipient costs a point, an accepted message earns one.
    let mut c = Client::smtp(env.mx).await;
    c.cmd("EHLO remote.example").await;
    c.cmd("MAIL FROM:<ann@remote.example>").await;
    assert!(c.cmd("RCPT TO:<nobody@example.org>").await.starts_with("550"));
    c.cmd("RSET").await;
    assert!(c.send_mail("ann@remote.example", &["bob@example.org"], &message("ann@remote.example", "bob@example.org", "Hi", "x")).await.starts_with("250"));
    assert_eq!(bob.get("/api/smtp-access/karma").await.status, StatusCode::FORBIDDEN);
    let karma = admin.get("/api/smtp-access/karma").await.body;
    assert_eq!(karma.as_array().unwrap().len(), 1);
    let record = &karma[0];
    assert_eq!((record["ip"].as_str(), record["score"].as_i64(), record["good"].as_i64(), record["bad"].as_i64(), record["hits"].as_i64()), (Some("127.0.0.1"), Some(0), Some(1), Some(1), Some(2)));
    assert_eq!(record["last_event"], "message accepted");

    // A public address that keeps misbehaving is blacklisted automatically, for a day.
    let offender: IpAddr = "203.0.113.50".parse().unwrap();
    for _ in 0..3 {
        access::karma(&env.app, offender, -5, "message rejected").await;
    }
    assert_eq!(access::check(&env.app, offender).await, Verdict::Neutral, "a score of -15 is not enough");
    access::karma(&env.app, offender, -5, "message rejected").await;
    assert_eq!(access::check(&env.app, offender).await, Verdict::Blocked);
    assert_eq!(admin.get("/api/smtp-access/rules").await.body, json!([]), "automatic rules are listed separately");
    let auto = admin.get("/api/smtp-access/rules?source=auto").await.body;
    assert_eq!(auto.as_array().unwrap().len(), 1);
    assert_eq!((auto[0]["network"].as_str(), auto[0]["source"].as_str(), auto[0]["hits"].as_i64()), (Some("203.0.113.50"), Some("auto"), Some(1)));
    assert_eq!(auto[0]["description"], "Karma dropped to -20 (message rejected)");
    let expires = auto[0]["expires_at"].as_i64().unwrap();
    assert!((expires - unomail::util::now() - access::AUTO_BLOCK_SECS).abs() < 5);

    // Good behaviour never creates a rule; private addresses are scored but never blocked.
    let friend: IpAddr = "198.51.100.7".parse().unwrap();
    for _ in 0..40 {
        access::karma(&env.app, friend, 5, "message accepted").await;
    }
    let internal: IpAddr = "10.1.2.3".parse().unwrap();
    for _ in 0..40 {
        access::karma(&env.app, internal, -5, "authentication failure").await;
    }
    assert_eq!(access::check(&env.app, friend).await, Verdict::Neutral);
    assert_eq!(access::check(&env.app, internal).await, Verdict::Neutral);
    let karma = admin.get("/api/smtp-access/karma").await.body;
    let score = |ip: &str| karma.as_array().unwrap().iter().find(|r| r["ip"] == ip).unwrap()["score"].as_i64().unwrap();
    assert_eq!((score("198.51.100.7"), score("10.1.2.3")), (100, -100), "scores are capped");

    // An administrator can adopt an automatic rule (it becomes permanent) or lift it.
    let id = auto[0]["id"].as_i64().unwrap();
    assert_eq!(admin.put(&format!("/api/smtp-access/rules/{id}"), json!({ "list": "blacklist", "network": "203.0.113.50", "description": "known spammer" })).await.status, StatusCode::OK);
    assert_eq!(admin.get("/api/smtp-access/rules?source=auto").await.body, json!([]));
    let adopted = admin.get("/api/smtp-access/rules").await.body;
    assert_eq!((adopted[0]["source"].as_str(), adopted[0]["expires_at"].is_null()), (Some("user"), true));
    assert_eq!(admin.delete(&format!("/api/smtp-access/rules/{id}")).await.status, StatusCode::OK);
    assert_eq!(access::check(&env.app, offender).await, Verdict::Neutral);

    // Forgetting a record gives the address a clean slate.
    assert_eq!(admin.delete("/api/smtp-access/karma/203.0.113.50").await.status, StatusCode::OK);
    assert_eq!(admin.delete("/api/smtp-access/karma/203.0.113.50").await.status, StatusCode::NOT_FOUND);
    assert_eq!(admin.delete("/api/smtp-access/karma/not-an-ip").await.status, StatusCode::BAD_REQUEST);

    // Whitelisted peers are not scored.
    admin.post("/api/smtp-access/rules", json!({ "list": "whitelist", "network": "127.0.0.1" })).await;
    let mut c = Client::smtp(env.mx).await;
    c.cmd("EHLO remote.example").await;
    c.cmd("MAIL FROM:<ann@remote.example>").await;
    c.cmd("RCPT TO:<nobody@example.org>").await;
    let after = admin.get("/api/smtp-access/karma").await.body;
    assert_eq!(after.as_array().unwrap().iter().find(|r| r["ip"] == "127.0.0.1").unwrap()["hits"], 2, "unchanged");
}

#[tokio::test]
async fn dashboard_shows_remote_addresses_and_the_latest_smtp_replies() {
    let (env, admin, bob) = admin_env().await;
    assert_eq!(bob.get("/api/dashboard/activity").await.status, StatusCode::FORBIDDEN);

    let mut c = Client::smtp(env.mx).await;
    c.cmd("EHLO remote.example").await;
    c.cmd("MAIL FROM:<ann@remote.example>").await;
    c.cmd("RCPT TO:<nobody@example.org>").await;
    assert_eq!(c.cmd("QUIT").await, "221 2.0.0 mail.test.example closing connection. Have a jolly good day.");

    let activity = admin.get("/api/dashboard/activity").await.body;
    let ips = activity["remote_ips"].as_array().unwrap();
    assert_eq!(ips.len(), 1);
    assert_eq!((ips[0]["ip"].as_str(), ips[0]["connections"].as_i64()), (Some("127.0.0.1"), Some(1)));
    assert!(ips[0]["country"].is_null() && ips[0]["rdns"].is_null(), "private addresses are never looked up");
    let replies = activity["replies"].as_array().unwrap();
    let texts: Vec<(i64, &str)> = replies.iter().map(|r| (r["code"].as_i64().unwrap(), r["text"].as_str().unwrap())).collect();
    assert_eq!(texts[0], (221, "2.0.0 mail.test.example closing connection. Have a jolly good day."), "newest first");
    assert_eq!(texts[1], (550, "5.1.1 <nobody@example.org>: Recipient address rejected: User unknown"));
    assert_eq!(texts.last().unwrap(), &(220, "mail.test.example ESMTP unoMail"));
    assert!(replies.iter().all(|r| r["ip"] == "127.0.0.1" && r["ts"].is_i64()));
}

#[derive(Clone, Default)]
struct Controller {
    posts: Arc<Mutex<Vec<(String, Value)>>>,
}

/// A stand-in for Rspamd's controller API.
async fn controller() -> (String, Controller) {
    let state = Controller::default();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    async fn save(State(c): State<Controller>, uri: axum::http::Uri, Json(body): Json<Value>) -> Json<Value> {
        c.posts.lock().push((uri.path().to_owned(), body));
        Json(json!({ "success": true }))
    }
    let router = Router::new()
        .route("/stat", get(|| async { Json(json!({ "version": "3.9", "scanned": 120, "learned": 7, "actions": { "reject": 3, "no action": 110 }, "config_id": "internal" })) }))
        .route("/actions", get(|| async { Json(json!([{ "action": "reject", "value": 15.0 }, { "action": "add header", "value": 6.0 }])) }))
        .route("/symbols", get(|| async { Json(json!([{ "group": "headers", "rules": [{ "symbol": "MISSING_DATE", "weight": 1.0, "description": "Message date is missing" }] }])) }))
        .route("/history", get(|| async { Json(json!({ "version": 2, "rows": [{ "unix_time": 5, "ip": "203.0.113.1", "action": "reject", "score": 20.5, "required_score": 15, "subject": "Buy now", "symbols": { "GTUBE": { "score": 20.0 } } }] })) }))
        .route("/saveactions", post(save))
        .route("/savesymbols", post(save))
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}/"), state)
}

#[tokio::test]
async fn spam_filter_settings_are_read_and_changed_through_the_controller() {
    let (url, rspamd) = controller().await;
    let env = TestEnv::start_with(|cfg| cfg.rspamd_controller_url = Some(url)).await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;

    assert_eq!(bob.get("/api/spam-filter").await.status, StatusCode::FORBIDDEN);
    assert_eq!(bob.put("/api/spam-filter/thresholds", json!({ "reject": 1, "add_header": 0 })).await.status, StatusCode::FORBIDDEN);
    let overview = admin.get("/api/spam-filter").await.body;
    assert_eq!((overview["configured"].as_bool(), overview["available"].as_bool()), (Some(true), Some(true)), "{overview}");
    assert_eq!((overview["stat"]["scanned"].as_i64(), overview["stat"]["version"].as_str()), (Some(120), Some("3.9")));
    assert!(overview["stat"].get("config_id").is_none());
    assert_eq!(overview["actions"][0], json!({ "action": "reject", "value": 15.0 }));
    assert_eq!(overview["groups"][0]["rules"][0]["symbol"], "MISSING_DATE");
    assert_eq!((overview["history"][0]["subject"].as_str(), overview["history"][0]["symbols"][0]["name"].as_str()), (Some("Buy now"), Some("GTUBE")));

    for bad in [json!({ "reject": 5, "add_header": 6 }), json!({ "reject": 5, "add_header": 5 }), json!({ "reject": -1, "add_header": -2 }), json!({ "reject": 5000, "add_header": 1 }), json!({ "reject": "high", "add_header": 1 })] {
        assert_ne!(admin.put("/api/spam-filter/thresholds", bad.clone()).await.status, StatusCode::OK, "{bad}");
    }
    assert_eq!(admin.put("/api/spam-filter/thresholds", json!({ "reject": 12.5, "add_header": 5 })).await.status, StatusCode::OK);
    for bad in [json!({ "name": "lower_case", "value": 1 }), json!({ "name": "X; rm -rf", "value": 1 }), json!({ "name": "", "value": 1 }), json!({ "name": "GTUBE", "value": 1e9 })] {
        assert_eq!(admin.put("/api/spam-filter/rules", bad.clone()).await.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert_eq!(admin.put("/api/spam-filter/rules", json!({ "name": "MISSING_DATE", "value": 2.5 })).await.status, StatusCode::OK);
    assert_eq!(
        *rspamd.posts.lock(),
        vec![("/saveactions".to_owned(), json!([12.5, null, 5.0, null])), ("/savesymbols".to_owned(), json!([{ "name": "MISSING_DATE", "value": 2.5 }]))],
        "only validated changes reach the filter"
    );
}

#[tokio::test]
async fn spam_filter_page_degrades_gracefully() {
    let (_env, admin, _bob) = admin_env().await;
    assert_eq!(admin.get("/api/spam-filter").await.body, json!({ "configured": false, "available": false }));
    assert_eq!(admin.put("/api/spam-filter/thresholds", json!({ "reject": 15, "add_header": 6 })).await.status, StatusCode::BAD_REQUEST);

    let env = TestEnv::start_with(|cfg| cfg.rspamd_controller_url = Some("http://127.0.0.1:1".into())).await;
    env.domain("example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let overview = admin.get("/api/spam-filter").await.body;
    assert_eq!((overview["configured"].as_bool(), overview["available"].as_bool(), overview["error"].as_str()), (Some(true), Some(false), Some("the spam filter cannot be reached")));
}

#[tokio::test]
async fn capacity_history_for_the_dashboard_charts() {
    let (env, admin, bob) = admin_env().await;
    assert_eq!(bob.get("/api/dashboard/system").await.status, StatusCode::FORBIDDEN);

    // Nothing stored yet: the server measures on the spot.
    let first = admin.get("/api/dashboard/system").await.body;
    let samples = first["samples"].as_array().unwrap();
    assert_eq!(samples.len(), 1);
    let s = &samples[0];
    assert!(s["mem_total"].as_i64().unwrap() > 0 && s["mem_used"].as_i64().unwrap() <= s["mem_total"].as_i64().unwrap(), "{s}");
    assert!(s["disk_total"].as_i64().unwrap() > 0 && s["disk_free"].as_i64().unwrap() <= s["disk_total"].as_i64().unwrap(), "{s}");
    assert!(s["process"].as_i64().unwrap() > 0);

    // A week of minute samples is thinned out to what a chart can show, newest included.
    let now = unomail::util::now();
    sqlx::query("DELETE FROM system_samples").execute(&env.app.db).await.unwrap();
    let mut tx = env.app.db.begin().await.unwrap();
    for minute in 0..(3 * 24 * 60) {
        sqlx::query("INSERT INTO system_samples (ts, disk_free, disk_total, mem_used, mem_total, process) VALUES (?, ?, 1000, 500, 1000, 10)")
            .bind(now - minute * 60)
            .bind(1000 - minute / 10)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    let day = admin.get("/api/dashboard/system?hours=24").await.body["samples"].as_array().unwrap().clone();
    assert!(day.len() > 100 && day.len() as i64 <= unomail::sysstat::MAX_POINTS + 1, "{}", day.len());
    assert_eq!(day.last().unwrap()["ts"].as_i64(), Some(now));
    assert!(day.first().unwrap()["ts"].as_i64().unwrap() >= now - 24 * 3600);
    assert!(day.windows(2).all(|pair| pair[0]["ts"].as_i64() < pair[1]["ts"].as_i64()), "in time order");
    let three_days = admin.get("/api/dashboard/system?hours=72").await.body["samples"].as_array().unwrap().clone();
    assert!(three_days.len() as i64 <= unomail::sysstat::MAX_POINTS + 1);
    assert!(three_days.first().unwrap()["ts"].as_i64().unwrap() < now - 48 * 3600);
    assert_eq!(admin.get("/api/dashboard/system?hours=100000").await.status, StatusCode::OK, "the window is clamped");
}
