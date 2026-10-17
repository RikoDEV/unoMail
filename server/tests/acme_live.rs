//! Certificate issuance against a real ACME server (Pebble, Let's Encrypt's test CA).
//!
//! Ignored by default because it needs Docker. To run it:
//!
//! ```sh
//! docker run -d --name pebble -p 14000:14000 -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
//!     --add-host host.docker.internal:host-gateway ghcr.io/letsencrypt/pebble:latest
//! docker cp pebble:/test/certs/pebble.minica.pem pebble-root.pem
//! UNOMAIL_PEBBLE_ROOT=$PWD/pebble-root.pem cargo test --test acme_live -- --ignored
//! ```
//!
//! Pebble validates HTTP-01 challenges by connecting to `host.docker.internal:5002`, which is
//! where this test serves the challenge responses.

mod common;

use common::Client;
use tokio::net::TcpListener;
use unomail::{
    acme::{self, AcmeConfig, Challenge},
    api,
    app::App,
    config::Config,
    http,
    smtp::server::{self, Mode},
    tls::CertKind,
};

const DOMAIN: &str = "host.docker.internal";

#[tokio::test]
#[ignore = "requires a running Pebble ACME server"]
async fn issues_and_renews_a_certificate_with_http01_validation() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = std::env::var("UNOMAIL_PEBBLE_ROOT").expect("set UNOMAIL_PEBBLE_ROOT to Pebble's root certificate");
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_tests(dir.path().to_path_buf());
    cfg.hostname = DOMAIN.into();
    cfg.acme_directory = std::env::var("UNOMAIL_PEBBLE_DIRECTORY").unwrap_or_else(|_| "https://localhost:14000/dir".into());
    cfg.acme_ca_file = Some(root.into());
    let app = App::new(cfg, None).await.unwrap();
    assert_eq!(app.tls.info().kind, CertKind::SelfSigned);

    // Pebble's validation authority connects to port 5002 for HTTP-01.
    let challenge_listener = TcpListener::bind("0.0.0.0:5002").await.expect("port 5002 must be free");
    tokio::spawn(http::serve(challenge_listener, api::redirect_router(app.clone()), None));
    let smtps = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let smtps_addr = smtps.local_addr().unwrap();
    tokio::spawn(server::serve(app.clone(), Mode::Smtps, smtps));

    let config = AcmeConfig { domains: vec![DOMAIN.into()], email: "admin@example.org".into(), challenge: Challenge::Http01, cloudflare_token: None }
        .validated()
        .unwrap();
    acme::save_config(&app, &config).await.unwrap();

    acme::issue(&app).await.expect("certificate issuance failed");
    let issued = app.tls.info();
    assert_eq!(issued.kind, CertKind::Acme);
    assert_eq!(issued.domains, [DOMAIN]);
    assert!(issued.issuer.contains("Pebble"), "{}", issued.issuer);
    assert!(issued.seconds_remaining() > 3600);
    assert!(app.tls.http_challenges.lock().is_empty(), "challenge tokens are removed after validation");
    assert!(acme::last_error(&app).await.is_none());
    assert!(!acme::needs_issue(issued.kind, &issued.domains, issued.seconds_remaining(), &config) || issued.seconds_remaining() < unomail::tls::RENEW_BEFORE_SECS);

    // The certificate is live on already-running listeners without a restart.
    let mut client = Client::connect_tls(smtps_addr).await;
    assert!(client.read_reply().await.starts_with("220 "));

    // Renewal reuses the stored account and replaces the certificate.
    acme::issue(&app).await.expect("renewal failed");
    let renewed = app.tls.info();
    assert_eq!(renewed.kind, CertKind::Acme);
    assert_ne!(renewed.id, issued.id);
    let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM settings WHERE key LIKE 'acme.credentials:%'").fetch_one(&app.db).await.unwrap();
    assert_eq!(accounts, 1, "one ACME account is registered and reused");

    // A name Pebble cannot reach fails validation and leaves the working certificate alone.
    let unreachable = AcmeConfig { domains: vec!["unreachable.invalid".into()], ..config.clone() };
    acme::save_config(&app, &unreachable).await.unwrap();
    assert!(acme::issue(&app).await.is_err());
    assert_eq!(app.tls.info().id, renewed.id);
    assert!(acme::last_error(&app).await.is_some());
    assert!(app.tls.http_challenges.lock().is_empty());
}

/// DNS-01 issuance, including a wildcard name, through the Cloudflare client.
///
/// Needs a second Pebble that resolves through `pebble-challtestsrv`:
///
/// ```sh
/// docker network create acme
/// docker run -d --name challtestsrv --network acme -p 8055:8055 ghcr.io/letsencrypt/pebble-challtestsrv:latest \
///     -http01 "" -https01 "" -tlsalpn01 "" -doh ""
/// docker run -d --name pebble-dns --network acme -p 14001:14000 -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 -e PEBBLE_AUTHZREUSE=0 \
///     ghcr.io/letsencrypt/pebble:latest -config /test/config/pebble-config.json -dnsserver challtestsrv:8053
/// ```
///
/// The Cloudflare API itself is replaced by a local stand-in that implements the three calls
/// the client makes (zone lookup, record creation, record deletion) and publishes the records
/// on the test DNS server, so the CA performs a real DNS validation of what the client wrote.
#[tokio::test]
#[ignore = "requires Pebble with pebble-challtestsrv"]
async fn issues_a_wildcard_certificate_with_dns01_validation() {
    use std::sync::{Arc, Mutex};

    use axum::{
        Json, Router,
        extract::{Path, Query, State},
        http::HeaderMap,
        routing::{delete, get, post},
    };
    use serde_json::{Value, json};

    const TOKEN: &str = "cf_test_token_123";
    #[derive(Clone, Default)]
    struct Mock {
        dns: String,
        log: Arc<Mutex<Vec<String>>>,
    }
    fn authorized(headers: &HeaderMap) -> bool {
        headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {TOKEN}"))
    }
    async fn zones(State(mock): State<Mock>, headers: HeaderMap, Query(q): Query<std::collections::HashMap<String, String>>) -> Json<Value> {
        if !authorized(&headers) {
            return Json(json!({ "success": false, "errors": [{ "message": "Invalid API token" }] }));
        }
        let name = q.get("name").cloned().unwrap_or_default();
        mock.log.lock().unwrap().push(format!("zones {name}"));
        let result = if name == "dns01.test" { json!([{ "id": "zone1", "name": name }]) } else { json!([]) };
        Json(json!({ "success": true, "result": result }))
    }
    async fn create(State(mock): State<Mock>, headers: HeaderMap, Path(zone): Path<String>, Json(body): Json<Value>) -> Json<Value> {
        if !authorized(&headers) || zone != "zone1" || body["type"] != "TXT" {
            return Json(json!({ "success": false, "errors": [{ "message": "bad request" }] }));
        }
        let (name, value) = (body["name"].as_str().unwrap().to_owned(), body["content"].as_str().unwrap().trim_matches('"').to_owned());
        reqwest::Client::new().post(format!("{}/set-txt", mock.dns)).json(&json!({ "host": format!("{name}."), "value": value })).send().await.unwrap();
        let mut log = mock.log.lock().unwrap();
        log.push(format!("create {name}"));
        Json(json!({ "success": true, "result": { "id": format!("rec{}", log.len()) } }))
    }
    async fn remove(State(mock): State<Mock>, headers: HeaderMap, Path((_zone, record)): Path<(String, String)>) -> Json<Value> {
        if !authorized(&headers) {
            return Json(json!({ "success": false, "errors": [] }));
        }
        mock.log.lock().unwrap().push(format!("delete {record}"));
        Json(json!({ "success": true, "result": { "id": record } }))
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = std::env::var("UNOMAIL_PEBBLE_ROOT").expect("set UNOMAIL_PEBBLE_ROOT to Pebble's root certificate");
    let mock = Mock { dns: std::env::var("UNOMAIL_CHALLTESTSRV").unwrap_or_else(|_| "http://localhost:8055".into()), log: Arc::default() };
    reqwest::Client::new().post(format!("{}/clear-txt", mock.dns)).json(&json!({ "host": "_acme-challenge.dns01.test." })).send().await.expect("pebble-challtestsrv must be running");
    let api_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = api_listener.local_addr().unwrap();
    let router = Router::new().route("/zones", get(zones)).route("/zones/{zone}/dns_records", post(create)).route("/zones/{zone}/dns_records/{record}", delete(remove)).with_state(mock.clone());
    tokio::spawn(async move { axum::serve(api_listener, router).await.unwrap() });

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_tests(dir.path().to_path_buf());
    cfg.hostname = "mail.dns01.test".into();
    cfg.acme_directory = std::env::var("UNOMAIL_PEBBLE_DNS_DIRECTORY").unwrap_or_else(|_| "https://localhost:14001/dir".into());
    cfg.acme_ca_file = Some(root.into());
    cfg.cloudflare_api_url = format!("http://{api_addr}");
    cfg.acme_dns_wait_secs = 1;
    let app = App::new(cfg, None).await.unwrap();

    let config = AcmeConfig { domains: vec!["dns01.test".into(), "*.dns01.test".into()], email: "admin@example.org".into(), challenge: Challenge::Dns01, cloudflare_token: Some(TOKEN.into()) }
        .validated()
        .unwrap();
    acme::save_config(&app, &config).await.unwrap();
    acme::issue(&app).await.expect("DNS-01 issuance failed");

    let issued = app.tls.info();
    assert_eq!(issued.kind, CertKind::Acme);
    let mut names = issued.domains.clone();
    names.sort();
    assert_eq!(names, ["*.dns01.test", "dns01.test"]);
    assert!(unomail::tls::san_matches("*.dns01.test", "mail.dns01.test"), "the wildcard covers the mail host");

    let log = mock.log.lock().unwrap().clone();
    let count = |prefix: &str| log.iter().filter(|l| l.starts_with(prefix)).count();
    assert_eq!(count("create _acme-challenge.dns01.test"), 2, "one TXT record per authorization: {log:?}");
    assert_eq!(count("delete rec"), 2, "challenge records are cleaned up afterwards: {log:?}");
    assert!(log.iter().any(|l| l == "zones dns01.test"), "{log:?}");

    // A wrong API token fails cleanly and keeps the certificate that is already active.
    acme::save_config(&app, &AcmeConfig { cloudflare_token: Some("wrong".into()), ..config }).await.unwrap();
    let error = acme::issue(&app).await.unwrap_err().to_string();
    assert!(error.contains("Cloudflare API error"), "{error}");
    assert_eq!(app.tls.info().id, issued.id);
}
