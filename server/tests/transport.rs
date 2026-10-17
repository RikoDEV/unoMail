//! MTA-STS published for hosted domains, and SMTP TLS reporting both ways.

mod common;

use axum::http::{Method, StatusCode, header};
use common::{Api, Client, TestEnv};
use serde_json::json;
use unomail::smtp::transport::{self, Applied};

#[tokio::test]
async fn hosted_domains_publish_an_mta_sts_policy_when_asked_to() {
    let env = TestEnv::start().await;
    let domain = env.domain("example.org").await;
    env.account_with("admin@example.org", unomail::auth::Role::SuperAdmin, None).await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let policy = |host: &'static str| {
        let api = Api::new(&env);
        async move { api.send(Method::GET, "/.well-known/mta-sts.txt", None, &[("host", host)]).await }
    };

    // Off unless switched on.
    assert_eq!(admin.get(&format!("/api/domains/{domain}")).await.body["mta_sts_mode"], "none");
    assert_eq!(policy("mta-sts.example.org").await.status, StatusCode::NOT_FOUND);
    assert_eq!(admin.patch(&format!("/api/domains/{domain}"), json!({ "mta_sts_mode": "sometimes" })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(admin.patch(&format!("/api/domains/{domain}"), json!({ "mta_sts_mode": "testing" })).await.status, StatusCode::OK);
    let served = policy("mta-sts.example.org").await;
    assert_eq!(served.status, StatusCode::OK);
    assert!(served.headers[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/plain"));
    assert_eq!(served.text, "version: STSv1\nmode: testing\nmx: mail.test.example\nmax_age: 86400\n");
    assert_eq!(policy("mta-sts.example.org:443").await.status, StatusCode::OK, "with a port in the Host header");
    // Only for hosted domains, and only on the mta-sts host.
    for other in ["mta-sts.other.example", "example.org", "mail.test.example", ""] {
        assert_eq!(policy(other).await.status, StatusCode::NOT_FOUND, "{other}");
    }

    // The DNS page tells what to publish: the record (with the policy's id), the host, reporting.
    admin.patch(&format!("/api/domains/{domain}"), json!({ "mta_sts_mode": "enforce" })).await;
    assert!(policy("mta-sts.example.org").await.text.contains("mode: enforce\n"));
    let records = admin.get(&format!("/api/domains/{domain}/dns")).await.body;
    let checks = records["checks"].as_array().unwrap();
    let find = |id: &str| checks.iter().find(|c| c["id"] == id).cloned().unwrap_or_else(|| panic!("{id} missing: {records}"));
    let sts = find("mta-sts");
    assert_eq!(sts["record_name"], "_mta-sts.example.org");
    let id = transport::policy_id(&transport::policy_for_hosted("enforce", "mail.test.example").unwrap());
    assert_eq!(sts["record_value"], format!("v=STSv1; id={id}"));
    assert_eq!(find("mta-sts-host")["record_value"], "mail.test.example.");
    assert_eq!(find("tls-rpt")["record_value"], "v=TLSRPTv1; rua=mailto:postmaster@example.org");
    let dane = find("dane");
    assert_eq!(dane["record_name"], "_25._tcp.mail.test.example");
    assert!(dane["record_value"].as_str().unwrap().starts_with("3 1 1 ") && dane["record_value"].as_str().unwrap().len() == 6 + 64);
    admin.patch(&format!("/api/domains/{domain}"), json!({ "mta_sts_mode": "none" })).await;
    let records = admin.get(&format!("/api/domains/{domain}/dns")).await.body;
    assert!(!records["checks"].as_array().unwrap().iter().any(|c| c["id"] == "mta-sts"));
}

#[tokio::test]
async fn sessions_are_counted_and_reported_per_receiving_domain() {
    let env = TestEnv::start().await;
    let sts = Applied { policy_type: "sts", policy_string: vec!["version: STSv1".into(), "mode: enforce".into(), "mx: mx.partner.example".into(), "max_age: 604800".into()] };
    for _ in 0..3 {
        transport::record(&env.app, "partner.example", &sts, "mx.partner.example", "203.0.113.5", None).await;
    }
    transport::record(&env.app, "partner.example", &sts, "mx.partner.example", "203.0.113.5", Some("certificate-expired")).await;
    let none = Applied { policy_type: "no-policy-found", policy_string: Vec::new() };
    transport::record(&env.app, "partner.example", &none, "mx2.partner.example", "203.0.113.6", None).await;
    transport::record(&env.app, "elsewhere.example", &none, "mx.elsewhere.example", "198.51.100.1", None).await;

    let day = unomail::util::now().div_euclid(86_400);
    let report = transport::build_report(&env.app, "partner.example", day).await.unwrap().unwrap();
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["organization-name"], "mail.test.example");
    assert_eq!(json["report-id"], format!("{day}.partner.example@mail.test.example"));
    let policies = json["policies"].as_array().unwrap();
    assert_eq!(policies.len(), 2, "{json}");
    let enforced = policies.iter().find(|p| p["policy"]["policy-type"] == "sts").unwrap();
    assert_eq!(enforced["summary"], json!({ "total-successful-session-count": 3, "total-failure-session-count": 1 }));
    assert_eq!(enforced["policy"]["mx-host"], json!(["mx.partner.example"]));
    assert_eq!(enforced["policy"]["policy-string"][1], "mode: enforce");
    assert_eq!(enforced["failure-details"][0]["result-type"], "certificate-expired");
    assert_eq!(enforced["failure-details"][0]["receiving-ip"], "203.0.113.5");
    let plain = policies.iter().find(|p| p["policy"]["policy-type"] == "no-policy-found").unwrap();
    assert_eq!(plain["summary"]["total-successful-session-count"], 1);
    assert!(transport::build_report(&env.app, "nobody.example", day).await.unwrap().is_none());
    // Today's results wait for the day to end.
    transport::send_reports(&env.app).await;
    let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tls_rpt_results").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(pending, 4, "three successes share a row");
}

#[tokio::test]
async fn reports_from_other_servers_are_stored_for_the_domains_they_concern() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.domain("other.example").await;
    env.account("postmaster@example.org").await;
    env.account_with("admin@example.org", unomail::auth::Role::SuperAdmin, None).await;
    let report = json!({
        "organization-name": "Big Mail Inc.",
        "date-range": { "start-datetime": "2026-10-13T00:00:00Z", "end-datetime": "2026-10-13T23:59:59Z" },
        "contact-info": "smtp-tls-reporting@bigmail.example",
        "report-id": "2026-10-13T00:00:00Z_example.org",
        "policies": [{
            "policy": { "policy-type": "sts", "policy-string": ["version: STSv1", "mode: testing", "mx: mail.test.example", "max_age: 86400"], "policy-domain": "example.org", "mx-host": ["mail.test.example"] },
            "summary": { "total-successful-session-count": 120, "total-failure-session-count": 2 },
            "failure-details": [{ "result-type": "certificate-host-mismatch", "sending-mta-ip": "198.51.100.9", "receiving-ip": "203.0.113.1", "receiving-mx-hostname": "mail.test.example", "failed-session-count": 2 }]
        }, {
            "policy": { "policy-type": "no-policy-found", "policy-domain": "unrelated.example" },
            "summary": { "total-successful-session-count": 5, "total-failure-session-count": 0 }
        }]
    });
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gz, report.to_string().as_bytes()).unwrap();
    let attachment = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, gz.finish().unwrap());
    let mail = format!(
        "From: reports@bigmail.example\r\nTo: postmaster@example.org\r\nSubject: Report Domain: example.org Submitter: bigmail.example Report-ID: <x>\r\nTLS-Report-Domain: example.org\r\nTLS-Report-Submitter: bigmail.example\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/report; report-type=tlsrpt; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nThis is a TLS report.\r\n--b\r\nContent-Type: application/tlsrpt+gzip; name=\"report.json.gz\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{attachment}\r\n--b--\r\n"
    );
    let mut smtp = Client::smtp(env.mx).await;
    assert!(smtp.send_mail("reports@bigmail.example", &["postmaster@example.org"], &mail).await.starts_with("250"));
    // Sent twice: stored once.
    assert!(smtp.send_mail("reports@bigmail.example", &["postmaster@example.org"], &mail).await.starts_with("250"));

    let admin = Api::logged_in(&env, "admin@example.org").await;
    let seen = admin.get("/api/tls-reports").await;
    assert_eq!(seen.status, StatusCode::OK, "{}", seen.text);
    let received = seen.body["received"].as_array().unwrap();
    assert_eq!(received.len(), 1, "the unrelated domain is not kept: {}", seen.body);
    assert_eq!((received[0]["reporter"].clone(), received[0]["domain"].clone(), received[0]["successes"].clone(), received[0]["failures"].clone()), (json!("Big Mail Inc."), json!("example.org"), json!(120), json!(2)));
    assert_eq!(received[0]["details"][0]["result-type"], "certificate-host-mismatch");
    assert!(seen.body["outgoing"].is_array());
}

