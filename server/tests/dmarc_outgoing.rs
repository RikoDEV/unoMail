//! DMARC aggregate reports this server sends to the domains whose mail it received.

mod common;

use common::TestEnv;
use unomail::{dmarc_outgoing, security::authn::DmarcObservation};

fn observation(disposition: &'static str, dkim: &'static str) -> DmarcObservation {
    DmarcObservation {
        header_from: "sender.example".into(),
        disposition,
        dkim,
        spf: "fail",
        dkim_domain: "sender.example".into(),
        dkim_result: dkim.into(),
        spf_domain: "bounces.sender.example".into(),
        spf_result: "softfail".into(),
        override_reason: None,
        policy: serde_json::to_string(&mail_auth::report::PolicyPublished::from_record("sender.example", &mail_auth::common::parse::TxtRecordParser::parse(b"v=DMARC1; p=reject; rua=mailto:dmarc@sender.example").unwrap())).unwrap(),
        rua: vec!["mailto:dmarc@sender.example".into()],
    }
}

#[tokio::test]
async fn evaluations_are_counted_and_reported_once_a_day() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    for _ in 0..3 {
        dmarc_outgoing::record(&env.app, &observation("none", "pass"), "203.0.113.7", "bounce@bounces.sender.example").await;
    }
    dmarc_outgoing::record(&env.app, &observation("reject", "fail"), "198.51.100.66", "x@spoofer.example").await;
    let mut vouched = observation("none", "fail");
    vouched.override_reason = Some("trusted_forwarder");
    dmarc_outgoing::record(&env.app, &vouched, "209.85.220.41", "list@lists.example").await;
    // Domains that do not ask for reports are not tracked at all.
    let mut quiet = observation("none", "pass");
    quiet.header_from = "quiet.example".into();
    quiet.rua.clear();
    dmarc_outgoing::record(&env.app, &quiet, "203.0.113.8", "a@quiet.example").await;

    let today = unomail::util::now().div_euclid(86_400);
    let (report, rua) = dmarc_outgoing::build_report(&env.app, "sender.example", today).await.unwrap().unwrap();
    assert_eq!(rua, ["mailto:dmarc@sender.example"]);
    let xml = report.to_xml();
    assert!(xml.contains("<org_name>mail.test.example</org_name>"), "{xml}");
    assert!(xml.contains("<domain>sender.example</domain>") && xml.contains("<p>reject</p>"), "{xml}");
    assert!(xml.contains("<source_ip>203.0.113.7</source_ip>") && xml.contains("<count>3</count>"), "{xml}");
    assert!(xml.contains("<source_ip>198.51.100.66</source_ip>") && xml.contains("<disposition>reject</disposition>"), "{xml}");
    assert!(xml.contains("<type>trusted_forwarder</type>"), "{xml}");
    assert!(xml.contains("<envelope_from>spoofer.example</envelope_from>"), "{xml}");
    assert!(dmarc_outgoing::build_report(&env.app, "quiet.example", today).await.unwrap().is_none());

    // Same domain, or a subdomain: no authorization record needed. Elsewhere: one is.
    assert!(dmarc_outgoing::destination_allowed(&env.app, "sender.example", "sender.example").await);
    assert!(dmarc_outgoing::destination_allowed(&env.app, "sender.example", "reports.sender.example").await);
    assert!(!dmarc_outgoing::destination_allowed(&env.app, "sender.example", "collector.example").await);

    // Today's results wait for the day to end; yesterday's go out, once.
    dmarc_outgoing::send_reports(&env.app).await;
    let queued = || async { sqlx::query_as::<_, (String, String)>("SELECT sender, recipient FROM queue").fetch_all(&env.app.db).await.unwrap() };
    assert!(queued().await.is_empty());
    sqlx::query("UPDATE dmarc_observations SET day = day - 1").execute(&env.app.db).await.unwrap();
    sqlx::query("UPDATE dmarc_policies SET day = day - 1").execute(&env.app.db).await.unwrap();
    dmarc_outgoing::send_reports(&env.app).await;
    dmarc_outgoing::send_reports(&env.app).await;
    assert_eq!(queued().await, [(String::new(), "dmarc@sender.example".to_owned())], "a null sender, so it never bounces back");
    let blob: String = sqlx::query_scalar("SELECT blob_hash FROM queue").fetch_one(&env.app.db).await.unwrap();
    let raw = String::from_utf8_lossy(&env.app.store.read_blob(&blob).await.unwrap()).into_owned();
    assert!(raw.contains("From: <noreply-reports@example.org>") || raw.contains("From: noreply-reports@example.org"), "{raw}");
    assert!(raw.contains(".sender.example@mail.test.example>"), "{raw}");
    assert!(raw.contains("application/gzip"), "{raw}");
}
