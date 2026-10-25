//! HTTP API tests: authentication, CSRF, authorization boundaries and management endpoints.

mod common;

use axum::http::{Method, StatusCode, header};
use common::{Api, PASSWORD, TestEnv};
use serde_json::{Value, json};
use unomail::auth::Role;

async fn setup() -> (TestEnv, Api) {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let api = Api::logged_in(&env, "admin@example.org").await;
    (env, api)
}

#[tokio::test]
async fn login_sets_a_hardened_cookie_and_logout_invalidates_it() {
    let env = TestEnv::start_with(|cfg| cfg.cookie_secure = true).await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let mut api = Api::new(&env);

    assert_eq!(api.get("/api/auth/me").await.status, StatusCode::UNAUTHORIZED);
    let bad = api.login("bob@example.org", "wrong").await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bad.body["error"]["code"], "invalid_credentials");
    // Unknown accounts are indistinguishable from wrong passwords.
    let unknown = api.login("nobody@example.org", PASSWORD).await;
    assert_eq!((unknown.status, &unknown.body), (bad.status, &bad.body));

    let ok = api.login("BOB@example.org", PASSWORD).await;
    assert_eq!(ok.status, StatusCode::OK);
    let cookie = ok.headers.get(header::SET_COOKIE).unwrap().to_str().unwrap().to_owned();
    assert!(cookie.starts_with("__Host-unomail="), "{cookie}");
    for attribute in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
        assert!(cookie.contains(attribute), "missing {attribute}: {cookie}");
    }
    assert!(!ok.text.contains("password"), "no credential material in responses");
    assert_eq!(ok.body["account"]["email"], "bob@example.org");

    // Only a hash of the session token is stored.
    let token = cookie.split(';').next().unwrap().split_once('=').unwrap().1.to_owned();
    let stored: String = sqlx::query_scalar("SELECT token_hash FROM sessions").fetch_one(&env.app.db).await.unwrap();
    assert_ne!(stored, token);

    assert_eq!(api.get("/api/auth/me").await.status, StatusCode::OK);
    assert_eq!(api.post("/api/auth/logout", json!({})).await.status, StatusCode::OK);
    assert_eq!(api.get("/api/auth/me").await.status, StatusCode::UNAUTHORIZED, "the old cookie no longer works");
}

#[tokio::test]
async fn state_changing_requests_require_the_csrf_token() {
    let (_env, api) = setup().await;
    let mut forged = api.clone();
    forged.csrf = None;
    assert_eq!(forged.post("/api/domains", json!({ "name": "evil.example" })).await.status, StatusCode::FORBIDDEN);
    forged.csrf = Some("guessed".into());
    assert_eq!(forged.post("/api/domains", json!({ "name": "evil.example" })).await.status, StatusCode::FORBIDDEN);
    assert_eq!(forged.delete("/api/domains/1").await.status, StatusCode::FORBIDDEN);
    assert_eq!(forged.get("/api/domains").await.status, StatusCode::OK, "safe methods do not need it");
    assert_eq!(api.get("/api/domains").await.body.as_array().unwrap().len(), 1, "nothing was created");
}

#[tokio::test]
async fn responses_carry_security_headers() {
    let (_env, api) = setup().await;
    let reply = api.get("/api/auth/me").await;
    let h = |name: &str| reply.headers.get(name).map(|v| v.to_str().unwrap().to_owned()).unwrap_or_default();
    assert_eq!(h("x-content-type-options"), "nosniff");
    assert_eq!(h("x-frame-options"), "DENY");
    assert_eq!(h("cache-control"), "no-store");
    assert!(h("strict-transport-security").contains("max-age=63072000"));
    let csp = h("content-security-policy");
    assert!(csp.contains("default-src 'self'") && csp.contains("frame-ancestors 'none'") && csp.contains("object-src 'none'"));
    assert!(!csp.contains("script-src 'self' 'unsafe-inline'"));
    assert!(csp.contains("frame-src 'self';"), "no blob: frames: {csp}");
    assert!(h("permissions-policy").contains("usb=()") && h("x-permitted-cross-domain-policies") == "none");
    assert_eq!(api.get("/api/does-not-exist").await.status, StatusCode::NOT_FOUND);
    // Calendars, contacts, list pages and setup files carry personal data or tokens: never cached.
    for path in ["/dav/", "/lists/confirm/x", "/email.mobileconfig?email=bob@example.org", "/mail/config-v1.1.xml"] {
        assert_eq!(api.get(path).await.headers.get("cache-control").map(|v| v.to_str().unwrap().to_owned()).as_deref(), Some("no-store"), "{path}");
    }
}

#[tokio::test]
async fn login_is_rate_limited_per_account_and_ignores_spoofed_forwarding_headers() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let api = Api::new(&env);
    for i in 0..5 {
        // An untrusted client cannot dodge the limiter by inventing X-Forwarded-For values.
        let spoofed = format!("10.0.0.{i}");
        let reply = api
            .send(Method::POST, "/api/auth/login", Some(json!({ "email": "bob@example.org", "password": "nope" })), &[("x-forwarded-for", &spoofed)])
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
    let mut api = api;
    assert_eq!(api.login("bob@example.org", PASSWORD).await.status, StatusCode::TOO_MANY_REQUESTS);
    let ips: Vec<String> = sqlx::query_scalar("SELECT DISTINCT ip FROM audit_log WHERE action = 'login.failed'").fetch_all(&env.app.db).await.unwrap();
    assert_eq!(ips, ["198.51.100.7"]);
}

#[tokio::test]
async fn forwarded_address_is_honoured_only_from_trusted_proxies() {
    let env = TestEnv::start_with(|cfg| cfg.trusted_proxies = vec!["198.51.100.0/24".parse().unwrap()]).await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let api = Api::new(&env);
    api.send(
        Method::POST,
        "/api/auth/login",
        Some(json!({ "email": "bob@example.org", "password": "nope" })),
        &[("x-forwarded-for", "1.2.3.4, 203.0.113.50, 198.51.100.1")],
    )
    .await;
    let ip: String = sqlx::query_scalar("SELECT ip FROM audit_log WHERE action = 'login.failed'").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(ip, "203.0.113.50", "rightmost untrusted hop; the client-supplied prefix is ignored");
}

#[tokio::test]
async fn domain_lifecycle_with_dkim_and_dns_records() {
    let (_env, api) = setup().await;
    let created = api.post("/api/domains", json!({ "name": "New-Domain.Example" })).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    assert_eq!(created.body["name"], "new-domain.example");
    let id = created.body["id"].as_i64().unwrap();

    assert_eq!(api.post("/api/domains", json!({ "name": "new-domain.example" })).await.status, StatusCode::CONFLICT);
    for bad in ["", "nodots", "bad domain.example", "../etc", "a..b.example", "192.168.1.1"] {
        assert_eq!(api.post("/api/domains", json!({ "name": bad })).await.status, StatusCode::BAD_REQUEST, "{bad:?}");
    }

    // A signing key is generated automatically, and its private half never leaves the server.
    let keys = api.get(&format!("/api/domains/{id}/dkim")).await;
    let keys_list = keys.body.as_array().unwrap();
    assert_eq!(keys_list.len(), 1);
    assert_eq!(keys_list[0]["algorithm"], "rsa-sha256");
    assert!(keys_list[0]["dns_value"].as_str().unwrap().starts_with("v=DKIM1; k=rsa; p="));
    assert!(!keys.text.contains("PRIVATE") && !keys.text.contains("private_key"));

    let second = api.post(&format!("/api/domains/{id}/dkim"), json!({ "selector": "Rotate-2026", "algorithm": "ed25519" })).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.text);
    assert_eq!(second.body["selector"], "rotate-2026");
    assert_eq!(api.post(&format!("/api/domains/{id}/dkim"), json!({ "selector": "rotate-2026" })).await.status, StatusCode::CONFLICT);
    assert_eq!(api.post(&format!("/api/domains/{id}/dkim"), json!({ "selector": "bad selector" })).await.status, StatusCode::BAD_REQUEST);
    let old_key = keys_list[0]["id"].as_i64().unwrap();
    assert_eq!(api.patch(&format!("/api/domains/{id}/dkim/{old_key}"), json!({ "active": false })).await.status, StatusCode::OK);
    // Keys are addressed within their domain.
    assert_eq!(api.delete(&format!("/api/domains/1/dkim/{old_key}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(api.delete(&format!("/api/domains/{id}/dkim/{old_key}")).await.status, StatusCode::OK);

    let dns = api.get(&format!("/api/domains/{id}/dns")).await;
    let checks = dns.body["checks"].as_array().unwrap();
    let ids: Vec<&str> = checks.iter().map(|c| c["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["mx", "spf", "dkim:rotate-2026", "dmarc", "tls-rpt", "dane", "ptr", "tls", "autoconfig", "autodiscover", "srv:submission", "srv:imaps", "srv:pop3s"]);
    assert_eq!(checks[0]["record_value"], "10 mail.test.example.");
    assert_eq!(checks[7]["status"], "warning", "self-signed certificate is flagged");

    let updated = api.patch(&format!("/api/domains/{id}"), json!({ "catch_all": "all@new-domain.example", "max_mailboxes": 1 })).await;
    assert_eq!(updated.body["catch_all"], "all@new-domain.example");
    assert_eq!(api.patch(&format!("/api/domains/{id}"), json!({ "catch_all": "x@elsewhere.example" })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.patch(&format!("/api/domains/{id}"), json!({ "catch_all": null })).await.body["catch_all"], Value::Null);
    assert_eq!(api.patch(&format!("/api/domains/{id}"), json!({ "max_mailboxes": -1 })).await.status, StatusCode::BAD_REQUEST);

    assert_eq!(api.delete("/api/domains/1").await.status, StatusCode::BAD_REQUEST, "own domain is protected");
    assert_eq!(api.delete(&format!("/api/domains/{id}")).await.status, StatusCode::OK);
    assert_eq!(api.get(&format!("/api/domains/{id}")).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mailbox_and_alias_management() {
    let (env, api) = setup().await;
    let created = api.post("/api/accounts", json!({ "email": "Carol@Example.org", "password": PASSWORD, "display_name": " Carol ", "quota_bytes": 5000 })).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    assert_eq!(created.body["email"], "carol@example.org");
    assert_eq!(created.body["display_name"], "Carol");
    assert!(!created.text.contains("password_hash") && !created.text.contains("argon2"));
    let id = created.body["id"].as_i64().unwrap();

    for (body, why) in [
        (json!({ "email": "carol@example.org", "password": PASSWORD }), "duplicate"),
        (json!({ "email": "x@unknown.example", "password": PASSWORD }), "foreign domain"),
        (json!({ "email": "weak@example.org", "password": "short" }), "weak password"),
        (json!({ "email": "bad address@example.org", "password": PASSWORD }), "bad address"),
        (json!({ "email": "../../x@example.org", "password": PASSWORD }), "path characters"),
        (json!({ "email": "q@example.org", "password": PASSWORD, "quota_bytes": -5 }), "negative quota"),
        (json!({ "email": "r@example.org", "password": PASSWORD, "role": "root" }), "unknown role"),
    ] {
        let status = api.post("/api/accounts", body).await.status;
        assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::CONFLICT, "{why}: {status}");
    }

    // Default folders exist for the new mailbox.
    let carol = unomail::auth::Account::by_id(&env.app.db, id).await.unwrap().unwrap();
    assert_eq!(env.app.store.list_mailboxes(carol.id).await.unwrap().len(), 6);

    let listed = api.get("/api/accounts?q=car").await;
    assert_eq!(listed.body["total"], 1);
    assert_eq!(api.get("/api/accounts?q=%25").await.body["total"], 0, "LIKE wildcards in the search term are literal");
    assert_eq!(api.get("/api/accounts").await.body["total"], 2);

    // Resetting a password signs the user out everywhere.
    let carol_api = Api::logged_in(&env, "carol@example.org").await;
    let new_password = "a completely new password";
    let updated = api.patch(&format!("/api/accounts/{id}"), json!({ "password": new_password, "imap_enabled": false })).await;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.body["imap_enabled"], false);
    assert_eq!(carol_api.get("/api/auth/me").await.status, StatusCode::UNAUTHORIZED);
    let mut carol_api = Api::new(&env);
    assert_eq!(carol_api.login("carol@example.org", PASSWORD).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(carol_api.login("carol@example.org", new_password).await.status, StatusCode::OK);

    assert_eq!(api.patch(&format!("/api/accounts/{id}"), json!({ "enabled": false })).await.status, StatusCode::OK);
    assert_eq!(carol_api.get("/api/auth/me").await.status, StatusCode::UNAUTHORIZED, "disabled accounts lose their sessions");

    let alias = api.post("/api/aliases", json!({ "source": "Info@example.org", "destinations": ["carol@example.org", "ext@other.example", "carol@example.org"] })).await;
    assert_eq!(alias.status, StatusCode::OK, "{}", alias.text);
    assert_eq!(alias.body["destinations"], json!(["carol@example.org", "ext@other.example"]));
    let alias_id = alias.body["id"].as_i64().unwrap();
    assert_eq!(api.post("/api/aliases", json!({ "source": "carol@example.org", "destinations": ["x@y.example"] })).await.status, StatusCode::CONFLICT);
    assert_eq!(api.post("/api/aliases", json!({ "source": "loop@example.org", "destinations": ["loop@example.org"] })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.post("/api/aliases", json!({ "source": "none@example.org", "destinations": [] })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.post("/api/accounts", json!({ "email": "info@example.org", "password": PASSWORD })).await.status, StatusCode::CONFLICT);
    let patched = api.patch(&format!("/api/aliases/{alias_id}"), json!({ "destinations": ["only@other.example"], "enabled": false })).await;
    assert_eq!(patched.body["enabled"], false);
    assert_eq!(api.get("/api/aliases?q=only").await.body.as_array().unwrap().len(), 1);
    assert_eq!(api.delete(&format!("/api/aliases/{alias_id}")).await.status, StatusCode::OK);

    assert_eq!(api.delete(&format!("/api/accounts/{id}")).await.status, StatusCode::OK);
    let own_id = api.get("/api/auth/me").await.body["account"]["id"].as_i64().unwrap();
    assert_eq!(api.delete(&format!("/api/accounts/{own_id}")).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.patch(&format!("/api/accounts/{own_id}"), json!({ "role": "user" })).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ordinary_users_have_no_access_to_administration() {
    let (env, _admin) = setup().await;
    env.account("bob@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    for path in ["/api/domains", "/api/accounts", "/api/aliases", "/api/tls", "/api/dashboard", "/api/queue", "/api/logs/audit", "/api/logs/delivery", "/api/domains/1", "/api/domains/1/dkim", "/api/accounts/1"] {
        assert_eq!(bob.get(path).await.status, StatusCode::FORBIDDEN, "{path}");
    }
    assert_eq!(bob.post("/api/accounts", json!({ "email": "x@example.org", "password": PASSWORD })).await.status, StatusCode::FORBIDDEN);
    assert_eq!(bob.patch("/api/accounts/1", json!({ "password": PASSWORD })).await.status, StatusCode::FORBIDDEN);
    assert_eq!(bob.put("/api/tls/custom", json!({ "cert_pem": "", "key_pem": "" })).await.status, StatusCode::FORBIDDEN);
    assert_eq!(bob.post("/api/tls/self-signed", json!({})).await.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn domain_administrators_are_confined_to_their_domains() {
    let (env, admin) = setup().await;
    let other_domain = env.domain("other.example").await;
    env.account("dana@example.org").await;
    let victim = env.account("victim@other.example").await;
    let peer = env.account("peer@example.org").await;

    let set = admin.put("/api/domains/1/admins", json!({ "emails": ["dana@example.org"] })).await;
    assert_eq!(set.body, json!(["dana@example.org"]));
    let dana = Api::logged_in(&env, "dana@example.org").await;

    // Sees and manages only the delegated domain.
    let domains = dana.get("/api/domains").await;
    assert_eq!(domains.body.as_array().unwrap().len(), 1);
    assert_eq!(dana.get(&format!("/api/domains/{other_domain}")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(dana.get(&format!("/api/domains/{other_domain}/dkim")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(dana.get(&format!("/api/accounts?domain_id={other_domain}")).await.status, StatusCode::NOT_FOUND);
    let visible = dana.get("/api/accounts").await;
    let emails: Vec<&str> = visible.body["items"].as_array().unwrap().iter().map(|a| a["email"].as_str().unwrap()).collect();
    assert_eq!(emails, ["dana@example.org", "peer@example.org"], "no foreign accounts, no other administrators");

    assert_eq!(dana.patch(&format!("/api/accounts/{}", victim.id), json!({ "password": PASSWORD })).await.status, StatusCode::NOT_FOUND);
    assert_eq!(dana.delete(&format!("/api/accounts/{}", victim.id)).await.status, StatusCode::NOT_FOUND);
    assert_eq!(dana.post("/api/accounts", json!({ "email": "new@other.example", "password": PASSWORD })).await.status, StatusCode::FORBIDDEN);
    assert_eq!(dana.post("/api/aliases", json!({ "source": "x@other.example", "destinations": ["dana@example.org"] })).await.status, StatusCode::FORBIDDEN);

    // No privilege escalation: cannot touch the super administrator, grant roles or lift limits.
    assert_eq!(dana.patch("/api/accounts/1", json!({ "password": "attacker chosen password" })).await.status, StatusCode::NOT_FOUND);
    assert_eq!(dana.delete("/api/accounts/1").await.status, StatusCode::NOT_FOUND);
    assert_eq!(dana.patch(&format!("/api/accounts/{}", peer.id), json!({ "role": "super_admin" })).await.status, StatusCode::FORBIDDEN);
    assert_eq!(dana.post("/api/accounts", json!({ "email": "boss@example.org", "password": PASSWORD, "role": "super_admin" })).await.status, StatusCode::FORBIDDEN);
    assert_eq!(dana.patch("/api/domains/1", json!({ "max_mailboxes": 0 })).await.status, StatusCode::FORBIDDEN);
    assert_eq!(dana.patch("/api/domains/1", json!({ "enabled": false })).await.status, StatusCode::FORBIDDEN);
    assert_eq!(dana.put("/api/domains/1/admins", json!({ "emails": [] })).await.status, StatusCode::FORBIDDEN);
    assert_eq!(dana.post("/api/domains", json!({ "name": "mine.example" })).await.status, StatusCode::FORBIDDEN);
    assert_eq!(dana.delete("/api/domains/1").await.status, StatusCode::FORBIDDEN);
    for path in ["/api/tls", "/api/dashboard", "/api/queue", "/api/logs/audit"] {
        assert_eq!(dana.get(path).await.status, StatusCode::FORBIDDEN, "{path}");
    }

    // What delegation does allow.
    assert_eq!(dana.post("/api/accounts", json!({ "email": "new@example.org", "password": PASSWORD })).await.status, StatusCode::OK);
    assert_eq!(dana.patch(&format!("/api/accounts/{}", peer.id), json!({ "quota_bytes": 1234 })).await.body["quota_bytes"], 1234);
    assert_eq!(dana.post("/api/aliases", json!({ "source": "team@example.org", "destinations": ["peer@example.org"] })).await.status, StatusCode::OK);
    assert_eq!(dana.patch("/api/domains/1", json!({ "catch_all": "peer@example.org" })).await.status, StatusCode::OK);

    // Delivery logs are filtered to the administrator's domains.
    for (sender, recipient) in [("a@remote.example", "peer@example.org"), ("b@remote.example", "victim@other.example")] {
        sqlx::query("INSERT INTO delivery_log (ts, direction, sender, recipient, status) VALUES (0, 'inbound', ?, ?, 'delivered')")
            .bind(sender)
            .bind(recipient)
            .execute(&env.app.db)
            .await
            .unwrap();
    }
    let logs = dana.get("/api/logs/delivery").await;
    let recipients: Vec<&str> = logs.body.as_array().unwrap().iter().map(|r| r["recipient"].as_str().unwrap()).collect();
    assert_eq!(recipients, ["peer@example.org"]);
    assert_eq!(admin.get("/api/logs/delivery").await.body.as_array().unwrap().len(), 2);

    // Revoking the delegation demotes the account.
    admin.put("/api/domains/1/admins", json!({ "emails": [] })).await;
    assert_eq!(dana.get("/api/domains").await.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mailbox_limit_per_domain_is_enforced() {
    let (_env, api) = setup().await;
    assert_eq!(api.patch("/api/domains/1", json!({ "max_mailboxes": 2 })).await.status, StatusCode::OK);
    assert_eq!(api.post("/api/accounts", json!({ "email": "one@example.org", "password": PASSWORD })).await.status, StatusCode::OK);
    assert_eq!(api.post("/api/accounts", json!({ "email": "two@example.org", "password": PASSWORD })).await.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn password_change_requires_the_current_password_and_revokes_other_sessions() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let other_device = Api::logged_in(&env, "bob@example.org").await;
    assert_eq!(bob.get("/api/auth/sessions").await.body.as_array().unwrap().len(), 2);

    let wrong = bob.post("/api/auth/password", json!({ "current_password": "guess", "new_password": "another good password" })).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    let weak = bob.post("/api/auth/password", json!({ "current_password": PASSWORD, "new_password": "weak" })).await;
    assert_eq!(weak.status, StatusCode::BAD_REQUEST);
    let same = bob.post("/api/auth/password", json!({ "current_password": PASSWORD, "new_password": PASSWORD })).await;
    assert_eq!(same.status, StatusCode::BAD_REQUEST);

    let ok = bob.post("/api/auth/password", json!({ "current_password": PASSWORD, "new_password": "another good password" })).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text);
    assert_eq!(bob.get("/api/auth/me").await.status, StatusCode::OK, "the current session survives");
    assert_eq!(other_device.get("/api/auth/me").await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn certificate_management_validates_and_hot_swaps() {
    let (env, api) = setup().await;
    let status = api.get("/api/tls").await;
    assert_eq!(status.body["mode"], "self_signed");
    assert_eq!(status.body["certificate"]["kind"], "self_signed");
    assert!(!status.text.contains("PRIVATE KEY"));

    let (cert, key) = unomail::tls::generate_self_signed("mail.test.example").unwrap();
    let (other_cert, other_key) = unomail::tls::generate_self_signed("unrelated.example").unwrap();

    let dry = api.post("/api/tls/validate", json!({ "cert_pem": cert, "key_pem": key })).await;
    assert_eq!(dry.body["valid"], true);
    assert_eq!(dry.body["domains"], json!(["mail.test.example"]));
    assert_eq!(api.get("/api/tls").await.body["mode"], "self_signed", "validation changes nothing");
    let mismatch = api.post("/api/tls/validate", json!({ "cert_pem": cert, "key_pem": other_key })).await;
    assert_eq!(mismatch.body["valid"], false);
    assert_eq!(mismatch.body["error"], "private key does not match the certificate");

    let before = env.app.tls.info().id;
    assert_eq!(api.put("/api/tls/custom", json!({ "cert_pem": cert, "key_pem": other_key })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.put("/api/tls/custom", json!({ "cert_pem": "garbage", "key_pem": "garbage" })).await.status, StatusCode::BAD_REQUEST);
    let huge = "A".repeat(100_000);
    assert_eq!(api.put("/api/tls/custom", json!({ "cert_pem": huge, "key_pem": key })).await.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(env.app.tls.info().id, before, "failed uploads leave the active certificate alone");

    let installed = api.put("/api/tls/custom", json!({ "cert_pem": other_cert, "key_pem": other_key })).await;
    assert_eq!(installed.status, StatusCode::OK, "{}", installed.text);
    assert_eq!(installed.body["mode"], "custom");
    assert_eq!(installed.body["certificate"]["covers_hostname"], false);
    let warnings = installed.body["warnings"].as_array().unwrap();
    assert!(warnings.iter().any(|w| w.as_str().unwrap().contains("not valid for the server hostname")));
    assert!(!installed.text.contains("PRIVATE KEY"), "the key is never echoed back");

    assert_eq!(api.put("/api/tls/acme", json!({ "domains": [], "email": "admin@example.org" })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.put("/api/tls/acme", json!({ "domains": ["*.example.org"], "email": "admin@example.org" })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(api.post("/api/tls/acme/renew", json!({})).await.status, StatusCode::BAD_REQUEST, "nothing to renew");

    // Enabling automation with an unreachable CA keeps the working certificate in place.
    let acme = api.put("/api/tls/acme", json!({ "domains": ["mail.test.example"], "email": "admin@example.org", "challenge": "dns-01", "cloudflare_token": "secret_token_value" })).await;
    assert_eq!(acme.status, StatusCode::OK, "{}", acme.text);
    assert_eq!(acme.body["issued"], false);
    assert_eq!(acme.body["mode"], "acme");
    assert_eq!(acme.body["certificate"]["kind"], "custom");
    assert_eq!(acme.body["acme"]["has_cloudflare_token"], true);
    assert!(!acme.text.contains("secret_token_value"), "provider credentials are write-only");
    assert!(acme.body["acme_last_error"].is_string());

    let reset = api.post("/api/tls/self-signed", json!({})).await;
    assert_eq!(reset.body["mode"], "self_signed");
    assert_eq!(reset.body["acme"], Value::Null);

    let actions: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_log WHERE action LIKE 'tls.%' ORDER BY id").fetch_all(&env.app.db).await.unwrap();
    assert_eq!(actions, ["tls.custom_installed", "tls.acme_configured", "tls.acme_failed", "tls.self_signed"]);
}

#[tokio::test]
async fn dashboard_queue_and_audit_log() {
    let (env, api) = setup().await;
    let dashboard = api.get("/api/dashboard").await;
    assert_eq!(dashboard.status, StatusCode::OK, "{}", dashboard.text);
    assert_eq!(dashboard.body["domains"], 1);
    assert_eq!(dashboard.body["mailboxes"], 1);
    assert_eq!(dashboard.body["queue_size"], 0);
    assert_eq!(dashboard.body["certificate"]["healthy"], false);

    let hash = env.app.store.put_blob(b"Subject: queued\r\n\r\nbody").await.unwrap();
    let rcpt = unomail::util::Address::parse("x@remote.example").unwrap();
    let id = unomail::smtp::delivery::enqueue(&env.app, "admin@example.org", &rcpt, &hash, 10, None).await.unwrap();
    sqlx::query("UPDATE queue SET next_attempt_at = ?").bind(unomail::util::now() + 9999).execute(&env.app.db).await.unwrap();
    let queue = api.get("/api/queue").await;
    assert_eq!(queue.body.as_array().unwrap().len(), 1);
    assert_eq!(queue.body[0]["recipient"], "x@remote.example");
    assert_eq!(api.post(&format!("/api/queue/{id}/retry"), json!({})).await.status, StatusCode::OK);
    let next: i64 = sqlx::query_scalar("SELECT next_attempt_at FROM queue").fetch_one(&env.app.db).await.unwrap();
    assert!(next <= unomail::util::now());
    assert_eq!(api.delete(&format!("/api/queue/{id}")).await.status, StatusCode::OK);
    assert_eq!(api.delete(&format!("/api/queue/{id}")).await.status, StatusCode::NOT_FOUND);

    let audit = api.get("/api/logs/audit?q=queue").await;
    let actions: Vec<&str> = audit.body.as_array().unwrap().iter().map(|r| r["action"].as_str().unwrap()).collect();
    assert_eq!(actions, ["queue.deleted", "queue.retry"]);
    assert_eq!(audit.body[0]["actor"], "admin@example.org");
    assert_eq!(audit.body[0]["ip"], "198.51.100.7");
    let newest = api.get("/api/logs/audit?limit=1").await.body[0]["id"].as_i64().unwrap();
    assert!(api.get(&format!("/api/logs/audit?after={newest}")).await.body.as_array().unwrap().is_empty(), "live tail cursor");
}

#[tokio::test]
async fn health_is_public_and_metrics_are_protected() {
    let env = TestEnv::start().await;
    let public = Api::new(&env);
    let health = public.get("/health").await;
    assert_eq!((health.status, &health.body), (StatusCode::OK, &json!({ "status": "ok" })));
    assert_eq!(public.get("/metrics").await.status, StatusCode::NOT_FOUND, "not exposed to the internet");

    // A private address alone is not enough (behind NAT everybody may have one); loopback and
    // the networks the operator trusts are.
    let mut private = Api::new(&env);
    private.peer = "10.0.0.5:5000".parse().unwrap();
    assert_eq!(private.get("/metrics").await.status, StatusCode::NOT_FOUND);
    let mut local = Api::new(&env);
    local.peer = "127.0.0.1:5000".parse().unwrap();
    assert_eq!(local.get("/metrics").await.status, StatusCode::OK);
    let env = TestEnv::start_with(|cfg| cfg.trusted_networks = vec!["10.0.0.0/24".parse().unwrap()]).await;
    let mut internal = Api::new(&env);
    internal.peer = "10.0.0.5:5000".parse().unwrap();
    let metrics = internal.get("/metrics").await;
    assert_eq!(metrics.status, StatusCode::OK);
    assert!(metrics.text.contains("unomail_up 1\n") && metrics.text.contains("# TYPE unomail_queue_size gauge"));

    let env = TestEnv::start_with(|cfg| cfg.metrics_token = Some("scrape-secret".into())).await;
    let mut internal = Api::new(&env);
    internal.peer = "10.0.0.5:5000".parse().unwrap();
    assert_eq!(internal.get("/metrics").await.status, StatusCode::NOT_FOUND, "a configured token is always required");
    assert_eq!(internal.send(Method::GET, "/metrics", None, &[("authorization", "Bearer wrong")]).await.status, StatusCode::NOT_FOUND);
    assert_eq!(internal.send(Method::GET, "/metrics", None, &[("authorization", "Bearer scrape-secret")]).await.status, StatusCode::OK);
}

#[tokio::test]
async fn oversized_and_malformed_bodies_are_rejected() {
    let (_env, api) = setup().await;
    let big = json!({ "name": "a".repeat(2 * 1024 * 1024) });
    assert_eq!(api.post("/api/domains", big).await.status, StatusCode::PAYLOAD_TOO_LARGE);
    let malformed = api
        .send(Method::POST, "/api/domains", None, &[("content-type", "application/json")])
        .await;
    assert!(malformed.status.is_client_error());
}

#[tokio::test]
async fn password_spraying_from_one_address_is_slowed_and_then_blocked() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let mut attacker = Api::new(&env);
    attacker.peer = "203.0.113.66:40000".parse().unwrap();

    // Different, mostly non-existent accounts each time: no single account limit is reached.
    let started = std::time::Instant::now();
    for i in 0..10 {
        let reply = attacker.post("/api/auth/login", json!({ "email": format!("user{i}@example.org"), "password": format!("guess-number-{i}") })).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "attempt {i}");
    }
    assert!(started.elapsed() >= std::time::Duration::from_secs(5), "repeated failures are answered slowly: {:?}", started.elapsed());

    // From now on the address is refused outright, even with correct credentials.
    let quick = std::time::Instant::now();
    for email in ["user99@example.org", "bob@example.org"] {
        assert_eq!(attacker.login(email, PASSWORD).await.status, StatusCode::TOO_MANY_REQUESTS, "{email}");
    }
    assert!(quick.elapsed() < std::time::Duration::from_secs(1), "refusals cost the server nothing");
    let limited: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = 'login.rate_limited' AND ip = '203.0.113.66'").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(limited, 2);

    // Everybody else, including the real owner of the account, is unaffected.
    let mut owner = Api::new(&env);
    assert_eq!(owner.login("bob@example.org", PASSWORD).await.status, StatusCode::OK);
}

#[tokio::test]
async fn the_web_client_starts_with_one_request() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    assert!(bob.put("/api/me/preferences", serde_json::json!({ "skin": "paper" })).await.status.is_success());
    let start = bob.get("/api/me/startup").await;
    assert!(start.status.is_success(), "{}", start.text);
    assert_eq!(start.body["preferences"]["skin"], "paper");
    assert!(start.body["skins"].is_array() && start.body["packages"].is_array());
    assert_eq!(Api::new(&env).get("/api/me/startup").await.status.as_u16(), 401);
}

#[tokio::test]
async fn every_domain_keeps_a_postmaster_mailbox() {
    let (env, api) = setup().await;
    let created = api.post("/api/domains", json!({ "name": "reports.example" })).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let listed = api.get("/api/accounts?q=postmaster@reports.example").await.body;
    let postmaster = &listed["items"][0];
    assert_eq!((postmaster["email"].as_str(), postmaster["system"].as_bool()), (Some("postmaster@reports.example"), Some(true)));
    let id = postmaster["id"].as_i64().unwrap();
    let refused = api.delete(&format!("/api/accounts/{id}")).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.text);

    // Domains made before (or outside the API) get one at startup; existing mailboxes and
    // aliases of that name are respected.
    env.account("postmaster@example.org").await;
    env.domain("aliased.example").await;
    env.alias("postmaster@aliased.example", &["admin@example.org"]).await;
    env.domain("old.example").await;
    unomail::directory::ensure_postmasters(&env.app).await;
    let system: Vec<String> = sqlx::query_scalar("SELECT email FROM accounts WHERE system = 1 ORDER BY email").fetch_all(&env.app.db).await.unwrap();
    assert_eq!(system, ["postmaster@example.org", "postmaster@old.example", "postmaster@reports.example"]);

    // Mail to it is accepted (and a DMARC report in it would feed the dashboard).
    let mut c = common::Client::smtp(env.mx).await;
    let reply = c.send_mail("noreply-dmarc@google.example", &["postmaster@old.example"], &common::message("Google <noreply-dmarc@google.example>", "postmaster@old.example", "Report Domain: old.example", "x")).await;
    assert!(reply.starts_with("250"), "{reply}");
}
