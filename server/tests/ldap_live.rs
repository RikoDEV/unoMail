//! Address book lookups against a real LDAP server. Ignored by default; run with
//!
//! ```text
//! docker run -d --name ldap -p 10389:10389 ghcr.io/rroemhild/docker-test-openldap:master
//! cargo test --test ldap_live -- --ignored
//! ```
//!
//! The image ships a small, well-known directory (the Planet Express crew).

mod common;

use axum::http::StatusCode;
use common::{Api, TestEnv};
use serde_json::json;
use unomail::auth::Role;

fn url() -> String {
    std::env::var("UNOMAIL_TEST_LDAP").unwrap_or_else(|_| "ldap://127.0.0.1:10389".into())
}

#[tokio::test]
#[ignore = "needs a running test LDAP server"]
async fn suggestions_come_from_the_directory() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;

    let config = json!({
        "enabled": true,
        "url": url(),
        "base_dn": "ou=people,dc=planetexpress,dc=com",
        "bind_dn": "cn=admin,dc=planetexpress,dc=com",
        "password": "GoodNewsEveryone",
    });

    // The test button works with unsaved settings and reports a wrong password clearly.
    let mut probe = config.clone();
    probe["query"] = json!("fry");
    let tested = admin.post("/api/ldap/test", probe.clone()).await;
    assert_eq!(tested.body["ok"], true, "{}", tested.text);
    assert_eq!(tested.body["entries"], json!([{ "name": "Philip J. Fry", "email": "fry@planetexpress.com" }]));
    probe["password"] = json!("wrong");
    let refused = admin.post("/api/ldap/test", probe).await;
    assert_eq!(refused.body["ok"], false);
    assert!(refused.body["error"].as_str().unwrap().contains("bind failed"), "{}", refused.text);
    assert_eq!(bob.get("/api/me/contacts/suggest?q=fry").await.body, json!([]), "nothing is used before it is saved");

    assert_eq!(admin.put("/api/ldap", config).await.status, StatusCode::OK);
    let suggestions = bob.get("/api/me/contacts/suggest?q=fry").await.body;
    assert_eq!(suggestions, json!([{ "source": "ldap", "name": "Philip J. Fry", "email": "fry@planetexpress.com" }]));
    // Matching on the address works too, and results are capped.
    let many = bob.get("/api/me/contacts/suggest?q=planetexpress").await.body;
    assert!((2..=10).contains(&many.as_array().unwrap().len()), "{many}");

    // Filter metacharacters in the search text are data, not syntax.
    for injection in ["*", "*)(uid=*", "fry)(|(uid=*", "\\2a"] {
        let encoded: String = injection.bytes().map(|b| format!("%{b:02X}")).collect();
        let reply = bob.get(&format!("/api/me/contacts/suggest?q={encoded}")).await;
        assert_eq!(reply.body, json!([]), "{injection}");
    }

    // A contact of the user's own takes precedence over the directory entry.
    bob.post("/api/me/contacts", json!({ "name": "Fry (my note)", "email": "fry@planetexpress.com" })).await;
    let merged = bob.get("/api/me/contacts/suggest?q=fry").await.body;
    assert_eq!(merged, json!([{ "source": "contact", "name": "Fry (my note)", "email": "fry@planetexpress.com" }]));
}
