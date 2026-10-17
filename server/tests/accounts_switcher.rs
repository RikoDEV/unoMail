//! Several accounts signed in at once in one browser, and switching between them.

mod common;

use std::collections::BTreeMap;

use axum::http::{Method, StatusCode, header};
use common::{Api, PASSWORD, Reply, TestEnv};
use serde_json::{Value, json};

/// A browser: keeps every cookie the server sets, and the current CSRF token.
struct Browser {
    api: Api,
    cookies: BTreeMap<String, String>,
}

impl Browser {
    fn new(env: &TestEnv) -> Self {
        Browser { api: Api::new(env), cookies: BTreeMap::new() }
    }

    async fn call(&mut self, method: Method, path: &str, body: Option<Value>) -> Reply {
        self.api.cookie = (!self.cookies.is_empty()).then(|| self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; "));
        let reply = self.api.send(method, path, body, &[]).await;
        for set in reply.headers.get_all(header::SET_COOKIE) {
            let set = set.to_str().unwrap();
            let (pair, attributes) = set.split_once(';').unwrap_or((set, ""));
            let (name, value) = pair.split_once('=').unwrap();
            if attributes.contains("Max-Age=0") || value.is_empty() {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_owned(), value.to_owned());
            }
        }
        if let Some(csrf) = reply.body["csrf_token"].as_str().or(reply.body["next"]["csrf_token"].as_str()) {
            self.api.csrf = Some(csrf.to_owned());
        }
        reply
    }

    async fn login(&mut self, email: &str) -> Reply {
        self.call(Method::POST, "/api/auth/login", Some(json!({ "email": email, "password": PASSWORD }))).await
    }

    async fn current(&mut self) -> String {
        self.call(Method::GET, "/api/auth/me", None).await.body["account"]["email"].as_str().unwrap_or("").to_owned()
    }

    async fn signed_in(&mut self) -> Vec<(String, bool)> {
        let reply = self.call(Method::GET, "/api/auth/accounts", None).await;
        reply.body["accounts"].as_array().unwrap().iter().map(|a| (a["account"]["email"].as_str().unwrap().to_owned(), a["active"].as_bool().unwrap())).collect()
    }
}

#[tokio::test]
async fn accounts_are_added_switched_and_signed_out() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let mut ids = BTreeMap::new();
    for name in ["alice", "bob", "carol", "dave", "erin", "frank"] {
        ids.insert(name, env.account(&format!("{name}@example.org")).await.id);
    }
    let mut browser = Browser::new(&env);
    assert_eq!(browser.login("alice@example.org").await.status, StatusCode::OK);
    assert_eq!(browser.signed_in().await, [("alice@example.org".to_owned(), true)]);

    // Signing in to Bob keeps Alice signed in.
    assert_eq!(browser.login("bob@example.org").await.status, StatusCode::OK);
    assert_eq!(browser.current().await, "bob@example.org");
    assert_eq!(browser.signed_in().await, [("bob@example.org".to_owned(), true), ("alice@example.org".to_owned(), false)]);

    // Switching back; mail is Alice's again.
    let switched = browser.call(Method::POST, "/api/auth/switch", Some(json!({ "account_id": ids["alice"] }))).await;
    assert_eq!(switched.status, StatusCode::OK, "{}", switched.text);
    assert_eq!(browser.current().await, "alice@example.org");
    let session = browser.call(Method::GET, "/jmap/session", None).await;
    assert_eq!(session.body["username"], "alice@example.org");
    // Only accounts signed in here can be switched to.
    assert_eq!(browser.call(Method::POST, "/api/auth/switch", Some(json!({ "account_id": ids["carol"] }))).await.status, StatusCode::NOT_FOUND);

    // Signing in to an account that is there already does not list it twice.
    browser.login("bob@example.org").await;
    assert_eq!(browser.signed_in().await, [("bob@example.org".to_owned(), true), ("alice@example.org".to_owned(), false)]);

    // At most five accounts: the oldest one is signed out to make room.
    for name in ["carol", "dave", "erin", "frank"] {
        browser.login(&format!("{name}@example.org")).await;
    }
    let list = browser.signed_in().await;
    assert_eq!(list.len(), 5, "{list:?}");
    assert_eq!(list[0], ("frank@example.org".to_owned(), true));
    assert!(!list.iter().any(|(email, _)| email == "alice@example.org"), "{list:?}");

    // Signing out moves on to the next account; "all" signs out everywhere.
    let out = browser.call(Method::POST, "/api/auth/logout", None).await;
    assert_eq!(out.body["next"]["account"]["email"], "erin@example.org", "{}", out.text);
    assert_eq!(browser.current().await, "erin@example.org");
    assert_eq!(browser.signed_in().await.len(), 4);
    let out = browser.call(Method::POST, "/api/auth/logout", Some(json!({ "all": true }))).await;
    assert_eq!(out.body["next"], Value::Null);
    assert_eq!(browser.call(Method::GET, "/api/auth/me", None).await.status, StatusCode::UNAUTHORIZED);
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(left, 0, "every session ended");
}

#[tokio::test]
async fn a_signed_out_session_drops_out_of_the_list() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("alice@example.org").await;
    env.account("bob@example.org").await;
    let mut browser = Browser::new(&env);
    browser.login("alice@example.org").await;
    browser.login("bob@example.org").await;
    // Alice's session ends elsewhere (for example a password change on another device).
    sqlx::query("DELETE FROM sessions WHERE account_id = (SELECT id FROM accounts WHERE email = 'alice@example.org')").execute(&env.app.db).await.unwrap();
    assert_eq!(browser.signed_in().await, [("bob@example.org".to_owned(), true)]);
    // Signing in again keeps the account that was current.
    browser.login("alice@example.org").await;
    browser.login("bob@example.org").await;
    assert_eq!(browser.signed_in().await, [("bob@example.org".to_owned(), true), ("alice@example.org".to_owned(), false)]);
}
