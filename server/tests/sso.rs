//! Single sign-on through an OpenID Connect provider: the browser flow and token logins from
//! mail clients, against a local stand-in for the identity provider.

mod common;

use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}};
use common::{Api, Client, PASSWORD, TestEnv};
use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use unomail::auth::Role;

#[derive(Clone, Default)]
struct Provider {
    base: Arc<Mutex<String>>,
    /// Raw bodies posted to the token endpoint.
    token_requests: Arc<Mutex<Vec<String>>>,
    userinfo_calls: Arc<Mutex<usize>>,
}

/// A minimal identity provider. Authorization codes and access tokens are fixed strings that
/// select which user the provider claims to have authenticated.
async fn provider() -> (SocketAddr, Provider) {
    let state = Provider::default();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    *state.base.lock() = format!("http://{addr}");

    async fn discovery(State(p): State<Provider>) -> Json<Value> {
        let base = p.base.lock().clone();
        Json(json!({ "issuer": base, "authorization_endpoint": format!("{base}/authorize"), "token_endpoint": format!("{base}/token"), "userinfo_endpoint": format!("{base}/userinfo"), "introspection_endpoint": format!("{base}/introspect") }))
    }
    /// RFC 7662: which client a token was issued to.
    async fn introspect(body: String) -> Json<Value> {
        let token = body.split('&').find_map(|pair| pair.strip_prefix("token=")).unwrap_or("");
        Json(match token {
            "token-bob" | "token-unverified" | "token-stranger" | "token-impostor" => json!({ "active": true, "client_id": "unomail", "aud": ["unomail", "account"] }),
            "token-other-app" => json!({ "active": true, "client_id": "someone-elses-app", "aud": "someone-elses-app" }),
            _ => json!({ "active": false }),
        })
    }
    async fn token(State(p): State<Provider>, body: String) -> (StatusCode, Json<Value>) {
        p.token_requests.lock().push(body.clone());
        match body.split('&').find_map(|pair| pair.strip_prefix("code=")) {
            Some(code) if code.starts_with("code-for-") => (StatusCode::OK, Json(json!({ "access_token": code.replace("code-for-", "token-"), "token_type": "Bearer" }))),
            _ => (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_grant" }))),
        }
    }
    async fn userinfo(State(p): State<Provider>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
        *p.userinfo_calls.lock() += 1;
        let token = headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
        let profile = match token {
            "token-bob" | "token-other-app" => json!({ "sub": "u-1", "email": "Bob@Example.org", "email_verified": true }),
            "token-unverified" => json!({ "sub": "u-2", "email": "bob@example.org", "email_verified": false }),
            "token-stranger" => json!({ "sub": "u-3", "email": "nobody@example.org", "email_verified": true }),
            // Someone else at the provider who came to hold Bob's address (e-mail addresses change there).
            "token-impostor" => json!({ "sub": "u-9", "email": "bob@example.org", "email_verified": true }),
            _ => return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid_token" }))),
        };
        (StatusCode::OK, Json(profile))
    }
    let router = Router::new().route("/.well-known/openid-configuration", get(discovery)).route("/token", post(token)).route("/userinfo", get(userinfo)).route("/introspect", post(introspect)).with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, state)
}

async fn env_with_sso() -> (TestEnv, Api, SocketAddr, Provider) {
    let (addr, state) = provider().await;
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let saved = admin.put("/api/oauth", json!({ "enabled": true, "name": "Company login", "issuer": format!("http://{addr}/"), "client_id": "unomail", "secret": "client-secret" })).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text);
    (env, admin, addr, state)
}

/// The cookie through which the callback hands its outcome to the sign-in page.
fn result_cookie(reply: &common::Reply) -> String {
    reply.headers.get_all("set-cookie").iter().map(|v| v.to_str().unwrap()).find(|c| c.starts_with("unomail_sso_result=")).expect("an outcome cookie").split(';').next().unwrap().to_owned()
}

fn query_param(url: &str, name: &str) -> String {
    let query = url.split_once('?').map_or("", |(_, q)| q);
    query.split('&').find_map(|pair| pair.strip_prefix(&format!("{name}="))).unwrap_or_default().to_owned()
}

/// Starts the browser flow and returns (state, code challenge, browser holding the flow cookie).
async fn start(env: &TestEnv) -> (String, String, Api) {
    let mut browser = Api::new(env);
    let started = browser.get("/api/auth/oauth/start").await;
    assert_eq!(started.status, StatusCode::SEE_OTHER, "{}", started.text);
    let location = started.headers["location"].to_str().unwrap().to_owned();
    let cookie = started.headers["set-cookie"].to_str().unwrap().to_owned();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax") && cookie.contains("Path=/api/auth/oauth"), "{cookie}");
    browser.cookie = Some(cookie.split(';').next().unwrap().to_owned());
    (query_param(&location, "state"), query_param(&location, "code_challenge"), browser)
}

#[tokio::test]
async fn browser_sign_in_through_the_identity_provider() {
    let (env, admin, addr, provider) = env_with_sso().await;

    // Administration: the secret is write-only and stored encrypted.
    let shown = admin.get("/api/oauth").await;
    assert_eq!((shown.body["has_secret"].as_bool(), shown.body["issuer"].as_str()), (Some(true), Some(format!("http://{addr}").as_str())));
    assert_eq!(shown.body["redirect_uri"], "https://mail.test.example/api/auth/oauth/callback");
    assert!(!shown.text.contains("client-secret"));
    let stored: String = sqlx::query_scalar("SELECT value FROM settings WHERE key = 'oauth.config'").fetch_one(&env.app.db).await.unwrap();
    assert!(!stored.contains("client-secret"));
    assert_eq!(Api::logged_in(&env, "bob@example.org").await.get("/api/oauth").await.status, StatusCode::FORBIDDEN);
    for bad in [json!({ "enabled": true, "issuer": "ftp://x", "client_id": "a" }), json!({ "enabled": true, "issuer": format!("http://{addr}"), "client_id": "" }), json!({ "enabled": true, "issuer": format!("http://{addr}"), "client_id": "a", "scopes": "email" })] {
        assert_eq!(admin.put("/api/oauth", bad.clone()).await.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert_eq!(Api::new(&env).get("/api/auth/oauth").await.body, json!({ "enabled": true, "name": "Company login" }));

    // The happy path.
    let (state, challenge, browser) = start(&env).await;
    let done = browser.get(&format!("/api/auth/oauth/callback?code=code-for-bob&state={state}")).await;
    assert_eq!((done.status, done.headers["location"].to_str().unwrap()), (StatusCode::SEE_OTHER, "/"), "{}", done.text);
    let session = done.headers.get_all("set-cookie").iter().map(|v| v.to_str().unwrap().to_owned()).find(|c| c.starts_with("unomail=")).expect("a session cookie is set");
    assert!(session.contains("HttpOnly") && session.contains("SameSite=Strict"));
    let mut signed_in = Api::new(&env);
    signed_in.cookie = Some(session.split(';').next().unwrap().to_owned());
    assert_eq!(signed_in.get("/api/auth/me").await.body["account"]["email"], "bob@example.org");

    // The provider received the client secret and a PKCE verifier matching the challenge.
    let request = provider.token_requests.lock()[0].clone();
    assert!(request.contains("client_secret=client-secret") && request.contains("grant_type=authorization_code"));
    let verifier = request.split('&').find_map(|p| p.strip_prefix("code_verifier=")).unwrap();
    assert_eq!(URL_SAFE_NO_PAD.encode(unomail::util::sha256(verifier.as_bytes())), challenge);
    assert!(request.contains("redirect_uri=https%3A%2F%2Fmail.test.example%2Fapi%2Fauth%2Foauth%2Fcallback"));

    // A state can be used once only.
    let replay = browser.get(&format!("/api/auth/oauth/callback?code=code-for-bob&state={state}")).await;
    assert_eq!(replay.headers["location"].to_str().unwrap(), "/login?sso=1");
    // The reason is handed to this browser's sign-in page once, never through the address.
    let mut returned = Api::new(&env);
    returned.cookie = Some(result_cookie(&replay));
    assert!(returned.get("/api/auth/oauth/result").await.body["error"].as_str().unwrap().contains("expired"));
    assert_eq!(returned.get("/api/auth/oauth/result").await.body, json!({}), "single use");
    assert_eq!(Api::new(&env).get("/api/auth/oauth/result").await.body, json!({}));

    let refused = |location: &str| location == "/login?sso=1";
    // A response that does not belong to this browser's flow (login CSRF) is refused.
    let (state, _, _) = start(&env).await;
    let other_browser = Api::new(&env);
    let forged = other_browser.get(&format!("/api/auth/oauth/callback?code=code-for-bob&state={state}")).await;
    assert!(refused(forged.headers["location"].to_str().unwrap()) && forged.headers.get_all("set-cookie").iter().all(|c| !c.to_str().unwrap().starts_with("unomail=")));
    // Unverified addresses, identities without a mailbox here, bad codes and provider errors.
    for query in ["code=code-for-unverified", "code=code-for-stranger", "code=garbage", "error=access_denied"] {
        let (state, _, browser) = start(&env).await;
        let reply = browser.get(&format!("/api/auth/oauth/callback?{query}&state={state}")).await;
        assert!(refused(reply.headers["location"].to_str().unwrap()), "{query}");
        assert!(reply.headers.get_all("set-cookie").iter().all(|c| !c.to_str().unwrap().starts_with("unomail=")), "{query}: no session");
    }

    // A second factor set up here is still asked for after the provider's sign-in.
    let bob_id: i64 = sqlx::query_scalar("SELECT id FROM accounts WHERE email = 'bob@example.org'").fetch_one(&env.app.db).await.unwrap();
    sqlx::query("INSERT INTO totp_secrets (account_id, secret, enabled, created_at) VALUES (?, ?, 1, 0)").bind(bob_id).bind(env.app.secrets.seal("JBSWY3DPEHPK3PXP")).execute(&env.app.db).await.unwrap();
    let (state, _, browser) = start(&env).await;
    let pending = browser.get(&format!("/api/auth/oauth/callback?code=code-for-bob&state={state}")).await;
    assert_eq!(pending.headers["location"].to_str().unwrap(), "/login?sso=1");
    assert!(pending.headers.get_all("set-cookie").iter().all(|c| !c.to_str().unwrap().starts_with("unomail=")), "no session before the second factor");
    let mut returned = Api::new(&env);
    returned.cookie = Some(result_cookie(&pending));
    let outcome = returned.get("/api/auth/oauth/result").await.body;
    assert_eq!(outcome["second_factor"]["methods"]["totp"], true, "{outcome}");
    sqlx::query("DELETE FROM totp_secrets").execute(&env.app.db).await.unwrap();

    // Switched off: the button disappears and the flow cannot be started.
    assert_eq!(admin.put("/api/oauth", json!({ "enabled": false, "issuer": format!("http://{addr}"), "client_id": "unomail" })).await.status, StatusCode::OK);
    assert_eq!(Api::new(&env).get("/api/auth/oauth").await.body, json!({ "enabled": false }));
    assert!(refused(Api::new(&env).get("/api/auth/oauth/start").await.headers["location"].to_str().unwrap()));
}

/// Whether the browser callback for `code` ended with a session.
async fn browser_signs_in(env: &TestEnv, code: &str) -> bool {
    let (state, _, browser) = start(env).await;
    let reply = browser.get(&format!("/api/auth/oauth/callback?code={code}&state={state}")).await;
    reply.headers.get_all("set-cookie").iter().any(|c| c.to_str().unwrap().starts_with("unomail="))
}

#[tokio::test]
async fn a_mailbox_stays_with_the_identity_that_first_signed_in() {
    let (env, admin, _, _) = env_with_sso().await;
    let ip = "127.0.0.1".parse().unwrap();
    let bob_id: i64 = sqlx::query_scalar("SELECT id FROM accounts WHERE email = 'bob@example.org'").fetch_one(&env.app.db).await.unwrap();
    let linked = || async { sqlx::query_scalar::<_, String>("SELECT subject FROM oauth_links WHERE account_id = ?").bind(bob_id).fetch_optional(&env.app.db).await.unwrap() };

    // The first sign-in ties the mailbox to the provider's identity.
    assert!(browser_signs_in(&env, "code-for-bob").await);
    assert_eq!(linked().await.as_deref(), Some("u-1"));
    assert_eq!(admin.get(&format!("/api/accounts/{bob_id}/two-factor")).await.body["sso_linked"], true);

    // A different identity with the same verified address is refused, in the browser and for mail programs.
    assert!(!browser_signs_in(&env, "code-for-impostor").await);
    assert!(unomail::oauth::authenticate_token(&env.app, "bob@example.org", "token-impostor", ip, unomail::auth::Protocol::Imap).await.is_err());
    assert_eq!(linked().await.as_deref(), Some("u-1"), "a refused identity does not replace the link");
    assert!(unomail::oauth::authenticate_token(&env.app, "bob@example.org", "token-bob", ip, unomail::auth::Protocol::Imap).await.is_ok());

    // An administrator's sign-in reset removes the link; the next identity is linked instead.
    assert_eq!(admin.delete(&format!("/api/accounts/{bob_id}/two-factor")).await.status, StatusCode::OK);
    assert_eq!(linked().await, None);
    assert_eq!(admin.get(&format!("/api/accounts/{bob_id}/two-factor")).await.body["sso_linked"], false);
    assert!(browser_signs_in(&env, "code-for-impostor").await);
    assert_eq!(linked().await.as_deref(), Some("u-9"));
    assert!(!browser_signs_in(&env, "code-for-bob").await);
}

fn xoauth2(user: &str, token: &str) -> String {
    STANDARD.encode(format!("user={user}\x01auth=Bearer {token}\x01\x01"))
}

#[tokio::test]
async fn mail_clients_sign_in_with_access_tokens() {
    let (env, admin, addr, provider) = env_with_sso().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let imap = listener.local_addr().unwrap();
    tokio::spawn(unomail::imap::serve(env.app.clone(), listener));

    // IMAP: XOAUTH2 and OAUTHBEARER are advertised and accepted.
    let mut c = Client::connect_tls(imap).await;
    assert!(c.read_line().await.unwrap().contains("AUTH=PLAIN AUTH=XOAUTH2 AUTH=OAUTHBEARER"));
    c.send_raw(format!("a1 AUTHENTICATE XOAUTH2 {}\r\n", xoauth2("bob@example.org", "token-bob")).as_bytes()).await;
    assert!(c.read_line().await.unwrap().starts_with("a1 OK"), "token login works");
    c.send_raw(b"a2 SELECT INBOX\r\n").await;
    let mut selected = false;
    for _ in 0..12 {
        if c.read_line().await.unwrap().starts_with("a2 OK") {
            selected = true;
            break;
        }
    }
    assert!(selected);

    let mut c = Client::connect_tls(imap).await;
    c.read_line().await.unwrap();
    let bearer = STANDARD.encode("n,a=bob@example.org,\x01host=mail.test.example\x01port=993\x01auth=Bearer token-bob\x01\x01");
    c.send_raw(format!("b1 AUTHENTICATE OAUTHBEARER {bearer}\r\n").as_bytes()).await;
    assert!(c.read_line().await.unwrap().starts_with("b1 OK"));
    assert_eq!(*provider.userinfo_calls.lock(), 1, "a verified token is not re-checked for every connection");

    // A valid token for one user never opens another user's mailbox; bad tokens are refused.
    // A genuine token for bob that the provider issued to another application is refused too.
    for (user, token) in [("bob@example.org", "token-other-app"), ("admin@example.org", "token-bob"), ("bob@example.org", "token-forged"), ("bob@example.org", "token-unverified"), ("nobody@example.org", "token-stranger")] {
        let mut c = Client::connect_tls(imap).await;
        c.read_line().await.unwrap();
        c.send_raw(format!("c1 AUTHENTICATE XOAUTH2 {}\r\n", xoauth2(user, token)).as_bytes()).await;
        assert!(c.read_line().await.unwrap().starts_with("c1 NO"), "{user} with {token}");
    }

    // SMTP submission.
    let mut c = Client::smtp(env.submission).await;
    c.cmd("EHLO client.example").await;
    c.starttls().await;
    assert!(c.cmd("EHLO client.example").await.contains("AUTH PLAIN LOGIN XOAUTH2 OAUTHBEARER"));
    assert!(c.cmd(&format!("AUTH XOAUTH2 {}", xoauth2("bob@example.org", "token-forged"))).await.starts_with("535"));
    assert!(c.cmd(&format!("AUTH XOAUTH2 {}", xoauth2("bob@example.org", "token-bob"))).await.starts_with("235"));
    assert!(c.cmd("MAIL FROM:<bob@example.org>").await.starts_with("250"));
    assert!(c.cmd("MAIL FROM:<admin@example.org>").await.starts_with("503"), "one transaction at a time");

    // Accounts in a switched-off domain cannot sign in with a token either.
    sqlx::query("UPDATE domains SET enabled = 0 WHERE name = 'example.org'").execute(&env.app.db).await.unwrap();
    let mut c = Client::connect_tls(imap).await;
    c.read_line().await.unwrap();
    c.send_raw(format!("f1 AUTHENTICATE XOAUTH2 {}\r\n", xoauth2("bob@example.org", "token-bob")).as_bytes()).await;
    assert!(c.read_line().await.unwrap().starts_with("f1 NO"), "disabled domain");
    sqlx::query("UPDATE domains SET enabled = 1 WHERE name = 'example.org'").execute(&env.app.db).await.unwrap();

    // Per-protocol switches apply to token logins too.
    sqlx::query("UPDATE accounts SET imap_enabled = 0 WHERE email = 'bob@example.org'").execute(&env.app.db).await.unwrap();
    let mut c = Client::connect_tls(imap).await;
    c.read_line().await.unwrap();
    c.send_raw(format!("d1 AUTHENTICATE XOAUTH2 {}\r\n", xoauth2("bob@example.org", "token-bob")).as_bytes()).await;
    assert!(c.read_line().await.unwrap().starts_with("d1 NO"));

    // With single sign-on switched off, tokens are worthless and no longer advertised.
    admin.put("/api/oauth", json!({ "enabled": false, "issuer": format!("http://{addr}"), "client_id": "unomail" })).await;
    sqlx::query("UPDATE accounts SET imap_enabled = 1").execute(&env.app.db).await.unwrap();
    let mut c = Client::connect_tls(imap).await;
    assert!(!c.read_line().await.unwrap().contains("XOAUTH2"));
    c.send_raw(format!("e1 AUTHENTICATE XOAUTH2 {}\r\n", xoauth2("bob@example.org", "token-bob")).as_bytes()).await;
    assert!(c.read_line().await.unwrap().starts_with("e1 NO"));
    c.send_raw(format!("e2 LOGIN bob@example.org \"{PASSWORD}\"\r\n").as_bytes()).await;
    assert!(c.read_line().await.unwrap().starts_with("e2 OK"), "passwords keep working");
}

#[tokio::test]
async fn one_network_cannot_crowd_out_everybody_elses_sign_ins() {
    let env = TestEnv::start().await;
    let mut browser = Api::new(&env);
    browser.peer = "203.0.113.77:40000".parse().unwrap();
    // Anybody can produce error outcomes; each waits on the server for its sign-in page.
    for _ in 0..50 {
        let failed = browser.get("/api/auth/oauth/callback?error=access_denied").await;
        assert_eq!(failed.headers["location"], "/login?sso=1");
    }
    let crowded = browser.get("/api/auth/oauth/callback?error=access_denied").await;
    assert_eq!(crowded.headers["location"], "/login", "no more outcomes are kept for this network");
    browser.peer = "203.0.113.78:40000".parse().unwrap();
    assert_eq!(browser.get("/api/auth/oauth/callback?error=access_denied").await.headers["location"], "/login?sso=1");
}

#[tokio::test]
async fn token_sessions_end_when_the_provider_or_the_server_stops_vouching() {
    use unomail::auth::{Account, Grant, Protocol};
    let (env, admin, addr, _) = env_with_sso().await;
    let bob = Account::by_email(&env.app.db, "bob@example.org").await.unwrap().unwrap();
    let session = |token: &str| Grant::new(&bob, Protocol::Imap, None).with_token(token.into());
    // A connection starts with a sign-in, which links the mailbox to the identity.
    unomail::oauth::authenticate_token(&env.app, "bob@example.org", "token-bob", "127.0.0.1".parse().unwrap(), Protocol::Imap).await.unwrap();
    assert!(session("token-bob").valid(&env.app).await);
    // The link removed (an administrator's sign-in reset): the open connection is closed.
    let link: String = sqlx::query_scalar("SELECT subject FROM oauth_links WHERE account_id = ?").bind(bob.id).fetch_one(&env.app.db).await.unwrap();
    sqlx::query("DELETE FROM oauth_links").execute(&env.app.db).await.unwrap();
    assert!(!session("token-bob").valid(&env.app).await);
    sqlx::query("INSERT INTO oauth_links (account_id, subject, linked_at) VALUES (?, ?, 0)").bind(bob.id).bind(link).execute(&env.app.db).await.unwrap();
    assert!(session("token-bob").valid(&env.app).await);
    // Revoked (or never issued) at the provider: the open connection is closed too.
    assert!(!session("token-forged").valid(&env.app).await);
    assert!(!session("token-stranger").valid(&env.app).await, "a token for someone else");
    // Single sign-on turned off here.
    admin.put("/api/oauth", json!({ "enabled": false, "issuer": format!("http://{addr}"), "client_id": "unomail" })).await;
    assert!(!session("token-bob").valid(&env.app).await);
}
