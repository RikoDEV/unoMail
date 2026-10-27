//! Two-step sign-in (authenticator app, passkeys, recovery codes) and app passwords.

mod common;

use std::net::IpAddr;

use axum::http::{Method, StatusCode, header};
use base64::Engine;
use common::{Api, PASSWORD, TestEnv};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::{Value, json};
use unomail::{
    auth::{self, AuthError, Protocol},
    twofactor::{b64url, code_at, unb64url, unbase32},
    util::sha256,
};

const ORIGIN: &str = "https://mail.test.example";
const RP_ID: &str = "mail.test.example";

/// The code an authenticator app shows now (or `steps` periods later).
fn code(secret: &str, steps: i64) -> String {
    code_at(&unbase32(secret).unwrap(), unomail::util::now() / 30 + steps)
}

/// Signs in as a program would; each check from another network, so that the wrong passwords
/// these tests try on purpose do not add up to a lockout.
async fn programs(env: &TestEnv, password: &str, protocol: Protocol) -> Result<(), AuthError> {
    static NEXT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(10);
    let from: IpAddr = format!("203.0.113.{}", NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)).parse().unwrap();
    auth::authenticate(&env.app.db, &env.app.limiter, "bob@example.org", password, from, protocol).await.map(|_| ())
}

/// Signs in with the password; returns the second-factor challenge (or the session reply).
async fn password_step(env: &TestEnv) -> (Api, Value) {
    let api = Api::new(env);
    let reply = api.post("/api/auth/login", json!({ "email": "bob@example.org", "password": PASSWORD })).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    (api, reply.body)
}

#[tokio::test]
async fn an_authenticator_app_guards_the_sign_in() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    assert_eq!(bob.get("/api/me/two-factor").await.body["enabled"], false);

    // Setting up: nothing changes until a code from the app proves it works.
    let setup = bob.post("/api/me/two-factor/totp", json!({})).await.body;
    let secret = setup["secret"].as_str().unwrap().to_owned();
    assert!(setup["uri"].as_str().unwrap().starts_with("otpauth://totp/example.org:bob@example.org?secret="));
    let (_, plain) = password_step(&env).await;
    assert!(plain["account"].is_object(), "not active yet: {plain}");
    assert_eq!(bob.put("/api/me/two-factor/totp", json!({ "code": "000000", "password": PASSWORD })).await.status, StatusCode::BAD_REQUEST);
    // A session alone cannot enrol an authenticator: that would let a thief lock the owner out.
    assert_eq!(bob.put("/api/me/two-factor/totp", json!({ "code": code(&secret, 0), "password": "not the password" })).await.status, StatusCode::UNAUTHORIZED);
    let enabled = bob.put("/api/me/two-factor/totp", json!({ "code": code(&secret, 0), "password": PASSWORD })).await;
    assert_eq!(enabled.status, StatusCode::OK, "{}", enabled.text);
    let recovery: Vec<String> = serde_json::from_value(enabled.body["recovery_codes"].clone()).unwrap();
    assert_eq!(recovery.len(), 10, "recovery codes come with the first factor");
    assert_eq!(recovery[0].len(), 19, "80 bits each: {}", recovery[0]);
    let stored: String = sqlx::query_scalar("SELECT code_hash FROM recovery_codes LIMIT 1").fetch_one(&env.app.db).await.unwrap();
    assert!(!recovery.iter().any(|c| unomail::util::sha256_hex(c.replace('-', "").as_bytes()) == stored), "stored keyed, not as a plain hash");
    assert_eq!(bob.get("/api/me/two-factor").await.body["recovery_codes_left"], 10);
    // Starting a new setup must not quietly switch the working authenticator off (that needs
    // the password).
    assert_eq!(bob.post("/api/me/two-factor/totp", json!({})).await.status, StatusCode::CONFLICT);
    assert_eq!(bob.get("/api/me/two-factor").await.body["totp"], true);

    // The password alone no longer signs in; no session cookie is handed out yet.
    let (mut api, waiting) = password_step(&env).await;
    let second = waiting["second_factor"].clone();
    assert_eq!(second["methods"], json!({ "totp": true, "passkey": false, "recovery": true }));
    assert!(api.cookie.is_none() && waiting.get("account").is_none());
    let token = second["token"].as_str().unwrap().to_owned();
    assert_eq!(api.post("/api/auth/second-factor", json!({ "token": token, "code": "123456" })).await.status, StatusCode::CONFLICT);
    // The code used to switch the app on was used up: the next one is needed.
    let reply = api.post("/api/auth/second-factor", json!({ "token": token, "code": code(&secret, 1) })).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    assert_eq!(reply.body["account"]["email"], "bob@example.org");
    let cookie = reply.headers[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_owned();
    api.cookie = Some(cookie);
    api.csrf = reply.body["csrf_token"].as_str().map(str::to_owned);
    assert_eq!(api.get("/api/auth/me").await.status, StatusCode::OK);
    assert_eq!(api.post("/api/auth/second-factor", json!({ "token": token, "code": code(&secret, 1) })).await.status, StatusCode::BAD_REQUEST, "a sign-in step is used once");

    // A code is good once, even for another sign-in.
    let (api2, waiting) = password_step(&env).await;
    let token2 = waiting["second_factor"]["token"].as_str().unwrap().to_owned();
    assert_eq!(api2.post("/api/auth/second-factor", json!({ "token": token2, "code": code(&secret, 1) })).await.status, StatusCode::CONFLICT);
    // A recovery code works, once.
    assert_eq!(api2.post("/api/auth/second-factor", json!({ "token": token2, "recovery_code": recovery[0].to_uppercase() })).await.status, StatusCode::OK);
    let (api3, waiting) = password_step(&env).await;
    let token3 = waiting["second_factor"]["token"].as_str().unwrap().to_owned();
    assert_eq!(api3.post("/api/auth/second-factor", json!({ "token": token3, "recovery_code": recovery[0] })).await.status, StatusCode::CONFLICT);
    assert_eq!(bob.get("/api/me/two-factor").await.body["recovery_codes_left"], 9);

    // Guessing: a few tries per sign-in, then the password is needed again. (From another
    // network: the wrong codes count against it like wrong passwords.)
    let mut api4 = Api::new(&env);
    api4.peer = "203.0.113.200:40000".parse().unwrap();
    let waiting = api4.post("/api/auth/login", json!({ "email": "bob@example.org", "password": PASSWORD })).await.body;
    let token4 = waiting["second_factor"]["token"].as_str().unwrap().to_owned();
    for _ in 0..5 {
        api4.post("/api/auth/second-factor", json!({ "token": token4, "code": "999999" })).await;
    }
    assert_eq!(api4.post("/api/auth/second-factor", json!({ "token": token4, "code": code(&secret, 0) })).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(Api::new(&env).post("/api/auth/second-factor", json!({ "token": "made-up", "code": "123456" })).await.status, StatusCode::BAD_REQUEST);

    // Switching it off needs the password; the recovery codes go with the last factor.
    assert_eq!(bob.send(Method::DELETE, "/api/me/two-factor/totp", Some(json!({ "password": "wrong" })), &[]).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bob.send(Method::DELETE, "/api/me/two-factor/totp", Some(json!({ "password": PASSWORD })), &[]).await.status, StatusCode::OK);
    assert_eq!(bob.get("/api/me/two-factor").await.body, json!({ "enabled": false, "totp": false, "recovery_codes_left": 0, "passkeys_supported": true, "passkeys": [] }), "test hosts have a name, so passkeys are possible");
    assert!(password_step(&env).await.1["account"].is_object());
}

#[tokio::test]
async fn parallel_guesses_do_not_get_extra_tries() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let secret = "JBSWY3DPEHPK3PXP";
    sqlx::query("INSERT INTO totp_secrets (account_id, secret, enabled, created_at) VALUES (?, ?, 1, 0)").bind(bob.id).bind(env.app.secrets.seal(secret)).execute(&env.app.db).await.unwrap();
    let mut api = Api::new(&env);
    api.peer = "203.0.113.201:40000".parse().unwrap();
    let waiting = api.post("/api/auth/login", json!({ "email": "bob@example.org", "password": PASSWORD })).await.body;
    let token = waiting["second_factor"]["token"].as_str().unwrap().to_owned();
    // More wrong codes than allowed, all at once: each must count.
    let guesses = (0..8).map(|_| api.post("/api/auth/second-factor", json!({ "token": token, "code": "999999" })));
    futures_util::future::join_all(guesses).await;
    let reply = api.post("/api/auth/second-factor", json!({ "token": token, "code": code(secret, 0) })).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "the sign-in is used up: {}", reply.text);
}

#[tokio::test]
async fn programs_need_app_passwords_once_two_step_sign_in_is_on() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    // Without a second factor the account password works everywhere.
    for protocol in [Protocol::Imap, Protocol::Smtp, Protocol::Pop3, Protocol::Dav, Protocol::Jmap] {
        assert_eq!(programs(&env, PASSWORD, protocol).await, Ok(()), "{protocol:?}");
    }

    let made = bob.post("/api/me/app-passwords", json!({ "name": "Phone mail", "scopes": ["mail"], "password": PASSWORD })).await;
    assert_eq!(made.status, StatusCode::OK, "{}", made.text);
    let phone = made.body["password"].as_str().unwrap().to_owned();
    assert_eq!(phone.len(), 29);
    let calendar = bob.post("/api/me/app-passwords", json!({ "name": "Calendar", "scopes": ["dav", "nonsense"], "password": PASSWORD })).await.body;
    assert_eq!(calendar["scopes"], json!(["dav"]));
    let calendar_password = calendar["password"].as_str().unwrap().to_owned();
    for bad in [json!({ "name": "", "scopes": ["mail"], "password": PASSWORD }), json!({ "name": "x", "scopes": [], "password": PASSWORD })] {
        assert_eq!(bob.post("/api/me/app-passwords", bad).await.status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(bob.post("/api/me/app-passwords", json!({ "name": "x", "scopes": ["mail"], "password": "wrong" })).await.status, StatusCode::UNAUTHORIZED);

    // Each password for what it was made for, typed with or without the spaces.
    assert_eq!(programs(&env, &phone, Protocol::Imap).await, Ok(()));
    assert_eq!(programs(&env, &phone.replace(' ', "").to_uppercase(), Protocol::Smtp).await, Ok(()));
    assert_eq!(programs(&env, &phone, Protocol::Dav).await, Err(AuthError::Invalid));
    assert_eq!(programs(&env, &calendar_password, Protocol::Dav).await, Ok(()));
    assert_eq!(programs(&env, &calendar_password, Protocol::Imap).await, Err(AuthError::Invalid));
    // Never for the web sign-in.
    assert_eq!(Api::new(&env).post("/api/auth/login", json!({ "email": "bob@example.org", "password": phone })).await.status, StatusCode::UNAUTHORIZED);

    // With an authenticator app on, the account password no longer opens programs.
    let secret = bob.post("/api/me/two-factor/totp", json!({})).await.body["secret"].as_str().unwrap().to_owned();
    bob.put("/api/me/two-factor/totp", json!({ "code": code(&secret, 0), "password": PASSWORD })).await;
    for protocol in [Protocol::Imap, Protocol::Smtp, Protocol::Pop3, Protocol::Dav, Protocol::Jmap, Protocol::Sieve] {
        assert_eq!(programs(&env, PASSWORD, protocol).await, Err(AuthError::Invalid), "{protocol:?}");
    }
    assert_eq!(programs(&env, &phone, Protocol::Imap).await, Ok(()));
    // Over HTTP too: CalDAV takes the calendar's app password, not the account password.
    let basic = |password: &str| format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("bob@example.org:{password}")));
    let dav = |password: String| {
        let api = Api::new(&env);
        async move { api.send(Method::from_bytes(b"PROPFIND").unwrap(), "/dav/", None, &[("authorization", &basic(&password))]).await.status }
    };
    assert_eq!(dav(PASSWORD.to_owned()).await, StatusCode::UNAUTHORIZED);
    assert_eq!(dav(calendar_password.clone()).await, StatusCode::MULTI_STATUS);

    // Listed with when they were last used; revoking one ends it at once, cached or not.
    let listed = bob.get("/api/me/app-passwords").await.body;
    assert_eq!(listed.as_array().unwrap().len(), 2);
    let entry = listed.as_array().unwrap().iter().find(|p| p["name"] == "Calendar").unwrap().clone();
    assert!(entry["last_used_at"].is_number() && entry["last_ip"].is_string() && entry.get("password").is_none());
    assert_eq!(bob.delete(&format!("/api/me/app-passwords/{}", entry["id"])).await.status, StatusCode::OK);
    assert_eq!(dav(calendar_password.clone()).await, StatusCode::UNAUTHORIZED);
    assert_eq!(programs(&env, &calendar_password, Protocol::Dav).await, Err(AuthError::Invalid));

    // Somebody else's app password does nothing for Bob, and Bob's list is his own.
    env.account("carol@example.org").await;
    let carol = Api::logged_in(&env, "carol@example.org").await;
    let carols = carol.post("/api/me/app-passwords", json!({ "name": "Hers", "scopes": ["mail"], "password": PASSWORD })).await.body["password"].as_str().unwrap().to_owned();
    assert_eq!(programs(&env, &carols, Protocol::Imap).await, Err(AuthError::Invalid));
    assert_eq!(carol.get("/api/me/app-passwords").await.body.as_array().unwrap().len(), 1);
    let bobs_id = bob.get("/api/me/app-passwords").await.body[0]["id"].clone();
    assert_eq!(carol.delete(&format!("/api/me/app-passwords/{bobs_id}")).await.status, StatusCode::NOT_FOUND);
}

/// A software passkey: one P-256 key.
struct Authenticator {
    key: EcdsaKeyPair,
    id: Vec<u8>,
    counter: u32,
    /// Flags of the next sign-in (user present and verified unless changed).
    flags: u8,
}

impl Authenticator {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        Authenticator { key: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap(), id: vec![7; 16], counter: 0, flags: 0x05 }
    }

    fn with_id(byte: u8) -> Self {
        Authenticator { id: vec![byte; 16], ..Self::new() }
    }

    /// A sign-in as a discoverable passkey does it: naming the user it was made for.
    fn sign_as(&mut self, options: &Value, user_handle: &[u8]) -> Value {
        let mut answer = self.sign(options);
        answer["userHandle"] = json!(b64url(user_handle));
        answer
    }

    fn client_data(kind: &str, challenge: &str) -> String {
        b64url(&serde_json::to_vec(&json!({ "type": kind, "challenge": challenge, "origin": ORIGIN })).unwrap())
    }

    fn register(&self, options: &Value) -> Value {
        let point = self.key.public_key().as_ref();
        let mut cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        cose.extend_from_slice(&point[1..33]);
        cose.extend_from_slice(&[0x22, 0x58, 0x20]);
        cose.extend_from_slice(&point[33..65]);
        let mut data = sha256(RP_ID.as_bytes()).to_vec();
        data.push(0x45);
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.id);
        data.extend_from_slice(&cose);
        let mut object = vec![0xa3, 0x63];
        object.extend_from_slice(b"fmt");
        object.push(0x64);
        object.extend_from_slice(b"none");
        object.push(0x67);
        object.extend_from_slice(b"attStmt");
        object.extend_from_slice(&[0xa0, 0x68]);
        object.extend_from_slice(b"authData");
        object.extend_from_slice(&[0x59, (data.len() >> 8) as u8, data.len() as u8]);
        object.extend_from_slice(&data);
        json!({ "name": "Laptop", "clientDataJSON": Self::client_data("webauthn.create", options["challenge"].as_str().unwrap()), "attestationObject": b64url(&object) })
    }

    fn sign(&mut self, options: &Value) -> Value {
        self.counter += 1;
        let mut data = sha256(RP_ID.as_bytes()).to_vec();
        data.push(self.flags);
        data.extend_from_slice(&self.counter.to_be_bytes());
        let client = Self::client_data("webauthn.get", options["challenge"].as_str().unwrap());
        let signed = [&data[..], &sha256(&unb64url(&client).unwrap())[..]].concat();
        let signature = self.key.sign(&SystemRandom::new(), &signed).unwrap();
        json!({ "id": b64url(&self.id), "clientDataJSON": client, "authenticatorData": b64url(&data), "signature": b64url(signature.as_ref()) })
    }
}

#[tokio::test]
async fn a_passkey_is_a_second_factor() {
    let env = TestEnv::start_with(|cfg| cfg.public_url_override = Some(ORIGIN.into())).await;
    env.domain("example.org").await;
    let bob_account = env.account("bob@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    assert_eq!(bob.get("/api/me/two-factor").await.body["passkeys_supported"], true);
    let mut device = Authenticator::new();

    // A passkey signs in on its own: adding one needs the password.
    assert_eq!(bob.post("/api/me/passkeys/register/options", json!({ "password": "wrong" })).await.status, StatusCode::UNAUTHORIZED);
    let options = bob.post("/api/me/passkeys/register/options", json!({ "password": PASSWORD })).await.body;
    assert_eq!((options["rp"]["id"].clone(), options["attestation"].clone()), (json!(RP_ID), json!("none")));
    let added = bob.post("/api/me/passkeys/register", device.register(&options)).await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.text);
    assert_eq!(added.body["recovery_codes"].as_array().unwrap().len(), 10);
    // A challenge answers one registration only.
    assert_eq!(bob.post("/api/me/passkeys/register", device.register(&options)).await.status, StatusCode::BAD_REQUEST);
    let listed = bob.get("/api/me/two-factor").await.body;
    assert_eq!((listed["enabled"].clone(), listed["passkeys"][0]["name"].clone()), (json!(true), json!("Laptop")));

    let (mut api, waiting) = password_step(&env).await;
    let second = waiting["second_factor"].clone();
    assert_eq!(second["methods"]["passkey"], true);
    assert_eq!(second["passkey"]["allowCredentials"][0]["id"], b64url(&device.id));
    let answer = device.sign(&second["passkey"]);
    let reply = api.post("/api/auth/second-factor", json!({ "token": second["token"], "passkey": answer })).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    api.cookie = Some(reply.headers[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_owned());
    assert_eq!(api.get("/api/auth/me").await.status, StatusCode::OK);

    // An answer cannot be replayed, and another device's key does not pass for this one.
    let (api2, waiting) = password_step(&env).await;
    let second = waiting["second_factor"].clone();
    assert_eq!(api2.post("/api/auth/second-factor", json!({ "token": second["token"], "passkey": answer })).await.status, StatusCode::CONFLICT);
    let retry = api2.post("/api/auth/second-factor/passkey", json!({ "token": second["token"] })).await.body["passkey"].clone();
    let mut stranger = Authenticator::new();
    assert_eq!(api2.post("/api/auth/second-factor", json!({ "token": second["token"], "passkey": stranger.sign(&retry) })).await.status, StatusCode::CONFLICT);
    let retry = api2.post("/api/auth/second-factor/passkey", json!({ "token": second["token"] })).await.body["passkey"].clone();
    assert_eq!(api2.post("/api/auth/second-factor", json!({ "token": second["token"], "passkey": device.sign(&retry) })).await.status, StatusCode::OK);

    // An administrator can reset a mailbox whose owner lost the device.
    let admin_account = env.account_with("admin@example.org", unomail::auth::Role::SuperAdmin, None).await;
    let _ = admin_account;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    assert_eq!(admin.get(&format!("/api/accounts/{}/two-factor", bob_account.id)).await.body["passkeys"], 1);
    assert_eq!(bob.delete(&format!("/api/accounts/{}/two-factor", bob_account.id)).await.status, StatusCode::FORBIDDEN);
    assert_eq!(admin.delete(&format!("/api/accounts/{}/two-factor", bob_account.id)).await.status, StatusCode::OK);
    assert!(password_step(&env).await.1["account"].is_object());
}

#[tokio::test]
async fn a_passkey_signs_in_without_a_password() {
    let env = TestEnv::start_with(|cfg| cfg.public_url_override = Some(ORIGIN.into())).await;
    env.domain("example.org").await;
    let bob_account = env.account("bob@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let handle = bob_account.id.to_be_bytes();

    // Registration asks for a passkey proper: discoverable and unlocked by the user.
    let options = bob.post("/api/me/passkeys/register/options", json!({ "password": PASSWORD })).await.body;
    assert_eq!(options["authenticatorSelection"], json!({ "residentKey": "required", "requireResidentKey": true, "userVerification": "required" }));
    assert_eq!(options["extensions"]["credProps"], true);
    assert_eq!(options["user"]["id"], b64url(&handle));
    let mut device = Authenticator::new();
    let mut registration = device.register(&options);
    registration["transports"] = json!(["internal", "hybrid", "carrier-pigeon"]);
    registration["discoverable"] = json!(true);
    assert_eq!(bob.post("/api/me/passkeys/register", registration).await.status, StatusCode::OK);
    let listed = bob.get("/api/me/two-factor").await.body["passkeys"][0].clone();
    assert_eq!((listed["discoverable"].clone(), listed["synced"].clone()), (json!(true), json!(false)));
    let again = bob.post("/api/me/passkeys/register/options", json!({ "password": PASSWORD })).await.body;
    assert_eq!(again["excludeCredentials"][0]["transports"], json!(["hybrid", "internal"]), "only known transports are kept");

    // Signing in: no address, no password, no list of credentials.
    let anonymous = Api::new(&env);
    let start = anonymous.get("/api/auth/passkey").await.body;
    assert_eq!((start["options"]["userVerification"].clone(), start["options"]["allowCredentials"].clone()), (json!("required"), json!([])));
    let answer = device.sign_as(&start["options"], &handle);
    let reply = anonymous.post("/api/auth/passkey", json!({ "token": start["token"], "credential": answer })).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
    assert_eq!(reply.body["account"]["email"], "bob@example.org");
    let mut signed_in = Api::new(&env);
    signed_in.cookie = Some(reply.headers[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_owned());
    assert_eq!(signed_in.get("/api/auth/me").await.body["account"]["email"], "bob@example.org");
    // The token and its challenge are good for one answer.
    assert_eq!(anonymous.post("/api/auth/passkey", json!({ "token": start["token"], "credential": answer })).await.status, StatusCode::BAD_REQUEST);


    // Another user's handle, a passkey that did not verify the user, a passkey nobody has.
    for (label, flags, handle, expected) in [
        ("wrong user", 0x05, (bob_account.id + 1).to_be_bytes(), StatusCode::UNAUTHORIZED),
        ("not verified", 0x01, handle, StatusCode::UNAUTHORIZED),
    ] {
        let api = Api::new(&env);
        let start = api.get("/api/auth/passkey").await.body;
        device.flags = flags;
        let credential = device.sign_as(&start["options"], &handle);
        assert_eq!(api.post("/api/auth/passkey", json!({ "token": start["token"], "credential": credential })).await.status, expected, "{label}");
    }
    device.flags = 0x05;
    let api = Api::new(&env);
    let start = api.get("/api/auth/passkey").await.body;
    let mut stranger = Authenticator::with_id(9);
    let credential = stranger.sign_as(&start["options"], &handle);
    assert_eq!(api.post("/api/auth/passkey", json!({ "token": start["token"], "credential": credential })).await.status, StatusCode::NOT_FOUND, "unknown passkeys are told apart");

    // Renaming, and removing with what the browser needs to forget it.
    let id = listed["id"].as_i64().unwrap();
    assert_eq!(bob.patch(&format!("/api/me/passkeys/{id}"), json!({ "name": "Phone" })).await.status, StatusCode::OK);
    assert_eq!(bob.get("/api/me/two-factor").await.body["passkeys"][0]["name"], "Phone");
    let removed = bob.send(Method::DELETE, &format!("/api/me/passkeys/{id}"), Some(json!({ "password": PASSWORD })), &[]).await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.text);
    assert_eq!(removed.body["signal"], json!({ "rpId": RP_ID, "userId": b64url(&handle), "allAcceptedCredentialIds": [] }));
    let api = Api::new(&env);
    let start = api.get("/api/auth/passkey").await.body;
    let credential = device.sign_as(&start["options"], &handle);
    assert_eq!(api.post("/api/auth/passkey", json!({ "token": start["token"], "credential": credential })).await.status, StatusCode::NOT_FOUND);
}

async fn app_password_count(env: &TestEnv) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM app_passwords").fetch_one(&env.app.db).await.unwrap()
}

/// Whoever took an account over may have made an app password for themselves: resetting the
/// account must not leave it working.
#[tokio::test]
async fn resets_revoke_app_passwords() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob_account = env.account("bob@example.org").await;
    env.account_with("admin@example.org", unomail::auth::Role::SuperAdmin, None).await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let make = json!({ "name": "Phone", "scopes": ["mail"], "password": PASSWORD });

    // An administrator's password reset.
    let bob = Api::logged_in(&env, "bob@example.org").await;
    assert_eq!(bob.post("/api/me/app-passwords", make.clone()).await.status, StatusCode::OK);
    assert_eq!(admin.patch(&format!("/api/accounts/{}", bob_account.id), json!({ "password": "a brand new long passphrase" })).await.status, StatusCode::OK);
    assert_eq!(app_password_count(&env).await, 0);
    sqlx::query("UPDATE accounts SET password_hash = ? WHERE id = ?").bind(auth::hash_password(PASSWORD).await.unwrap()).bind(bob_account.id).execute(&env.app.db).await.unwrap();

    // An administrator's reset of the second factors.
    let bob = Api::logged_in(&env, "bob@example.org").await;
    assert_eq!(bob.post("/api/me/app-passwords", make.clone()).await.status, StatusCode::OK);
    assert_eq!(admin.delete(&format!("/api/accounts/{}/two-factor", bob_account.id)).await.status, StatusCode::OK);
    assert_eq!(app_password_count(&env).await, 0);
    assert_eq!(bob.get("/api/auth/me").await.status, StatusCode::UNAUTHORIZED, "sessions end too");

    // The owner's own password change: kept unless asked for.
    let bob = Api::logged_in(&env, "bob@example.org").await;
    assert_eq!(bob.post("/api/me/app-passwords", make.clone()).await.status, StatusCode::OK);
    assert_eq!(bob.post("/api/auth/password", json!({ "current_password": PASSWORD, "new_password": "another good password" })).await.status, StatusCode::OK);
    assert_eq!(app_password_count(&env).await, 1);
    let revoke = json!({ "current_password": "another good password", "new_password": "and yet another one", "revoke_app_passwords": true });
    assert_eq!(bob.post("/api/auth/password", revoke).await.status, StatusCode::OK);
    assert_eq!(app_password_count(&env).await, 0);

    // An administrator cannot set their own password without the current one.
    let admin_id: i64 = sqlx::query_scalar("SELECT id FROM accounts WHERE email = 'admin@example.org'").fetch_one(&env.app.db).await.unwrap();
    assert_eq!(admin.patch(&format!("/api/accounts/{admin_id}"), json!({ "password": "attacker chosen password" })).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn passkey_sign_ins_are_limited_per_network() {
    let env = TestEnv::start().await;
    let mut api = Api::new(&env);
    // An IPv6 customer holds a whole /64: every address in it counts as one.
    for host in 1..=500u32 {
        api.peer = format!("[2001:db8:77:1::{host:x}]:40000").parse().unwrap();
        assert_eq!(api.get("/api/auth/passkey").await.status, StatusCode::OK);
    }
    api.peer = "[2001:db8:77:1:ffff::1]:40000".parse().unwrap();
    assert_eq!(api.get("/api/auth/passkey").await.status, StatusCode::TOO_MANY_REQUESTS);
    api.peer = "[2001:db8:77:2::1]:40000".parse().unwrap();
    assert_eq!(api.get("/api/auth/passkey").await.status, StatusCode::OK, "other networks are not affected");
}

#[tokio::test]
async fn setup_qr_codes_carry_the_account_password_only_without_two_step_sign_in() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let bob = Api::logged_in(&env, "bob@example.org").await;

    let setup = bob.get("/api/me/client-setup").await.body;
    assert_eq!(setup["email"], "bob@example.org");
    assert_eq!(setup["hostname"], env.app.cfg.hostname.as_str());
    assert_eq!((setup["imap_port"].as_i64(), setup["smtp_port"].as_i64()), (Some(993), Some(465)));
    assert_eq!(setup["two_factor"], false);
    assert_eq!(bob.post("/api/me/client-setup", json!({ "password": "wrong" })).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bob.post("/api/me/client-setup", json!({ "password": PASSWORD })).await.status, StatusCode::OK);

    // With an authenticator app on, programs need an app password, so the account password is refused.
    let secret = bob.post("/api/me/two-factor/totp", json!({})).await.body["secret"].as_str().unwrap().to_owned();
    bob.put("/api/me/two-factor/totp", json!({ "code": code(&secret, 0), "password": PASSWORD })).await;
    assert_eq!(bob.get("/api/me/client-setup").await.body["two_factor"], true);
    assert_eq!(bob.post("/api/me/client-setup", json!({ "password": PASSWORD })).await.status, StatusCode::CONFLICT);
}
