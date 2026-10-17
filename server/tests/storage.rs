//! Where mail is kept: OpenPGP encryption at rest, encrypted blobs, S3, retention and backups.

mod common;

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Router,
    body::Bytes,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::IntoResponse,
};
use common::{Api, Client, TestEnv, message};
use parking_lot::Mutex;
use pgp::composed::{ArmorOptions, EncryptionCaps, KeyType, Message, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder};
use serde_json::json;
use unomail::{backup, config::BackupTarget, s3::S3Config};

/// The server allows one backup at a time per process; tests that take backups take turns.
static BACKUP_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn key_pair(uid: &str) -> (SignedSecretKey, String) {
    let mut encryption = SubkeyParamsBuilder::default();
    encryption.key_type(KeyType::ECDH(pgp::crypto::ecc_curve::ECCCurve::Curve25519Legacy)).can_sign(false).can_encrypt(EncryptionCaps::All).can_authenticate(false);
    let mut params = SecretKeyParamsBuilder::default();
    params.key_type(KeyType::Ed25519Legacy).can_certify(true).can_sign(true).can_encrypt(EncryptionCaps::None).primary_user_id(uid.into()).subkeys(vec![encryption.build().unwrap()]);
    let secret = params.build().unwrap().generate(rand::thread_rng()).unwrap();
    let public = SignedPublicKey::from(secret.clone()).to_armored_string(ArmorOptions::default()).unwrap();
    (secret, public)
}

#[tokio::test]
async fn incoming_mail_is_encrypted_to_the_owners_key() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    assert_eq!(api.get("/api/me/pgp/encryption").await.body, json!({ "enabled": false, "key": null, "problem": null }));
    assert_eq!(api.put("/api/me/pgp/encryption", json!({ "enabled": true })).await.status, StatusCode::BAD_REQUEST, "no key yet");

    // The key the web mail keeps (its private half stays passphrase-protected).
    let (secret, public) = key_pair("Bob <bob@example.org>");
    assert_eq!(api.put("/api/me/pgp", json!({ "public_key": public })).await.status, StatusCode::OK);
    let set = api.put("/api/me/pgp/encryption", json!({ "enabled": true })).await;
    assert_eq!(set.status, StatusCode::OK, "{}", set.text);
    assert_eq!(set.body["enabled"], true);
    assert_eq!(set.body["key"]["user_ids"], json!(["Bob <bob@example.org>"]));

    let mut smtp = Client::smtp(env.mx).await;
    let msg = message("alice@remote.example", "bob@example.org", "Quarterly numbers", "Revenue went up");
    assert!(smtp.send_mail("alice@remote.example", &["bob@example.org"], &msg).await.starts_with("250"));
    let stored = env.inbox(&bob).await.pop().unwrap();
    assert!(stored.contains("Subject: Quarterly numbers") && stored.contains("multipart/encrypted"), "{stored}");
    assert!(!stored.contains("Revenue went up"), "the content is not readable on the server");
    let armored = stored.split("-----BEGIN PGP MESSAGE-----").nth(1).unwrap().split("-----END PGP MESSAGE-----").next().unwrap();
    let armored = format!("-----BEGIN PGP MESSAGE-----{armored}-----END PGP MESSAGE-----\r\n");
    let (encrypted, _) = Message::from_armor(armored.as_bytes()).unwrap();
    let mut decrypted = encrypted.decrypt(&"".into(), &secret).unwrap();
    if decrypted.is_compressed() {
        decrypted = decrypted.decompress().unwrap();
    }
    assert!(String::from_utf8(decrypted.as_data_vec().unwrap()).unwrap().contains("Revenue went up"));

    // Switched off: new mail is stored as it comes.
    assert_eq!(api.put("/api/me/pgp/encryption", json!({ "enabled": false })).await.body["enabled"], false);
    let msg = message("alice@remote.example", "bob@example.org", "Plain again", "readable");
    assert!(smtp.send_mail("alice@remote.example", &["bob@example.org"], &msg).await.starts_with("250"));
    assert!(env.inbox(&bob).await.iter().any(|m| m.contains("readable")));
}

#[tokio::test]
async fn trash_and_junk_are_emptied_after_the_configured_time() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let mut smtp = Client::smtp(env.mx).await;
    for subject in ["old trash", "new trash", "old junk"] {
        let msg = message("alice@remote.example", "bob@example.org", subject, "x");
        assert!(smtp.send_mail("alice@remote.example", &["bob@example.org"], &msg).await.starts_with("250"));
    }
    let store = &env.app.store;
    let inbox = store.mailbox_by_role(bob.id, "inbox").await.unwrap().unwrap();
    let trash = store.mailbox_by_role(bob.id, "trash").await.unwrap().unwrap();
    let junk = store.mailbox_by_role(bob.id, "junk").await.unwrap().unwrap();
    let messages = store.messages_in(inbox.id).await.unwrap();
    let id = |subject: &str| messages.iter().find(|m| m.subject == subject).unwrap().id;
    store.move_message(bob.id, id("old trash"), trash.id).await.unwrap();
    store.move_message(bob.id, id("new trash"), trash.id).await.unwrap();
    store.move_message(bob.id, id("old junk"), junk.id).await.unwrap();
    let long_ago = unomail::util::now() - 40 * 86_400;
    sqlx::query("UPDATE messages SET mailbox_since = ?, internal_date = ? WHERE subject IN ('old trash', 'old junk')").bind(long_ago).bind(long_ago).execute(&env.app.db).await.unwrap();

    // Junk kept forever by the administrator's choice; Trash after 30 days.
    let mut settings = (*env.app.rt()).clone();
    settings.junk_retention_days = 0;
    env.app.settings.store(Arc::new(settings));
    assert_eq!(unomail::retention::run(&env.app).await, 1);
    let left: Vec<String> = sqlx::query_scalar("SELECT subject FROM messages ORDER BY subject").fetch_all(&env.app.db).await.unwrap();
    assert_eq!(left, ["new trash", "old junk"]);
}

/// An in-memory, path-style S3 endpoint: just enough of the API.
#[derive(Clone, Default)]
struct FakeS3 {
    objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    unsigned: Arc<Mutex<usize>>,
}

async fn fake_s3(State(s3): State<FakeS3>, request: Request) -> impl IntoResponse {
    let signed = request.headers().get("authorization").and_then(|v| v.to_str().ok()).is_some_and(|v| v.starts_with("AWS4-HMAC-SHA256 Credential=key/"));
    if !signed {
        *s3.unsigned.lock() += 1;
        return (StatusCode::FORBIDDEN, Vec::new()).into_response();
    }
    let method = request.method().clone();
    let path = request.uri().path().trim_start_matches("/bucket").trim_start_matches('/').to_owned();
    let query = request.uri().query().unwrap_or("").to_owned();
    let range = request.headers().get("range").and_then(|v| v.to_str().ok()).map(str::to_owned);
    let body: Bytes = axum::body::to_bytes(request.into_body(), usize::MAX).await.unwrap();
    let mut objects = s3.objects.lock();
    match method {
        Method::PUT => {
            objects.insert(path, body.to_vec());
            StatusCode::OK.into_response()
        }
        Method::GET if path.is_empty() && query.contains("list-type=2") => {
            let prefix = query.split('&').find_map(|p| p.strip_prefix("prefix=")).unwrap_or("").replace("%2F", "/");
            let keys: String = objects.keys().filter(|k| k.starts_with(&prefix)).map(|k| format!("<Contents><Key>{k}</Key></Contents>")).collect();
            format!("<ListBucketResult><IsTruncated>false</IsTruncated>{keys}</ListBucketResult>").into_response()
        }
        Method::GET | Method::HEAD => match objects.get(&path) {
            Some(data) => {
                let data = match range.as_deref().and_then(|r| r.strip_prefix("bytes=0-")).and_then(|end| end.parse::<usize>().ok()) {
                    Some(end) => data[..data.len().min(end + 1)].to_vec(),
                    None => data.clone(),
                };
                (StatusCode::OK, if method == Method::HEAD { Vec::new() } else { data }).into_response()
            }
            None => (StatusCode::NOT_FOUND, "<Error><Code>NoSuchKey</Code></Error>").into_response(),
        },
        Method::DELETE => {
            objects.remove(&path);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

async fn start_fake_s3() -> (FakeS3, S3Config) {
    let s3 = FakeS3::default();
    let router = Router::new().fallback(fake_s3).with_state(s3.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let cfg = S3Config {
        endpoint: format!("http://{addr}"),
        bucket: "bucket".into(),
        region: "us-east-1".into(),
        access_key: "key".into(),
        secret_key: "secret".into(),
        prefix: "mail/".into(),
        path_style: true,
    };
    (s3, cfg)
}

#[tokio::test]
async fn mail_can_live_in_s3_sealed() {
    let (s3, cfg) = start_fake_s3().await;
    let env = TestEnv::start_with(|c| {
        c.blob_s3 = Some(cfg);
        c.encrypt_mail = true;
    })
    .await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let mut smtp = Client::smtp(env.mx).await;
    let msg = message("alice@remote.example", "bob@example.org", "Stored remotely", "in a bucket");
    assert!(smtp.send_mail("alice@remote.example", &["bob@example.org"], &msg).await.starts_with("250"));

    let objects = s3.objects.lock().clone();
    let (name, stored) = objects.iter().next().expect("the message went to the bucket");
    assert!(name.starts_with("mail/blobs/") && name.len() == "mail/blobs/aa/bb/".len() + 64, "{name}");
    assert!(stored.starts_with(b"UNOBLOB1") && !stored.windows(11).any(|w| w == b"in a bucket"), "sealed at rest");
    assert_eq!(*s3.unsigned.lock(), 0);
    let inbox = env.inbox(&bob).await;
    assert!(inbox[0].contains("in a bucket"), "read back transparently");
    let message = env.app.store.messages_in(env.app.store.mailbox_by_role(bob.id, "inbox").await.unwrap().unwrap().id).await.unwrap().remove(0);
    assert!(env.app.store.read_blob_head(&message.blob_hash, 12).await.unwrap().starts_with(b"Return-Path:"));
    assert!(env.app.cfg.data_dir.join("blob.key").exists());
}

#[tokio::test]
async fn backups_are_incremental_pruned_and_restorable() {
    let _one_at_a_time = BACKUP_TESTS.lock().await;
    let target = tempfile::tempdir().unwrap();
    let target_dir = target.path().to_owned();
    let env = TestEnv::start_with(|c| {
        c.backup_target = Some(BackupTarget::Dir(target_dir.clone()));
        c.backup_keep = 2;
    })
    .await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let mut smtp = Client::smtp(env.mx).await;
    let send = |subject: &'static str| message("alice@remote.example", "bob@example.org", subject, subject);
    assert!(smtp.send_mail("alice@remote.example", &["bob@example.org"], &send("first")).await.starts_with("250"));

    let first = backup::run(&env.app).await.unwrap();
    assert_eq!(first.blobs_copied, 1);
    assert!(target_dir.join("snapshots").join(&first.snapshot).join("manifest.json").exists());
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // Nothing new: nothing copied.
    let second = backup::run(&env.app).await.unwrap();
    assert_eq!((second.blobs_copied, second.snapshots_removed), (0, 0));
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // The first message is deleted, a second arrives; with two snapshots kept, the first
    // snapshot goes, but its message stays: the second snapshot still has it.
    let inbox = env.app.store.mailbox_by_role(bob.id, "inbox").await.unwrap().unwrap();
    let old = env.app.store.messages_in(inbox.id).await.unwrap().remove(0);
    env.app.store.delete_message(bob.id, old.id).await.unwrap();
    sqlx::query("UPDATE blobs SET created_at = 0").execute(&env.app.db).await.unwrap();
    env.app.store.gc_blobs().await.unwrap();
    assert!(smtp.send_mail("alice@remote.example", &["bob@example.org"], &send("second")).await.starts_with("250"));
    let third = backup::run(&env.app).await.unwrap();
    assert_eq!((third.blobs_copied, third.snapshots_removed, third.blobs_removed), (1, 1, 0));
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let fourth = backup::run(&env.app).await.unwrap();
    assert_eq!((fourth.snapshots_removed, fourth.blobs_removed), (1, 1), "now no snapshot needs the deleted message");
    let target_handle = backup::Target::Dir(target_dir.clone());
    assert_eq!(target_handle.snapshots().await.unwrap(), [third.snapshot.clone(), fourth.snapshot.clone()]);

    // The admin panel shows runs and snapshots.
    env.account_with("admin@example.org", unomail::auth::Role::SuperAdmin, None).await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let listed = admin.get("/api/backups").await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.text);
    assert_eq!(listed.body["snapshots"].as_array().unwrap().len(), 2);
    assert_eq!(listed.body["runs"].as_array().unwrap().len(), 4);
    assert_eq!(listed.body["runs"][0]["status"], "ok");
    let bobs = Api::logged_in(&env, "bob@example.org").await;
    assert_eq!(bobs.get("/api/backups").await.status, StatusCode::FORBIDDEN);

    // Restore into an empty data directory.
    let fresh = tempfile::tempdir().unwrap();
    let mut cfg = env.app.cfg.clone();
    cfg.data_dir = fresh.path().to_owned();
    let report = backup::restore(&cfg, None, false).await.unwrap();
    assert!(report.contains(&fourth.snapshot), "{report}");
    assert!(backup::restore(&cfg, None, false).await.unwrap_err().to_string().contains("--force"), "an existing database is not overwritten");
    let restored = unomail::app::App::new(cfg, None).await.unwrap();
    let subjects: Vec<String> = sqlx::query_scalar("SELECT subject FROM messages").fetch_all(&restored.db).await.unwrap();
    assert_eq!(subjects, ["second"]);
    let hash: String = sqlx::query_scalar("SELECT blob_hash FROM messages").fetch_one(&restored.db).await.unwrap();
    assert!(String::from_utf8(restored.store.read_blob(&hash).await.unwrap()).unwrap().contains("second"));
}

#[tokio::test]
async fn existing_mail_can_be_sealed_and_moved_later() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;
    let mut smtp = Client::smtp(env.mx).await;
    let msg = message("alice@remote.example", "bob@example.org", "Before", "written in the clear");
    assert!(smtp.send_mail("alice@remote.example", &["bob@example.org"], &msg).await.starts_with("250"));

    // Restart with encryption on and the store in S3: migrate-blobs moves and seals it.
    let (s3, s3_cfg) = start_fake_s3().await;
    let mut cfg = env.app.cfg.clone();
    cfg.encrypt_mail = true;
    cfg.blob_s3 = Some(s3_cfg);
    let old_dir = cfg.data_dir.join("blobs");
    let moved = unomail::app::App::new(cfg, None).await.unwrap();
    assert_eq!(backup::migrate_blobs(&moved, Some(old_dir)).await.unwrap(), 1);
    assert_eq!(backup::migrate_blobs(&moved, None).await.unwrap(), 0, "already in the right form");
    assert!(s3.objects.lock().values().all(|v| v.starts_with(b"UNOBLOB1")));
    let hash: String = sqlx::query_scalar("SELECT blob_hash FROM messages").fetch_one(&moved.db).await.unwrap();
    assert!(String::from_utf8(moved.store.read_blob(&hash).await.unwrap()).unwrap().contains("written in the clear"));
    let _ = bob;
}

#[tokio::test]
async fn backups_of_an_encrypted_store_are_encrypted() {
    let _one_at_a_time = BACKUP_TESTS.lock().await;
    let target = tempfile::tempdir().unwrap();
    let target_dir = target.path().to_owned();
    let env = TestEnv::start_with(|c| {
        c.backup_target = Some(BackupTarget::Dir(target_dir.clone()));
        c.encrypt_mail = true;
    })
    .await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let mut smtp = Client::smtp(env.mx).await;
    let msg = message("alice@remote.example", "bob@example.org", "Confidential subject line", "secret body");
    assert!(smtp.send_mail("alice@remote.example", &["bob@example.org"], &msg).await.starts_with("250"));
    let snapshot = backup::run(&env.app).await.unwrap().snapshot;

    // The database snapshot (subjects, addresses, the search index) is sealed like the mail.
    let stored = std::fs::read(target_dir.join("snapshots").join(&snapshot).join("unomail.db.gz")).unwrap();
    assert!(stored.starts_with(b"UNOBLOB1"), "sealed");
    let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(target_dir.join("snapshots").join(&snapshot).join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["encrypted_mail"], true);

    // Restoring needs the key, and works with it.
    let fresh = tempfile::tempdir().unwrap();
    let mut cfg = env.app.cfg.clone();
    cfg.data_dir = fresh.path().to_owned();
    assert!(backup::restore(&cfg, None, false).await.unwrap_err().to_string().contains("blob.key"));
    std::fs::copy(env.app.cfg.data_dir.join("blob.key"), fresh.path().join("blob.key")).unwrap();
    backup::restore(&cfg, None, false).await.unwrap();
    let restored = unomail::app::App::new(cfg, None).await.unwrap();
    let subjects: Vec<String> = sqlx::query_scalar("SELECT subject FROM messages").fetch_all(&restored.db).await.unwrap();
    assert_eq!(subjects, ["Confidential subject line"]);
}
