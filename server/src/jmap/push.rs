//! JMAP push subscriptions (RFC 8620 section 7.2) delivered as Web Push (RFC 8030): the
//! payload is encrypted for the subscriber (RFC 8291, aes128gcm) and the request identifies
//! this server with VAPID (RFC 8292), so browsers can be notified of new mail through their
//! push service even with no tab open.

use std::{collections::HashSet, time::Duration};

use ring::{
    aead, agreement, hkdf,
    rand::SystemRandom,
    signature::{self, EcdsaKeyPair, KeyPair},
};
use serde_json::{Map, Value, json};

use super::{Context, MethodError, MethodResult};
use crate::{
    app::{App, AppState},
    twofactor::{b64url, unb64url},
    util::{now, random_token},
};

const MAX_SUBSCRIPTIONS: i64 = 20;
/// Subscriptions live at most this long unless renewed.
const MAX_LIFETIME: i64 = 7 * 86_400;
const RECORD_SIZE: u32 = 4096;

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);
    let mut out = vec![0u8; len];
    prk.expand(&[info], Len(len)).and_then(|okm| okm.fill(&mut out)).expect("lengths are valid");
    out
}

/// Encrypts a push message for a subscriber's P-256 key and auth secret (RFC 8291).
pub fn encrypt(ua_public: &[u8], auth: &[u8], payload: &[u8]) -> Result<Vec<u8>, &'static str> {
    let rng = SystemRandom::new();
    let private = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).map_err(|_| "key generation failed")?;
    let as_public = private.compute_public_key().map_err(|_| "key generation failed")?.as_ref().to_vec();
    let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, ua_public);
    let secret = agreement::agree_ephemeral(private, &peer, |shared| shared.to_vec()).map_err(|_| "invalid subscriber key")?;
    let key_info = [b"WebPush: info\0".as_slice(), ua_public, &as_public].concat();
    let ikm = hkdf(auth, &secret, &key_info, 32);
    let salt = crate::util::random_bytes::<16>();
    let cek = hkdf(&salt, &ikm, b"Content-Encoding: aes128gcm\0", 16);
    let nonce = hkdf(&salt, &ikm, b"Content-Encoding: nonce\0", 12);
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &cek).map_err(|_| "bad key")?);
    // One record: the payload and the last-record delimiter.
    let mut record = [payload, &[2u8]].concat();
    key.seal_in_place_append_tag(aead::Nonce::try_assume_unique_for_key(&nonce).map_err(|_| "bad nonce")?, aead::Aad::empty(), &mut record).map_err(|_| "encryption failed")?;
    let mut out = Vec::with_capacity(86 + record.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    out.push(as_public.len() as u8);
    out.extend_from_slice(&as_public);
    out.extend_from_slice(&record);
    Ok(out)
}

/// The server's VAPID key, created on first use in `<data>/vapid.key`.
pub struct Vapid(EcdsaKeyPair);

impl Vapid {
    pub fn load(data_dir: &std::path::Path) -> anyhow::Result<Self> {
        let path = data_dir.join("vapid.key");
        let rng = SystemRandom::new();
        let pkcs8 = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let doc = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng).map_err(|_| anyhow::anyhow!("cannot create a VAPID key"))?;
                std::fs::write(&path, doc.as_ref())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                }
                doc.as_ref().to_vec()
            }
            Err(err) => return Err(err.into()),
        };
        let pair = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng).map_err(|_| anyhow::anyhow!("vapid.key is not a P-256 key"))?;
        Ok(Vapid(pair))
    }

    /// The application server key browsers subscribe with (uncompressed point, base64url).
    pub fn public_key(&self) -> String {
        b64url(self.0.public_key().as_ref())
    }

    /// `Authorization` header value for a push request to `endpoint`.
    pub fn authorization(&self, endpoint: &reqwest::Url, contact: &str) -> Option<String> {
        let audience = endpoint.origin().ascii_serialization();
        let header = b64url(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = b64url(json!({ "aud": audience, "exp": now() + 12 * 3600, "sub": contact }).to_string().as_bytes());
        let input = format!("{header}.{claims}");
        let signature = self.0.sign(&SystemRandom::new(), input.as_bytes()).ok()?;
        Some(format!("vapid t={input}.{}, k={}", b64url(signature.as_ref()), self.public_key()))
    }
}

fn vapid(app: &App) -> Option<&Vapid> {
    static VAPID: std::sync::OnceLock<Option<Vapid>> = std::sync::OnceLock::new();
    VAPID
        .get_or_init(|| {
            Vapid::load(&app.cfg.data_dir)
                .map_err(|err| tracing::warn!(%err, "web push is unavailable"))
                .ok()
        })
        .as_ref()
}

/// The VAPID public key for the session object.
pub fn application_server_key(app: &App) -> Option<String> {
    vapid(app).map(Vapid::public_key)
}

#[derive(sqlx::FromRow)]
struct Subscription {
    id: i64,
    account_id: i64,
    device_client_id: String,
    url: String,
    p256dh: String,
    auth: String,
    verification_code: String,
    verified: bool,
    expires: i64,
    types: String,
}

impl Subscription {
    fn view(&self) -> Value {
        let types: Value = serde_json::from_str(&self.types).unwrap_or(Value::Null);
        json!({
            "id": format!("p{}", self.id),
            "deviceClientId": self.device_client_id,
            "verificationCode": if self.verified { Value::String(self.verification_code.clone()) } else { Value::Null },
            "expires": crate::jmap::email::timestamp(self.expires),
            "types": types,
        })
    }
}

/// Sends one push message. A gone subscription (404, 410) is reported as `Ok(false)`.
async fn deliver(app: &App, subscription: &Subscription, payload: &Value) -> anyhow::Result<bool> {
    let url = reqwest::Url::parse(&subscription.url)?;
    let client = crate::outbound::to_public(app, &url, &[443], Duration::from_secs(15)).await.map_err(|e| anyhow::anyhow!("{e}"))?;
    let body = payload.to_string().into_bytes();
    let mut request = client.post(url.clone()).header("ttl", "86400").header("urgency", "normal");
    request = match (unb64url(&subscription.p256dh), unb64url(&subscription.auth)) {
        (Some(key), Some(auth)) if !subscription.p256dh.is_empty() => {
            let encrypted = encrypt(&key, &auth, &body).map_err(|e| anyhow::anyhow!(e))?;
            request.header("content-encoding", "aes128gcm").header("content-type", "application/octet-stream").body(encrypted)
        }
        _ => request.header("content-type", "application/json").body(body),
    };
    if let Some(authorization) = vapid(app).and_then(|v| v.authorization(&url, &format!("mailto:postmaster@{}", app.cfg.hostname))) {
        request = request.header("authorization", authorization);
    }
    let response = request.send().await?;
    match response.status().as_u16() {
        200..=299 => Ok(true),
        404 | 410 => Ok(false),
        status => anyhow::bail!("the push service answered {status}"),
    }
}

/// `PushSubscription/get` (no account: subscriptions belong to the user).
pub async fn get(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let rows: Vec<Subscription> = sqlx::query_as("SELECT * FROM push_subscriptions WHERE account_id = ? ORDER BY id").bind(ctx.account.id).fetch_all(&ctx.app.db).await?;
    let wanted: Option<Vec<String>> = args.get("ids").and_then(Value::as_array).map(|ids| ids.iter().filter_map(|i| i.as_str().map(str::to_owned)).collect());
    let mut list = Vec::new();
    let mut found = HashSet::new();
    for row in &rows {
        let id = format!("p{}", row.id);
        if wanted.as_ref().is_none_or(|w| w.contains(&id)) {
            found.insert(id);
            list.push(row.view());
        }
    }
    let not_found: Vec<String> = wanted.unwrap_or_default().into_iter().filter(|id| !found.contains(id)).collect();
    Ok(json!({ "list": list, "notFound": not_found }))
}

fn parse_expires(value: Option<&Value>) -> i64 {
    let requested = value.and_then(Value::as_str).and_then(|t| time::OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339).ok()).map(|t| t.unix_timestamp());
    requested.unwrap_or(i64::MAX).min(now() + MAX_LIFETIME).max(now() + 60)
}

fn parse_types(value: Option<&Value>) -> Result<String, MethodError> {
    match value {
        None | Some(Value::Null) => Ok("null".into()),
        Some(Value::Array(items)) if items.iter().all(|t| matches!(t.as_str(), Some("Email" | "Mailbox" | "Thread" | "EmailDelivery"))) => Ok(Value::Array(items.clone()).to_string()),
        _ => Err(MethodError("invalidArguments", "types must list Email, Mailbox, Thread or EmailDelivery".into())),
    }
}

/// `PushSubscription/set`: creating one sends a verification code to its URL.
pub async fn set(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let mut created = Map::new();
    let mut not_created = Map::new();
    let mut updated = Map::new();
    let mut not_updated = Map::new();
    let mut destroyed = Vec::new();
    let mut not_destroyed = Map::new();
    let invalid = |description: &str| json!({ "type": "invalidProperties", "description": description });

    for (creation_id, object) in args.get("create").and_then(Value::as_object).into_iter().flatten() {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM push_subscriptions WHERE account_id = ?").bind(ctx.account.id).fetch_one(&ctx.app.db).await?;
        if count >= MAX_SUBSCRIPTIONS {
            not_created.insert(creation_id.clone(), json!({ "type": "overQuota" }));
            continue;
        }
        let device = object["deviceClientId"].as_str().unwrap_or("").chars().take(200).collect::<String>();
        let url = object["url"].as_str().unwrap_or("");
        let parsed = reqwest::Url::parse(url).ok().filter(|u| u.scheme() == "https" || (ctx.app.cfg.allow_private_destinations && u.scheme() == "http"));
        if device.is_empty() || parsed.is_none() || url.len() > 2000 {
            not_created.insert(creation_id.clone(), invalid("deviceClientId and an https url are required"));
            continue;
        }
        let (p256dh, auth) = match &object["keys"] {
            Value::Null => (String::new(), String::new()),
            keys => match (keys["p256dh"].as_str(), keys["auth"].as_str()) {
                (Some(p), Some(a)) if unb64url(p).is_some_and(|k| k.len() == 65) && unb64url(a).is_some_and(|k| k.len() == 16) => (p.to_owned(), a.to_owned()),
                _ => {
                    not_created.insert(creation_id.clone(), invalid("keys must hold a P-256 p256dh key and a 16-byte auth secret"));
                    continue;
                }
            },
        };
        let types = match parse_types(object.get("types")) {
            Ok(types) => types,
            Err(MethodError(_, description)) => {
                not_created.insert(creation_id.clone(), invalid(&description));
                continue;
            }
        };
        let expires = parse_expires(object.get("expires"));
        let code = random_token();
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO push_subscriptions (account_id, device_client_id, url, p256dh, auth, verification_code, verified, expires, types, created_at)
             VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?) RETURNING id",
        )
        .bind(ctx.account.id)
        .bind(&device)
        .bind(url)
        .bind(&p256dh)
        .bind(&auth)
        .bind(&code)
        .bind(expires)
        .bind(&types)
        .bind(now())
        .fetch_one(&ctx.app.db)
        .await?;
        // The verification travels like any push message (RFC 8620 section 7.2.2).
        let app = ctx.app.clone();
        tokio::spawn(async move {
            if let Ok(Some(row)) = sqlx::query_as::<_, Subscription>("SELECT * FROM push_subscriptions WHERE id = ?").bind(id).fetch_optional(&app.db).await {
                let verification = json!({ "@type": "PushVerification", "pushSubscriptionId": format!("p{id}"), "verificationCode": row.verification_code });
                if let Err(err) = deliver(&app, &row, &verification).await {
                    tracing::info!(%err, "push verification could not be delivered");
                }
            }
        });
        ctx.created.insert(creation_id.clone(), format!("p{id}"));
        created.insert(creation_id.clone(), json!({ "id": format!("p{id}"), "keys": null, "expires": crate::jmap::email::timestamp(expires) }));
    }

    for (id, patch) in args.get("update").and_then(Value::as_object).into_iter().flatten() {
        let Some(row_id) = super::parse_id(&ctx.resolve_id(id), 'p') else {
            not_updated.insert(id.clone(), json!({ "type": "notFound" }));
            continue;
        };
        let row: Option<Subscription> = sqlx::query_as("SELECT * FROM push_subscriptions WHERE id = ? AND account_id = ?").bind(row_id).bind(ctx.account.id).fetch_optional(&ctx.app.db).await?;
        let Some(row) = row else {
            not_updated.insert(id.clone(), json!({ "type": "notFound" }));
            continue;
        };
        let mut changes = Map::new();
        if let Some(code) = patch.get("verificationCode") {
            if code.as_str() != Some(row.verification_code.as_str()) {
                not_updated.insert(id.clone(), invalid("wrong verification code"));
                continue;
            }
            sqlx::query("UPDATE push_subscriptions SET verified = 1 WHERE id = ?").bind(row.id).execute(&ctx.app.db).await?;
        }
        if patch.get("expires").is_some() {
            let expires = parse_expires(patch.get("expires"));
            sqlx::query("UPDATE push_subscriptions SET expires = ? WHERE id = ?").bind(expires).bind(row.id).execute(&ctx.app.db).await?;
            changes.insert("expires".into(), json!(crate::jmap::email::timestamp(expires)));
        }
        if patch.get("types").is_some() {
            match parse_types(patch.get("types")) {
                Ok(types) => {
                    sqlx::query("UPDATE push_subscriptions SET types = ? WHERE id = ?").bind(types).bind(row.id).execute(&ctx.app.db).await?;
                }
                Err(MethodError(_, description)) => {
                    not_updated.insert(id.clone(), invalid(&description));
                    continue;
                }
            }
        }
        updated.insert(id.clone(), if changes.is_empty() { Value::Null } else { Value::Object(changes) });
    }

    for id in args.get("destroy").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
        let removed = match super::parse_id(id, 'p') {
            Some(row_id) => sqlx::query("DELETE FROM push_subscriptions WHERE id = ? AND account_id = ?").bind(row_id).bind(ctx.account.id).execute(&ctx.app.db).await?.rows_affected() > 0,
            None => false,
        };
        if removed {
            destroyed.push(id.to_owned());
        } else {
            not_destroyed.insert(id.to_owned(), json!({ "type": "notFound" }));
        }
    }
    let null_if_empty = |map: Map<String, Value>| if map.is_empty() { Value::Null } else { Value::Object(map) };
    Ok(json!({
        "created": null_if_empty(created),
        "notCreated": null_if_empty(not_created),
        "updated": null_if_empty(updated),
        "notUpdated": null_if_empty(not_updated),
        "destroyed": if destroyed.is_empty() { Value::Null } else { json!(destroyed) },
        "notDestroyed": null_if_empty(not_destroyed),
    }))
}

/// Whether something arrived in the account in the last minute (the first change seen after
/// a restart has nothing to compare with).
async fn recently_delivered(app: &App, account: i64) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM messages WHERE account_id = ? AND mailbox_since >= ?").bind(account).bind(now() - 60).fetch_one(&app.db).await.unwrap_or(0) > 0
}

/// The `StateChange` object announcing an account's current state.
pub async fn state_change(app: &App, account: i64) -> Option<Value> {
    let state = app.store.account_state(account).await.ok()?.to_string();
    let id = account_id_of(account);
    Some(json!({ "@type": "StateChange", "changed": { id: { "Email": state, "Mailbox": state, "Thread": state } } }))
}

fn account_id_of(account: i64) -> String {
    format!("a{account}")
}

/// Pushes state changes to verified subscriptions, at most one message per account every
/// couple of seconds.
pub async fn run(app: AppState) {
    let mut changes = app.store.subscribe();
    // Newest message that arrived in each account's ordinary mailboxes, to tell deliveries
    // (EmailDelivery) from other changes.
    let mut newest: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
    loop {
        let mut accounts = HashSet::new();
        match changes.recv().await {
            Ok(change) => {
                accounts.insert(change.account_id);
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        }
        // Gather what else changes meanwhile.
        let deadline = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                change = changes.recv() => match change {
                    Ok(change) => { accounts.insert(change.account_id); }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                },
            }
        }
        let _ = sqlx::query("DELETE FROM push_subscriptions WHERE expires < ?").bind(now()).execute(&app.db).await;
        for account in accounts {
            let rows: Vec<Subscription> = sqlx::query_as("SELECT * FROM push_subscriptions WHERE account_id = ? AND verified = 1").bind(account).fetch_all(&app.db).await.unwrap_or_default();
            if rows.is_empty() {
                continue;
            }
            let Some(mut payload) = state_change(&app, account).await else { continue };
            let latest: Option<i64> = sqlx::query_scalar(
                "SELECT MAX(m.id) FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id WHERE m.account_id = ? AND COALESCE(b.role, '') NOT IN ('sent', 'drafts', 'trash', 'junk')",
            )
            .bind(account)
            .fetch_one(&app.db)
            .await
            .ok()
            .flatten();
            let latest = latest.unwrap_or(0);
            let previous = newest.insert(account, latest);
            let delivered = previous.is_some_and(|before| latest > before) || (previous.is_none() && latest > 0 && recently_delivered(&app, account).await);
            let id = account_id_of(account);
            if delivered {
                let state = payload["changed"][&id]["Email"].clone();
                payload["changed"][&id]["EmailDelivery"] = state;
            }
            for row in rows {
                let types: Option<Vec<String>> = serde_json::from_str(&row.types).ok().flatten();
                let wanted = |t: &str| types.as_ref().is_none_or(|types| types.iter().any(|x| x == t));
                if !(wanted("Email") || wanted("Mailbox") || wanted("Thread") || (delivered && wanted("EmailDelivery"))) {
                    continue;
                }
                let app = app.clone();
                let payload = payload.clone();
                tokio::spawn(async move {
                    match deliver(&app, &row, &payload).await {
                        Ok(true) => {}
                        Ok(false) => {
                            let _ = sqlx::query("DELETE FROM push_subscriptions WHERE id = ?").bind(row.id).execute(&app.db).await;
                        }
                        Err(err) => tracing::debug!(%err, account = row.account_id, "push not delivered"),
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_messages_decrypt_for_the_subscriber() {
        let rng = SystemRandom::new();
        let subscriber = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
        let ua_public = subscriber.compute_public_key().unwrap().as_ref().to_vec();
        let auth = [9u8; 16];
        let message = encrypt(&ua_public, &auth, b"{\"@type\":\"StateChange\"}").unwrap();

        // The subscriber's side (RFC 8291 section 3.4 and RFC 8188).
        let (salt, rest) = message.split_at(16);
        assert_eq!(u32::from_be_bytes(rest[..4].try_into().unwrap()), RECORD_SIZE);
        assert_eq!(rest[4], 65);
        let as_public = &rest[5..70];
        let ciphertext = &rest[70..];
        let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, as_public);
        let secret = agreement::agree_ephemeral(subscriber, &peer, |s| s.to_vec()).unwrap();
        let ikm = hkdf(&auth, &secret, &[b"WebPush: info\0".as_slice(), &ua_public, as_public].concat(), 32);
        let cek = hkdf(salt, &ikm, b"Content-Encoding: aes128gcm\0", 16);
        let nonce = hkdf(salt, &ikm, b"Content-Encoding: nonce\0", 12);
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &cek).unwrap());
        let mut buffer = ciphertext.to_vec();
        let plain = key.open_in_place(aead::Nonce::try_assume_unique_for_key(&nonce).unwrap(), aead::Aad::empty(), &mut buffer).unwrap();
        assert_eq!(plain, b"{\"@type\":\"StateChange\"}\x02");
    }

    #[test]
    fn vapid_tokens_verify() {
        let dir = tempfile::tempdir().unwrap();
        let vapid = Vapid::load(dir.path()).unwrap();
        assert_eq!(Vapid::load(dir.path()).unwrap().public_key(), vapid.public_key(), "the key is kept");
        let url = reqwest::Url::parse("https://push.example.net/send/abc").unwrap();
        let header = vapid.authorization(&url, "mailto:postmaster@example.org").unwrap();
        let token = header.strip_prefix("vapid t=").unwrap().split(", k=").next().unwrap();
        let (signed, signature) = token.rsplit_once('.').unwrap();
        let claims: Value = serde_json::from_slice(&unb64url(signed.split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert_eq!(claims["aud"], "https://push.example.net");
        let public = unb64url(&vapid.public_key()).unwrap();
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, public).verify(signed.as_bytes(), &unb64url(signature).unwrap()).unwrap();
    }
}
