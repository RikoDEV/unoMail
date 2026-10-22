//! Persistent outbound delivery queue with retry backoff and bounce generation.

use std::time::Duration;

use crate::{
    app::{App, AppState, Metrics},
    db::{DeliveryEvent, Direction, log_delivery},
    smtp::{
        client::{self, SendError},
        delivery::{self, LocalDelivery, Resolution, Target},
        dsn::{self, Action, Dsn},
    },
    util::{Address, now, sanitize_line},
};

const BACKOFF_SECS: [i64; 8] = [60, 300, 900, 1800, 3600, 7200, 14400, 21600];
/// A sender who asked to hear about delays (`NOTIFY=DELAY`) is told once, after this long.
const DELAY_NOTICE_SECS: i64 = 4 * 3600;

pub fn backoff(attempts: i64) -> i64 {
    BACKOFF_SECS[(attempts.max(1) - 1).min(BACKOFF_SECS.len() as i64 - 1) as usize]
}

/// How many attempts the backoff schedule fits between queuing and expiry (ignoring the time
/// each attempt takes): retries stop once a failure happens after `expires_at`.
pub fn max_attempts(created_at: i64, expires_at: i64) -> i64 {
    let (mut attempts, mut at) = (1, created_at);
    while at < expires_at {
        at += backoff(attempts);
        attempts += 1;
    }
    attempts
}

#[derive(Debug, sqlx::FromRow)]
struct Entry {
    id: i64,
    sender: String,
    recipient: String,
    blob_hash: String,
    size: i64,
    attempts: i64,
    expires_at: i64,
    created_at: i64,
    relay_identity_id: Option<i64>,
    dsn_notify: Option<String>,
    dsn_ret: Option<String>,
    dsn_envid: Option<String>,
    dsn_orcpt: Option<String>,
    delay_notified: i64,
    require_tls: i64,
}

impl Entry {
    fn dsn(&self) -> Dsn {
        Dsn { notify: self.dsn_notify.clone(), ret: self.dsn_ret.clone(), envid: self.dsn_envid.clone(), orcpt: self.dsn_orcpt.clone(), require_tls: self.require_tls != 0 }
    }
}

/// Builds a delivery status notification (RFC 3464) for a failed recipient.
pub fn build_bounce(hostname: &str, original_sender: &str, failed_recipient: &str, reason: &str, original: &[u8]) -> Vec<u8> {
    dsn::build(hostname, original_sender, failed_recipient, Action::Failed, reason, original, &Dsn::default())
}

/// Notifies `original_sender` that delivery to `failed_recipient` failed, unless the sender
/// asked not to be told (`NOTIFY=NEVER`). Messages with a null sender are never bounced,
/// which prevents bounce loops.
pub async fn bounce(app: &App, original_sender: &str, failed_recipient: &str, reason: &str, original: &[u8]) {
    let request = dsn::current(failed_recipient);
    bounce_with(app, original_sender, failed_recipient, reason, original, &request).await;
}

async fn bounce_with(app: &App, original_sender: &str, failed_recipient: &str, reason: &str, original: &[u8], request: &Dsn) {
    Metrics::inc(&app.metrics.messages_bounced);
    crate::webhooks::emit(app, "message.bounced", serde_json::json!({ "sender": original_sender, "recipient": failed_recipient, "reason": sanitize_line(reason) }));
    if request.wants_failure() {
        notify(app, original_sender, failed_recipient, Action::Failed, reason, original, request).await;
    }
}

/// Sends a delivery status notification about `recipient` to `original_sender`.
pub async fn notify(app: &App, original_sender: &str, recipient: &str, action: Action, reason: &str, original: &[u8], request: &Dsn) {
    let Some(sender) = Address::parse(original_sender) else { return };
    let report = dsn::build(&app.cfg.hostname, original_sender, recipient, action, reason, original, request);

    let result = async {
        let targets = match delivery::resolve(app, &sender).await? {
            Resolution::Deliver(targets) => targets,
            Resolution::NotLocal => vec![Target::Remote(sender.clone())],
            Resolution::NoSuchUser => Vec::new(),
        };
        let mut blob = None;
        for target in targets {
            match target {
                Target::Trap => {}
                // A report about a list's copy: the list counts it against the member.
                Target::List { list_id, role } => {
                    if let Err(err) = crate::lists::receive(app, list_id, role, crate::lists::Sender { envelope: "", envelope_verified: false, author_verified: false }, &report, false).await {
                        tracing::warn!(error = ?err, "list could not process a delivery report");
                    }
                }
                Target::Local { account_id, address } => {
                    let delivery = LocalDelivery {
                        account_id,
                        recipient: &address,
                        sender: "",
                        raw: &report,
                        junk: false,
                        remote: "",
                        direction: Direction::Local,
                        author_verified: false,
                        sender_verified: false,
                    };
                    if let Err(err) = delivery::deliver_local(app, delivery).await {
                        tracing::warn!(%err, recipient = address, "could not deliver a delivery notification");
                    }
                }
                Target::Remote(remote) => {
                    let hash = match &blob {
                        Some(h) => String::clone(h),
                        None => app.store.put_blob(&report).await?,
                    };
                    blob = Some(hash.clone());
                    delivery::enqueue(app, "", &remote, &hash, report.len(), None).await?;
                }
            }
        }
        anyhow::Ok(())
    }
    .await;
    if let Err(err) = result {
        tracing::error!(error = ?err, "failed to generate a delivery notification");
    }
}

async fn attempt(app: &App, entry: Entry) {
    let event = |status: &'static str, detail: &str| {
        let detail = detail.to_owned();
        let (sender, recipient, size) = (entry.sender.clone(), entry.recipient.clone(), entry.size);
        async move {
            log_delivery(
                &app.db,
                DeliveryEvent {
                    direction: Direction::Outbound,
                    sender: &sender,
                    recipient: &recipient,
                    status,
                    detail: &detail,
                    remote: "",
                    message_id: "",
                    size,
                },
            )
            .await;
        }
    };
    let remove = || async {
        if let Err(err) = sqlx::query("DELETE FROM queue WHERE id = ?").bind(entry.id).execute(&app.db).await {
            tracing::error!(%err, id = entry.id, "failed to remove queue entry");
        }
    };

    let raw = match app.store.read_blob(&entry.blob_hash).await {
        Ok(raw) => raw,
        Err(err) => {
            tracing::error!(%err, id = entry.id, "queued message content is missing, dropping entry");
            event("bounced", "message content missing").await;
            remove().await;
            return;
        }
    };
    let domain = entry.recipient.rsplit_once('@').map_or("", |(_, domain)| domain).to_owned();
    let span = tracing::info_span!("smtp.deliver", smtp.recipient_domain = %domain, smtp.attempt = entry.attempts + 1, smtp.outcome = tracing::field::Empty);
    let started = std::time::Instant::now();
    let request = entry.dsn();
    // Notifications are never asked of, or about, notifications themselves.
    let request = if entry.sender.is_empty() { Dsn { require_tls: request.require_tls, ..Dsn::default() } } else { request };
    let outcome = tracing::Instrument::instrument(async { match (Address::parse(&entry.recipient), entry.relay_identity_id) {
        (None, _) => Err(SendError::Permanent("invalid recipient address".into())),
        (Some(recipient), None) => client::deliver_with(app, &entry.sender, &recipient, &raw, Some(&request)).await,
        (Some(recipient), Some(identity)) => match client::Relay::load(app, identity).await {
            Ok(Some(relay)) => client::deliver_via_with(app, &relay, &entry.sender, &recipient, &raw, Some(&request)).await,
            // The identity was removed (or its password can no longer be read) after queueing.
            Ok(None) => Err(SendError::Permanent("the SMTP server of the sending identity is no longer configured".into())),
            Err(err) => Err(SendError::Temporary(format!("identity lookup failed: {err}"))),
        },
    } }, span.clone())
    .await;
    app.metrics.delivery_duration.observe(started.elapsed());
    span.record("smtp.outcome", match &outcome {
        Ok(_) => "delivered",
        Err(SendError::Temporary(_)) => "deferred",
        Err(SendError::Permanent(_)) => "failed",
    });

    match outcome {
        Ok((reply, passed_on)) => {
            Metrics::inc(&app.metrics.messages_sent);
            event("delivered", &reply).await;
            // A receiver that took the DSN request reports delivery itself; otherwise we say
            // how far the message got.
            if request.wants_success() && !passed_on {
                notify(app, &entry.sender, &entry.recipient, Action::Relayed, &reply, &raw, &request).await;
            }
            remove().await;
        }
        Err(SendError::Temporary(reason)) if now() < entry.expires_at => {
            let attempts = entry.attempts + 1;
            Metrics::inc(&app.metrics.deliveries_deferred);
            event("deferred", &reason).await;
            if request.wants_delay() && entry.delay_notified == 0 && now() - entry.created_at >= DELAY_NOTICE_SECS {
                notify(app, &entry.sender, &entry.recipient, Action::Delayed, &reason, &raw, &request).await;
                let _ = sqlx::query("UPDATE queue SET delay_notified = 1 WHERE id = ?").bind(entry.id).execute(&app.db).await;
            }
            let res = sqlx::query("UPDATE queue SET status = 'queued', attempts = ?, next_attempt_at = ?, last_error = ? WHERE id = ?")
                .bind(attempts)
                .bind(now() + backoff(attempts))
                .bind(sanitize_line(&reason))
                .bind(entry.id)
                .execute(&app.db)
                .await;
            if let Err(err) = res {
                tracing::error!(%err, id = entry.id, "failed to reschedule queue entry");
            }
        }
        Err(err) => {
            let reason = match &err {
                SendError::Temporary(m) => format!("delivery timed out after repeated attempts; last error: {m}"),
                SendError::Permanent(m) => m.clone(),
            };
            event("bounced", &reason).await;
            bounce_with(app, &entry.sender, &entry.recipient, &reason, &raw, &request).await;
            remove().await;
        }
    }
}

/// Deliveries under way at once, in all and per receiving domain. A slow or unresponsive
/// server ties up only its own domain's share; everything else keeps moving.
pub const MAX_PARALLEL: usize = 20;
pub const MAX_PARALLEL_PER_DOMAIN: i64 = 4;

/// Claims up to `limit` due entries for delivery, respecting the per-domain share (entries
/// already being delivered count against it).
pub async fn claim(app: &App, limit: usize) -> sqlx::Result<Vec<i64>> {
    claim_entries(app, limit).await.map(|entries| entries.into_iter().map(|e| e.id).collect())
}

async fn claim_entries(app: &App, limit: usize) -> sqlx::Result<Vec<Entry>> {
    sqlx::query_as(
        "WITH busy AS (SELECT recipient_domain, COUNT(*) AS n FROM queue WHERE status = 'sending' GROUP BY recipient_domain),
              due AS (SELECT q.id, q.next_attempt_at,
                             ROW_NUMBER() OVER (PARTITION BY q.recipient_domain ORDER BY q.next_attempt_at, q.id) + COALESCE(b.n, 0) AS slot
                      FROM queue q LEFT JOIN busy b ON b.recipient_domain = q.recipient_domain
                      WHERE q.status = 'queued' AND q.next_attempt_at <= ?1)
         UPDATE queue SET status = 'sending' WHERE id IN (SELECT id FROM due WHERE slot <= ?2 ORDER BY next_attempt_at, id LIMIT ?3)
         RETURNING id, sender, recipient, blob_hash, size, attempts, expires_at, created_at, relay_identity_id, dsn_notify, dsn_ret, dsn_envid, dsn_orcpt, delay_notified, require_tls",
    )
    .bind(now())
    .bind(MAX_PARALLEL_PER_DOMAIN)
    .bind(limit as i64)
    .fetch_all(&app.db)
    .await
}

/// Attempts delivery of every due entry once and waits for the outcome (the worker does the
/// same without waiting; this form is for maintenance and tests). Returns the number of
/// entries processed.
pub async fn process_due(app: &App) -> usize {
    let mut processed = 0;
    loop {
        let entries = match claim_entries(app, MAX_PARALLEL).await {
            Ok(entries) => entries,
            Err(err) => {
                tracing::error!(%err, "failed to read the delivery queue");
                return processed;
            }
        };
        if entries.is_empty() {
            return processed;
        }
        processed += entries.len();
        futures_util::future::join_all(entries.into_iter().map(|entry| attempt(app, entry))).await;
    }
}

/// Queue worker: runs until the process exits. Each delivery starts as soon as a slot is free,
/// so one slow delivery never holds up the ones behind it.
pub async fn run(app: AppState) {
    // Entries left in `sending` belong to a previous process that died mid-delivery.
    if let Err(err) = sqlx::query("UPDATE queue SET status = 'queued' WHERE status = 'sending'").execute(&app.db).await {
        tracing::error!(%err, "failed to recover the delivery queue");
    }
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_PARALLEL));
    loop {
        let free = slots.available_permits();
        let entries = if free == 0 {
            Vec::new()
        } else {
            claim_entries(&app, free).await.unwrap_or_else(|err| {
                tracing::error!(%err, "failed to read the delivery queue");
                Vec::new()
            })
        };
        let claimed = entries.len();
        for entry in entries {
            let Ok(permit) = slots.clone().acquire_owned().await else { return };
            let app = app.clone();
            tokio::spawn(async move {
                attempt(&app, entry).await;
                drop(permit);
                // A slot (and perhaps a domain's share) is free: look for more work.
                app.queue_wake.notify_one();
            });
        }
        // Every free slot was filled: there may be more due right away.
        if claimed > 0 && claimed == free {
            continue;
        }
        tokio::select! {
            _ = app.queue_wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(30)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_saturates() {
        assert_eq!(backoff(0), 60);
        assert_eq!(backoff(1), 60);
        assert_eq!(backoff(2), 300);
        assert_eq!(backoff(8), 21600);
        assert_eq!(backoff(1000), 21600);
    }

    #[test]
    fn bounce_contains_status_and_original_headers_only() {
        let original = b"From: a@example.org\r\nSubject: Secret plans\r\n\r\nconfidential body\r\n";
        let dsn = String::from_utf8(build_bounce(
            "mail.example.org",
            "a@example.org",
            "b@example.net",
            "550 5.1.1 User\r\nInjected: header",
            original,
        ))
        .unwrap();
        assert!(dsn.starts_with("From: Mail Delivery System <MAILER-DAEMON@mail.example.org>\r\nTo: <a@example.org>\r\n"));
        assert!(dsn.contains("Final-Recipient: rfc822; b@example.net\r\nAction: failed\r\nStatus: 5.0.0\r\n"));
        assert!(dsn.contains("Subject: Secret plans"));
        assert!(!dsn.contains("confidential body"), "the original body is not disclosed in bounces");
        assert!(!dsn.contains("\r\nInjected: header"), "the remote reply cannot inject headers");
        assert!(mail_parser::MessageParser::default().parse(dsn.as_bytes()).is_some());
    }
}
