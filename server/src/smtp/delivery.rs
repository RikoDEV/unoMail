//! Recipient resolution (accounts, aliases, catch-all, SRS), local delivery and queueing.

use std::{collections::HashSet, net::IpAddr};

use time::format_description::well_known::Rfc2822;

use crate::{
    app::{App, Metrics},
    db::{DeliveryEvent, Direction, log_delivery},
    smtp::srs,
    store::{Flags, StoreError},
    util::{Address, now, sha256_hex},
};

const MAX_ALIAS_DEPTH: usize = 5;
const MAX_ALIAS_TARGETS: usize = 100;
const GREYLIST_PASS_TTL_SECS: i64 = 35 * 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Target {
    Local { account_id: i64, address: String },
    Remote(Address),
    /// A mailing list, or one of its `-request`, `-owner` and `-bounces` addresses.
    List { list_id: i64, role: crate::lists::Role },
}

#[derive(Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Deliver to these targets. `forwarded` is set when remote targets come from an alias, in
    /// which case the envelope sender must be SRS-rewritten.
    Deliver(Vec<Target>),
    /// The domain is ours but nothing accepts mail for this address.
    NoSuchUser,
    /// Not one of our domains.
    NotLocal,
}

pub fn rfc2822_now() -> String {
    time::OffsetDateTime::now_utc().format(&Rfc2822).unwrap_or_default()
}

pub async fn is_local_domain(app: &App, domain: &str) -> sqlx::Result<bool> {
    Ok(sqlx::query_scalar::<_, i64>("SELECT 1 FROM domains WHERE name = ? AND enabled = 1")
        .bind(domain)
        .fetch_optional(&app.db)
        .await?
        .is_some())
}

async fn alias_destinations(app: &App, source: &str) -> sqlx::Result<Option<Vec<String>>> {
    let json: Option<String> = sqlx::query_scalar("SELECT destinations FROM aliases WHERE source = ? AND enabled = 1")
        .bind(source)
        .fetch_optional(&app.db)
        .await?;
    Ok(json.map(|j| serde_json::from_str(&j).unwrap_or_default()))
}

async fn account_id(app: &App, email: &str) -> sqlx::Result<Option<i64>> {
    sqlx::query_scalar("SELECT id FROM accounts WHERE email = ? AND enabled = 1").bind(email).fetch_optional(&app.db).await
}

/// Resolves an envelope recipient to its final delivery targets.
pub async fn resolve(app: &App, recipient: &Address) -> sqlx::Result<Resolution> {
    if !is_local_domain(app, &recipient.domain).await? {
        return Ok(Resolution::NotLocal);
    }
    // Bounces for mail we forwarded come back to an SRS address; route them to the original sender.
    if srs::is_srs(&recipient.local) {
        let secret = crate::db::get_or_create_secret(&app.db, "srs.secret").await?;
        return Ok(match srs::reverse(&secret, &recipient.local) {
            Some(original) => Resolution::Deliver(vec![Target::Remote(original)]),
            None => Resolution::NoSuchUser,
        });
    }

    let mut targets: Vec<Target> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut pending: Vec<(Address, usize)> = vec![(recipient.clone(), 0)];
    while let Some((addr, depth)) = pending.pop() {
        if targets.len() >= MAX_ALIAS_TARGETS || !seen.insert(addr.to_string()) {
            continue;
        }
        if !is_local_domain(app, &addr.domain).await? {
            targets.push(Target::Remote(addr));
            continue;
        }
        if let Some(list) = crate::lists::target(app, &addr).await? {
            targets.push(list);
            continue;
        }
        // Exact match first, then the address with its +tag removed, then the catch-all.
        let plain = addr.without_tag();
        let mut destinations = None;
        let mut account = None;
        for candidate in [addr.to_string(), plain.to_string()] {
            if let Some(d) = alias_destinations(app, &candidate).await? {
                destinations = Some(d);
                break;
            }
            if let Some(id) = account_id(app, &candidate).await? {
                account = Some((id, candidate));
                break;
            }
        }
        if let Some((account_id, address)) = account {
            targets.push(Target::Local { account_id, address });
            continue;
        }
        if destinations.is_none() {
            let catch_all: Option<String> =
                sqlx::query_scalar("SELECT catch_all FROM domains WHERE name = ? AND enabled = 1 AND catch_all IS NOT NULL")
                    .bind(&addr.domain)
                    .fetch_optional(&app.db)
                    .await?;
            destinations = catch_all.filter(|c| *c != addr.to_string()).map(|c| vec![c]);
        }
        if let Some(destinations) = destinations
            && depth < MAX_ALIAS_DEPTH
        {
            pending.extend(destinations.iter().filter_map(|d| Address::parse(d)).map(|d| (d, depth + 1)));
        }
    }
    targets.dedup();
    Ok(if targets.is_empty() { Resolution::NoSuchUser } else { Resolution::Deliver(targets) })
}

/// Greylisting: the first delivery attempt for an unknown (network, sender, recipient) triplet
/// is deferred. Returns true when the message may proceed.
pub async fn greylist_pass(app: &App, ip: IpAddr, sender: &str, recipient: &str) -> sqlx::Result<bool> {
    let network = match ip {
        IpAddr::V4(v4) => format!("{}.{}.{}", v4.octets()[0], v4.octets()[1], v4.octets()[2]),
        IpAddr::V6(v6) => v6.segments()[..4].iter().map(|s| format!("{s:x}")).collect::<Vec<_>>().join(":"),
    };
    let key = sha256_hex(format!("{network}\0{sender}\0{recipient}").as_bytes());
    let now = now();
    let row: Option<(i64, bool)> =
        sqlx::query_as("SELECT first_seen, passed FROM greylist WHERE key = ?").bind(&key).fetch_optional(&app.db).await?;
    match row {
        Some((first_seen, passed)) if passed || now - first_seen >= app.rt().greylist_delay_secs => {
            sqlx::query("UPDATE greylist SET passed = 1, last_seen = ? WHERE key = ?").bind(now).bind(&key).execute(&app.db).await?;
            Ok(true)
        }
        Some(_) => Ok(false),
        None => {
            sqlx::query("INSERT OR IGNORE INTO greylist (key, first_seen, last_seen) VALUES (?, ?, ?)")
                .bind(&key)
                .bind(now)
                .bind(now)
                .execute(&app.db)
                .await?;
            Ok(false)
        }
    }
}

pub async fn prune_greylist(app: &App) {
    let now = now();
    let _ = sqlx::query("DELETE FROM greylist WHERE (passed = 0 AND first_seen < ?) OR last_seen < ?")
        .bind(now - 24 * 3600)
        .bind(now - GREYLIST_PASS_TTL_SECS)
        .execute(&app.db)
        .await;
}

pub struct LocalDelivery<'a> {
    pub account_id: i64,
    pub recipient: &'a str,
    pub sender: &'a str,
    pub raw: &'a [u8],
    pub junk: bool,
    pub remote: &'a str,
    pub direction: Direction,
    /// The From address is known to be genuine (DMARC passed, a user of this server sent it,
    /// or a trusted relay handed it over). Only then may the message change things by itself,
    /// such as calendar entries.
    pub author_verified: bool,
}

/// Converts Sieve/IMAP flag names into system flags and keywords.
fn split_flags(names: &[String]) -> (Flags, Vec<String>) {
    let mut flags = Flags::default();
    let mut keywords = Vec::new();
    for name in names {
        match name.to_ascii_lowercase().as_str() {
            "\\seen" => flags.seen = true,
            "\\answered" => flags.answered = true,
            "\\flagged" => flags.flagged = true,
            "\\draft" => flags.draft = true,
            "\\deleted" => flags.deleted = true,
            other if !other.starts_with('\\') && other.len() <= 100 && other.bytes().all(|b| b.is_ascii_graphic() && !b"(){]%*\"\\".contains(&b))
                && !keywords.iter().any(|k| k == other) => {
                    keywords.push(other.to_owned());
                }
            _ => {}
        }
    }
    (flags, keywords)
}

/// True when the message's header block has a `Delivered-To` field for `address`.
fn has_delivered_to(raw: &[u8], address: &str) -> bool {
    let headers = &raw[..crate::security::authn::find_header_end(raw)];
    headers.split(|b| *b == b'\n').any(|line| {
        let line = String::from_utf8_lossy(line);
        line.split_once(':').is_some_and(|(name, value)| name.eq_ignore_ascii_case("delivered-to") && value.trim().trim_matches(['<', '>']).eq_ignore_ascii_case(address))
    })
}

/// Delivers a message to a local account, applying the account's Sieve script: by default
/// into the INBOX (or Junk when the message was classified as spam).
pub async fn deliver_local(app: &App, d: LocalDelivery<'_>) -> Result<(), StoreError> {
    let mut message = Vec::with_capacity(d.raw.len() + 128);
    message.extend_from_slice(format!("Return-Path: <{}>\r\nDelivered-To: {}\r\n", d.sender, d.recipient).as_bytes());
    message.extend_from_slice(d.raw);
    // Correspondents who sign with S/MIME can be written to encrypted.
    if !d.sender.is_empty() {
        crate::smime::collect(app, d.account_id, d.raw).await;
    }
    // Stored encrypted to the owner's OpenPGP key, when they asked for that.
    let message = crate::openpgp::protect(app, d.account_id, message).await;

    let outcome = match crate::sieve::active_script(app, d.account_id).await {
        Some(script) => script.evaluate(&crate::sieve::Envelope { from: d.sender, to: d.recipient, raw: d.raw }),
        None => crate::sieve::Outcome { keep: Some(Vec::new()), ..Default::default() },
    };
    // Mail from a sender the user blocked is accepted like any other (the sender learns
    // nothing) but treated as junk. Both the visible author and the envelope sender count.
    let author = crate::store::parse_metadata(d.raw).from_addr;
    let blocked = crate::api::mailtools::is_blocked(&app.db, d.account_id, &author).await? || crate::api::mailtools::is_blocked(&app.db, d.account_id, d.sender).await?;
    // The recipient's own filter, trained by their spam reports. Mail from people they write
    // to is never filed away by it, and teaches it what they want.
    let personal = if d.junk || blocked || !matches!(d.direction, Direction::Inbound) { crate::bayes::Verdict::Undecided } else { crate::bayes::judge(app, d.account_id, &author, d.raw).await };
    if personal == crate::bayes::Verdict::Correspondent
        && app.rt().personal_spam_filter
        && let Err(err) = crate::bayes::learn(&app.db, d.account_id, d.raw, false).await
    {
        tracing::warn!(error = %err, "personal spam filter training failed");
    }
    let filtered = matches!(personal, crate::bayes::Verdict::Spam(_));
    let junk = d.junk || blocked || filtered;
    let default_role = if junk { "junk" } else { "inbox" };
    let default_mailbox = app.store.mailbox_by_role(d.account_id, default_role).await?.ok_or(StoreError::NotFound)?;

    // (mailbox id, flag names); a spam verdict always wins over the user's filing rules.
    let mut targets: Vec<(i64, Vec<String>)> = Vec::new();
    if let Some(flags) = &outcome.keep {
        targets.push((default_mailbox.id, flags.clone()));
    }
    for (name, create, flags) in &outcome.fileinto {
        let mailbox = if junk {
            default_mailbox.id
        } else {
            match app.store.mailbox_by_name(d.account_id, name).await? {
                Some(mailbox) => mailbox.id,
                None if *create => app.store.create_mailbox(d.account_id, name).await.map_or(default_mailbox.id, |m| m.id),
                // RFC 5228: a missing mailbox must not lose the message.
                None => default_mailbox.id,
            }
        };
        if !targets.iter().any(|(id, _)| *id == mailbox) {
            targets.push((mailbox, flags.clone()));
        }
    }

    // Sort legitimate mail into its inbox category (stored as a keyword), as the user taught.
    if !junk && let Some(keyword) = crate::categories::categorize(&app.db, d.account_id, d.raw).await.keyword() {
        for (_, flags) in &mut targets {
            flags.push(keyword.to_owned());
        }
    }

    let mut result: Result<(), StoreError> = Ok(());
    for (mailbox, flag_names) in &targets {
        let (flags, keywords) = split_flags(flag_names);
        match app.store.append_with(d.account_id, *mailbox, &message, flags, None, &keywords).await {
            Ok(_) => {}
            Err(err) => {
                result = Err(err);
                break;
            }
        }
    }

    // Redirects leave through the queue with an SRS sender, like alias forwards. Spam is
    // never forwarded on the user's behalf.
    let mut redirected = 0;
    if result.is_ok() && !junk && !outcome.redirect.is_empty() {
        let domain = d.recipient.rsplit_once('@').map_or("", |(_, domain)| domain);
        let queued: anyhow::Result<()> = async {
            // A message that passed through this mailbox before is not sent on again: two
            // filters redirecting to each other (or to themselves) would otherwise loop, each
            // pass multiplying the copies.
            if has_delivered_to(d.raw, d.recipient) {
                tracing::warn!(recipient = d.recipient, "Sieve redirect skipped: the message was delivered here before (mail loop)");
                return Ok(());
            }
            let mut destinations: Vec<Address> = Vec::new();
            for address in &outcome.redirect {
                let Some(target) = Address::parse(address) else { continue };
                // A redirect back to the same mailbox (under any of its addresses) would loop.
                let same_mailbox = match resolve(app, &target).await? {
                    Resolution::Deliver(list) => list.iter().any(|t| matches!(t, Target::Local { account_id, .. } if *account_id == d.account_id)),
                    _ => false,
                };
                if !same_mailbox && !destinations.contains(&target) {
                    destinations.push(target);
                }
            }
            if destinations.is_empty() {
                return Ok(());
            }
            // Mail sent on by a filter is mail the user sends: it counts against their limits.
            let Some(account) = crate::auth::Account::by_id(&app.db, d.account_id).await? else { return Ok(()) };
            if crate::security::outbound::register_submission(app, &account, destinations.len()).await?.is_err() {
                tracing::warn!(recipient = d.recipient, "Sieve redirect refused: the account is over its sending limit or blocked");
                return Ok(());
            }
            let copy = [format!("Delivered-To: {}\r\n", d.recipient).as_bytes(), d.raw].concat();
            let hash = app.store.put_blob(&copy).await?;
            let sender = forwarding_sender(app, d.sender, domain).await?;
            for target in &destinations {
                enqueue(app, &sender, target, &hash, copy.len(), Some(d.account_id)).await?;
                redirected += 1;
            }
            Ok(())
        }
        .await;
        if let Err(err) = queued {
            tracing::error!(error = ?err, recipient = d.recipient, "failed to queue Sieve redirect");
        }
    }

    let (status, detail) = match &result {
        Err(err) => ("rejected", err.to_string()),
        Ok(()) if targets.is_empty() && redirected == 0 => ("discarded", "discarded by the mailbox filter".to_owned()),
        Ok(()) if targets.is_empty() => ("delivered", format!("redirected to {redirected} address(es) by the mailbox filter")),
        Ok(()) => (
            if junk { "junk" } else { "delivered" },
            match &personal {
                _ if blocked => "sender blocked by the recipient".to_owned(),
                crate::bayes::Verdict::Spam(score) => format!("filed as spam by the recipient's filter (score {score:.2})"),
                _ => String::new(),
            },
        ),
    };
    if result.is_ok() {
        Metrics::inc(&app.metrics.messages_delivered_local);
        // Answers to invitations and cancellations update the calendar by themselves.
        if !junk && d.author_verified {
            crate::calendar::scheduling::process_incoming(app, d.account_id, &author, d.raw).await;
        }
        crate::webhooks::emit(
            app,
            "message.received",
            serde_json::json!({ "sender": d.sender, "recipient": d.recipient, "size": message.len(), "junk": junk, "status": status }),
        );
        // Out-of-office replies are never sent for junk, discarded mail or mail without a return path.
        if !junk && !d.sender.is_empty() && !targets.is_empty() {
            crate::vacation::maybe_reply(app, d.account_id, d.recipient, d.sender, d.raw).await;
            if let Some(action) = &outcome.vacation {
                crate::vacation::reply_from_sieve(app, d.account_id, d.recipient, d.sender, d.raw, action).await;
            }
        }
    }
    log_delivery(
        &app.db,
        DeliveryEvent {
            direction: d.direction,
            sender: d.sender,
            recipient: d.recipient,
            status,
            detail: &detail,
            remote: d.remote,
            message_id: &crate::store::parse_metadata(d.raw).message_id,
            size: message.len() as i64,
        },
    )
    .await;
    result
}

/// Queues a message for delivery to a remote recipient.
pub async fn enqueue(app: &App, sender: &str, recipient: &Address, blob_hash: &str, size: usize, account_id: Option<i64>) -> sqlx::Result<i64> {
    enqueue_via(app, sender, recipient, blob_hash, size, account_id, None).await
}

/// Queues a message, optionally for relaying through the SMTP server of a sender identity.
pub async fn enqueue_via(
    app: &App,
    sender: &str,
    recipient: &Address,
    blob_hash: &str,
    size: usize,
    account_id: Option<i64>,
    relay_identity: Option<i64>,
) -> sqlx::Result<i64> {
    let now = now();
    // Within an SMTP transaction: what its sender asked to be notified about.
    let dsn = if sender.is_empty() { crate::smtp::dsn::Dsn::default() } else { crate::smtp::dsn::current(&recipient.to_string()) };
    let id = sqlx::query(
        "INSERT INTO queue (sender, recipient, recipient_domain, blob_hash, size, account_id, next_attempt_at, created_at, expires_at, relay_identity_id, dsn_notify, dsn_ret, dsn_envid, dsn_orcpt)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(sender)
    .bind(recipient.to_string())
    .bind(&recipient.domain)
    .bind(blob_hash)
    .bind(size as i64)
    .bind(account_id)
    .bind(now)
    .bind(now)
    .bind(now + app.cfg.queue_max_age_secs)
    .bind(relay_identity)
    .bind(dsn.notify)
    .bind(dsn.ret)
    .bind(dsn.envid)
    .bind(dsn.orcpt)
    .execute(&app.db)
    .await?
    .last_insert_rowid();
    app.queue_wake.notify_one();
    Ok(id)
}

/// The envelope sender to use when forwarding mail from `sender` on behalf of `forwarder_domain`.
pub async fn forwarding_sender(app: &App, sender: &str, forwarder_domain: &str) -> sqlx::Result<String> {
    let Some(address) = Address::parse(sender) else { return Ok(String::new()) };
    let secret = crate::db::get_or_create_secret(&app.db, "srs.secret").await?;
    // If the address cannot be rewritten, forward with a null sender rather than break SPF.
    Ok(srs::forward(&secret, &address, forwarder_domain).unwrap_or_default())
}
