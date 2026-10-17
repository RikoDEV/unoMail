//! Message acceptance pipelines: inbound mail from other servers, and submissions from
//! authenticated users (SMTP submission and the web client share the same path).

use std::net::IpAddr;

use mail_parser::MessageParser;

use crate::{
    app::{App, Metrics},
    auth::Account,
    db::{DeliveryEvent, Direction, log_delivery},
    security::{
        attachments,
        authn::{self, Disposition},
        clamav::{self, Verdict},
        dkim, outbound,
        reputation::is_trusted_source,
        rspamd::{self, Action, ScanRequest},
    },
    smtp::{
        delivery::{self, LocalDelivery, Resolution, Target, rfc2822_now},
        queue,
    },
    store::StoreError,
    util::{Address, random_token, sanitize_line},
};

const MAX_RECEIVED_HEADERS: usize = 50;

/// Result of handing a message to the server. The strings are complete SMTP reply lines.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Accepted(String),
    Deferred(String),
    Rejected(String),
}

impl Outcome {
    pub fn reply(&self) -> &str {
        match self {
            Outcome::Accepted(s) | Outcome::Deferred(s) | Outcome::Rejected(s) => s,
        }
    }
}

fn internal(context: &str, err: impl std::fmt::Debug) -> Outcome {
    tracing::error!(error = ?err, "{context}");
    Outcome::Deferred("451 4.3.0 Temporary server error, please try again later".into())
}

/// How many header fields named `name` the message's header block has.
pub fn header_count(raw: &[u8], name: &str) -> usize {
    let headers = &raw[..authn::find_header_end(raw)];
    headers
        .split(|b| *b == b'\n')
        .filter(|line| line.iter().position(|b| *b == b':').is_some_and(|colon| line[..colon].trim_ascii_end().eq_ignore_ascii_case(name.as_bytes())))
        .count()
}

/// A message with more than one author or sender field is ambiguous: checks and signatures
/// read one of them, mail clients may show the other (RFC 5322 allows exactly one of each).
fn ambiguous_author(raw: &[u8]) -> bool {
    header_count(raw, "From") > 1 || header_count(raw, "Sender") > 1
}

fn received_count(raw: &[u8]) -> usize {
    let headers = &raw[..authn::find_header_end(raw)];
    headers
        .split(|b| *b == b'\n')
        .filter(|line| line.len() >= 9 && line[..9].eq_ignore_ascii_case(b"received:"))
        .count()
}

/// The identity with its own SMTP server that `account` configured for `address`, if any.
/// Mail from such an identity is relayed through that server instead of being sent by us.
///
/// Never for an address in a domain hosted here: that address belongs to someone on this
/// server, and a relay through another server (or back into ours) would let the user send
/// as them.
pub async fn relay_identity(app: &App, account: &Account, address: &Address) -> sqlx::Result<Option<i64>> {
    if hosted_domain(&app.db, &address.domain).await? {
        return Ok(None);
    }
    sqlx::query_scalar("SELECT id FROM identities WHERE account_id = ? AND email = ? AND smtp_host IS NOT NULL")
        .bind(account.id)
        .bind(address.to_string())
        .fetch_optional(&app.db)
        .await
}

/// True when `domain` is one of the domains this server hosts, enabled or not.
pub async fn hosted_domain(db: &sqlx::SqlitePool, domain: &str) -> sqlx::Result<bool> {
    Ok(sqlx::query_scalar::<_, i64>("SELECT 1 FROM domains WHERE name = ?").bind(domain).fetch_optional(db).await?.is_some())
}

/// True when `account` may send mail as `address`: an address it owns, or an identity that
/// sends through its own SMTP server.
pub async fn identity_allowed(app: &App, account: &Account, address: &Address) -> sqlx::Result<bool> {
    Ok(owns_address(app, account, address).await? || relay_identity(app, account, address).await?.is_some())
}

/// True when `address` belongs to `account`: its own address, or an alias that delivers to it.
pub async fn owns_address(app: &App, account: &Account, address: &Address) -> sqlx::Result<bool> {
    let address = address.to_string();
    if address == account.email {
        return Ok(true);
    }
    let destinations: Option<String> = sqlx::query_scalar("SELECT destinations FROM aliases WHERE source = ? AND enabled = 1")
        .bind(&address)
        .fetch_optional(&app.db)
        .await?;
    Ok(destinations
        .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
        .is_some_and(|d| d.iter().any(|dest| dest.eq_ignore_ascii_case(&account.email))))
}

pub struct Inbound<'a> {
    pub ip: IpAddr,
    pub helo: &'a str,
    /// Envelope sender; empty for bounces.
    pub sender: &'a str,
    pub recipients: &'a [(Address, Vec<Target>)],
    pub raw: &'a [u8],
    pub tls: bool,
    /// Handed over by a trusted mail server (LMTP) that checked the sender already.
    pub trusted_relay: bool,
    /// The connection misbehaved (protocol errors, unknown recipients) or comes from an
    /// address with a bad record.
    pub misbehaving: bool,
}

/// Accepts a message received from another mail server for local recipients.
pub async fn accept_inbound(app: &App, msg: Inbound<'_>) -> Outcome {
    Metrics::inc(&app.metrics.messages_received);
    let remote = msg.ip.to_string();
    let reject = |reply: &str, detail: String| {
        let reply = reply.to_owned();
        async move {
            Metrics::inc(&app.metrics.messages_rejected);
            for (rcpt, _) in msg.recipients {
                log_delivery(
                    &app.db,
                    DeliveryEvent {
                        direction: Direction::Inbound,
                        sender: msg.sender,
                        recipient: &rcpt.to_string(),
                        status: "rejected",
                        detail: &detail,
                        remote: &msg.ip.to_string(),
                        message_id: "",
                        size: msg.raw.len() as i64,
                    },
                )
                .await;
            }
            Outcome::Rejected(reply)
        }
    };

    if received_count(msg.raw) > MAX_RECEIVED_HEADERS {
        return reject("554 5.4.6 Too many hops, mail loop suspected", "mail loop".into()).await;
    }
    if ambiguous_author(msg.raw) {
        return reject("550 5.7.1 Message rejected: it has more than one From or Sender header field", "duplicate From/Sender header".into()).await;
    }

    let mut stripped = authn::strip_forged_results(msg.raw, &app.cfg.hostname);
    let mut junk = false;
    let mut extra_headers = String::new();
    let mut arc_headers: Option<String> = None;
    // Whether the envelope sender is known to be the real sender (SPF passed).
    let mut sender_verified = false;
    // Whether the visible author is (DMARC passed). Mail from the server itself, a trusted
    // network or a trusted relay skips the checks: those sources are vouched for.
    let mut author_verified = is_trusted_source(&app.cfg, msg.ip) || msg.trusted_relay;

    if let Some(authenticator) = &app.authenticator
        // Only the server itself and networks the operator vouches for skip the checks: a
        // private address alone may be NAT in front of us, carrying anybody's mail.
        && !is_trusted_source(&app.cfg, msg.ip)
        && !msg.trusted_relay
    {
        // Mail forwarded on through an alias gets our ARC seal, so its next hop can trust what
        // we found before the sender was rewritten.
        let forwarding_domain = msg.recipients.iter().find(|(_, targets)| targets.iter().any(|t| matches!(t, Target::Remote(_)))).map(|(rcpt, _)| rcpt.domain.clone());
        let sealer = match &forwarding_domain {
            Some(domain) => crate::security::dkim::arc_key(&app.db, domain).await,
            None => None,
        };
        match authn::verify(authenticator, &app.cfg.hostname, msg.ip, msg.helo, msg.sender, &stripped, &app.cfg.arc_trusted_sealers, sealer).await {
            Some(verdict) => {
                extra_headers.push_str(&verdict.header);
                arc_headers = verdict.arc_headers;
                sender_verified = verdict.spf_pass;
                author_verified = verdict.author_aligned;
                if let Some(observation) = &verdict.dmarc
                    && app.rt().dmarc_reports_enabled
                {
                    crate::dmarc_outgoing::record(app, observation, &remote, msg.sender).await;
                }
                match verdict.disposition {
                    Disposition::Reject => {
                        return reject(
                            "550 5.7.1 Message rejected due to the sender domain's authentication policy (SPF/DMARC)",
                            verdict.summary,
                        )
                        .await;
                    }
                    Disposition::Quarantine => junk = true,
                    Disposition::Accept => {}
                }
            }
            None => return reject("554 5.6.0 Message could not be parsed", "unparsable message".into()).await,
        }
    }

    // External content filters (milters) may reject, defer, drop or edit the message.
    if !app.cfg.milters.is_empty() {
        let recipients: Vec<String> = msg.recipients.iter().map(|(a, _)| a.to_string()).collect();
        let envelope = crate::milter::Envelope { ip: msg.ip, helo: msg.helo, sender: msg.sender, recipients: &recipients, hostname: &app.cfg.hostname };
        match crate::milter::check(&app.cfg.milters, app.cfg.milter_fail_open, &envelope, &stripped).await {
            crate::milter::Verdict::Deliver { message, quarantine } => {
                stripped = message;
                if let Some(reason) = quarantine {
                    tracing::info!(reason, "message quarantined by a milter");
                    junk = true;
                }
            }
            crate::milter::Verdict::Reject(reply) => return reject(&reply, "rejected by a milter".into()).await,
            crate::milter::Verdict::TempFail(reply) => return Outcome::Deferred(reply),
            crate::milter::Verdict::Discard => {
                tracing::info!(sender = msg.sender, "message discarded by a milter");
                return Outcome::Accepted("250 2.0.0 Ok".into());
            }
        }
    }

    let rt = app.rt();
    if rt.quarantine_misbehaving && msg.misbehaving && !msg.trusted_relay {
        tracing::info!(ip = %msg.ip, sender = msg.sender, "message from a misbehaving connection quarantined");
        junk = true;
    }

    if rt.block_executable_attachments
        && let Some(name) = attachments::blocked_attachment(&stripped)
    {
        Metrics::inc(&app.metrics.spam_blocked);
        return reject(&attachments::refusal(&name), format!("executable attachment: {name}")).await;
    }

    // Whether the message was marked as carrying a virus (and is delivered to Junk as such).
    let mut infected = false;
    let virus_scan = if rt.antivirus_inbound { clamav::scan(app, &stripped).await } else { Ok(None) };
    match virus_scan {
        Ok(Some(Verdict::Infected(name))) => {
            Metrics::inc(&app.metrics.spam_blocked);
            if !rt.virus_quarantine {
                return reject("554 5.7.1 Message rejected: it contains a virus", format!("virus detected: {name}")).await;
            }
            // Kept on the administrator's wish: out of the inbox, and unmistakably marked.
            extra_headers.push_str(&crate::security::summary::virus_header(&name));
            (junk, infected) = (true, true);
        }
        Ok(_) => {}
        Err(_) => return Outcome::Deferred("451 4.7.1 Content filter temporarily unavailable, please try again later".into()),
    }

    let recipient_list: Vec<String> = msg.recipients.iter().map(|(a, _)| a.to_string()).collect();
    let scan = if rt.spam_check_inbound {
        rspamd::scan(app, ScanRequest { ip: msg.ip, helo: msg.helo, sender: msg.sender, recipients: &recipient_list, user: None, raw: &stripped }).await
    } else {
        Ok(None)
    };
    let scan = match scan {
        Ok(scan) => scan,
        Err(rspamd::Unavailable) => return Outcome::Deferred("451 4.7.1 Content filter temporarily unavailable, please try again later".into()),
    };
    if let Some(scan) = &scan {
        extra_headers.push_str(&scan.headers());
        let scanner_found_virus = scan.symbols.iter().any(|symbol| symbol == rspamd::VIRUS_SYMBOL);
        if scanner_found_virus && !infected && rt.virus_quarantine {
            extra_headers.push_str(&crate::security::summary::virus_header("reported-by-the-content-filter"));
            (junk, infected) = (true, true);
        }
        match scan.action {
            // A virus kept for quarantine is not refused for being "spam" on top of it.
            Action::Reject if infected => {}
            Action::Reject => {
                Metrics::inc(&app.metrics.spam_blocked);
                // Tell the sender (and the log) when the reason is malware rather than spam.
                if scanner_found_virus {
                    return reject("554 5.7.1 Message rejected: it contains a virus", "virus detected".into()).await;
                }
                return reject("554 5.7.1 Message rejected as spam", format!("spam score {:.2}", scan.score)).await;
            }
            Action::Defer => return Outcome::Deferred("451 4.7.1 Please try again later".into()),
            Action::Junk => {
                Metrics::inc(&app.metrics.spam_blocked);
                junk = true;
            }
            Action::Accept => {}
        }
        // Readers see at a glance what the filter thought of it.
        if rt.spam_subject_enabled && scan.score >= rt.spam_subject_score {
            stripped = prefix_subject(&stripped, rt.spam_subject_prefix.trim());
        }
    }

    let id = random_token()[..12].to_owned();
    let received = format!(
        "Received: from {} ([{}])\r\n\tby {} with {} id {};\r\n\t{}\r\n",
        sanitize_line(msg.helo),
        msg.ip,
        app.cfg.hostname,
        if msg.tls { "ESMTPS" } else { "ESMTP" },
        id,
        rfc2822_now()
    );
    let mut message = Vec::with_capacity(stripped.len() + received.len() + extra_headers.len());
    message.extend_from_slice(received.as_bytes());
    message.extend_from_slice(extra_headers.as_bytes());
    message.extend_from_slice(&stripped);

    let mut delivered = 0usize;
    let mut quota_failures: Vec<String> = Vec::new();
    let mut forward_blob: Option<String> = None;
    for (rcpt, targets) in msg.recipients {
        for target in targets {
            match target {
                Target::Local { account_id, address } => {
                    let result = delivery::deliver_local(
                        app,
                        LocalDelivery {
                            account_id: *account_id,
                            recipient: address,
                            sender: msg.sender,
                            raw: &message,
                            junk,
                            remote: &remote,
                            direction: Direction::Inbound,
                            author_verified,
                        },
                    )
                    .await;
                    match result {
                        Ok(()) => {
                            delivered += 1;
                            // Success notices go only where SPF says the message came from;
                            // otherwise anyone could make this server mail a third party.
                            if sender_verified {
                                delivered_notice(app, msg.sender, rcpt, &message).await;
                            }
                        }
                        Err(StoreError::QuotaExceeded) => quota_failures.push(address.clone()),
                        Err(err) => return internal("local delivery failed", err),
                    }
                }
                Target::List { list_id, role } => match crate::lists::receive(app, *list_id, *role, msg.sender, &message, junk).await {
                    Ok(()) => delivered += 1,
                    Err(err) => return internal("mailing list failed", err),
                },
                Target::Remote(remote_addr) => {
                    // Forwarding through an alias: rewrite the sender so SPF keeps passing.
                    let result = async {
                        let hash = match &forward_blob {
                            Some(h) => h.clone(),
                            None => match &arc_headers {
                                Some(seal) => app.store.put_blob(&[seal.as_bytes(), &message].concat()).await.map_err(anyhow::Error::from)?,
                                None => app.store.put_blob(&message).await.map_err(anyhow::Error::from)?,
                            },
                        };
                        forward_blob = Some(hash.clone());
                        let size = message.len() + arc_headers.as_ref().map_or(0, String::len);
                        let sender = delivery::forwarding_sender(app, msg.sender, &rcpt.domain).await?;
                        delivery::enqueue(app, &sender, remote_addr, &hash, size, None).await?;
                        anyhow::Ok(())
                    }
                    .await;
                    match result {
                        Ok(()) => delivered += 1,
                        Err(err) => return internal("failed to queue forwarded message", err),
                    }
                }
            }
        }
    }

    if delivered == 0 && !quota_failures.is_empty() {
        return Outcome::Deferred("452 4.2.2 Mailbox full".into());
    }
    for address in &quota_failures {
        queue::bounce(app, msg.sender, address, "552 5.2.2 Mailbox full", &message).await;
    }
    // Aggregate reports sent to a hosted domain feed the DMARC dashboard.
    crate::dmarc_reports::ingest_mail(app, &stripped).await;
    // So do TLS reports (RFC 8460) about how other servers reach ours.
    crate::smtp::transport::ingest_mail(app, &stripped).await;
    Outcome::Accepted(format!("250 2.0.0 Ok: queued as {id}"))
}

/// Tells a sender who asked for it (`NOTIFY=SUCCESS`) that `recipient` has the message now.
async fn delivered_notice(app: &App, sender: &str, recipient: &Address, message: &[u8]) {
    let request = crate::smtp::dsn::current(&recipient.to_string());
    if !sender.is_empty() && request.wants_success() {
        queue::notify(app, sender, &recipient.to_string(), crate::smtp::dsn::Action::Delivered, "", message, &request).await;
    }
}

/// Adds `Date` and `Message-ID` headers when a submitting client omitted them.
/// The header block of a message (up to the empty line) and the rest.
fn split_headers(raw: &[u8]) -> (&[u8], &[u8]) {
    match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(at) => raw.split_at(at + 2),
        None => (raw, b""),
    }
}

/// The header fields of a header block, each with its continuation lines.
fn header_fields(headers: &[u8]) -> Vec<&[u8]> {
    let mut fields: Vec<&[u8]> = Vec::new();
    let mut start = 0;
    let mut at = 0;
    while at < headers.len() {
        let end = headers[at..].windows(2).position(|w| w == b"\r\n").map_or(headers.len(), |p| at + p + 2);
        let continued = end < headers.len() && matches!(headers[end], b' ' | b'\t');
        if !continued {
            fields.push(&headers[start..end]);
            start = end;
        }
        at = end;
    }
    fields
}

fn field_name(field: &[u8]) -> &str {
    std::str::from_utf8(&field[..field.iter().position(|b| *b == b':').unwrap_or(0)]).unwrap_or("").trim()
}

/// The message without the header fields `drop` picks (by name).
pub fn remove_headers(raw: &[u8], drop: impl Fn(&str) -> bool) -> Vec<u8> {
    let (headers, body) = split_headers(raw);
    let mut out = Vec::with_capacity(raw.len());
    for field in header_fields(headers).into_iter().filter(|field| !drop(field_name(field))) {
        out.extend_from_slice(field);
    }
    out.extend_from_slice(body);
    out
}

/// The message with `prefix` in front of its subject (added once; a message without a
/// subject gets one). A non-ASCII prefix is written as an encoded word.
pub fn prefix_subject(raw: &[u8], prefix: &str) -> Vec<u8> {
    use base64::Engine;
    let encoded = if prefix.is_ascii() { prefix.to_owned() } else { format!("=?utf-8?b?{}?=", base64::engine::general_purpose::STANDARD.encode(prefix)) };
    let (headers, body) = split_headers(raw);
    let mut out = Vec::with_capacity(raw.len() + encoded.len() + 12);
    let mut found = false;
    for field in header_fields(headers) {
        if !found && field_name(field).eq_ignore_ascii_case("subject") {
            found = true;
            let colon = field.iter().position(|b| *b == b':').unwrap_or(0);
            let value = &field[colon + 1..];
            let text = value.strip_prefix(b" ").unwrap_or(value);
            if text.starts_with(encoded.as_bytes()) {
                out.extend_from_slice(field);
            } else {
                out.extend_from_slice(&field[..=colon]);
                out.extend_from_slice(format!(" {encoded} ").as_bytes());
                out.extend_from_slice(text);
            }
        } else {
            out.extend_from_slice(field);
        }
    }
    if !found {
        let mut with = format!("Subject: {encoded}\r\n").into_bytes();
        with.extend_from_slice(&out);
        out = with;
    }
    out.extend_from_slice(body);
    out
}

fn ensure_headers(raw: &[u8], domain: &str) -> Vec<u8> {
    let parsed = MessageParser::default().parse_headers(raw);
    let (has_date, has_id) = parsed.as_ref().map_or((false, false), |m| (m.date().is_some(), m.message_id().is_some()));
    let mut out = Vec::with_capacity(raw.len() + 128);
    if !has_date {
        out.extend_from_slice(format!("Date: {}\r\n", rfc2822_now()).as_bytes());
    }
    if !has_id {
        out.extend_from_slice(format!("Message-ID: <{}@{}>\r\n", random_token(), domain).as_bytes());
    }
    out.extend_from_slice(raw);
    out
}

pub struct Submission<'a> {
    pub account: &'a Account,
    pub sender: &'a Address,
    pub recipients: &'a [Address],
    pub raw: &'a [u8],
    /// Someone else who sends in the account's name (a colleague writing to its shared
    /// calendar): the message counts against their sending limits, not the account's.
    pub delegate: Option<&'a Account>,
    pub ip: IpAddr,
}

/// Accepts a message from an authenticated user for local and/or remote delivery.
///
/// Enforces sender identity (envelope and header `From`), per-account sending limits and
/// outbound spam scanning before signing the message with DKIM and queueing it.
pub async fn submit(app: &App, sub: Submission<'_>) -> Outcome {
    let account = sub.account;
    if sub.recipients.is_empty() {
        return Outcome::Rejected("554 5.5.1 No valid recipients".into());
    }
    if sub.raw.len() > app.rt().max_message_size {
        return Outcome::Rejected("552 5.3.4 Message size exceeds fixed limit".into());
    }
    match identity_allowed(app, account, sub.sender).await {
        Ok(true) => {}
        Ok(false) => return Outcome::Rejected("550 5.7.1 Sender address rejected: not owned by authenticated user".into()),
        Err(err) => return internal("identity lookup failed", err),
    }

    // The visible author must be an identity of the authenticated user as well; otherwise one
    // user could impersonate another while keeping a valid envelope sender.
    let Some(parsed) = MessageParser::default().parse_headers(sub.raw) else {
        return Outcome::Rejected("554 5.6.0 Message could not be parsed".into());
    };
    if ambiguous_author(sub.raw) {
        return Outcome::Rejected("550 5.6.0 Message must have exactly one From header (and at most one Sender header)".into());
    }
    let from_addresses: Vec<Address> =
        parsed.from().map(|f| f.iter().filter_map(|a| a.address()).filter_map(Address::parse).collect()).unwrap_or_default();
    if from_addresses.is_empty() {
        return Outcome::Rejected("550 5.6.0 Message must have a valid From header".into());
    }
    let rt = app.rt();
    for from in from_addresses.iter().filter(|_| rt.strict_from_check) {
        match identity_allowed(app, account, from).await {
            Ok(true) => {}
            Ok(false) => return Outcome::Rejected("550 5.7.1 From header rejected: not owned by authenticated user".into()),
            Err(err) => return internal("identity lookup failed", err),
        }
    }
    if received_count(sub.raw) > MAX_RECEIVED_HEADERS {
        return Outcome::Rejected("554 5.4.6 Too many hops, mail loop suspected".into());
    }
    if app.rt().block_executable_attachments
        && let Some(name) = attachments::blocked_attachment(sub.raw)
    {
        return Outcome::Rejected(attachments::refusal(&name));
    }

    // An identity with its own SMTP server hands everything to that server, local recipients
    // included: the message is not ours to sign or deliver.
    let relay = match relay_identity(app, account, &from_addresses[0]).await {
        Ok(relay) => relay,
        Err(err) => return internal("identity lookup failed", err),
    };
    // Mail we sign and deliver ourselves names only addresses the user owns: an identity that
    // sends through another server must not ride along as a second author of such a message.
    if relay.is_none() && rt.strict_from_check {
        for from in &from_addresses[1..] {
            match owns_address(app, account, from).await {
                Ok(true) => {}
                Ok(false) => return Outcome::Rejected("550 5.7.1 From header rejected: an identity that sends through its own SMTP server must be the only author".into()),
                Err(err) => return internal("identity lookup failed", err),
            }
        }
    }
    if relay.is_some() && from_addresses.len() > 1 {
        return Outcome::Rejected("550 5.7.1 From header rejected: an identity that sends through its own SMTP server must be the only author".into());
    }

    // Resolve every recipient before accepting anything.
    let mut targets: Vec<(Address, Target)> = Vec::new();
    for rcpt in sub.recipients {
        if relay.is_some() {
            targets.push((rcpt.clone(), Target::Remote(rcpt.clone())));
            continue;
        }
        match delivery::resolve(app, rcpt).await {
            Ok(Resolution::NotLocal) => targets.push((rcpt.clone(), Target::Remote(rcpt.clone()))),
            Ok(Resolution::Deliver(list)) => targets.extend(list.into_iter().map(|t| (rcpt.clone(), t))),
            Ok(Resolution::NoSuchUser) => return Outcome::Rejected(format!("550 5.1.1 <{rcpt}>: Recipient address rejected: User unknown")),
            Err(err) => return internal("recipient lookup failed", err),
        }
    }

    match outbound::register_submission(app, sub.delegate.unwrap_or(account), sub.recipients.len()).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            return Outcome::Rejected(
                "550 5.7.1 This account is blocked from sending mail; contact your administrator".into(),
            );
        }
        Err(err) => return internal("outbound accounting failed", err),
    }

    crate::bayes::learn_from_reply(app, account.id, sub.raw).await;

    let virus_scan = if rt.antivirus_outbound { clamav::scan(app, sub.raw).await } else { Ok(None) };
    match virus_scan {
        Ok(Some(Verdict::Infected(name))) => {
            crate::db::audit(&app.db, &account.email, "outbound.virus_rejected", &name, &sub.ip.to_string(), "").await;
            return Outcome::Rejected("554 5.7.1 Message rejected: it contains a virus".into());
        }
        Ok(_) => {}
        Err(_) => return Outcome::Deferred("451 4.7.1 Content filter temporarily unavailable, please try again later".into()),
    }

    let recipient_list: Vec<String> = sub.recipients.iter().map(|a| a.to_string()).collect();
    let sender = sub.sender.to_string();
    let scan = if rt.spam_check_outbound {
        rspamd::scan(app, ScanRequest { ip: sub.ip, helo: &app.cfg.hostname, sender: &sender, recipients: &recipient_list, user: Some(&account.email), raw: sub.raw }).await
    } else {
        Ok(None)
    };
    let scan = match scan {
        Ok(scan) => scan,
        Err(rspamd::Unavailable) => return Outcome::Deferred("451 4.7.1 Content filter temporarily unavailable, please try again later".into()),
    };
    if let Some(scan) = &scan
        && matches!(scan.action, Action::Reject | Action::Junk)
    {
        Metrics::inc(&app.metrics.spam_blocked);
        if let Err(err) = outbound::register_spam(app, account).await {
            tracing::error!(error = ?err, "failed to record outbound spam hit");
        }
        crate::db::audit(&app.db, &account.email, "outbound.spam_rejected", &recipient_list.join(","), &sub.ip.to_string(), "").await;
        return Outcome::Rejected("554 5.7.1 Message rejected as spam".into());
    }

    let id = random_token()[..12].to_owned();
    // Unless the administrator wants it shown, the submitting client's address stays private.
    let client = if rt.privacy_hide_client_ip { "localhost (localhost [127.0.0.1])".to_owned() } else { format!("[{0}] ([{0}])", sub.ip) };
    let received = format!("Received: from {client}\r\n\tby {} with ESMTPSA id {id};\r\n\t{}\r\n", app.cfg.hostname, rfc2822_now());
    // What the sender's program says about itself, removed before signing if asked.
    let raw = if rt.privacy_remove_x_headers || rt.privacy_remove_user_agent {
        remove_headers(sub.raw, |name| (rt.privacy_remove_x_headers && name.len() > 2 && name[..2].eq_ignore_ascii_case("x-")) || (rt.privacy_remove_user_agent && name.eq_ignore_ascii_case("user-agent")))
    } else {
        sub.raw.to_vec()
    };
    let body = ensure_headers(&raw, &sub.sender.domain);
    let signed = match relay {
        // The other server signs for its own domain.
        Some(_) => body,
        None => match dkim::sign(&app.db, &from_addresses[0].domain, &body).await {
            Ok(signed) => signed,
            Err(err) => return internal("DKIM signing failed", err),
        },
    };
    let mut message = Vec::with_capacity(signed.len() + received.len());
    message.extend_from_slice(received.as_bytes());
    message.extend_from_slice(&signed);

    let mut blob: Option<String> = None;
    for (rcpt, target) in &targets {
        match target {
            Target::Local { account_id, address } => {
                let result = delivery::deliver_local(
                    app,
                    LocalDelivery {
                        account_id: *account_id,
                        recipient: address,
                        sender: &sender,
                        raw: &message,
                        junk: false,
                        remote: "",
                        direction: Direction::Local,
                        author_verified: rt.strict_from_check,
                    },
                )
                .await;
                match result {
                    Ok(()) => delivered_notice(app, &sender, rcpt, &message).await,
                    Err(StoreError::QuotaExceeded) => queue::bounce(app, &sender, address, "552 5.2.2 Mailbox full", &message).await,
                    Err(err) => return internal("local delivery failed", err),
                }
            }
            Target::List { list_id, role } => {
                if let Err(err) = crate::lists::receive(app, *list_id, *role, &sender, &message, false).await {
                    return internal("mailing list failed", err);
                }
            }
            Target::Remote(remote) => {
                let result = async {
                    let hash = match &blob {
                        Some(h) => h.clone(),
                        None => app.store.put_blob(&message).await.map_err(anyhow::Error::from)?,
                    };
                    blob = Some(hash.clone());
                    // Mail leaving through one of our aliases is a forward and needs SRS.
                    let envelope_sender = if rcpt == remote {
                        sender.clone()
                    } else {
                        delivery::forwarding_sender(app, &sender, &rcpt.domain).await?
                    };
                    delivery::enqueue_via(app, &envelope_sender, remote, &hash, message.len(), Some(account.id), relay).await?;
                    log_delivery(
                        &app.db,
                        DeliveryEvent {
                            direction: Direction::Outbound,
                            sender: &sender,
                            recipient: &remote.to_string(),
                            status: "queued",
                            detail: "",
                            remote: "",
                            message_id: "",
                            size: message.len() as i64,
                        },
                    )
                    .await;
                    anyhow::Ok(())
                }
                .await;
                if let Err(err) = result {
                    return internal("failed to queue message", err);
                }
            }
        }
    }
    // People written to count as correspondents for the personal spam filter.
    if let Err(err) = crate::bayes::remember_recipients(&app.db, account.id, sub.recipients).await {
        tracing::warn!(error = %err, "could not record correspondents");
    }
    crate::webhooks::emit(app, "message.sent", serde_json::json!({ "sender": sender, "recipients": recipient_list, "size": message.len(), "queue_id": id }));
    Outcome::Accepted(format!("250 2.0.0 Ok: queued as {id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_the_subject_once() {
        let raw = b"From: a@b.example\r\nSubject: Cheap watches\r\n\tfor you\r\nTo: c@d.example\r\n\r\nSubject: not a header\r\n";
        let marked = prefix_subject(raw, "[SPAM]");
        assert_eq!(marked, b"From: a@b.example\r\nSubject: [SPAM] Cheap watches\r\n\tfor you\r\nTo: c@d.example\r\n\r\nSubject: not a header\r\n");
        assert_eq!(prefix_subject(&marked, "[SPAM]"), marked, "never twice");
        assert_eq!(prefix_subject(b"From: a@b.example\r\n\r\nbody", "[SPAM]"), b"Subject: [SPAM]\r\nFrom: a@b.example\r\n\r\nbody");
        assert_eq!(prefix_subject(b"Subject: Hi\r\n\r\nx", "[Spam?]"), b"Subject: [Spam?] Hi\r\n\r\nx");
        let polish = prefix_subject(b"Subject: Hi\r\n\r\nx", "[Śmieci]");
        let parsed = MessageParser::default().parse(&polish).unwrap();
        assert_eq!(parsed.subject(), Some("[Śmieci] Hi"));
    }

    #[test]
    fn removes_header_fields_with_their_continuations() {
        let raw = b"From: a@b.example\r\nX-Mailer: Thing\r\n 2.0\r\nUser-Agent: Mozilla/5.0\r\nX-Priority: 1\r\nSubject: Hi\r\n\r\nX-Not: body\r\n";
        let stripped = remove_headers(raw, |name| name.to_ascii_lowercase().starts_with("x-") || name.eq_ignore_ascii_case("user-agent"));
        assert_eq!(stripped, b"From: a@b.example\r\nSubject: Hi\r\n\r\nX-Not: body\r\n");
        assert_eq!(remove_headers(raw, |_| false), raw.to_vec());
    }

    #[test]
    fn counts_received_headers_only_in_the_header_block() {
        let raw = b"Received: a\r\nreceived: b\r\nX-Received: c\r\nSubject: x\r\n\r\nReceived: body\r\n";
        assert_eq!(received_count(raw), 2);
    }

    #[test]
    fn adds_missing_headers_only() {
        let out = String::from_utf8(ensure_headers(b"From: a@example.org\r\n\r\nhi", "example.org")).unwrap();
        assert!(out.starts_with("Date: "));
        assert!(out.contains("\r\nMessage-ID: <") && out.contains("@example.org>\r\nFrom: a@example.org\r\n\r\nhi"));

        let complete = b"Date: Mon, 05 Oct 2026 10:00:00 +0000\r\nMessage-ID: <x@y>\r\nFrom: a@example.org\r\n\r\nhi";
        assert_eq!(ensure_headers(complete, "example.org"), complete);
    }
}
