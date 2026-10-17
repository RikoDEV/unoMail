//! Out-of-office autoreplies (RFC 3834 behaviour): date ranges, per-sender deduplication and
//! strict loop avoidance.

use mail_parser::{HeaderValue, MessageParser};
use serde::{Deserialize, Serialize};

use crate::{
    app::App,
    security::dkim,
    smtp::delivery::{self, Resolution, Target, rfc2822_now},
    store::Flags,
    util::{Address, now, random_token, sanitize_line},
};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Vacation {
    pub enabled: bool,
    pub subject: String,
    pub body: String,
    pub starts_at: Option<i64>,
    pub ends_at: Option<i64>,
    pub interval_days: i64,
    /// The body is a MIME entity (`vacation :mime` in Sieve) rather than plain text.
    #[serde(skip)]
    #[sqlx(skip)]
    pub mime: bool,
}

impl Default for Vacation {
    fn default() -> Self {
        Vacation { enabled: false, subject: String::new(), body: String::new(), starts_at: None, ends_at: None, interval_days: 7, mime: false }
    }
}

impl Vacation {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.subject.chars().count() > 200 || self.subject.chars().any(|c| c.is_control()) {
            return Err("invalid subject");
        }
        if self.body.len() > 10_000 {
            return Err("the message is too long");
        }
        if self.enabled && self.body.trim().is_empty() {
            return Err("a message is required");
        }
        if !(1..=90).contains(&self.interval_days) {
            return Err("the reply interval must be between 1 and 90 days");
        }
        if let (Some(start), Some(end)) = (self.starts_at, self.ends_at)
            && end <= start
        {
            return Err("the end date must be after the start date");
        }
        Ok(())
    }

    pub fn active_at(&self, time: i64) -> bool {
        self.enabled && self.starts_at.is_none_or(|s| time >= s) && self.ends_at.is_none_or(|e| time < e)
    }
}

pub async fn load(app: &App, account_id: i64) -> sqlx::Result<Vacation> {
    Ok(sqlx::query_as("SELECT enabled, subject, body, starts_at, ends_at, interval_days FROM vacation WHERE account_id = ?")
        .bind(account_id)
        .fetch_optional(&app.db)
        .await?
        .unwrap_or_default())
}

pub async fn save(app: &App, account_id: i64, v: &Vacation) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO vacation (account_id, enabled, subject, body, starts_at, ends_at, interval_days) VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(account_id) DO UPDATE SET enabled = excluded.enabled, subject = excluded.subject, body = excluded.body,
            starts_at = excluded.starts_at, ends_at = excluded.ends_at, interval_days = excluded.interval_days",
    )
    .bind(account_id)
    .bind(v.enabled)
    .bind(&v.subject)
    .bind(&v.body)
    .bind(v.starts_at)
    .bind(v.ends_at)
    .bind(v.interval_days)
    .execute(&app.db)
    .await?;
    // New settings start a new round of replies.
    sqlx::query("DELETE FROM vacation_sent WHERE account_id = ?").bind(account_id).execute(&app.db).await?;
    Ok(())
}

/// Decides whether a message may be answered automatically. Automated mail, mailing lists,
/// bounces and mail not addressed directly to the user never are.
pub fn should_reply(sender: &str, recipient: &str, raw: &[u8]) -> bool {
    let Some(sender_address) = Address::parse(sender) else { return false };
    let local = &sender_address.local;
    const ROBOTS: [&str; 9] = ["mailer-daemon", "postmaster", "noreply", "no-reply", "no_reply", "donotreply", "do-not-reply", "bounce", "bounces"];
    if ROBOTS.contains(&local.as_str()) || local.starts_with("owner-") || local.ends_with("-request") || local.ends_with("-bounces") || local.starts_with("srs0=") {
        return false;
    }
    if sender.eq_ignore_ascii_case(recipient) {
        return false;
    }
    let Some(message) = MessageParser::default().parse_headers(raw) else { return false };
    let text = |name: &'static str| message.header_raw(name).map(|v| v.trim().to_ascii_lowercase());
    if text("Auto-Submitted").is_some_and(|v| v != "no") {
        return false;
    }
    if text("Precedence").is_some_and(|v| matches!(v.as_str(), "bulk" | "junk" | "list")) {
        return false;
    }
    for header in ["List-Id", "List-Unsubscribe", "List-Post", "X-Auto-Response-Suppress", "X-Autoreply", "X-Autorespond", "Feedback-ID"] {
        if message.header_raw(header).is_some() {
            return false;
        }
    }
    if matches!(message.return_path(), HeaderValue::Text(path) if path.trim().is_empty() || path.trim() == "<>") {
        return false;
    }
    // Only answer mail that names the user as a visible recipient.
    let recipient = recipient.to_ascii_lowercase();
    let plain = recipient.split_once('@').map(|(local, domain)| format!("{}@{domain}", local.split('+').next().unwrap_or(local)));
    [message.to(), message.cc()].into_iter().flatten().flat_map(|list| list.iter()).filter_map(|a| a.address()).any(|address| {
        let address = address.to_ascii_lowercase();
        address == recipient || plain.as_deref() == Some(address.as_str())
    })
}

fn build_reply(v: &Vacation, from: &str, display_name: &str, to: &str, original: &[u8]) -> Vec<u8> {
    let parsed = MessageParser::default().parse_headers(original);
    let original_subject = parsed.as_ref().and_then(|m| m.subject()).map(sanitize_line).unwrap_or_default();
    let subject = if v.subject.trim().is_empty() { format!("Automatic reply: {original_subject}") } else { sanitize_line(&v.subject) };
    let domain = from.rsplit_once('@').map_or("localhost", |(_, d)| d);
    let mut builder = mail_builder::MessageBuilder::new()
        .from((sanitize_line(display_name), from.to_owned()))
        .to(to.to_owned())
        .subject(subject)
        .message_id(format!("{}@{domain}", random_token()))
        .header("Auto-Submitted", mail_builder::headers::raw::Raw::new("auto-replied"))
        .header("X-Auto-Response-Suppress", mail_builder::headers::raw::Raw::new("All"))
        .text_body(if v.mime { String::new() } else { v.body.clone() });
    if let Some(id) = parsed.as_ref().and_then(|m| m.message_id()) {
        let id = sanitize_line(id);
        builder = builder.in_reply_to(id.clone()).references(id);
    }
    let built = builder.write_to_vec().unwrap_or_default();
    if !v.mime {
        return built;
    }
    // MIME reason: keep our own headers, replace the content headers and body with the entity
    // from the script (validated to contain Content-* headers only).
    let headers = &built[..crate::security::authn::find_header_end(&built)];
    let mut out = Vec::with_capacity(headers.len() + v.body.len() + 32);
    let mut skipping = false;
    for line in headers.split_inclusive(|b| *b == b'\n') {
        if !matches!(line.first(), Some(b' ' | b'\t')) {
            let lower = String::from_utf8_lossy(line).to_ascii_lowercase();
            skipping = lower.starts_with("content-") || lower.starts_with("mime-version:");
        }
        if !skipping {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(b"MIME-Version: 1.0\r\n");
    out.extend_from_slice(v.body.replace("\r\n", "\n").replace('\n', "\r\n").as_bytes());
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Sends the account's autoreply to `sender`, if one is due. Failures are logged and never
/// affect delivery of the original message.
pub async fn maybe_reply(app: &App, account_id: i64, recipient: &str, sender: &str, raw: &[u8]) {
    let result = async {
        let vacation = load(app, account_id).await?;
        if !vacation.active_at(now()) || !should_reply(sender, recipient, raw) {
            return anyhow::Ok(());
        }
        send_reply(app, account_id, recipient, sender, raw, &vacation, "").await
    }
    .await;
    if let Err(err) = result {
        tracing::warn!(error = ?err, recipient, "failed to send autoreply");
    }
}

/// Autoreply requested by the `vacation` action of a Sieve script. The same safety rules as
/// for the out-of-office setting apply; `:addresses` lists further addresses of the user.
pub async fn reply_from_sieve(app: &App, account_id: i64, recipient: &str, sender: &str, raw: &[u8], action: &crate::sieve::Vacation) {
    let addressed = std::iter::once(recipient).chain(action.addresses.iter().map(String::as_str)).any(|own| should_reply(sender, own, raw));
    if !addressed {
        return;
    }
    let settings = Vacation {
        enabled: true,
        subject: action.subject.clone(),
        body: action.reason.clone(),
        starts_at: None,
        ends_at: None,
        interval_days: action.days,
        mime: action.mime,
    };
    // Different handles (or reply texts) are tracked separately, as RFC 5230 requires.
    let handle = if action.handle.is_empty() { format!("{}\0{}", action.subject, action.reason) } else { action.handle.clone() };
    let key = format!("|sieve:{}", &crate::util::sha256_hex(handle.as_bytes())[..16]);
    if let Err(err) = send_reply(app, account_id, recipient, sender, raw, &settings, &key).await {
        tracing::warn!(error = ?err, recipient, "failed to send Sieve vacation reply");
    }
}

/// Sends one autoreply unless `sender` already received one within the interval.
async fn send_reply(app: &App, account_id: i64, recipient: &str, sender: &str, raw: &[u8], vacation: &Vacation, dedupe_suffix: &str) -> anyhow::Result<()> {
    {
        let Some(sender_address) = Address::parse(sender) else { return Ok(()) };
        let sender = sender_address.to_string();
        let dedupe_key = format!("{sender}{dedupe_suffix}");

        // Smart deduplication: at most one reply per correspondent per interval. The row is
        // claimed atomically so concurrent deliveries cannot both reply.
        let cutoff = now() - vacation.interval_days * 86400;
        let claimed = sqlx::query(
            "INSERT INTO vacation_sent (account_id, sender, sent_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(account_id, sender) DO UPDATE SET sent_at = excluded.sent_at WHERE vacation_sent.sent_at < ?4",
        )
        .bind(account_id)
        .bind(&dedupe_key)
        .bind(now())
        .bind(cutoff)
        .execute(&app.db)
        .await?
        .rows_affected();
        if claimed == 0 {
            return Ok(());
        }

        let display_name: String = sqlx::query_scalar("SELECT display_name FROM accounts WHERE id = ?").bind(account_id).fetch_one(&app.db).await?;
        let reply = build_reply(vacation, recipient, &display_name, &sender, raw);
        let domain = recipient.rsplit_once('@').map_or("", |(_, d)| d);
        let mut message = format!("Received: by {} (autoreply); {}\r\n", app.cfg.hostname, rfc2822_now()).into_bytes();
        message.extend_from_slice(&dkim::sign(&app.db, domain, &reply).await?);

        // The envelope sender is null so that a bounce or another autoresponder cannot loop.
        let targets = match delivery::resolve(app, &sender_address).await? {
            Resolution::Deliver(targets) => targets,
            Resolution::NotLocal => vec![Target::Remote(sender_address.clone())],
            Resolution::NoSuchUser => Vec::new(),
        };
        for target in targets {
            match target {
                Target::Local { account_id: target_account, address } => {
                    if let Some(inbox) = app.store.mailbox_by_role(target_account, "inbox").await? {
                        let mut local = format!("Return-Path: <>\r\nDelivered-To: {address}\r\n").into_bytes();
                        local.extend_from_slice(&message);
                        app.store.append(target_account, inbox.id, &local, Flags::default(), None).await?;
                    }
                }
                Target::Remote(remote) => {
                    let hash = app.store.put_blob(&message).await?;
                    delivery::enqueue(app, "", &remote, &hash, message.len(), Some(account_id)).await?;
                }
                // Lists do not get out-of-office replies.
                Target::List { .. } | Target::Trap => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "bob@example.org";

    fn msg(extra_headers: &str) -> Vec<u8> {
        format!("From: Alice <alice@remote.example>\r\nTo: bob@example.org\r\nSubject: Question\r\nMessage-ID: <q1@remote.example>\r\n{extra_headers}\r\nHi\r\n").into_bytes()
    }

    #[test]
    fn replies_only_to_personal_mail() {
        assert!(should_reply("alice@remote.example", ME, &msg("")));
        assert!(should_reply("alice@remote.example", "bob+tag@example.org", &msg("")));
        // Bounces and robots.
        assert!(!should_reply("", ME, &msg("")));
        for robot in ["MAILER-DAEMON@remote.example", "noreply@shop.example", "no-reply@shop.example", "owner-list@lists.example", "list-request@lists.example", "announce-bounces@lists.example"] {
            assert!(!should_reply(robot, ME, &msg("")), "{robot}");
        }
        // Automated and bulk mail.
        for header in ["Auto-Submitted: auto-replied\r\n", "Auto-Submitted: auto-generated\r\n", "Precedence: bulk\r\n", "Precedence: list\r\n", "List-Id: <announce.lists.example>\r\n", "List-Unsubscribe: <mailto:u@lists.example>\r\n", "X-Auto-Response-Suppress: OOF\r\n"] {
            assert!(!should_reply("alice@remote.example", ME, &msg(header)), "{header}");
        }
        assert!(should_reply("alice@remote.example", ME, &msg("Auto-Submitted: no\r\n")));
        // Not a visible recipient (Bcc, alias expansion, mailing list).
        let other = b"From: alice@remote.example\r\nTo: team@example.org\r\nSubject: x\r\n\r\nbody";
        assert!(!should_reply("alice@remote.example", ME, other));
        // Never to oneself.
        assert!(!should_reply(ME, ME, &msg("")));
    }

    #[test]
    fn schedule_and_validation() {
        let mut v = Vacation { enabled: true, body: "Away".into(), starts_at: Some(100), ends_at: Some(200), ..Default::default() };
        assert!(!v.active_at(99));
        assert!(v.active_at(100) && v.active_at(199));
        assert!(!v.active_at(200));
        assert!(v.validate().is_ok());
        v.ends_at = Some(50);
        assert!(v.validate().is_err());
        v.ends_at = None;
        v.interval_days = 0;
        assert!(v.validate().is_err());
        v.interval_days = 7;
        v.body = "  ".into();
        assert!(v.validate().is_err());
        v.enabled = false;
        assert!(v.validate().is_ok());
        assert!(!v.active_at(150));
        v.subject = "bad\r\nBcc: x@y".into();
        assert!(v.validate().is_err());
    }

    #[test]
    fn mime_reply_keeps_our_headers_and_uses_the_scripts_entity() {
        let v = Vacation { enabled: true, mime: true, body: "Content-Type: text/html; charset=utf-8\n\n<p>Away <b>today</b></p>".into(), ..Default::default() };
        let reply = String::from_utf8(build_reply(&v, ME, "Bob", "alice@remote.example", &msg(""))).unwrap();
        assert!(reply.contains("Auto-Submitted: auto-replied\r\n") && reply.contains("To: <alice@remote.example>\r\n"));
        assert_eq!(reply.matches("Content-Type:").count(), 1);
        assert!(reply.contains("MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Away <b>today</b></p>\r\n"), "{reply}");
        let parsed = MessageParser::default().parse(reply.as_bytes()).unwrap();
        assert_eq!(parsed.body_html(0).unwrap().trim(), "<p>Away <b>today</b></p>");
    }

    #[test]
    fn reply_is_marked_as_automatic_and_threaded() {
        let v = Vacation { enabled: true, body: "I am away until Monday.".into(), ..Default::default() };
        let reply = String::from_utf8(build_reply(&v, ME, "Bob", "alice@remote.example", &msg(""))).unwrap();
        assert!(reply.contains("Auto-Submitted: auto-replied\r\n"));
        assert!(reply.contains("Subject: Automatic reply: Question\r\n"));
        assert!(reply.contains("In-Reply-To: <q1@remote.example>\r\n"));
        assert!(reply.contains("To: <alice@remote.example>\r\n"));
        assert!(reply.contains("I am away until Monday."));
        // The reply itself would never trigger another autoreply.
        assert!(!should_reply(ME, "alice@remote.example", reply.as_bytes()));
    }
}
