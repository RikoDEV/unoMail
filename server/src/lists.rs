//! Mailing lists. A list `team@example.org` comes with
//! - `team-request@` for `subscribe`, `unsubscribe` and `help` by mail (confirmed by a link),
//! - `team-owner@`, which reaches the owners,
//! - `team-bounces@`, the envelope sender of distributed copies: members whose mail keeps
//!   bouncing are removed.
//!
//! Posts are checked against the posting policy; whatever may not go out directly waits for a
//! moderator, who approves or discards it from a link in the notice or the admin panel. Every
//! copy carries the RFC 2369 list headers and a one-click unsubscribe link (RFC 8058) for its
//! recipient, and is signed for the list's domain. When the sender's domain asks receivers to
//! reject mail that fails DMARC, the copy is sent "via" the list address, as rewriting the
//! subject would break the sender's signature.

use mail_parser::MessageParser;
use serde::Serialize;

use crate::{
    app::App,
    security::authn::find_header_end,
    db::Direction,
    smtp::delivery::{self, LocalDelivery, Resolution, Target, rfc2822_now},
    util::{Address, hmac_sha256, now, random_token, sanitize_line},
};

/// Members of one list at most.
pub const MAX_MEMBERS: i64 = 10_000;
/// Bounced copies after which a member is removed.
const MAX_BOUNCES: i64 = 5;
const MAX_HELD: i64 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Post,
    Request,
    Owner,
    /// The plain bounce address, which no copy is sent from: reports to it are ignored.
    Bounces,
    /// The bounce address one member's copies are sent from (VERP), authenticated by its tag.
    MemberBounces(i64),
}

/// Who a message to the list is from, and how far that is established.
#[derive(Debug, Clone, Copy)]
pub struct Sender<'a> {
    pub envelope: &'a str,
    /// The envelope sender is authenticated (SMTP AUTH, or an SPF pass).
    pub envelope_verified: bool,
    /// The From address is authenticated (DMARC alignment, or checked at submission).
    pub author_verified: bool,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct List {
    pub id: i64,
    pub domain_id: i64,
    pub address: String,
    pub name: String,
    pub description: String,
    pub posting: String,
    pub subscription: String,
    pub reply_to_list: bool,
    pub subject_prefix: String,
    pub enabled: bool,
    pub created_at: i64,
}

impl List {
    fn local(&self) -> &str {
        self.address.split('@').next().unwrap_or("")
    }

    fn domain(&self) -> &str {
        self.address.rsplit('@').next().unwrap_or("")
    }

    fn special(&self, suffix: &str) -> String {
        format!("{}-{suffix}@{}", self.local(), self.domain())
    }

    /// `List-Id` value (RFC 2919): the address with its `@` made a dot.
    fn list_id(&self) -> String {
        format!("{}.{}", self.local(), self.domain())
    }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Member {
    pub id: i64,
    pub list_id: i64,
    pub email: String,
    pub name: String,
    pub role: String,
    pub bounces: i64,
    pub created_at: i64,
}

pub async fn load(app: &App, id: i64) -> sqlx::Result<Option<List>> {
    sqlx::query_as("SELECT * FROM mailing_lists WHERE id = ?").bind(id).fetch_optional(&app.db).await
}

/// Whether `address` belongs to a list, and in which role.
pub async fn target(app: &App, address: &Address) -> sqlx::Result<Option<Target>> {
    let full = address.without_tag().to_string();
    if let Some(id) = sqlx::query_scalar::<_, i64>("SELECT id FROM mailing_lists WHERE address = ? AND enabled = 1").bind(&full).fetch_optional(&app.db).await? {
        return Ok(Some(Target::List { list_id: id, role: Role::Post }));
    }
    let (local, tag) = address.local.split_once('+').map_or((address.local.as_str(), None), |(local, tag)| (local, Some(tag)));
    for (suffix, role) in [("-request", Role::Request), ("-owner", Role::Owner), ("-bounces", Role::Bounces)] {
        if let Some(local) = local.strip_suffix(suffix) {
            let base = format!("{local}@{}", address.domain);
            if let Some(id) = sqlx::query_scalar::<_, i64>("SELECT id FROM mailing_lists WHERE address = ? AND enabled = 1").bind(&base).fetch_optional(&app.db).await? {
                let role = match (role, tag) {
                    (Role::Bounces, Some(tag)) => bounce_member(app, id, tag).await?.map_or(Role::Bounces, Role::MemberBounces),
                    _ => role,
                };
                return Ok(Some(Target::List { list_id: id, role }));
            }
        }
    }
    Ok(None)
}

fn bounce_tag(secret: &[u8], list_id: i64, member_id: i64) -> String {
    let mac = hmac_sha256(secret, format!("bounces:{list_id}:{member_id}").as_bytes());
    format!("{member_id}.{}", &hex::encode(mac)[..20])
}

/// The member a VERP bounce tag stands for, if the tag is genuine.
async fn bounce_member(app: &App, list_id: i64, tag: &str) -> sqlx::Result<Option<i64>> {
    let Some(member_id) = tag.split_once('.').and_then(|(id, _)| id.parse::<i64>().ok()) else { return Ok(None) };
    let secret = crate::db::get_or_create_secret(&app.db, &app.secrets, "lists.secret").await?;
    Ok(crate::util::ct_eq(bounce_tag(secret.as_bytes(), list_id, member_id).as_bytes(), tag.to_ascii_lowercase().as_bytes()).then_some(member_id))
}

/// Whether an address is taken by a list (or one of its special addresses).
pub async fn address_taken(app: &App, address: &Address) -> sqlx::Result<bool> {
    Ok(target(app, address).await?.is_some())
}

/// Hands a message to whatever lives at `address`: a mailbox here or a remote server.
async fn send(app: &App, envelope_sender: &str, recipient: &str, raw: &[u8]) -> anyhow::Result<()> {
    let Some(address) = Address::parse(recipient) else { anyhow::bail!("invalid address {recipient}") };
    let targets = match delivery::resolve(app, &address).await? {
        Resolution::Deliver(targets) => targets,
        Resolution::NotLocal => vec![Target::Remote(address.clone())],
        Resolution::NoSuchUser => return Ok(()),
    };
    let mut blob = None;
    for target in targets {
        match target {
            Target::Local { account_id, address } => {
                let delivery = LocalDelivery { account_id, recipient: &address, sender: envelope_sender, raw, junk: false, remote: "", direction: Direction::Local, author_verified: false };
                if let Err(err) = delivery::deliver_local(app, delivery).await {
                    tracing::warn!(%err, recipient = address, "list mail not delivered");
                }
            }
            Target::Remote(remote) => {
                let hash = match &blob {
                    Some(hash) => String::clone(hash),
                    None => app.store.put_blob(raw).await?,
                };
                blob = Some(hash.clone());
                delivery::enqueue(app, envelope_sender, &remote, &hash, raw.len(), None).await?;
            }
            // A list never posts to itself (or another list) directly: that is how loops start.
            Target::List { .. } | Target::Trap => {}
        }
    }
    Ok(())
}

/// A message from the list itself (confirmations, notices), signed for its domain.
async fn notice(app: &App, list: &List, recipient: &str, subject: &str, text: &str) {
    let raw = format!(
        "From: \"{name}\" <{from}>\r\nTo: <{recipient}>\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: <{id}@{domain}>\r\nAuto-Submitted: auto-replied\r\n\
         List-Id: \"{name}\" <{list_id}>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{text}\r\n",
        name = sanitize_line(&list.name).replace('"', ""),
        from = list.special("request"),
        subject = sanitize_line(subject),
        date = rfc2822_now(),
        id = random_token(),
        domain = list.domain(),
        list_id = list.list_id(),
        text = text.replace('\n', "\r\n").replace("\r\r\n", "\r\n"),
    );
    let signed = crate::security::dkim::sign(&app.db, &app.secrets, list.domain(), raw.as_bytes()).await.unwrap_or_else(|_| raw.into_bytes());
    // A null sender: nothing answers a notice automatically.
    if let Err(err) = send(app, "", recipient, &signed).await {
        tracing::warn!(%err, "list notice not sent");
    }
}

fn header_value(raw: &[u8], name: &str) -> Option<String> {
    let head = String::from_utf8_lossy(&raw[..find_header_end(raw).min(raw.len())]).into_owned();
    let mut found: Option<String> = None;
    let mut current = false;
    for line in head.split("\r\n").flat_map(|l| l.split('\n')) {
        if line.starts_with([' ', '\t']) {
            if current && let Some(value) = &mut found {
                value.push_str(line);
            }
            continue;
        }
        current = false;
        if found.is_none()
            && let Some((key, value)) = line.split_once(':')
            && key.trim().eq_ignore_ascii_case(name)
        {
            found = Some(value.trim().to_owned());
            current = true;
        }
    }
    found
}

/// Removes header fields (all occurrences) from a message.
fn without_headers(raw: &[u8], names: &[&str]) -> Vec<u8> {
    let end = find_header_end(raw).min(raw.len());
    let head = &raw[..end];
    let mut out = Vec::with_capacity(raw.len());
    let mut skipping = false;
    for line in head.split_inclusive(|b| *b == b'\n') {
        if line.starts_with(b" ") || line.starts_with(b"\t") {
            if !skipping {
                out.extend_from_slice(line);
            }
            continue;
        }
        let name = line.split(|b| *b == b':').next().unwrap_or(b"");
        skipping = names.iter().any(|n| name.eq_ignore_ascii_case(n.as_bytes()));
        if !skipping {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(&raw[end..]);
    out
}

async fn members(app: &App, list_id: i64) -> sqlx::Result<Vec<Member>> {
    sqlx::query_as("SELECT * FROM list_members WHERE list_id = ? ORDER BY email").bind(list_id).fetch_all(&app.db).await
}

fn unsubscribe_token(secret: &[u8], member: &Member) -> String {
    let mac = hmac_sha256(secret, format!("unsubscribe:{}:{}", member.id, member.email).as_bytes());
    format!("{}.{}", member.id, &hex::encode(mac)[..32])
}

/// Checks a one-click unsubscribe token; the member it names, if valid.
pub async fn member_for_token(app: &App, token: &str) -> sqlx::Result<Option<Member>> {
    let Some(id) = token.split_once('.').and_then(|(id, _)| id.parse::<i64>().ok()) else { return Ok(None) };
    let Some(member) = sqlx::query_as::<_, Member>("SELECT * FROM list_members WHERE id = ?").bind(id).fetch_optional(&app.db).await? else { return Ok(None) };
    let secret = crate::db::get_or_create_secret(&app.db, &app.secrets, "lists.secret").await?;
    let expected = unsubscribe_token(secret.as_bytes(), &member);
    Ok(bool::from(subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), token.as_bytes())).then_some(member))
}

/// Whether the sender's domain asks receivers to reject or quarantine mail failing DMARC.
async fn strict_dmarc(app: &App, domain: &str) -> bool {
    let Some(resolver) = &app.authenticator else { return false };
    let records = crate::dns::txt(resolver, &format!("_dmarc.{domain}")).await.unwrap_or_default();
    records.iter().any(|r| {
        let r = r.to_ascii_lowercase().replace(' ', "");
        r.starts_with("v=dmarc1") && (r.contains(";p=reject") || r.contains(";p=quarantine"))
    })
}

/// Sends a post to every member.
async fn distribute(app: &App, list: &List, raw: &[u8]) -> anyhow::Result<usize> {
    let parsed = MessageParser::default().parse_headers(raw);
    let author = parsed.as_ref().and_then(|m| m.from()).and_then(|f| f.first()).map(|a| (a.name().unwrap_or("").to_owned(), a.address().unwrap_or("").to_owned())).unwrap_or_default();
    let subject = parsed.as_ref().and_then(|m| m.subject()).unwrap_or("").to_owned();
    let mut copy = without_headers(raw, &["Return-Path", "Delivered-To", "List-Id", "List-Post", "List-Help", "List-Subscribe", "List-Unsubscribe", "List-Unsubscribe-Post", "List-Owner", "List-Archive", "Precedence", "X-Loop"]);
    let mut extra = String::new();
    let prefix = list.subject_prefix.trim();
    if !prefix.is_empty() && !subject.contains(prefix) {
        copy = without_headers(&copy, &["Subject"]);
        extra.push_str(&format!("Subject: {prefix} {}\r\n", sanitize_line(&subject)));
    }
    let author_domain = author.1.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase()).unwrap_or_default();
    let ours = author_domain == list.domain() || delivery::is_local_domain(app, &author_domain).await.unwrap_or(false);
    if !ours && strict_dmarc(app, &author_domain).await {
        copy = without_headers(&copy, &["From", "Reply-To", "DKIM-Signature"]);
        let display = if author.0.is_empty() { author.1.clone() } else { author.0.clone() };
        extra.push_str(&format!("From: \"{} via {}\" <{}>\r\n", sanitize_line(&display).replace('"', ""), sanitize_line(&list.name).replace('"', ""), list.address));
        let address = crate::util::sanitize_line(&author.1).replace(['<', '>'], "");
        extra.push_str(&format!("X-Original-From: {address}\r\n"));
        if !list.reply_to_list {
            extra.push_str(&format!("Reply-To: <{address}>\r\n"));
        }
    }
    if list.reply_to_list {
        copy = without_headers(&copy, &["Reply-To"]);
        extra.push_str(&format!("Reply-To: <{}>\r\n", list.address));
    }
    extra.push_str(&format!(
        "List-Id: \"{name}\" <{id}>\r\nList-Post: <mailto:{post}>\r\nList-Help: <mailto:{request}?subject=help>\r\nList-Subscribe: <mailto:{request}?subject=subscribe>\r\nList-Owner: <mailto:{owner}>\r\nPrecedence: list\r\nX-Loop: {post}\r\n",
        name = sanitize_line(&list.name).replace('"', ""),
        id = list.list_id(),
        post = list.address,
        request = list.special("request"),
        owner = list.special("owner"),
    ));
    let secret = crate::db::get_or_create_secret(&app.db, &app.secrets, "lists.secret").await?;
    let base = app.cfg.public_url();
    let members = members(app, list.id).await?;
    // Posts come from outside, so no account's sending limit covers what a list sends out.
    if !crate::security::outbound::register_forward(app, &list.address, members.len()).await? {
        anyhow::bail!("{} reached its sending limit", list.address);
    }
    let mut sent = 0;
    for member in members {
        let token = unsubscribe_token(secret.as_bytes(), &member);
        // Each copy carries its own return address, so a report about it can only be about
        // this member: nobody can report someone else's address as failing.
        let bounces = format!("{}-bounces+{}@{}", list.local(), bounce_tag(secret.as_bytes(), list.id, member.id), list.domain());
        let message = [
            extra.as_bytes(),
            format!(
                "List-Unsubscribe: <{base}/lists/unsubscribe/{token}>, <mailto:{}?subject=unsubscribe>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
                list.special("request")
            )
            .as_bytes(),
            &copy,
        ]
        .concat();
        let signed = crate::security::dkim::sign(&app.db, &app.secrets, list.domain(), &message).await.unwrap_or(message);
        match send(app, &bounces, &member.email, &signed).await {
            Ok(()) => sent += 1,
            Err(err) => tracing::warn!(%err, member = member.email, "list copy not sent"),
        }
    }
    crate::db::audit(&app.db, "system", "list.distributed", &list.address, "", &format!("{sent} copies")).await;
    Ok(sent)
}

/// Holds a post for a moderator and tells the moderators.
async fn hold(app: &App, list: &List, sender: &str, raw: &[u8], reason: &str) -> anyhow::Result<()> {
    let held: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM list_pending WHERE list_id = ? AND kind = 'post'").bind(list.id).fetch_one(&app.db).await?;
    if held >= MAX_HELD {
        tracing::warn!(list = list.address, "moderation queue full, post dropped");
        return Ok(());
    }
    let subject = MessageParser::default().parse_headers(raw).and_then(|m| m.subject().map(str::to_owned)).unwrap_or_default();
    let hash = app.store.put_blob(raw).await?;
    let token = random_token();
    sqlx::query("INSERT INTO list_pending (list_id, kind, token, email, subject, reason, blob_hash, created_at) VALUES (?, 'post', ?, ?, ?, ?, ?, ?)")
        .bind(list.id)
        .bind(&token)
        .bind(sender)
        .bind(subject.chars().take(300).collect::<String>())
        .bind(reason)
        .bind(&hash)
        .bind(now())
        .execute(&app.db)
        .await?;
    let base = app.cfg.public_url();
    for moderator in members(app, list.id).await?.into_iter().filter(|m| m.role != "member") {
        let text = format!(
            "A message to {list} is waiting for approval.\n\nFrom: {sender}\nSubject: {subject}\nReason: {reason}\n\nApprove or discard it here:\n{base}/lists/moderate/{token}\n",
            list = list.address,
            subject = sanitize_line(&subject),
        );
        notice(app, list, &moderator.email, &format!("Approval needed: {}", sanitize_line(&subject)), &text).await;
    }
    Ok(())
}

/// What a moderator decided about a held post.
pub async fn moderate(app: &App, token: &str, approve: bool) -> anyhow::Result<Option<String>> {
    let row: Option<(i64, i64, Option<String>, String)> = sqlx::query_as("SELECT id, list_id, blob_hash, subject FROM list_pending WHERE token = ? AND kind = 'post'").bind(token).fetch_optional(&app.db).await?;
    let Some((id, list_id, hash, subject)) = row else { return Ok(None) };
    let list = load(app, list_id).await?.ok_or_else(|| anyhow::anyhow!("the list no longer exists"))?;
    sqlx::query("DELETE FROM list_pending WHERE id = ?").bind(id).execute(&app.db).await?;
    if approve && let Some(hash) = hash {
        let raw = app.store.read_blob(&hash).await?;
        distribute(app, &list, &raw).await?;
    }
    Ok(Some(format!("{} \u{201c}{}\u{201d} ({})", if approve { "Sent" } else { "Discarded" }, subject, list.address)))
}

/// A subscription or unsubscription waiting for confirmation by its link.
pub async fn confirm(app: &App, token: &str) -> anyhow::Result<Option<String>> {
    let row: Option<(i64, i64, String, String)> = sqlx::query_as("SELECT id, list_id, kind, email FROM list_pending WHERE token = ? AND kind IN ('subscribe', 'unsubscribe') AND created_at > ?")
        .bind(token)
        .bind(now() - 7 * 86_400)
        .fetch_optional(&app.db)
        .await?;
    let Some((id, list_id, kind, email)) = row else { return Ok(None) };
    let list = load(app, list_id).await?.ok_or_else(|| anyhow::anyhow!("the list no longer exists"))?;
    sqlx::query("DELETE FROM list_pending WHERE id = ?").bind(id).execute(&app.db).await?;
    if kind == "subscribe" {
        add_member(app, list_id, &email, "", "member").await?;
        Ok(Some(format!("{email} is now subscribed to {}.", list.address)))
    } else {
        sqlx::query("DELETE FROM list_members WHERE list_id = ? AND email = ?").bind(list_id).bind(&email).execute(&app.db).await?;
        Ok(Some(format!("{email} has left {}.", list.address)))
    }
}

/// Adds (or updates) a member.
pub async fn add_member(app: &App, list_id: i64, email: &str, name: &str, role: &str) -> anyhow::Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM list_members WHERE list_id = ?").bind(list_id).fetch_one(&app.db).await?;
    anyhow::ensure!(count < MAX_MEMBERS, "a list can have at most {MAX_MEMBERS} members");
    sqlx::query(
        "INSERT INTO list_members (list_id, email, name, role, created_at) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (list_id, email) DO UPDATE SET role = excluded.role, name = CASE WHEN excluded.name = '' THEN name ELSE excluded.name END, bounces = 0",
    )
    .bind(list_id)
    .bind(email.to_ascii_lowercase())
    .bind(name)
    .bind(role)
    .bind(now())
    .execute(&app.db)
    .await?;
    Ok(())
}

/// The command in a message to the `-request` address: from the subject, else the first line.
fn command(raw: &[u8]) -> String {
    let subject = header_value(raw, "Subject").unwrap_or_default();
    let body = String::from_utf8_lossy(&raw[find_header_end(raw).min(raw.len())..]).into_owned();
    let first = body.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("").to_owned();
    for text in [subject, first] {
        let word = text.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
        if matches!(word.as_str(), "subscribe" | "join" | "unsubscribe" | "leave" | "remove" | "help") {
            return word;
        }
    }
    "help".into()
}

/// The address a message is from (the author; the envelope sender as a fallback).
fn author(raw: &[u8], envelope: &str) -> String {
    MessageParser::default()
        .parse_headers(raw)
        .and_then(|m| m.from().and_then(|f| f.first()).and_then(|a| a.address().map(str::to_ascii_lowercase)))
        .filter(|a| Address::parse(a).is_some())
        .unwrap_or_else(|| envelope.to_ascii_lowercase())
}

/// Handles mail to one of a list's addresses.
pub async fn receive(app: &App, list_id: i64, role: Role, sender: Sender<'_>, raw: &[u8], junk: bool) -> anyhow::Result<()> {
    let envelope_sender = sender.envelope;
    let Some(list) = load(app, list_id).await? else { return Ok(()) };
    match role {
        Role::Post => {
            // Our own copies coming back (through a member's forward) end here.
            if header_value(raw, "X-Loop").is_some_and(|v| v.eq_ignore_ascii_case(&list.address)) || header_value(raw, "List-Id").is_some_and(|v| v.contains(&format!("<{}>", list.list_id()))) {
                return Ok(());
            }
            let from = author(raw, envelope_sender);
            // Only authenticated addresses count: anyone can write a member's address into From.
            let role_of = |email: String| async move {
                sqlx::query_scalar::<_, String>("SELECT role FROM list_members WHERE list_id = ? AND email = ?").bind(list.id).bind(email).fetch_optional(&app.db).await
            };
            let by_author = if sender.author_verified { role_of(from.clone()).await? } else { None };
            let by_envelope = if sender.envelope_verified && !envelope_sender.is_empty() { role_of(envelope_sender.to_ascii_lowercase()).await? } else { None };
            let membership = match (by_author, by_envelope) {
                (Some(a), Some(b)) => Some(if a == "member" { b } else { a }),
                (a, b) => a.or(b),
            };
            // Claims a member's address without proof: a moderator decides.
            let claimed = membership.is_none() && role_of(from.clone()).await?.is_some();
            let moderator = membership.as_deref().is_some_and(|r| r != "member");
            let decision = match list.posting.as_str() {
                _ if junk => Err("classified as spam"),
                "anyone" => Ok(()),
                _ if claimed => Err("the sender's address could not be verified"),
                "members" if membership.is_some() => Ok(()),
                "members" => Err("the sender is not a member"),
                _ if moderator => Ok(()),
                "announce" => {
                    if !envelope_sender.is_empty() {
                        notice(app, &list, &from, &format!("Your message to {} was not sent", list.address), &format!("Only the owners of {} can post to it.\n", list.address)).await;
                    }
                    return Ok(());
                }
                _ => Err("the list is moderated"),
            };
            match decision {
                Ok(()) => distribute(app, &list, raw).await.map(|_| ()),
                Err(reason) => hold(app, &list, &from, raw, reason).await,
            }
        }
        Role::Owner => {
            for owner in members(app, list.id).await?.into_iter().filter(|m| m.role == "owner") {
                if let Err(err) = send(app, &list.special("bounces"), &owner.email, raw).await {
                    tracing::warn!(%err, "mail to the list owner not forwarded");
                }
            }
            Ok(())
        }
        Role::Bounces => {
            // Copies go out from per-member addresses; the bare one never gets genuine reports.
            Ok(())
        }
        Role::MemberBounces(member_id) => {
            // A failure report (RFC 3464) counts once against the member its address names,
            // whatever recipients the report itself lists.
            let text = String::from_utf8_lossy(raw).to_ascii_lowercase();
            if !text.contains("action: failed") {
                return Ok(());
            }
            sqlx::query("UPDATE list_members SET bounces = bounces + 1 WHERE list_id = ? AND id = ?").bind(list.id).bind(member_id).execute(&app.db).await?;
            let removed: Option<String> = sqlx::query_scalar("DELETE FROM list_members WHERE list_id = ? AND id = ? AND bounces >= ? AND role = 'member' RETURNING email")
                .bind(list.id)
                .bind(member_id)
                .bind(MAX_BOUNCES)
                .fetch_optional(&app.db)
                .await?;
            if let Some(address) = removed {
                crate::db::audit(&app.db, "system", "list.member_bounced_out", &list.address, "", &address).await;
            }
            Ok(())
        }
        Role::Request => {
            let from = author(raw, envelope_sender);
            // Never answer automatic mail: that is how mail loops start.
            if envelope_sender.is_empty() || header_value(raw, "Auto-Submitted").is_some_and(|v| !v.eq_ignore_ascii_case("no")) {
                return Ok(());
            }
            let base = app.cfg.public_url();
            match command(raw).as_str() {
                "subscribe" | "join" if list.subscription == "open" => {
                    let token = random_token();
                    sqlx::query("INSERT INTO list_pending (list_id, kind, token, email, created_at) VALUES (?, 'subscribe', ?, ?, ?)").bind(list.id).bind(&token).bind(&from).bind(now()).execute(&app.db).await?;
                    let text = format!("Someone, probably you, asked to subscribe {from} to {}.\n\nTo confirm, open this link:\n{base}/lists/confirm/{token}\n\nIf this was not you, ignore this message.\n", list.address);
                    notice(app, &list, &from, &format!("Confirm your subscription to {}", list.address), &text).await;
                }
                "subscribe" | "join" => notice(app, &list, &from, &format!("Subscribing to {}", list.address), &format!("Members of {} are added by its owners. Write to {} to ask.\n", list.address, list.special("owner"))).await,
                "unsubscribe" | "leave" | "remove" => {
                    let member: Option<i64> = sqlx::query_scalar("SELECT id FROM list_members WHERE list_id = ? AND email = ?").bind(list.id).bind(&from).fetch_optional(&app.db).await?;
                    if member.is_some() {
                        let token = random_token();
                        sqlx::query("INSERT INTO list_pending (list_id, kind, token, email, created_at) VALUES (?, 'unsubscribe', ?, ?, ?)").bind(list.id).bind(&token).bind(&from).bind(now()).execute(&app.db).await?;
                        let text = format!("To stop receiving mail from {} at {from}, open this link:\n{base}/lists/confirm/{token}\n", list.address);
                        notice(app, &list, &from, &format!("Confirm leaving {}", list.address), &text).await;
                    }
                }
                _ => {
                    let text = format!(
                        "{name} <{post}>\n{description}\n\nTo post, write to {post}.\nTo subscribe, send \"subscribe\" to {request}.\nTo unsubscribe, send \"unsubscribe\" to {request}.\nTo reach the owners, write to {owner}.\n",
                        name = list.name,
                        post = list.address,
                        description = list.description,
                        request = list.special("request"),
                        owner = list.special("owner"),
                    );
                    notice(app, &list, &from, &format!("Help for {}", list.address), &text).await;
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_messages_do_not_panic() {
        for raw in crate::fuzzing::inputs(3, 3000, 16) {
            let _ = header_value(&raw, "Subject");
            let cleaned = without_headers(&raw, &["List-Id", "Subject"]);
            assert!(cleaned.len() <= raw.len());
            let _ = command(&raw);
            let _ = author(&raw, "x@y.example");
        }
    }


    #[test]
    fn headers_and_commands() {
        let raw = b"From: a@b.example\r\nList-Id: <x.y>\r\nSubject: Hello\r\n\tthere\r\nX-Other: 1\r\n\r\nsubscribe me\r\n";
        assert_eq!(header_value(raw, "subject").as_deref(), Some("Hello\tthere"));
        assert_eq!(without_headers(raw, &["List-Id", "Subject"]), b"From: a@b.example\r\nX-Other: 1\r\n\r\nsubscribe me\r\n");
        assert_eq!(command(raw), "subscribe");
        assert_eq!(command(b"Subject: unsubscribe\r\n\r\n"), "unsubscribe");
        assert_eq!(command(b"Subject: what?\r\n\r\nhi"), "help");
        assert_eq!(author(raw, "x@y.example"), "a@b.example");
    }
}
