//! Personal spam filter: a Bayes classifier per account, trained by what the user does.
//!
//! Rspamd's Bayes is shared by the whole server and only exists where Rspamd runs. This one
//! learns each user's own idea of spam: reporting a message (moving it into Junk, or the
//! `$Junk` keyword IMAP clients set) teaches spam; "Not spam" (moving out of Junk, `$NotJunk`),
//! replying to a message and mail from people the user corresponds with teach the opposite.
//! Once it has seen enough of both, new mail it is confident about goes to Junk.
//!
//! Scoring follows Gary Robinson's method as used by SpamBayes: per-token probabilities
//! smoothed towards 0.5, the most telling tokens combined with Fisher's chi-square test.

use std::collections::{BTreeSet, HashMap};

use mail_parser::{MessageParser, MimeHeaders};
use sha2::{Digest, Sha256};
use sqlx::{QueryBuilder, Sqlite, SqlitePool};

use crate::{app::App, util::now};

/// Messages of each kind needed before the filter decides anything.
pub const MIN_LEARNED: i64 = 10;
/// Score from which a message counts as spam (SpamBayes' default cutoff).
pub const SPAM_CUTOFF: f64 = 0.9;
/// Distinct tokens taken from one message.
const MAX_TOKENS: usize = 3000;
/// Body text looked at, in bytes.
const MAX_TEXT: usize = 200_000;
/// Tokens combined into a score: the ones furthest from neutral.
const MAX_CLUES: usize = 150;
/// Tokens closer to 0.5 than this say nothing and are left out.
const MIN_STRENGTH: f64 = 0.1;
/// Robinson's smoothing: weight `S` of the assumed probability `X` for rarely seen tokens.
const S: f64 = 0.45;
const X: f64 = 0.5;

/// The tokens of a message, and a fingerprint identifying it across copies. `None` for
/// content the filter cannot read (unparsable, or stored encrypted).
pub fn tokenize(raw: &[u8]) -> Option<(String, Vec<String>)> {
    let message = MessageParser::default().parse(raw)?;
    if message.content_type().is_some_and(|ct| ct.ctype().eq_ignore_ascii_case("multipart") && ct.subtype().is_some_and(|s| s.eq_ignore_ascii_case("encrypted"))) {
        return None;
    }
    let mut tokens = BTreeSet::new();
    let add_words = |prefix: &str, text: &str, tokens: &mut BTreeSet<String>| {
        for word in text.split(|c: char| !c.is_alphanumeric() && c != '$' && c != '€').filter(|w| (3..=24).contains(&w.chars().count())) {
            if word.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if tokens.len() >= MAX_TOKENS {
                return;
            }
            tokens.insert(format!("{prefix}{}", word.to_lowercase()));
        }
    };
    if let Some(subject) = message.subject() {
        add_words("s:", subject, &mut tokens);
    }
    if let Some(from) = message.from().and_then(|f| f.first()) {
        if let Some(address) = from.address() {
            let address = address.to_lowercase();
            if let Some((_, domain)) = address.rsplit_once('@') {
                tokens.insert(format!("fd:{domain}"));
            }
            tokens.insert(format!("f:{address}"));
        }
        if let Some(name) = from.name() {
            add_words("fn:", name, &mut tokens);
        }
    }
    let mut text = String::new();
    for index in 0.. {
        let Some(part) = message.body_text(index) else { break };
        text.push_str(&part);
        text.push('\n');
        if text.len() > MAX_TEXT {
            break;
        }
    }
    let mut html = String::new();
    for index in 0.. {
        let Some(part) = message.body_html(index) else { break };
        html.push_str(&part);
        if html.len() > MAX_TEXT {
            break;
        }
    }
    // Where links lead says more than their wording.
    for source in [&text, &html] {
        for (start, _) in source.match_indices("://").take(200) {
            let host: String = source[start + 3..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-').collect();
            if host.contains('.') {
                tokens.insert(format!("u:{}", host.to_ascii_lowercase().trim_start_matches("www.")));
            }
        }
    }
    let mut cut = text.len().min(MAX_TEXT);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    add_words("", &text[..cut], &mut tokens);
    for part in &message.parts {
        if let Some(name) = part.attachment_name() {
            let extension = name.rsplit_once('.').map_or("", |(_, e)| e).to_ascii_lowercase();
            tokens.insert(format!("a:{extension}"));
        }
    }
    if tokens.is_empty() {
        return None;
    }
    // The Message-ID names the message in every copy (the stored one carries extra headers);
    // without one, its content does.
    let fingerprint = match message.message_id() {
        Some(id) if !id.is_empty() => hex(&Sha256::digest(format!("id:{id}").as_bytes())),
        _ => hex(&Sha256::digest(tokens.iter().cloned().collect::<Vec<_>>().join("\n").as_bytes())),
    };
    Some((fingerprint, tokens.into_iter().collect()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Tokens are stored as hashes: the statistics need no readable text.
pub(crate) fn token_id(token: &str) -> i64 {
    let digest = Sha256::digest(token.as_bytes());
    i64::from_le_bytes(digest[..8].try_into().expect("8 bytes"))
}

/// Training transactions read before they write. They start as writers (`BEGIN IMMEDIATE`,
/// which waits for the lock instead of failing when another connection wrote in between) and
/// take turns among themselves, so a burst of reports does not crowd out deliveries.
static TRAINING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Teaches the account's filter that a message is (or is not) spam. A message learned the
/// other way before is moved over; one learned the same way is left alone.
pub async fn learn(db: &SqlitePool, account_id: i64, raw: &[u8], spam: bool) -> sqlx::Result<()> {
    let Some((fingerprint, tokens)) = tokenize(raw) else { return Ok(()) };
    let _turn = TRAINING.lock().await;
    let mut tx = db.begin_with("BEGIN IMMEDIATE").await?;
    let previous: Option<i64> = sqlx::query_scalar("SELECT spam FROM bayes_learned WHERE account_id = ? AND fingerprint = ?")
        .bind(account_id)
        .bind(&fingerprint)
        .fetch_optional(&mut *tx)
        .await?;
    let (spam_delta, ham_delta) = match (previous, spam) {
        (Some(1), true) | (Some(0), false) => return Ok(()),
        (Some(_), true) => (1, -1),
        (Some(_), false) => (-1, 1),
        (None, true) => (1, 0),
        (None, false) => (0, 1),
    };
    for token in &tokens {
        sqlx::query(
            "INSERT INTO bayes_tokens (account_id, token, spam, ham) VALUES (?1, ?2, max(?3, 0), max(?4, 0))
             ON CONFLICT (account_id, token) DO UPDATE SET spam = max(spam + ?3, 0), ham = max(ham + ?4, 0)",
        )
        .bind(account_id)
        .bind(token_id(token))
        .bind(spam_delta)
        .bind(ham_delta)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("DELETE FROM bayes_tokens WHERE account_id = ? AND spam = 0 AND ham = 0").bind(account_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO bayes_learned (account_id, fingerprint, spam, learned_at) VALUES (?, ?, ?, ?) ON CONFLICT (account_id, fingerprint) DO UPDATE SET spam = excluded.spam, learned_at = excluded.learned_at")
        .bind(account_id)
        .bind(&fingerprint)
        .bind(spam)
        .bind(now())
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

/// How many messages of each kind the account's filter has learned.
pub async fn counts(db: &SqlitePool, account_id: i64) -> sqlx::Result<(i64, i64)> {
    let (spam, ham): (Option<i64>, Option<i64>) = sqlx::query_as("SELECT sum(spam), sum(1 - spam) FROM bayes_learned WHERE account_id = ?").bind(account_id).fetch_one(db).await?;
    Ok((spam.unwrap_or(0), ham.unwrap_or(0)))
}

/// Forgets everything the account's filter learned.
pub async fn reset(db: &SqlitePool, account_id: i64) -> sqlx::Result<()> {
    let _turn = TRAINING.lock().await;
    let mut tx = db.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query("DELETE FROM bayes_tokens WHERE account_id = ?").bind(account_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM bayes_learned WHERE account_id = ?").bind(account_id).execute(&mut *tx).await?;
    tx.commit().await
}

/// Upper tail of the chi-square distribution with `v` (even) degrees of freedom.
fn chi2q(x2: f64, v: usize) -> f64 {
    let m = x2 / 2.0;
    let mut term = (-m).exp();
    let mut sum = term;
    for i in 1..v / 2 {
        term *= m / i as f64;
        sum += term;
    }
    sum.min(1.0)
}

/// Combines per-token probabilities into a score from 0 (ham) to 1 (spam).
pub fn combine(mut probabilities: Vec<f64>) -> f64 {
    probabilities.retain(|p| (p - 0.5).abs() >= MIN_STRENGTH);
    probabilities.sort_by(|a, b| (b - 0.5).abs().total_cmp(&(a - 0.5).abs()));
    probabilities.truncate(MAX_CLUES);
    if probabilities.is_empty() {
        return 0.5;
    }
    let n = probabilities.len();
    let spam_log: f64 = probabilities.iter().map(|p| (1.0 - p).max(1e-200).ln()).sum();
    let ham_log: f64 = probabilities.iter().map(|p| p.max(1e-200).ln()).sum();
    let s = 1.0 - chi2q(-2.0 * spam_log, 2 * n);
    let h = 1.0 - chi2q(-2.0 * ham_log, 2 * n);
    (s - h + 1.0) / 2.0
}

/// Robinson's smoothed probability that a message containing the token is spam.
fn token_probability(spam: i64, ham: i64, total_spam: i64, total_ham: i64) -> f64 {
    let spam_ratio = spam as f64 / total_spam.max(1) as f64;
    let ham_ratio = ham as f64 / total_ham.max(1) as f64;
    let p = if spam_ratio + ham_ratio == 0.0 { X } else { spam_ratio / (spam_ratio + ham_ratio) };
    let n = (spam + ham) as f64;
    (S * X + n * p) / (S + n)
}

/// The account's spam score for a message, or `None` while the filter has not learned enough
/// (or cannot read the message).
pub async fn score(db: &SqlitePool, account_id: i64, raw: &[u8]) -> sqlx::Result<Option<f64>> {
    let (total_spam, total_ham) = counts(db, account_id).await?;
    if total_spam < MIN_LEARNED || total_ham < MIN_LEARNED {
        return Ok(None);
    }
    let Some((_, tokens)) = tokenize(raw) else { return Ok(None) };
    let ids: Vec<i64> = tokens.iter().map(|t| token_id(t)).collect();
    let mut known: HashMap<i64, (i64, i64)> = HashMap::new();
    for chunk in ids.chunks(500) {
        let mut query: QueryBuilder<Sqlite> = QueryBuilder::new("SELECT token, spam, ham FROM bayes_tokens WHERE account_id = ");
        query.push_bind(account_id).push(" AND token IN (");
        let mut list = query.separated(", ");
        for id in chunk {
            list.push_bind(*id);
        }
        query.push(")");
        for (token, spam, ham) in query.build_query_as::<(i64, i64, i64)>().fetch_all(db).await? {
            known.insert(token, (spam, ham));
        }
    }
    let probabilities = known.values().map(|&(spam, ham)| token_probability(spam, ham, total_spam, total_ham)).collect();
    Ok(Some(combine(probabilities)))
}

/// Whether the sender is someone the user corresponds with: in the address book, or written
/// to from this account. Their mail is never filed as spam by this filter, and teaches it ham.
pub async fn is_correspondent(db: &SqlitePool, account_id: i64, sender: &str) -> sqlx::Result<bool> {
    let sender = sender.trim().to_lowercase();
    if !sender.contains('@') {
        return Ok(false);
    }
    // Two key lookups: the address book, and the addresses written to (see `remember_recipients`).
    let found: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM correspondents WHERE account_id = ?1 AND address = ?2
         UNION ALL
         SELECT 1 FROM contacts WHERE account_id = ?1 AND lower(email) = ?2
         LIMIT 1",
    )
    .bind(account_id)
    .bind(&sender)
    .fetch_optional(db)
    .await?;
    Ok(found.is_some())
}

/// Notes the addresses a user sent mail to: they count as correspondents from now on.
pub async fn remember_recipients(db: &SqlitePool, account_id: i64, recipients: &[crate::util::Address]) -> sqlx::Result<()> {
    if recipients.is_empty() {
        return Ok(());
    }
    let mut query: QueryBuilder<Sqlite> = QueryBuilder::new("INSERT INTO correspondents (account_id, address, last_at) ");
    query.push_values(recipients.iter().take(500), |mut row, address| {
        row.push_bind(account_id).push_bind(address.to_string().to_lowercase()).push_bind(now());
    });
    query.push(" ON CONFLICT (account_id, address) DO UPDATE SET last_at = excluded.last_at");
    query.build().execute(db).await?;
    Ok(())
}

/// What the personal filter makes of a message arriving for `account_id`.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// Not enough training yet, the filter is off, or the message cannot be read.
    Undecided,
    /// From a correspondent: kept out of Junk, and learned as ham.
    Correspondent,
    Ham(f64),
    Spam(f64),
}

/// Whether the visible sender of a message received here can be believed: DMARC passed, it was
/// sent by a user of this server, or this server ran no checks (a trusted relay or local
/// network). A forged correspondent address must not get past the filter, or teach it.
pub fn sender_is_authentic(raw: &[u8], hostname: &str) -> bool {
    matches!(crate::security::summary::summarize(raw, hostname).verdict, "verified" | "internal" | "unknown")
}

pub async fn judge(app: &App, account_id: i64, author: &str, raw: &[u8]) -> Verdict {
    if !app.rt().personal_spam_filter {
        return Verdict::Undecided;
    }
    if sender_is_authentic(raw, &app.cfg.hostname) && is_correspondent(&app.db, account_id, author).await.unwrap_or(false) {
        return Verdict::Correspondent;
    }
    match score(&app.db, account_id, raw).await {
        Ok(Some(score)) if score >= SPAM_CUTOFF => Verdict::Spam(score),
        Ok(Some(score)) => Verdict::Ham(score),
        Ok(None) => Verdict::Undecided,
        Err(err) => {
            tracing::warn!(error = %err, "personal spam filter unavailable");
            Verdict::Undecided
        }
    }
}

/// Teaches both filters (this one, and Rspamd's shared statistics where configured). Runs in
/// the background; the user's action never waits for it.
pub fn train(app: &crate::app::AppState, account_id: i64, raw: Vec<u8>, spam: bool) {
    let app = app.clone();
    tokio::spawn(async move {
        if app.rt().personal_spam_filter
            && let Err(err) = learn(&app.db, account_id, &raw, spam).await
        {
            tracing::warn!(error = %err, "personal spam filter training failed");
        }
        // The source of the message earns its reputation from the decision too.
        if app.rt().sender_reputation {
            crate::security::filter::learn_from_message(&app, &raw, spam).await;
        }
        crate::security::rspamd::learn(&app, raw, spam).await;
    });
}

/// Trains from a stored message, read in the background.
pub fn train_blob(app: &crate::app::AppState, account_id: i64, blob_hash: &str, spam: bool) {
    let (app, blob_hash) = (app.clone(), blob_hash.to_owned());
    tokio::spawn(async move {
        if let Ok(raw) = app.store.read_blob(&blob_hash).await {
            train(&app, account_id, raw, spam);
        }
    });
}

/// A user filed a message: into Junk is spam, out of Junk (other than into Trash) is not.
pub fn train_on_move(app: &crate::app::AppState, account_id: i64, blob_hash: &str, source_mailbox: i64, target_mailbox: i64) {
    if source_mailbox == target_mailbox {
        return;
    }
    let (app, blob_hash) = (app.clone(), blob_hash.to_owned());
    tokio::spawn(async move {
        let role = |id: i64| {
            let app = app.clone();
            async move { app.store.mailbox(account_id, id).await.ok().and_then(|m| m.role) }
        };
        let spam = match (role(source_mailbox).await.as_deref(), role(target_mailbox).await.as_deref()) {
            (_, Some("junk")) => true,
            (Some("junk"), Some("trash")) => return,
            (Some("junk"), _) => false,
            _ => return,
        };
        train_blob(&app, account_id, &blob_hash, spam);
    });
}

/// IMAP clients (Thunderbird, Apple Mail) mark spam with keywords instead of moving it.
pub fn train_on_keywords(app: &crate::app::AppState, account_id: i64, blob_hash: &str, before: &[String], after: &[String]) {
    let has = |list: &[String], keyword: &str| list.iter().any(|k| k.eq_ignore_ascii_case(keyword));
    if has(after, "$junk") && !has(before, "$junk") {
        train_blob(app, account_id, blob_hash, true);
    } else if has(after, "$notjunk") && !has(before, "$notjunk") {
        train_blob(app, account_id, blob_hash, false);
    }
}

/// A reply shows that the message replied to was wanted: it is learned as ham (by this filter
/// only; it is local and quick, so the submission can wait for it).
pub async fn learn_from_reply(app: &App, account_id: i64, raw: &[u8]) {
    if !app.rt().personal_spam_filter {
        return;
    }
    let Some(parsed) = MessageParser::default().parse_headers(raw) else { return };
    let header = parsed.in_reply_to();
    let Some(parent) = header.as_text().or_else(|| header.as_text_list().and_then(|list| list.first().map(|id| id.as_ref()))) else { return };
    let parent = parent.trim_matches(['<', '>', ' ']).to_owned();
    let found: Option<String> = sqlx::query_scalar(
        "SELECT m.blob_hash FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id
          WHERE m.account_id = ? AND m.message_id IN (?, ?) AND coalesce(b.role, '') NOT IN ('sent', 'drafts', 'junk') LIMIT 1",
    )
    .bind(account_id)
    .bind(&parent)
    .bind(format!("<{parent}>"))
    .fetch_optional(&app.db)
    .await
    .ok()
    .flatten();
    if let Some(blob_hash) = found
        && let Ok(original) = app.store.read_blob(&blob_hash).await
        && let Err(err) = learn(&app.db, account_id, &original, false).await
    {
        tracing::warn!(error = %err, "personal spam filter training failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mail(from: &str, subject: &str, body: &str) -> Vec<u8> {
        format!("From: {from}\r\nTo: me@example.org\r\nSubject: {subject}\r\nMessage-ID: <{}@test>\r\n\r\n{body}\r\n", token_id(&format!("{subject}{body}"))).into_bytes()
    }

    #[test]
    fn tokens_cover_subject_sender_body_and_links() {
        let (fingerprint, tokens) = tokenize(&mail("Shop <deals@shop.example>", "Cheap watches", "Visit https://www.cheap.example/now for 90% off 12345")).unwrap();
        for expected in ["s:cheap", "s:watches", "f:deals@shop.example", "fd:shop.example", "fn:shop", "visit", "u:cheap.example"] {
            assert!(tokens.contains(&expected.to_owned()), "{expected} in {tokens:?}");
        }
        assert!(!tokens.iter().any(|t| t == "12345"), "plain numbers say nothing");
        assert_eq!(fingerprint.len(), 64);
        // The same message with other headers in front (as stored) has the same fingerprint.
        let stored = [b"Return-Path: <x@y>\r\nX-Spam-Status: No\r\n".as_slice(), &mail("Shop <deals@shop.example>", "Cheap watches", "Visit https://www.cheap.example/now for 90% off 12345")].concat();
        assert_eq!(tokenize(&stored).unwrap().0, fingerprint);
        assert!(tokenize(b"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=x\r\n\r\n--x--\r\n").is_none());
    }

    #[test]
    fn only_authentic_correspondents_count() {
        const HOST: &str = "mail.example.com";
        let with = |results: &str| format!("Received: from x ([198.51.100.7])\r\n\tby {HOST} with ESMTPS id a; date\r\nAuthentication-Results: {HOST}; {results}\r\nFrom: Anna <anna@partner.example>\r\nSubject: Hi\r\n\r\nbody\r\n").into_bytes();
        assert!(sender_is_authentic(&with("dkim=pass header.d=partner.example; spf=pass smtp.mailfrom=anna@partner.example; dmarc=pass header.from=partner.example"), HOST));
        assert!(!sender_is_authentic(&with("dkim=none; spf=softfail smtp.mailfrom=anna@partner.example; dmarc=fail header.from=partner.example"), HOST), "spoofed");
        assert!(!sender_is_authentic(&with("dkim=none; spf=pass smtp.mailfrom=x@other.example; dmarc=none header.from=partner.example"), HOST), "not aligned");
        assert!(sender_is_authentic(b"From: anna@partner.example\r\nSubject: local\r\n\r\nbody\r\n", HOST), "not checked here (trusted source)");
    }

    #[test]
    fn combining_clues() {
        assert_eq!(combine(vec![]), 0.5);
        assert_eq!(combine(vec![0.5, 0.55, 0.45]), 0.5, "neutral tokens are ignored");
        assert!(combine(vec![0.99; 20]) > 0.99);
        assert!(combine(vec![0.01; 20]) < 0.01);
        let mixed = combine([vec![0.99; 10], vec![0.01; 10]].concat());
        assert!((mixed - 0.5).abs() < 0.05, "{mixed}");
        assert!(token_probability(5, 0, 10, 10) > 0.8 && token_probability(0, 5, 10, 10) < 0.2);
        assert_eq!(token_probability(0, 0, 10, 10), 0.5);
    }

    async fn db() -> SqlitePool {
        // One connection: every connection to ":memory:" is a database of its own. Foreign keys
        // are off so the statistics can be tested without creating an account.
        let options = <sqlx::sqlite::SqliteConnectOptions as std::str::FromStr>::from_str("sqlite::memory:").unwrap().foreign_keys(false);
        let db = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect_with(options).await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        db
    }

    #[tokio::test]
    async fn learns_scores_and_changes_its_mind() {
        let db = db().await;
        let account = 7;
        let spam = |i: usize| mail("Prize Desk <winner@lottery.example>", &format!("You won {i} million"), &format!("Claim your prize now at https://claim.lottery.example/{i} urgent winner transfer fee {i}"));
        let ham = |i: usize| mail("Anna <anna@example.net>", &format!("Minutes of meeting {i}"), &format!("Hi, attached are the notes from our project meeting number {i}. Let us discuss the schedule tomorrow."));

        for i in 0..MIN_LEARNED as usize {
            learn(&db, account, &spam(i), true).await.unwrap();
            assert_eq!(score(&db, account, &spam(99)).await.unwrap(), None, "no verdict before enough ham");
            learn(&db, account, &ham(i), false).await.unwrap();
        }
        assert_eq!(counts(&db, account).await.unwrap(), (MIN_LEARNED, MIN_LEARNED));
        // Learning the same message twice counts once.
        learn(&db, account, &spam(0), true).await.unwrap();
        assert_eq!(counts(&db, account).await.unwrap(), (MIN_LEARNED, MIN_LEARNED));

        let new_spam = score(&db, account, &spam(42)).await.unwrap().unwrap();
        let new_ham = score(&db, account, &ham(42)).await.unwrap().unwrap();
        assert!(new_spam >= SPAM_CUTOFF, "{new_spam}");
        assert!(new_ham < 0.2, "{new_ham}");

        // "Not spam" on a message learned as spam moves it over.
        learn(&db, account, &spam(1), false).await.unwrap();
        assert_eq!(counts(&db, account).await.unwrap(), (MIN_LEARNED - 1, MIN_LEARNED + 1));

        reset(&db, account).await.unwrap();
        assert_eq!(counts(&db, account).await.unwrap(), (0, 0));
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM bayes_tokens").fetch_one(&db).await.unwrap();
        assert_eq!(left, 0);
    }
}
