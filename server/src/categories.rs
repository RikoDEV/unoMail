//! Inbox categories: incoming mail is sorted into General, Offers, Communities, Notifications
//! and Forums from what its headers say about how it was sent. The category is stored as a
//! keyword on the message (`$cat_<name>`), so it is visible to every protocol and can be
//! changed by the user; General is simply the absence of such a keyword.
//!
//! The header rules are only where a new account starts. Each account learns from the user
//! moving messages between categories (see [`learn`] and [`categorize`]).

use std::collections::HashMap;

use mail_parser::{HeaderValue, MessageParser};
use sqlx::{QueryBuilder, Sqlite, SqlitePool};


pub const PREFIX: &str = "$cat_";
/// Categories other than General, in display order.
pub const NAMES: [&str; 4] = ["offers", "communities", "notifications", "forums"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    General,
    Offers,
    Communities,
    Notifications,
    Forums,
}

impl Category {
    pub const ALL: [Category; 5] = [Category::General, Category::Offers, Category::Communities, Category::Notifications, Category::Forums];

    /// The keyword that marks a message as belonging to this category; none for General.
    pub fn keyword(self) -> Option<&'static str> {
        match self {
            Category::General => None,
            Category::Offers => Some("$cat_offers"),
            Category::Communities => Some("$cat_communities"),
            Category::Notifications => Some("$cat_notifications"),
            Category::Forums => Some("$cat_forums"),
        }
    }

    pub fn name(self) -> &'static str {
        self.keyword().and_then(|keyword| keyword.strip_prefix(PREFIX)).unwrap_or("general")
    }

    pub fn from_name(name: &str) -> Option<Category> {
        Category::ALL.into_iter().find(|category| category.name() == name)
    }

    /// The category a message's keywords put it in.
    pub fn of_keywords(keywords: &[String]) -> Category {
        keywords.iter().find_map(|keyword| keyword.to_ascii_lowercase().strip_prefix(PREFIX).and_then(Category::from_name)).unwrap_or(Category::General)
    }
}

pub fn valid_name(name: &str) -> bool {
    name == "general" || NAMES.contains(&name)
}

/// Social networks and community platforms, by the domain their mail comes from.
const COMMUNITY_DOMAINS: [&str; 24] = [
    "facebook.com", "facebookmail.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "pinterest.com", "reddit.com", "redditmail.com",
    "youtube.com", "tiktok.com", "discord.com", "snapchat.com", "tumblr.com", "meetup.com", "nextdoor.com", "strava.com", "twitch.tv",
    "mastodon.social", "threads.net", "bsky.app", "quora.com", "vk.com", "goodreads.com",
];

/// Headers set by bulk-mail platforms on marketing campaigns.
const CAMPAIGN_HEADERS: [&str; 8] = ["X-Campaign", "X-CampaignId", "X-Campaign-Id", "X-MC-User", "X-Mailgun-Tag", "X-SES-Outgoing", "X-Mailer-Campaign", "Feedback-ID"];

const TRANSACTIONAL_SENDERS: [&str; 20] = [
    "noreply", "no-reply", "no_reply", "donotreply", "do-not-reply", "notification", "notifications", "notify", "alerts", "alert", "billing", "invoice", "invoices",
    "receipts", "orders", "support", "security", "account", "accounts", "mailer-daemon",
];

const TRANSACTIONAL_WORDS: [&str; 30] = [
    "invoice", "receipt", "order", "payment", "shipped", "shipping", "delivery", "delivered", "confirmation", "confirm your", "verify", "verification", "password",
    "security alert", "sign-in", "login", "statement", "reminder", "ticket", "booking", "reservation", "subscription", "renewal", "build", "deploy", "faktura", "zamówieni",
    "płatnoś", "potwierdzenie", "hasło",
];

const PROMOTIONAL_WORDS: [&str; 24] = [
    "% off", "sale", "discount", "deal", "offer", "promo", "coupon", "save ", "free shipping", "newsletter", "black friday", "cyber monday", "limited time", "new arrivals",
    "exclusive", "clearance", "this week", "last chance", "rabat", "promocj", "wyprzeda", "oferta", "kupon", "zniżk",
];

fn has(value: &HeaderValue<'_>) -> bool {
    !matches!(value, HeaderValue::Empty)
}

/// Whether `domain` is `suffix` or one of its subdomains.
fn within(domain: &str, suffix: &str) -> bool {
    domain == suffix || domain.strip_suffix(suffix).is_some_and(|rest| rest.ends_with('.'))
}

/// Decides the category of a message from its headers. Deliberately simple and explainable:
/// who sent it (a social network?), how it was sent (a mailing list? a bulk campaign? an
/// automatic system?) and, as a tie-breaker, what the subject says.
pub fn classify(raw: &[u8]) -> Category {
    let Some(message) = MessageParser::default().parse_headers(raw) else { return Category::General };
    let header = |name: &str| message.header(name).is_some_and(has);
    let text = |name: &str| message.header(name).and_then(|value| value.as_text()).unwrap_or("").to_ascii_lowercase();
    let from = message.from().and_then(|list| list.first()).and_then(|address| address.address()).unwrap_or("").to_ascii_lowercase();
    let (local, domain) = from.rsplit_once('@').unwrap_or(("", ""));
    let subject = message.subject().unwrap_or("").to_lowercase();

    if COMMUNITY_DOMAINS.iter().any(|suffix| within(domain, suffix)) {
        return Category::Communities;
    }
    // A discussion list: it has an identity and an address to post to.
    let precedence = text("Precedence");
    if header("List-Id") && (header("List-Post") || precedence == "list") {
        return Category::Forums;
    }
    let transactional_subject = TRANSACTIONAL_WORDS.iter().any(|word| subject.contains(word));
    let promotional_subject = PROMOTIONAL_WORDS.iter().any(|word| subject.contains(word));
    let bulk = header("List-Unsubscribe") || precedence == "bulk" || CAMPAIGN_HEADERS.iter().any(|name| header(name));
    if bulk {
        // Bulk mail is an offer unless it is clearly about something the reader did.
        return if transactional_subject && !promotional_subject { Category::Notifications } else { Category::Offers };
    }
    // Generated by a system. Automatic *replies* (out-of-office notes) answer the reader's own
    // mail and stay in General.
    let automatic = text("Auto-Submitted") == "auto-generated";
    let system_sender = TRANSACTIONAL_SENDERS.iter().any(|name| local == *name || local.starts_with(&format!("{name}-")) || local.starts_with(&format!("{name}+")) || local.starts_with(&format!("{name}.")));
    if automatic || system_sender || (transactional_subject && header("List-Id")) {
        return Category::Notifications;
    }
    Category::General
}

// --- Learning from the user ----------------------------------------------------------------
//
// Every time the user moves a message to another category, the account learns from it twice:
// - the sender: later mail from that address goes where the user last put its mail;
// - the content: a naive Bayes classifier over the personal spam filter's tokens, trained on
//   every corrected message. It overrules the header rules once it has seen enough examples
//   of both the category the rules chose and its own, and only when it is confident.

/// Corrected messages of a category needed before the classifier speaks for or against it.
pub const MIN_LEARNED: i64 = 5;
/// Probability from which the classifier's choice replaces the header rules'.
const CONFIDENCE: f64 = 0.9;
/// Tokens combined into a decision: the ones that tell the categories apart most.
const MAX_CLUES: usize = 60;
/// Laplace smoothing of the per-category token frequencies.
const ALPHA: f64 = 0.5;

/// One learning transaction at a time, as for the spam filter (they read before they write).
static TRAINING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn sender_of(raw: &[u8]) -> String {
    crate::store::parse_metadata(raw).from_addr.trim().to_lowercase()
}

/// Teaches the account that a message belongs in `category`. A message learned before under
/// another category is moved over.
pub async fn learn(db: &SqlitePool, account_id: i64, raw: &[u8], category: Category) -> sqlx::Result<()> {
    let Some((fingerprint, tokens)) = crate::bayes::tokenize(raw) else { return Ok(()) };
    let _turn = TRAINING.lock().await;
    let mut tx = db.begin_with("BEGIN IMMEDIATE").await?;
    let previous: Option<String> = sqlx::query_scalar("SELECT category FROM category_learned WHERE account_id = ? AND fingerprint = ?")
        .bind(account_id)
        .bind(&fingerprint)
        .fetch_optional(&mut *tx)
        .await?;
    if previous.as_deref() != Some(category.name()) {
        for token in &tokens {
            let token = crate::bayes::token_id(token);
            if let Some(previous) = &previous {
                sqlx::query("UPDATE category_tokens SET count = count - 1 WHERE account_id = ? AND token = ? AND category = ?")
                    .bind(account_id)
                    .bind(token)
                    .bind(previous)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("INSERT INTO category_tokens (account_id, token, category, count) VALUES (?, ?, ?, 1) ON CONFLICT (account_id, token, category) DO UPDATE SET count = count + 1")
                .bind(account_id)
                .bind(token)
                .bind(category.name())
                .execute(&mut *tx)
                .await?;
        }
        if previous.is_some() {
            sqlx::query("DELETE FROM category_tokens WHERE account_id = ? AND count <= 0").bind(account_id).execute(&mut *tx).await?;
        }
    }
    // Learned again (even the same way) counts as the latest word on its sender. Times are in
    // milliseconds and strictly increase per account, so "latest" is never a tie.
    let millis = (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64;
    sqlx::query(
        "INSERT INTO category_learned (account_id, fingerprint, category, sender, learned_at)
         VALUES (?1, ?2, ?3, ?4, max(?5, coalesce((SELECT max(learned_at) + 1 FROM category_learned WHERE account_id = ?1), 0)))
         ON CONFLICT (account_id, fingerprint) DO UPDATE SET category = excluded.category, learned_at = excluded.learned_at",
    )
    .bind(account_id)
    .bind(&fingerprint)
    .bind(category.name())
    .bind(sender_of(raw))
    .bind(millis)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// How many corrected messages the account has learned, per category.
pub async fn counts(db: &SqlitePool, account_id: i64) -> sqlx::Result<HashMap<Category, i64>> {
    let rows: Vec<(String, i64)> = sqlx::query_as("SELECT category, count(*) FROM category_learned WHERE account_id = ? GROUP BY category").bind(account_id).fetch_all(db).await?;
    Ok(rows.into_iter().filter_map(|(name, count)| Some((Category::from_name(&name)?, count))).collect())
}

/// Senders whose mail the account files by what the user did with it.
pub async fn sender_count(db: &SqlitePool, account_id: i64) -> sqlx::Result<i64> {
    sqlx::query_scalar("SELECT count(DISTINCT sender) FROM category_learned WHERE account_id = ? AND sender <> ''").bind(account_id).fetch_one(db).await
}

/// Forgets everything the account learned about categories.
pub async fn reset(db: &SqlitePool, account_id: i64) -> sqlx::Result<()> {
    let _turn = TRAINING.lock().await;
    let mut tx = db.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query("DELETE FROM category_tokens WHERE account_id = ?").bind(account_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM category_learned WHERE account_id = ?").bind(account_id).execute(&mut *tx).await?;
    tx.commit().await
}

/// Where the user last put mail from `sender`.
async fn sender_category(db: &SqlitePool, account_id: i64, sender: &str) -> sqlx::Result<Option<Category>> {
    if sender.is_empty() {
        return Ok(None);
    }
    let name: Option<String> = sqlx::query_scalar("SELECT category FROM category_learned WHERE account_id = ? AND sender = ? ORDER BY learned_at DESC LIMIT 1")
        .bind(account_id)
        .bind(sender)
        .fetch_optional(db)
        .await?;
    Ok(name.as_deref().and_then(Category::from_name))
}

/// The classifier's choice among the categories it has learned enough of, with its
/// probability; `None` before it knows at least two of them.
pub async fn predict(db: &SqlitePool, account_id: i64, raw: &[u8]) -> sqlx::Result<Option<(Category, f64)>> {
    let learned = counts(db, account_id).await?;
    let candidates: Vec<(Category, i64)> = Category::ALL.into_iter().filter_map(|c| learned.get(&c).filter(|n| **n >= MIN_LEARNED).map(|n| (c, *n))).collect();
    if candidates.len() < 2 {
        return Ok(None);
    }
    let Some((_, tokens)) = crate::bayes::tokenize(raw) else { return Ok(None) };
    let ids: Vec<i64> = tokens.iter().map(|t| crate::bayes::token_id(t)).collect();
    let mut known: HashMap<i64, HashMap<String, i64>> = HashMap::new();
    for chunk in ids.chunks(500) {
        let mut query: QueryBuilder<Sqlite> = QueryBuilder::new("SELECT token, category, count FROM category_tokens WHERE account_id = ");
        query.push_bind(account_id).push(" AND token IN (");
        let mut list = query.separated(", ");
        for id in chunk {
            list.push_bind(*id);
        }
        query.push(")");
        for (token, category, count) in query.build_query_as::<(i64, String, i64)>().fetch_all(db).await? {
            known.entry(token).or_default().insert(category, count);
        }
    }
    // Per token, the log-probability of seeing it in a message of each candidate category.
    let mut clues: Vec<Vec<f64>> = known
        .values()
        .map(|per_category| candidates.iter().map(|(c, n)| ((per_category.get(c.name()).copied().unwrap_or(0) as f64 + ALPHA) / (*n as f64 + 2.0 * ALPHA)).ln()).collect())
        .collect();
    let spread = |logs: &Vec<f64>| logs.iter().copied().fold(f64::MIN, f64::max) - logs.iter().copied().fold(f64::MAX, f64::min);
    clues.sort_by(|a, b| spread(b).total_cmp(&spread(a)));
    clues.truncate(MAX_CLUES);
    if clues.is_empty() {
        return Ok(None);
    }
    // Equal priors: how often the user corrected towards a category says little about new mail.
    let totals: Vec<f64> = (0..candidates.len()).map(|i| clues.iter().map(|logs| logs[i]).sum()).collect();
    let best = totals.iter().copied().fold(f64::MIN, f64::max);
    let weights: Vec<f64> = totals.iter().map(|total| (total - best).exp()).collect();
    let sum: f64 = weights.iter().sum();
    let (index, weight) = weights.iter().copied().enumerate().max_by(|a, b| a.1.total_cmp(&b.1)).expect("two candidates");
    Ok(Some((candidates[index].0, weight / sum)))
}

/// The category of a message arriving for `account_id`: where the user files its sender, else
/// the learned classifier when it knows better than the header rules, else the rules.
pub async fn categorize(db: &SqlitePool, account_id: i64, raw: &[u8]) -> Category {
    let rules = classify(raw);
    let learned = async {
        if let Some(category) = sender_category(db, account_id, &sender_of(raw)).await? {
            return Ok(Some(category));
        }
        let known = counts(db, account_id).await?;
        // The classifier may only overrule a choice it has seen examples of.
        if known.get(&rules).copied().unwrap_or(0) < MIN_LEARNED {
            return Ok(None);
        }
        Ok::<_, sqlx::Error>(predict(db, account_id, raw).await?.filter(|(_, p)| *p >= CONFIDENCE).map(|(category, _)| category))
    };
    match learned.await {
        Ok(Some(category)) => category,
        Ok(None) => rules,
        Err(err) => {
            tracing::warn!(error = %err, "learned inbox categories unavailable");
            rules
        }
    }
}

/// The user changed a message's keywords: a different category is a correction to learn from.
/// Runs in the background; the user's action never waits for it.
pub fn train_on_keywords(app: &crate::app::AppState, account_id: i64, blob_hash: &str, before: &[String], after: &[String]) {
    let category = Category::of_keywords(after);
    if category == Category::of_keywords(before) {
        return;
    }
    let (app, blob_hash) = (app.clone(), blob_hash.to_owned());
    tokio::spawn(async move {
        if let Ok(raw) = app.store.read_blob(&blob_hash).await
            && let Err(err) = learn(&app.db, account_id, &raw, category).await
        {
            tracing::warn!(error = %err, "inbox category training failed");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn category(headers: &str) -> Category {
        classify(format!("{headers}\r\n\r\nbody\r\n").as_bytes())
    }

    #[test]
    fn personal_mail_stays_in_general() {
        assert_eq!(category("From: Anna <anna@partner.example>\r\nSubject: Lunch on Thursday?"), Category::General);
        assert_eq!(category("From: boss@example.org\r\nSubject: Re: the order of slides in my talk"), Category::General);
        assert_eq!(classify(b"not a message at all"), Category::General);
        assert_eq!(classify(b""), Category::General);
    }

    #[test]
    fn marketing_goes_to_offers() {
        assert_eq!(category("From: Shop <news@shop.example>\r\nSubject: 30% off everything\r\nList-Unsubscribe: <https://shop.example/u>"), Category::Offers);
        assert_eq!(category("From: news@brand.example\r\nSubject: Our autumn collection\r\nPrecedence: bulk"), Category::Offers);
        assert_eq!(category("From: hello@brand.example\r\nSubject: Hello\r\nX-MC-User: abc123"), Category::Offers);
        // A sale announced with a transactional-looking word is still an offer.
        assert_eq!(category("From: deals@shop.example\r\nSubject: Flash sale: free delivery on every order\r\nList-Unsubscribe: <mailto:u@shop.example>"), Category::Offers);
    }

    #[test]
    fn automatic_mail_goes_to_notifications() {
        assert_eq!(category("From: no-reply@bank.example\r\nSubject: Your statement"), Category::Notifications);
        assert_eq!(category("From: billing@hosting.example\r\nSubject: Invoice 2026-10 is ready"), Category::Notifications);
        assert_eq!(category("From: ci@builds.example\r\nSubject: Build passed\r\nAuto-Submitted: auto-generated"), Category::Notifications);
        assert_eq!(category("From: anna@partner.example\r\nSubject: Out of office\r\nAuto-Submitted: auto-replied"), Category::General);
        assert_eq!(category("From: shop@shop.example\r\nSubject: Your order has shipped\r\nList-Unsubscribe: <https://shop.example/u>"), Category::Notifications);
        assert_eq!(category("From: notifications+abc@service.example\r\nSubject: New comment"), Category::Notifications);
        // Not fooled by a local part that merely begins with the same letters.
        assert_eq!(category("From: supporter@club.example\r\nSubject: See you there"), Category::General);
    }

    #[test]
    fn social_networks_and_mailing_lists() {
        assert_eq!(category("From: LinkedIn <messages-noreply@linkedin.com>\r\nSubject: You have a new invitation"), Category::Communities);
        assert_eq!(category("From: notification@em.facebookmail.com\r\nSubject: Someone commented\r\nList-Unsubscribe: <https://x.example>"), Category::Communities);
        assert_eq!(category("From: someone@notlinkedin.com\r\nSubject: Hi"), Category::General, "a look-alike domain is not the network");
        assert_eq!(category("From: dev@lists.example\r\nSubject: [dev] RFC: new API\r\nList-Id: <dev.lists.example>\r\nList-Post: <mailto:dev@lists.example>\r\nList-Unsubscribe: <mailto:x@lists.example>"), Category::Forums);
        assert_eq!(category("From: a@b.example\r\nSubject: x\r\nList-Id: <announce.b.example>\r\nPrecedence: list"), Category::Forums);
    }

    #[test]
    fn keywords_and_names() {
        assert_eq!(Category::General.keyword(), None);
        for name in NAMES {
            assert!(valid_name(name));
        }
        assert!(valid_name("general") && !valid_name("spam") && !valid_name(""));
        assert_eq!(Category::Forums.keyword(), Some("$cat_forums"));
        for category in Category::ALL {
            assert_eq!(Category::from_name(category.name()), Some(category));
        }
        assert_eq!(Category::of_keywords(&["work".into(), "$Cat_Offers".into()]), Category::Offers);
        assert_eq!(Category::of_keywords(&["$cat_spam".into()]), Category::General);
    }

    async fn db() -> SqlitePool {
        // One connection, as ":memory:" is a database per connection; no accounts needed.
        let options = <sqlx::sqlite::SqliteConnectOptions as std::str::FromStr>::from_str("sqlite::memory:").unwrap().foreign_keys(false);
        let db = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect_with(options).await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        db
    }

    fn mail(from: &str, subject: &str, body: &str) -> Vec<u8> {
        format!("From: {from}\r\nTo: me@example.org\r\nSubject: {subject}\r\nMessage-ID: <{}.{}@test>\r\n\r\n{body}\r\n", subject.len(), crate::bayes::token_id(&format!("{from}{subject}{body}"))).into_bytes()
    }

    #[tokio::test]
    async fn remembers_where_the_user_files_a_sender() {
        let db = db().await;
        let digest = |i: usize| mail("Weekly <digest@club.example>", &format!("Club digest {i}"), "What happened at the club this week.");
        assert_eq!(categorize(&db, 1, &digest(1)).await, Category::General, "the rules know nothing about it");
        learn(&db, 1, &digest(1), Category::Forums).await.unwrap();
        assert_eq!(categorize(&db, 1, &digest(2)).await, Category::Forums);
        assert_eq!(categorize(&db, 2, &digest(2)).await, Category::General, "other accounts are unaffected");
        // The latest decision wins, and moving the same message again does not count it twice.
        learn(&db, 1, &digest(3), Category::Offers).await.unwrap();
        assert_eq!(categorize(&db, 1, &digest(4)).await, Category::Offers);
        learn(&db, 1, &digest(1), Category::Offers).await.unwrap();
        assert_eq!(counts(&db, 1).await.unwrap(), HashMap::from([(Category::Offers, 2)]));
        assert_eq!(sender_count(&db, 1).await.unwrap(), 1);
        reset(&db, 1).await.unwrap();
        assert_eq!(categorize(&db, 1, &digest(5)).await, Category::General);
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM category_tokens").fetch_one(&db).await.unwrap();
        assert_eq!(left, 0);
    }

    #[tokio::test]
    async fn learns_what_new_senders_mail_is_about() {
        let db = db().await;
        let promo = |i: usize| mail(&format!("Store {i} <hello@store{i}.example>"), &format!("Weekend coupon {i}"), &format!("Use coupon code SAVE{i} for a discount on sneakers and jackets at https://store{i}.example/shop. Offer valid this weekend."));
        let personal = |i: usize| mail(&format!("Friend {i} <friend{i}@people.example>"), &format!("Dinner plans {i}"), &format!("Hi, shall we meet for dinner on Friday? Bring the photos from the trip, I cannot wait to hear about it. Number {i}."));
        // Without List-Unsubscribe the rules leave these promotions in General.
        assert_eq!(classify(&promo(99)), Category::General);
        for i in 0..MIN_LEARNED as usize - 1 {
            learn(&db, 1, &promo(i), Category::Offers).await.unwrap();
            learn(&db, 1, &personal(i), Category::General).await.unwrap();
        }
        assert_eq!(predict(&db, 1, &promo(99)).await.unwrap(), None, "not enough examples yet");
        assert_eq!(categorize(&db, 1, &promo(99)).await, Category::General);
        learn(&db, 1, &promo(50), Category::Offers).await.unwrap();
        learn(&db, 1, &personal(50), Category::General).await.unwrap();
        assert_eq!(categorize(&db, 1, &promo(99)).await, Category::Offers);
        assert_eq!(categorize(&db, 1, &personal(99)).await, Category::General);
        // A category the classifier has no examples of is still decided by the rules.
        let forum = [b"List-Id: <dev.lists.example>\r\nList-Post: <mailto:dev@lists.example>\r\n".as_slice(), &mail("dev@lists.example", "[dev] coupon code discount", "x")].concat();
        assert_eq!(categorize(&db, 1, &forum).await, Category::Forums);
    }
}
