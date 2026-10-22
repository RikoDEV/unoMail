//! Mail storage: content-addressed message blobs on disk, metadata in SQLite.

use std::path::Path;

use mail_parser::MessageParser;
use serde::Serialize;
use sqlx::SqlitePool;
use tokio::sync::broadcast;

use crate::util::{now, sha256_hex};

pub const DEFAULT_MAILBOXES: &[(&str, &str)] = &[
    ("INBOX", "inbox"),
    ("Sent", "sent"),
    ("Drafts", "drafts"),
    ("Junk", "junk"),
    ("Trash", "trash"),
    ("Archive", "archive"),
];

pub const MAX_MAILBOX_NAME_LEN: usize = 200;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("mailbox quota exceeded")]
    QuotaExceeded,
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("already exists")]
    Exists,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<StoreError> for crate::error::ApiError {
    fn from(err: StoreError) -> Self {
        use crate::error::ApiError;
        match err {
            StoreError::QuotaExceeded => ApiError::bad("mailbox quota exceeded"),
            StoreError::NotFound => ApiError::NotFound,
            StoreError::Invalid(msg) => ApiError::bad(msg),
            StoreError::Exists => ApiError::Conflict("already exists".into()),
            StoreError::Db(e) => e.into(),
            StoreError::Io(e) => e.into(),
        }
    }
}

/// Emitted whenever the contents of a mailbox change (IMAP IDLE, web push).
#[derive(Debug, Clone, Copy)]
pub struct Change {
    pub account_id: i64,
    pub mailbox_id: i64,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Mailbox {
    pub id: i64,
    pub account_id: i64,
    pub name: String,
    pub role: Option<String>,
    pub uid_validity: i64,
    pub uid_next: i64,
    pub highest_modseq: i64,
    pub subscribed: bool,
}

#[derive(Debug, Clone, Default, Serialize, sqlx::FromRow)]
pub struct MailboxCounts {
    pub total: i64,
    pub unread: i64,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Message {
    pub id: i64,
    pub account_id: i64,
    pub mailbox_id: i64,
    pub uid: i64,
    pub blob_hash: String,
    pub size: i64,
    pub internal_date: i64,
    pub modseq: i64,
    pub seen: bool,
    pub answered: bool,
    pub flagged: bool,
    pub deleted: bool,
    pub draft: bool,
    pub keywords: String,
    pub thread_id: i64,
    pub message_id: String,
    pub subject: String,
    pub from_addr: String,
    pub from_name: String,
    pub to_addrs: String,
    pub snippet: String,
    pub has_attachments: bool,
    pub sent_date: i64,
}

pub const MESSAGE_COLUMNS: &str = "id, account_id, mailbox_id, uid, blob_hash, size, internal_date, modseq, seen, answered, \
     flagged, deleted, draft, keywords, thread_id, message_id, subject, from_addr, from_name, to_addrs, snippet, \
     has_attachments, sent_date";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    pub seen: bool,
    pub answered: bool,
    pub flagged: bool,
    pub deleted: bool,
    pub draft: bool,
}

/// Coalesced changes to one object type since a given state.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ChangeSet {
    pub created: Vec<i64>,
    pub updated: Vec<i64>,
    pub destroyed: Vec<i64>,
    /// Threads touched by the email changes.
    pub threads: Vec<i64>,
    pub new_state: i64,
    pub has_more: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Appended {
    pub id: i64,
    pub uid: i64,
    pub thread_id: i64,
}

/// Header-derived metadata cached alongside each message.
#[derive(Debug, Default, PartialEq)]
pub struct Parsed {
    pub message_id: String,
    pub in_reply_to: String,
    pub references: Vec<String>,
    pub subject: String,
    pub from_addr: String,
    pub from_name: String,
    pub to_addrs: String,
    pub snippet: String,
    pub has_attachments: bool,
    pub sent_date: i64,
}

fn clip(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

pub fn parse_metadata(raw: &[u8]) -> Parsed {
    let Some(msg) = MessageParser::default().parse(raw) else {
        return Parsed::default();
    };
    let ids = |v: &mail_parser::HeaderValue| -> Vec<String> {
        v.as_text_list().map(|l| l.iter().map(|s| clip(s, 500)).collect()).unwrap_or_default()
    };
    let from = msg.from().and_then(|a| a.first());
    let to = msg
        .to()
        .map(|a| a.iter().filter_map(|x| x.address()).map(|s| clip(s, 320)).collect::<Vec<_>>().join(", "))
        .unwrap_or_default();
    let snippet = msg.body_preview(200).map(|s| s.split_whitespace().collect::<Vec<_>>().join(" ")).unwrap_or_default();
    Parsed {
        message_id: msg.message_id().map(|s| clip(s, 500)).unwrap_or_default(),
        in_reply_to: ids(msg.in_reply_to()).into_iter().next().unwrap_or_default(),
        references: ids(msg.references()),
        subject: msg.subject().map(|s| clip(s, 500)).unwrap_or_default(),
        from_addr: from.and_then(|a| a.address()).map(|s| clip(s, 320).to_lowercase()).unwrap_or_default(),
        from_name: from.and_then(|a| a.name()).map(|s| clip(s, 200)).unwrap_or_default(),
        to_addrs: clip(&to, 2000),
        snippet: clip(&snippet, 200),
        has_attachments: msg.attachment_count() > 0,
        sent_date: msg.date().map(|d| d.to_timestamp()).unwrap_or(0),
    }
}

/// Mailbox names are user controlled and end up in IMAP responses and SQL LIKE patterns.
pub fn validate_mailbox_name(name: &str) -> Result<(), StoreError> {
    let bad = name.is_empty()
        || name.len() > MAX_MAILBOX_NAME_LEN
        || name.starts_with('/')
        || name.ends_with('/')
        || name.contains("//")
        || name.chars().any(|c| c.is_control() || matches!(c, '%' | '*' | '\\' | '"'))
        // The namespace under which other users' shared mailboxes appear.
        || name == "Shared"
        || name.starts_with(crate::sharing::SHARED_PREFIX);
    if bad { Err(StoreError::Invalid("invalid mailbox name")) } else { Ok(()) }
}

#[derive(Clone)]
pub struct Store {
    pub db: SqlitePool,
    pub blobs: std::sync::Arc<crate::blobstore::Blobs>,
    changes: broadcast::Sender<Change>,
    /// The store's write transactions take turns here. SQLite admits one writer at a time and
    /// makes the others retry with growing sleeps (up to 100 ms each), which under parallel
    /// deliveries cost far more than the writes themselves.
    writes: std::sync::Arc<tokio::sync::Mutex<()>>,
}

impl Store {
    /// A store keeping message contents in `<data_dir>/blobs`, unencrypted.
    pub fn new(db: SqlitePool, data_dir: &Path) -> std::io::Result<Self> {
        let blob_dir = data_dir.join("blobs");
        std::fs::create_dir_all(&blob_dir)?;
        Ok(Self::with_blobs(db, crate::blobstore::Blobs::new(crate::blobstore::Backend::Disk(blob_dir), None)))
    }

    pub fn with_blobs(db: SqlitePool, blobs: crate::blobstore::Blobs) -> Self {
        let (changes, _) = broadcast::channel(256);
        Store { db, blobs: std::sync::Arc::new(blobs), changes, writes: std::sync::Arc::new(tokio::sync::Mutex::new(())) }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Change> {
        self.changes.subscribe()
    }

    fn notify(&self, account_id: i64, mailbox_id: i64) {
        let _ = self.changes.send(Change { account_id, mailbox_id });
    }

    /// Hashes come from the database, but never use anything that is not exactly a lowercase
    /// sha256 digest as a blob address.
    fn check_hash(hash: &str) -> Result<(), StoreError> {
        if hash.len() != 64 || !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(StoreError::Invalid("invalid blob id"));
        }
        Ok(())
    }

    /// A write transaction, begun as soon as it is this one's turn (see `writes`).
    async fn begin_write(&self) -> Result<(tokio::sync::MutexGuard<'_, ()>, sqlx::Transaction<'static, sqlx::Sqlite>), StoreError> {
        let turn = self.writes.lock().await;
        let tx = self.db.begin_with("BEGIN IMMEDIATE").await?;
        Ok((turn, tx))
    }

    pub async fn put_blob(&self, data: &[u8]) -> Result<String, StoreError> {
        let hash = sha256_hex(data);
        // Register the blob before writing so the collector never sees an untracked file as
        // older than it is.
        sqlx::query("INSERT INTO blobs (hash, size, created_at) VALUES (?, ?, ?) ON CONFLICT(hash) DO UPDATE SET created_at = excluded.created_at")
            .bind(&hash)
            .bind(data.len() as i64)
            .bind(now())
            .execute(&self.db)
            .await?;
        self.blobs.put(&hash, data).await?;
        Ok(hash)
    }

    pub async fn read_blob(&self, hash: &str) -> Result<Vec<u8>, StoreError> {
        Self::check_hash(hash)?;
        self.blobs.get(hash).await
    }

    /// The first `limit` bytes of a blob: enough for the headers of a message, without reading
    /// its attachments.
    pub async fn read_blob_head(&self, hash: &str, limit: usize) -> Result<Vec<u8>, StoreError> {
        Self::check_hash(hash)?;
        self.blobs.head(hash, limit).await
    }

    /// Removes blobs no longer referenced by any message or queue entry. Blobs younger than an
    /// hour are kept so that in-flight deliveries cannot lose their content.
    pub async fn gc_blobs(&self) -> Result<usize, StoreError> {
        // Uploads that were never attached to a message expire after a day.
        sqlx::query("DELETE FROM uploads WHERE created_at < ?").bind(now() - 86400).execute(&self.db).await?;
        let hashes: Vec<String> = sqlx::query_scalar(
            "DELETE FROM blobs WHERE created_at < ?
               AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.blob_hash = blobs.hash)
               AND NOT EXISTS (SELECT 1 FROM queue q WHERE q.blob_hash = blobs.hash)
               AND NOT EXISTS (SELECT 1 FROM uploads u WHERE u.hash = blobs.hash)
               AND NOT EXISTS (SELECT 1 FROM list_pending p WHERE p.blob_hash = blobs.hash)
             RETURNING hash",
        )
        .bind(now() - 3600)
        .fetch_all(&self.db)
        .await?;
        for hash in &hashes {
            Self::check_hash(hash)?;
            if let Err(err) = self.blobs.remove(hash).await {
                tracing::warn!(%err, hash, "failed to remove unreferenced blob");
            }
        }
        Ok(hashes.len())
    }

    pub async fn create_default_mailboxes(&self, account_id: i64) -> Result<(), StoreError> {
        for (name, role) in DEFAULT_MAILBOXES {
            sqlx::query("INSERT OR IGNORE INTO mailboxes (account_id, name, role, uid_validity) VALUES (?, ?, ?, ?)")
                .bind(account_id)
                .bind(name)
                .bind(role)
                .bind(now())
                .execute(&self.db)
                .await?;
        }
        Ok(())
    }

    pub async fn list_mailboxes(&self, account_id: i64) -> Result<Vec<Mailbox>, StoreError> {
        Ok(sqlx::query_as("SELECT * FROM mailboxes WHERE account_id = ? ORDER BY role IS NULL, id")
            .bind(account_id)
            .fetch_all(&self.db)
            .await?)
    }

    pub async fn mailbox(&self, account_id: i64, id: i64) -> Result<Mailbox, StoreError> {
        sqlx::query_as("SELECT * FROM mailboxes WHERE account_id = ? AND id = ?")
            .bind(account_id)
            .bind(id)
            .fetch_optional(&self.db)
            .await?
            .ok_or(StoreError::NotFound)
    }

    pub async fn mailbox_by_name(&self, account_id: i64, name: &str) -> Result<Option<Mailbox>, StoreError> {
        // INBOX is case-insensitive per RFC 3501.
        let name = if name.eq_ignore_ascii_case("INBOX") { "INBOX" } else { name };
        Ok(sqlx::query_as("SELECT * FROM mailboxes WHERE account_id = ? AND name = ?")
            .bind(account_id)
            .bind(name)
            .fetch_optional(&self.db)
            .await?)
    }

    pub async fn mailbox_by_role(&self, account_id: i64, role: &str) -> Result<Option<Mailbox>, StoreError> {
        Ok(sqlx::query_as("SELECT * FROM mailboxes WHERE account_id = ? AND role = ?")
            .bind(account_id)
            .bind(role)
            .fetch_optional(&self.db)
            .await?)
    }

    pub async fn mailbox_counts(&self, mailbox_id: i64) -> Result<MailboxCounts, StoreError> {
        Ok(sqlx::query_as(
            "SELECT COUNT(*) AS total, COALESCE(SUM(seen = 0), 0) AS unread FROM messages WHERE mailbox_id = ?",
        )
        .bind(mailbox_id)
        .fetch_one(&self.db)
        .await?)
    }

    pub async fn create_mailbox(&self, account_id: i64, name: &str) -> Result<Mailbox, StoreError> {
        validate_mailbox_name(name)?;
        if self.mailbox_by_name(account_id, name).await?.is_some() {
            return Err(StoreError::Exists);
        }
        let id = sqlx::query("INSERT INTO mailboxes (account_id, name, uid_validity) VALUES (?, ?, ?)")
            .bind(account_id)
            .bind(name)
            .bind(now())
            .execute(&self.db)
            .await?
            .last_insert_rowid();
        Self::record(&self.db, account_id, "mailbox", id, None, "created").await?;
        self.notify(account_id, id);
        self.mailbox(account_id, id).await
    }

    pub async fn rename_mailbox(&self, account_id: i64, id: i64, new_name: &str) -> Result<(), StoreError> {
        validate_mailbox_name(new_name)?;
        let mailbox = self.mailbox(account_id, id).await?;
        if mailbox.role.is_some() {
            return Err(StoreError::Invalid("system mailboxes cannot be renamed"));
        }
        if self.mailbox_by_name(account_id, new_name).await?.is_some() {
            return Err(StoreError::Exists);
        }
        let (_turn, mut tx) = self.begin_write().await?;
        // Children keep their relative names under the new parent.
        sqlx::query(
            "UPDATE mailboxes SET name = ? || substr(name, ?) WHERE account_id = ? AND substr(name, 1, ?) = ?",
        )
        .bind(new_name)
        .bind(mailbox.name.len() as i64 + 1)
        .bind(account_id)
        .bind(mailbox.name.len() as i64 + 1)
        .bind(format!("{}/", mailbox.name))
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE mailboxes SET name = ? WHERE id = ?").bind(new_name).bind(id).execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO changes (account_id, kind, object_id, change)
             SELECT account_id, 'mailbox', id, 'updated' FROM mailboxes WHERE account_id = ?1 AND (id = ?2 OR substr(name, 1, ?3) = ?4)",
        )
        .bind(account_id)
        .bind(id)
        .bind(new_name.len() as i64 + 1)
        .bind(format!("{new_name}/"))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.notify(account_id, id);
        Ok(())
    }

    pub async fn delete_mailbox(&self, account_id: i64, id: i64) -> Result<(), StoreError> {
        let mailbox = self.mailbox(account_id, id).await?;
        if mailbox.role.is_some() {
            return Err(StoreError::Invalid("system mailboxes cannot be deleted"));
        }
        let (_turn, mut tx) = self.begin_write().await?;
        let size: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(size), 0) FROM messages WHERE mailbox_id = ?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO changes (account_id, kind, object_id, thread_id, change)
             SELECT account_id, 'email', id, thread_id, 'destroyed' FROM messages WHERE mailbox_id = ?",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        Self::record(&mut *tx, account_id, "mailbox", id, None, "destroyed").await?;
        sqlx::query("DELETE FROM mailboxes WHERE id = ?").bind(id).execute(&mut *tx).await?;
        sqlx::query("UPDATE accounts SET used_bytes = MAX(0, used_bytes - ?) WHERE id = ?")
            .bind(size)
            .bind(account_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        self.notify(account_id, id);
        Ok(())
    }

    /// Stores `raw` as a new message in `mailbox_id`, enforcing the account quota.
    pub async fn append(
        &self,
        account_id: i64,
        mailbox_id: i64,
        raw: &[u8],
        flags: Flags,
        internal_date: Option<i64>,
    ) -> Result<Appended, StoreError> {
        self.append_with(account_id, mailbox_id, raw, flags, internal_date, &[]).await
    }

    /// `append`, with keywords (labels, categories) set in the same transaction.
    pub async fn append_with(
        &self,
        account_id: i64,
        mailbox_id: i64,
        raw: &[u8],
        flags: Flags,
        internal_date: Option<i64>,
        keywords: &[String],
    ) -> Result<Appended, StoreError> {
        self.append_with_provenance(account_id,mailbox_id,raw,flags,internal_date,keywords,None).await
    }

    /// `masked_to` is trusted SMTP envelope metadata, never extracted from MIME headers.
    #[allow(clippy::too_many_arguments)]
    pub async fn append_with_provenance(&self,account_id:i64,mailbox_id:i64,raw:&[u8],flags:Flags,internal_date:Option<i64>,keywords:&[String],masked_to:Option<&str>)->Result<Appended,StoreError>{
        // Refuse before writing: a full account would otherwise leave a blob on disk with each
        // try, until the collector gets to it. The transaction below checks again.
        let fits: Option<bool> = sqlx::query_scalar("SELECT quota_bytes = 0 OR used_bytes + ? <= quota_bytes FROM accounts WHERE id = ?")
            .bind(raw.len() as i64)
            .bind(account_id)
            .fetch_optional(&self.db)
            .await?;
        if fits == Some(false) {
            return Err(StoreError::QuotaExceeded);
        }
        let hash = self.put_blob(raw).await?;
        // Parsing and text extraction happen before the write turn is taken.
        let parsed = parse_metadata(raw);
        let indexed = crate::search::extract(raw, &hash);
        let offers_unsubscribe = crate::subscriptions::offered(raw);
        let size = raw.len() as i64;
        let mut keywords = keywords.to_vec();
        keywords.sort();
        keywords.dedup();
        let keywords = serde_json::to_string(&keywords).unwrap_or_else(|_| "[]".into());

        let (_turn, mut tx) = self.begin_write().await?;
        let quota_ok = sqlx::query(
            "UPDATE accounts SET used_bytes = used_bytes + ?1 WHERE id = ?2 AND (quota_bytes = 0 OR used_bytes + ?1 <= quota_bytes)",
        )
        .bind(size)
        .bind(account_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if quota_ok == 0 {
            return Err(StoreError::QuotaExceeded);
        }

        let (uid, modseq): (i64, i64) = sqlx::query_as(
            "UPDATE mailboxes SET uid_next = uid_next + 1, highest_modseq = highest_modseq + 1
             WHERE id = ? AND account_id = ? RETURNING uid_next - 1, highest_modseq",
        )
        .bind(mailbox_id)
        .bind(account_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::NotFound)?;

        // Thread by the first referenced message we already hold for this account.
        let mut thread_id: Option<i64> = None;
        let refs = parsed.references.iter().rev().chain(std::iter::once(&parsed.in_reply_to));
        for reference in refs.filter(|r| !r.is_empty()).take(20) {
            thread_id = sqlx::query_scalar("SELECT thread_id FROM messages WHERE account_id = ? AND message_id = ? LIMIT 1")
                .bind(account_id)
                .bind(reference)
                .fetch_optional(&mut *tx)
                .await?;
            if thread_id.is_some() {
                break;
            }
        }
        let thread_id = match thread_id {
            Some(id) => id,
            None => sqlx::query("INSERT INTO threads (account_id) VALUES (?)")
                .bind(account_id)
                .execute(&mut *tx)
                .await?
                .last_insert_rowid(),
        };

        let id = sqlx::query(
            "INSERT INTO messages (account_id, mailbox_id, uid, blob_hash, size, internal_date, modseq, seen, answered,
                flagged, deleted, draft, thread_id, message_id, in_reply_to, subject, from_addr, from_name, to_addrs,
                snippet, has_attachments, sent_date, keywords, mailbox_since)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CAST(strftime('%s', 'now') AS INTEGER))",
        )
        .bind(account_id)
        .bind(mailbox_id)
        .bind(uid)
        .bind(&hash)
        .bind(size)
        .bind(internal_date.unwrap_or_else(now))
        .bind(modseq)
        .bind(flags.seen)
        .bind(flags.answered)
        .bind(flags.flagged)
        .bind(flags.deleted)
        .bind(flags.draft)
        .bind(thread_id)
        .bind(&parsed.message_id)
        .bind(&parsed.in_reply_to)
        .bind(&parsed.subject)
        .bind(&parsed.from_addr)
        .bind(&parsed.from_name)
        .bind(&parsed.to_addrs)
        .bind(&parsed.snippet)
        .bind(parsed.has_attachments)
        .bind(parsed.sent_date)
        .bind(&keywords)
        .execute(&mut *tx)
        .await?
        .last_insert_rowid();
        Self::record(&mut *tx, account_id, "email", id, Some(thread_id), "created").await?;
        Self::record(&mut *tx, account_id, "mailbox", mailbox_id, None, "updated").await?;
        // Searchable at once, in the same transaction.
        crate::search::store_in(&mut tx, &hash, &indexed).await?;
        crate::subscriptions::store(&mut *tx, &hash, offers_unsubscribe).await?;
        if let Some(address)=masked_to{sqlx::query("INSERT INTO message_mask_delivery(message_id,email) VALUES(?,?)").bind(id).bind(address).execute(&mut *tx).await?;}
        // Durable, local-first card extraction happens off the delivery path. Bound the queue
        // during large imports; older messages can still be processed explicitly in the reader.
        sqlx::query("INSERT OR IGNORE INTO summary_card_jobs (message_id, account_id) SELECT ?1, ?2 WHERE ?3 = 0 AND ?4 = 0 AND COALESCE((SELECT role FROM mailboxes WHERE id = ?5), '') NOT IN ('junk', 'trash', 'drafts', 'sent') AND (SELECT COUNT(*) FROM summary_card_jobs WHERE state IN ('pending', 'running')) < 5000")
            .bind(id).bind(account_id).bind(flags.draft).bind(flags.deleted).bind(mailbox_id).execute(&mut *tx).await?;
        tx.commit().await?;
        self.notify(account_id, mailbox_id);
        Ok(Appended { id, uid, thread_id })
    }

    pub async fn message(&self, account_id: i64, id: i64) -> Result<Message, StoreError> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE account_id = ? AND id = ?"
        )))
        .bind(account_id)
        .bind(id)
        .fetch_optional(&self.db)
        .await?
        .ok_or(StoreError::NotFound)
    }

    /// All messages of a mailbox in UID order (the IMAP sequence order).
    pub async fn messages_in(&self, mailbox_id: i64) -> Result<Vec<Message>, StoreError> {
        Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE mailbox_id = ? ORDER BY uid"
        )))
        .bind(mailbox_id)
        .fetch_all(&self.db)
        .await?)
    }

    /// Messages of a mailbox changed or added after `modseq`, in UID order (IMAP sync).
    pub async fn messages_changed_since(&self, mailbox_id: i64, modseq: i64) -> Result<Vec<Message>, StoreError> {
        Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE mailbox_id = ? AND modseq > ? ORDER BY uid"
        )))
        .bind(mailbox_id)
        .bind(modseq)
        .fetch_all(&self.db)
        .await?)
    }

    async fn bump_modseq(tx: &mut sqlx::SqliteConnection, mailbox_id: i64) -> Result<i64, StoreError> {
        Ok(sqlx::query_scalar(
            "UPDATE mailboxes SET highest_modseq = highest_modseq + 1 WHERE id = ? RETURNING highest_modseq",
        )
        .bind(mailbox_id)
        .fetch_one(tx)
        .await?)
    }

    /// Appends an entry to the account's change log (see JMAP `/changes`).
    async fn record<'e>(
        executor: impl sqlx::SqliteExecutor<'e>,
        account_id: i64,
        kind: &str,
        object_id: i64,
        thread_id: Option<i64>,
        change: &str,
    ) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO changes (account_id, kind, object_id, thread_id, change) VALUES (?, ?, ?, ?, ?)")
            .bind(account_id)
            .bind(kind)
            .bind(object_id)
            .bind(thread_id)
            .bind(change)
            .execute(executor)
            .await?;
        Ok(())
    }

    /// Changes to objects of `kind` after state `since`, coalesced per object.
    ///
    /// Returns `None` when the log no longer reaches back to `since` (the client must refetch).
    pub async fn changes_since(&self, account_id: i64, kind: &str, since: i64, max: usize) -> Result<Option<ChangeSet>, StoreError> {
        let floor: i64 = crate::db::get_setting(&self.db, "changes.floor").await?.and_then(|v| v.parse().ok()).unwrap_or(0);
        let current = self.account_state(account_id).await?;
        if since < floor || since > current {
            return Ok(None);
        }
        let rows: Vec<(i64, i64, Option<i64>, String)> = sqlx::query_as(
            "SELECT id, object_id, thread_id, change FROM changes WHERE account_id = ? AND kind = ? AND id > ? ORDER BY id",
        )
        .bind(account_id)
        .bind(kind)
        .bind(since)
        .fetch_all(&self.db)
        .await?;
        let mut set = ChangeSet { new_state: current, ..Default::default() };
        // object id -> (first change, last change), in order of first appearance.
        let mut order: Vec<i64> = Vec::new();
        let mut seen: std::collections::HashMap<i64, (String, String)> = std::collections::HashMap::new();
        for (change_id, object_id, thread_id, change) in rows {
            if !seen.contains_key(&object_id) {
                if order.len() >= max {
                    // Stop at a change boundary; the client continues from this state.
                    set.has_more = true;
                    set.new_state = change_id - 1;
                    break;
                }
                order.push(object_id);
            }
            if let Some(thread) = thread_id
                && !set.threads.contains(&thread)
            {
                set.threads.push(thread);
            }
            seen.entry(object_id).and_modify(|e| e.1 = change.clone()).or_insert((change.clone(), change));
        }
        for object_id in order {
            match seen[&object_id].clone() {
                (first, last) if first == "created" && last == "destroyed" => {}
                (first, _) if first == "created" => set.created.push(object_id),
                (_, last) if last == "destroyed" => set.destroyed.push(object_id),
                _ => set.updated.push(object_id),
            }
        }
        Ok(Some(set))
    }

    /// Drops old change-log entries, remembering how far back the log still reaches.
    pub async fn prune_changes(&self, keep: i64) -> Result<(), StoreError> {
        let max: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(id), 0) FROM changes").fetch_one(&self.db).await?;
        let floor = max - keep;
        if floor > 0 {
            sqlx::query("DELETE FROM changes WHERE id <= ?").bind(floor).execute(&self.db).await?;
            crate::db::set_setting(&self.db, "changes.floor", &floor.to_string()).await?;
        }
        Ok(())
    }

    /// UIDs expunged from a mailbox after `modseq` (IMAP QRESYNC).
    pub async fn expunged_since(&self, mailbox_id: i64, modseq: i64) -> Result<Vec<i64>, StoreError> {
        Ok(sqlx::query_scalar("SELECT uid FROM expunged WHERE mailbox_id = ? AND modseq > ? ORDER BY uid")
            .bind(mailbox_id)
            .bind(modseq)
            .fetch_all(&self.db)
            .await?)
    }

    /// Distinct custom keywords (labels) used in the account.
    pub async fn keywords(&self, account_id: i64) -> Result<Vec<String>, StoreError> {
        Ok(sqlx::query_scalar(
            // Keywords starting with "$" are the server's own (categories, $forwarded, ...).
            "SELECT DISTINCT keyword FROM message_keywords WHERE account_id = ? AND (keyword < '$' OR keyword >= '%') ORDER BY keyword LIMIT 500",
        )
        .bind(account_id)
        .fetch_all(&self.db)
        .await?)
    }

    /// Renames a keyword (label) on every message of the account, or removes it when `to` is
    /// `None`. Returns the number of messages changed.
    pub async fn rename_keyword(&self, account_id: i64, from: &str, to: Option<&str>) -> Result<usize, StoreError> {
        let ids: Vec<i64> = sqlx::query_scalar(
            "SELECT message_id FROM message_keywords WHERE account_id = ? AND keyword = ?",
        )
        .bind(account_id)
        .bind(from)
        .fetch_all(&self.db)
        .await?;
        for id in &ids {
            let message = self.message(account_id, *id).await?;
            let mut keywords: Vec<String> = serde_json::from_str(&message.keywords).unwrap_or_default();
            keywords.retain(|k| k != from);
            if let Some(to) = to
                && !keywords.iter().any(|k| k == to)
            {
                keywords.push(to.to_owned());
            }
            let flags = Flags { seen: message.seen, answered: message.answered, flagged: message.flagged, deleted: message.deleted, draft: message.draft };
            self.set_flags_and_keywords(account_id, *id, flags, &keywords).await?;
        }
        Ok(ids.len())
    }

    pub async fn set_flags(&self, account_id: i64, id: i64, flags: Flags) -> Result<(), StoreError> {
        let msg = self.message(account_id, id).await?;
        let (_turn, mut tx) = self.begin_write().await?;
        let modseq = Self::bump_modseq(&mut tx, msg.mailbox_id).await?;
        sqlx::query(
            "UPDATE messages SET seen = ?, answered = ?, flagged = ?, deleted = ?, draft = ?, modseq = ? WHERE id = ?",
        )
        .bind(flags.seen)
        .bind(flags.answered)
        .bind(flags.flagged)
        .bind(flags.deleted)
        .bind(flags.draft)
        .bind(modseq)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        Self::record(&mut *tx, account_id, "email", id, Some(msg.thread_id), "updated").await?;
        Self::record(&mut *tx, account_id, "mailbox", msg.mailbox_id, None, "updated").await?;
        tx.commit().await?;
        self.notify(account_id, msg.mailbox_id);
        Ok(())
    }

    /// Replaces the flags and custom keywords of a message.
    pub async fn set_flags_and_keywords(&self, account_id: i64, id: i64, flags: Flags, keywords: &[String]) -> Result<(), StoreError> {
        let msg = self.message(account_id, id).await?;
        let (_turn, mut tx) = self.begin_write().await?;
        let modseq = Self::bump_modseq(&mut tx, msg.mailbox_id).await?;
        sqlx::query(
            "UPDATE messages SET seen = ?, answered = ?, flagged = ?, deleted = ?, draft = ?, keywords = ?, modseq = ? WHERE id = ?",
        )
        .bind(flags.seen)
        .bind(flags.answered)
        .bind(flags.flagged)
        .bind(flags.deleted)
        .bind(flags.draft)
        .bind(serde_json::to_string(keywords).unwrap_or_else(|_| "[]".into()))
        .bind(modseq)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        Self::record(&mut *tx, account_id, "email", id, Some(msg.thread_id), "updated").await?;
        Self::record(&mut *tx, account_id, "mailbox", msg.mailbox_id, None, "updated").await?;
        tx.commit().await?;
        self.notify(account_id, msg.mailbox_id);
        Ok(())
    }

    /// The account's JMAP state: the id of its latest change-log entry.
    pub async fn account_state(&self, account_id: i64) -> Result<i64, StoreError> {
        Ok(sqlx::query_scalar("SELECT COALESCE(MAX(id), 0) FROM changes WHERE account_id = ?")
            .bind(account_id)
            .fetch_one(&self.db)
            .await?)
    }

    /// Moves a message to another mailbox of the same account, assigning it a new UID.
    pub async fn move_message(&self, account_id: i64, id: i64, target_mailbox: i64) -> Result<i64, StoreError> {
        let msg = self.message(account_id, id).await?;
        if msg.mailbox_id == target_mailbox {
            return Ok(msg.uid);
        }
        let (_turn, mut tx) = self.begin_write().await?;
        let (uid, modseq): (i64, i64) = sqlx::query_as(
            "UPDATE mailboxes SET uid_next = uid_next + 1, highest_modseq = highest_modseq + 1
             WHERE id = ? AND account_id = ? RETURNING uid_next - 1, highest_modseq",
        )
        .bind(target_mailbox)
        .bind(account_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::NotFound)?;
        let source_modseq = Self::bump_modseq(&mut tx, msg.mailbox_id).await?;
        sqlx::query("INSERT OR REPLACE INTO expunged (mailbox_id, uid, modseq) VALUES (?, ?, ?)")
            .bind(msg.mailbox_id)
            .bind(msg.uid)
            .bind(source_modseq)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE messages SET mailbox_id = ?, uid = ?, modseq = ?, deleted = 0, mailbox_since = CAST(strftime('%s', 'now') AS INTEGER) WHERE id = ?")
            .bind(target_mailbox)
            .bind(uid)
            .bind(modseq)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        Self::record(&mut *tx, account_id, "email", id, Some(msg.thread_id), "updated").await?;
        Self::record(&mut *tx, account_id, "mailbox", msg.mailbox_id, None, "updated").await?;
        Self::record(&mut *tx, account_id, "mailbox", target_mailbox, None, "updated").await?;
        tx.commit().await?;
        self.notify(account_id, msg.mailbox_id);
        self.notify(account_id, target_mailbox);
        Ok(uid)
    }

    pub async fn copy_message(&self, account_id: i64, id: i64, target_mailbox: i64) -> Result<Appended, StoreError> {
        let msg = self.message(account_id, id).await?;
        let raw = self.read_blob(&msg.blob_hash).await?;
        let flags =
            Flags { seen: msg.seen, answered: msg.answered, flagged: msg.flagged, deleted: false, draft: msg.draft };
        let masked:Option<String>=sqlx::query_scalar("SELECT email FROM message_mask_delivery WHERE message_id=? LIMIT 1").bind(id).fetch_optional(&self.db).await?;
        self.append_with_provenance(account_id, target_mailbox, &raw, flags, Some(msg.internal_date),&[],masked.as_deref()).await
    }

    /// Copies a message into a mailbox that may belong to another account (shared folders).
    /// The copy counts against the quota of the target mailbox's owner.
    pub async fn copy_across(&self, owner: i64, id: i64, target_owner: i64, target_mailbox: i64) -> Result<Appended, StoreError> {
        let msg = self.message(owner, id).await?;
        let raw = self.read_blob(&msg.blob_hash).await?;
        let flags = Flags { seen: msg.seen, answered: msg.answered, flagged: msg.flagged, deleted: false, draft: msg.draft };
        let masked:Option<String>=if owner==target_owner{sqlx::query_scalar("SELECT email FROM message_mask_delivery WHERE message_id=? LIMIT 1").bind(id).fetch_optional(&self.db).await?}else{None};
        let appended = self.append_with_provenance(target_owner, target_mailbox, &raw, flags, Some(msg.internal_date),&[],masked.as_deref()).await?;
        let keywords: Vec<String> = serde_json::from_str(&msg.keywords).unwrap_or_default();
        if !keywords.is_empty() {
            self.set_flags_and_keywords(target_owner, appended.id, flags, &keywords).await?;
        }
        Ok(appended)
    }

    /// Moves a message, possibly into another account's mailbox. Returns the (id, uid) of the
    /// message in its new place; the id changes when the owner does.
    pub async fn move_across(&self, owner: i64, id: i64, target_owner: i64, target_mailbox: i64) -> Result<(i64, i64), StoreError> {
        if owner == target_owner {
            return Ok((id, self.move_message(owner, id, target_mailbox).await?));
        }
        let appended = self.copy_across(owner, id, target_owner, target_mailbox).await?;
        self.delete_message(owner, id).await?;
        Ok((appended.id, appended.uid))
    }

    /// Permanently removes a message and releases its quota.
    pub async fn delete_message(&self, account_id: i64, id: i64) -> Result<(), StoreError> {
        let msg = self.message(account_id, id).await?;
        let (_turn, mut tx) = self.begin_write().await?;
        let modseq = Self::bump_modseq(&mut tx, msg.mailbox_id).await?;
        sqlx::query("INSERT OR REPLACE INTO expunged (mailbox_id, uid, modseq) VALUES (?, ?, ?)")
            .bind(msg.mailbox_id)
            .bind(msg.uid)
            .bind(modseq)
            .execute(&mut *tx)
            .await?;
        Self::record(&mut *tx, account_id, "email", id, Some(msg.thread_id), "destroyed").await?;
        Self::record(&mut *tx, account_id, "mailbox", msg.mailbox_id, None, "updated").await?;
        sqlx::query("DELETE FROM messages WHERE id = ?").bind(id).execute(&mut *tx).await?;
        sqlx::query("UPDATE accounts SET used_bytes = MAX(0, used_bytes - ?) WHERE id = ?")
            .bind(msg.size)
            .bind(account_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        self.notify(account_id, msg.mailbox_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &[u8] = b"From: Alice Example <Alice@Example.com>\r\nTo: bob@example.org, carol@example.org\r\n\
Subject: Hello there\r\nMessage-ID: <one@example.com>\r\nDate: Mon, 05 Oct 2026 10:00:00 +0000\r\n\r\n\
This is the   body\r\nof the message.\r\n";

    #[test]
    fn metadata() {
        let p = parse_metadata(RAW);
        assert_eq!(p.message_id, "one@example.com");
        assert_eq!(p.subject, "Hello there");
        assert_eq!(p.from_addr, "alice@example.com");
        assert_eq!(p.from_name, "Alice Example");
        assert_eq!(p.to_addrs, "bob@example.org, carol@example.org");
        assert_eq!(p.snippet, "This is the body of the message.");
        assert!(!p.has_attachments);
        assert_eq!(p.sent_date, 1791194400);
    }

    #[test]
    fn metadata_of_garbage_is_empty() {
        assert_eq!(parse_metadata(b""), Parsed::default());
    }

    #[test]
    fn mailbox_names() {
        assert!(validate_mailbox_name("Work/Projects").is_ok());
        for bad in ["", "/x", "x/", "a//b", "a%b", "a*b", "a\"b", "a\\b", "a\r\nb", "Shared", "Shared/bob@example.org/INBOX"] {
            assert!(validate_mailbox_name(bad).is_err(), "{bad:?}");
        }
    }

    async fn setup() -> (tempfile::TempDir, Store, i64) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::open(&dir.path().join("test.db")).await.unwrap();
        let store = Store::new(db.clone(), dir.path()).unwrap();
        sqlx::query("INSERT INTO domains (name, created_at) VALUES ('example.org', 0)").execute(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO accounts (domain_id, local_part, email, password_hash, quota_bytes, created_at)
             VALUES (1, 'bob', 'bob@example.org', 'x', 1000, 0)",
        )
        .execute(&db)
        .await
        .unwrap();
        store.create_default_mailboxes(1).await.unwrap();
        (dir, store, 1)
    }

    #[tokio::test]
    async fn the_keyword_table_follows_the_messages() {
        let (_dir, store, account) = setup().await;
        let inbox = store.mailbox_by_name(account, "inbox").await.unwrap().unwrap();
        let keywords = |id: i64| {
            let db = store.db.clone();
            async move {
                sqlx::query_scalar::<_, String>("SELECT keyword FROM message_keywords WHERE message_id = ? ORDER BY keyword").bind(id).fetch_all(&db).await.unwrap()
            }
        };
        let first = store.append_with(account, inbox.id, RAW, Flags::default(), None, &["work".into(), "$cat_offers".into(), "work".into()]).await.unwrap();
        assert_eq!(keywords(first.id).await, ["$cat_offers", "work"], "set with the message, once each");
        let message = store.message(account, first.id).await.unwrap();
        assert_eq!(message.keywords, r#"["$cat_offers","work"]"#);
        assert_eq!(store.keywords(account).await.unwrap(), ["work"], "labels only, not the server's own keywords");

        store.set_flags_and_keywords(account, first.id, Flags::default(), &["home".into()]).await.unwrap();
        assert_eq!(keywords(first.id).await, ["home"]);
        assert_eq!(store.rename_keyword(account, "home", Some("family")).await.unwrap(), 1);
        assert_eq!(store.keywords(account).await.unwrap(), ["family"]);

        // Moving keeps them; deleting removes them.
        let archive = store.mailbox_by_role(account, "archive").await.unwrap().unwrap();
        store.move_message(account, first.id, archive.id).await.unwrap();
        assert_eq!(keywords(first.id).await, ["family"]);
        store.delete_message(account, first.id).await.unwrap();
        assert!(keywords(first.id).await.is_empty());
        assert!(store.keywords(account).await.unwrap().is_empty());

        // The new message is searchable at once (indexed in the same transaction).
        let second = store.append(account, inbox.id, RAW, Flags::default(), None).await.unwrap();
        let hash = store.message(account, second.id).await.unwrap().blob_hash;
        let body: String = sqlx::query_scalar("SELECT t.body FROM message_extras e JOIN message_text t ON t.rowid = e.id WHERE e.hash = ?").bind(&hash).fetch_one(&store.db).await.unwrap();
        assert!(body.contains("body"), "{body}");
    }

    #[tokio::test]
    async fn append_thread_move_delete() {
        let (_dir, store, account) = setup().await;
        let inbox = store.mailbox_by_name(account, "inbox").await.unwrap().unwrap();
        let trash = store.mailbox_by_role(account, "trash").await.unwrap().unwrap();

        let first = store.append(account, inbox.id, RAW, Flags::default(), None).await.unwrap();
        assert_eq!(first.uid, 1);
        let reply = b"From: bob@example.org\r\nSubject: Re: Hello there\r\nMessage-ID: <two@example.org>\r\n\
In-Reply-To: <one@example.com>\r\n\r\nReply\r\n";
        let second = store.append(account, inbox.id, reply, Flags::default(), None).await.unwrap();
        assert_eq!(second.uid, 2);
        assert_eq!(second.thread_id, first.thread_id, "reply joins the original thread");

        let counts = store.mailbox_counts(inbox.id).await.unwrap();
        assert_eq!((counts.total, counts.unread), (2, 2));
        store.set_flags(account, first.id, Flags { seen: true, ..Default::default() }).await.unwrap();
        assert_eq!(store.mailbox_counts(inbox.id).await.unwrap().unread, 1);

        assert_eq!(store.read_blob(&store.message(account, first.id).await.unwrap().blob_hash).await.unwrap(), RAW);

        let new_uid = store.move_message(account, first.id, trash.id).await.unwrap();
        assert_eq!(new_uid, 1);
        assert_eq!(store.messages_in(inbox.id).await.unwrap().len(), 1);

        let used: i64 = sqlx::query_scalar("SELECT used_bytes FROM accounts WHERE id = 1").fetch_one(&store.db).await.unwrap();
        assert_eq!(used, (RAW.len() + reply.len()) as i64);
        store.delete_message(account, first.id).await.unwrap();
        let used: i64 = sqlx::query_scalar("SELECT used_bytes FROM accounts WHERE id = 1").fetch_one(&store.db).await.unwrap();
        assert_eq!(used, reply.len() as i64);
    }

    #[tokio::test]
    async fn change_log_is_coalesced_per_object() {
        let (_dir, store, account) = setup().await;
        let inbox = store.mailbox_by_name(account, "INBOX").await.unwrap().unwrap();
        let trash = store.mailbox_by_role(account, "trash").await.unwrap().unwrap();
        let start = store.account_state(account).await.unwrap();

        let kept = store.append(account, inbox.id, RAW, Flags::default(), None).await.unwrap();
        let gone = store.append(account, inbox.id, b"Subject: temp\r\n\r\nx", Flags::default(), None).await.unwrap();
        store.delete_message(account, gone.id).await.unwrap();
        let middle = store.account_state(account).await.unwrap();
        let set = store.changes_since(account, "email", start, 100).await.unwrap().unwrap();
        assert_eq!((set.created.clone(), set.updated.clone(), set.destroyed.clone()), (vec![kept.id], vec![], vec![]), "created+destroyed cancels out");
        assert_eq!(set.new_state, middle);

        store.set_flags(account, kept.id, Flags { seen: true, ..Default::default() }).await.unwrap();
        store.move_message(account, kept.id, trash.id).await.unwrap();
        let set = store.changes_since(account, "email", middle, 100).await.unwrap().unwrap();
        assert_eq!((set.created, set.updated, set.destroyed), (vec![], vec![kept.id], vec![]));
        assert_eq!(set.threads, vec![kept.thread_id]);
        let boxes = store.changes_since(account, "mailbox", middle, 100).await.unwrap().unwrap();
        assert_eq!(boxes.updated, vec![inbox.id, trash.id]);
        assert_eq!(store.expunged_since(inbox.id, 0).await.unwrap(), vec![1, 2]);

        store.delete_message(account, kept.id).await.unwrap();
        let set = store.changes_since(account, "email", middle, 100).await.unwrap().unwrap();
        assert_eq!(set.destroyed, vec![kept.id]);

        // Paging stops at a change boundary; unknown or pruned states cannot be answered.
        let paged = store.changes_since(account, "mailbox", start, 1).await.unwrap().unwrap();
        assert!(paged.has_more && paged.new_state < store.account_state(account).await.unwrap());
        assert!(store.changes_since(account, "email", 999_999, 100).await.unwrap().is_none());
        store.prune_changes(1).await.unwrap();
        assert!(store.changes_since(account, "email", start, 100).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn quota_is_enforced() {
        let (_dir, store, account) = setup().await;
        let inbox = store.mailbox_by_name(account, "INBOX").await.unwrap().unwrap();
        let big = vec![b'x'; 600];
        store.append(account, inbox.id, &big, Flags::default(), None).await.unwrap();
        let other = vec![b'y'; 600];
        let err = store.append(account, inbox.id, &other, Flags::default(), None).await.unwrap_err();
        assert!(matches!(err, StoreError::QuotaExceeded));
        assert_eq!(store.messages_in(inbox.id).await.unwrap().len(), 1);
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blobs WHERE hash = ?").bind(sha256_hex(&other)).fetch_one(&store.db).await.unwrap();
        assert_eq!(left, 0, "a refused message leaves nothing on disk");
    }

    #[tokio::test]
    async fn messages_are_isolated_between_accounts() {
        let (_dir, store, account) = setup().await;
        sqlx::query(
            "INSERT INTO accounts (domain_id, local_part, email, password_hash, created_at)
             VALUES (1, 'eve', 'eve@example.org', 'x', 0)",
        )
        .execute(&store.db)
        .await
        .unwrap();
        store.create_default_mailboxes(2).await.unwrap();
        let inbox = store.mailbox_by_name(account, "INBOX").await.unwrap().unwrap();
        let eve_inbox = store.mailbox_by_name(2, "INBOX").await.unwrap().unwrap();
        let msg = store.append(account, inbox.id, RAW, Flags::default(), None).await.unwrap();

        assert!(matches!(store.message(2, msg.id).await, Err(StoreError::NotFound)));
        assert!(matches!(store.delete_message(2, msg.id).await, Err(StoreError::NotFound)));
        assert!(matches!(store.mailbox(2, inbox.id).await, Err(StoreError::NotFound)));
        // Appending into or moving to another account's mailbox must fail.
        assert!(matches!(store.append(2, inbox.id, RAW, Flags::default(), None).await, Err(StoreError::NotFound)));
        assert!(matches!(store.move_message(account, msg.id, eve_inbox.id).await, Err(StoreError::NotFound)));
    }

    #[tokio::test]
    async fn mailbox_management_and_blob_ids() {
        let (_dir, store, account) = setup().await;
        let work = store.create_mailbox(account, "Work").await.unwrap();
        store.create_mailbox(account, "Work/Sub").await.unwrap();
        assert!(matches!(store.create_mailbox(account, "Work").await, Err(StoreError::Exists)));
        store.rename_mailbox(account, work.id, "Jobs").await.unwrap();
        assert!(store.mailbox_by_name(account, "Jobs/Sub").await.unwrap().is_some());
        let inbox = store.mailbox_by_name(account, "INBOX").await.unwrap().unwrap();
        assert!(store.delete_mailbox(account, inbox.id).await.is_err());
        store.delete_mailbox(account, work.id).await.unwrap();

        assert!(matches!(store.read_blob("../../etc/passwd").await, Err(StoreError::Invalid(_))));
        assert!(matches!(store.read_blob(&"a".repeat(64)).await, Err(StoreError::NotFound)));
    }
}
