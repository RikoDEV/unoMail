//! Full-text search over messages, and the facts about a message's attachments that the list
//! view shows without opening each message.
//!
//! Every stored message content (blob) is indexed once, whatever number of mailboxes hold it:
//! subject, sender, recipients, the text of the body, and the names of attached files, in a
//! SQLite FTS5 table. Messages stored before the index existed are indexed in the background;
//! until then searches fall back to the summary columns for them.

use mail_parser::{MessageParser, MimeHeaders};
use serde_json::{Value, json};
use sqlx::SqlitePool;

use crate::app::AppState;

/// Most of a body that is indexed; enough for any real letter.
const MAX_BODY_CHARS: usize = 200_000;
const BACKFILL_BATCH: i64 = 100;

/// Searchable columns of the index, in table order.
pub const COLUMNS: [&str; 7] = ["subject", "sender", "recipients_to", "recipients_cc", "recipients_bcc", "body", "attachments"];

/// What is indexed for one message content.
#[derive(Debug, Default, PartialEq)]
pub struct Indexed {
    /// The attachments as JMAP `EmailBodyPart` objects (the `attachments` property).
    pub attachments: Vec<Value>,
    pub subject: String,
    pub sender: String,
    pub to: String,
    pub cc: String,
    pub bcc: String,
    pub body: String,
    pub names: String,
}

fn addresses(list: Option<&mail_parser::Address<'_>>) -> String {
    list.map(|list| list.iter().map(|a| format!("{} {}", a.name().unwrap_or(""), a.address().unwrap_or(""))).collect::<Vec<_>>().join(", ")).unwrap_or_default()
}

/// The attachments of a parsed message as JMAP reports them. `hash` names the message's blob;
/// each part is reachable as `<hash>.<part>`.
pub fn attachment_values(parsed: &mail_parser::Message<'_>, hash: &str) -> Vec<Value> {
    parsed
        .attachments
        .iter()
        .filter_map(|i| {
            let index = *i as usize;
            let part = parsed.parts.get(index)?;
            let kind = part.content_type().map(|ct| match ct.subtype() {
                Some(sub) => format!("{}/{}", ct.ctype(), sub).to_ascii_lowercase(),
                None => ct.ctype().to_ascii_lowercase(),
            });
            Some(json!({
                "partId": index.to_string(),
                "blobId": format!("{hash}.{index}"),
                "size": part.len(),
                "name": part.attachment_name(),
                "type": kind.unwrap_or_else(|| "application/octet-stream".into()),
                "disposition": if part.content_disposition().is_some_and(|d| d.is_inline()) { "inline" } else { "attachment" },
                "cid": part.content_id(),
            }))
        })
        .collect()
}

pub fn extract(raw: &[u8], hash: &str) -> Indexed {
    let Some(message) = MessageParser::default().parse(raw) else { return Indexed::default() };
    let mut body = String::new();
    for index in 0..message.text_body.len() {
        if let Some(text) = message.body_text(index) {
            body.push_str(&text);
            body.push('\n');
        }
        if body.len() > MAX_BODY_CHARS {
            break;
        }
    }
    // A message with only an HTML part: its text, as mail-parser renders it.
    if body.trim().is_empty() {
        for index in 0..message.html_body.len() {
            if let Some(text) = message.body_text(index) {
                body.push_str(&text);
            }
        }
    }
    let body: String = body.chars().take(MAX_BODY_CHARS).collect();
    let attachments = attachment_values(&message, hash);
    let names = attachments.iter().filter_map(|a| a["name"].as_str()).collect::<Vec<_>>().join(" ");
    Indexed {
        subject: message.subject().unwrap_or("").to_owned(),
        sender: addresses(message.from()),
        to: addresses(message.to()),
        cc: addresses(message.cc()),
        bcc: addresses(message.bcc()),
        body,
        names,
        attachments,
    }
}

/// Indexes a message content unless that was done before. Returns its attachments.
pub async fn index(db: &SqlitePool, hash: &str, raw: &[u8]) -> sqlx::Result<Vec<Value>> {
    if let Some(known) = attachments(db, hash).await? {
        return Ok(known);
    }
    let indexed = extract(raw, hash);
    store(db, hash, &indexed).await?;
    Ok(indexed.attachments)
}

async fn store(db: &SqlitePool, hash: &str, indexed: &Indexed) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    store_in(&mut tx, hash, indexed).await?;
    tx.commit().await
}

/// Writes the index entry of a message content within the caller's transaction (a content
/// indexed before is left as it is).
pub async fn store_in(tx: &mut sqlx::SqliteConnection, hash: &str, indexed: &Indexed) -> sqlx::Result<()> {
    let inserted = sqlx::query("INSERT OR IGNORE INTO message_extras (hash, attachments) VALUES (?, ?)").bind(hash).bind(Value::Array(indexed.attachments.clone()).to_string()).execute(&mut *tx).await?;
    if inserted.rows_affected() == 1 {
        sqlx::query("INSERT INTO message_text (rowid, subject, sender, recipients_to, recipients_cc, recipients_bcc, body, attachments) VALUES (last_insert_rowid(), ?, ?, ?, ?, ?, ?, ?)")
            .bind(&indexed.subject)
            .bind(&indexed.sender)
            .bind(&indexed.to)
            .bind(&indexed.cc)
            .bind(&indexed.bcc)
            .bind(&indexed.body)
            .bind(&indexed.names)
            .execute(&mut *tx)
            .await?;
    }
    Ok(())
}

/// The attachments recorded for a message content, if it was indexed.
pub async fn attachments(db: &SqlitePool, hash: &str) -> sqlx::Result<Option<Vec<Value>>> {
    let found: Option<String> = sqlx::query_scalar("SELECT attachments FROM message_extras WHERE hash = ?").bind(hash).fetch_optional(db).await?;
    Ok(found.map(|json| serde_json::from_str::<Vec<Value>>(&json).unwrap_or_default()))
}

/// Indexes, in the background and a batch at a time, messages stored before the index existed.
pub async fn backfill(app: AppState) {
    let mut done = 0usize;
    loop {
        let pending: Vec<String> = match sqlx::query_scalar("SELECT DISTINCT m.blob_hash FROM messages m WHERE NOT EXISTS (SELECT 1 FROM message_extras e WHERE e.hash = m.blob_hash) LIMIT ?").bind(BACKFILL_BATCH).fetch_all(&app.db).await {
            Ok(pending) => pending,
            Err(err) => {
                tracing::warn!(%err, "search index backfill stopped");
                return;
            }
        };
        if pending.is_empty() {
            if done > 0 {
                tracing::info!(messages = done, "search index complete");
            }
            return;
        }
        for hash in pending {
            // A content that cannot be read is recorded as empty, so it is not tried forever.
            let indexed = match app.store.read_blob(&hash).await {
                Ok(raw) => extract(&raw, &hash),
                Err(_) => Indexed::default(),
            };
            if let Err(err) = store(&app.db, &hash, &indexed).await {
                tracing::warn!(%err, "could not index a message");
                return;
            }
            done += 1;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Turns words a user typed into an FTS5 query: every word must occur (as a word or the start
/// of one), optionally in one column. Quotes in the input are taken literally. `None` when
/// nothing searchable is left (only punctuation, say).
pub fn fts_query(column: Option<&str>, text: &str) -> Option<String> {
    let terms: Vec<String> = text
        .split_whitespace()
        .filter(|word| word.chars().any(char::is_alphanumeric))
        .take(32)
        .map(|word| {
            let phrase = format!("\"{}\"*", word.chars().take(100).collect::<String>().replace('"', "\"\""));
            match column {
                Some(column) => format!("{column} : {phrase}"),
                None => phrase,
            }
        })
        .collect();
    (!terms.is_empty()).then(|| terms.join(" AND "))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &[u8] = b"From: Anna Kowalska <anna@partner.example>\r\nTo: bob@example.org\r\nCc: Carol <carol@example.org>\r\nSubject: Quarterly report\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThe numbers are in. Za\xc5\xbc\xc3\xb3\xc5\x82\xc4\x87 g\xc4\x99\xc5\x9bl\xc4\x85 ja\xc5\xba\xc5\x84.\r\n\
--b\r\nContent-Type: application/pdf; name=\"report-q3.pdf\"\r\nContent-Disposition: attachment; filename=\"report-q3.pdf\"\r\n\r\nJVBERi0x\r\n--b--\r\n";

    #[test]
    fn what_is_indexed() {
        let indexed = extract(RAW, "abc");
        assert_eq!(indexed.subject, "Quarterly report");
        assert!(indexed.sender.contains("Anna Kowalska") && indexed.sender.contains("anna@partner.example"));
        assert!(indexed.cc.contains("carol@example.org") && indexed.bcc.is_empty());
        assert!(indexed.body.contains("The numbers are in.") && indexed.body.contains("gęślą"));
        assert_eq!(indexed.names, "report-q3.pdf");
        assert_eq!(indexed.attachments.len(), 1);
        assert_eq!(indexed.attachments[0]["name"], "report-q3.pdf");
        assert_eq!(indexed.attachments[0]["type"], "application/pdf");
        assert!(indexed.attachments[0]["blobId"].as_str().unwrap().starts_with("abc."));
        assert_eq!(extract(b"", "x"), Indexed::default());
    }

    #[test]
    fn queries_are_built_from_words() {
        assert_eq!(fts_query(None, "quarterly  report").as_deref(), Some("\"quarterly\"* AND \"report\"*"));
        assert_eq!(fts_query(Some("sender"), "anna@partner.example").as_deref(), Some("sender : \"anna@partner.example\"*"));
        assert_eq!(fts_query(None, "say \"hi\"").as_deref(), Some("\"say\"* AND \"\"\"hi\"\"\"*"));
        assert_eq!(fts_query(None, "-- @ ..."), None);
        assert_eq!(fts_query(None, ""), None);
    }
}
