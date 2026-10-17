//! Mailbox import: copying mail from another server over IMAP, or ingesting a Maildir placed
//! in the server's import directory. Imports run as background jobs.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use rustls::pki_types::ServerName;
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;

use crate::{
    app::AppState,
    imap::parse::utf7_decode,
    security::reputation::is_private,
    store::{Flags, StoreError, validate_mailbox_name},
    util::now,
};

const IO_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_LINE: usize = 64 * 1024;
const MAX_FOLDERS: usize = 500;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Job {
    pub id: i64,
    pub kind: String,
    pub source: String,
    pub status: String,
    pub imported: i64,
    pub skipped: i64,
    pub error: Option<String>,
    pub started_at: i64,
    pub finished_at: Option<i64>,
}

pub async fn jobs(app: &AppState, account_id: i64) -> sqlx::Result<Vec<Job>> {
    sqlx::query_as(
        "SELECT id, kind, source, status, imported, skipped, error, started_at, finished_at FROM import_jobs WHERE account_id = ? ORDER BY id DESC LIMIT 50",
    )
    .bind(account_id)
    .fetch_all(&app.db)
    .await
}

async fn create_job(app: &AppState, account_id: i64, kind: &str, source: &str) -> Result<i64, String> {
    let running: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM import_jobs WHERE account_id = ? AND status = 'running'")
        .bind(account_id)
        .fetch_one(&app.db)
        .await
        .map_err(|_| "database error")?;
    if running > 0 {
        return Err("an import is already running for this mailbox".into());
    }
    Ok(sqlx::query("INSERT INTO import_jobs (account_id, kind, source, started_at) VALUES (?, ?, ?, ?)")
        .bind(account_id)
        .bind(kind)
        .bind(crate::util::sanitize_line(source))
        .bind(now())
        .execute(&app.db)
        .await
        .map_err(|_| "database error")?
        .last_insert_rowid())
}

/// Shared bookkeeping of a running import.
struct Progress {
    app: AppState,
    account_id: i64,
    job: i64,
    imported: i64,
    skipped: i64,
}

impl Progress {
    async fn flush(&self) {
        let _ = sqlx::query("UPDATE import_jobs SET imported = ?, skipped = ? WHERE id = ?")
            .bind(self.imported)
            .bind(self.skipped)
            .bind(self.job)
            .execute(&self.app.db)
            .await;
    }

    /// Finds the local mailbox for a source folder, creating it when needed.
    async fn mailbox(&self, name: &str, role: Option<&str>) -> Result<i64, String> {
        let store = &self.app.store;
        let found = match role {
            Some(role) => store.mailbox_by_role(self.account_id, role).await,
            None => store.mailbox_by_name(self.account_id, name).await,
        }
        .map_err(|e| e.to_string())?;
        if let Some(mailbox) = found {
            return Ok(mailbox.id);
        }
        // Names that are not valid here are flattened into a safe one instead of failing.
        let safe: String = if validate_mailbox_name(name).is_ok() {
            name.to_owned()
        } else {
            let cleaned: String = name.chars().filter(|c| !c.is_control() && !matches!(c, '%' | '*' | '\\' | '"')).take(150).collect();
            format!("Imported/{}", cleaned.trim_matches('/').replace("//", "/"))
        };
        match store.create_mailbox(self.account_id, &safe).await {
            Ok(mailbox) => Ok(mailbox.id),
            Err(StoreError::Exists) => store.mailbox_by_name(self.account_id, &safe).await.ok().flatten().map(|m| m.id).ok_or_else(|| "mailbox lookup failed".into()),
            Err(err) => Err(format!("cannot create folder {safe}: {err}")),
        }
    }

    /// Stores one message unless the mailbox already holds a message with the same Message-ID,
    /// which makes repeated imports idempotent.
    async fn store(&mut self, mailbox: i64, raw: &[u8], flags: Flags, keywords: &[String], date: Option<i64>) -> Result<(), String> {
        if raw.is_empty() || raw.len() > self.app.rt().max_message_size {
            self.skipped += 1;
            return Ok(());
        }
        let message_id = crate::store::parse_metadata(raw).message_id;
        if !message_id.is_empty() {
            let exists: Option<i64> = sqlx::query_scalar("SELECT 1 FROM messages WHERE mailbox_id = ? AND message_id = ? LIMIT 1")
                .bind(mailbox)
                .bind(&message_id)
                .fetch_optional(&self.app.db)
                .await
                .map_err(|e| e.to_string())?;
            if exists.is_some() {
                self.skipped += 1;
                return Ok(());
            }
        }
        match self.app.store.append(self.account_id, mailbox, raw, flags, date).await {
            Ok(appended) => {
                if !keywords.is_empty() {
                    let _ = self.app.store.set_flags_and_keywords(self.account_id, appended.id, flags, keywords).await;
                }
                self.imported += 1;
                if self.imported % 25 == 0 {
                    self.flush().await;
                }
                Ok(())
            }
            Err(StoreError::QuotaExceeded) => Err("the mailbox quota is exhausted".into()),
            Err(err) => Err(err.to_string()),
        }
    }
}

async fn finish(progress: &Progress, result: Result<(), String>) {
    let (status, error) = match result {
        Ok(()) => ("completed", None),
        Err(err) => ("failed", Some(crate::util::sanitize_line(&err))),
    };
    let _ = sqlx::query("UPDATE import_jobs SET status = ?, error = ?, imported = ?, skipped = ?, finished_at = ? WHERE id = ?")
        .bind(status)
        .bind(&error)
        .bind(progress.imported)
        .bind(progress.skipped)
        .bind(now())
        .bind(progress.job)
        .execute(&progress.app.db)
        .await;
    crate::db::audit(&progress.app.db, "system", &format!("import.{status}"), &progress.account_id.to_string(), "", error.as_deref().unwrap_or("")).await;
}

fn role_for(name: &str, attributes: &str) -> Option<&'static str> {
    let attributes = attributes.to_ascii_lowercase();
    for (flag, role) in [("\\sent", "sent"), ("\\drafts", "drafts"), ("\\trash", "trash"), ("\\junk", "junk"), ("\\archive", "archive")] {
        if attributes.contains(flag) {
            return Some(role);
        }
    }
    match name.to_ascii_lowercase().as_str() {
        "inbox" => Some("inbox"),
        "sent" | "sent items" | "sent messages" => Some("sent"),
        "drafts" => Some("drafts"),
        "trash" | "deleted items" | "deleted messages" => Some("trash"),
        "junk" | "spam" | "junk e-mail" => Some("junk"),
        "archive" | "archives" => Some("archive"),
        _ => None,
    }
}

/// Splits IMAP flag names into system flags and keywords.
pub fn parse_flag_names(text: &str) -> (Flags, Vec<String>) {
    let mut flags = Flags::default();
    let mut keywords = Vec::new();
    for name in text.split_whitespace() {
        match name.to_ascii_lowercase().as_str() {
            "\\seen" => flags.seen = true,
            "\\answered" => flags.answered = true,
            "\\flagged" => flags.flagged = true,
            "\\draft" => flags.draft = true,
            other if !other.starts_with('\\') && other.len() <= 100 && keywords.len() < 30 && other.bytes().all(|b| b.is_ascii_graphic() && !b"(){]%*\"\\".contains(&b)) => {
                keywords.push(other.to_owned())
            }
            _ => {}
        }
    }
    (flags, keywords)
}

// --- IMAP source --------------------------------------------------------------------------

pub struct ImapSource {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    /// Connect in plaintext and upgrade with STARTTLS (port 143) instead of implicit TLS.
    pub starttls: bool,
    /// Accept self-signed or otherwise unverifiable certificates.
    pub allow_invalid_certificate: bool,
    /// Whether the requester may reach private/internal addresses (super administrators only).
    pub allow_private: bool,
}

struct ImapClient {
    stream: TlsStream<TcpStream>,
    buf: Vec<u8>,
    tag: u32,
}

/// One untagged response, with any literals it carried.
struct Response {
    text: String,
    literals: Vec<Vec<u8>>,
}

fn quote(value: &str) -> Result<String, String> {
    if value.chars().any(|c| c == '\r' || c == '\n' || c == '\0') {
        return Err("credentials and folder names must not contain line breaks".into());
    }
    Ok(format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
}

impl ImapClient {
    async fn fill(&mut self) -> Result<(), String> {
        let mut chunk = [0u8; 16 * 1024];
        let n = tokio::time::timeout(IO_TIMEOUT, self.stream.read(&mut chunk))
            .await
            .map_err(|_| "the remote server stopped responding")?
            .map_err(|e| format!("connection error: {e}"))?;
        if n == 0 {
            return Err("the remote server closed the connection".into());
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(())
    }

    async fn line(&mut self) -> Result<String, String> {
        loop {
            if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=pos).collect();
                return Ok(String::from_utf8_lossy(&line).trim_end().to_owned());
            }
            if self.buf.len() > MAX_LINE {
                return Err("the remote server sent an oversized line".into());
            }
            self.fill().await?;
        }
    }

    async fn exact(&mut self, n: usize) -> Result<Vec<u8>, String> {
        while self.buf.len() < n {
            self.fill().await?;
        }
        Ok(self.buf.drain(..n).collect())
    }

    /// Reads one complete response line including literals announced with `{n}`.
    async fn response(&mut self, max_literal: usize) -> Result<Response, String> {
        let mut text = String::new();
        let mut literals = Vec::new();
        loop {
            let line = self.line().await?;
            let literal = line.strip_suffix('}').and_then(|l| l.rsplit_once('{')).and_then(|(_, n)| n.parse::<usize>().ok());
            text.push_str(&line);
            match literal {
                Some(n) if n > max_literal => return Err("the remote server announced an oversized message".into()),
                Some(n) => literals.push(self.exact(n).await?),
                None => return Ok(Response { text, literals }),
            }
        }
    }

    /// Sends a command and collects the untagged responses until its tagged completion.
    async fn command(&mut self, command: &str, max_literal: usize) -> Result<Vec<Response>, String> {
        self.tag += 1;
        let tag = format!("u{}", self.tag);
        tokio::time::timeout(IO_TIMEOUT, self.stream.write_all(format!("{tag} {command}\r\n").as_bytes()))
            .await
            .map_err(|_| "the remote server stopped responding")?
            .map_err(|e| format!("connection error: {e}"))?;
        let mut responses = Vec::new();
        loop {
            let response = self.response(max_literal).await?;
            if let Some(status) = response.text.strip_prefix(&format!("{tag} ")) {
                if status.to_ascii_uppercase().starts_with("OK") {
                    return Ok(responses);
                }
                // The remote text is untrusted; keep it short and free of control characters.
                return Err(format!("the remote server refused the request: {}", crate::util::sanitize_line(status).chars().take(200).collect::<String>()));
            }
            if responses.len() > 100_000 {
                return Err("the remote server sent too many responses".into());
            }
            responses.push(response);
        }
    }
}

async fn connect(source: &ImapSource) -> Result<ImapClient, String> {
    if crate::util::normalize_domain(&source.host).is_none() && source.host.parse::<std::net::IpAddr>().is_err() {
        return Err("invalid host name".into());
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((source.host.as_str(), source.port)).await.map_err(|e| format!("cannot resolve {}: {e}", source.host))?.collect();
    // The address is resolved once and that exact address is connected to, so a DNS answer
    // cannot change between the check and the connection.
    let addr = *addrs.first().ok_or("the host does not resolve to an address")?;
    if !source.allow_private && addrs.iter().any(|a| is_private(a.ip())) {
        return Err("importing from private or internal addresses is not allowed".into());
    }
    let mut tcp = tokio::time::timeout(Duration::from_secs(20), TcpStream::connect(addr)).await.map_err(|_| "connection timed out")?.map_err(|e| format!("cannot connect: {e}"))?;
    if source.starttls {
        tokio::time::timeout(Duration::from_secs(20), negotiate_starttls(&mut tcp)).await.map_err(|_| "STARTTLS negotiation timed out")??;
    }
    let name = ServerName::try_from(source.host.clone()).map_err(|_| "invalid host name")?;
    let config = crate::smtp::client::tls_config(!source.allow_invalid_certificate);
    let stream = tokio::time::timeout(Duration::from_secs(20), tokio_rustls::TlsConnector::from(config).connect(name, tcp))
        .await
        .map_err(|_| "TLS handshake timed out")?
        .map_err(|e| format!("TLS handshake failed: {e}"))?;
    let mut client = ImapClient { stream, buf: Vec::new(), tag: 0 };
    // With STARTTLS the greeting was already read in plaintext; there is none after the upgrade.
    if !source.starttls {
        let greeting = client.line().await?;
        if !greeting.to_ascii_uppercase().starts_with("* OK") {
            return Err("the remote server did not greet as an IMAP server".into());
        }
    }
    client.command(&format!("LOGIN {} {}", quote(&source.username)?, quote(&source.password)?), 0).await.map_err(|_| "the remote server rejected the credentials".to_owned())?;
    Ok(client)
}

/// Reads one line from the plaintext connection one byte at a time, so that nothing beyond the
/// line is consumed: bytes after the STARTTLS reply belong to the TLS handshake.
async fn plain_line(tcp: &mut TcpStream) -> Result<String, String> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        if tcp.read(&mut byte).await.map_err(|e| format!("connection error: {e}"))? == 0 {
            return Err("the remote server closed the connection".into());
        }
        if byte[0] == b'\n' {
            return Ok(String::from_utf8_lossy(&line).trim_end().to_owned());
        }
        line.push(byte[0]);
        if line.len() > 8192 {
            return Err("the remote server sent an oversized line".into());
        }
    }
}

/// Plaintext part of a STARTTLS connection: greeting, then the upgrade request. Nothing
/// sensitive is sent before the TLS handshake, and the upgrade is mandatory.
async fn negotiate_starttls(tcp: &mut TcpStream) -> Result<(), String> {
    let greeting = plain_line(tcp).await?;
    if !greeting.to_ascii_uppercase().starts_with("* OK") {
        return Err("the remote server did not greet as an IMAP server".into());
    }
    tcp.write_all(b"s1 STARTTLS\r\n").await.map_err(|e| format!("connection error: {e}"))?;
    for _ in 0..20 {
        let line = plain_line(tcp).await?;
        if let Some(status) = line.strip_prefix("s1 ") {
            return if status.to_ascii_uppercase().starts_with("OK") { Ok(()) } else { Err("the remote server does not support STARTTLS".into()) };
        }
    }
    Err("the remote server did not answer STARTTLS".into())
}

/// Parses `* LIST (attrs) "delim" name` into (attributes, delimiter, name).
fn parse_list(response: &Response) -> Option<(String, Option<char>, String)> {
    let rest = response.text.strip_prefix("* LIST (").or_else(|| response.text.strip_prefix("* list ("))?;
    let (attributes, rest) = rest.split_once(')')?;
    let rest = rest.trim_start();
    let (delimiter, rest) = if let Some(rest) = rest.strip_prefix("NIL") {
        (None, rest.trim_start())
    } else {
        let inner = rest.strip_prefix('"')?;
        let c = inner.chars().next()?;
        let c = if c == '\\' { inner.chars().nth(1)? } else { c };
        (Some(c), inner.split_once("\" ")?.1)
    };
    let name = if let Some(literal) = response.literals.first() {
        String::from_utf8_lossy(literal).into_owned()
    } else if let Some(quoted) = rest.strip_prefix('"') {
        quoted.strip_suffix('"')?.replace("\\\"", "\"").replace("\\\\", "\\")
    } else {
        rest.to_owned()
    };
    Some((attributes.to_owned(), delimiter, name))
}

fn fetch_field<'a>(text: &'a str, name: &str, open: char, close: char) -> Option<&'a str> {
    let upper = text.to_ascii_uppercase();
    let start = upper.find(&format!("{name} {open}"))? + name.len() + 2;
    let end = start + text[start..].find(close)?;
    Some(&text[start..end])
}

async fn run_imap(progress: &mut Progress, source: &ImapSource) -> Result<(), String> {
    let max = progress.app.rt().max_message_size;
    let mut client = connect(source).await?;
    let listing = client.command("LIST \"\" \"*\"", 4096).await?;
    let folders: Vec<(String, Option<char>, String)> = listing.iter().filter_map(parse_list).filter(|(attrs, ..)| !attrs.to_ascii_lowercase().contains("\\noselect")).take(MAX_FOLDERS).collect();
    for (attributes, delimiter, remote_name) in folders {
        let decoded = utf7_decode(&remote_name);
        let local_name = match delimiter {
            Some(d) if d != '/' => decoded.replace('/', "_").replace(d, "/"),
            _ => decoded,
        };
        let mailbox = progress.mailbox(&local_name, role_for(&local_name, &attributes)).await?;
        if client.command(&format!("EXAMINE {}", quote(&remote_name)?), 4096).await.is_err() {
            continue;
        }
        let search = client.command("UID SEARCH ALL", 0).await?;
        let uids: Vec<u64> = search
            .iter()
            .filter_map(|r| r.text.strip_prefix("* SEARCH"))
            .flat_map(|list| list.split_whitespace().filter_map(|n| n.parse().ok()).collect::<Vec<u64>>())
            .collect();
        for uid in uids {
            // Messages are fetched one at a time so memory use stays bounded by one message.
            let responses = match client.command(&format!("UID FETCH {uid} (FLAGS INTERNALDATE BODY.PEEK[])"), max.saturating_add(1024)).await {
                Ok(responses) => responses,
                Err(err) if err.contains("oversized message") => return Err(err),
                Err(_) => {
                    progress.skipped += 1;
                    continue;
                }
            };
            let Some(response) = responses.iter().find(|r| r.text.to_ascii_uppercase().contains(" FETCH (") && !r.literals.is_empty()) else {
                progress.skipped += 1;
                continue;
            };
            let (flags, keywords) = parse_flag_names(fetch_field(&response.text, "FLAGS", '(', ')').unwrap_or(""));
            let date = fetch_field(&response.text, "INTERNALDATE", '"', '"').and_then(|d| {
                let format = time::macros::format_description!("[day padding:none]-[month repr:short]-[year] [hour]:[minute]:[second] [offset_hour sign:mandatory][offset_minute]");
                time::OffsetDateTime::parse(d.trim(), format).ok().map(|t| t.unix_timestamp())
            });
            progress.store(mailbox, &response.literals[response.literals.len() - 1], flags, &keywords, date).await?;
        }
    }
    let _ = client.command("LOGOUT", 0).await;
    Ok(())
}

/// Starts an IMAP import in the background and returns the job id.
pub async fn start_imap(app: &AppState, account_id: i64, source: ImapSource) -> Result<i64, String> {
    if source.username.is_empty() || source.username.len() > 320 || source.password.len() > 512 {
        return Err("invalid credentials".into());
    }
    let job = create_job(app, account_id, "imap", &format!("{}@{}:{}", source.username, source.host, source.port)).await?;
    let mut progress = Progress { app: app.clone(), account_id, job, imported: 0, skipped: 0 };
    tokio::spawn(async move {
        let result = run_imap(&mut progress, &source).await;
        finish(&progress, result).await;
    });
    Ok(job)
}

// --- Maildir source -----------------------------------------------------------------------

/// Resolves a user supplied path inside the import directory, refusing anything that escapes
/// it (absolute paths, `..`, symlinks pointing elsewhere).
pub fn resolve_import_path(base: &Path, relative: &str) -> Result<PathBuf, String> {
    let relative = relative.trim().trim_matches(['/', '\\']);
    if relative.is_empty() || Path::new(relative).components().any(|c| !matches!(c, std::path::Component::Normal(_))) {
        return Err("the path must be a directory name inside the import directory".into());
    }
    let base = base.canonicalize().map_err(|_| "the import directory does not exist; create it and copy the Maildir there".to_owned())?;
    let full = base.join(relative).canonicalize().map_err(|_| "no such directory in the import directory".to_owned())?;
    if !full.starts_with(&base) || !full.is_dir() {
        return Err("the path must be a directory inside the import directory".into());
    }
    Ok(full)
}

/// Flags encoded in a Maildir file name (`...:2,FRS`).
pub fn maildir_flags(file_name: &str) -> Flags {
    let info = file_name.rsplit_once(":2,").or_else(|| file_name.rsplit_once("!2,")).map_or("", |(_, info)| info);
    Flags { seen: info.contains('S'), answered: info.contains('R'), flagged: info.contains('F'), draft: info.contains('D'), deleted: false }
}

/// Maildir++ folder directory name (`.Sent.2025`) to a mailbox name (`Sent/2025`).
pub fn maildir_folder_name(dir: &str) -> Option<String> {
    let name = dir.strip_prefix('.')?;
    (!name.is_empty()).then(|| name.split('.').filter(|part| !part.is_empty()).collect::<Vec<_>>().join("/"))
}

fn regular_files(dir: &Path) -> Vec<(PathBuf, String, i64)> {
    let mut out = Vec::new();
    for sub in ["cur", "new"] {
        let Ok(entries) = std::fs::read_dir(dir.join(sub)) else { continue };
        for entry in entries.flatten() {
            // symlink_metadata: links are never followed out of the import directory.
            let Ok(meta) = entry.path().symlink_metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            let modified = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs() as i64);
            out.push((entry.path(), entry.file_name().to_string_lossy().into_owned(), modified));
        }
    }
    out.sort();
    out
}

async fn run_maildir(progress: &mut Progress, root: &Path) -> Result<(), String> {
    let mut folders: Vec<(PathBuf, String)> = vec![(root.to_path_buf(), "INBOX".to_owned())];
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_dir = entry.path().symlink_metadata().is_ok_and(|m| m.is_dir());
            if let (true, Some(folder)) = (is_dir, maildir_folder_name(&name)) {
                folders.push((entry.path(), folder));
            }
        }
    }
    folders.truncate(MAX_FOLDERS);
    if folders.iter().all(|(dir, _)| !dir.join("cur").is_dir() && !dir.join("new").is_dir()) {
        return Err("the directory is not a Maildir (no cur/ or new/ folder)".into());
    }
    let max = progress.app.rt().max_message_size as u64;
    for (dir, name) in folders {
        let dir_for_scan = dir.clone();
        let files = tokio::task::spawn_blocking(move || regular_files(&dir_for_scan)).await.map_err(|_| "directory scan failed")?;
        if files.is_empty() {
            continue;
        }
        let mailbox = progress.mailbox(&name, role_for(&name, "")).await?;
        for (path, file_name, modified) in files {
            if tokio::fs::metadata(&path).await.map_or(true, |m| m.len() > max) {
                progress.skipped += 1;
                continue;
            }
            let Ok(raw) = tokio::fs::read(&path).await else {
                progress.skipped += 1;
                continue;
            };
            progress.store(mailbox, &raw, maildir_flags(&file_name), &[], (modified > 0).then_some(modified)).await?;
        }
    }
    Ok(())
}

/// Starts a Maildir import from `<data dir>/import/<relative>`.
pub async fn start_maildir(app: &AppState, account_id: i64, relative: &str) -> Result<i64, String> {
    let root = resolve_import_path(&app.cfg.data_dir.join("import"), relative)?;
    let job = create_job(app, account_id, "maildir", relative).await?;
    let mut progress = Progress { app: app.clone(), account_id, job, imported: 0, skipped: 0 };
    tokio::spawn(async move {
        let result = run_maildir(&mut progress, &root).await;
        finish(&progress, result).await;
    });
    Ok(job)
}

/// Marks jobs left over from a previous process as failed.
pub async fn recover(app: &AppState) {
    let _ = sqlx::query("UPDATE import_jobs SET status = 'failed', error = 'interrupted by a server restart', finished_at = ? WHERE status = 'running'")
        .bind(now())
        .execute(&app.db)
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maildir_names_and_flags() {
        assert_eq!(maildir_folder_name(".Sent"), Some("Sent".into()));
        assert_eq!(maildir_folder_name(".Work.Projects.2025"), Some("Work/Projects/2025".into()));
        assert_eq!(maildir_folder_name("cur"), None);
        assert_eq!(maildir_folder_name("."), None);
        let flags = maildir_flags("1700000000.M1P2.host,S=1234:2,FRS");
        assert!(flags.seen && flags.answered && flags.flagged && !flags.draft);
        assert_eq!(maildir_flags("1700000000.M1P2.host"), Flags::default());
    }

    #[test]
    fn import_paths_cannot_escape_the_import_directory() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("import");
        std::fs::create_dir_all(base.join("alice/cur")).unwrap();
        std::fs::create_dir_all(dir.path().join("secret")).unwrap();
        assert!(resolve_import_path(&base, "alice").is_ok());
        assert!(resolve_import_path(&base, "/alice/").is_ok());
        for bad in ["", "..", "../secret", "alice/../../secret", "/etc", "C:\\Windows", "alice/./cur/..", "missing"] {
            assert!(resolve_import_path(&base, bad).is_err(), "{bad:?}");
        }
        assert!(resolve_import_path(&dir.path().join("nope"), "alice").is_err());
    }

    #[test]
    fn list_and_fetch_parsing() {
        let r = |text: &str| Response { text: text.into(), literals: vec![] };
        assert_eq!(parse_list(&r("* LIST (\\HasNoChildren \\Sent) \"/\" \"Sent Items\"")), Some(("\\HasNoChildren \\Sent".into(), Some('/'), "Sent Items".into())));
        assert_eq!(parse_list(&r("* LIST () \".\" INBOX.Work")), Some(("".into(), Some('.'), "INBOX.Work".into())));
        assert_eq!(parse_list(&r("* LIST (\\Noselect) NIL Shared")), Some(("\\Noselect".into(), None, "Shared".into())));
        assert_eq!(parse_list(&r("* OK nothing")), None);
        let text = "* 3 FETCH (UID 7 FLAGS (\\Seen $Forwarded) INTERNALDATE \"05-Oct-2026 10:00:00 +0000\" BODY[] {12}";
        assert_eq!(fetch_field(text, "FLAGS", '(', ')'), Some("\\Seen $Forwarded"));
        assert_eq!(fetch_field(text, "INTERNALDATE", '"', '"'), Some("05-Oct-2026 10:00:00 +0000"));
        let (flags, keywords) = parse_flag_names("\\Seen $Forwarded \\Recent bad(flag");
        assert!(flags.seen && keywords == ["$forwarded"]);
        assert!(quote("pass\r\nA1 DELETE INBOX").is_err(), "credentials cannot inject commands");
        assert_eq!(quote("p\"a\\ss").unwrap(), "\"p\\\"a\\\\ss\"");
        assert_eq!(role_for("Spam", ""), Some("junk"));
        assert_eq!(role_for("Whatever", "\\HasNoChildren \\Trash"), Some("trash"));
        assert_eq!(role_for("Projects", ""), None);
    }
}
