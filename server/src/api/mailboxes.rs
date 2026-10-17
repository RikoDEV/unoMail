//! Folder-level operations of the web client: exporting and importing messages, sharing a
//! folder with other users, and fetching remote images on the reader's behalf.

use std::net::SocketAddr;

use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use time::{OffsetDateTime, macros::format_description};

use super::{JsonResult, Session};
use crate::{
    app::AppState,
    error::ApiError,
    security::reputation::is_private,
    sharing::{self, AclError},
    store::{Flags, Mailbox},
};

/// A mailbox the session may use, requiring every right in `needed`.
async fn mailbox_with(state: &AppState, session: &Session, id: i64, needed: &str) -> Result<Mailbox, ApiError> {
    let (mailbox, rights) = sharing::mailbox(&state.db, &session.account, id).await?.ok_or(ApiError::NotFound)?;
    if needed.chars().all(|right| rights.contains(right)) { Ok(mailbox) } else { Err(ApiError::Forbidden) }
}

// --- Export --------------------------------------------------------------------------------

/// Converts a stored message to its mbox form: LF line endings and `From ` lines quoted
/// (the "mboxrd" convention, which is reversible).
pub fn to_mbox_entry(sender: &str, date: i64, raw: &[u8]) -> Vec<u8> {
    let format = format_description!("[weekday repr:short] [month repr:short] [day padding:space] [hour]:[minute]:[second] [year]");
    let stamp = OffsetDateTime::from_unix_timestamp(date).ok().and_then(|t| t.format(&format).ok()).unwrap_or_else(|| "Thu Jan  1 00:00:00 1970".into());
    let sender = if sender.is_empty() || sender.contains(char::is_whitespace) { "MAILER-DAEMON" } else { sender };
    let mut out = format!("From {sender} {stamp}\n").into_bytes();
    for line in raw.split_inclusive(|b| *b == b'\n') {
        let content = line.strip_suffix(b"\n").unwrap_or(line);
        let content = content.strip_suffix(b"\r").unwrap_or(content);
        let unquoted = &content[content.iter().take_while(|b| **b == b'>').count()..];
        if unquoted.starts_with(b"From ") {
            out.push(b'>');
        }
        out.extend_from_slice(content);
        out.push(b'\n');
    }
    out.push(b'\n');
    out
}

/// Splits an mbox file into messages with CRLF line endings, undoing the `From ` quoting.
pub fn parse_mbox(data: &[u8]) -> Vec<Vec<u8>> {
    let mut messages: Vec<Vec<u8>> = Vec::new();
    let mut current: Option<Vec<u8>> = None;
    let mut previous_blank = true;
    for line in data.split_inclusive(|b| *b == b'\n') {
        let content = line.strip_suffix(b"\n").unwrap_or(line);
        let content = content.strip_suffix(b"\r").unwrap_or(content);
        if previous_blank && content.starts_with(b"From ") {
            if let Some(done) = current.take() {
                messages.push(done);
            }
            current = Some(Vec::new());
            previous_blank = false;
            continue;
        }
        previous_blank = content.is_empty();
        let Some(message) = current.as_mut() else { continue };
        let quotes = content.iter().take_while(|b| **b == b'>').count();
        let unquoted = if quotes > 0 && content[quotes..].starts_with(b"From ") { &content[1..] } else { content };
        message.extend_from_slice(unquoted);
        message.extend_from_slice(b"\r\n");
    }
    messages.extend(current);
    // The blank line that separates entries is not part of the message.
    for message in &mut messages {
        while message.ends_with(b"\r\n\r\n") {
            message.truncate(message.len() - 2);
        }
    }
    messages.into_iter().filter(|m| !m.is_empty()).collect()
}

/// Downloads a folder as an mbox file.
pub async fn export(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> Result<Response, ApiError> {
    let mailbox = mailbox_with(&state, &session, id, "r").await?;
    let rows: Vec<(String, String, i64)> = sqlx::query_as("SELECT blob_hash, from_addr, internal_date FROM messages WHERE mailbox_id = ? ORDER BY uid")
        .bind(mailbox.id)
        .fetch_all(&state.db)
        .await?;
    let store = state.store.clone();
    // Messages are read one at a time so that large folders are never held in memory at once.
    let stream = futures_util::stream::iter(rows).then(move |(hash, sender, date)| {
        let store = store.clone();
        async move { store.read_blob(&hash).await.map(|raw| Bytes::from(to_mbox_entry(&sender, date, &raw))).map_err(std::io::Error::other) }
    });
    let name: String = mailbox.name.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') { c } else { '_' }).take(80).collect();
    let mut response = Body::from_stream(stream).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/mbox"));
    headers.insert(header::CONTENT_DISPOSITION, HeaderValue::from_str(&format!("attachment; filename=\"{name}.mbox\"")).unwrap_or(HeaderValue::from_static("attachment")));
    session.audit(&state, "mailbox.exported", &mailbox.name, "").await;
    Ok(response)
}

// --- Import --------------------------------------------------------------------------------

/// Adds messages from an uploaded `.eml` file or mbox archive to a folder.
pub async fn import(State(state): State<AppState>, session: Session, Path(id): Path<i64>, body: Bytes) -> JsonResult<Value> {
    let mailbox = mailbox_with(&state, &session, id, "i").await?;
    if body.is_empty() {
        return Err(ApiError::bad("the file is empty"));
    }
    let messages = if body.starts_with(b"From ") { parse_mbox(&body) } else { vec![body.to_vec()] };
    let limit = state.rt().max_message_size;
    let (mut imported, mut skipped) = (0, 0);
    for raw in messages {
        // Anything that is not a message with headers (or is too large) is skipped, not stored.
        let parsed = mail_parser::MessageParser::default().parse_headers(&raw[..]);
        if raw.len() > limit || parsed.is_none_or(|m| m.from().is_none() && m.subject().is_none() && m.date().is_none()) {
            skipped += 1;
            continue;
        }
        let meta = crate::store::parse_metadata(&raw);
        if !meta.message_id.is_empty() {
            let exists: Option<i64> = sqlx::query_scalar("SELECT 1 FROM messages WHERE mailbox_id = ? AND message_id = ? LIMIT 1").bind(mailbox.id).bind(&meta.message_id).fetch_optional(&state.db).await?;
            if exists.is_some() {
                skipped += 1;
                continue;
            }
        }
        let date = (meta.sent_date > 0).then_some(meta.sent_date);
        state.store.append(mailbox.account_id, mailbox.id, &raw, Flags { seen: true, ..Default::default() }, date).await?;
        imported += 1;
    }
    session.audit(&state, "mailbox.imported", &mailbox.name, &imported.to_string()).await;
    Ok(Json(json!({ "imported": imported, "skipped": skipped })))
}

// --- Sharing -------------------------------------------------------------------------------

fn acl_error(err: AclError) -> ApiError {
    match err {
        AclError::Db(err) => err.into(),
        other => ApiError::bad(other.to_string()),
    }
}

async fn acl_json(state: &AppState, mailbox: &Mailbox) -> Result<Value, ApiError> {
    let entries = sharing::list(&state.db, mailbox).await?;
    // The first entry is the owner, who is not part of the editable list.
    Ok(json!(entries.into_iter().skip(1).map(|(identifier, rights)| json!({ "identifier": identifier, "rights": rights })).collect::<Vec<_>>()))
}

pub async fn acl_get(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    let mailbox = mailbox_with(&state, &session, id, "a").await?;
    Ok(Json(acl_json(&state, &mailbox).await?))
}

#[derive(Deserialize)]
pub struct AclEntry {
    identifier: String,
    /// Empty removes the entry.
    rights: String,
}

/// Grants, changes or revokes one user's access to a folder.
pub async fn acl_put(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(entry): Json<AclEntry>) -> JsonResult<Value> {
    let mailbox = mailbox_with(&state, &session, id, "a").await?;
    let rights = sharing::normalize_rights(&entry.rights).ok_or_else(|| ApiError::bad("invalid rights"))?;
    sharing::set(&state.db, &mailbox, &entry.identifier, &rights).await.map_err(acl_error)?;
    session.audit(&state, "mailbox.shared", &mailbox.name, &format!("{} {}", crate::util::sanitize_line(&entry.identifier), rights)).await;
    Ok(Json(acl_json(&state, &mailbox).await?))
}

// --- Remote images -------------------------------------------------------------------------

const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;
const MAX_REDIRECTS: usize = 3;
const IMAGE_PORTS: [u16; 4] = [80, 443, 8080, 8443];

#[derive(Deserialize)]
pub struct ImageQuery {
    url: String,
}

/// Identifies an image by its leading bytes; the declared content type alone is not trusted.
pub(crate) fn sniff_image(data: &[u8]) -> Option<&'static str> {
    match data {
        [0x89, b'P', b'N', b'G', ..] => Some("image/png"),
        [0xff, 0xd8, 0xff, ..] => Some("image/jpeg"),
        [b'G', b'I', b'F', b'8', ..] => Some("image/gif"),
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => Some("image/webp"),
        _ => None,
    }
}

/// Resolves the host of `url` and returns the address to connect to, refusing anything that is
/// not a public web server.
pub(crate) async fn public_target(state: &crate::app::App, url: &reqwest::Url, ports: &[u16]) -> Result<(String, SocketAddr), ApiError> {
    let refuse = || ApiError::bad("this address cannot be reached");
    if !matches!(url.scheme(), "http" | "https") || !url.username().is_empty() || url.password().is_some() {
        return Err(refuse());
    }
    let host = url.host_str().ok_or_else(refuse)?.trim_matches(['[', ']']).to_owned();
    let port = url.port_or_known_default().ok_or_else(refuse)?;
    let lenient = state.cfg.allow_private_destinations;
    if !lenient && !ports.contains(&port) {
        return Err(refuse());
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port)).await.map_err(|_| refuse())?.collect();
    // Every address must be public: the server must not become a way to reach internal hosts.
    if addrs.is_empty() || (!lenient && addrs.iter().any(|a| is_private(a.ip()))) {
        return Err(refuse());
    }
    Ok((host, addrs[0]))
}

/// Downloads a small public resource for the server's own use (a logo, a certificate),
/// following a few redirects. Every hop is checked like any other outbound request, and the
/// connection goes to exactly the address that was checked.
pub(crate) async fn fetch_public(state: &crate::app::App, url: reqwest::Url, ports: &[u16], limit: usize, accept: &str) -> Result<Vec<u8>, ApiError> {
    fetch_public_with(state, url, ports, limit, accept, MAX_REDIRECTS).await
}

/// [`fetch_public`] without following redirects (MTA-STS policies must be served in place).
pub(crate) async fn fetch_public_strict(state: &crate::app::App, url: reqwest::Url, ports: &[u16], limit: usize, accept: &str) -> Result<Vec<u8>, ApiError> {
    fetch_public_with(state, url, ports, limit, accept, 0).await
}

async fn fetch_public_with(state: &crate::app::App, mut url: reqwest::Url, ports: &[u16], limit: usize, accept: &str, redirects: usize) -> Result<Vec<u8>, ApiError> {
    for _ in 0..=redirects {
        let (host, addr) = public_target(state, &url, ports).await?;
        let client = reqwest::Client::builder()
            .use_preconfigured_tls((*crate::smtp::client::tls_config(true)).clone())
            .resolve(&host, addr)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(8))
            .build()
            .map_err(anyhow::Error::from)?;
        let mut response = client.get(url.clone()).header(header::USER_AGENT, "unoMail").header(header::ACCEPT, accept).send().await.map_err(|_| ApiError::NotFound)?;
        if response.status().is_redirection() {
            let location = response.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()).ok_or(ApiError::NotFound)?;
            url = url.join(location).map_err(|_| ApiError::NotFound)?;
            continue;
        }
        if !response.status().is_success() {
            return Err(ApiError::NotFound);
        }
        let mut data = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| ApiError::NotFound)? {
            if data.len() + chunk.len() > limit {
                return Err(ApiError::TooLarge);
            }
            data.extend_from_slice(&chunk);
        }
        return Ok(data);
    }
    Err(ApiError::NotFound)
}

/// Fetches a remote image for the reader. The sender only ever sees the server's address, no
/// cookies and no referrer, and the browser never contacts the remote host itself.
pub async fn image_proxy(State(state): State<AppState>, _session: Session, Query(query): Query<ImageQuery>) -> Result<Response, ApiError> {
    let invalid = || ApiError::bad("this image address cannot be loaded");
    let mut url = reqwest::Url::parse(query.url.trim()).map_err(|_| invalid())?;
    for _ in 0..=MAX_REDIRECTS {
        let (host, addr) = public_target(&state, &url, &IMAGE_PORTS).await?;
        // The connection goes to exactly the address that was checked.
        let client = reqwest::Client::builder()
            .use_preconfigured_tls((*crate::smtp::client::tls_config(true)).clone())
            .resolve(&host, addr)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(anyhow::Error::from)?;
        let mut response = client.get(url.clone()).header(header::USER_AGENT, "unoMail image proxy").header(header::ACCEPT, "image/*").send().await.map_err(|_| ApiError::NotFound)?;
        if response.status().is_redirection() {
            let location = response.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()).ok_or_else(invalid)?;
            url = url.join(location).map_err(|_| invalid())?;
            continue;
        }
        if !response.status().is_success() {
            return Err(ApiError::NotFound);
        }
        let mut data = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| ApiError::NotFound)? {
            if data.len() + chunk.len() > MAX_IMAGE_BYTES {
                return Err(ApiError::TooLarge);
            }
            data.extend_from_slice(&chunk);
        }
        let content_type = sniff_image(&data).ok_or_else(|| ApiError::bad("the address does not point to an image"))?;
        return Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, content_type), (header::CONTENT_SECURITY_POLICY, "default-src 'none'; sandbox")],
            data,
        )
            .into_response());
    }
    Err(invalid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mbox_round_trip_preserves_from_lines() {
        let first = b"From: a@example.org\r\nSubject: One\r\n\r\nHello\r\nFrom the start\r\n>From quoted\r\n";
        let second = b"From: b@example.org\r\nSubject: Two\r\n\r\nBye\r\n";
        let mut mbox = to_mbox_entry("a@example.org", 0, first);
        mbox.extend(to_mbox_entry("", 86_400, second));
        let text = String::from_utf8(mbox.clone()).unwrap();
        assert!(text.starts_with("From a@example.org Thu Jan  1 00:00:00 1970\nFrom: a@example.org\n"));
        assert!(text.contains("\n>From the start\n>>From quoted\n"));
        assert!(text.contains("\nFrom MAILER-DAEMON Fri Jan  2 00:00:00 1970\n"));
        assert_eq!(parse_mbox(&mbox), vec![first.to_vec(), second.to_vec()]);
    }

    #[test]
    fn mbox_parsing_ignores_garbage_before_the_first_message() {
        assert!(parse_mbox(b"not an mbox\nat all\n").is_empty());
        let parsed = parse_mbox(b"From x Thu Jan  1 00:00:00 1970\r\nSubject: crlf\r\n\r\nbody\r\n\r\nFrom y Thu Jan  1 00:00:00 1970\nSubject: second\n\ntext\nFrom inside is not a separator\n");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], b"Subject: crlf\r\n\r\nbody\r\n");
        assert_eq!(parsed[1], b"Subject: second\r\n\r\ntext\r\nFrom inside is not a separator\r\n");
    }

    #[test]
    fn images_are_recognised_by_content() {
        assert_eq!(sniff_image(b"\x89PNG\r\n\x1a\n...."), Some("image/png"));
        assert_eq!(sniff_image(b"GIF89a"), Some("image/gif"));
        assert_eq!(sniff_image(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(sniff_image(b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>"), None);
        assert_eq!(sniff_image(b"<html>"), None);
    }
}
