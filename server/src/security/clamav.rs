//! Direct ClamAV scanning over clamd's INSTREAM protocol.
//!
//! Rspamd already passes attachments to ClamAV; this second pass hands the complete raw message
//! to clamd, whose own mail parser also inspects message bodies and nested content.

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::app::App;

const TIMEOUT: Duration = Duration::from_secs(60);
const CHUNK: usize = 64 * 1024;

trait ScanIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> ScanIo for T {}

async fn connect(addr: &str) -> std::io::Result<Box<dyn ScanIo>> {
    if let Some(path) = addr.strip_prefix("unix:") {
        #[cfg(unix)]
        return Ok(Box::new(tokio::net::UnixStream::connect(path).await?));
        #[cfg(not(unix))]
        return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, format!("Unix socket is unavailable: {path}")));
    }
    Ok(Box::new(TcpStream::connect(addr).await?))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    /// Signature name reported by ClamAV.
    Infected(String),
}

/// The scanner is configured but did not give a usable answer.
#[derive(Debug)]
pub struct Unavailable(pub String);

/// Interprets clamd's reply to INSTREAM, e.g. `stream: Eicar-Signature FOUND`.
pub fn parse_reply(reply: &str) -> Result<Verdict, Unavailable> {
    let reply = reply.trim_matches(['\0', '\n', '\r', ' ']);
    let body = reply.strip_prefix("stream: ").unwrap_or(reply);
    if body == "OK" {
        Ok(Verdict::Clean)
    } else if let Some(name) = body.strip_suffix(" FOUND") {
        Ok(Verdict::Infected(crate::util::sanitize_line(name)))
    } else {
        Err(Unavailable(crate::util::sanitize_line(reply)))
    }
}

async fn instream(addr: &str, raw: &[u8]) -> Result<Verdict, Unavailable> {
    let io = |e: std::io::Error| Unavailable(e.to_string());
    let mut stream = connect(addr).await.map_err(io)?;
    stream.write_all(b"zINSTREAM\0").await.map_err(io)?;
    for chunk in raw.chunks(CHUNK) {
        stream.write_all(&(chunk.len() as u32).to_be_bytes()).await.map_err(io)?;
        stream.write_all(chunk).await.map_err(io)?;
    }
    stream.write_all(&0u32.to_be_bytes()).await.map_err(io)?;
    stream.flush().await.map_err(io)?;
    let mut reply = Vec::new();
    stream.take(4096).read_to_end(&mut reply).await.map_err(io)?;
    parse_reply(&String::from_utf8_lossy(&reply))
}

/// Whether clamd answers its PING command.
pub async fn ping(addr: &str) -> bool {
    let attempt = async {
        let mut stream = connect(addr).await.ok()?;
        stream.write_all(b"zPING\0").await.ok()?;
        let mut reply = Vec::new();
        (&mut stream).take(64).read_to_end(&mut reply).await.ok()?;
        Some(reply.starts_with(b"PONG"))
    };
    matches!(tokio::time::timeout(Duration::from_secs(3), attempt).await, Ok(Some(true)))
}

/// Most text parts scanned individually per message.
const MAX_PARTS: usize = 30;

/// The decoded text and HTML parts of a message, trimmed, for individual scanning.
pub fn text_parts(raw: &[u8]) -> Vec<Vec<u8>> {
    let Some(message) = mail_parser::MessageParser::default().parse(raw) else { return Vec::new() };
    message
        .parts
        .iter()
        .filter_map(|part| match &part.body {
            mail_parser::PartType::Text(text) | mail_parser::PartType::Html(text) => Some(text.trim().as_bytes().to_vec()),
            _ => None,
        })
        .filter(|content| !content.is_empty())
        .take(MAX_PARTS)
        .collect()
}

/// Scans the complete message and then each decoded text part on its own. ClamAV judges a
/// mail file as a container and does not treat its plain body as a file, so content that is
/// only malicious as a standalone file (scripts, test signatures) is caught by the second pass.
async fn scan_all(addr: &str, raw: &[u8]) -> Result<Verdict, Unavailable> {
    if let Verdict::Infected(name) = instream(addr, raw).await? {
        return Ok(Verdict::Infected(name));
    }
    for part in text_parts(raw) {
        if let Verdict::Infected(name) = instream(addr, &part).await? {
            return Ok(Verdict::Infected(name));
        }
    }
    Ok(Verdict::Clean)
}

/// Scans a message. `Ok(None)` means no scanner is configured. When the scanner cannot be
/// reached the message is deferred by the caller, unless fail-open is enabled.
pub async fn scan(app: &App, raw: &[u8]) -> Result<Option<Verdict>, Unavailable> {
    let Some(addr) = app.cfg.clamav_addr.as_deref() else { return Ok(None) };
    let result = match tokio::time::timeout(TIMEOUT, scan_all(addr, raw)).await {
        Ok(result) => result,
        Err(_) => Err(Unavailable("timed out".into())),
    };
    match result {
        Ok(verdict) => Ok(Some(verdict)),
        Err(Unavailable(reason)) if app.rt().rspamd_fail_open => {
            tracing::warn!(reason, "virus scanner unavailable, accepting message unscanned (fail-open)");
            Ok(None)
        }
        Err(err) => {
            tracing::warn!(reason = err.0, "virus scanner unavailable, deferring message");
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_parts_are_extracted_decoded_and_trimmed() {
        let raw = b"From: a@b.example\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8gd29ybGQ=\r\n--B\r\nContent-Type: text/html\r\n\r\n<p>hi</p>\r\n\r\n--B\r\nContent-Type: application/pdf\r\n\r\nJVBERi0=\r\n--B--\r\n";
        assert_eq!(text_parts(raw), vec![b"hello world".to_vec(), b"<p>hi</p>".to_vec()]);
        assert_eq!(text_parts(b"Subject: x\r\n\r\n  payload  \r\n"), vec![b"payload".to_vec()]);
        assert!(text_parts(b"").is_empty());
    }

    #[test]
    fn replies() {
        assert_eq!(parse_reply("stream: OK\0").unwrap(), Verdict::Clean);
        assert_eq!(parse_reply("stream: Win.Test.EICAR_HDB-1 FOUND\0").unwrap(), Verdict::Infected("Win.Test.EICAR_HDB-1".into()));
        assert!(parse_reply("INSTREAM size limit exceeded. ERROR\0").is_err());
        assert!(parse_reply("").is_err());
        // The signature name ends up in logs and SMTP replies; it cannot carry line breaks.
        assert_eq!(parse_reply("stream: Evil\r\n250 OK FOUND").unwrap(), Verdict::Infected("Evil250 OK".into()));
    }
}
