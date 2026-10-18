//! POP3 server (RFC 1939) over implicit TLS (port 995).

use std::{collections::HashSet, net::SocketAddr, time::Duration};

use tokio::net::{TcpListener, TcpStream};

use crate::{
    app::{AppState, Metrics},
    auth::{self, Account, AuthError, Protocol},
    net::{Conn, ReadError},
    store::Message,
};

const IDLE_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_LINE: usize = 512;
const MAX_ERRORS: u32 = 10;

struct Session {
    app: AppState,
    conn: Conn,
    peer: SocketAddr,
    user: Option<String>,
    account: Option<Account>,
    /// What the account signed in with, checked again now and then.
    grant: Option<auth::Grant>,
    /// Snapshot of the INBOX taken at login; message numbers index into it (1-based).
    messages: Vec<Message>,
    deleted: HashSet<usize>,
    errors: u32,
}

/// Byte-stuffs a message for a multi-line response and appends the terminating dot line.
pub fn stuff(raw: &[u8], max_body_lines: Option<usize>) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 64);
    let mut in_body = false;
    let mut body_lines = 0;
    for line in raw.split_inclusive(|b| *b == b'\n') {
        let content = line.strip_suffix(b"\n").unwrap_or(line);
        let content = content.strip_suffix(b"\r").unwrap_or(content);
        if in_body {
            if max_body_lines.is_some_and(|max| body_lines >= max) {
                break;
            }
            body_lines += 1;
        } else if content.is_empty() {
            in_body = true;
        }
        if content.first() == Some(&b'.') {
            out.push(b'.');
        }
        out.extend_from_slice(content);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

impl Session {
    async fn ok(&mut self, text: &str) -> std::io::Result<()> {
        self.conn.write_all(format!("+OK {text}\r\n").as_bytes()).await
    }

    async fn err(&mut self, text: &str) -> std::io::Result<()> {
        self.errors += 1;
        self.conn.write_all(format!("-ERR {text}\r\n").as_bytes()).await
    }

    /// Resolves a 1-based message number to a live (not deleted) message.
    fn message(&self, arg: &str) -> Option<(usize, &Message)> {
        let number: usize = arg.trim().parse().ok()?;
        let index = number.checked_sub(1)?;
        if self.deleted.contains(&index) {
            return None;
        }
        self.messages.get(index).map(|m| (index, m))
    }

    fn live(&self) -> impl Iterator<Item = (usize, &Message)> {
        self.messages.iter().enumerate().filter(|(i, _)| !self.deleted.contains(i))
    }

    async fn login(&mut self, password: &str) -> std::io::Result<bool> {
        let Some(user) = self.user.take() else {
            self.err("USER first").await?;
            return Ok(true);
        };
        match auth::authenticate_with(&self.app.db, &self.app.limiter, &user, password, self.peer.ip(), Protocol::Pop3).await {
            Ok((account, credential)) => {
                let inbox = match self.app.store.mailbox_by_role(account.id, "inbox").await {
                    Ok(Some(inbox)) => inbox,
                    _ => {
                        self.err("[SYS/TEMP] mailbox unavailable").await?;
                        return Ok(false);
                    }
                };
                self.messages = self.app.store.messages_in(inbox.id).await.unwrap_or_default();
                self.grant = Some(auth::Grant::new(&account, Protocol::Pop3, Some(credential)));
                self.account = Some(account);
                self.ok(&format!("{} messages", self.messages.len())).await?;
                Ok(true)
            }
            Err(AuthError::RateLimited) => {
                self.err("[AUTH] too many failed attempts, try again later").await?;
                Ok(false)
            }
            Err(_) => {
                Metrics::inc(&self.app.metrics.auth_failures);
                self.err("[AUTH] invalid credentials").await?;
                Ok(true)
            }
        }
    }

    async fn retrieve(&mut self, arg: &str, lines: Option<usize>) -> std::io::Result<()> {
        let Some((_, message)) = self.message(arg) else {
            return self.err("no such message").await;
        };
        let (hash, size) = (message.blob_hash.clone(), message.size);
        match self.app.store.read_blob(&hash).await {
            Ok(raw) => {
                let mut out = format!("+OK {size} octets\r\n").into_bytes();
                out.extend_from_slice(&stuff(&raw, lines));
                self.conn.write_all(&out).await
            }
            Err(err) => {
                tracing::error!(%err, "POP3 message content is missing");
                self.err("[SYS/TEMP] message unavailable").await
            }
        }
    }

    async fn run(mut self) -> std::io::Result<()> {
        self.ok(&format!("{} POP3 server ready", self.app.cfg.hostname)).await?;
        loop {
            if self.errors >= MAX_ERRORS {
                return self.err("too many errors").await;
            }
            let line = match self.conn.read_line(MAX_LINE).await {
                Ok(line) => line,
                Err(ReadError::TooLong) => return self.err("line too long").await,
                Err(_) => return Ok(()),
            };
            if let Some(grant) = self.grant.as_mut()
                && !grant.recheck(&self.app).await
            {
                // Nothing marked for deletion is removed: the session did not end properly.
                return self.conn.write_all(b"-ERR [AUTH] the sign-in is no longer valid\r\n").await;
            }
            let Ok(line) = String::from_utf8(line) else {
                self.err("invalid command").await?;
                continue;
            };
            let (verb, arg) = line.split_once(' ').unwrap_or((&line, ""));
            let verb = verb.to_ascii_uppercase();

            // Commands valid in any state.
            match verb.as_str() {
                "CAPA" => {
                    self.conn.write_all(b"+OK capabilities\r\nUSER\r\nUIDL\r\nTOP\r\nRESP-CODES\r\nAUTH-RESP-CODE\r\nPIPELINING\r\n.\r\n").await?;
                    continue;
                }
                "NOOP" => {
                    self.ok("").await?;
                    continue;
                }
                "QUIT" => {
                    return self.quit().await;
                }
                _ => {}
            }

            if self.account.is_none() {
                match verb.as_str() {
                    "USER" if !arg.trim().is_empty() => {
                        self.user = Some(arg.trim().to_owned());
                        // The same reply whether or not the mailbox exists.
                        self.ok("send PASS").await?;
                    }
                    "PASS" => {
                        if !self.login(arg).await? {
                            return Ok(());
                        }
                    }
                    _ => self.err("authenticate first").await?,
                }
                continue;
            }

            match verb.as_str() {
                "STAT" => {
                    let (count, size) = self.live().fold((0, 0), |(c, s), (_, m)| (c + 1, s + m.size));
                    self.ok(&format!("{count} {size}")).await?;
                }
                "LIST" | "UIDL" => {
                    let describe = |index: usize, m: &Message| if verb == "LIST" { format!("{} {}", index + 1, m.size) } else { format!("{} {}", index + 1, m.id) };
                    if arg.trim().is_empty() {
                        let mut out = String::from("+OK\r\n");
                        for (index, message) in self.live() {
                            out.push_str(&describe(index, message));
                            out.push_str("\r\n");
                        }
                        out.push_str(".\r\n");
                        self.conn.write_all(out.as_bytes()).await?;
                    } else {
                        match self.message(arg).map(|(i, m)| describe(i, m)) {
                            Some(text) => self.ok(&text).await?,
                            None => self.err("no such message").await?,
                        }
                    }
                }
                "RETR" => self.retrieve(arg, None).await?,
                "TOP" => {
                    let mut parts = arg.split_whitespace();
                    match (parts.next(), parts.next().and_then(|n| n.parse::<usize>().ok())) {
                        (Some(number), Some(lines)) => self.retrieve(number, Some(lines)).await?,
                        _ => self.err("usage: TOP msg lines").await?,
                    }
                }
                "DELE" => match self.message(arg).map(|(index, _)| index) {
                    Some(index) => {
                        self.deleted.insert(index);
                        self.ok("message deleted").await?;
                    }
                    None => self.err("no such message").await?,
                },
                "RSET" => {
                    self.deleted.clear();
                    self.ok("").await?;
                }
                _ => self.err("unknown command").await?,
            }
        }
    }

    /// The UPDATE state: deletions only take effect on a clean QUIT.
    async fn quit(&mut self) -> std::io::Result<()> {
        if let Some(account) = &self.account {
            for index in &self.deleted {
                if let Err(err) = self.app.store.delete_message(account.id, self.messages[*index].id).await {
                    tracing::warn!(%err, "POP3 could not delete message");
                }
            }
        }
        self.ok("bye").await?;
        self.conn.shutdown().await;
        Ok(())
    }
}

async fn handle(app: AppState, tcp: TcpStream, peer: SocketAddr) {
    let Some(_guard) = app.accept_connection(peer.ip()) else { return };
    Metrics::inc(&app.metrics.pop3_connections);
    let _ = tcp.set_nodelay(true);
    let conn = match Conn::accept_tls(tcp, app.tls.server_config(&[]), IDLE_TIMEOUT).await {
        Ok(conn) => conn,
        Err(err) => {
            tracing::debug!(%err, %peer, "TLS handshake failed");
            return;
        }
    };
    let session = Session { app, conn, peer, user: None, account: None, grant: None, messages: Vec::new(), deleted: HashSet::new(), errors: 0 };
    if let Err(err) = session.run().await {
        tracing::debug!(%err, %peer, "POP3 session ended with an error");
    }
}

pub async fn serve(app: AppState, listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                tokio::spawn(handle(app.clone(), tcp, peer));
            }
            Err(err) => {
                tracing::warn!(%err, "failed to accept POP3 connection");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stuffing_and_top() {
        let raw = b"Subject: x\r\n\r\n.hidden\r\nline2\r\nline3\r\n";
        assert_eq!(stuff(raw, None), b"Subject: x\r\n\r\n..hidden\r\nline2\r\nline3\r\n.\r\n");
        assert_eq!(stuff(raw, Some(1)), b"Subject: x\r\n\r\n..hidden\r\n.\r\n");
        assert_eq!(stuff(raw, Some(0)), b"Subject: x\r\n\r\n.\r\n");
        assert_eq!(stuff(b"bare\nlf", None), b"bare\r\nlf\r\n.\r\n");
    }
}
