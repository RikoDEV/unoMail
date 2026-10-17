//! ManageSieve (RFC 5804, port 4190): lets mail programs (Thunderbird's Sieve add-on,
//! Roundcube, K-9, sieve-connect, ...) manage the account's filter scripts. STARTTLS is
//! required before any credentials are accepted.

use std::{net::SocketAddr, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    app::{AppState, Metrics},
    auth::{self, Account, AuthError, Protocol},
    net::{Conn, ReadError},
    sieve::{self, Stored},
};

const LOGIN_TIMEOUT: Duration = Duration::from_secs(60);
const SESSION_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_LINE: usize = 8 * 1024;
pub const MAX_SCRIPT: usize = 64 * 1024;
pub const MAX_SCRIPTS: usize = 20;
const MAX_ERRORS: u32 = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Atom(String),
    Str(Vec<u8>),
}

impl Token {
    fn text(&self) -> Option<String> {
        match self {
            Token::Str(bytes) => String::from_utf8(bytes.clone()).ok(),
            Token::Atom(_) => None,
        }
    }
}

/// Quotes a string for a response.
fn quoted(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\"").replace(['\r', '\n'], " "))
}

/// Splits one line into tokens. A trailing literal marker `{n}` / `{n+}` is returned as its
/// length, for the caller to read the octets and continue.
fn tokenize_line(line: &[u8], tokens: &mut Vec<Token>) -> Result<Option<usize>, &'static str> {
    let mut i = 0;
    while i < line.len() {
        match line[i] {
            b' ' => i += 1,
            b'"' => {
                let mut value = Vec::new();
                i += 1;
                loop {
                    match line.get(i) {
                        None => return Err("unterminated string"),
                        Some(b'"') => {
                            i += 1;
                            break;
                        }
                        Some(b'\\') => {
                            value.push(*line.get(i + 1).ok_or("unterminated string")?);
                            i += 2;
                        }
                        Some(byte) => {
                            value.push(*byte);
                            i += 1;
                        }
                    }
                }
                tokens.push(Token::Str(value));
            }
            b'{' => {
                let end = line[i..].iter().position(|b| *b == b'}').ok_or("bad literal")? + i;
                if end + 1 != line.len() {
                    return Err("a literal must end the line");
                }
                let spec = std::str::from_utf8(&line[i + 1..end]).map_err(|_| "bad literal")?;
                let length = spec.trim_end_matches('+').parse::<usize>().map_err(|_| "bad literal")?;
                return Ok(Some(length));
            }
            _ => {
                let end = line[i..].iter().position(|b| *b == b' ').map_or(line.len(), |p| p + i);
                tokens.push(Token::Atom(String::from_utf8_lossy(&line[i..end]).to_ascii_uppercase()));
                i = end;
            }
        }
    }
    Ok(None)
}

struct Session {
    app: AppState,
    conn: Conn,
    peer: SocketAddr,
    account: Option<Account>,
    /// What the account signed in with, checked again now and then.
    grant: Option<auth::Grant>,
    errors: u32,
    failures: u32,
}

enum Reply {
    Ok(String),
    No(String),
    Bye(String),
    /// The connection was closed after the reply (LOGOUT).
    Closed,
}

impl Session {
    async fn send(&mut self, text: &str) -> std::io::Result<()> {
        self.conn.write_all(text.as_bytes()).await
    }

    fn capabilities(&self) -> String {
        let mut out = String::from("\"IMPLEMENTATION\" \"unoMail\"\r\n");
        // Credentials only over TLS.
        out.push_str(if self.conn.is_tls() && self.account.is_none() { "\"SASL\" \"PLAIN\"\r\n" } else { "\"SASL\" \"\"\r\n" });
        out.push_str(&format!("\"SIEVE\" {}\r\n", quoted(&sieve::SUPPORTED.join(" "))));
        if !self.conn.is_tls() {
            out.push_str("\"STARTTLS\"\r\n");
        }
        out.push_str(&format!("\"MAXREDIRECTS\" \"{}\"\r\n\"OWNER\" {}\r\n", sieve::MAX_REDIRECTS, quoted(self.account.as_ref().map_or("", |a| a.email.as_str()))));
        out.push_str("\"VERSION\" \"1.0\"\r\n");
        out
    }

    /// Reads one command with its literals.
    async fn read_command(&mut self) -> Result<Result<Vec<Token>, &'static str>, ReadError> {
        let mut tokens = Vec::new();
        let mut line = self.conn.read_line(MAX_LINE).await?;
        loop {
            match tokenize_line(&line, &mut tokens) {
                Ok(None) => return Ok(Ok(tokens)),
                Ok(Some(length)) => {
                    let limit = if self.account.is_some() { MAX_SCRIPT } else { 1024 };
                    if length > limit {
                        return Err(ReadError::TooLong);
                    }
                    tokens.push(Token::Str(self.conn.read_exact(length).await?));
                    line = self.conn.read_line(MAX_LINE).await?;
                }
                Err(err) => return Ok(Err(err)),
            }
        }
    }

    async fn run(mut self) -> std::io::Result<()> {
        let greeting = format!("{}OK \"unoMail ManageSieve ready\"\r\n", self.capabilities());
        self.send(&greeting).await?;
        loop {
            if self.errors >= MAX_ERRORS {
                return self.send("BYE \"too many errors\"\r\n").await;
            }
            self.conn.timeout = if self.account.is_some() { SESSION_TIMEOUT } else { LOGIN_TIMEOUT };
            let tokens = match self.read_command().await {
                Ok(Ok(tokens)) if tokens.is_empty() => continue,
                Ok(Ok(tokens)) => tokens,
                Ok(Err(err)) => {
                    self.errors += 1;
                    self.send(&format!("NO {}\r\n", quoted(err))).await?;
                    continue;
                }
                Err(ReadError::TooLong) => return self.send("BYE (QUOTA/MAXSIZE) \"too large\"\r\n").await,
                Err(ReadError::Timeout) => return self.send("BYE \"idle timeout\"\r\n").await,
                Err(_) => return Ok(()),
            };
            let Token::Atom(command) = &tokens[0] else {
                self.errors += 1;
                self.send("NO \"command expected\"\r\n").await?;
                continue;
            };
            let command = command.clone();
            let args = &tokens[1..];
            if self.account.is_some()
                && let Some(grant) = self.grant.as_mut()
                && !grant.recheck(&self.app.db).await
            {
                return self.send("BYE \"the sign-in is no longer valid\"\r\n").await;
            }
            let reply = match self.execute(&command, args).await? {
                Some(reply) => reply,
                None => continue,
            };
            match reply {
                Reply::Ok(text) => self.send(&format!("OK {}\r\n", quoted(&text))).await?,
                Reply::No(text) => {
                    self.errors += 1;
                    // A response code, if any, comes first and unquoted.
                    if text.starts_with('(') {
                        let (code, rest) = text.split_once(") ").unwrap_or((&text, ""));
                        self.send(&format!("NO {code}) {}\r\n", quoted(rest))).await?;
                    } else {
                        self.send(&format!("NO {}\r\n", quoted(&text))).await?;
                    }
                }
                Reply::Closed => return Ok(()),
                Reply::Bye(text) => {
                    self.send(&format!("BYE {}\r\n", quoted(&text))).await?;
                    self.conn.shutdown().await;
                    return Ok(());
                }
            }
        }
    }

    /// Runs one command. `None` when the command already answered (STARTTLS, LOGOUT, ...).
    async fn execute(&mut self, command: &str, args: &[Token]) -> std::io::Result<Option<Reply>> {
        let arg = |i: usize| args.get(i).and_then(Token::text);
        Ok(Some(match command {
            "CAPABILITY" => {
                let capabilities = self.capabilities();
                self.send(&capabilities).await?;
                Reply::Ok("CAPABILITY completed".into())
            }
            "NOOP" => Reply::Ok("NOOP completed".into()),
            "LOGOUT" => {
                self.send("OK \"bye\"\r\n").await?;
                self.conn.shutdown().await;
                Reply::Closed
            }
            "STARTTLS" if !self.conn.is_tls() => {
                if self.conn.has_buffered() {
                    return Ok(Some(Reply::Bye("pipelining after STARTTLS is not allowed".into())));
                }
                self.send("OK \"begin TLS negotiation now\"\r\n").await?;
                let config = self.app.tls.server_config(&[]);
                if self.conn.start_tls(config).await.is_err() {
                    return Ok(Some(Reply::Bye("TLS negotiation failed".into())));
                }
                // The capabilities change after the handshake (RFC 5804 section 2.2).
                let capabilities = format!("{}OK \"TLS active\"\r\n", self.capabilities());
                self.send(&capabilities).await?;
                return Ok(None);
            }
            "STARTTLS" => Reply::No("TLS is already active".into()),
            "AUTHENTICATE" if self.account.is_some() => Reply::No("already authenticated".into()),
            "AUTHENTICATE" if !self.conn.is_tls() => Reply::No("(ENCRYPT-NEEDED) issue STARTTLS first".into()),
            "AUTHENTICATE" => {
                if arg(0).is_none_or(|m| !m.eq_ignore_ascii_case("PLAIN")) {
                    return Ok(Some(Reply::No("unsupported mechanism".into())));
                }
                let response = match arg(1) {
                    Some(initial) => initial,
                    None => {
                        self.send("\"\"\r\n").await?;
                        match self.read_command().await {
                            Ok(Ok(tokens)) => tokens.first().and_then(Token::text).unwrap_or_default(),
                            _ => return Ok(Some(Reply::No("authentication aborted".into()))),
                        }
                    }
                };
                let credentials = STANDARD.decode(response.trim()).ok().and_then(|bytes| {
                    let mut parts = bytes.split(|b| *b == 0);
                    let (_authz, user, pass) = (parts.next()?, parts.next()?, parts.next()?);
                    Some((String::from_utf8(user.to_vec()).ok()?, String::from_utf8(pass.to_vec()).ok()?))
                });
                let Some((user, password)) = credentials else { return Ok(Some(Reply::No("malformed authentication data".into()))) };
                match auth::authenticate_with(&self.app.db, &self.app.limiter, &user, &password, self.peer.ip(), Protocol::Sieve).await {
                    Ok((account, credential)) => {
                        self.grant = Some(auth::Grant::new(&account, Protocol::Sieve, Some(credential)));
                        self.account = Some(account);
                        Reply::Ok("authenticated".into())
                    }
                    Err(AuthError::RateLimited) => Reply::Bye("too many failed attempts, try again later".into()),
                    Err(_) => {
                        Metrics::inc(&self.app.metrics.auth_failures);
                        self.failures += 1;
                        if self.failures >= 3 {
                            Reply::Bye("authentication failed".into())
                        } else {
                            Reply::No("authentication failed".into())
                        }
                    }
                }
            }
            _ if self.account.is_none() => Reply::No("authenticate first".into()),
            "UNAUTHENTICATE" => {
                self.account = None;
                self.grant = None;
                Reply::Ok("unauthenticated".into())
            }
            _ => self.script_command(command, args).await?,
        }))
    }

    async fn script_command(&mut self, command: &str, args: &[Token]) -> std::io::Result<Reply> {
        let account_id = self.account.as_ref().map_or(0, |a| a.id);
        let arg = |i: usize| args.get(i).and_then(Token::text);
        let scripts = match sieve::all(&self.app, account_id).await {
            Ok(scripts) => scripts,
            Err(err) => {
                tracing::error!(%err, "sieve scripts unavailable");
                return Ok(Reply::No("(TRYLATER) internal error".into()));
            }
        };
        let compile = |name: &str, source: &str, scripts: &[Stored], globals: &[Stored]| sieve::compile_among(source, name, scripts, globals).map(|_| ()).map_err(|e| e.to_string());
        Ok(match command {
            "LISTSCRIPTS" => {
                let mut out = String::new();
                for script in &scripts {
                    out.push_str(&quoted(&script.name));
                    if script.active {
                        out.push_str(" ACTIVE");
                    }
                    out.push_str("\r\n");
                }
                self.send(&out).await?;
                Reply::Ok("LISTSCRIPTS completed".into())
            }
            "GETSCRIPT" => match arg(0).and_then(|name| scripts.iter().find(|s| s.name == name)) {
                Some(script) => {
                    let text = format!("{{{}}}\r\n{}\r\n", script.script.len(), script.script);
                    self.send(&text).await?;
                    Reply::Ok("GETSCRIPT completed".into())
                }
                None => Reply::No("(NONEXISTENT) no such script".into()),
            },
            "HAVESPACE" => {
                let (Some(name), Some(Token::Atom(size))) = (arg(0), args.get(1)) else { return Ok(Reply::No("usage: HAVESPACE name size".into())) };
                let size = size.parse::<usize>().unwrap_or(usize::MAX);
                if size > MAX_SCRIPT {
                    Reply::No(format!("(QUOTA/MAXSIZE) scripts may be at most {MAX_SCRIPT} bytes"))
                } else if scripts.len() >= MAX_SCRIPTS && !scripts.iter().any(|s| s.name == name) {
                    Reply::No(format!("(QUOTA/MAXSCRIPTS) at most {MAX_SCRIPTS} scripts"))
                } else {
                    Reply::Ok("putscript would succeed".into())
                }
            }
            "PUTSCRIPT" | "CHECKSCRIPT" => {
                let (name, source) = if command == "PUTSCRIPT" { (arg(0), arg(1)) } else { (Some("checked".into()), arg(0)) };
                let (Some(name), Some(source)) = (name, source) else { return Ok(Reply::No(format!("usage: {command} name script"))) };
                if !sieve::valid_script_name(&name) {
                    return Ok(Reply::No("script names may contain letters, digits, '.', '-' and '_'".into()));
                }
                if command == "PUTSCRIPT" && scripts.len() >= MAX_SCRIPTS && !scripts.iter().any(|s| s.name == name) {
                    return Ok(Reply::No(format!("(QUOTA/MAXSCRIPTS) at most {MAX_SCRIPTS} scripts")));
                }
                let globals = sieve::globals(&self.app).await.unwrap_or_default();
                if let Err(err) = compile(&name, &source, &scripts, &globals) {
                    return Ok(Reply::No(err));
                }
                if command == "CHECKSCRIPT" {
                    return Ok(Reply::Ok("script is valid".into()));
                }
                let active = scripts.iter().any(|s| s.name == name && s.active);
                if let Err(err) = sieve::save(&self.app, account_id, &Stored { name: name.clone(), script: source, active }).await {
                    tracing::error!(%err, "saving a sieve script failed");
                    return Ok(Reply::No("(TRYLATER) internal error".into()));
                }
                self.audit("sieve.updated", &name).await;
                Reply::Ok("PUTSCRIPT completed".into())
            }
            "SETACTIVE" => {
                let Some(name) = arg(0) else { return Ok(Reply::No("usage: SETACTIVE name".into())) };
                let result = if name.is_empty() {
                    sqlx::query("UPDATE sieve_scripts SET active = 0 WHERE account_id = ?").bind(account_id).execute(&self.app.db).await.map(|_| ())
                } else {
                    let Some(script) = scripts.iter().find(|s| s.name == name) else { return Ok(Reply::No("(NONEXISTENT) no such script".into())) };
                    let globals = sieve::globals(&self.app).await.unwrap_or_default();
                    if let Err(err) = compile(&name, &script.script, &scripts, &globals) {
                        return Ok(Reply::No(err));
                    }
                    sieve::save(&self.app, account_id, &Stored { active: true, ..script.clone() }).await
                };
                if result.is_err() {
                    return Ok(Reply::No("(TRYLATER) internal error".into()));
                }
                self.audit("sieve.activated", &name).await;
                Reply::Ok("SETACTIVE completed".into())
            }
            "DELETESCRIPT" => match arg(0).and_then(|name| scripts.iter().find(|s| s.name == name)) {
                Some(script) if script.active => Reply::No("(ACTIVE) deactivate the script first".into()),
                Some(script) => {
                    let name = script.name.clone();
                    let _ = sieve::delete(&self.app, account_id, &name).await;
                    self.audit("sieve.deleted", &name).await;
                    Reply::Ok("DELETESCRIPT completed".into())
                }
                None => Reply::No("(NONEXISTENT) no such script".into()),
            },
            "RENAMESCRIPT" => {
                let (Some(old), Some(new)) = (arg(0), arg(1)) else { return Ok(Reply::No("usage: RENAMESCRIPT old new".into())) };
                if !scripts.iter().any(|s| s.name == old) {
                    return Ok(Reply::No("(NONEXISTENT) no such script".into()));
                }
                if scripts.iter().any(|s| s.name == new) {
                    return Ok(Reply::No("(ALREADYEXISTS) a script with that name exists".into()));
                }
                if !sieve::valid_script_name(&new) {
                    return Ok(Reply::No("script names may contain letters, digits, '.', '-' and '_'".into()));
                }
                match sqlx::query("UPDATE sieve_scripts SET name = ? WHERE account_id = ? AND name = ?").bind(&new).bind(account_id).bind(&old).execute(&self.app.db).await {
                    Ok(_) => Reply::Ok("RENAMESCRIPT completed".into()),
                    Err(_) => Reply::No("(TRYLATER) internal error".into()),
                }
            }
            _ => Reply::No("unknown command".into()),
        })
    }

    async fn audit(&self, action: &str, name: &str) {
        if let Some(account) = &self.account {
            crate::db::audit(&self.app.db, &account.email, action, &account.email, &self.peer.ip().to_string(), name).await;
        }
    }
}

async fn handle(app: AppState, tcp: TcpStream, peer: SocketAddr) {
    let Some(_guard) = app.accept_connection(peer.ip()) else { return };
    let _ = tcp.set_nodelay(true);
    let session = Session { app, conn: Conn::plain(tcp, LOGIN_TIMEOUT), peer, account: None, grant: None, errors: 0, failures: 0 };
    if let Err(err) = session.run().await {
        tracing::debug!(%err, %peer, "ManageSieve session ended with an error");
    }
}

/// Serves ManageSieve with STARTTLS (port 4190).
pub async fn serve(app: AppState, listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                tokio::spawn(handle(app.clone(), tcp, peer));
            }
            Err(err) => {
                tracing::warn!(%err, "failed to accept ManageSieve connection");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_command_lines_do_not_panic() {
        for line in crate::fuzzing::inputs(1, 4000, 12) {
            let mut tokens = Vec::new();
            if let Ok(Some(length)) = tokenize_line(&line, &mut tokens) {
                // A literal length is only a number here; reading it is bounded by the caller.
                let _ = length;
            }
            assert!(tokens.len() <= line.len() + 1);
        }
    }


    #[test]
    fn tokens() {
        let mut tokens = Vec::new();
        assert_eq!(tokenize_line(b"PUTSCRIPT \"my \\\"script\\\"\" {12+}", &mut tokens), Ok(Some(12)));
        assert_eq!(tokens, [Token::Atom("PUTSCRIPT".into()), Token::Str(b"my \"script\"".to_vec())]);
        let mut tokens = Vec::new();
        assert_eq!(tokenize_line(b"havespace \"x\" 100", &mut tokens), Ok(None));
        assert_eq!(tokens[2], Token::Atom("100".into()));
        assert!(tokenize_line(b"X \"open", &mut Vec::new()).is_err());
        assert!(tokenize_line(b"X {5} y", &mut Vec::new()).is_err());
        assert_eq!(quoted("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }
}
