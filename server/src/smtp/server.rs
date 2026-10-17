//! SMTP server: MX (port 25), submission (587, STARTTLS) and submissions (465, implicit TLS).

use std::{net::SocketAddr, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    app::{AppState, Metrics},
    dailystats::Metric,
    auth::{self, Account, AuthError, Protocol},
    net::{Conn, ReadError},
    security::{access, reputation},
    smtp::{
        delivery::{self, Resolution, Target},
        submit::{self, Inbound, Outcome, Submission},
    },
    util::{Address, is_valid_domain},
};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_COMMAND_LINE: usize = 4096;
/// Generous compared to the 998 octets of RFC 5322, but bounded.
const MAX_DATA_LINE: usize = 100_000;
const MAX_ERRORS: u32 = 10;
/// Protocol errors (unknown commands, unknown recipients, bad sequences) from which a
/// connection counts as misbehaving, for the quarantine setting.
const MISBEHAVING_ERRORS: u32 = 3;
const MAX_MESSAGES_PER_CONNECTION: u32 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Port 25: server-to-server mail for local recipients. No authentication, no relaying.
    Mx,
    /// Port 587: authenticated submission; STARTTLS is mandatory before AUTH.
    Submission,
    /// Port 465: authenticated submission over implicit TLS.
    Smtps,
    /// LMTP (RFC 2033): final delivery handed over by a mail server in front of this one,
    /// with one reply per recipient. Only for clients on local or private networks (or on the
    /// administrator's allow list); sender authentication is the front server's job.
    Lmtp,
}

struct Transaction {
    /// The client declared an internationalized message (RFC 6531).
    smtputf8: bool,
    sender: String,
    recipients: Vec<(Address, Vec<Target>)>,
    /// Delivery status notifications asked for (RFC 3461).
    dsn: crate::smtp::dsn::Request,
    /// The message so far when it arrives in BDAT chunks (RFC 3030).
    chunks: Vec<u8>,
    /// A chunk went past the size limit: the rest is read and discarded.
    chunks_too_large: bool,
    /// BDAT was used, so DATA may no longer be.
    chunked: bool,
}

/// Unknown recipients in one connection from which it counts as a directory harvest.
const HARVEST_THRESHOLD: u32 = 5;
/// Refused relay attempts in one connection from which it counts as probing for an open relay.
const RELAY_PROBE_THRESHOLD: u32 = 3;

struct Session {
    app: AppState,
    mode: Mode,
    conn: Conn,
    peer: SocketAddr,
    helo: Option<String>,
    account: Option<Account>,
    /// What the account signed in with, checked again now and then.
    grant: Option<crate::auth::Grant>,
    tx: Option<Transaction>,
    errors: u32,
    messages: u32,
    /// The peer is on the whitelist: reputation checks and greylisting do not apply.
    whitelisted: bool,
    /// Unknown recipients and refused relay attempts in this connection (abuse reports).
    unknown_recipients: u32,
    relay_attempts: u32,
    /// The SPF-authorised domain of the envelope sender, once looked up for greylisting.
    spf_domain: Option<(String, Option<String>)>,
}

enum Flow {
    Continue,
    Close,
}

#[derive(Debug, PartialEq, Eq)]
enum DataError {
    TooLarge,
    BareNewline,
}

/// Whether a BDAT chunk of `size` octets still fits after `received` ones. The size is the
/// client's number: an overflowing sum must not wrap around into "fits".
fn chunk_fits(received: usize, size: usize, max: usize) -> bool {
    received.checked_add(size).is_some_and(|total| total <= max)
}

/// Extracts the address from a `FROM:<path>` / `TO:<path>` argument, returning the address and
/// the remaining ESMTP parameters.
fn parse_path<'a>(args: &'a str, keyword: &str) -> Option<(&'a str, &'a str)> {
    let args = args.trim_start();
    // `get` rather than slicing: the line may contain multi-byte characters.
    if !args.get(..keyword.len())?.eq_ignore_ascii_case(keyword) {
        return None;
    }
    let rest = args[keyword.len()..].trim_start();
    let rest = rest.strip_prefix('<')?;
    let (path, params) = rest.split_once('>')?;
    // Drop an obsolete source route ("@a,@b:user@domain").
    let address = match path.rsplit_once(':') {
        Some((route, addr)) if route.starts_with('@') => addr,
        _ => path,
    };
    Some((address, params.trim()))
}

fn valid_helo(arg: &str, strict: bool) -> bool {
    if arg.is_empty() || arg.len() > 255 || arg.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    if !strict {
        return true;
    }
    match arg.strip_prefix('[').and_then(|a| a.strip_suffix(']')) {
        Some(literal) => literal.trim_start_matches("IPv6:").parse::<std::net::IpAddr>().is_ok(),
        None => is_valid_domain(&arg.to_ascii_lowercase()),
    }
}

impl Session {
    /// The envelope sender's domain when SPF authorises the client to send for it. Looked up
    /// once per sender, not for every recipient.
    async fn spf_domain(&mut self, sender: &str) -> Option<String> {
        if let Some((cached, domain)) = &self.spf_domain
            && cached == sender
        {
            return domain.clone();
        }
        let domain = match (&self.app.authenticator, sender.rsplit_once('@')) {
            (Some(authenticator), Some((_, domain))) => {
                let helo = self.helo.as_deref().unwrap_or(domain);
                let spf = authenticator
                    .verify_spf(mail_auth::spf::verify::SpfParameters::verify_mail_from(self.peer.ip(), helo, &self.app.cfg.hostname, sender))
                    .await;
                (spf.result() == mail_auth::SpfResult::Pass).then(|| domain.to_owned())
            }
            _ => None,
        };
        self.spf_domain = Some((sender.to_owned(), domain.clone()));
        domain
    }

    async fn reply(&mut self, line: &str) -> std::io::Result<()> {
        self.app.activity.reply(self.peer.ip(), line);
        self.conn.write_all(format!("{line}\r\n").as_bytes()).await
    }

    /// Records good or bad behaviour of the peer. Whitelisted peers are not scored.
    async fn karma(&self, delta: i64, event: &str) {
        if !self.whitelisted {
            access::karma(&self.app, self.peer.ip(), delta, event).await;
        }
    }

    async fn error(&mut self, line: &str) -> std::io::Result<()> {
        self.errors += 1;
        self.reply(line).await
    }

    fn tls(&self) -> bool {
        self.conn.is_tls()
    }

    async fn run(mut self) -> std::io::Result<()> {
        let ip = self.peer.ip();
        // The administrator's lists come first and apply on every SMTP port.
        match access::check(&self.app, ip).await {
            access::Verdict::Blocked => {
                Metrics::inc(&self.app.metrics.messages_rejected);
                self.app.daily.add(Metric::ConnectionBlocked);
                return self.reply(&format!("554 5.7.1 Service unavailable; client host [{ip}] is blocked")).await;
            }
            access::Verdict::Allowed => self.whitelisted = true,
            access::Verdict::Neutral => {}
        }
        if self.mode == Mode::Lmtp && !self.whitelisted && !reputation::is_private(ip) {
            self.app.daily.add(Metric::ConnectionBlocked);
            return self.reply("554 5.7.1 LMTP is only offered to mail servers on the local network").await;
        }
        if self.mode == Mode::Mx && reputation::is_private(ip) && !reputation::is_trusted_source(&self.app.cfg, ip) {
            reputation::note_untrusted_private_peer(ip);
        }
        if self.mode == Mode::Mx && !self.whitelisted {
            let listings = reputation::dnsbl_listings(&self.app, ip).await;
            if let Some(zone) = listings.first() {
                Metrics::inc(&self.app.metrics.messages_rejected);
                self.app.daily.add(Metric::ConnectionBlocked);
                crate::db::audit(&self.app.db, "system", "smtp.dnsbl_blocked", &ip.to_string(), &ip.to_string(), zone).await;
                self.karma(-2, "listed in a DNS blocklist").await;
                return self.reply(&format!("554 5.7.1 Service unavailable; client host [{ip}] is listed in {zone}")).await;
            }
            if let Some(score) = reputation::abuseipdb_score(&self.app, ip).await
                && score >= self.app.rt().abuseipdb_threshold
            {
                Metrics::inc(&self.app.metrics.messages_rejected);
                self.app.daily.add(Metric::ConnectionBlocked);
                crate::db::audit(&self.app.db, "system", "smtp.abuseipdb_blocked", &ip.to_string(), &ip.to_string(), &format!("score {score}")).await;
                return self.reply(&format!("554 5.7.1 Service unavailable; client host [{ip}] has a poor reputation")).await;
            }
        }
        self.app.daily.add(Metric::ConnectionValid);
        let protocol = if self.mode == Mode::Lmtp { "LMTP" } else { "ESMTP" };
        self.reply(&format!("220 {} {protocol} unoMail", self.app.cfg.hostname)).await?;

        loop {
            if self.errors >= MAX_ERRORS {
                self.karma(-5, "too many errors").await;
                return self.reply("421 4.7.0 Too many errors, closing connection").await;
            }
            let line = match self.conn.read_line(MAX_COMMAND_LINE).await {
                Ok(line) => line,
                Err(ReadError::TooLong) => return self.reply("500 5.5.2 Line too long").await,
                Err(ReadError::Timeout) => return self.reply("421 4.4.2 Timeout, closing connection").await,
                Err(_) => return Ok(()),
            };
            let Ok(line) = String::from_utf8(line) else {
                self.error("500 5.5.2 Command contains invalid characters").await?;
                continue;
            };
            let (verb, args) = line.split_once(' ').unwrap_or((&line, ""));
            let verb = verb.to_ascii_uppercase();
            if self.account.is_some()
                && let Some(grant) = self.grant.as_mut()
                && !grant.recheck(&self.app.db).await
            {
                return self.reply("421 4.7.0 The sign-in is no longer valid, closing connection").await;
            }
            let flow = match verb.as_str() {
                "LHLO" if self.mode == Mode::Lmtp => self.cmd_helo(args.trim(), true).await?,
                "EHLO" | "HELO" | "LHLO" if (verb == "LHLO") != (self.mode == Mode::Lmtp) => {
                    self.error("500 5.5.1 Wrong greeting for this protocol").await?;
                    Flow::Continue
                }
                "EHLO" => self.cmd_helo(args.trim(), true).await?,
                "HELO" => self.cmd_helo(args.trim(), false).await?,
                "STARTTLS" => self.cmd_starttls().await?,
                "AUTH" => self.cmd_auth(args.trim()).await?,
                "MAIL" => self.cmd_mail(args).await?,
                "RCPT" => self.cmd_rcpt(args).await?,
                "DATA" => self.cmd_data().await?,
                "BDAT" => self.cmd_bdat(args.trim()).await?,
                "RSET" => {
                    self.tx = None;
                    self.reply("250 2.0.0 Ok").await?;
                    Flow::Continue
                }
                "NOOP" => {
                    self.reply("250 2.0.0 Ok").await?;
                    Flow::Continue
                }
                "QUIT" => {
                    let farewell = format!("221 2.0.0 {} closing connection. Have a jolly good day.", self.app.cfg.hostname);
                    self.reply(&farewell).await?;
                    Flow::Close
                }
                // VRFY/EXPN would let anyone enumerate valid addresses.
                "VRFY" | "EXPN" => {
                    self.error("502 5.5.1 Command not implemented").await?;
                    Flow::Continue
                }
                _ => {
                    self.error("500 5.5.2 Command not recognized").await?;
                    Flow::Continue
                }
            };
            if matches!(flow, Flow::Close) {
                self.conn.shutdown().await;
                return Ok(());
            }
        }
    }

    async fn cmd_helo(&mut self, arg: &str, extended: bool) -> std::io::Result<Flow> {
        let strict = self.mode == Mode::Mx;
        if !valid_helo(arg, strict) {
            self.error("501 5.5.4 Invalid domain name").await?;
            return Ok(Flow::Continue);
        }
        // A remote server introducing itself with our own name is forging its identity.
        if strict && arg.eq_ignore_ascii_case(&self.app.cfg.hostname) && !self.peer.ip().is_loopback() {
            self.error("550 5.7.1 Refused: you are not me").await?;
            return Ok(Flow::Continue);
        }
        self.helo = Some(arg.to_owned());
        self.tx = None;
        let host = self.app.cfg.hostname.clone();
        if !extended {
            self.reply(&format!("250 {host}")).await?;
            return Ok(Flow::Continue);
        }
        let mut lines = vec![host, format!("SIZE {}", self.app.rt().max_message_size), "8BITMIME".into(), "SMTPUTF8".into(), "PIPELINING".into(), "DSN".into(), "CHUNKING".into()];
        if self.tls() {
            // RFC 8689: offered only where the session itself is encrypted.
            lines.push("REQUIRETLS".into());
        } else {
            lines.push("STARTTLS".into());
        }
        // Credentials are only ever accepted over an encrypted channel.
        if self.mode != Mode::Mx && self.tls() {
            // Token logins are offered only while single sign-on is configured.
            let oauth = if crate::oauth::active(&self.app).await.is_some() { " XOAUTH2 OAUTHBEARER" } else { "" };
            lines.push(format!("AUTH PLAIN LOGIN{oauth}"));
        }
        lines.push("ENHANCEDSTATUSCODES".into());
        let last = lines.len() - 1;
        let text: String =
            lines.iter().enumerate().map(|(i, l)| format!("250{}{l}\r\n", if i == last { ' ' } else { '-' })).collect();
        self.conn.write_all(text.as_bytes()).await?;
        Ok(Flow::Continue)
    }

    async fn cmd_starttls(&mut self) -> std::io::Result<Flow> {
        if self.tls() {
            self.error("503 5.5.1 TLS already active").await?;
            return Ok(Flow::Continue);
        }
        if self.conn.has_buffered() {
            // Commands pipelined behind STARTTLS would otherwise run inside the TLS session.
            self.reply("501 5.5.2 Pipelining after STARTTLS is not allowed").await?;
            return Ok(Flow::Close);
        }
        self.reply("220 2.0.0 Ready to start TLS").await?;
        let config = self.app.tls.server_config(&[]);
        if let Err(err) = self.conn.start_tls(config).await {
            tracing::debug!(%err, peer = %self.peer, "STARTTLS handshake failed");
            return Ok(Flow::Close);
        }
        // RFC 3207: discard everything learned before the handshake.
        self.helo = None;
        self.account = None;
        self.tx = None;
        Ok(Flow::Continue)
    }

    async fn read_auth_line(&mut self, prompt: &str) -> std::io::Result<Option<Vec<u8>>> {
        self.reply(&format!("334 {prompt}")).await?;
        let line = match self.conn.read_line(MAX_COMMAND_LINE).await {
            Ok(line) => line,
            Err(_) => return Ok(None),
        };
        if line == b"*" {
            return Ok(None);
        }
        Ok(STANDARD.decode(&line).ok())
    }

    async fn cmd_auth(&mut self, args: &str) -> std::io::Result<Flow> {
        if matches!(self.mode, Mode::Mx | Mode::Lmtp) {
            self.error("503 5.5.1 Authentication is not available on this port").await?;
            return Ok(Flow::Continue);
        }
        if !self.tls() {
            self.error("538 5.7.11 Encryption required for requested authentication mechanism").await?;
            return Ok(Flow::Continue);
        }
        if self.account.is_some() || self.helo.is_none() {
            self.error("503 5.5.1 Bad sequence of commands").await?;
            return Ok(Flow::Continue);
        }
        let (mechanism, initial) = args.split_once(' ').unwrap_or((args, ""));
        let mechanism = mechanism.to_ascii_uppercase();
        if matches!(mechanism.as_str(), "XOAUTH2" | "OAUTHBEARER") {
            let decoded = if initial.is_empty() { self.read_auth_line("").await? } else { STANDARD.decode(initial.trim()).ok() };
            let Some((user, token)) = decoded.and_then(|bytes| crate::oauth::parse_sasl(&mechanism, &bytes)) else {
                self.error("501 5.5.2 Authentication cancelled or malformed").await?;
                return Ok(Flow::Continue);
            };
            let result = crate::oauth::authenticate_token(&self.app, &user, &token, self.peer.ip(), Protocol::Smtp).await;
            return self.finish_auth(result.map(|account| (account, None))).await;
        }
        let credentials: Option<(String, String)> = match mechanism.as_str() {
            "PLAIN" => {
                let decoded = if initial.is_empty() { self.read_auth_line("").await? } else { STANDARD.decode(initial.trim()).ok() };
                decoded.and_then(|bytes| {
                    // authorization-id NUL authentication-id NUL password
                    let mut parts = bytes.split(|b| *b == 0);
                    let (_authz, user, pass) = (parts.next()?, parts.next()?, parts.next()?);
                    Some((String::from_utf8(user.to_vec()).ok()?, String::from_utf8(pass.to_vec()).ok()?))
                })
            }
            "LOGIN" => {
                let user = if initial.is_empty() { self.read_auth_line("VXNlcm5hbWU6").await? } else { STANDARD.decode(initial.trim()).ok() };
                let pass = match user {
                    Some(_) => self.read_auth_line("UGFzc3dvcmQ6").await?,
                    None => None,
                };
                user.zip(pass).and_then(|(u, p)| Some((String::from_utf8(u).ok()?, String::from_utf8(p).ok()?)))
            }
            _ => {
                self.error("504 5.5.4 Unrecognized authentication mechanism").await?;
                return Ok(Flow::Continue);
            }
        };
        let Some((user, password)) = credentials else {
            self.error("501 5.5.2 Authentication cancelled or malformed").await?;
            return Ok(Flow::Continue);
        };
        let result = auth::authenticate_with(&self.app.db, &self.app.limiter, &user, &password, self.peer.ip(), Protocol::Smtp).await;
        self.finish_auth(result.map(|(account, credential)| (account, Some(credential)))).await
    }

    async fn finish_auth(&mut self, result: Result<(crate::auth::Account, Option<crate::auth::Credential>), AuthError>) -> std::io::Result<Flow> {
        match result {
            Ok((account, credential)) => {
                self.grant = Some(crate::auth::Grant::new(&account, Protocol::Smtp, credential));
                self.account = Some(account);
                self.reply("235 2.7.0 Authentication successful").await?;
                Ok(Flow::Continue)
            }
            Err(AuthError::Invalid) => {
                Metrics::inc(&self.app.metrics.auth_failures);
                self.karma(-3, "authentication failure").await;
                self.error("535 5.7.8 Authentication credentials invalid").await?;
                Ok(Flow::Continue)
            }
            Err(AuthError::RateLimited) => {
                self.reply("454 4.7.0 Too many failed authentication attempts, try again later").await?;
                Ok(Flow::Close)
            }
            Err(AuthError::Internal) => {
                self.reply("454 4.7.0 Temporary authentication failure").await?;
                Ok(Flow::Continue)
            }
        }
    }

    async fn cmd_mail(&mut self, args: &str) -> std::io::Result<Flow> {
        if self.helo.is_none() || self.tx.is_some() {
            self.error("503 5.5.1 Bad sequence of commands").await?;
            return Ok(Flow::Continue);
        }
        if matches!(self.mode, Mode::Submission | Mode::Smtps) && self.account.is_none() {
            self.error("530 5.7.0 Authentication required").await?;
            return Ok(Flow::Continue);
        }
        // Optional strict mode: no plaintext mail from other servers. Off by default because
        // RFC 3207 forbids publicly referenced MX hosts from requiring TLS.
        if self.mode == Mode::Mx && !self.tls() && self.app.rt().smtp_require_tls {
            self.error("530 5.7.0 Must issue a STARTTLS command first").await?;
            return Ok(Flow::Continue);
        }
        if self.messages >= MAX_MESSAGES_PER_CONNECTION {
            self.reply("421 4.7.0 Too many messages on this connection").await?;
            return Ok(Flow::Close);
        }
        let Some((address, params)) = parse_path(args, "FROM:") else {
            self.error("501 5.5.4 Syntax: MAIL FROM:<address>").await?;
            return Ok(Flow::Continue);
        };
        let mut smtputf8 = false;
        let mut dsn = crate::smtp::dsn::Request::default();
        for param in params.split_whitespace() {
            let (key, value) = param.split_once('=').unwrap_or((param, ""));
            match key.to_ascii_uppercase().as_str() {
                "SMTPUTF8" if value.is_empty() => smtputf8 = true,
                "RET" if dsn.ret.is_none() => match crate::smtp::dsn::parse_ret(value) {
                    Some(ret) => dsn.ret = Some(ret),
                    None => {
                        self.error("501 5.5.4 Invalid RET parameter").await?;
                        return Ok(Flow::Continue);
                    }
                },
                "ENVID" if dsn.envid.is_none() => {
                    if !crate::smtp::dsn::valid_xtext(value, 100) {
                        self.error("501 5.5.4 Invalid ENVID parameter").await?;
                        return Ok(Flow::Continue);
                    }
                    dsn.envid = Some(value.to_owned());
                }
                "SIZE" => {
                    if value.parse::<usize>().map_or(true, |size| size > self.app.rt().max_message_size) {
                        self.error("552 5.3.4 Message size exceeds fixed limit").await?;
                        return Ok(Flow::Continue);
                    }
                }
                "BODY" if matches!(value.to_ascii_uppercase().as_str(), "7BIT" | "8BITMIME") => {}
                "REQUIRETLS" if value.is_empty() && !dsn.require_tls => {
                    if !self.tls() {
                        self.error("530 5.7.10 REQUIRETLS needs an encrypted session").await?;
                        return Ok(Flow::Continue);
                    }
                    dsn.require_tls = true;
                }
                // Where AUTH is offered, the submitter's identity may be named (RFC 4954 5);
                // relays name it as "<>". It is noted by nobody here: the sign-in decides.
                "AUTH" if matches!(self.mode, Mode::Submission | Mode::Smtps) => {
                    if !crate::smtp::dsn::valid_xtext(value, 500) {
                        self.error("501 5.5.4 Invalid AUTH parameter").await?;
                        return Ok(Flow::Continue);
                    }
                }
                _ => {
                    self.error("555 5.5.4 Unsupported MAIL FROM parameter").await?;
                    return Ok(Flow::Continue);
                }
            }
        }
        let sender = if address.is_empty() {
            String::new()
        } else {
            match Address::parse(address) {
                // Non-ASCII addresses are only valid in a transaction that announced them.
                Some(addr) if !addr.is_ascii() && !smtputf8 => {
                    self.error("553 5.6.7 Internationalized address requires the SMTPUTF8 parameter").await?;
                    return Ok(Flow::Continue);
                }
                Some(addr) => addr.to_string(),
                None => {
                    self.error("501 5.1.7 Bad sender address syntax").await?;
                    return Ok(Flow::Continue);
                }
            }
        };
        if let Some(account) = &self.account {
            let allowed = match Address::parse(&sender) {
                Some(addr) => submit::identity_allowed(&self.app, account, &addr).await.unwrap_or(false),
                None => false,
            };
            if !allowed {
                self.error("550 5.7.1 Sender address rejected: not owned by authenticated user").await?;
                return Ok(Flow::Continue);
            }
        }
        self.tx = Some(Transaction { smtputf8, sender, recipients: Vec::new(), dsn, chunks: Vec::new(), chunks_too_large: false, chunked: false });
        self.reply("250 2.1.0 Ok").await?;
        Ok(Flow::Continue)
    }

    async fn cmd_rcpt(&mut self, args: &str) -> std::io::Result<Flow> {
        let Some(tx) = &self.tx else {
            self.error("503 5.5.1 Need MAIL command first").await?;
            return Ok(Flow::Continue);
        };
        if tx.recipients.len() >= self.app.rt().max_recipients {
            self.reply("452 4.5.3 Too many recipients").await?;
            return Ok(Flow::Continue);
        }
        let Some((address, params)) = parse_path(args, "TO:").and_then(|(a, params)| Some((Address::parse(a)?, params))) else {
            self.error("501 5.1.3 Bad recipient address syntax").await?;
            return Ok(Flow::Continue);
        };
        let (mut notify, mut orcpt) = (None, None);
        for param in params.split_whitespace() {
            let (key, value) = param.split_once('=').unwrap_or((param, ""));
            match key.to_ascii_uppercase().as_str() {
                "NOTIFY" if notify.is_none() => match crate::smtp::dsn::parse_notify(value) {
                    Some(value) => notify = Some(value),
                    None => {
                        self.error("501 5.5.4 Invalid NOTIFY parameter").await?;
                        return Ok(Flow::Continue);
                    }
                },
                "ORCPT" if orcpt.is_none() => match crate::smtp::dsn::parse_orcpt(value) {
                    Some(value) => orcpt = Some(value),
                    None => {
                        self.error("501 5.5.4 Invalid ORCPT parameter").await?;
                        return Ok(Flow::Continue);
                    }
                },
                _ => {
                    self.error("555 5.5.4 Unsupported RCPT TO parameter").await?;
                    return Ok(Flow::Continue);
                }
            }
        }
        if !address.is_ascii() && !tx.smtputf8 {
            self.error("553 5.6.7 Internationalized address requires the SMTPUTF8 parameter").await?;
            return Ok(Flow::Continue);
        }
        let resolution = match delivery::resolve(&self.app, &address).await {
            Ok(r) => r,
            Err(err) => {
                tracing::error!(%err, "recipient lookup failed");
                self.reply("451 4.3.0 Temporary lookup failure").await?;
                return Ok(Flow::Continue);
            }
        };
        let targets = match (resolution, self.mode) {
            (Resolution::Deliver(targets), _) => targets,
            (Resolution::NoSuchUser, _) => {
                if self.mode == Mode::Mx {
                    self.karma(-1, "unknown recipient").await;
                    self.unknown_recipients += 1;
                    // A few typos are normal; a run of guesses is harvesting addresses.
                    if self.unknown_recipients == HARVEST_THRESHOLD && !self.whitelisted {
                        reputation::report_abuse(&self.app, self.peer.ip(), reputation::Abuse::DirectoryHarvest);
                    }
                }
                self.error(&format!("550 5.1.1 <{address}>: Recipient address rejected: User unknown")).await?;
                return Ok(Flow::Continue);
            }
            // Unauthenticated peers may only reach our own domains: we are not an open relay.
            (Resolution::NotLocal, Mode::Mx | Mode::Lmtp) => {
                self.relay_attempts += 1;
                if self.mode == Mode::Mx && self.relay_attempts == RELAY_PROBE_THRESHOLD && !self.whitelisted {
                    reputation::report_abuse(&self.app, self.peer.ip(), reputation::Abuse::RelayProbe);
                }
                self.error(&format!("554 5.7.1 <{address}>: Relay access denied")).await?;
                return Ok(Flow::Continue);
            }
            (Resolution::NotLocal, _) => vec![Target::Remote(address.clone())],
        };
        if self.mode == Mode::Mx && !self.whitelisted && self.app.rt().greylist_enabled && !reputation::is_trusted_source(&self.app.cfg, self.peer.ip()) {
            let sender = self.tx.as_ref().map(|t| t.sender.clone()).unwrap_or_default();
            let spf_domain = self.spf_domain(&sender).await;
            match delivery::greylist_pass(&self.app, self.peer.ip(), spf_domain.as_deref(), &sender, &address.to_string()).await {
                Ok(true) => {}
                Ok(false) => {
                    self.reply("451 4.7.1 Greylisted, please try again in a few minutes").await?;
                    return Ok(Flow::Continue);
                }
                Err(err) => tracing::error!(%err, "greylist lookup failed, accepting recipient"),
            }
        }
        if let Some(tx) = &mut self.tx {
            if notify.is_some() || orcpt.is_some() {
                tx.dsn.recipients.insert(address.to_string().to_ascii_lowercase(), (notify, orcpt));
            }
            tx.recipients.push((address, targets));
        }
        self.reply("250 2.1.5 Ok").await?;
        Ok(Flow::Continue)
    }

    /// Reads the DATA payload up to the `<CRLF>.<CRLF>` terminator, undoing dot-stuffing.
    ///
    /// Only a strict CRLF-delimited dot line ends the message. Bare CR or LF characters are
    /// rejected outright: treating them as line breaks (or passing them on) is what makes SMTP
    /// smuggling possible. Input is always consumed to the terminator to stay in sync.
    async fn read_data(&mut self) -> Result<Result<Vec<u8>, DataError>, ReadError> {
        let deadline = tokio::time::Instant::now() + COMMAND_TIMEOUT;
        let max = self.app.rt().max_message_size;
        let mut data = Vec::new();
        let mut error = None;
        loop {
            let line = tokio::time::timeout_at(deadline, self.conn.read_line_raw(MAX_DATA_LINE)).await.map_err(|_| ReadError::Timeout)??;
            if line == b".\r\n" {
                break;
            }
            let body = line.strip_suffix(b"\r\n");
            if body.is_none_or(|b| b.contains(&b'\r')) {
                error.get_or_insert(DataError::BareNewline);
            }
            if data.len() + line.len() > max {
                error.get_or_insert(DataError::TooLarge);
                data = Vec::new();
            }
            if error.is_none() {
                data.extend_from_slice(line.strip_prefix(b".").unwrap_or(&line));
            }
        }
        Ok(match error {
            Some(err) => Err(err),
            None => Ok(data),
        })
    }

    async fn cmd_data(&mut self) -> std::io::Result<Flow> {
        if self.tx.as_ref().is_none_or(|tx| tx.recipients.is_empty()) {
            self.error(if self.tx.is_some() { "554 5.5.1 No valid recipients" } else { "503 5.5.1 Need MAIL command first" }).await?;
            return Ok(Flow::Continue);
        }
        if self.tx.as_ref().is_some_and(|tx| tx.chunked) {
            self.error("503 5.5.1 DATA cannot follow BDAT").await?;
            return Ok(Flow::Continue);
        }
        self.reply("354 End data with <CR><LF>.<CR><LF>").await?;
        let data = match self.read_data().await {
            Ok(data) => data,
            Err(ReadError::TooLong) => {
                self.reply("500 5.5.2 Line too long").await?;
                return Ok(Flow::Close);
            }
            Err(ReadError::Timeout) => {
                self.reply("421 4.4.2 Timeout, closing connection").await?;
                return Ok(Flow::Close);
            }
            Err(_) => return Ok(Flow::Close),
        };
        let tx = self.tx.take().expect("transaction presence was checked above");
        let raw = match data {
            Ok(raw) => raw,
            Err(DataError::TooLarge) => {
                self.error("552 5.3.4 Message size exceeds fixed limit").await?;
                return Ok(Flow::Continue);
            }
            Err(DataError::BareNewline) => {
                self.error("554 5.6.0 Message contains bare CR or LF characters").await?;
                return Ok(Flow::Continue);
            }
        };
        self.finish(tx, raw).await
    }

    /// `BDAT <size> [LAST]`: one chunk of the message, read as exactly that many octets.
    async fn cmd_bdat(&mut self, args: &str) -> std::io::Result<Flow> {
        let mut parts = args.split_ascii_whitespace();
        let size = parts.next().and_then(|n| n.parse::<usize>().ok());
        let last = match parts.next() {
            None => false,
            Some(word) if word.eq_ignore_ascii_case("LAST") => true,
            Some(_) => {
                self.error("501 5.5.4 Syntax: BDAT <size> [LAST]").await?;
                return Ok(Flow::Close);
            }
        };
        let Some(size) = size.filter(|_| parts.next().is_none()) else {
            // Without a valid size the chunk cannot be skipped: the session is out of sync.
            self.reply("501 5.5.4 Syntax: BDAT <size> [LAST]").await?;
            return Ok(Flow::Close);
        };
        // The chunk is always read, whatever is answered, to stay in step with the client.
        let max = self.app.rt().max_message_size;
        let keep = self.tx.as_ref().is_some_and(|tx| !tx.recipients.is_empty() && !tx.chunks_too_large && chunk_fits(tx.chunks.len(), size, max));
        let mut chunk = Vec::new();
        let mut remaining = size;
        let deadline = tokio::time::Instant::now() + COMMAND_TIMEOUT;
        while remaining > 0 {
            let piece = remaining.min(64 * 1024);
            match tokio::time::timeout_at(deadline, self.conn.read_exact(piece)).await.unwrap_or(Err(ReadError::Timeout)) {
                Ok(data) if keep => chunk.extend_from_slice(&data),
                Ok(_) => {}
                Err(ReadError::Timeout) => {
                    self.reply("421 4.4.2 Timeout, closing connection").await?;
                    return Ok(Flow::Close);
                }
                Err(_) => return Ok(Flow::Close),
            }
            remaining -= piece;
        }
        let Some(tx) = self.tx.as_mut() else {
            self.error("503 5.5.1 Need MAIL command first").await?;
            return Ok(Flow::Continue);
        };
        if tx.recipients.is_empty() {
            self.error("554 5.5.1 No valid recipients").await?;
            return Ok(Flow::Continue);
        }
        tx.chunked = true;
        if keep {
            tx.chunks.extend_from_slice(&chunk);
        } else {
            tx.chunks_too_large = true;
            tx.chunks = Vec::new();
        }
        if !last {
            let reply = format!("250 2.0.0 {size} octets received");
            self.reply(&reply).await?;
            return Ok(Flow::Continue);
        }
        let mut tx = self.tx.take().expect("transaction presence was checked above");
        if tx.chunks_too_large {
            self.error("552 5.3.4 Message size exceeds fixed limit").await?;
            return Ok(Flow::Continue);
        }
        // Same rule as DATA: line breaks are CRLF, so the message means the same to everyone.
        let raw = std::mem::take(&mut tx.chunks);
        let bare = raw.iter().enumerate().any(|(i, b)| match b {
            b'\r' => raw.get(i + 1) != Some(&b'\n'),
            b'\n' => i == 0 || raw[i - 1] != b'\r',
            _ => false,
        });
        if bare {
            self.error("554 5.6.0 Message contains bare CR or LF characters").await?;
            return Ok(Flow::Continue);
        }
        self.finish(tx, raw).await
    }

    /// Accepts (or not) a complete message and answers the client.
    async fn finish(&mut self, tx: Transaction, raw: Vec<u8>) -> std::io::Result<Flow> {
        self.messages += 1;

        let mut request = tx.dsn.clone();
        // A remote, unauthenticated sender may name anyone as its return path: notices to it
        // never carry the message itself (backscatter of attacker content).
        if self.account.is_none() {
            request.ret = None;
        }
        // LMTP: every recipient gets its own answer, in RCPT order.
        if self.mode == Mode::Lmtp {
            let mut replies = String::new();
            for recipient in &tx.recipients {
                let single = Transaction { recipients: vec![recipient.clone()], dsn: tx.dsn.clone(), chunks: Vec::new(), chunks_too_large: false, chunked: false, smtputf8: tx.smtputf8, sender: tx.sender.clone() };
                let outcome = crate::smtp::dsn::REQUEST.scope(request.clone(), self.accept(&single, &raw)).await;
                replies.push_str(outcome.reply());
                replies.push_str("\r\n");
            }
            self.conn.write_all(replies.as_bytes()).await?;
            return Ok(Flow::Continue);
        }
        let span = tracing::info_span!("smtp.receive", smtp.mode = ?self.mode, smtp.recipients = tx.recipients.len(), smtp.size = raw.len(), smtp.tls = self.tls());
        let outcome = tracing::Instrument::instrument(crate::smtp::dsn::REQUEST.scope(request, self.accept(&tx, &raw)), span).await;
        if matches!(outcome, Outcome::Rejected(_)) {
            self.errors += 1;
        }
        if self.mode == Mode::Mx {
            match &outcome {
                Outcome::Accepted(_) => self.karma(1, "message accepted").await,
                Outcome::Rejected(_) => self.karma(-5, "message rejected").await,
                Outcome::Deferred(_) => {}
            }
        }
        self.reply(outcome.reply()).await?;
        Ok(Flow::Continue)
    }

    /// Hands a received message to the submission or inbound pipeline.
    async fn accept(&self, tx: &Transaction, raw: &[u8]) -> Outcome {
        match &self.account {
            Some(account) => {
                let recipients: Vec<Address> = tx.recipients.iter().map(|(a, _)| a.clone()).collect();
                match Address::parse(&tx.sender) {
                    Some(sender) => {
                        submit::submit(
                            &self.app,
                            Submission { account, sender: &sender, recipients: &recipients, raw, delegate: None, ip: self.peer.ip() },
                        )
                        .await
                    }
                    None => Outcome::Rejected("550 5.7.1 Sender address rejected".into()),
                }
            }
            None => {
                submit::accept_inbound(
                    &self.app,
                    Inbound {
                        ip: self.peer.ip(),
                        helo: self.helo.as_deref().unwrap_or(""),
                        sender: &tx.sender,
                        recipients: &tx.recipients,
                        raw,
                        tls: self.tls(),
                        trusted_relay: self.mode == Mode::Lmtp,
                        misbehaving: self.errors >= MISBEHAVING_ERRORS || access::karma_of(&self.app, self.peer.ip()).await < 0,
                    },
                )
                .await
            }
        }
    }
}

async fn handle(app: AppState, mode: Mode, mut tcp: TcpStream, peer: SocketAddr) {
    let Some(_guard) = app.accept_connection(peer.ip()) else {
        use tokio::io::AsyncWriteExt;
        app.daily.add(Metric::ConnectionLimited);
        let _ = tcp.write_all(b"421 4.7.0 Too many connections from your address\r\n").await;
        return;
    };
    Metrics::inc(&app.metrics.smtp_connections);
    let _ = tcp.set_nodelay(true);
    let conn = if mode == Mode::Smtps {
        match Conn::accept_tls(tcp, app.tls.server_config(&[]), COMMAND_TIMEOUT).await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::debug!(%err, %peer, "TLS handshake failed");
                return;
            }
        }
    } else {
        Conn::plain(tcp, COMMAND_TIMEOUT)
    };
    let session = Session { app, mode, conn, peer, helo: None, account: None, grant: None, tx: None, errors: 0, messages: 0, whitelisted: false, spf_domain: None, unknown_recipients: 0, relay_attempts: 0 };
    if let Err(err) = session.run().await {
        tracing::debug!(%err, %peer, "SMTP session ended with an error");
    }
}

pub async fn serve(app: AppState, mode: Mode, listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                tokio::spawn(handle(app.clone(), mode, tcp, peer));
            }
            Err(err) => {
                tracing::warn!(%err, "failed to accept SMTP connection");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_paths_and_greetings_do_not_panic() {
        for text in crate::fuzzing::texts(6, 4000, 8) {
            let _ = parse_path(&text, "FROM:");
            let _ = parse_path(&format!("TO:{text}"), "TO:");
            let _ = valid_helo(&text, true);
        }
    }


    #[test]
    fn chunk_sizes_cannot_overflow() {
        assert!(chunk_fits(10, 90, 100));
        assert!(!chunk_fits(10, 91, 100));
        assert!(!chunk_fits(10, usize::MAX - 5, 100), "a wrapping sum is not a small one");
        assert!(!chunk_fits(usize::MAX, 1, usize::MAX));
    }

    #[test]
    fn paths() {
        assert_eq!(parse_path("FROM:<a@b.example>", "FROM:"), Some(("a@b.example", "")));
        assert_eq!(parse_path("from: <a@b.example> SIZE=100 BODY=8BITMIME", "FROM:"), Some(("a@b.example", "SIZE=100 BODY=8BITMIME")));
        assert_eq!(parse_path("FROM:<józef@b.example> SMTPUTF8", "FROM:"), Some(("józef@b.example", "SMTPUTF8")));
        // Multi-byte characters where the keyword is expected must not panic.
        assert_eq!(parse_path("ééééé", "FROM:"), None);
        assert_eq!(parse_path("żó", "TO:"), None);
        assert_eq!(parse_path("FROM:<>", "FROM:"), Some(("", "")));
        assert_eq!(parse_path("TO:<@relay.example,@other.example:a@b.example>", "TO:"), Some(("a@b.example", "")));
        assert_eq!(parse_path("FROM:a@b.example", "FROM:"), None);
        assert_eq!(parse_path("TO:<a@b.example>", "FROM:"), None);
        assert_eq!(parse_path("", "FROM:"), None);
    }

    #[test]
    fn helo_validation() {
        assert!(valid_helo("mail.example.com", true));
        assert!(valid_helo("[192.0.2.1]", true));
        assert!(valid_helo("[IPv6:2001:db8::1]", true));
        assert!(!valid_helo("localhost", true));
        assert!(!valid_helo("192.0.2.1", true));
        assert!(!valid_helo("", true));
        assert!(!valid_helo("bad host", true));
        assert!(!valid_helo("[not-an-ip]", true));
        // Submission clients routinely send unqualified names.
        assert!(valid_helo("laptop", false));
        assert!(!valid_helo("lap top", false));
    }
}
