//! Outbound SMTP client used by the delivery queue.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use super::transport;
use crate::{app::App, security::reputation::is_private, util::Address};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Waiting for the greeting and for replies to EHLO, MAIL and RCPT (RFC 5321 4.5.3.2: 5 minutes).
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
/// Waiting for the reply to DATA (2 minutes).
const DATA_INIT_TIMEOUT: Duration = Duration::from_secs(120);
/// Sending the message and waiting for the final reply (10 minutes).
const DATA_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_REPLY_BYTES: usize = 64 * 1024;
const MAX_HOSTS: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// Worth retrying later (4xx, network trouble).
    Temporary(String),
    /// The remote side refused the message for good (5xx) or the destination cannot exist.
    Permanent(String),
}

impl SendError {
    pub fn message(&self) -> &str {
        match self {
            SendError::Temporary(m) | SendError::Permanent(m) => m,
        }
    }
}

fn temp(msg: impl std::fmt::Display) -> SendError {
    SendError::Temporary(msg.to_string())
}

/// Accepts any certificate. Used for opportunistic TLS, where an unauthenticated encrypted
/// channel is still better than the plaintext fallback (RFC 7435). Signatures are still checked.
#[derive(Debug)]
struct AcceptAnyCert(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// TLS client configuration; with `verify` unset any certificate is accepted.
pub fn tls_config(verify: bool) -> Arc<ClientConfig> {
    let provider = crate::tls::provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions");
    let config = if verify {
        builder
            .with_root_certificates(rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() })
            .with_no_client_auth()
    } else {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider))).with_no_client_auth()
    };
    Arc::new(config)
}

struct Reply {
    code: u16,
    lines: Vec<String>,
}

impl Reply {
    fn text(&self) -> String {
        format!("{} {}", self.code, self.lines.join(" "))
    }
}

/// Minimal buffered SMTP client transport.
struct Transport<S> {
    stream: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Transport<S> {
    fn new(stream: S) -> Self {
        Transport { stream, buf: Vec::new() }
    }

    async fn read_reply(&mut self, timeout: Duration) -> Result<Reply, SendError> {
        let mut lines = Vec::new();
        loop {
            let line = loop {
                if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = self.buf.drain(..=pos).collect();
                    break String::from_utf8_lossy(&line).trim_end().to_owned();
                }
                if self.buf.len() > MAX_REPLY_BYTES {
                    return Err(temp("remote server sent an oversized reply"));
                }
                let mut chunk = [0u8; 4096];
                let n = tokio::time::timeout(timeout, self.stream.read(&mut chunk))
                    .await
                    .map_err(|_| temp("timed out waiting for a reply"))?
                    .map_err(|e| temp(format!("connection error: {e}")))?;
                if n == 0 {
                    return Err(temp("connection closed unexpectedly"));
                }
                self.buf.extend_from_slice(&chunk[..n]);
            };
            if line.len() < 3 || !line.as_bytes()[..3].iter().all(u8::is_ascii_digit) {
                return Err(temp("remote server sent a malformed reply"));
            }
            let code: u16 = line[..3].parse().map_err(|_| temp("malformed reply code"))?;
            let more = line.as_bytes().get(3) == Some(&b'-');
            lines.push(line.get(4..).unwrap_or("").to_owned());
            if lines.len() > 100 {
                return Err(temp("remote server sent too many reply lines"));
            }
            if !more {
                return Ok(Reply { code, lines });
            }
        }
    }

    async fn write(&mut self, data: &[u8], timeout: Duration) -> Result<(), SendError> {
        tokio::time::timeout(timeout, async {
            self.stream.write_all(data).await?;
            self.stream.flush().await
        })
        .await
        .map_err(|_| temp("timed out while sending"))?
        .map_err(|e| temp(format!("connection error: {e}")))
    }

    /// Sends a command and requires a reply whose first digit is `expect`.
    async fn command(&mut self, line: &str, expect: u8) -> Result<Reply, SendError> {
        self.command_within(line, expect, COMMAND_TIMEOUT).await
    }

    async fn command_within(&mut self, line: &str, expect: u8, timeout: Duration) -> Result<Reply, SendError> {
        self.write(format!("{line}\r\n").as_bytes(), timeout).await?;
        self.expect(expect, timeout).await
    }

    async fn expect(&mut self, expect: u8, timeout: Duration) -> Result<Reply, SendError> {
        let reply = self.read_reply(timeout).await?;
        match (reply.code / 100) as u8 {
            class if class == expect => Ok(reply),
            5 => Err(SendError::Permanent(reply.text())),
            _ => Err(SendError::Temporary(reply.text())),
        }
    }
}

/// Converts a message to its on-the-wire DATA form: CRLF line endings, leading dots doubled,
/// terminated by the end-of-data marker.
pub fn encode_data(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + raw.len() / 40 + 8);
    for line in raw.split_inclusive(|b| *b == b'\n') {
        let content = line.strip_suffix(b"\n").unwrap_or(line);
        let content = content.strip_suffix(b"\r").unwrap_or(content);
        if content.first() == Some(&b'.') {
            out.push(b'.');
        }
        // A bare CR inside a line could be read as a line break by a lenient receiver.
        out.extend(content.iter().filter(|b| **b != b'\r'));
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

struct Envelope<'a> {
    helo: &'a str,
    sender: &'a str,
    recipient: &'a str,
    /// The message as written, for conversion to 7 bits.
    raw: &'a [u8],
    /// The message in its on-the-wire DATA form.
    data: &'a [u8],
    /// What the sender asked to be notified about, passed on when the receiver supports DSN.
    dsn: Option<&'a crate::smtp::dsn::Dsn>,
    /// Set once the receiving server took over the notifications.
    dsn_passed: std::sync::atomic::AtomicBool,
}

/// Decides whether a message must or should travel as internationalized mail (RFC 6531).
///
/// A non-ASCII envelope address cannot be expressed without the extension, so delivery to a
/// server lacking it fails for good. Non-ASCII header content alone is announced when
/// possible but does not block delivery.
fn smtputf8_parameter(env: &Envelope<'_>, supported: bool) -> Result<&'static str, &'static str> {
    let envelope = !env.sender.is_ascii() || !env.recipient.is_ascii();
    let header_end = env.data.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(env.data.len());
    let headers = !env.data[..header_end].is_ascii();
    match (envelope, headers, supported) {
        (true, _, false) => Err("the receiving server does not support internationalized addresses (SMTPUTF8)"),
        (true, _, true) | (false, true, true) => Ok(" SMTPUTF8"),
        _ => Ok(""),
    }
}

/// Greets with EHLO and returns the extensions offered. A server that does not know EHLO is
/// greeted with HELO instead and offers none (RFC 5321 3.2).
async fn ehlo<S: AsyncRead + AsyncWrite + Unpin>(t: &mut Transport<S>, helo: &str) -> Result<Vec<String>, SendError> {
    match t.command(&format!("EHLO {helo}"), 2).await {
        Ok(reply) => Ok(reply.lines.iter().skip(1).map(|l| l.to_ascii_uppercase()).collect()),
        Err(SendError::Permanent(_)) => {
            t.command(&format!("HELO {helo}"), 2).await?;
            Ok(Vec::new())
        }
        Err(err) => Err(err),
    }
}

async fn transact<S: AsyncRead + AsyncWrite + Unpin>(t: &mut Transport<S>, env: &Envelope<'_>, extensions: &[String]) -> Result<String, SendError> {
    let utf8 = match smtputf8_parameter(env, extensions.iter().any(|e| e == "SMTPUTF8")) {
        Ok(parameter) => parameter,
        Err(reason) => return Err(SendError::Permanent(reason.into())),
    };
    // 8-bit content is announced (RFC 6152); a server without the extension gets it
    // converted to 7 bits, or not at all.
    let converted;
    let (data, body) = if env.raw.is_ascii() {
        (env.data, "")
    } else if extensions.iter().any(|e| e == "8BITMIME") {
        (env.data, " BODY=8BITMIME")
    } else {
        let Some(seven) = crate::smtp::sevenbit::downconvert(env.raw) else {
            return Err(SendError::Permanent("the receiving server accepts only 7-bit mail, and this message cannot be converted".into()));
        };
        converted = encode_data(&seven);
        (converted.as_slice(), "")
    };
    let size = if extensions.iter().any(|e| e.starts_with("SIZE")) { format!(" SIZE={}", data.len()) } else { String::new() };
    let (mail_dsn, rcpt_dsn) = match env.dsn.filter(|dsn| !dsn.is_empty()) {
        Some(dsn) if extensions.iter().any(|e| e == "DSN") => crate::smtp::dsn::smtp_parameters(dsn, env.recipient),
        _ => (String::new(), String::new()),
    };
    t.command(&format!("MAIL FROM:<{}>{size}{body}{utf8}{mail_dsn}", env.sender), 2).await?;
    t.command(&format!("RCPT TO:<{}>{rcpt_dsn}", env.recipient), 2).await?;
    env.dsn_passed.store(!rcpt_dsn.is_empty(), std::sync::atomic::Ordering::Relaxed);
    t.command_within("DATA", 3, DATA_INIT_TIMEOUT).await?;
    t.write(data, DATA_TIMEOUT).await?;
    let reply = t.expect(2, DATA_TIMEOUT).await?;
    // The message is accepted at this point; a failing QUIT must not turn that into an error.
    let _ = t.write(b"QUIT\r\n", Duration::from_secs(5)).await;
    Ok(reply.text())
}

/// A session's TLS outcome for reporting: the TLS-RPT failure type, if the session (or the
/// certificate) did not live up to the policy.
type Outcome = Option<&'static str>;

/// Whether encryption is demanded (DANE, an enforced MTA-STS policy, or the administrator's
/// setting) rather than merely used when available.
fn tls_required(check: &Option<transport::Check>) -> bool {
    matches!(check, Some(transport::Check::WebPki | transport::Check::Dane(_)))
}

/// One SMTP session. Also tells whether encryption failed: the server offered STARTTLS, but
/// it could not be set up. With `try_tls` false, STARTTLS is not attempted at all.
async fn session(tcp: TcpStream, host: &str, check: Option<transport::Check>, env: &Envelope<'_>, try_tls: bool) -> (Result<String, SendError>, Outcome, bool) {
    // `None`: opportunistic TLS with no checking at all (the receiver asked for nothing).
    let required = tls_required(&check);
    let mut plain = Transport::new(tcp);
    if let Err(err) = plain.expect(2, COMMAND_TIMEOUT).await {
        return (Err(err), None, false);
    }
    let extensions = match ehlo(&mut plain, env.helo).await {
        Ok(extensions) => extensions,
        Err(err) => return (Err(err), None, false),
    };

    if !try_tls || !extensions.iter().any(|e| e == "STARTTLS") {
        if required {
            return (Err(temp("remote server does not offer STARTTLS and TLS is required")), Some("starttls-not-supported"), false);
        }
        let outcome = (try_tls && check.is_some()).then_some("starttls-not-supported");
        return (transact(&mut plain, env, &extensions).await, outcome, false);
    }

    if let Err(err) = plain.command("STARTTLS", 2).await {
        return (Err(err), Some("starttls-not-supported"), true);
    }
    if !plain.buf.is_empty() {
        // Anything received before the handshake is unauthenticated plaintext.
        return (Err(temp("unexpected data after STARTTLS reply")), Some("validation-failure"), false);
    }
    let Ok(name) = ServerName::try_from(host.to_owned()) else { return (Err(temp("invalid TLS server name")), None, false) };
    let verifier = check.clone().map(transport::Verifier::new);
    let config = match &verifier {
        Some(verifier) => {
            let provider = crate::tls::provider();
            let config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("ring provider supports the default protocol versions")
                .dangerous()
                .with_custom_certificate_verifier(verifier.clone())
                .with_no_client_auth();
            Arc::new(config)
        }
        None => tls_config(false),
    };
    let connector = tokio_rustls::TlsConnector::from(config);
    let problem = || verifier.as_ref().and_then(|v| v.problem.lock().as_ref().map(|(kind, _)| *kind));
    let tls = match tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, plain.stream)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => return (Err(temp(format!("TLS handshake failed: {e}"))), Some(problem().unwrap_or("validation-failure")), true),
        Err(_) => return (Err(temp("TLS handshake timed out")), None, true),
    };
    let mut secure = Transport::new(tls);
    let result = match ehlo(&mut secure, env.helo).await {
        Ok(extensions) => transact(&mut secure, env, &extensions).await,
        Err(err) => Err(err),
    };
    (result, problem(), false)
}

/// The SMTP server of a sender identity.
pub struct Relay {
    pub host: String,
    pub port: u16,
    /// `tls` (implicit), `starttls` or `none`.
    pub security: String,
    pub username: String,
    pub password: String,
}

impl Relay {
    pub async fn load(app: &App, identity_id: i64) -> sqlx::Result<Option<Relay>> {
        type Row = (Option<String>, Option<i64>, Option<String>, String, String);
        let row: Option<Row> =
            sqlx::query_as("SELECT smtp_host, smtp_port, smtp_security, smtp_username, smtp_password FROM identities WHERE id = ?").bind(identity_id).fetch_optional(&app.db).await?;
        Ok(row.and_then(|(host, port, security, username, sealed)| {
            Some(Relay { host: host?, port: u16::try_from(port?).ok()?, security: security?, username, password: app.secrets.open(&sealed)? })
        }))
    }
}

async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(t: &mut Transport<S>, relay: &Relay, extensions: &[String]) -> Result<(), SendError> {
    if relay.username.is_empty() {
        return Ok(());
    }
    if !extensions.iter().any(|e| e.starts_with("AUTH") && e.split_whitespace().any(|m| m == "PLAIN")) {
        return Err(SendError::Permanent("the SMTP server does not offer AUTH PLAIN".into()));
    }
    use base64::Engine;
    let token = base64::engine::general_purpose::STANDARD.encode(format!("\0{}\0{}", relay.username, relay.password));
    match t.command(&format!("AUTH PLAIN {token}"), 2).await {
        Ok(_) => Ok(()),
        // Wrong credentials will not fix themselves; report instead of retrying for days.
        Err(err) => Err(SendError::Permanent(format!("authentication at the SMTP server failed: {}", err.message()))),
    }
}

async fn relay_session(tcp: TcpStream, relay: &Relay, env: &Envelope<'_>) -> Result<String, SendError> {
    let name = ServerName::try_from(relay.host.clone()).map_err(|_| temp("invalid TLS server name"))?;
    // Certificates are always verified here: credentials travel over this connection.
    let connector = tokio_rustls::TlsConnector::from(tls_config(true));
    match relay.security.as_str() {
        "tls" => {
            let tls = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, tcp)).await.map_err(|_| temp("TLS handshake timed out"))?.map_err(|e| temp(format!("TLS handshake failed: {e}")))?;
            let mut secure = Transport::new(tls);
            secure.expect(2, COMMAND_TIMEOUT).await?;
            let extensions = ehlo(&mut secure, env.helo).await?;
            authenticate(&mut secure, relay, &extensions).await?;
            transact(&mut secure, env, &extensions).await
        }
        "starttls" => {
            let mut plain = Transport::new(tcp);
            plain.expect(2, COMMAND_TIMEOUT).await?;
            let extensions = ehlo(&mut plain, env.helo).await?;
            if !extensions.iter().any(|e| e == "STARTTLS") {
                return Err(SendError::Permanent("the SMTP server does not offer STARTTLS".into()));
            }
            plain.command("STARTTLS", 2).await?;
            if !plain.buf.is_empty() {
                return Err(temp("unexpected data after STARTTLS reply"));
            }
            let tls = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, plain.stream)).await.map_err(|_| temp("TLS handshake timed out"))?.map_err(|e| temp(format!("TLS handshake failed: {e}")))?;
            let mut secure = Transport::new(tls);
            let extensions = ehlo(&mut secure, env.helo).await?;
            authenticate(&mut secure, relay, &extensions).await?;
            transact(&mut secure, env, &extensions).await
        }
        _ => {
            let mut plain = Transport::new(tcp);
            plain.expect(2, COMMAND_TIMEOUT).await?;
            let extensions = ehlo(&mut plain, env.helo).await?;
            authenticate(&mut plain, relay, &extensions).await?;
            transact(&mut plain, env, &extensions).await
        }
    }
}

/// Hands one message to the SMTP server of a sender identity.
pub async fn deliver_via(app: &App, relay: &Relay, sender: &str, recipient: &Address, raw: &[u8]) -> Result<String, SendError> {
    deliver_via_with(app, relay, sender, recipient, raw, None).await.map(|(reply, _)| reply)
}

/// [`deliver_via`], passing on DSN parameters. Also tells whether the server took them.
pub async fn deliver_via_with(app: &App, relay: &Relay, sender: &str, recipient: &Address, raw: &[u8], dsn: Option<&crate::smtp::dsn::Dsn>) -> Result<(String, bool), SendError> {
    relay_deliver(app, relay, false, sender, recipient, raw, dsn).await
}

/// Hands one message to a relay. A `trusted` relay is the administrator's default route,
/// which may be on the local network; the servers of users' identities may not.
async fn relay_deliver(app: &App, relay: &Relay, trusted: bool, sender: &str, recipient: &Address, raw: &[u8], dsn: Option<&crate::smtp::dsn::Dsn>) -> Result<(String, bool), SendError> {
    let allow_private = trusted || app.cfg.identity_relay_allow_private;
    if relay.security == "none" && !allow_private {
        return Err(SendError::Permanent("unencrypted SMTP servers are not allowed".into()));
    }
    let data = encode_data(raw);
    let recipient_text = recipient.to_string();
    let env = Envelope { helo: &app.cfg.hostname, sender, recipient: &recipient_text, raw, data: &data, dsn, dsn_passed: Default::default() };
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((relay.host.as_str(), relay.port)).await.map_err(|e| temp(format!("cannot resolve {}: {e}", relay.host)))?.collect();
    // Users choose this host: it must not be a way to reach the server's internal network.
    if !allow_private && addrs.iter().any(|a| is_private(a.ip())) {
        return Err(SendError::Permanent("the SMTP server resolves to a private address".into()));
    }
    let addr = *addrs.first().ok_or_else(|| temp(format!("{} does not resolve to an address", relay.host)))?;
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| temp(format!("connection to {} timed out", relay.host)))?
        .map_err(|e| temp(format!("connection to {} failed: {e}", relay.host)))?;
    relay_session(tcp, relay, &env).await.map(|reply| (format!("{}: {reply}", relay.host), env.dsn_passed.load(std::sync::atomic::Ordering::Relaxed))).map_err(|err| match err {
        SendError::Permanent(m) => SendError::Permanent(format!("{}: {m}", relay.host)),
        SendError::Temporary(m) => SendError::Temporary(format!("{}: {m}", relay.host)),
    })
}

/// Splits a `host:port` relay specification.
pub fn parse_relay(relay: &str) -> Option<(String, u16)> {
    let (host, port) = relay.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty()).then_some((host.to_owned(), port.parse().ok()?))
}

/// Delivers one message to one recipient, trying the destination's mail exchangers in order.
/// Returns the final reply of the accepting server.
pub async fn deliver(app: &App, sender: &str, recipient: &Address, raw: &[u8]) -> Result<String, SendError> {
    deliver_with(app, sender, recipient, raw, None).await.map(|(reply, _)| reply)
}

/// [`deliver`], passing on DSN parameters. Also tells whether the receiver took them.
pub async fn deliver_with(app: &App, sender: &str, recipient: &Address, raw: &[u8], dsn: Option<&crate::smtp::dsn::Dsn>) -> Result<(String, bool), SendError> {
    let data = encode_data(raw);
    let recipient_text = recipient.to_string();
    let env = Envelope { helo: &app.cfg.hostname, sender, recipient: &recipient_text, raw, data: &data, dsn, dsn_passed: Default::default() };

    // The administrator's default route takes all outgoing mail. With credentials it is a
    // submission server (implicit TLS on 465, STARTTLS otherwise); without, a smarthost
    // treated like a mail exchanger.
    let rt = app.rt();
    if let Some(route) = rt.route()
        && rt.route_signs_in()
    {
        let (host, port) = parse_relay(route).ok_or_else(|| temp("invalid default route"))?;
        let password = if rt.default_route_password.is_empty() {
            String::new()
        } else {
            app.secrets.open(&rt.default_route_password).ok_or_else(|| SendError::Permanent("the password of the default route cannot be read; enter it again".into()))?
        };
        let relay = Relay { host, port, security: if port == 465 { "tls".into() } else { "starttls".into() }, username: rt.default_route_username.clone(), password };
        return relay_deliver(app, &relay, true, sender, recipient, raw, dsn).await;
    }

    // (TLS name, socket addresses) candidates in preference order.
    let mut candidates: Vec<(String, Vec<SocketAddr>)> = Vec::new();
    if let Some(route) = rt.route() {
        let (host, port) = parse_relay(route).ok_or_else(|| temp("invalid default route"))?;
        let addrs = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| temp(format!("cannot resolve relay {host}: {e}")))?
            .collect();
        candidates.push((host, addrs));
    } else {
        let resolver = app.authenticator.as_ref().ok_or_else(|| temp("no DNS resolver available"))?;
        let Some(mut hosts) = crate::dns::mail_exchangers(resolver, &recipient.domain).await.map_err(temp)? else {
            return Err(SendError::Permanent(format!("domain {} does not exist", recipient.domain)));
        };
        if hosts.iter().any(|(_, host)| host.is_empty()) {
            return Err(SendError::Permanent(format!("domain {} does not accept mail (null MX)", recipient.domain)));
        }
        // RFC 5321 5.1: without MX records, the address records of the domain itself serve.
        let implicit = hosts.is_empty();
        if implicit {
            hosts.push((0, recipient.domain.clone()));
        }
        let mut any_resolved = false;
        let mut lookup_failed = false;
        for (_, host) in hosts.into_iter().take(MAX_HOSTS) {
            match crate::dns::ips(resolver, &host).await {
                Ok(ips) => {
                    any_resolved = true;
                    // Never let mail routing reach into internal networks: a hostile domain
                    // could otherwise point its MX at our own infrastructure.
                    let addrs: Vec<SocketAddr> = ips.into_iter().filter(|ip| !is_private(*ip)).map(|ip| SocketAddr::new(ip, 25)).collect();
                    if !addrs.is_empty() {
                        candidates.push((host, addrs));
                    }
                }
                Err(crate::dns::DnsError::NotFound) => {}
                Err(err) => {
                    lookup_failed = true;
                    tracing::debug!(%err, host, "MX host lookup failed");
                }
            }
        }
        if candidates.is_empty() {
            return Err(if any_resolved {
                SendError::Permanent(format!("mail servers of {} resolve to non-public addresses", recipient.domain))
            } else if implicit && !lookup_failed {
                // Neither MX nor address records: the domain receives no mail (RFC 5321 5.1).
                SendError::Permanent(format!("domain {} has no mail server (no MX or address records)", recipient.domain))
            } else {
                temp(format!("no mail server found for {}", recipient.domain))
            });
        }
    }

    // The receiving domain's MTA-STS policy (not for a configured relay).
    let relayed = rt.route().is_some();
    let sts = match (relayed, rt.mta_sts_enabled) {
        (false, true) => match transport::sts_policy(app, &recipient.domain).await {
            Ok(policy) => policy.filter(|p| p.mode != transport::StsMode::None),
            Err(reason) => {
                tracing::debug!(reason, domain = recipient.domain, "MTA-STS policy unavailable");
                let applied = transport::Applied { policy_type: "sts", policy_string: Vec::new() };
                transport::record(app, &recipient.domain, &applied, "", "", Some("sts-policy-fetch-error")).await;
                None
            }
        },
        _ => None,
    };
    if let Some(policy) = sts.as_ref().filter(|p| p.mode == transport::StsMode::Enforce)
        && !relayed
    {
        candidates.retain(|(host, _)| policy.allows(host));
        if candidates.is_empty() {
            return Err(temp(format!("no mail server of {} is allowed by its MTA-STS policy", recipient.domain)));
        }
    }

    let mut last_error = temp("no mail server could be reached");
    for (host, addrs) in candidates {
        // DANE first, then MTA-STS, then the server's own setting.
        let dane = if !relayed { transport::dane_for(app, &recipient.domain, &host).await } else { transport::Dane::None };
        let (check, applied) = match dane {
            transport::Dane::Failed(reason) => {
                last_error = temp(format!("{host}: DNSSEC lookup of its TLSA records failed: {reason}"));
                let applied = transport::Applied { policy_type: "tlsa", policy_string: Vec::new() };
                transport::record(app, &recipient.domain, &applied, &host, "", Some("dnssec-invalid")).await;
                continue;
            }
            transport::Dane::Records(records) => {
                let lines = records.iter().map(|r| format!("{} {} {} {}", r.usage, r.selector, r.matching, r.data.iter().map(|b| format!("{b:02x}")).collect::<String>())).collect();
                (Some(transport::Check::Dane(records)), transport::Applied { policy_type: "tlsa", policy_string: lines })
            }
            transport::Dane::None => match &sts {
                Some(policy) if policy.mode == transport::StsMode::Enforce => (Some(transport::Check::WebPki), transport::Applied { policy_type: "sts", policy_string: policy.lines() }),
                Some(policy) => (Some(transport::Check::Observe), transport::Applied { policy_type: "sts", policy_string: policy.lines() }),
                None if app.rt().outbound_require_tls => (Some(transport::Check::WebPki), transport::Applied { policy_type: "no-policy-found", policy_string: Vec::new() }),
                None => (None, transport::Applied { policy_type: "no-policy-found", policy_string: Vec::new() }),
            },
        };
        for addr in addrs.into_iter().take(2) {
            let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(tcp)) => tcp,
                Ok(Err(err)) => {
                    last_error = temp(format!("connection to {host} [{}] failed: {err}", addr.ip()));
                    continue;
                }
                Err(_) => {
                    last_error = temp(format!("connection to {host} [{}] timed out", addr.ip()));
                    continue;
                }
            };
            let (mut result, outcome, tls_failed) = session(tcp, &host, check.clone(), &env, true).await;
            if !relayed {
                transport::record(app, &recipient.domain, &applied, &host, &addr.ip().to_string(), outcome).await;
            }
            // Opportunistic TLS (RFC 7435): a server whose encryption cannot be set up gets the
            // mail without it, like a server that offers none, unless encryption is demanded.
            if tls_failed && !tls_required(&check) {
                tracing::info!(host, error = %result.as_ref().err().map_or("", |e| e.message()), "STARTTLS failed; delivering without encryption");
                result = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
                    Ok(Ok(tcp)) => session(tcp, &host, check.clone(), &env, false).await.0,
                    Ok(Err(err)) => Err(temp(format!("connection to {host} [{}] failed: {err}", addr.ip()))),
                    Err(_) => Err(temp(format!("connection to {host} [{}] timed out", addr.ip()))),
                };
            }
            match result {
                Ok(reply) => return Ok((format!("{host}: {reply}"), env.dsn_passed.load(std::sync::atomic::Ordering::Relaxed))),
                Err(SendError::Permanent(msg)) => return Err(SendError::Permanent(format!("{host}: {msg}"))),
                Err(SendError::Temporary(msg)) => last_error = temp(format!("{host}: {msg}")),
            }
        }
    }
    Err(last_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_encoding() {
        assert_eq!(encode_data(b"a\r\n.b\r\n..c\r\n"), b"a\r\n..b\r\n...c\r\n.\r\n");
        assert_eq!(encode_data(b"no newline"), b"no newline\r\n.\r\n");
        assert_eq!(encode_data(b"bare\nlf\n"), b"bare\r\nlf\r\n.\r\n");
        // A smuggled end-of-data sequence built from bare line endings is neutralized.
        assert_eq!(encode_data(b"x\n.\nMAIL FROM:<a>\n"), b"x\r\n..\r\nMAIL FROM:<a>\r\n.\r\n");
        assert_eq!(encode_data(b"x\r.\rY\r\n"), b"x.Y\r\n.\r\n");
        assert_eq!(encode_data(b""), b".\r\n");
    }

    #[test]
    fn internationalized_mail_needs_the_extension() {
        let env = |sender: &'static str, recipient: &'static str, data: &'static [u8]| Envelope { helo: "h", sender, recipient, raw: data, data, dsn: None, dsn_passed: Default::default() };
        let ascii = env("a@example.org", "b@example.org", b"Subject: plain\r\n\r\nza\xc5\xbc\xc3\xb3\xc5\x82\xc4\x87\r\n.\r\n");
        assert_eq!(smtputf8_parameter(&ascii, true), Ok(""), "a UTF-8 body alone is ordinary 8BITMIME");
        let rcpt = env("a@example.org", "j\u{f3}zef@example.org", b"Subject: x\r\n\r\n.\r\n");
        assert_eq!(smtputf8_parameter(&rcpt, true), Ok(" SMTPUTF8"));
        assert!(smtputf8_parameter(&rcpt, false).is_err(), "the address cannot be sent to a server without the extension");
        let header = env("a@example.org", "b@example.org", b"Subject: \xc5\xbc\r\n\r\n.\r\n");
        assert_eq!(smtputf8_parameter(&header, true), Ok(" SMTPUTF8"));
        assert_eq!(smtputf8_parameter(&header, false), Ok(""), "header content alone never blocks delivery");
    }

    #[test]
    fn relay_parsing() {
        assert_eq!(parse_relay("smtp.example.com:587"), Some(("smtp.example.com".into(), 587)));
        assert_eq!(parse_relay("[::1]:2525"), Some(("::1".into(), 2525)));
        assert_eq!(parse_relay("nohost"), None);
        assert_eq!(parse_relay(":25"), None);
        assert_eq!(parse_relay("host:notaport"), None);
    }
}
