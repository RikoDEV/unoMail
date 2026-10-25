//! Shared helpers for integration tests: a running server on ephemeral ports, a scriptable
//! SMTP client and a fake remote mail server.
#![allow(dead_code)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Extension, Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use parking_lot::Mutex;
use serde_json::{Value, json};
use tower::ServiceExt;
use rustls::pki_types::ServerName;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use unomail::{
    app::{App, AppState},
    auth::{Account, Role},
    config::Config,
    directory::{self, NewAccount},
    smtp::server::{self, Mode},
};

pub const PASSWORD: &str = "correct horse battery staple";

pub struct TestEnv {
    pub app: AppState,
    pub mx: SocketAddr,
    pub submission: SocketAddr,
    pub smtps: SocketAddr,
    _dir: tempfile::TempDir,
}

async fn listen() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

impl TestEnv {
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    pub async fn start_with(configure: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_tests(dir.path().to_path_buf());
        configure(&mut cfg);
        let app = App::new(cfg, None).await.unwrap();
        let (mx_listener, mx) = listen().await;
        let (sub_listener, submission) = listen().await;
        let (smtps_listener, smtps) = listen().await;
        tokio::spawn(server::serve(app.clone(), Mode::Mx, mx_listener));
        tokio::spawn(server::serve(app.clone(), Mode::Submission, sub_listener));
        tokio::spawn(server::serve(app.clone(), Mode::Smtps, smtps_listener));
        TestEnv { app, mx, submission, smtps, _dir: dir }
    }

    pub async fn domain(&self, name: &str) -> i64 {
        directory::create_domain(&self.app.db, name).await.unwrap()
    }

    pub async fn account(&self, email: &str) -> Account {
        self.account_with(email, Role::User, None).await
    }

    pub async fn account_with(&self, email: &str, role: Role, quota_bytes: Option<i64>) -> Account {
        directory::create_account(&self.app, NewAccount { email, password: PASSWORD, display_name: "", role, quota_bytes })
            .await
            .unwrap()
    }

    pub async fn alias(&self, source: &str, destinations: &[&str]) {
        let destinations: Vec<String> = destinations.iter().map(|s| s.to_string()).collect();
        directory::create_alias(&self.app.db, source, &destinations).await.unwrap();
    }

    /// Raw contents of every message in the given mailbox role of an account.
    pub async fn mailbox(&self, account: &Account, role: &str) -> Vec<String> {
        let mailbox = self.app.store.mailbox_by_role(account.id, role).await.unwrap().unwrap();
        let mut out = Vec::new();
        for message in self.app.store.messages_in(mailbox.id).await.unwrap() {
            out.push(String::from_utf8(self.app.store.read_blob(&message.blob_hash).await.unwrap()).unwrap());
        }
        out
    }

    pub async fn inbox(&self, account: &Account) -> Vec<String> {
        self.mailbox(account, "inbox").await
    }
}

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// Line-oriented test client for SMTP-style protocols.
pub struct Client {
    stream: Option<BufReader<Box<dyn Io>>>,
}

impl Client {
    pub async fn connect(addr: SocketAddr) -> Self {
        let tcp = TcpStream::connect(addr).await.unwrap();
        Client { stream: Some(BufReader::new(Box::new(tcp))) }
    }

    /// Connects, reads the greeting and sends EHLO.
    pub async fn smtp(addr: SocketAddr) -> Self {
        let mut client = Self::connect(addr).await;
        assert!(client.read_reply().await.starts_with("220 "));
        assert!(client.cmd("EHLO client.example.net").await.starts_with("250"));
        client
    }

    pub async fn connect_tls(addr: SocketAddr) -> Self {
        let mut client = Self::connect(addr).await;
        client.upgrade().await;
        client
    }

    /// Performs the client side of a TLS handshake on the current connection.
    pub async fn upgrade(&mut self) {
        let reader = self.stream.take().unwrap();
        assert!(reader.buffer().is_empty(), "unexpected plaintext before TLS handshake");
        let connector = tokio_rustls::TlsConnector::from(unomail::smtp::client::tls_config(false));
        let name = ServerName::try_from("mail.test.example").unwrap();
        let tls = connector.connect(name, reader.into_inner()).await.unwrap();
        self.stream = Some(BufReader::new(Box::new(tls)));
    }

    pub async fn starttls(&mut self) {
        assert!(self.cmd("STARTTLS").await.starts_with("220 "));
        self.upgrade().await;
        assert!(self.cmd("EHLO client.example.net").await.starts_with("250"));
    }

    pub async fn send_raw(&mut self, data: &[u8]) {
        let stream = self.stream.as_mut().unwrap().get_mut();
        stream.write_all(data).await.unwrap();
        stream.flush().await.unwrap();
    }

    pub async fn read_line(&mut self) -> Option<String> {
        let mut line = String::new();
        let read = tokio::time::timeout(Duration::from_secs(10), self.stream.as_mut().unwrap().read_line(&mut line)).await;
        match read {
            Ok(Ok(n)) if n > 0 => Some(line.trim_end().to_owned()),
            Ok(_) => None,
            Err(_) => panic!("timed out waiting for the server"),
        }
    }

    /// Reads one complete (possibly multi-line) SMTP reply.
    pub async fn read_reply(&mut self) -> String {
        let mut lines = Vec::new();
        loop {
            let line = self.read_line().await.expect("connection closed while reading a reply");
            let done = line.as_bytes().get(3) != Some(&b'-');
            lines.push(line);
            if done {
                return lines.join("\n");
            }
        }
    }

    pub async fn cmd(&mut self, line: &str) -> String {
        self.send_raw(format!("{line}\r\n").as_bytes()).await;
        self.read_reply().await
    }

    pub async fn auth_plain(&mut self, user: &str, password: &str) -> String {
        use base64::Engine;
        let token = base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{password}"));
        self.cmd(&format!("AUTH PLAIN {token}")).await
    }

    /// Runs a full mail transaction and returns the reply to the end of DATA.
    pub async fn send_mail(&mut self, from: &str, to: &[&str], message: &str) -> String {
        let reply = self.cmd(&format!("MAIL FROM:<{from}>")).await;
        assert!(reply.starts_with("250"), "MAIL FROM failed: {reply}");
        for rcpt in to {
            let reply = self.cmd(&format!("RCPT TO:<{rcpt}>")).await;
            assert!(reply.starts_with("250"), "RCPT TO failed: {reply}");
        }
        assert!(self.cmd("DATA").await.starts_with("354"));
        self.send_raw(message.as_bytes()).await;
        self.cmd(".").await
    }

    /// Like `send_mail`, with the MAIL FROM command given in full (for its parameters).
    pub async fn send_mail_with(&mut self, _from: &str, mail_from: &str, to: &[&str], message: &str) -> String {
        let reply = self.cmd(mail_from).await;
        if !reply.starts_with("250") {
            return reply;
        }
        for rcpt in to {
            let reply = self.cmd(&format!("RCPT TO:<{rcpt}>")).await;
            assert!(reply.starts_with("250"), "RCPT TO failed: {reply}");
        }
        assert!(self.cmd("DATA").await.starts_with("354"));
        self.send_raw(message.as_bytes()).await;
        self.cmd(".").await
    }

    /// Whatever bytes arrive next (for compressed streams).
    pub async fn read_raw(&mut self) -> Vec<u8> {
        let reader = self.stream.as_mut().unwrap();
        let data = tokio::time::timeout(Duration::from_secs(10), reader.fill_buf()).await.expect("timed out waiting for the server").unwrap().to_vec();
        reader.consume(data.len());
        data
    }

    /// True when the server has closed the connection.
    pub async fn is_closed(&mut self) -> bool {
        let mut buf = [0u8; 1];
        matches!(
            tokio::time::timeout(Duration::from_secs(5), self.stream.as_mut().unwrap().read(&mut buf)).await,
            Ok(Ok(0)) | Ok(Err(_))
        )
    }
}

#[derive(Debug, Clone)]
pub struct Captured {
    pub from: String,
    pub to: String,
    pub data: String,
    /// ESMTP parameters of MAIL FROM and RCPT TO, space separated.
    pub params: String,
}

/// A fake remote mail server. Recipients whose local part starts with `reject` get a 550,
/// those starting with `defer` a 451; everything else is accepted and recorded.
pub struct Sink {
    pub addr: SocketAddr,
    pub messages: Arc<Mutex<Vec<Captured>>>,
    /// Whether the fake server advertises SMTPUTF8.
    pub smtputf8: Arc<std::sync::atomic::AtomicBool>,
    /// Whether the fake server advertises DSN.
    pub dsn: Arc<std::sync::atomic::AtomicBool>,
    /// How the fake server deviates from a modern one.
    pub quirks: Arc<Quirks>,
}

/// Behaviour of older or broken mail servers, switched on one by one.
#[derive(Default)]
pub struct Quirks {
    /// No 8BITMIME: 7-bit mail only.
    pub seven_bit: std::sync::atomic::AtomicBool,
    /// EHLO is not understood (502); only HELO works.
    pub no_ehlo: std::sync::atomic::AtomicBool,
    /// STARTTLS is offered, but the handshake fails.
    pub broken_tls: std::sync::atomic::AtomicBool,
    /// Recipients whose local part starts with `slow` are answered only after a minute.
    pub slow: std::sync::atomic::AtomicBool,
}

impl Quirks {
    fn on(flag: &std::sync::atomic::AtomicBool) -> bool {
        flag.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Sink {
    pub async fn start() -> Self {
        let (listener, addr) = listen().await;
        let messages: Arc<Mutex<Vec<Captured>>> = Arc::default();
        let store = messages.clone();
        let smtputf8: Arc<std::sync::atomic::AtomicBool> = Arc::default();
        let dsn: Arc<std::sync::atomic::AtomicBool> = Arc::default();
        let quirks: Arc<Quirks> = Arc::default();
        let (utf8, with_dsn, with_quirks) = (smtputf8.clone(), dsn.clone(), quirks.clone());
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(Self::session(tcp, store.clone(), utf8.clone(), with_dsn.clone(), with_quirks.clone()));
            }
        });
        Sink { addr, messages, smtputf8, dsn, quirks }
    }

    pub fn relay(&self) -> String {
        format!("127.0.0.1:{}", self.addr.port())
    }

    pub fn received(&self) -> Vec<Captured> {
        self.messages.lock().clone()
    }

    async fn session(tcp: TcpStream, store: Arc<Mutex<Vec<Captured>>>, utf8: Arc<std::sync::atomic::AtomicBool>, dsn: Arc<std::sync::atomic::AtomicBool>, quirks: Arc<Quirks>) {
        let mut io = BufReader::new(tcp);
        let _ = io.get_mut().write_all(b"220 sink.example ESMTP\r\n").await;
        let (mut from, mut to, mut params) = (String::new(), String::new(), String::new());
        loop {
            let mut line = String::new();
            if io.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }
            let upper = line.trim_end().to_ascii_uppercase();
            let reply: String = if upper.starts_with("EHLO") && Quirks::on(&quirks.no_ehlo) {
                "502 5.5.1 Command not implemented\r\n".into()
            } else if upper.starts_with("HELO") {
                "250 sink.example\r\n".into()
            } else if upper == "STARTTLS" && Quirks::on(&quirks.broken_tls) {
                // Agrees, then answers the handshake with nonsense.
                let _ = io.get_mut().write_all(b"220 Go ahead\r\n").await;
                let mut hello = [0u8; 512];
                let _ = io.get_mut().read(&mut hello).await;
                let _ = io.get_mut().write_all(b"this is not TLS\r\n").await;
                return;
            } else if upper.starts_with("EHLO") {
                let mut reply = String::from("250-sink.example\r\n");
                if !Quirks::on(&quirks.seven_bit) {
                    reply.push_str("250-8BITMIME\r\n");
                }
                if Quirks::on(&quirks.broken_tls) {
                    reply.push_str("250-STARTTLS\r\n");
                }
                if utf8.load(std::sync::atomic::Ordering::Relaxed) {
                    reply.push_str("250-SMTPUTF8\r\n");
                }
                if dsn.load(std::sync::atomic::Ordering::Relaxed) {
                    reply.push_str("250-DSN\r\n");
                }
                reply + "250 SIZE 10000000\r\n"
            } else if upper.starts_with("MAIL FROM:") {
                let (path, rest) = line.trim_end()[10..].split_once('>').unwrap();
                from = path.trim_start_matches('<').to_owned();
                params = rest.trim().to_owned();
                "250 Ok\r\n".into()
            } else if upper.starts_with("RCPT TO:") {
                let (path, rest) = line.trim_end()[8..].split_once('>').unwrap();
                to = path.trim_start_matches('<').to_owned();
                params = format!("{params} {}", rest.trim()).trim().to_owned();
                if to.starts_with("slow") && Quirks::on(&quirks.slow) {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
                if to.starts_with("reject") {
                    "550 5.1.1 No such user here\r\n".into()
                } else if to.starts_with("defer") {
                    "451 4.3.0 Try again later\r\n".into()
                } else {
                    "250 Ok\r\n".into()
                }
            } else if upper == "DATA" {
                let _ = io.get_mut().write_all(b"354 Go ahead\r\n").await;
                let mut data = String::new();
                loop {
                    let mut l = String::new();
                    if io.read_line(&mut l).await.unwrap_or(0) == 0 {
                        return;
                    }
                    if l == ".\r\n" {
                        break;
                    }
                    data.push_str(l.strip_prefix('.').unwrap_or(&l));
                }
                store.lock().push(Captured { from: from.clone(), to: to.clone(), data, params: params.clone() });
                "250 Ok: accepted\r\n".into()
            } else if upper == "QUIT" {
                let _ = io.get_mut().write_all(b"221 Bye\r\n").await;
                return;
            } else {
                "250 Ok\r\n".into()
            };
            if io.get_mut().write_all(reply.as_bytes()).await.is_err() {
                return;
            }
        }
    }
}

pub fn message(from: &str, to: &str, subject: &str, body: &str) -> String {
    format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nDate: Mon, 05 Oct 2026 10:00:00 +0000\r\n\
         Message-ID: <{}@test>\r\n\r\n{body}\r\n",
        unomail::util::random_token()
    )
}

/// A browser-like API client holding one session.
#[derive(Clone)]
pub struct Api {
    pub router: Router,
    pub cookie: Option<String>,
    pub csrf: Option<String>,
    pub peer: SocketAddr,
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: axum::http::HeaderMap,
    pub body: Value,
    pub text: String,
    pub bytes: Vec<u8>,
}

impl Api {
    pub fn new(env: &TestEnv) -> Self {
        Api { router: unomail::api::router(env.app.clone()), cookie: None, csrf: None, peer: "198.51.100.7:40000".parse().unwrap() }
    }

    pub async fn send(&self, method: Method, path: &str, body: Option<Value>, extra: &[(&str, &str)]) -> Reply {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(cookie) = &self.cookie {
            request = request.header(header::COOKIE, cookie);
        }
        if let Some(csrf) = &self.csrf {
            request = request.header("x-csrf-token", csrf);
        }
        for (name, value) in extra {
            request = request.header(*name, *value);
        }
        let body = match body {
            Some(json) => {
                request = request.header(header::CONTENT_TYPE, "application/json");
                Body::from(json.to_string())
            }
            None => Body::empty(),
        };
        let router = self.router.clone().layer(Extension(unomail::api::PeerAddr(self.peer)));
        let response = router.oneshot(request.body(body).unwrap()).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        Reply { status: parts.status, headers: parts.headers, body: serde_json::from_slice(&bytes).unwrap_or(Value::Null), text, bytes: bytes.to_vec() }
    }

    /// Sends a request with a raw (non-JSON) body.
    pub async fn raw(&self, method: Method, path: &str, body: Vec<u8>, content_type: &str) -> Reply {
        let mut request = Request::builder().method(method).uri(path).header(header::CONTENT_TYPE, content_type);
        if let Some(cookie) = &self.cookie {
            request = request.header(header::COOKIE, cookie);
        }
        if let Some(csrf) = &self.csrf {
            request = request.header("x-csrf-token", csrf);
        }
        let router = self.router.clone().layer(Extension(unomail::api::PeerAddr(self.peer)));
        let response = router.oneshot(request.body(Body::from(body)).unwrap()).await.unwrap();
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        Reply { status: parts.status, headers: parts.headers, body: serde_json::from_slice(&bytes).unwrap_or(Value::Null), text, bytes: bytes.to_vec() }
    }

    pub async fn get(&self, path: &str) -> Reply {
        self.send(Method::GET, path, None, &[]).await
    }

    pub async fn post(&self, path: &str, body: Value) -> Reply {
        self.send(Method::POST, path, Some(body), &[]).await
    }

    pub async fn put(&self, path: &str, body: Value) -> Reply {
        self.send(Method::PUT, path, Some(body), &[]).await
    }

    pub async fn patch(&self, path: &str, body: Value) -> Reply {
        self.send(Method::PATCH, path, Some(body), &[]).await
    }

    pub async fn delete(&self, path: &str) -> Reply {
        self.send(Method::DELETE, path, None, &[]).await
    }

    pub async fn login(&mut self, email: &str, password: &str) -> Reply {
        let reply = self.post("/api/auth/login", json!({ "email": email, "password": password })).await;
        if reply.status == StatusCode::OK {
            let set_cookie = reply.headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
            self.cookie = Some(set_cookie.split(';').next().unwrap().to_owned());
            self.csrf = reply.body["csrf_token"].as_str().map(str::to_owned);
        }
        reply
    }

    pub async fn logged_in(env: &TestEnv, email: &str) -> Self {
        let mut api = Api::new(env);
        assert_eq!(api.login(email, PASSWORD).await.status, StatusCode::OK);
        api
    }
}

impl Api {
    /// Sends one JMAP request and returns the `methodResponses` array.
    pub async fn jmap(&self, calls: Value) -> Value {
        let reply = self
            .post("/jmap/api", json!({ "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"], "methodCalls": calls }))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text);
        reply.body["methodResponses"].clone()
    }

    /// The JMAP account id of the logged-in user.
    pub async fn jmap_account(&self) -> String {
        self.get("/jmap/session").await.body["primaryAccounts"]["urn:ietf:params:jmap:mail"].as_str().unwrap().to_owned()
    }
}
