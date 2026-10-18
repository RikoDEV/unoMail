//! IMAP4rev1 (RFC 3501) and IMAP4rev2 (RFC 9051) server over implicit TLS (port 993) or STARTTLS (port 143), with the
//! IDLE, MOVE, UIDPLUS, LITERAL+, SASL-IR, NAMESPACE, UNSELECT, SPECIAL-USE, ID, ENABLE, CONDSTORE, QRESYNC, QUOTA,
//! SORT, THREAD, ESEARCH, LIST-EXTENDED, LIST-STATUS, STATUS=SIZE, BINARY and COMPRESS=DEFLATE extensions. Mailbox
//! names use modified UTF-7 on the wire (RFC 3501 section 5.1.3) until a client enables IMAP4rev2, then UTF-8.

use std::{net::SocketAddr, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};
use mail_parser::MessageParser;
use time::{OffsetDateTime, format_description::FormatItem, macros::format_description};
use tokio::net::{TcpListener, TcpStream};

use crate::{
    app::{AppState, Metrics},
    auth::{self, Account, AuthError, Protocol},
    net::{Conn, ReadError},
    store::{Flags, Mailbox, Message, StoreError},
};

pub mod fetch;
pub mod parse;

use fetch::Section;
use parse::{Arg, SequenceSet, Tokenizer, list_match, string, uid_set, utf7_decode, utf7_encode};

const CAPABILITIES: &str = "IMAP4rev1 IMAP4rev2 LITERAL+ SASL-IR AUTH=PLAIN IDLE NAMESPACE ACL UIDPLUS MOVE UNSELECT CHILDREN SPECIAL-USE ID ENABLE CONDSTORE QRESYNC \
     QUOTA QUOTA=RES-STORAGE SORT THREAD=ORDEREDSUBJECT THREAD=REFERENCES ESEARCH LIST-EXTENDED LIST-STATUS STATUS=SIZE BINARY COMPRESS=DEFLATE";
/// Advertised before STARTTLS: no authentication is possible in plaintext.
const PLAINTEXT_CAPABILITIES: &str = "IMAP4rev1 STARTTLS LOGINDISABLED";
const LOGIN_TIMEOUT: Duration = Duration::from_secs(60);
const SESSION_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_LINE: usize = 16 * 1024;
/// Literals other than APPEND payloads (user names, search strings, ...) are small.
const MAX_SMALL_LITERAL: usize = 16 * 1024;
const MAX_ERRORS: u32 = 20;
const MAX_LOGIN_FAILURES: u32 = 3;

const INTERNAL_DATE: &[FormatItem<'_>] = format_description!("[day]-[month repr:short]-[year] [hour]:[minute]:[second] +0000");
const DATE_TIME: &[FormatItem<'_>] =
    format_description!("[day padding:none]-[month repr:short]-[year] [hour]:[minute]:[second] [offset_hour sign:mandatory][offset_minute]");
const DATE: &[FormatItem<'_>] = format_description!("[day padding:none]-[month repr:short]-[year]");

struct Selected {
    mailbox: Mailbox,
    /// Rights of the logged-in account on the mailbox (everything for its own mailboxes).
    rights: String,
    read_only: bool,
    /// Messages in sequence-number order (ascending UID), as last reported to the client.
    messages: Vec<Message>,
    /// The mailbox's mod-sequence the snapshot above is known to be complete up to.
    synced_modseq: i64,
}

struct Session {
    app: AppState,
    conn: Conn,
    peer: SocketAddr,
    account: Option<Account>,
    /// What the account signed in with, checked again now and then.
    grant: Option<auth::Grant>,
    selected: Option<Selected>,
    errors: u32,
    login_failures: u32,
    /// The client understands MODSEQ data (CONDSTORE).
    condstore: bool,
    /// The client enabled QRESYNC: expunges are reported as VANISHED.
    qresync: bool,
    /// Single sign-on is configured: token logins are advertised.
    oauth: bool,
    /// The client enabled IMAP4rev2: UTF-8 mailbox names, ESEARCH replies, no RECENT.
    rev2: bool,
}

enum Flow {
    Continue,
    Close,
    /// The command answered itself (COMPRESS: its reply must precede the switch).
    Silent,
}

type CmdResult = Result<String, String>;

fn bad(msg: &str) -> CmdResult {
    Err(format!("BAD {msg}"))
}

fn no(msg: &str) -> CmdResult {
    Err(format!("NO {msg}"))
}

fn internal(err: impl std::fmt::Debug) -> String {
    tracing::error!(error = ?err, "IMAP command failed");
    "NO [SERVERBUG] internal error".to_owned()
}

fn flags_text(message: &Message) -> String {
    let mut flags = Vec::new();
    for (name, set) in [("\\Seen", message.seen), ("\\Answered", message.answered), ("\\Flagged", message.flagged), ("\\Deleted", message.deleted), ("\\Draft", message.draft)] {
        if set {
            flags.push(name.to_owned());
        }
    }
    flags.extend(serde_json::from_str::<Vec<String>>(&message.keywords).unwrap_or_default());
    flags.join(" ")
}

fn valid_keyword(keyword: &str) -> bool {
    !keyword.is_empty() && keyword.len() <= 100 && keyword.bytes().all(|b| b.is_ascii_graphic() && !b"(){]%*\"\\".contains(&b))
}

/// Splits a client flag list into system flags and keywords.
fn parse_flags(args: &[Arg]) -> Result<(Flags, Vec<String>), String> {
    let mut flags = Flags::default();
    let mut keywords = Vec::new();
    for arg in args {
        let Arg::Atom(flag) = arg else { return Err("BAD invalid flag".into()) };
        match flag.to_ascii_lowercase().as_str() {
            "\\seen" => flags.seen = true,
            "\\answered" => flags.answered = true,
            "\\flagged" => flags.flagged = true,
            "\\deleted" => flags.deleted = true,
            "\\draft" => flags.draft = true,
            "\\recent" => {}
            other if !other.starts_with('\\') && valid_keyword(other) => keywords.push(other.to_owned()),
            _ => return Err("BAD invalid flag".into()),
        }
    }
    if keywords.len() > 30 {
        return Err("NO too many keywords".into());
    }
    Ok((flags, keywords))
}

fn special_use(role: Option<&str>) -> &'static str {
    match role {
        Some("sent") => " \\Sent",
        Some("drafts") => " \\Drafts",
        Some("trash") => " \\Trash",
        Some("junk") => " \\Junk",
        Some("archive") => " \\Archive",
        _ => "",
    }
}

fn parse_date(text: &str) -> Option<i64> {
    time::Date::parse(text.trim_matches('"'), DATE).ok().map(|d| d.midnight().assume_utc().unix_timestamp())
}

/// One term of a SEARCH program.
enum Key {
    All,
    Flag(&'static str, bool),
    Keyword(String, bool),
    Header(String, String),
    Text(String, bool),
    Larger(i64),
    Smaller(i64),
    Internal(i64, i64),
    Sent(i64, i64),
    Uid(SequenceSet),
    Modseq(i64),
    Seq(SequenceSet),
    Not(Box<Key>),
    Or(Box<Key>, Box<Key>),
    And(Vec<Key>),
}

/// FETCH responses collected before they are written to the connection.
const FETCH_BATCH: usize = 64 * 1024;

/// Headers the full-text index holds (decoded); other headers need the message itself.
const INDEXED_HEADERS: [&str; 5] = ["subject", "from", "to", "cc", "bcc"];

impl Key {
    /// Whether matching looks at the message text rather than at the stored columns.
    fn needs_content(&self) -> bool {
        match self {
            Key::Header(..) | Key::Text(..) => true,
            Key::Not(k) => k.needs_content(),
            Key::Or(a, b) => a.needs_content() || b.needs_content(),
            Key::And(keys) => keys.iter().any(Key::needs_content),
            _ => false,
        }
    }

    /// Whether matching needs the raw message: a header the index does not hold.
    fn needs_raw(&self) -> bool {
        match self {
            Key::Header(name, _) => !INDEXED_HEADERS.contains(&name.to_ascii_lowercase().as_str()),
            Key::Not(k) => k.needs_raw(),
            Key::Or(a, b) => a.needs_raw() || b.needs_raw(),
            Key::And(keys) => keys.iter().any(Key::needs_raw),
            _ => false,
        }
    }
}

/// What the full-text index holds about a message, lowercased for matching.
#[derive(Default)]
struct IndexedText {
    subject: String,
    sender: String,
    to: String,
    cc: String,
    bcc: String,
    body: String,
    names: String,
}

fn parse_search(args: &mut std::slice::Iter<'_, Arg>, depth: usize) -> Result<Key, String> {
    const DAY: i64 = 86400;
    let syntax = || "BAD invalid search criteria".to_owned();
    if depth > 10 {
        return Err(syntax());
    }
    let arg = args.next().ok_or_else(syntax)?;
    if let Arg::List(list) = arg {
        let mut inner = list.iter();
        let mut keys = Vec::new();
        while inner.len() > 0 {
            keys.push(parse_search(&mut inner, depth + 1)?);
        }
        return Ok(Key::And(keys));
    }
    let Arg::Atom(atom) = arg else { return Err(syntax()) };
    let text = |args: &mut std::slice::Iter<'_, Arg>| args.next().and_then(Arg::text).map(|s| s.to_lowercase()).ok_or_else(syntax);
    let date = |args: &mut std::slice::Iter<'_, Arg>| args.next().and_then(Arg::text).and_then(|d| parse_date(&d)).ok_or_else(syntax);
    let number = |args: &mut std::slice::Iter<'_, Arg>| args.next().and_then(Arg::text).and_then(|n| n.parse::<i64>().ok()).ok_or_else(syntax);
    Ok(match atom.to_ascii_uppercase().as_str() {
        "ALL" => Key::All,
        "ANSWERED" => Key::Flag("answered", true),
        "UNANSWERED" => Key::Flag("answered", false),
        "DELETED" => Key::Flag("deleted", true),
        "UNDELETED" => Key::Flag("deleted", false),
        "DRAFT" => Key::Flag("draft", true),
        "UNDRAFT" => Key::Flag("draft", false),
        "FLAGGED" => Key::Flag("flagged", true),
        "UNFLAGGED" => Key::Flag("flagged", false),
        "SEEN" => Key::Flag("seen", true),
        "UNSEEN" => Key::Flag("seen", false),
        // \Recent is not tracked: nothing is recent, everything is old.
        "NEW" | "RECENT" => Key::Not(Box::new(Key::All)),
        "OLD" => Key::All,
        "KEYWORD" => Key::Keyword(text(args)?, true),
        "UNKEYWORD" => Key::Keyword(text(args)?, false),
        "FROM" => Key::Header("from".into(), text(args)?),
        "TO" => Key::Header("to".into(), text(args)?),
        "CC" => Key::Header("cc".into(), text(args)?),
        "BCC" => Key::Header("bcc".into(), text(args)?),
        "SUBJECT" => Key::Header("subject".into(), text(args)?),
        "HEADER" => Key::Header(text(args)?, text(args)?),
        "BODY" => Key::Text(text(args)?, false),
        "TEXT" => Key::Text(text(args)?, true),
        "LARGER" => Key::Larger(number(args)?),
        "SMALLER" => Key::Smaller(number(args)?),
        "BEFORE" => Key::Internal(i64::MIN, date(args)?),
        "ON" => date(args).map(|d| Key::Internal(d, d + DAY))?,
        "SINCE" => Key::Internal(date(args)?, i64::MAX),
        "SENTBEFORE" => Key::Sent(i64::MIN, date(args)?),
        "SENTON" => date(args).map(|d| Key::Sent(d, d + DAY))?,
        "SENTSINCE" => Key::Sent(date(args)?, i64::MAX),
        "MODSEQ" => Key::Modseq(number(args)?),
        "UID" => Key::Uid(args.next().and_then(Arg::text).and_then(|s| SequenceSet::parse(&s)).ok_or_else(syntax)?),
        "NOT" => Key::Not(Box::new(parse_search(args, depth + 1)?)),
        "OR" => Key::Or(Box::new(parse_search(args, depth + 1)?), Box::new(parse_search(args, depth + 1)?)),
        other => Key::Seq(SequenceSet::parse(other).ok_or_else(syntax)?),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Arrival,
    Cc,
    Date,
    From,
    Size,
    Subject,
    To,
}

/// The date SORT and THREAD use: the sent date, else the arrival.
fn sort_date(message: &Message) -> i64 {
    if message.sent_date > 0 { message.sent_date } else { message.internal_date }
}

/// The subject without reply and forward markers (RFC 5256 section 2.1, simplified).
fn base_subject(subject: &str) -> String {
    let mut text = subject.trim().to_lowercase();
    loop {
        let before = text.len();
        for prefix in ["re:", "fw:", "fwd:", "aw:", "wg:", "sv:", "odp:", "pd:"] {
            if let Some(rest) = text.strip_prefix(prefix) {
                text = rest.trim_start().to_owned();
            }
        }
        if text.starts_with('[')
            && let Some(end) = text.find(']')
            && end + 1 < text.len()
        {
            text = text[end + 1..].trim_start().to_owned();
        }
        if let Some(rest) = text.strip_suffix("(fwd)") {
            text = rest.trim_end().to_owned();
        }
        if text.len() == before {
            return text.split_whitespace().collect::<Vec<_>>().join(" ");
        }
    }
}

/// The local part of an address, for sorting by sender or recipient.
fn mailbox_part(address: &str) -> String {
    let address = address.trim();
    let address = address.rsplit_once('<').map_or(address, |(_, a)| a.trim_end_matches('>'));
    address.split('@').next().unwrap_or("").to_lowercase()
}

fn first_cc(head: &[u8]) -> String {
    MessageParser::default()
        .parse_headers(head)
        .and_then(|m| m.cc().and_then(|cc| cc.first()).and_then(|a| a.address().map(str::to_owned)))
        .unwrap_or_default()
}

/// Numbers as a compact sequence set: `1:3,5`.
fn sequence_set(numbers: &[u32]) -> String {
    let mut sorted = numbers.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut parts: Vec<String> = Vec::new();
    let mut iter = sorted.into_iter().peekable();
    while let Some(start) = iter.next() {
        let mut end = start;
        while iter.peek() == Some(&(end + 1)) {
            end = iter.next().unwrap_or(end);
        }
        parts.push(if start == end { start.to_string() } else { format!("{start}:{end}") });
    }
    parts.join(",")
}

struct SearchContext<'a> {
    seq: u32,
    max_seq: u32,
    max_uid: u32,
    message: &'a Message,
    raw: Option<&'a [u8]>,
    /// The indexed text; when present it answers text and address criteria.
    text: Option<&'a IndexedText>,
}

fn matches(key: &Key, ctx: &SearchContext<'_>) -> bool {
    let m = ctx.message;
    match key {
        Key::All => true,
        Key::Flag(name, wanted) => {
            let value = match *name {
                "answered" => m.answered,
                "deleted" => m.deleted,
                "draft" => m.draft,
                "flagged" => m.flagged,
                _ => m.seen,
            };
            value == *wanted
        }
        Key::Keyword(keyword, wanted) => serde_json::from_str::<Vec<String>>(&m.keywords).unwrap_or_default().contains(keyword) == *wanted,
        Key::Larger(n) => m.size > *n,
        Key::Smaller(n) => m.size < *n,
        Key::Internal(from, to) => m.internal_date >= *from && m.internal_date < *to,
        Key::Sent(from, to) => m.sent_date >= *from && m.sent_date < *to,
        Key::Uid(set) => set.contains(m.uid as u32, ctx.max_uid),
        Key::Modseq(value) => m.modseq >= *value,
        Key::Seq(set) => set.contains(ctx.seq, ctx.max_seq),
        Key::Not(inner) => !matches(inner, ctx),
        Key::Or(a, b) => matches(a, ctx) || matches(b, ctx),
        Key::And(keys) => keys.iter().all(|k| matches(k, ctx)),
        Key::Header(name, needle) if ctx.text.is_some() && INDEXED_HEADERS.contains(&name.to_ascii_lowercase().as_str()) => {
            let text = ctx.text.unwrap_or_else(|| unreachable!("checked above"));
            let field = match name.to_ascii_lowercase().as_str() {
                "subject" => &text.subject,
                "from" => &text.sender,
                "to" => &text.to,
                "cc" => &text.cc,
                _ => &text.bcc,
            };
            if needle.is_empty() { !field.trim().is_empty() || name.eq_ignore_ascii_case("subject") } else { field.contains(needle.as_str()) }
        }
        Key::Text(needle, include_headers) if ctx.text.is_some() => {
            let text = ctx.text.unwrap_or_else(|| unreachable!("checked above"));
            let needle = needle.as_str();
            text.body.contains(needle)
                || text.names.contains(needle)
                || (*include_headers && [&text.subject, &text.sender, &text.to, &text.cc, &text.bcc].iter().any(|field| field.contains(needle)))
        }
        Key::Header(name, needle) => {
            let Some(raw) = ctx.raw else { return false };
            let headers = &raw[..crate::security::authn::find_header_end(raw)];
            let mut current = false;
            String::from_utf8_lossy(headers).lines().any(|line| {
                if !line.starts_with([' ', '\t']) {
                    current = line.split_once(':').is_some_and(|(n, _)| n.eq_ignore_ascii_case(name));
                }
                current && (needle.is_empty() || line.to_lowercase().contains(needle))
            })
        }
        Key::Text(needle, include_headers) => {
            let Some(raw) = ctx.raw else { return false };
            let start = if *include_headers { 0 } else { crate::security::authn::find_header_end(raw) };
            String::from_utf8_lossy(&raw[start..]).to_lowercase().contains(needle)
        }
    }
}

impl Session {
    async fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.conn.write_all(data).await
    }

    async fn line(&mut self, text: &str) -> std::io::Result<()> {
        self.send(format!("{text}\r\n").as_bytes()).await
    }

    /// Reads one complete command, including any literals, and tokenizes it.
    async fn read_command(&mut self) -> Result<Option<Vec<Arg>>, ReadError> {
        let mut tokenizer = Tokenizer::default();
        let mut first = true;
        let mut append = false;
        loop {
            let line = self.conn.read_line(MAX_LINE).await?;
            if first {
                // Only APPEND may carry a message-sized literal.
                append = line.splitn(3, |b| *b == b' ').nth(1).is_some_and(|c| c.eq_ignore_ascii_case(b"APPEND"));
                first = false;
            }
            match tokenizer.feed(&line) {
                Ok(None) => return Ok(tokenizer.finish().ok()),
                Ok(Some(literal)) => {
                    let limit = if append { self.app.rt().max_message_size } else { MAX_SMALL_LITERAL };
                    if literal.len > limit || (self.account.is_none() && literal.len > 1024) {
                        // The announced data would otherwise be parsed as commands.
                        self.line("* BYE literal too large").await?;
                        return Err(ReadError::Closed);
                    }
                    if literal.sync {
                        self.line("+ Ready for literal data").await?;
                    }
                    tokenizer.feed_literal(self.conn.read_exact(literal.len).await?);
                }
                Err(_) => return Ok(None),
            }
        }
    }

    async fn run(mut self) -> std::io::Result<()> {
        // On the STARTTLS port nothing but the upgrade is offered until the channel is encrypted.
        self.oauth = crate::oauth::active(&self.app).await.is_some();
        let capabilities = if self.conn.is_tls() { self.capabilities() } else { PLAINTEXT_CAPABILITIES.to_owned() };
        self.line(&format!("* OK [CAPABILITY {capabilities}] {} IMAP4rev1 ready", self.app.cfg.hostname)).await?;
        loop {
            if self.errors >= MAX_ERRORS {
                return self.line("* BYE too many errors").await;
            }
            self.conn.timeout = if self.account.is_some() { SESSION_TIMEOUT } else { LOGIN_TIMEOUT };
            let args = match self.read_command().await {
                Ok(Some(args)) => args,
                Ok(None) => {
                    self.errors += 1;
                    self.line("* BAD invalid command syntax").await?;
                    continue;
                }
                Err(ReadError::TooLong) => return self.line("* BYE line too long").await,
                Err(ReadError::Timeout) => return self.line("* BYE idle timeout").await,
                Err(_) => return Ok(()),
            };
            let (Some(tag), Some(command)) = (args.first().and_then(Arg::atom_upper).filter(|t| t.len() <= 64 && !t.contains(['*', '+'])), args.get(1).and_then(Arg::atom_upper)) else {
                self.errors += 1;
                self.line("* BAD missing tag or command").await?;
                continue;
            };
            // Tags are echoed verbatim; keep the original spelling.
            let tag = match &args[0] {
                Arg::Atom(t) => t.clone(),
                _ => tag,
            };
            if !self.conn.is_tls() {
                match command.as_str() {
                    "STARTTLS" => {
                        // Commands pipelined behind STARTTLS would otherwise be executed inside
                        // the TLS session although they were sent in the clear.
                        if self.conn.has_buffered() {
                            self.line(&format!("{tag} BAD pipelining after STARTTLS is not allowed")).await?;
                            return Ok(());
                        }
                        self.line(&format!("{tag} OK begin TLS negotiation now")).await?;
                        let config = self.app.tls.server_config(&[]);
                        if let Err(err) = self.conn.start_tls(config).await {
                            tracing::debug!(%err, peer = %self.peer, "STARTTLS handshake failed");
                            return Ok(());
                        }
                    }
                    "CAPABILITY" => {
                        self.line(&format!("* CAPABILITY {PLAINTEXT_CAPABILITIES}")).await?;
                        self.line(&format!("{tag} OK CAPABILITY completed")).await?;
                    }
                    "NOOP" => self.line(&format!("{tag} OK NOOP completed")).await?,
                    "LOGOUT" => {
                        self.line("* BYE logging out").await?;
                        self.line(&format!("{tag} OK LOGOUT completed")).await?;
                        return Ok(());
                    }
                    // Credentials are never accepted over an unencrypted connection.
                    _ => {
                        self.errors += 1;
                        self.line(&format!("{tag} BAD [PRIVACYREQUIRED] issue STARTTLS first")).await?;
                    }
                }
                continue;
            }
            if !self.still_signed_in().await {
                return self.line("* BYE the sign-in is no longer valid").await;
            }
            Metrics::inc(&self.app.metrics.imap_commands);
            let span = tracing::info_span!("imap.command", imap.command = %command);
            let (result, flow) = tracing::Instrument::instrument(self.execute(&tag, &command, &args[2..]), span).await?;
            // Untagged updates may not be sent while a FETCH/STORE/SEARCH by sequence number is
            // in progress, because they renumber messages.
            if matches!(flow, Flow::Silent) {
                continue;
            }
            if !matches!(command.as_str(), "FETCH" | "STORE" | "SEARCH" | "SORT" | "THREAD") {
                self.sync().await?;
            }
            match result {
                Ok(text) => self.line(&format!("{tag} OK {text}")).await?,
                Err(text) => {
                    self.errors += 1;
                    self.line(&format!("{tag} {text}")).await?;
                }
            }
            if matches!(flow, Flow::Close) {
                self.conn.shutdown().await;
                return Ok(());
            }
        }
    }

    async fn execute(&mut self, tag: &str, command: &str, args: &[Arg]) -> std::io::Result<(CmdResult, Flow)> {
        let result = match command {
            "CAPABILITY" => {
                let capabilities = self.capabilities();
                self.line(&format!("* CAPABILITY {capabilities}")).await?;
                Ok("CAPABILITY completed".into())
            }
            "NOOP" | "CHECK" => Ok(format!("{command} completed")),
            "ID" => {
                self.line("* ID (\"name\" \"unoMail\")").await?;
                Ok("ID completed".into())
            }
            "LOGOUT" => {
                self.line("* BYE logging out").await?;
                return Ok((Ok("LOGOUT completed".into()), Flow::Close));
            }
            "LOGIN" | "AUTHENTICATE" if self.account.is_some() => bad("already authenticated"),
            "LOGIN" => match (args.first().and_then(Arg::text), args.get(1).and_then(Arg::text)) {
                (Some(user), Some(password)) => return self.login(&user, &password).await,
                _ => bad("usage: LOGIN user password"),
            },
            "AUTHENTICATE" => return self.authenticate(args).await,
            _ if self.account.is_none() => bad("authenticate first"),
            "NAMESPACE" => {
                // Personal mailboxes, then the mailboxes other users shared with this account.
                self.line("* NAMESPACE ((\"\" \"/\")) ((\"Shared/\" \"/\")) NIL").await?;
                Ok("NAMESPACE completed".into())
            }
            "MYRIGHTS" | "GETACL" | "SETACL" | "DELETEACL" | "LISTRIGHTS" => self.cmd_acl(args, command).await?,
            "ENABLE" => {
                let mut enabled = Vec::new();
                for extension in args.iter().filter_map(Arg::atom_upper) {
                    match extension.as_str() {
                        "CONDSTORE" => self.condstore = true,
                        "IMAP4REV2" => self.rev2 = true,
                        "QRESYNC" => {
                            self.condstore = true;
                            self.qresync = true;
                        }
                        _ => continue,
                    }
                    enabled.push(if extension == "IMAP4REV2" { "IMAP4rev2".to_owned() } else { extension });
                }
                self.line(format!("* ENABLED {}", enabled.join(" ")).trim_end()).await?;
                Ok("ENABLE completed".into())
            }
            "SELECT" | "EXAMINE" => self.cmd_select(args, command == "EXAMINE").await?,
            "CREATE" => self.cmd_mailbox(args, command).await,
            "DELETE" | "RENAME" | "SUBSCRIBE" | "UNSUBSCRIBE" => self.cmd_mailbox(args, command).await,
            "LIST" | "LSUB" => self.cmd_list(args, command == "LSUB").await?,
            "GETQUOTAROOT" | "GETQUOTA" => self.cmd_quota(args, command == "GETQUOTAROOT").await?,
            "SETQUOTA" => no("[NOPERM] quotas are set by the administrator"),
            "COMPRESS" => {
                if self.conn.is_compressed() {
                    no("[COMPRESSIONACTIVE] compression is already on")
                } else if args.first().and_then(Arg::atom_upper).as_deref() != Some("DEFLATE") {
                    bad("only DEFLATE is supported")
                } else {
                    // The tagged reply is the last uncompressed data.
                    self.line(&format!("{tag} OK DEFLATE active")).await?;
                    self.conn.start_deflate()?;
                    return Ok((Ok(String::new()), Flow::Silent));
                }
            }
            "STATUS" => self.cmd_status(args).await?,
            "APPEND" => self.cmd_append(args).await,
            "IDLE" => return Ok((self.cmd_idle().await?, Flow::Continue)),
            _ if self.selected.is_none() => bad("no mailbox selected or unknown command"),
            "CLOSE" => {
                // CLOSE expunges silently (unless read-only); UNSELECT does not.
                if self.selected.as_ref().is_some_and(|s| !s.read_only) {
                    let _ = self.expunge(None, true).await;
                }
                self.selected = None;
                Ok("CLOSE completed".into())
            }
            "UNSELECT" => {
                self.selected = None;
                Ok("UNSELECT completed".into())
            }
            "EXPUNGE" => self.expunge(None, false).await,
            "FETCH" => self.cmd_fetch(args, false).await?,
            "STORE" => self.cmd_store(args, false).await?,
            "SEARCH" => self.cmd_search(tag, args, false).await?,
            "SORT" => self.cmd_sort(args, false).await?,
            "THREAD" => self.cmd_thread(args, false).await?,
            "COPY" => self.cmd_copy(args, false, false).await,
            "MOVE" => self.cmd_copy(args, false, true).await,
            "UID" => {
                let rest = args.get(1..).unwrap_or(&[]);
                match args.first().and_then(Arg::atom_upper).as_deref() {
                    Some("FETCH") => self.cmd_fetch(rest, true).await?,
                    Some("STORE") => self.cmd_store(rest, true).await?,
                    Some("SEARCH") => self.cmd_search(tag, rest, true).await?,
                    Some("SORT") => self.cmd_sort(rest, true).await?,
                    Some("THREAD") => self.cmd_thread(rest, true).await?,
                    Some("COPY") => self.cmd_copy(rest, true, false).await,
                    Some("MOVE") => self.cmd_copy(rest, true, true).await,
                    Some("EXPUNGE") => match rest.first().and_then(Arg::text).and_then(|s| SequenceSet::parse(&s)) {
                        Some(set) => self.expunge(Some(set), false).await,
                        None => bad("usage: UID EXPUNGE set"),
                    },
                    _ => bad("unknown UID command"),
                }
            }
            _ => bad("unknown command"),
        };
        Ok((result, Flow::Continue))
    }

    async fn login(&mut self, user: &str, password: &str) -> std::io::Result<(CmdResult, Flow)> {
        let result = auth::authenticate_with(&self.app.db, &self.app.limiter, user, password, self.peer.ip(), Protocol::Imap).await;
        self.finish_login(result.map(|(account, credential)| (account, Some(credential)))).await
    }

    async fn finish_login(&mut self, result: Result<(Account, Option<auth::Credential>), AuthError>) -> std::io::Result<(CmdResult, Flow)> {
        match result {
            Ok((account, credential)) => {
                self.grant = Some(auth::Grant::new(&account, Protocol::Imap, credential));
                self.account = Some(account);
                let capabilities = self.capabilities();
                Ok((Ok(format!("[CAPABILITY {capabilities}] authenticated")), Flow::Continue))
            }
            Err(AuthError::RateLimited) => {
                self.line("* BYE too many failed attempts, try again later").await?;
                Ok((no("[AUTHENTICATIONFAILED] temporarily blocked"), Flow::Close))
            }
            Err(_) => {
                Metrics::inc(&self.app.metrics.auth_failures);
                self.login_failures += 1;
                let flow = if self.login_failures >= MAX_LOGIN_FAILURES { Flow::Close } else { Flow::Continue };
                Ok((no("[AUTHENTICATIONFAILED] invalid credentials"), flow))
            }
        }
    }

    async fn authenticate(&mut self, args: &[Arg]) -> std::io::Result<(CmdResult, Flow)> {
        let mechanism = args.first().and_then(Arg::atom_upper).unwrap_or_default();
        if !matches!(mechanism.as_str(), "PLAIN" | "XOAUTH2" | "OAUTHBEARER") {
            return Ok((no("unsupported authentication mechanism"), Flow::Continue));
        }
        let response = match args.get(1).and_then(Arg::text) {
            Some(initial) => initial,
            None => {
                self.line("+ ").await?;
                match self.conn.read_line(MAX_LINE).await {
                    Ok(line) => String::from_utf8_lossy(&line).into_owned(),
                    Err(_) => return Ok((bad("authentication aborted"), Flow::Close)),
                }
            }
        };
        if response == "*" {
            return Ok((bad("authentication cancelled"), Flow::Continue));
        }
        if mechanism != "PLAIN" {
            // Token login through the configured identity provider.
            let Some((user, token)) = STANDARD.decode(response.trim()).ok().and_then(|bytes| crate::oauth::parse_sasl(&mechanism, &bytes)) else {
                return Ok((bad("malformed authentication data"), Flow::Continue));
            };
            let result = crate::oauth::authenticate_token(&self.app, &user, &token, self.peer.ip(), Protocol::Imap).await;
            let outcome = self.finish_login(result.map(|account| (account, None))).await;
            self.grant = self.grant.take().map(|grant| grant.with_token(token));
            return outcome;
        }
        let credentials = STANDARD.decode(response.trim()).ok().and_then(|bytes| {
            let mut parts = bytes.split(|b| *b == 0);
            let (_authz, user, pass) = (parts.next()?, parts.next()?, parts.next()?);
            Some((String::from_utf8(user.to_vec()).ok()?, String::from_utf8(pass.to_vec()).ok()?))
        });
        match credentials {
            Some((user, password)) => self.login(&user, &password).await,
            None => Ok((bad("malformed authentication data"), Flow::Continue)),
        }
    }

    /// Capabilities after TLS; token logins are offered only while single sign-on is set up.
    fn capabilities(&self) -> String {
        if self.oauth { CAPABILITIES.replace("AUTH=PLAIN", "AUTH=PLAIN AUTH=XOAUTH2 AUTH=OAUTHBEARER") } else { CAPABILITIES.to_owned() }
    }

    /// False once the account was disabled or the credential it signed in with revoked.
    async fn still_signed_in(&mut self) -> bool {
        match (&self.account, &mut self.grant) {
            (Some(_), Some(grant)) => grant.recheck(&self.app).await,
            _ => true,
        }
    }

    /// A mailbox name as the client sent it: modified UTF-7, or UTF-8 under IMAP4rev2.
    fn decode_name(&self, name: &str) -> String {
        if self.rev2 { name.to_owned() } else { utf7_decode(name) }
    }

    /// A mailbox name as the client expects it.
    fn encode_name(&self, name: &str) -> String {
        if self.rev2 { name.to_owned() } else { utf7_encode(name) }
    }

    fn account_id(&self) -> i64 {
        self.account.as_ref().map_or(0, |a| a.id)
    }

    /// Owner of the selected mailbox: the logged-in account, or whoever shared the mailbox.
    fn owner(&self) -> i64 {
        self.selected.as_ref().map_or(self.account_id(), |s| s.mailbox.account_id)
    }

    /// Whether the account holds `right` on the selected mailbox.
    fn may(&self, right: char) -> bool {
        self.selected.as_ref().is_some_and(|s| s.rights.contains(right))
    }

    /// Resolves a mailbox name to one of the account's own mailboxes or, in the `Shared/`
    /// namespace, to a mailbox another user shared with it, together with the rights held.
    async fn find_mailbox_rights(&self, name: Option<String>) -> Result<(Mailbox, String), String> {
        let name = self.decode_name(&name.ok_or("BAD mailbox name required")?);
        let Some(account) = &self.account else { return Err("BAD authenticate first".into()) };
        if name.starts_with(crate::sharing::SHARED_PREFIX) {
            return match crate::sharing::shared_by_name(&self.app.db, account, &name).await {
                Ok(Some(shared)) => Ok((shared.mailbox, shared.rights)),
                Ok(None) => Err("NO no such mailbox".into()),
                Err(err) => Err(internal(err)),
            };
        }
        match self.app.store.mailbox_by_name(account.id, &name).await {
            Ok(Some(mailbox)) => Ok((mailbox, crate::sharing::ALL_RIGHTS.to_owned())),
            Ok(None) => Err("NO [TRYCREATE] no such mailbox".into()),
            Err(err) => Err(internal(err)),
        }
    }

    /// Like `find_mailbox_rights`, additionally requiring every right in `needed`.
    async fn find_mailbox(&self, name: Option<String>, needed: &str) -> Result<Mailbox, String> {
        let (mailbox, rights) = self.find_mailbox_rights(name).await?;
        if needed.chars().all(|right| rights.contains(right)) { Ok(mailbox) } else { Err("NO [NOPERM] you do not have the necessary rights on this mailbox".into()) }
    }

    /// Access control lists (RFC 4314).
    async fn cmd_acl(&mut self, args: &[Arg], command: &str) -> std::io::Result<CmdResult> {
        let (mailbox, rights) = match self.find_mailbox_rights(args.first().and_then(Arg::text)).await {
            Ok(found) => found,
            Err(err) => return Ok(Err(err)),
        };
        let display = match (&self.account, mailbox.account_id == self.account_id()) {
            (_, true) => mailbox.name.clone(),
            _ => args.first().and_then(Arg::text).map(|n| self.decode_name(&n)).unwrap_or_default(),
        };
        let display = self.encode_name(&display);
        let mut out = Vec::new();
        let begin = |out: &mut Vec<u8>, keyword: &str| {
            out.extend_from_slice(format!("* {keyword} ").as_bytes());
            string(out, display.as_bytes());
        };
        if command == "MYRIGHTS" {
            begin(&mut out, "MYRIGHTS");
            out.extend_from_slice(format!(" {rights}\r\n").as_bytes());
            self.send(&out).await?;
            return Ok(Ok("MYRIGHTS completed".into()));
        }
        // Everything else administers the list and needs the `a` right.
        if !rights.contains('a') {
            return Ok(no("[NOPERM] you may not administer this mailbox"));
        }
        let identifier = args.get(1).and_then(Arg::text);
        let acl_error = |err: crate::sharing::AclError| match err {
            crate::sharing::AclError::Db(err) => internal(err),
            other => format!("NO {other}"),
        };
        match command {
            "GETACL" => {
                let entries = match crate::sharing::list(&self.app.db, &mailbox).await {
                    Ok(entries) => entries,
                    Err(err) => return Ok(Err(internal(err))),
                };
                begin(&mut out, "ACL");
                for (identifier, rights) in entries {
                    out.push(b' ');
                    string(&mut out, identifier.as_bytes());
                    out.extend_from_slice(format!(" {rights}").as_bytes());
                }
                out.extend_from_slice(b"\r\n");
                self.send(&out).await?;
            }
            "LISTRIGHTS" => {
                let Some(identifier) = identifier else { return Ok(bad("usage: LISTRIGHTS mailbox identifier")) };
                begin(&mut out, "LISTRIGHTS");
                out.push(b' ');
                string(&mut out, identifier.as_bytes());
                // No right is implied; each can be granted on its own.
                out.extend_from_slice(b" \"\" l r s w i p k x t e a\r\n");
                self.send(&out).await?;
            }
            "SETACL" => {
                let (Some(identifier), Some(change)) = (identifier, args.get(2).and_then(Arg::text)) else { return Ok(bad("usage: SETACL mailbox identifier rights")) };
                if let Err(err) = crate::sharing::set(&self.app.db, &mailbox, &identifier, &change).await {
                    return Ok(Err(acl_error(err)));
                }
            }
            _ => {
                let Some(identifier) = identifier else { return Ok(bad("usage: DELETEACL mailbox identifier")) };
                if let Err(err) = crate::sharing::remove(&self.app.db, &mailbox, &identifier).await {
                    return Ok(Err(acl_error(err)));
                }
            }
        }
        Ok(Ok(format!("{command} completed")))
    }

    async fn cmd_select(&mut self, args: &[Arg], read_only: bool) -> std::io::Result<CmdResult> {
        // RFC 9051 6.3.2 / RFC 7162 3.2.11: the end of the previous mailbox's responses is marked.
        if self.selected.take().is_some() && (self.rev2 || self.qresync) {
            self.line("* OK [CLOSED] previous mailbox is now closed").await?;
        }
        let (mailbox, rights) = match self.find_mailbox_rights(args.first().and_then(Arg::text)).await {
            Ok(found) => found,
            Err(err) => return Ok(Err(err)),
        };
        if !rights.contains('r') {
            return Ok(no("[NOPERM] you may not read this mailbox"));
        }
        let messages = match self.app.store.messages_in(mailbox.id).await {
            Ok(messages) => messages,
            Err(err) => return Ok(Err(internal(err))),
        };
        let recent = if self.rev2 { "" } else { "* 0 RECENT\r\n" };
        let mut out = format!(
            "* {} EXISTS\r\n{recent}* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n\
             * OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] flags\r\n\
             * OK [UIDVALIDITY {}] valid\r\n* OK [UIDNEXT {}] next\r\n* OK [HIGHESTMODSEQ {}] modseq\r\n",
            messages.len(),
            mailbox.uid_validity,
            mailbox.uid_next,
            mailbox.highest_modseq
        );
        if self.rev2 {
            // IMAP4rev2 names the mailbox in its canonical form instead of reporting UNSEEN.
            let mut list = format!("* LIST ({}) \"/\" ", special_use(mailbox.role.as_deref()).trim_start()).into_bytes();
            string(&mut list, self.encode_name(&mailbox.name).as_bytes());
            out.push_str(&String::from_utf8_lossy(&list));
            out.push_str("\r\n");
        } else if let Some(first) = messages.iter().position(|m| !m.seen) {
            out.push_str(&format!("* OK [UNSEEN {}] first unseen\r\n", first + 1));
        }
        // Select parameters: (CONDSTORE) and (QRESYNC (uidvalidity modseq [known-uids])).
        if let Some(Arg::List(params)) = args.get(1) {
            let mut params = params.iter();
            while let Some(param) = params.next() {
                match param.atom_upper().as_deref() {
                    Some("CONDSTORE") => self.condstore = true,
                    Some("QRESYNC") if self.qresync => {
                        let Some(Arg::List(values)) = params.next() else { return Ok(bad("invalid QRESYNC parameters")) };
                        let number = |i: usize| values.get(i).and_then(Arg::text).and_then(|v| v.parse::<i64>().ok());
                        let (Some(validity), Some(modseq)) = (number(0), number(1)) else { return Ok(bad("invalid QRESYNC parameters")) };
                        let known = values.get(2).and_then(Arg::text).and_then(|v| SequenceSet::parse(&v));
                        // Cached state is only usable while the UID validity is unchanged.
                        if validity == mailbox.uid_validity {
                            let max_uid = (mailbox.uid_next - 1).max(0) as u32;
                            let in_known = |uid: i64| known.as_ref().is_none_or(|set| set.contains(uid as u32, max_uid));
                            let vanished: Vec<i64> = match self.app.store.expunged_since(mailbox.id, modseq).await {
                                Ok(uids) => uids.into_iter().filter(|u| in_known(*u)).collect(),
                                Err(err) => return Ok(Err(internal(err))),
                            };
                            if !vanished.is_empty() {
                                out.push_str(&format!("* VANISHED (EARLIER) {}\r\n", uid_set(&vanished)));
                            }
                            for (index, message) in messages.iter().enumerate().filter(|(_, m)| m.modseq > modseq && in_known(m.uid)) {
                                out.push_str(&format!("* {} FETCH (UID {} FLAGS ({}) MODSEQ ({}))\r\n", index + 1, message.uid, flags_text(message), message.modseq));
                            }
                        }
                    }
                    Some("QRESYNC") => return Ok(bad("QRESYNC must be enabled first")),
                    _ => return Ok(bad("unknown select parameter")),
                }
            }
        }
        self.send(out.as_bytes()).await?;
        // The mailbox row was read before its messages, so the snapshot holds at least this state.
        let synced_modseq = mailbox.highest_modseq;
        self.selected = Some(Selected { mailbox, rights, read_only, messages, synced_modseq });
        Ok(Ok(format!("[{}] {} completed", if read_only { "READ-ONLY" } else { "READ-WRITE" }, if read_only { "EXAMINE" } else { "SELECT" })))
    }

    async fn cmd_mailbox(&mut self, args: &[Arg], command: &str) -> CmdResult {
        let store = self.app.store.clone();
        let account = self.account_id();
        let map = |err: StoreError| match err {
            StoreError::Exists => "NO mailbox already exists".to_owned(),
            StoreError::NotFound => "NO no such mailbox".to_owned(),
            StoreError::Invalid(msg) => format!("NO {msg}"),
            other => internal(other),
        };
        let name = args.first().and_then(Arg::text).map(|n| n.trim_end_matches('/').to_owned());
        if command == "CREATE" {
            let name = self.decode_name(&name.ok_or("BAD mailbox name required")?);
            store.create_mailbox(account, &name).await.map_err(map)?;
            return Ok("CREATE completed".into());
        }
        let mailbox = self.find_mailbox(name, "").await?;
        if mailbox.account_id != account {
            // Subscriptions aside, shared mailboxes are managed by their owner.
            return if matches!(command, "SUBSCRIBE" | "UNSUBSCRIBE") { Ok(format!("{command} completed")) } else { no("[NOPERM] shared mailboxes are managed by their owner") };
        }
        match command {
            "DELETE" => {
                if self.selected.as_ref().is_some_and(|s| s.mailbox.id == mailbox.id) {
                    self.selected = None;
                }
                store.delete_mailbox(account, mailbox.id).await.map_err(map)?;
            }
            "RENAME" => {
                let new_name = args.get(1).and_then(Arg::text).ok_or("BAD new name required")?;
                store.rename_mailbox(account, mailbox.id, self.decode_name(&new_name).trim_end_matches('/')).await.map_err(map)?;
            }
            _ => {
                sqlx::query("UPDATE mailboxes SET subscribed = ? WHERE id = ? AND account_id = ?")
                    .bind(command == "SUBSCRIBE")
                    .bind(mailbox.id)
                    .bind(account)
                    .execute(&store.db)
                    .await
                    .map_err(internal)?;
            }
        }
        Ok(format!("{command} completed"))
    }

    async fn cmd_list(&mut self, args: &[Arg], lsub: bool) -> std::io::Result<CmdResult> {
        // LIST-EXTENDED form (RFC 5258): LIST (selection options) reference pattern RETURN (options).
        let mut args = args;
        let mut subscribed_only = lsub;
        // Under LIST-EXTENDED the subscription state is reported as \Subscribed.
        let mut show_subscribed = false;
        if let Some(Arg::List(selection)) = args.first() {
            for option in selection.iter().filter_map(Arg::atom_upper) {
                match option.as_str() {
                    "SUBSCRIBED" => {
                        subscribed_only = true;
                        show_subscribed = true;
                    }
                    "RECURSIVEMATCH" | "SPECIAL-USE" | "REMOTE" => {}
                    _ => return Ok(bad("unknown LIST selection option")),
                }
            }
            args = &args[1..];
        }
        let mut status_items: Vec<Arg> = Vec::new();
        if args.get(2).and_then(Arg::atom_upper).as_deref() == Some("RETURN")
            && let Some(Arg::List(options)) = args.get(3)
        {
            let mut options = options.iter();
            while let Some(option) = options.next() {
                match option.atom_upper().as_deref() {
                    Some("STATUS") => match options.next() {
                        Some(Arg::List(items)) => status_items = items.clone(),
                        _ => return Ok(bad("usage: RETURN (STATUS (items))")),
                    },
                    Some("SUBSCRIBED") => show_subscribed = true,
                    // Children and special use are always reported.
                    Some("CHILDREN" | "SPECIAL-USE") => {}
                    _ => return Ok(bad("unknown LIST return option")),
                }
            }
        }
        let (Some(reference), Some(pattern)) = (args.first().and_then(Arg::text), args.get(1).and_then(Arg::text)) else {
            return Ok(bad("usage: LIST reference pattern"));
        };
        let name = if lsub { "LSUB" } else { "LIST" };
        if pattern.is_empty() {
            self.line(&format!("* {name} (\\Noselect) \"/\" \"\"")).await?;
            return Ok(Ok(format!("{name} completed")));
        }
        let pattern = self.decode_name(&format!("{reference}{pattern}"));
        let mailboxes = match self.app.store.list_mailboxes(self.account_id()).await {
            Ok(mailboxes) => mailboxes,
            Err(err) => return Ok(Err(internal(err))),
        };
        let mut out = Vec::new();
        for mailbox in mailboxes.iter().filter(|m| !subscribed_only || m.subscribed) {
            let matched = list_match(&pattern, &mailbox.name) || (mailbox.name == "INBOX" && pattern.eq_ignore_ascii_case("inbox"));
            if !matched {
                continue;
            }
            let prefix = format!("{}/", mailbox.name);
            let children = if mailboxes.iter().any(|m| m.name.starts_with(&prefix)) { "\\HasChildren" } else { "\\HasNoChildren" };
            let subscribed = if show_subscribed && mailbox.subscribed { " \\Subscribed" } else { "" };
            out.extend_from_slice(format!("* {name} ({children}{}{subscribed}) \"/\" ", special_use(mailbox.role.as_deref())).as_bytes());
            string(&mut out, self.encode_name(&mailbox.name).as_bytes());
            out.extend_from_slice(b"\r\n");
            // LIST-STATUS: the counters right after each mailbox.
            if !status_items.is_empty() {
                match self.status_line(mailbox, &status_items).await {
                    Ok(line) => out.extend_from_slice(&line),
                    Err(err) => return Ok(Err(err)),
                }
            }
        }
        // Mailboxes other users shared with this account, in their own namespace.
        if let Some(account) = &self.account {
            let shared = match crate::sharing::shared_with(&self.app.db, account).await {
                Ok(shared) => shared,
                Err(err) => return Ok(Err(internal(err))),
            };
            for entry in shared {
                let display = entry.display_name();
                if list_match(&pattern, &display) {
                    out.extend_from_slice(format!("* {name} (\\HasNoChildren) \"/\" ").as_bytes());
                    string(&mut out, self.encode_name(&display).as_bytes());
                    out.extend_from_slice(b"\r\n");
                }
            }
        }
        self.send(&out).await?;
        Ok(Ok(format!("{name} completed")))
    }

    async fn cmd_status(&mut self, args: &[Arg]) -> std::io::Result<CmdResult> {
        let mailbox = match self.find_mailbox(args.first().and_then(Arg::text), "r").await {
            Ok(mailbox) => mailbox,
            Err(err) => return Ok(Err(err)),
        };
        let Some(Arg::List(items)) = args.get(1) else { return Ok(bad("usage: STATUS mailbox (items)")) };
        match self.status_line(&mailbox, items).await {
            Ok(line) => self.send(&line).await?,
            Err(err) => return Ok(Err(err)),
        }
        Ok(Ok("STATUS completed".into()))
    }

    /// One `* STATUS` response.
    async fn status_line(&mut self, mailbox: &Mailbox, items: &[Arg]) -> Result<Vec<u8>, String> {
        let counts = self.app.store.mailbox_counts(mailbox.id).await.map_err(internal)?;
        // SIZE and DELETED (RFC 9051, RFC 8438) are only counted when asked for.
        let extra = if items.iter().any(|i| matches!(i.atom_upper().as_deref(), Some("SIZE" | "DELETED"))) {
            let row: (i64, i64) = sqlx::query_as("SELECT COALESCE(SUM(size), 0), COALESCE(SUM(deleted), 0) FROM messages WHERE mailbox_id = ?").bind(mailbox.id).fetch_one(&self.app.db).await.map_err(internal)?;
            row
        } else {
            (0, 0)
        };
        let mut parts = Vec::new();
        for item in items {
            let value = match item.atom_upper().as_deref() {
                Some("MESSAGES") => counts.total,
                Some("RECENT") => 0,
                Some("UIDNEXT") => mailbox.uid_next,
                Some("UIDVALIDITY") => mailbox.uid_validity,
                Some("UNSEEN") => counts.unread,
                Some("SIZE") => extra.0,
                Some("DELETED") => extra.1,
                Some("HIGHESTMODSEQ") => {
                    self.condstore = true;
                    mailbox.highest_modseq
                }
                _ => return Err("BAD unknown STATUS item".into()),
            };
            parts.push(format!("{} {value}", item.atom_upper().unwrap_or_default()));
        }
        let mut out = b"* STATUS ".to_vec();
        string(&mut out, self.encode_name(&mailbox.name).as_bytes());
        out.extend_from_slice(format!(" ({})\r\n", parts.join(" ")).as_bytes());
        Ok(out)
    }

    /// QUOTA (RFC 9208): one storage quota per account, rooted at "".
    async fn cmd_quota(&mut self, args: &[Arg], by_mailbox: bool) -> std::io::Result<CmdResult> {
        let Some(name) = args.first().and_then(Arg::text) else { return Ok(bad("mailbox or quota root required")) };
        let account_id = if by_mailbox {
            match self.find_mailbox(Some(name.clone()), "r").await {
                Ok(mailbox) => mailbox.account_id,
                Err(err) => return Ok(Err(err)),
            }
        } else if name.is_empty() {
            self.account_id()
        } else {
            return Ok(no("no such quota root"));
        };
        let usage: Option<(i64, i64)> = match sqlx::query_as("SELECT quota_bytes, used_bytes FROM accounts WHERE id = ?").bind(account_id).fetch_optional(&self.app.db).await {
            Ok(row) => row,
            Err(err) => return Ok(Err(internal(err))),
        };
        let mut out = Vec::new();
        if by_mailbox {
            out.extend_from_slice(b"* QUOTAROOT ");
            string(&mut out, name.as_bytes());
            out.extend_from_slice(b" \"\"\r\n");
        }
        if let Some((quota, used)) = usage.filter(|(quota, _)| *quota > 0) {
            // Units of 1024 octets.
            out.extend_from_slice(format!("* QUOTA \"\" (STORAGE {} {})\r\n", (used.max(0) + 1023) / 1024, quota / 1024).as_bytes());
        } else if !by_mailbox {
            out.extend_from_slice(b"* QUOTA \"\" ()\r\n");
        }
        self.send(&out).await?;
        Ok(Ok(format!("{} completed", if by_mailbox { "GETQUOTAROOT" } else { "GETQUOTA" })))
    }

    async fn cmd_append(&mut self, args: &[Arg]) -> CmdResult {
        let mailbox = self.find_mailbox(args.first().and_then(Arg::text), "i").await?;
        let Some(Arg::Str(raw)) = args.last().filter(|_| args.len() >= 2) else { return bad("usage: APPEND mailbox [flags] [date] literal") };
        let mut flags = Flags::default();
        let mut keywords = Vec::new();
        let mut date = None;
        for arg in &args[1..args.len() - 1] {
            match arg {
                Arg::List(list) => (flags, keywords) = parse_flags(list)?,
                Arg::Str(text) => {
                    let text = String::from_utf8_lossy(text);
                    date = Some(OffsetDateTime::parse(text.trim(), DATE_TIME).map_err(|_| "BAD invalid date-time".to_owned())?.unix_timestamp());
                }
                Arg::Atom(_) => return bad("unexpected argument"),
            }
        }
        if raw.is_empty() {
            return bad("empty message");
        }
        let foreign = self.account.as_ref().is_some_and(|account| account.id != mailbox.account_id);
        let raw = crate::security::admit_stored(&self.app, raw, foreign).map_err(|name| format!("NO [CANNOT] the message contains an executable attachment ({name}), which this server does not accept"))?;
        let appended = self.app.store.append(mailbox.account_id, mailbox.id, &raw, flags, date).await.map_err(|err| match err {
            StoreError::QuotaExceeded => "NO [OVERQUOTA] mailbox quota exceeded".to_owned(),
            other => internal(other),
        })?;
        if !keywords.is_empty() {
            self.app.store.set_flags_and_keywords(mailbox.account_id, appended.id, flags, &keywords).await.map_err(internal)?;
        }
        Ok(format!("[APPENDUID {} {}] APPEND completed", mailbox.uid_validity, appended.uid))
    }

    /// Reports changes made by other sessions (and by this one) to the selected mailbox.
    ///
    /// Every change to a message raises the mailbox's mod-sequence and every removal is logged
    /// in `expunged`, so only what changed since the last sync is read: nothing at all when the
    /// mod-sequence did not move.
    async fn sync(&mut self) -> std::io::Result<()> {
        let Some(selected) = &mut self.selected else { return Ok(()) };
        let Ok(mailbox) = self.app.store.mailbox(selected.mailbox.account_id, selected.mailbox.id).await else { return Ok(()) };
        if mailbox.highest_modseq == selected.synced_modseq {
            return Ok(());
        }
        let since = selected.synced_modseq;
        let (Ok(gone), Ok(current)) = (self.app.store.expunged_since(mailbox.id, since).await, self.app.store.messages_changed_since(mailbox.id, since).await) else {
            return Ok(());
        };
        // Read after the mailbox row: anything newer is simply looked at again next time.
        selected.synced_modseq = mailbox.highest_modseq;
        selected.mailbox = mailbox;
        let gone: std::collections::HashSet<i64> = gone.into_iter().collect();
        // A message moved away and back has a new UID; its old one is in `gone`.
        let present: std::collections::HashSet<i64> = current.iter().map(|m| m.uid).collect();
        let mut out = String::new();
        let mut vanished = Vec::new();
        // Expunges are reported from the highest sequence number down, so earlier numbers
        // in the same batch stay valid.
        for index in (0..selected.messages.len()).rev() {
            let uid = selected.messages[index].uid;
            if gone.contains(&uid) && !present.contains(&uid) {
                let removed = selected.messages.remove(index);
                if self.qresync {
                    vanished.push(removed.uid);
                } else {
                    out.push_str(&format!("* {} EXPUNGE\r\n", index + 1));
                }
            }
        }
        if !vanished.is_empty() {
            vanished.sort_unstable();
            out.push_str(&format!("* VANISHED {}\r\n", uid_set(&vanished)));
        }
        let known = selected.messages.len();
        let position: std::collections::HashMap<i64, usize> = selected.messages.iter().enumerate().map(|(index, m)| (m.id, index)).collect();
        let mut changed = Vec::new();
        let mut added: Vec<Message> = Vec::new();
        for new in current {
            match position.get(&new.id) {
                Some(&index) => {
                    if selected.messages[index].modseq != new.modseq {
                        selected.messages[index] = new;
                        changed.push(index);
                    }
                }
                None => added.push(new),
            }
        }
        if !added.is_empty() {
            selected.messages.extend(added);
            selected.messages[known..].sort_by_key(|m| m.uid);
            out.push_str(&format!("* {} EXISTS\r\n", selected.messages.len()));
        }
        for index in changed {
            let message = &selected.messages[index];
            let modseq = if self.condstore { format!(" MODSEQ ({})", message.modseq) } else { String::new() };
            out.push_str(&format!("* {} FETCH (FLAGS ({}) UID {}{modseq})\r\n", index + 1, flags_text(message), message.uid));
        }
        if out.is_empty() { Ok(()) } else { self.send(out.as_bytes()).await }
    }

    /// Indexes (0-based sequence positions) of the selected messages addressed by `set`.
    fn resolve(&self, set: &SequenceSet, uid: bool) -> Vec<usize> {
        let Some(selected) = &self.selected else { return Vec::new() };
        let max_seq = selected.messages.len() as u32;
        let max_uid = selected.messages.last().map_or(0, |m| m.uid as u32);
        selected
            .messages
            .iter()
            .enumerate()
            .filter(|(index, m)| if uid { set.contains(m.uid as u32, max_uid) } else { set.contains(*index as u32 + 1, max_seq) })
            .map(|(index, _)| index)
            .collect()
    }

    async fn expunge(&mut self, only: Option<SequenceSet>, silent: bool) -> CmdResult {
        let Some(selected) = &self.selected else { return bad("no mailbox selected") };
        if selected.read_only {
            return no("mailbox is read-only");
        }
        if !selected.rights.contains('e') {
            return no("[NOPERM] you may not expunge this mailbox");
        }
        let owner = selected.mailbox.account_id;
        let max_uid = selected.messages.last().map_or(0, |m| m.uid as u32);
        let targets: Vec<i64> = selected
            .messages
            .iter()
            .filter(|m| m.deleted && only.as_ref().is_none_or(|set| set.contains(m.uid as u32, max_uid)))
            .map(|m| m.id)
            .collect();
        for id in targets {
            match self.app.store.delete_message(owner, id).await {
                Ok(()) | Err(StoreError::NotFound) => {}
                Err(err) => return Err(internal(err)),
            }
        }
        if silent
            && let Some(selected) = &mut self.selected
        {
            selected.messages.retain(|m| !m.deleted);
        }
        Ok("EXPUNGE completed".into())
    }

    async fn cmd_fetch(&mut self, args: &[Arg], uid: bool) -> std::io::Result<CmdResult> {
        let Some(set) = args.first().and_then(Arg::text).and_then(|s| SequenceSet::parse(&s)) else { return Ok(bad("invalid sequence set")) };
        let mut items: Vec<String> = match args.get(1) {
            Some(Arg::List(list)) => list.iter().filter_map(|a| if let Arg::Atom(a) = a { Some(a.clone()) } else { None }).collect(),
            Some(Arg::Atom(item)) => match item.to_ascii_uppercase().as_str() {
                "ALL" => vec!["FLAGS".into(), "INTERNALDATE".into(), "RFC822.SIZE".into(), "ENVELOPE".into()],
                "FAST" => vec!["FLAGS".into(), "INTERNALDATE".into(), "RFC822.SIZE".into()],
                "FULL" => vec!["FLAGS".into(), "INTERNALDATE".into(), "RFC822.SIZE".into(), "ENVELOPE".into(), "BODY".into()],
                _ => vec![item.clone()],
            },
            _ => return Ok(bad("usage: FETCH set items")),
        };
        if items.is_empty() || items.len() > 50 {
            return Ok(bad("invalid FETCH items"));
        }
        if uid && !items.iter().any(|i| i.eq_ignore_ascii_case("UID")) {
            items.insert(0, "UID".into());
        }
        let read_only = self.selected.as_ref().is_none_or(|s| s.read_only);
        // Validate every item before producing any output.
        let mut plan: Vec<(String, Option<(bool, Section)>)> = Vec::new();
        // BINARY (RFC 3516): (peek, size only, section) of decoded part contents.
        let mut binary: Vec<(usize, bool, Section)> = Vec::new();
        for item in &items {
            let upper = item.to_ascii_uppercase();
            let binary_section = [("BINARY.PEEK[", true, false), ("BINARY.SIZE[", true, true), ("BINARY[", false, false)]
                .into_iter()
                .find_map(|(prefix, peek, size)| upper.strip_prefix(prefix).map(|rest| (peek, size, rest)));
            if let Some((peek, size, rest)) = binary_section {
                let Some(parsed) = rest.split_once(']').and_then(|(spec, partial)| Section::parse(spec, partial)).filter(|s| s.kind == fetch::SectionKind::All && !(size && s.partial.is_some())) else {
                    return Ok(bad("invalid binary section"));
                };
                binary.push((plan.len(), size, parsed));
                plan.push((upper, Some((peek, Section::parse("", "").expect("static section specification")))));
                continue;
            }
            let section = match (upper.strip_prefix("BODY.PEEK["), upper.strip_prefix("BODY[")) {
                (Some(rest), _) => Some((true, rest)),
                (None, Some(rest)) => Some((false, rest)),
                _ => None,
            };
            match section {
                Some((peek, rest)) => {
                    let Some(parsed) = rest.split_once(']').and_then(|(spec, partial)| Section::parse(spec, partial)) else {
                        return Ok(bad("invalid body section"));
                    };
                    plan.push((upper, Some((peek, parsed))));
                }
                None if matches!(
                    upper.as_str(),
                    "FLAGS" | "UID" | "MODSEQ" | "INTERNALDATE" | "RFC822.SIZE" | "ENVELOPE" | "BODY" | "BODYSTRUCTURE" | "RFC822" | "RFC822.HEADER" | "RFC822.TEXT"
                ) =>
                {
                    plan.push((upper, None))
                }
                None => return Ok(bad("unknown FETCH item")),
            }
        }
        let want_flags = plan.iter().any(|(name, _)| name == "FLAGS");
        let needs_content = plan.iter().any(|(name, _)| !matches!(name.as_str(), "FLAGS" | "UID" | "MODSEQ" | "INTERNALDATE" | "RFC822.SIZE"));
        // Fetch modifiers: (CHANGEDSINCE modseq [VANISHED]).
        let mut changed_since: Option<i64> = None;
        let mut report_vanished = false;
        if let Some(Arg::List(modifiers)) = args.get(2) {
            let mut modifiers = modifiers.iter();
            while let Some(modifier) = modifiers.next() {
                match modifier.atom_upper().as_deref() {
                    Some("CHANGEDSINCE") => match modifiers.next().and_then(Arg::text).and_then(|v| v.parse::<i64>().ok()) {
                        Some(value) => changed_since = Some(value),
                        None => return Ok(bad("invalid CHANGEDSINCE value")),
                    },
                    Some("VANISHED") if uid && self.qresync => report_vanished = true,
                    _ => return Ok(bad("invalid FETCH modifier")),
                }
            }
        }
        if report_vanished && changed_since.is_none() {
            return Ok(bad("VANISHED requires CHANGEDSINCE"));
        }
        let mut want_modseq = plan.iter().any(|(name, _)| name == "MODSEQ");
        if changed_since.is_some() || want_modseq {
            self.condstore = true;
            want_modseq = true;
        }
        if let (true, Some(since), Some(selected)) = (report_vanished, changed_since, &self.selected) {
            let max_uid = (selected.mailbox.uid_next - 1).max(0) as u32;
            let known_max = selected.messages.last().map_or(max_uid, |m| (m.uid as u32).max(max_uid));
            match self.app.store.expunged_since(selected.mailbox.id, since).await {
                Ok(uids) => {
                    let uids: Vec<i64> = uids.into_iter().filter(|u| set.contains(*u as u32, known_max)).collect();
                    if !uids.is_empty() {
                        self.line(&format!("* VANISHED (EARLIER) {}", uid_set(&uids))).await?;
                    }
                }
                Err(err) => return Ok(Err(internal(err))),
            }
        }

        // Responses are sent in batches: one write (and TLS record) per message made
        // `FETCH 1:*` on a large mailbox take a system call per line.
        let mut pending: Vec<u8> = Vec::with_capacity(FETCH_BATCH);
        for index in self.resolve(&set, uid) {
            let Some(mut message) = self.selected.as_ref().and_then(|s| s.messages.get(index).cloned()) else { continue };
            if changed_since.is_some_and(|since| message.modseq <= since) {
                continue;
            }
            let raw = if needs_content {
                match self.app.store.read_blob(&message.blob_hash).await {
                    Ok(data) => data,
                    Err(err) => {
                        tracing::error!(%err, "IMAP message content is missing");
                        continue;
                    }
                }
            } else {
                Vec::new()
            };
            let parsed = if needs_content { MessageParser::default().parse(&raw) } else { None };
            let mut parts: Vec<Vec<u8>> = Vec::new();
            let mut mark_seen = false;
            for (position, (name, section)) in plan.iter().enumerate() {
                let mut out = Vec::new();
                if let Some((_, size_only, wanted)) = binary.iter().find(|(at, ..)| *at == position) {
                    let Some(parsed) = &parsed else { continue };
                    let decoded = match fetch::binary_bytes(&raw, parsed, wanted) {
                        Ok(decoded) => decoded,
                        Err(fetch::BinaryError::UnknownEncoding) => return Ok(no("[UNKNOWN-CTE] the part has an unknown transfer encoding")),
                        Err(fetch::BinaryError::NoSuchPart) => None,
                    };
                    let path: Vec<String> = wanted.path.iter().map(u32::to_string).collect();
                    if *size_only {
                        out.extend_from_slice(format!("BINARY.SIZE[{}] {}", path.join("."), decoded.as_ref().map_or(0, Vec::len)).as_bytes());
                    } else {
                        mark_seen |= !name.starts_with("BINARY.PEEK");
                        let partial = wanted.partial.map(|(start, _)| format!("<{start}>")).unwrap_or_default();
                        out.extend_from_slice(format!("BINARY[{}]{partial}", path.join(".")).as_bytes());
                        match decoded {
                            Some(bytes) => {
                                let bytes = match wanted.partial {
                                    Some((start, len)) => bytes.get(start.min(bytes.len())..start.saturating_add(len).min(bytes.len())).unwrap_or(&[]).to_vec(),
                                    None => bytes,
                                };
                                out.extend_from_slice(format!(" ~{{{}}}\r\n", bytes.len()).as_bytes());
                                out.extend_from_slice(&bytes);
                            }
                            None => out.extend_from_slice(b" NIL"),
                        }
                    }
                    parts.push(out);
                    continue;
                }
                match (name.as_str(), section) {
                    ("FLAGS" | "MODSEQ", _) => continue,
                    ("UID", _) => out.extend_from_slice(format!("UID {}", message.uid).as_bytes()),
                    ("RFC822.SIZE", _) => out.extend_from_slice(format!("RFC822.SIZE {}", message.size).as_bytes()),
                    ("INTERNALDATE", _) => {
                        let date = OffsetDateTime::from_unix_timestamp(message.internal_date).ok().and_then(|d| d.format(INTERNAL_DATE).ok()).unwrap_or_default();
                        out.extend_from_slice(format!("INTERNALDATE \"{date}\"").as_bytes());
                    }
                    ("ENVELOPE" | "BODY" | "BODYSTRUCTURE", None) => {
                        let Some(parsed) = &parsed else { continue };
                        out.extend_from_slice(name.as_bytes());
                        out.push(b' ');
                        if name == "ENVELOPE" {
                            fetch::envelope(&mut out, parsed);
                        } else {
                            fetch::body_structure(&mut out, parsed, &raw, &parsed.parts[0], name == "BODYSTRUCTURE", 0);
                        }
                    }
                    (_, None) => {
                        let spec = match name.as_str() {
                            "RFC822.HEADER" => "HEADER",
                            "RFC822.TEXT" => "TEXT",
                            _ => "",
                        };
                        let section = Section::parse(spec, "").expect("static section specification");
                        let bytes = parsed.as_ref().and_then(|p| fetch::section_bytes(&raw, p, &section)).unwrap_or_else(|| if spec.is_empty() { raw.clone() } else { Vec::new() });
                        mark_seen |= name != "RFC822.HEADER";
                        out.extend_from_slice(format!("{name} {{{}}}\r\n", bytes.len()).as_bytes());
                        out.extend_from_slice(&bytes);
                    }
                    (_, Some((peek, section))) => {
                        let bytes = parsed.as_ref().and_then(|p| fetch::section_bytes(&raw, p, section));
                        mark_seen |= !peek;
                        out.extend_from_slice(section.response_name().as_bytes());
                        match bytes {
                            Some(bytes) => {
                                out.extend_from_slice(format!(" {{{}}}\r\n", bytes.len()).as_bytes());
                                out.extend_from_slice(&bytes);
                            }
                            None => out.extend_from_slice(b" NIL"),
                        }
                    }
                }
                parts.push(out);
            }
            // Fetching a body without PEEK sets \Seen; the new flags are part of this response.
            let mut flags_changed = false;
            if mark_seen && !read_only && !message.seen && self.may('s') {
                let flags = Flags { seen: true, answered: message.answered, flagged: message.flagged, deleted: message.deleted, draft: message.draft };
                let keywords: Vec<String> = serde_json::from_str(&message.keywords).unwrap_or_default();
                if self.app.store.set_flags_and_keywords(self.owner(), message.id, flags, &keywords).await.is_ok()
                    && let Ok(updated) = self.app.store.message(self.owner(), message.id).await
                {
                    message = updated;
                    flags_changed = true;
                    if let Some(slot) = self.selected.as_mut().and_then(|s| s.messages.get_mut(index)) {
                        *slot = message.clone();
                    }
                }
            }
            if want_flags || flags_changed {
                parts.push(format!("FLAGS ({})", flags_text(&message)).into_bytes());
            }
            if want_modseq {
                parts.push(format!("MODSEQ ({})", message.modseq).into_bytes());
            }
            pending.extend_from_slice(format!("* {} FETCH (", index + 1).as_bytes());
            pending.extend_from_slice(&parts.join(&b' '));
            pending.extend_from_slice(b")\r\n");
            if pending.len() >= FETCH_BATCH {
                self.send(&pending).await?;
                pending.clear();
            }
        }
        if !pending.is_empty() {
            self.send(&pending).await?;
        }
        Ok(Ok(format!("{}FETCH completed", if uid { "UID " } else { "" })))
    }

    async fn cmd_store(&mut self, args: &[Arg], uid: bool) -> std::io::Result<CmdResult> {
        let Some(set) = args.first().and_then(Arg::text).and_then(|s| SequenceSet::parse(&s)) else { return Ok(bad("invalid sequence set")) };
        // Optional store modifier: (UNCHANGEDSINCE modseq).
        let mut args = args.to_vec();
        let mut unchanged_since: Option<i64> = None;
        if let Some(Arg::List(modifiers)) = args.get(1).cloned() {
            match (modifiers.first().and_then(Arg::atom_upper).as_deref(), modifiers.get(1).and_then(Arg::text).and_then(|v| v.parse::<i64>().ok())) {
                (Some("UNCHANGEDSINCE"), Some(value)) => unchanged_since = Some(value),
                _ => return Ok(bad("invalid STORE modifier")),
            }
            args.remove(1);
            self.condstore = true;
        }
        let args = &args[..];
        let mut modified: Vec<i64> = Vec::new();
        let Some(mode) = args.get(1).and_then(Arg::atom_upper) else { return Ok(bad("usage: STORE set mode flags")) };
        let (operation, silent) = match mode.strip_suffix(".SILENT") {
            Some(op) => (op.to_owned(), true),
            None => (mode.clone(), false),
        };
        if !matches!(operation.as_str(), "FLAGS" | "+FLAGS" | "-FLAGS") {
            return Ok(bad("invalid STORE mode"));
        }
        let list: Vec<Arg> = match args.get(2) {
            Some(Arg::List(list)) => list.clone(),
            Some(_) => args[2..].to_vec(),
            None => return Ok(bad("flags required")),
        };
        let (flags, keywords) = match parse_flags(&list) {
            Ok(parsed) => parsed,
            Err(err) => return Ok(Err(err)),
        };
        // RFC 4314: \Seen needs `s`, \Deleted needs `t`, every other flag needs `w`.
        let other = flags.answered || flags.flagged || flags.draft || !keywords.is_empty();
        let needed: Vec<char> = if operation == "FLAGS" { vec!['s', 't', 'w'] } else { [(flags.seen, 's'), (flags.deleted, 't'), (other, 'w')].into_iter().filter(|(on, _)| *on).map(|(_, right)| right).collect() };
        if !needed.into_iter().all(|right| self.may(right)) {
            return Ok(no("[NOPERM] you may not change these flags in this mailbox"));
        }
        if self.selected.as_ref().is_none_or(|s| s.read_only) {
            return Ok(no("mailbox is read-only"));
        }
        let mut out = String::new();
        for index in self.resolve(&set, uid) {
            let Some(message) = self.selected.as_ref().and_then(|s| s.messages.get(index).cloned()) else { continue };
            // Conditional store: skip messages changed since the client last looked. The check
            // uses the stored state, not this session's possibly stale view.
            if let Some(limit) = unchanged_since {
                let latest = self.app.store.message(self.owner(), message.id).await.map(|m| m.modseq).unwrap_or(i64::MAX);
                if latest > limit {
                    modified.push(if uid { message.uid } else { index as i64 + 1 });
                    continue;
                }
            }
            let mut current: Vec<String> = serde_json::from_str(&message.keywords).unwrap_or_default();
            let (new_flags, new_keywords) = match operation.as_str() {
                "FLAGS" => (flags, keywords.clone()),
                "+FLAGS" => {
                    for keyword in &keywords {
                        if !current.contains(keyword) {
                            current.push(keyword.clone());
                        }
                    }
                    (
                        Flags {
                            seen: message.seen || flags.seen,
                            answered: message.answered || flags.answered,
                            flagged: message.flagged || flags.flagged,
                            deleted: message.deleted || flags.deleted,
                            draft: message.draft || flags.draft,
                        },
                        current,
                    )
                }
                _ => {
                    current.retain(|k| !keywords.contains(k));
                    (
                        Flags {
                            seen: message.seen && !flags.seen,
                            answered: message.answered && !flags.answered,
                            flagged: message.flagged && !flags.flagged,
                            deleted: message.deleted && !flags.deleted,
                            draft: message.draft && !flags.draft,
                        },
                        current,
                    )
                }
            };
            match self.app.store.set_flags_and_keywords(self.owner(), message.id, new_flags, &new_keywords).await {
                Ok(()) if self.owner() == self.account_id() => {
                    let before: Vec<String> = serde_json::from_str(&message.keywords).unwrap_or_default();
                    crate::bayes::train_on_keywords(&self.app, self.owner(), &message.blob_hash, &before, &new_keywords);
                    crate::categories::train_on_keywords(&self.app, self.owner(), &message.blob_hash, &before, &new_keywords);
                }
                Ok(()) => {}
                Err(StoreError::NotFound) => continue,
                Err(err) => return Ok(Err(internal(err))),
            }
            if let Ok(updated) = self.app.store.message(self.owner(), message.id).await {
                if !silent || self.condstore {
                    let modseq = if self.condstore { format!(" MODSEQ ({})", updated.modseq) } else { String::new() };
                    out.push_str(&format!("* {} FETCH (FLAGS ({}){}{modseq})\r\n", index + 1, flags_text(&updated), if uid { format!(" UID {}", updated.uid) } else { String::new() }));
                }
                if let Some(slot) = self.selected.as_mut().and_then(|s| s.messages.get_mut(index)) {
                    *slot = updated;
                }
            }
        }
        self.send(out.as_bytes()).await?;
        let prefix = if uid { "UID " } else { "" };
        if !modified.is_empty() {
            return Ok(Ok(format!("[MODIFIED {}] {prefix}STORE completed; some messages were changed by someone else", uid_set(&modified))));
        }
        Ok(Ok(format!("{prefix}STORE completed")))
    }

    /// Evaluates search criteria (after an optional CHARSET) on the selected mailbox: the
    /// matching message indexes and the highest mod-sequence among them.
    async fn search_hits(&mut self, args: &[Arg], charset_first: bool) -> Result<(Vec<usize>, i64, bool), String> {
        let mut args = args;
        if charset_first {
            // SORT and THREAD always name the charset, without the CHARSET keyword.
            match args.first().and_then(Arg::text).map(|c| c.to_ascii_uppercase()).as_deref() {
                Some("UTF-8" | "US-ASCII") => args = &args[1..],
                _ => return Err("NO [BADCHARSET (UTF-8)] unsupported charset".into()),
            }
        } else if args.first().and_then(Arg::atom_upper).as_deref() == Some("CHARSET") {
            match args.get(1).and_then(Arg::text).map(|c| c.to_ascii_uppercase()).as_deref() {
                Some("UTF-8" | "US-ASCII") => args = &args[2..],
                _ => return Err("NO [BADCHARSET (UTF-8)] unsupported charset".into()),
            }
        }
        let mut iter = args.iter();
        let mut keys = Vec::new();
        while iter.len() > 0 {
            keys.push(parse_search(&mut iter, 0)?);
        }
        if keys.is_empty() {
            return Err("BAD search criteria required".into());
        }
        let uses_modseq = args.iter().any(|a| a.atom_upper().as_deref() == Some("MODSEQ"));
        if uses_modseq {
            self.condstore = true;
        }
        let program = Key::And(keys);
        let Some(selected) = &self.selected else { return Err("BAD no mailbox selected".into()) };
        let max_seq = selected.messages.len() as u32;
        let max_uid = selected.messages.last().map_or(0, |m| m.uid as u32);
        let mut hits = Vec::new();
        let mut highest = 0;
        if !program.needs_content() {
            for (index, message) in selected.messages.iter().enumerate() {
                let ctx = SearchContext { seq: index as u32 + 1, max_seq, max_uid, message, raw: None, text: None };
                if matches(&program, &ctx) {
                    highest = highest.max(message.modseq);
                    hits.push(index);
                }
            }
            return Ok((hits, highest, uses_modseq));
        }
        // Text criteria are answered from the full-text index, streamed row by row; only a
        // message not indexed yet, or a header the index lacks, is read from its file.
        let needs_raw = program.needs_raw();
        let position: std::collections::HashMap<i64, usize> = selected.messages.iter().enumerate().map(|(index, m)| (m.id, index)).collect();
        let mut rows = sqlx::query_as::<_, (i64, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>)>(
            "SELECT m.id, t.subject, t.sender, t.recipients_to, t.recipients_cc, t.recipients_bcc, t.body, t.attachments
               FROM messages m LEFT JOIN message_extras e ON e.hash = m.blob_hash LEFT JOIN message_text t ON t.rowid = e.id
              WHERE m.mailbox_id = ?",
        )
        .bind(selected.mailbox.id)
        .fetch(&self.app.db);
        use futures_util::TryStreamExt;
        while let Some((id, subject, sender, to, cc, bcc, body, names)) = rows.try_next().await.map_err(internal)? {
            let Some(&index) = position.get(&id) else { continue };
            let message = &selected.messages[index];
            let text = body.map(|body| IndexedText {
                subject: subject.unwrap_or_default().to_lowercase(),
                sender: sender.unwrap_or_default().to_lowercase(),
                to: to.unwrap_or_default().to_lowercase(),
                cc: cc.unwrap_or_default().to_lowercase(),
                bcc: bcc.unwrap_or_default().to_lowercase(),
                body: body.to_lowercase(),
                names: names.unwrap_or_default().to_lowercase(),
            });
            let raw = if needs_raw || text.is_none() { self.app.store.read_blob(&message.blob_hash).await.ok() } else { None };
            let ctx = SearchContext { seq: index as u32 + 1, max_seq, max_uid, message, raw: raw.as_deref(), text: text.as_ref() };
            if matches(&program, &ctx) {
                highest = highest.max(message.modseq);
                hits.push(index);
            }
        }
        hits.sort_unstable();
        Ok((hits, highest, uses_modseq))
    }

    /// The number a client knows a message by: its UID or its sequence number.
    fn number(&self, index: usize, uid: bool) -> u32 {
        if uid { self.selected.as_ref().and_then(|s| s.messages.get(index)).map_or(0, |m| m.uid as u32) } else { index as u32 + 1 }
    }

    async fn cmd_search(&mut self, tag: &str, args: &[Arg], uid: bool) -> std::io::Result<CmdResult> {
        // ESEARCH (RFC 4731): SEARCH RETURN (MIN MAX COUNT ALL) criteria.
        let mut args = args;
        let mut returns: Option<Vec<String>> = None;
        if args.first().and_then(Arg::atom_upper).as_deref() == Some("RETURN") {
            let Some(Arg::List(options)) = args.get(1) else { return Ok(bad("usage: SEARCH RETURN (options) criteria")) };
            let options: Vec<String> = options.iter().filter_map(Arg::atom_upper).collect();
            if options.iter().any(|o| !matches!(o.as_str(), "MIN" | "MAX" | "COUNT" | "ALL")) {
                return Ok(bad("unsupported RETURN option"));
            }
            // An empty list means ALL.
            returns = Some(if options.is_empty() { vec!["ALL".into()] } else { options });
            args = &args[2..];
        } else if self.rev2 {
            // IMAP4rev2 has no SEARCH response: ESEARCH with ALL takes its place.
            returns = Some(vec!["ALL".into()]);
        }
        let (hits, highest, uses_modseq) = match self.search_hits(args, false).await {
            Ok(found) => found,
            Err(err) => return Ok(Err(err)),
        };
        let numbers: Vec<u32> = hits.iter().map(|&i| self.number(i, uid)).collect();
        let line = match returns {
            None => {
                let mut line = if numbers.is_empty() { "* SEARCH".to_owned() } else { format!("* SEARCH {}", numbers.iter().map(u32::to_string).collect::<Vec<_>>().join(" ")) };
                // A MODSEQ search reports the highest mod-sequence among the matches.
                if uses_modseq && !numbers.is_empty() {
                    line.push_str(&format!(" (MODSEQ {highest})"));
                }
                line
            }
            Some(options) => {
                let mut line = format!("* ESEARCH (TAG \"{tag}\"){}", if uid { " UID" } else { "" });
                for option in &options {
                    match option.as_str() {
                        "MIN" if !numbers.is_empty() => line.push_str(&format!(" MIN {}", numbers.iter().min().unwrap_or(&0))),
                        "MAX" if !numbers.is_empty() => line.push_str(&format!(" MAX {}", numbers.iter().max().unwrap_or(&0))),
                        "COUNT" => line.push_str(&format!(" COUNT {}", numbers.len())),
                        "ALL" if !numbers.is_empty() => line.push_str(&format!(" ALL {}", sequence_set(&numbers))),
                        _ => {}
                    }
                }
                if uses_modseq && !numbers.is_empty() {
                    line.push_str(&format!(" MODSEQ {highest}"));
                }
                line
            }
        };
        self.line(&line).await?;
        Ok(Ok(format!("{}SEARCH completed", if uid { "UID " } else { "" })))
    }

    /// SORT (RFC 5256): SORT (criteria) charset search-criteria.
    async fn cmd_sort(&mut self, args: &[Arg], uid: bool) -> std::io::Result<CmdResult> {
        let Some(Arg::List(criteria)) = args.first() else { return Ok(bad("usage: SORT (criteria) charset search")) };
        let mut order: Vec<(SortKey, bool)> = Vec::new();
        let mut reverse = false;
        for criterion in criteria.iter().filter_map(Arg::atom_upper) {
            let key = match criterion.as_str() {
                "REVERSE" => {
                    reverse = true;
                    continue;
                }
                "ARRIVAL" => SortKey::Arrival,
                "CC" => SortKey::Cc,
                "DATE" => SortKey::Date,
                "FROM" => SortKey::From,
                "SIZE" => SortKey::Size,
                "SUBJECT" => SortKey::Subject,
                "TO" => SortKey::To,
                _ => return Ok(bad("unknown sort criterion")),
            };
            order.push((key, reverse));
            reverse = false;
        }
        if order.is_empty() || reverse {
            return Ok(bad("invalid sort criteria"));
        }
        let (hits, _, _) = match self.search_hits(&args[1..], true).await {
            Ok(found) => found,
            Err(err) => return Ok(Err(err)),
        };
        let need_cc = order.iter().any(|(k, _)| *k == SortKey::Cc);
        let mut rows = Vec::with_capacity(hits.len());
        for index in hits {
            let Some(message) = self.selected.as_ref().and_then(|s| s.messages.get(index)).cloned() else { continue };
            let cc = if need_cc { first_cc(&self.app.store.read_blob_head(&message.blob_hash, 64 * 1024).await.unwrap_or_default()) } else { String::new() };
            rows.push((index, message, cc));
        }
        rows.sort_by(|(ia, a, cca), (ib, b, ccb)| {
            for (key, reverse) in &order {
                let ordering = match key {
                    SortKey::Arrival => a.internal_date.cmp(&b.internal_date),
                    SortKey::Date => sort_date(a).cmp(&sort_date(b)),
                    SortKey::Size => a.size.cmp(&b.size),
                    SortKey::Subject => base_subject(&a.subject).cmp(&base_subject(&b.subject)),
                    SortKey::From => mailbox_part(&a.from_addr).cmp(&mailbox_part(&b.from_addr)),
                    SortKey::To => mailbox_part(a.to_addrs.split(',').next().unwrap_or("")).cmp(&mailbox_part(b.to_addrs.split(',').next().unwrap_or(""))),
                    SortKey::Cc => mailbox_part(cca).cmp(&mailbox_part(ccb)),
                };
                let ordering = if *reverse { ordering.reverse() } else { ordering };
                if ordering != std::cmp::Ordering::Equal {
                    return ordering;
                }
            }
            ia.cmp(ib)
        });
        let numbers: Vec<String> = rows.iter().map(|(i, _, _)| self.number(*i, uid).to_string()).collect();
        self.line(&format!("* SORT{}{}", if numbers.is_empty() { "" } else { " " }, numbers.join(" "))).await?;
        Ok(Ok(format!("{}SORT completed", if uid { "UID " } else { "" })))
    }

    /// THREAD (RFC 5256): THREAD algorithm charset search-criteria.
    async fn cmd_thread(&mut self, args: &[Arg], uid: bool) -> std::io::Result<CmdResult> {
        let algorithm = args.first().and_then(Arg::atom_upper).unwrap_or_default();
        if !matches!(algorithm.as_str(), "ORDEREDSUBJECT" | "REFERENCES") {
            return Ok(bad("unsupported threading algorithm"));
        }
        let (hits, _, _) = match self.search_hits(args.get(1..).unwrap_or(&[]), true).await {
            Ok(found) => found,
            Err(err) => return Ok(Err(err)),
        };
        let Some(selected) = &self.selected else { return Ok(bad("no mailbox selected")) };
        // Threads keyed by the base subject or by the conversation the store assigned.
        let mut threads: Vec<(String, Vec<usize>)> = Vec::new();
        for index in hits {
            let message = &selected.messages[index];
            let key = if algorithm == "ORDEREDSUBJECT" { base_subject(&message.subject) } else { message.thread_id.to_string() };
            match threads.iter_mut().find(|(k, _)| *k == key) {
                Some((_, members)) => members.push(index),
                None => threads.push((key, vec![index])),
            }
        }
        for (_, members) in &mut threads {
            members.sort_by_key(|&i| (sort_date(&selected.messages[i]), i));
        }
        threads.sort_by_key(|(_, members)| (sort_date(&selected.messages[members[0]]), members[0]));
        let mut line = String::from("* THREAD ");
        for (_, members) in &threads {
            let numbers: Vec<u32> = members.iter().map(|&i| self.number(i, uid)).collect();
            let text = match (algorithm.as_str(), numbers.as_slice()) {
                // The first message is the parent of all the others, which are siblings.
                ("ORDEREDSUBJECT", [first, rest @ ..]) if rest.len() > 1 => format!("({first} {})", rest.iter().map(|n| format!("({n})")).collect::<String>()),
                // References: the conversation as a chain, oldest first.
                _ => format!("({})", numbers.iter().map(u32::to_string).collect::<Vec<_>>().join(" ")),
            };
            line.push_str(&text);
        }
        self.line(line.trim_end()).await?;
        Ok(Ok(format!("{}THREAD completed", if uid { "UID " } else { "" })))
    }

    async fn cmd_copy(&mut self, args: &[Arg], uid: bool, remove: bool) -> CmdResult {
        let set = args.first().and_then(Arg::text).and_then(|s| SequenceSet::parse(&s)).ok_or("BAD invalid sequence set")?;
        let target = self.find_mailbox(args.get(1).and_then(Arg::text), "i").await?;
        let name = if remove { "MOVE" } else { "COPY" };
        if remove && self.selected.as_ref().is_none_or(|s| s.read_only) {
            return no("mailbox is read-only");
        }
        // Moving out of a mailbox deletes from it.
        if remove && !(self.may('t') && self.may('e')) {
            return no("[NOPERM] you may not remove messages from this mailbox");
        }
        let owner = self.owner();
        let (mut source_uids, mut target_uids) = (Vec::new(), Vec::new());
        for index in self.resolve(&set, uid) {
            let Some(message) = self.selected.as_ref().and_then(|s| s.messages.get(index).cloned()) else { continue };
            // Copying into Junk (as some clients report spam) teaches the filter as moving does.
            if owner == target.account_id && owner == self.account_id() {
                crate::bayes::train_on_move(&self.app, owner, &message.blob_hash, message.mailbox_id, target.id);
            }
            let result = if remove {
                self.app.store.move_across(owner, message.id, target.account_id, target.id).await.map(|(_, uid)| uid)
            } else {
                self.app.store.copy_across(owner, message.id, target.account_id, target.id).await.map(|appended| appended.uid)
            };
            match result {
                Ok(new_uid) => {
                    source_uids.push(message.uid.to_string());
                    target_uids.push(new_uid.to_string());
                }
                Err(StoreError::NotFound) => {}
                Err(StoreError::QuotaExceeded) => return no("[OVERQUOTA] mailbox quota exceeded"),
                Err(err) => return Err(internal(err)),
            }
        }
        if source_uids.is_empty() {
            return Ok(format!("{name} completed"));
        }
        Ok(format!("[COPYUID {} {} {}] {name} completed", target.uid_validity, source_uids.join(","), target_uids.join(",")))
    }

    async fn cmd_idle(&mut self) -> std::io::Result<CmdResult> {
        self.line("+ idling").await?;
        let mut changes = self.app.store.subscribe();
        // Changes to a selected shared mailbox are recorded under its owner.
        let account = self.owner();
        let mut recheck = tokio::time::interval(auth::RECHECK_INTERVAL);
        recheck.tick().await;
        loop {
            tokio::select! {
                _ = recheck.tick() => {
                    if !self.still_signed_in().await {
                        self.line("* BYE the sign-in is no longer valid").await?;
                        return Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "sign-in revoked"));
                    }
                }
                line = self.conn.read_line(MAX_LINE) => {
                    return Ok(match line {
                        Ok(line) if line.eq_ignore_ascii_case(b"DONE") => Ok("IDLE completed".into()),
                        Ok(_) => bad("expected DONE"),
                        Err(_) => Err("BAD connection lost".into()),
                    });
                }
                change = changes.recv() => {
                    // A lagged receiver just means "something changed".
                    if change.as_ref().is_ok_and(|c| c.account_id != account) {
                        continue;
                    }
                    if matches!(change, Err(tokio::sync::broadcast::error::RecvError::Closed)) {
                        return Ok(bad("server shutting down"));
                    }
                    self.sync().await?;
                }
            }
        }
    }
}

async fn handle(app: AppState, tcp: TcpStream, peer: SocketAddr, starttls: bool) {
    let Some(_guard) = app.accept_connection(peer.ip()) else { return };
    Metrics::inc(&app.metrics.imap_connections);
    let _ = tcp.set_nodelay(true);
    let conn = if starttls {
        Conn::plain(tcp, LOGIN_TIMEOUT)
    } else {
        match Conn::accept_tls(tcp, app.tls.server_config(&[]), LOGIN_TIMEOUT).await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::debug!(%err, %peer, "TLS handshake failed");
                return;
            }
        }
    };
    let session = Session { app, conn, peer, account: None, grant: None, selected: None, errors: 0, login_failures: 0, condstore: false, qresync: false, oauth: false, rev2: false };
    if let Err(err) = session.run().await {
        tracing::debug!(%err, %peer, "IMAP session ended with an error");
    }
}

/// Serves IMAP over implicit TLS (port 993).
pub async fn serve(app: AppState, listener: TcpListener) {
    serve_mode(app, listener, false).await
}

/// Serves IMAP with mandatory STARTTLS (port 143).
pub async fn serve_starttls(app: AppState, listener: TcpListener) {
    serve_mode(app, listener, true).await
}

async fn serve_mode(app: AppState, listener: TcpListener, starttls: bool) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                tokio::spawn(handle(app.clone(), tcp, peer, starttls));
            }
            Err(err) => {
                tracing::warn!(%err, "failed to accept IMAP connection");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
