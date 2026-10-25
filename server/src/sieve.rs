//! Sieve mail filtering (RFC 5228). Scripts are parsed and validated when saved and
//! interpreted at delivery time under strict resource limits. Extensions (see `SUPPORTED`):
//! fileinto, envelope, encoded-character (RFC 5228); body (5173); environment (5183);
//! variables (5229); vacation (5230) with vacation-seconds (6131); relational (5231);
//! imap4flags (5232); subaddress (5233); spamtest and virustest (5235); date and index
//! (5260); editheader (5293); reject and ereject (5429); enotify with mailto (5435, 5436);
//! ihave (5463); mailbox (5490); foreverypart, mime and extracttext (5703); copy (3894);
//! extlists (6134) with the user's address book; include (6609); duplicate (7352);
//! special-use (8579); fcc (8580); mailboxid (9042); regex (draft); comparators
//! i;ascii-casemap, i;octet and i;ascii-numeric (4790).

use std::collections::{HashMap, HashSet};

use mail_parser::{MessageParser, MimeHeaders};

use crate::{security::authn::find_header_end, util::Address};

pub const MAX_SCRIPT_BYTES: usize = 64 * 1024;
const MAX_DEPTH: usize = 16;
pub const MAX_REDIRECTS: usize = 5;
const MAX_FILEINTO: usize = 10;
const MAX_INCLUDE_DEPTH: usize = 5;
const MAX_VARIABLES: usize = 100;
const MAX_VARIABLE_BYTES: usize = 4000;
const MAX_NOTIFY: usize = 3;
const MAX_HEADER_EDITS: usize = 50;
const MAX_PARTS: usize = 200;
/// Duplicate tracking lasts this long unless `:seconds` says otherwise, and never longer than the maximum.
pub const DUPLICATE_DEFAULT_SECONDS: i64 = 7 * 86400;
const DUPLICATE_MAX_SECONDS: i64 = 90 * 86400;
pub const SUPPORTED: &[&str] = &[
    "fileinto", "envelope", "encoded-character", "imap4flags", "copy", "body", "mailbox", "regex", "variables", "vacation", "vacation-seconds", "include",
    "relational", "subaddress", "spamtest", "virustest", "date", "index", "editheader", "reject", "ereject", "enotify", "ihave", "environment",
    "foreverypart", "mime", "extracttext", "extlists", "duplicate", "special-use", "fcc", "mailboxid",
    "comparator-i;ascii-casemap", "comparator-i;octet", "comparator-i;ascii-numeric",
];

/// The external list naming the user's address book (RFC 6134).
pub const ADDRESS_BOOK: &str = "urn:ietf:params:sieve:addrbook:default";
/// Headers a script may neither add nor delete (RFC 5293 section 6): the trace of the message
/// and the server's own verdicts.
const PROTECTED_HEADERS: &[&str] = &["received", "return-path", "delivered-to", "x-unomail-filter", "x-virus-status", "dkim-signature", "authentication-results", "arc-seal", "arc-message-signature", "arc-authentication-results"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SieveError {
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for SieveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Tag(String),
    Number(u64),
    Str(String),
    Punct(char),
}

fn tokenize(src: &str) -> Result<Vec<(Token, usize)>, SieveError> {
    let bytes = src.as_bytes();
    let mut tokens = Vec::new();
    let (mut i, mut line) = (0, 1);
    let err = |line: usize, message: &str| SieveError { line, message: message.into() };
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'\n' => {
                line += 1;
                i += 1;
            }
            b' ' | b'\t' | b'\r' => i += 1,
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let end = src[i + 2..].find("*/").ok_or_else(|| err(line, "unterminated comment"))?;
                line += src[i..i + 2 + end].matches('\n').count();
                i += end + 4;
            }
            b'"' => {
                let start_line = line;
                let mut out = Vec::new();
                i += 1;
                loop {
                    match bytes.get(i) {
                        None => return Err(err(start_line, "unterminated string")),
                        Some(b'"') => break,
                        Some(b'\\') => {
                            out.push(*bytes.get(i + 1).ok_or_else(|| err(start_line, "unterminated string"))?);
                            i += 2;
                        }
                        Some(b) => {
                            if *b == b'\n' {
                                line += 1;
                            }
                            out.push(*b);
                            i += 1;
                        }
                    }
                }
                i += 1;
                tokens.push((Token::Str(String::from_utf8(out).map_err(|_| err(start_line, "invalid UTF-8 in string"))?), start_line));
            }
            b'{' | b'}' | b'(' | b')' | b'[' | b']' | b',' | b';' => {
                tokens.push((Token::Punct(c as char), line));
                i += 1;
            }
            b':' => {
                let start = i + 1;
                i = start;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                if i == start {
                    return Err(err(line, "expected a tag name after ':'"));
                }
                tokens.push((Token::Tag(src[start..i].to_ascii_lowercase()), line));
            }
            b'0'..=b'9' => {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let mut value: u64 = src[start..i].parse().map_err(|_| err(line, "number too large"))?;
                let multiplier = match bytes.get(i).map(u8::to_ascii_uppercase) {
                    Some(b'K') => 1 << 10,
                    Some(b'M') => 1 << 20,
                    Some(b'G') => 1 << 30,
                    _ => 1,
                };
                if multiplier > 1 {
                    i += 1;
                }
                value = value.checked_mul(multiplier).ok_or_else(|| err(line, "number too large"))?;
                tokens.push((Token::Number(value), line));
            }
            _ if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let ident = src[start..i].to_ascii_lowercase();
                // Multi-line string: text: <newline> ... <newline> "."
                if ident == "text" && bytes.get(i) == Some(&b':') {
                    let start_line = line;
                    let after = src[i + 1..].find('\n').ok_or_else(|| err(line, "unterminated multi-line string"))? + i + 2;
                    let mut out = String::new();
                    let mut pos = after;
                    line += 1;
                    loop {
                        let end = src[pos..].find('\n').map(|e| e + pos).ok_or_else(|| err(start_line, "unterminated multi-line string"))?;
                        let text_line = src[pos..end].trim_end_matches('\r');
                        pos = end + 1;
                        line += 1;
                        if text_line == "." {
                            break;
                        }
                        out.push_str(text_line.strip_prefix('.').filter(|_| text_line.starts_with("..")).unwrap_or(text_line));
                        out.push_str("\r\n");
                    }
                    i = pos;
                    tokens.push((Token::Str(out), start_line));
                } else {
                    tokens.push((Token::Ident(ident), line));
                }
            }
            _ => return Err(err(line, &format!("unexpected character {:?}", c as char))),
        }
    }
    Ok(tokens)
}

/// A relational operator (RFC 5231).
#[derive(Debug, Clone, Copy, PartialEq)]
enum Rel {
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
    Ne,
}

impl Rel {
    fn parse(name: &str) -> Option<Rel> {
        Some(match name.to_ascii_lowercase().as_str() {
            "gt" => Rel::Gt,
            "ge" => Rel::Ge,
            "lt" => Rel::Lt,
            "le" => Rel::Le,
            "eq" => Rel::Eq,
            "ne" => Rel::Ne,
            _ => return None,
        })
    }

    fn holds(self, order: std::cmp::Ordering) -> bool {
        use std::cmp::Ordering::*;
        match self {
            Rel::Gt => order == Greater,
            Rel::Ge => order != Less,
            Rel::Lt => order == Less,
            Rel::Le => order != Greater,
            Rel::Eq => order == Equal,
            Rel::Ne => order != Equal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Match {
    Is,
    Contains,
    Matches,
    Regex,
    /// `:value` (relational): the values compared with the operator.
    Value(Rel),
    /// `:count` (relational): the number of values compared with the operator.
    Count(Rel),
    /// `:list` (extlists): the value is in one of the named lists.
    List,
}

/// Comparators (RFC 4790).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
enum Comparator {
    #[default]
    CaseMap,
    Octet,
    Numeric,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Part {
    All,
    Local,
    Domain,
    /// `:user` and `:detail` (subaddress): the parts of the local part around `+`.
    User,
    Detail,
}

/// What a `:mime` header test looks at (RFC 5703).
#[derive(Debug, Clone, PartialEq)]
enum MimeOption {
    Value,
    Type,
    Subtype,
    ContentType,
    Param(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Zone {
    /// The server's time zone (UTC).
    Server,
    /// As written in the header (`:originalzone`).
    Original,
    /// `:zone "+hhmm"`, in minutes.
    Fixed(i32),
}

/// The tagged arguments a test was given.
#[derive(Debug, Clone)]
struct Spec {
    how: Match,
    cmp: Comparator,
    part: Part,
    /// `:index n [:last]` (RFC 5260): only the n-th occurrence.
    index: Option<(usize, bool)>,
    mime: Option<MimeOption>,
    any_child: bool,
    zone: Zone,
}

impl Default for Spec {
    fn default() -> Self {
        Spec { how: Match::Is, cmp: Comparator::CaseMap, part: Part::All, index: None, mime: None, any_child: false, zone: Zone::Server }
    }
}

#[derive(Debug, Clone)]
enum Test {
    True,
    False,
    Not(Box<Test>),
    AllOf(Vec<Test>),
    AnyOf(Vec<Test>),
    Exists { names: Vec<String>, spec: Spec },
    Size { over: bool, limit: u64 },
    Header { names: Vec<String>, keys: Vec<String>, spec: Spec },
    Address { names: Vec<String>, keys: Vec<String>, spec: Spec },
    Envelope { names: Vec<String>, keys: Vec<String>, spec: Spec },
    Body { keys: Vec<String>, spec: Spec },
    /// `string` test of the variables extension.
    Str { sources: Vec<String>, keys: Vec<String>, spec: Spec },
    Date { header: String, part: String, keys: Vec<String>, spec: Spec },
    CurrentDate { part: String, keys: Vec<String>, spec: Spec },
    Environment { name: String, keys: Vec<String>, spec: Spec },
    Ihave(Vec<String>),
    Spam { keys: Vec<String>, spec: Spec },
    Virus { keys: Vec<String>, spec: Spec },
    Duplicate { handle: String, header: Option<String>, unique_id: Option<String>, seconds: i64, last: bool },
    MailboxExists(Vec<String>),
    SpecialUseExists { mailbox: Option<String>, uses: Vec<String> },
    MailboxIdExists(Vec<String>),
    ValidNotifyMethod(Vec<String>),
    NotifyMethodCapability { method: String, capability: String, keys: Vec<String>, spec: Spec },
    ValidExtList(Vec<String>),
}

/// A mailbox to file into: by name, or by special use or id with the name as fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInto {
    pub mailbox: String,
    pub special_use: Option<String>,
    pub mailbox_id: Option<String>,
    pub create: bool,
    pub flags: Vec<String>,
}

/// `:fcc` (RFC 8580): where a copy of a sent reply or notification is kept.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Fcc {
    pub mailbox: String,
    pub create: bool,
    pub flags: Vec<String>,
}

/// A notification requested by `notify` (RFC 5435), sent by e-mail (RFC 5436).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    /// The `mailto:` address.
    pub to: String,
    pub subject: String,
    pub message: String,
    /// 1 high, 2 normal, 3 low.
    pub importance: u8,
    pub fcc: Option<Fcc>,
}

#[derive(Debug, Clone)]
enum Command {
    If(Vec<(Option<Test>, Vec<Command>)>),
    Stop,
    /// Leaves the current included script.
    Return,
    Keep { flags: Vec<String> },
    Discard,
    FileInto { mailbox: String, copy: bool, create: bool, flags: Vec<String>, special_use: Option<String>, mailbox_id: Option<String> },
    Redirect { address: String, copy: bool },
    Flags { op: FlagOp, flags: Vec<String> },
    Set { name: String, value: String, modifiers: Vec<String> },
    Vacation(Vacation),
    /// The commands of an included script; `once` scripts carry their name.
    Include { commands: Vec<Command>, once: Option<String> },
    Reject { reason: String },
    /// `error` (ihave): the script fails, so the message is kept.
    Error,
    AddHeader { name: String, value: String, last: bool },
    DeleteHeader { name: String, values: Vec<String>, spec: Spec },
    Notify { method: String, importance: u8, message: Option<String>, fcc: Option<Fcc> },
    ForEveryPart { name: Option<String>, commands: Vec<Command> },
    Break { name: Option<String> },
    ExtractText { name: String, first: Option<usize>, modifiers: Vec<String> },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum FlagOp {
    Set,
    Add,
    Remove,
}

/// An autoreply requested by the `vacation` action (RFC 5230).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vacation {
    pub days: i64,
    /// `:seconds` (RFC 6131), in place of `:days`.
    pub seconds: Option<i64>,
    /// `:fcc` (RFC 8580): keep a copy of the reply.
    pub fcc: Option<Fcc>,
    pub subject: String,
    pub reason: String,
    /// Additional addresses of the user; mail to them is also answered.
    pub addresses: Vec<String>,
    /// Distinguishes different replies for the once-per-sender rule.
    pub handle: String,
    /// The reason is a complete MIME entity (`Content-*` headers, blank line, body).
    pub mime: bool,
}

/// A validated, executable script.
#[derive(Debug, Clone)]
pub struct Script {
    commands: Vec<Command>,
    /// Whether `${...}` references are expanded (the script requires `variables`).
    variables: bool,
    /// Whether the message's MIME structure is needed (`mime` or `foreverypart`).
    mime: bool,
}

impl Script {
    /// The addresses the script may redirect mail to, as written: one built from variables
    /// is returned unexpanded (it can name any address).
    pub fn redirect_targets(&self) -> Vec<String> {
        fn walk(commands: &[Command], out: &mut Vec<String>) {
            for command in commands {
                match command {
                    Command::Redirect { address, .. } if !out.contains(address) => out.push(address.clone()),
                    // Notifications are sent on the user's behalf too.
                    Command::Notify { method, .. } => {
                        let address = method.strip_prefix("mailto:").unwrap_or(method).split('?').next().unwrap_or_default().to_owned();
                        if !out.contains(&address) {
                            out.push(address);
                        }
                    }
                    Command::If(branches) => branches.iter().for_each(|(_, body)| walk(body, out)),
                    Command::Include { commands, .. } | Command::ForEveryPart { commands, .. } => walk(commands, out),
                    _ => {}
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.commands, &mut out);
        out
    }
}

/// Looks up a script for `include`: one of the user's own, or (second argument) a global
/// script provided by the administrator.
pub type Loader<'a> = &'a dyn Fn(&str, bool) -> Option<String>;

struct Parser<'a> {
    tokens: Vec<(Token, usize)>,
    pos: usize,
    required: Vec<String>,
    loader: Loader<'a>,
    /// Names of the scripts currently being included (cycle detection).
    including: Vec<String>,
    /// Set when this script or one it includes requires `variables`.
    uses_variables: bool,
    /// Names of the enclosing `foreverypart` loops (for `break :name`); `""` for unnamed ones.
    loops: Vec<String>,
}

fn has_variable(text: &str) -> bool {
    text.contains("${")
}

impl Parser<'_> {
    fn line(&self) -> usize {
        self.tokens.get(self.pos).or(self.tokens.last()).map_or(1, |t| t.1)
    }

    fn err<T>(&self, message: impl Into<String>) -> Result<T, SieveError> {
        Err(SieveError { line: self.line(), message: message.into() })
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|t| &t.0)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).map(|t| t.0.clone());
        self.pos += 1;
        token
    }

    fn expect(&mut self, c: char) -> Result<(), SieveError> {
        if self.peek() == Some(&Token::Punct(c)) {
            self.pos += 1;
            Ok(())
        } else {
            self.err(format!("expected '{c}'"))
        }
    }

    fn has(&self, extension: &str) -> bool {
        self.required.iter().any(|r| r == extension)
    }

    fn need(&self, extension: &str, what: &str) -> Result<(), SieveError> {
        if self.has(extension) { Ok(()) } else { self.err(format!("{what} needs: require \"{extension}\";")) }
    }

    /// True when `text` will be expanded at run time and cannot be validated now.
    fn dynamic(&self, text: &str) -> bool {
        self.has("variables") && has_variable(text)
    }

    fn string(&mut self) -> Result<String, SieveError> {
        match self.next() {
            Some(Token::Str(s)) if self.has("encoded-character") => decode_encoded(&s).map_err(|message| SieveError { line: self.line(), message }),
            Some(Token::Str(s)) => Ok(s),
            _ => {
                self.pos -= 1;
                self.err("expected a string")
            }
        }
    }

    fn number(&mut self) -> Result<u64, SieveError> {
        match self.next() {
            Some(Token::Number(n)) => Ok(n),
            _ => {
                self.pos -= 1;
                self.err("expected a number")
            }
        }
    }

    fn string_list(&mut self) -> Result<Vec<String>, SieveError> {
        if self.peek() != Some(&Token::Punct('[')) {
            return Ok(vec![self.string()?]);
        }
        self.pos += 1;
        let mut out = vec![self.string()?];
        while self.peek() == Some(&Token::Punct(',')) {
            self.pos += 1;
            out.push(self.string()?);
        }
        self.expect(']')?;
        if out.len() > 100 {
            return self.err("string list is too long");
        }
        if self.has("encoded-character") {
            out = out.iter().map(|s| decode_encoded(s)).collect::<Result<_, _>>().map_err(|message| SieveError { line: self.line(), message })?;
        }
        Ok(out)
    }

    /// Parses the tagged arguments of a test. `allowed` names the optional groups the test
    /// takes: `part` (address parts), `index`, `mime`, `zone`, `body` (body transforms),
    /// `percent` (spamtest).
    fn match_tags(&mut self, allowed: &[&str]) -> Result<Spec, SieveError> {
        let mut spec = Spec::default();
        let allows = |group: &str| allowed.contains(&group);
        let mut explicit_comparator = false;
        while let Some(Token::Tag(tag)) = self.peek().cloned() {
            self.pos += 1;
            match tag.as_str() {
                "is" => spec.how = Match::Is,
                "contains" => spec.how = Match::Contains,
                "matches" => spec.how = Match::Matches,
                "regex" => {
                    self.need("regex", ":regex")?;
                    spec.how = Match::Regex;
                }
                "value" | "count" => {
                    self.need("relational", &format!(":{tag}"))?;
                    let operator = self.string()?;
                    let Some(rel) = Rel::parse(&operator) else { return self.err(format!("unknown relational operator \"{operator}\"")) };
                    spec.how = if tag == "value" { Match::Value(rel) } else { Match::Count(rel) };
                }
                "list" => {
                    self.need("extlists", ":list")?;
                    spec.how = Match::List;
                }
                "comparator" => {
                    let name = self.string()?.to_ascii_lowercase();
                    spec.cmp = match name.as_str() {
                        "i;ascii-casemap" => Comparator::CaseMap,
                        "i;octet" => Comparator::Octet,
                        "i;ascii-numeric" => {
                            self.need("comparator-i;ascii-numeric", "the i;ascii-numeric comparator")?;
                            Comparator::Numeric
                        }
                        _ => return self.err(format!("unsupported comparator \"{name}\"")),
                    };
                    explicit_comparator = true;
                }
                "all" if allows("part") => spec.part = Part::All,
                "localpart" if allows("part") => spec.part = Part::Local,
                "domain" if allows("part") => spec.part = Part::Domain,
                "user" | "detail" if allows("part") => {
                    self.need("subaddress", &format!(":{tag}"))?;
                    spec.part = if tag == "user" { Part::User } else { Part::Detail };
                }
                "index" if allows("index") => {
                    self.need("index", ":index")?;
                    let n = self.number()?;
                    if n == 0 {
                        return self.err(":index counts from 1");
                    }
                    spec.index = Some((n as usize, spec.index.is_some_and(|(_, last)| last)));
                }
                "last" if allows("index") => {
                    self.need("index", ":last")?;
                    spec.index = Some((spec.index.map_or(1, |(n, _)| n), true));
                }
                "mime" if allows("mime") => {
                    self.need("mime", ":mime")?;
                    spec.mime.get_or_insert(MimeOption::Value);
                }
                "anychild" if allows("mime") => {
                    self.need("mime", ":anychild")?;
                    spec.any_child = true;
                }
                "type" | "subtype" | "contenttype" | "param" if allows("mime") => {
                    self.need("mime", &format!(":{tag}"))?;
                    spec.mime = Some(match tag.as_str() {
                        "type" => MimeOption::Type,
                        "subtype" => MimeOption::Subtype,
                        "contenttype" => MimeOption::ContentType,
                        _ => MimeOption::Param(self.string_list()?.iter().map(|p| p.to_ascii_lowercase()).collect()),
                    });
                }
                "zone" if allows("zone") => {
                    let zone = self.string()?;
                    let Some(minutes) = parse_zone(&zone) else { return self.err(format!("invalid time zone \"{zone}\"")) };
                    spec.zone = Zone::Fixed(minutes);
                }
                "originalzone" if allows("zone") => spec.zone = Zone::Original,
                "text" | "raw" if allows("body") => {}
                "content" if allows("body") => {
                    self.string_list()?;
                }
                "percent" if allows("percent") => return self.err(":percent needs spamtestplus, which is not supported"),
                other => return self.err(format!("unsupported tag :{other}")),
            }
        }
        if spec.cmp == Comparator::Numeric && matches!(spec.how, Match::Contains | Match::Matches | Match::Regex) {
            return self.err("the i;ascii-numeric comparator only supports :is, :value and :count");
        }
        // :count always compares numbers (RFC 5231 section 4.2).
        if matches!(spec.how, Match::Count(_)) && !explicit_comparator {
            spec.cmp = Comparator::Numeric;
        }
        if spec.any_child && spec.mime.is_none() {
            return self.err(":anychild needs :mime");
        }
        if spec.mime.is_some() && spec.index.is_some() {
            return self.err(":index cannot be combined with :mime");
        }
        Ok(spec)
    }

    /// Key list of a test; regular expressions are compiled once here to report mistakes.
    fn keys(&mut self, spec: &Spec) -> Result<Vec<String>, SieveError> {
        let keys = self.string_list()?;
        if spec.how == Match::Regex {
            for key in keys.iter().filter(|k| !self.dynamic(k)) {
                if let Err(err) = build_regex(key) {
                    return self.err(format!("invalid regular expression: {err}"));
                }
            }
        }
        if spec.how == Match::List {
            for key in keys.iter().filter(|k| !self.dynamic(k)) {
                if !valid_ext_list(key) {
                    return self.err(format!("unknown list \"{key}\""));
                }
            }
        }
        Ok(keys)
    }

    /// `:fcc mailbox [:create] [:flags list]` after the tag was read.
    fn fcc(&mut self) -> Result<Fcc, SieveError> {
        self.need("fcc", ":fcc")?;
        let mailbox = self.string()?;
        if !self.dynamic(&mailbox) && crate::store::validate_mailbox_name(&mailbox).is_err() {
            return self.err("invalid :fcc mailbox name");
        }
        Ok(Fcc { mailbox, ..Default::default() })
    }

    fn test(&mut self, depth: usize) -> Result<Test, SieveError> {
        if depth > MAX_DEPTH {
            return self.err("tests are nested too deeply");
        }
        let Some(Token::Ident(name)) = self.next() else {
            self.pos -= 1;
            return self.err("expected a test");
        };
        Ok(match name.as_str() {
            "true" => Test::True,
            "false" => Test::False,
            "not" => Test::Not(Box::new(self.test(depth + 1)?)),
            "allof" | "anyof" => {
                self.expect('(')?;
                let mut tests = vec![self.test(depth + 1)?];
                while self.peek() == Some(&Token::Punct(',')) {
                    self.pos += 1;
                    tests.push(self.test(depth + 1)?);
                }
                self.expect(')')?;
                if name == "allof" { Test::AllOf(tests) } else { Test::AnyOf(tests) }
            }
            "exists" => {
                let spec = self.match_tags(&["mime"])?;
                Test::Exists { names: self.string_list()?, spec }
            }
            "size" => {
                let over = match self.next() {
                    Some(Token::Tag(t)) if t == "over" => true,
                    Some(Token::Tag(t)) if t == "under" => false,
                    _ => {
                        self.pos -= 1;
                        return self.err("size needs :over or :under");
                    }
                };
                match self.next() {
                    Some(Token::Number(limit)) => Test::Size { over, limit },
                    _ => {
                        self.pos -= 1;
                        return self.err("size needs a number");
                    }
                }
            }
            "header" => {
                let spec = self.match_tags(&["index", "mime"])?;
                let names = self.string_list()?;
                Test::Header { names, keys: self.keys(&spec)?, spec }
            }
            "address" | "envelope" => {
                if name == "envelope" {
                    self.need("envelope", "the envelope test")?;
                }
                let spec = self.match_tags(if name == "envelope" { &["part"] } else { &["part", "index", "mime"] })?;
                let names = self.string_list()?;
                let keys = self.keys(&spec)?;
                if name == "envelope" {
                    if let Some(bad) = names.iter().find(|n| !matches!(n.to_ascii_lowercase().as_str(), "from" | "to")) {
                        return self.err(format!("unknown envelope part \"{bad}\""));
                    }
                    Test::Envelope { names, keys, spec }
                } else {
                    Test::Address { names, keys, spec }
                }
            }
            "body" => {
                self.need("body", "the body test")?;
                let spec = self.match_tags(&["body"])?;
                Test::Body { keys: self.keys(&spec)?, spec }
            }
            "string" => {
                self.need("variables", "the string test")?;
                let spec = self.match_tags(&[])?;
                let sources = self.string_list()?;
                Test::Str { sources, keys: self.keys(&spec)?, spec }
            }
            "date" | "currentdate" => {
                self.need("date", &format!("the {name} test"))?;
                let spec = self.match_tags(if name == "date" { &["zone", "index"] } else { &["zone"] })?;
                if name == "currentdate" && spec.zone == Zone::Original {
                    return self.err(":originalzone is only for the date test");
                }
                let header = if name == "date" { self.string()? } else { String::new() };
                let part = self.string()?.to_ascii_lowercase();
                if !DATE_PARTS.contains(&part.as_str()) {
                    return self.err(format!("unknown date part \"{part}\""));
                }
                let keys = self.keys(&spec)?;
                if name == "date" { Test::Date { header, part, keys, spec } } else { Test::CurrentDate { part, keys, spec } }
            }
            "environment" => {
                self.need("environment", "the environment test")?;
                let spec = self.match_tags(&[])?;
                let name = self.string()?.to_ascii_lowercase();
                Test::Environment { name, keys: self.keys(&spec)?, spec }
            }
            "ihave" => {
                self.need("ihave", "the ihave test")?;
                Test::Ihave(self.string_list()?)
            }
            "spamtest" | "virustest" => {
                self.need(&name, &format!("the {name} test"))?;
                let spec = self.match_tags(&["percent"])?;
                let keys = self.keys(&spec)?;
                if name == "spamtest" { Test::Spam { keys, spec } } else { Test::Virus { keys, spec } }
            }
            "duplicate" => {
                self.need("duplicate", "the duplicate test")?;
                let (mut handle, mut header, mut unique_id, mut seconds, mut last) = (String::new(), None, None, DUPLICATE_DEFAULT_SECONDS, false);
                while let Some(Token::Tag(tag)) = self.peek().cloned() {
                    self.pos += 1;
                    match tag.as_str() {
                        "handle" => handle = self.string()?,
                        "header" if unique_id.is_none() => header = Some(self.string()?.to_ascii_lowercase()),
                        "uniqueid" if header.is_none() => unique_id = Some(self.string()?),
                        "seconds" => seconds = (self.number()? as i64).min(DUPLICATE_MAX_SECONDS),
                        "last" => last = true,
                        "header" | "uniqueid" => return self.err(":header and :uniqueid cannot be combined"),
                        other => return self.err(format!("unsupported tag :{other}")),
                    }
                }
                Test::Duplicate { handle, header, unique_id, seconds, last }
            }
            "mailboxexists" => {
                self.need("mailbox", "the mailboxexists test")?;
                Test::MailboxExists(self.string_list()?)
            }
            "specialuse_exists" => {
                self.need("special-use", "the specialuse_exists test")?;
                let first = self.string_list()?;
                // With two arguments the first is the mailbox.
                if matches!(self.peek(), Some(Token::Str(_)) | Some(Token::Punct('['))) {
                    let uses = self.string_list()?;
                    Test::SpecialUseExists { mailbox: first.into_iter().next(), uses }
                } else {
                    Test::SpecialUseExists { mailbox: None, uses: first }
                }
            }
            "mailboxidexists" => {
                self.need("mailboxid", "the mailboxidexists test")?;
                Test::MailboxIdExists(self.string_list()?)
            }
            "valid_notify_method" => {
                self.need("enotify", "the valid_notify_method test")?;
                Test::ValidNotifyMethod(self.string_list()?)
            }
            "notify_method_capability" => {
                self.need("enotify", "the notify_method_capability test")?;
                let spec = self.match_tags(&[])?;
                let method = self.string()?;
                let capability = self.string()?.to_ascii_lowercase();
                Test::NotifyMethodCapability { method, capability, keys: self.keys(&spec)?, spec }
            }
            "valid_ext_list" => {
                self.need("extlists", "the valid_ext_list test")?;
                Test::ValidExtList(self.string_list()?)
            }
            other => return self.err(format!("unknown test \"{other}\"")),
        })
    }

    fn block(&mut self, depth: usize) -> Result<Vec<Command>, SieveError> {
        self.expect('{')?;
        let mut commands = Vec::new();
        while self.peek().is_some() && self.peek() != Some(&Token::Punct('}')) {
            if let Some(command) = self.command(depth + 1)? {
                commands.push(command);
            }
        }
        self.expect('}')?;
        Ok(commands)
    }

    fn flags_tag(&mut self) -> Result<Vec<String>, SieveError> {
        self.need("imap4flags", "the :flags argument")?;
        self.string_list()
    }

    fn vacation(&mut self) -> Result<Vacation, SieveError> {
        self.need("vacation", "vacation")?;
        let mut vacation = Vacation { days: 7, ..Default::default() };
        while let Some(Token::Tag(tag)) = self.peek().cloned() {
            self.pos += 1;
            match tag.as_str() {
                "days" => {
                    vacation.days = self.number()? as i64;
                    if !(1..=90).contains(&vacation.days) {
                        return self.err(":days must be between 1 and 90");
                    }
                }
                "seconds" => {
                    self.need("vacation-seconds", ":seconds")?;
                    // RFC 6131: at least an hour is sensible; zero means always reply, which
                    // could loop with another autoresponder, so an hour is the floor.
                    vacation.seconds = Some((self.number()? as i64).clamp(3600, 90 * 86400));
                }
                "fcc" => vacation.fcc = Some(self.fcc()?),
                "create" if vacation.fcc.is_some() => {
                    self.need("mailbox", ":create")?;
                    if let Some(fcc) = &mut vacation.fcc {
                        fcc.create = true;
                    }
                }
                "flags" if vacation.fcc.is_some() => {
                    let flags = self.flags_tag()?;
                    if let Some(fcc) = &mut vacation.fcc {
                        fcc.flags = flags;
                    }
                }
                "subject" => vacation.subject = self.string()?,
                "handle" => vacation.handle = self.string()?,
                "addresses" => vacation.addresses = self.string_list()?.iter().map(|a| a.to_lowercase()).collect(),
                // The reply is always sent from the address the message was delivered to.
                "from" => {
                    self.string()?;
                }
                "mime" => vacation.mime = true,
                other => return self.err(format!("unsupported tag :{other}")),
            }
        }
        vacation.reason = self.string()?;
        if vacation.reason.trim().is_empty() || vacation.reason.len() > 10_000 {
            return self.err("the vacation reason must be between 1 and 10000 characters");
        }
        if vacation.mime && !self.dynamic(&vacation.reason)
            && let Err(problem) = check_mime_entity(&vacation.reason) {
                return self.err(problem);
            }
        Ok(vacation)
    }

    fn include(&mut self, depth: usize) -> Result<Command, SieveError> {
        self.need("include", "include")?;
        let (mut once, mut optional, mut global) = (false, false, false);
        while let Some(Token::Tag(tag)) = self.peek().cloned() {
            self.pos += 1;
            match tag.as_str() {
                "personal" => global = false,
                "global" => global = true,
                "once" => once = true,
                "optional" => optional = true,
                other => return self.err(format!("unsupported tag :{other}")),
            }
        }
        let name = self.string()?;
        if self.including.len() >= MAX_INCLUDE_DEPTH {
            return self.err("scripts are included too deeply");
        }
        // Personal and global scripts live in separate namespaces.
        let key = if global { format!("global:{name}") } else { name.clone() };
        if self.including.contains(&key) {
            return self.err(format!("script \"{name}\" includes itself"));
        }
        let Some(source) = (self.loader)(&name, global) else {
            if optional {
                return Ok(Command::Include { commands: Vec::new(), once: None });
            }
            return self.err(format!("included script \"{name}\" does not exist"));
        };
        let line = self.line();
        let wrap = |err: SieveError| SieveError { line, message: format!("in included script \"{name}\": {err}") };
        let mut including = self.including.clone();
        including.push(key.clone());
        let mut inner = Parser { tokens: tokenize(&source).map_err(wrap)?, pos: 0, required: Vec::new(), loader: self.loader, including, uses_variables: false, loops: Vec::new() };
        let mut commands = Vec::new();
        while inner.peek().is_some() {
            if let Some(command) = inner.command(depth + 1).map_err(wrap)? {
                commands.push(command);
            }
        }
        self.uses_variables |= inner.uses_variables || inner.has("variables");
        Ok(Command::Include { commands, once: once.then_some(key) })
    }

    fn command(&mut self, depth: usize) -> Result<Option<Command>, SieveError> {
        if depth > MAX_DEPTH {
            return self.err("blocks are nested too deeply");
        }
        let Some(Token::Ident(name)) = self.next() else {
            self.pos -= 1;
            return self.err("expected a command");
        };
        let command = match name.as_str() {
            "require" => {
                for extension in self.string_list()? {
                    if !SUPPORTED.contains(&extension.as_str()) {
                        return self.err(format!("unsupported extension \"{extension}\""));
                    }
                    self.required.push(extension);
                }
                self.expect(';')?;
                return Ok(None);
            }
            "if" => {
                let mut branches = vec![(Some(self.test(0)?), self.block(depth)?)];
                loop {
                    match self.peek() {
                        Some(Token::Ident(word)) if word == "elsif" => {
                            self.pos += 1;
                            branches.push((Some(self.test(0)?), self.block(depth)?));
                        }
                        Some(Token::Ident(word)) if word == "else" => {
                            self.pos += 1;
                            branches.push((None, self.block(depth)?));
                            break;
                        }
                        _ => break,
                    }
                }
                return Ok(Some(Command::If(branches)));
            }
            "stop" => Command::Stop,
            "return" => {
                self.need("include", "return")?;
                Command::Return
            }
            "discard" => Command::Discard,
            "keep" => {
                let mut flags = Vec::new();
                while let Some(Token::Tag(tag)) = self.peek().cloned() {
                    self.pos += 1;
                    match tag.as_str() {
                        "flags" => flags = self.flags_tag()?,
                        other => return self.err(format!("unsupported tag :{other}")),
                    }
                }
                Command::Keep { flags }
            }
            "fileinto" => {
                self.need("fileinto", "fileinto")?;
                let (mut copy, mut create, mut flags, mut special_use, mut mailbox_id) = (false, false, Vec::new(), None, None);
                while let Some(Token::Tag(tag)) = self.peek().cloned() {
                    self.pos += 1;
                    match tag.as_str() {
                        "copy" => {
                            self.need("copy", ":copy")?;
                            copy = true;
                        }
                        "create" => {
                            self.need("mailbox", ":create")?;
                            create = true;
                        }
                        "flags" => flags = self.flags_tag()?,
                        "specialuse" => {
                            self.need("special-use", ":specialuse")?;
                            let usage = self.string()?;
                            if !self.dynamic(&usage) && special_use_role(&usage).is_none() {
                                return self.err(format!("unknown special use \"{usage}\""));
                            }
                            special_use = Some(usage);
                        }
                        "mailboxid" => {
                            self.need("mailboxid", ":mailboxid")?;
                            mailbox_id = Some(self.string()?);
                        }
                        other => return self.err(format!("unsupported tag :{other}")),
                    }
                }
                let mailbox = self.string()?;
                if !self.dynamic(&mailbox) && crate::store::validate_mailbox_name(&mailbox).is_err() {
                    return self.err("invalid mailbox name");
                }
                Command::FileInto { mailbox, copy, create, flags, special_use, mailbox_id }
            }
            "redirect" => {
                let mut copy = false;
                while let Some(Token::Tag(tag)) = self.peek().cloned() {
                    self.pos += 1;
                    match tag.as_str() {
                        "copy" => {
                            self.need("copy", ":copy")?;
                            copy = true;
                        }
                        other => return self.err(format!("unsupported tag :{other}")),
                    }
                }
                let address = self.string()?;
                if self.dynamic(&address) {
                    Command::Redirect { address, copy }
                } else {
                    let Some(parsed) = Address::parse(&address) else { return self.err("invalid redirect address") };
                    Command::Redirect { address: parsed.to_string(), copy }
                }
            }
            "setflag" | "addflag" | "removeflag" => {
                self.need("imap4flags", &name)?;
                let op = match name.as_str() {
                    "setflag" => FlagOp::Set,
                    "addflag" => FlagOp::Add,
                    _ => FlagOp::Remove,
                };
                Command::Flags { op, flags: self.string_list()? }
            }
            "set" => {
                self.need("variables", "set")?;
                let mut modifiers = Vec::new();
                while let Some(Token::Tag(tag)) = self.peek().cloned() {
                    self.pos += 1;
                    if !matches!(tag.as_str(), "lower" | "upper" | "lowerfirst" | "upperfirst" | "quotewildcard" | "length") {
                        return self.err(format!("unsupported tag :{tag}"));
                    }
                    modifiers.push(tag);
                }
                let name = self.string()?.to_ascii_lowercase();
                if !valid_variable_name(&name) {
                    return self.err("invalid variable name");
                }
                Command::Set { name, value: self.string()?, modifiers }
            }
            "vacation" => Command::Vacation(self.vacation()?),
            "reject" | "ereject" => {
                self.need(&name, &name)?;
                let reason = self.string()?;
                if reason.len() > 2000 {
                    return self.err("the reason is too long");
                }
                Command::Reject { reason }
            }
            "error" => {
                self.need("ihave", "error")?;
                self.string()?;
                Command::Error
            }
            "addheader" => {
                self.need("editheader", "addheader")?;
                let mut last = false;
                while let Some(Token::Tag(tag)) = self.peek().cloned() {
                    self.pos += 1;
                    match tag.as_str() {
                        "last" => last = true,
                        other => return self.err(format!("unsupported tag :{other}")),
                    }
                }
                let name = self.string()?;
                let value = self.string()?;
                if !self.dynamic(&name) && !editable_header(&name) {
                    return self.err(format!("the header \"{name}\" cannot be added"));
                }
                if value.len() > 998 || (!self.dynamic(&value) && value.contains(['\r', '\n'])) {
                    return self.err("header values must be one line of at most 998 characters");
                }
                Command::AddHeader { name, value, last }
            }
            "deleteheader" => {
                self.need("editheader", "deleteheader")?;
                let spec = self.match_tags(&["index"])?;
                let name = self.string()?;
                if !self.dynamic(&name) && !editable_header(&name) {
                    return self.err(format!("the header \"{name}\" cannot be deleted"));
                }
                let values = if matches!(self.peek(), Some(Token::Str(_)) | Some(Token::Punct('['))) { self.keys(&spec)? } else { Vec::new() };
                Command::DeleteHeader { name, values, spec }
            }
            "notify" => {
                self.need("enotify", "notify")?;
                let (mut importance, mut message, mut fcc) = (2u8, None, None);
                while let Some(Token::Tag(tag)) = self.peek().cloned() {
                    self.pos += 1;
                    match tag.as_str() {
                        // Notifications always come from the script owner's own address.
                        "from" => {
                            self.string()?;
                        }
                        "importance" => {
                            importance = match self.string()?.as_str() {
                                "1" => 1,
                                "2" => 2,
                                "3" => 3,
                                _ => return self.err(":importance must be \"1\", \"2\" or \"3\""),
                            }
                        }
                        "options" => {
                            self.string_list()?;
                        }
                        "message" => message = Some(self.string()?),
                        "fcc" => fcc = Some(self.fcc()?),
                        "create" if fcc.is_some() => {
                            self.need("mailbox", ":create")?;
                            if let Some(fcc) = &mut fcc {
                                fcc.create = true;
                            }
                        }
                        "flags" if fcc.is_some() => {
                            let flags = self.flags_tag()?;
                            if let Some(fcc) = &mut fcc {
                                fcc.flags = flags;
                            }
                        }
                        other => return self.err(format!("unsupported tag :{other}")),
                    }
                }
                let method = self.string()?;
                if !self.dynamic(&method) && mailto_target(&method).is_none() {
                    return self.err("only mailto: notifications are supported");
                }
                Command::Notify { method, importance, message, fcc }
            }
            "foreverypart" => {
                self.need("foreverypart", "foreverypart")?;
                let mut name = None;
                while let Some(Token::Tag(tag)) = self.peek().cloned() {
                    self.pos += 1;
                    match tag.as_str() {
                        "name" => name = Some(self.string()?),
                        other => return self.err(format!("unsupported tag :{other}")),
                    }
                }
                if self.loops.len() >= 4 {
                    return self.err("foreverypart loops are nested too deeply");
                }
                self.loops.push(name.clone().unwrap_or_default());
                let commands = self.block(depth);
                self.loops.pop();
                return Ok(Some(Command::ForEveryPart { name, commands: commands? }));
            }
            "break" => {
                self.need("foreverypart", "break")?;
                let mut name = None;
                while let Some(Token::Tag(tag)) = self.peek().cloned() {
                    self.pos += 1;
                    match tag.as_str() {
                        "name" => name = Some(self.string()?),
                        other => return self.err(format!("unsupported tag :{other}")),
                    }
                }
                match &name {
                    _ if self.loops.is_empty() => return self.err("break outside of foreverypart"),
                    Some(name) if !self.loops.contains(name) => return self.err(format!("no foreverypart loop is named \"{name}\"")),
                    _ => {}
                }
                Command::Break { name }
            }
            "extracttext" => {
                self.need("extracttext", "extracttext")?;
                self.need("variables", "extracttext")?;
                if self.loops.is_empty() {
                    return self.err("extracttext is only allowed inside foreverypart");
                }
                let (mut first, mut modifiers) = (None, Vec::new());
                while let Some(Token::Tag(tag)) = self.peek().cloned() {
                    self.pos += 1;
                    match tag.as_str() {
                        "first" => first = Some(self.number()? as usize),
                        "lower" | "upper" | "lowerfirst" | "upperfirst" | "quotewildcard" | "length" => modifiers.push(tag),
                        other => return self.err(format!("unsupported tag :{other}")),
                    }
                }
                let name = self.string()?.to_ascii_lowercase();
                if !valid_variable_name(&name) {
                    return self.err("invalid variable name");
                }
                Command::ExtractText { name, first, modifiers }
            }
            "include" => {
                let command = self.include(depth)?;
                self.expect(';')?;
                return Ok(Some(command));
            }
            other => return self.err(format!("unknown command \"{other}\"")),
        };
        self.expect(';')?;
        Ok(Some(command))
    }
}

/// Parses and validates a script that does not include other scripts.
pub fn compile(source: &str) -> Result<Script, SieveError> {
    compile_with(source, &|_, _| None)
}

/// Parses and validates a script, resolving `include` through `loader`.
pub fn compile_with(source: &str, loader: Loader<'_>) -> Result<Script, SieveError> {
    if source.len() > MAX_SCRIPT_BYTES {
        return Err(SieveError { line: 1, message: "the script is too large".into() });
    }
    let mut parser = Parser { tokens: tokenize(source)?, pos: 0, required: Vec::new(), loader, including: Vec::new(), uses_variables: false, loops: Vec::new() };
    let mut commands = Vec::new();
    while parser.peek().is_some() {
        if let Some(command) = parser.command(0)? {
            commands.push(command);
        }
    }
    let variables = parser.uses_variables || parser.has("variables");
    let mime = parser.has("mime") || parser.has("foreverypart");
    Ok(Script { commands, variables, mime })
}

/// What should happen to a message after the script ran.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Deliver to the inbox (with these flags).
    pub keep: Option<Vec<String>>,
    pub fileinto: Vec<FileInto>,
    pub redirect: Vec<String>,
    pub vacation: Option<Vacation>,
    /// `reject` / `ereject`: refuse the message with this reason.
    pub reject: Option<String>,
    pub notify: Vec<Notification>,
    /// Duplicate-tracking keys to record once the message is delivered, with their lifetime in seconds.
    pub duplicates: Vec<(String, i64)>,
    /// The message as the script's `addheader`/`deleteheader` left it, when it changed.
    pub edited: Option<Vec<u8>>,
}

/// A mailbox of the account, for `mailboxexists`, `:specialuse` and `:mailboxid`.
#[derive(Debug, Clone, Default)]
pub struct MailboxInfo {
    /// The JMAP id (`b<number>`).
    pub id: String,
    pub name: String,
    pub role: Option<String>,
}

/// What the delivery knows about the message and the account, beyond the message itself.
#[derive(Debug, Clone, Default)]
pub struct Context {
    /// spamtest (RFC 5235): 0 not tested, 1 surely not spam … 10 surely spam.
    pub spam: u8,
    /// virustest: 0 not tested, 1 clean … 5 infected.
    pub virus: u8,
    /// Now, as a Unix time (for `currentdate`).
    pub now: i64,
    /// The recipient's domain and the server's host name (`environment`).
    pub domain: String,
    pub host: String,
    pub remote_ip: String,
    pub mailboxes: Vec<MailboxInfo>,
    /// Duplicate-tracking keys still in force.
    pub duplicates: HashSet<String>,
    /// Addresses in the user's address book, lowercase (extlists).
    pub contacts: HashSet<String>,
}

static NO_CONTEXT: std::sync::LazyLock<Context> = std::sync::LazyLock::new(Context::default);

pub struct Envelope<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub raw: &'a [u8],
    pub context: &'a Context,
}

impl<'a> Envelope<'a> {
    /// An envelope without delivery context (scripts see no spam score, mailboxes or contacts).
    pub fn new(from: &'a str, to: &'a str, raw: &'a [u8]) -> Self {
        Envelope { from, to, raw, context: &NO_CONTEXT }
    }
}

enum Flow {
    Continue,
    Return,
    Stop,
    /// `break`, with the loop's name if one was given.
    Break(Option<String>),
}

/// One MIME part, for `foreverypart` and `:mime` tests.
#[derive(Debug, Default)]
struct MimePart {
    /// Header names and unfolded values.
    headers: Vec<(String, String)>,
    ctype: String,
    subtype: String,
    params: Vec<(String, String)>,
    text: Option<String>,
    children: Vec<usize>,
}

struct Runtime<'a> {
    env: &'a Envelope<'a>,
    headers: HashMap<String, Vec<String>>,
    addresses: HashMap<String, Vec<String>>,
    /// The header block as written (name, raw value with folding): what `editheader` edits.
    header_list: Vec<(String, String)>,
    body: &'a [u8],
    edits: usize,
    edited: bool,
    parts: Vec<MimePart>,
    current_part: Option<usize>,
    flags: Vec<String>,
    implicit_keep: bool,
    explicit_keep: bool,
    failed: bool,
    outcome: Outcome,
    variables: HashMap<String, String>,
    /// `${0}`..`${9}` from the most recent successful :matches or :regex test.
    captures: std::cell::RefCell<Vec<String>>,
    /// Duplicate-tracking keys seen or recorded during this run.
    duplicate_keys: std::cell::RefCell<Vec<(String, i64)>>,
    included_once: Vec<String>,
    expand_variables: bool,
}

/// Validates the reason of `vacation :mime`: a header block made of `Content-*` fields only,
/// a blank line, and a body. Any other header (From, Bcc, ...) is refused so a script cannot
/// rewrite the envelope-relevant headers of the reply.
pub fn check_mime_entity(reason: &str) -> Result<(), &'static str> {
    let normalized = reason.replace("\r\n", "\n");
    let Some((headers, body)) = normalized.split_once("\n\n") else { return Err("a :mime reason needs MIME headers, a blank line and a body") };
    let mut has_type = false;
    for line in headers.lines() {
        if line.starts_with([' ', '\t']) {
            continue;
        }
        let Some((name, _)) = line.split_once(':') else { return Err("a :mime reason must start with MIME headers") };
        if !name.to_ascii_lowercase().starts_with("content-") {
            return Err("only Content-* headers are allowed in a :mime reason");
        }
        has_type |= name.eq_ignore_ascii_case("content-type");
    }
    if !has_type {
        return Err("a :mime reason needs a Content-Type header");
    }
    if body.trim().is_empty() { Err("the :mime reason has an empty body") } else { Ok(()) }
}

fn valid_variable_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && !name.starts_with(|c: char| c.is_ascii_digit()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// `${hex:..}` and `${unicode:..}` (RFC 5228 section 2.4.2.4).
fn decode_encoded(text: &str) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            out.push_str(&rest[start..]);
            return Ok(out);
        };
        let inner = &after[..end];
        let lower = inner.to_ascii_lowercase();
        if let Some(hex) = lower.strip_prefix("hex:") {
            let mut bytes = Vec::new();
            for chunk in hex.split_whitespace() {
                bytes.push(u8::from_str_radix(chunk, 16).map_err(|_| "invalid ${hex:...} encoding".to_owned())?);
            }
            out.push_str(&String::from_utf8(bytes).map_err(|_| "${hex:...} must encode UTF-8".to_owned())?);
        } else if let Some(code_points) = lower.strip_prefix("unicode:") {
            for chunk in code_points.split_whitespace() {
                let c = u32::from_str_radix(chunk, 16).ok().and_then(char::from_u32).ok_or("invalid ${unicode:...} encoding")?;
                out.push(c);
            }
        } else {
            // Not an encoding: a variable reference, left as written.
            out.push_str(&rest[start..start + 2 + end + 1]);
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The mailbox role a special-use attribute (RFC 6154) stands for.
pub fn special_use_role(usage: &str) -> Option<&'static str> {
    Some(match usage.to_ascii_lowercase().as_str() {
        "\\inbox" => "inbox",
        "\\drafts" => "drafts",
        "\\sent" => "sent",
        "\\junk" => "junk",
        "\\trash" => "trash",
        "\\archive" => "archive",
        "\\all" => "all",
        "\\flagged" => "flagged",
        _ => return None,
    })
}

fn editable_header(name: &str) -> bool {
    !name.is_empty() && name.len() <= 76 && name.bytes().all(|b| b.is_ascii_graphic() && b != b':') && !PROTECTED_HEADERS.contains(&name.to_ascii_lowercase().as_str())
}

/// The address of a `mailto:` notification method.
fn mailto_target(method: &str) -> Option<Address> {
    let rest = method.strip_prefix("mailto:").or_else(|| method.strip_prefix("MAILTO:"))?;
    let address = rest.split('?').next()?;
    let decoded = percent_decode(address);
    Address::parse(&decoded)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(&text[i + 1..i + 3], 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Lists the extlists extension knows: the user's address book.
fn valid_ext_list(name: &str) -> bool {
    name.eq_ignore_ascii_case(ADDRESS_BOOK) || name.eq_ignore_ascii_case(":addrbook:default")
}

const DATE_PARTS: &[&str] = &["year", "month", "day", "date", "julian", "hour", "minute", "second", "time", "iso8601", "std11", "zone", "weekday"];

/// `+hhmm` / `-hhmm` in minutes.
fn parse_zone(zone: &str) -> Option<i32> {
    let (sign, digits) = match zone.as_bytes().first()? {
        b'+' => (1, &zone[1..]),
        b'-' => (-1, &zone[1..]),
        _ => return None,
    };
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (hours, minutes) = (digits[..2].parse::<i32>().ok()?, digits[2..].parse::<i32>().ok()?);
    (hours <= 14 && minutes < 60).then_some(sign * (hours * 60 + minutes))
}

/// A date part (RFC 5260 section 4.2) of `when`.
fn date_part(when: time::OffsetDateTime, part: &str) -> String {
    let offset = when.offset().whole_minutes();
    let zone = format!("{}{:02}{:02}", if offset < 0 { '-' } else { '+' }, offset.unsigned_abs() / 60, offset.unsigned_abs() % 60);
    let (year, month, day) = (when.year(), u8::from(when.month()), when.day());
    let (hour, minute, second) = (when.hour(), when.minute(), when.second());
    match part {
        "year" => format!("{year:04}"),
        "month" => format!("{month:02}"),
        "day" => format!("{day:02}"),
        "date" => format!("{year:04}-{month:02}-{day:02}"),
        // Modified Julian Day: days since 1858-11-17.
        "julian" => (when.date().to_julian_day() - 2_400_001).to_string(),
        "hour" => format!("{hour:02}"),
        "minute" => format!("{minute:02}"),
        "second" => format!("{second:02}"),
        "time" => format!("{hour:02}:{minute:02}:{second:02}"),
        "iso8601" => format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{}{:02}:{:02}", if offset < 0 { '-' } else { '+' }, offset.unsigned_abs() / 60, offset.unsigned_abs() % 60),
        "std11" => {
            const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
            const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
            format!("{}, {day:02} {} {year:04} {hour:02}:{minute:02}:{second:02} {zone}", DAYS[when.weekday().number_days_from_monday() as usize], MONTHS[month as usize - 1])
        }
        "zone" => zone,
        // 0 is Sunday.
        "weekday" => when.weekday().number_days_from_sunday().to_string(),
        _ => String::new(),
    }
}

/// Parses a date header (RFC 5322, tolerating comments and missing weekdays).
fn parse_date(value: &str) -> Option<time::OffsetDateTime> {
    let without_comment = value.split('(').next().unwrap_or(value).trim();
    time::OffsetDateTime::parse(without_comment, &time::format_description::well_known::Rfc2822).ok()
}

fn in_zone(when: time::OffsetDateTime, zone: Zone) -> time::OffsetDateTime {
    match zone {
        Zone::Original => when,
        Zone::Server => when.to_offset(time::UtcOffset::UTC),
        Zone::Fixed(minutes) => time::UtcOffset::from_whole_seconds(minutes * 60).map_or(when, |offset| when.to_offset(offset)),
    }
}

fn build_regex(pattern: &str) -> Result<regex::Regex, String> {
    build_regex_with(pattern, true)
}

fn build_regex_with(pattern: &str, case_insensitive: bool) -> Result<regex::Regex, String> {
    // The regex crate guarantees linear-time matching; the size limit bounds compilation.
    regex::RegexBuilder::new(pattern).case_insensitive(case_insensitive).size_limit(1 << 20).build().map_err(|e| e.to_string().lines().last().unwrap_or("syntax error").trim().to_owned())
}

/// Translates a Sieve glob (`*`, `?`, `\` escapes) into an anchored regular expression whose
/// groups capture what the wildcards matched.
fn glob_to_regex(pattern: &str) -> String {
    let mut out = String::from("(?s)^");
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        match c {
            '*' => out.push_str("(.*?)"),
            '?' => out.push_str("(.)"),
            '\\' => out.push_str(&regex::escape(&chars.next().map(String::from).unwrap_or_default())),
            other => out.push_str(&regex::escape(&other.to_string())),
        }
    }
    out.push('$');
    out
}

/// The leading digits of a value as a number (`i;ascii-numeric`); `None` stands for
/// "positive infinity", what values without leading digits compare as.
fn numeric(value: &str) -> Option<u128> {
    let digits: String = value.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() { None } else { Some(digits.parse().unwrap_or(u128::MAX)) }
}

fn order(cmp: Comparator, a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    match cmp {
        Comparator::CaseMap => a.to_lowercase().cmp(&b.to_lowercase()),
        Comparator::Octet => a.as_bytes().cmp(b.as_bytes()),
        Comparator::Numeric => match (numeric(a), numeric(b)) {
            (None, None) => Equal,
            (None, Some(_)) => Greater,
            (Some(_), None) => Less,
            (Some(x), Some(y)) => x.cmp(&y),
        },
    }
}

/// Compares `value` against `key`; returns the captured groups for wildcard and regex matches.
fn compare(how: Match, cmp: Comparator, value: &str, key: &str) -> Option<Vec<String>> {
    match how {
        Match::Is => (order(cmp, value, key) == std::cmp::Ordering::Equal).then(Vec::new),
        Match::Contains if cmp == Comparator::Octet => value.contains(key).then(Vec::new),
        Match::Contains => value.to_lowercase().contains(&key.to_lowercase()).then(Vec::new),
        Match::Matches | Match::Regex => {
            let pattern = if how == Match::Matches { glob_to_regex(key) } else { key.to_owned() };
            let regex = build_regex_with(&pattern, cmp != Comparator::Octet).ok()?;
            let value: String = value.chars().take(8192).collect();
            let found = regex.captures(&value)?;
            Some(found.iter().take(10).map(|group| group.map_or(String::new(), |m| m.as_str().to_owned())).collect())
        }
        Match::Value(rel) => rel.holds(order(cmp, value, key)).then(Vec::new),
        // Handled over all values at once.
        Match::Count(_) | Match::List => None,
    }
}

fn address_part(address: &str, part: Part) -> Option<String> {
    let (local, domain) = match address.rsplit_once('@') {
        Some((local, domain)) => (local, Some(domain)),
        None => (address, None),
    };
    match part {
        Part::All => Some(address.to_owned()),
        Part::Local => Some(local.to_owned()),
        Part::Domain => Some(domain.unwrap_or(address).to_owned()),
        // RFC 5233: without a separator the whole local part is the user, and there is no detail.
        Part::User => Some(local.split_once('+').map_or(local, |(user, _)| user).to_owned()),
        Part::Detail => local.split_once('+').map(|(_, detail)| detail.to_owned()),
    }
}

/// The n-th value (`:index n`, counted from the end with `:last`).
fn indexed(values: Vec<String>, index: Option<(usize, bool)>) -> Vec<String> {
    match index {
        None => values,
        Some((n, false)) => values.into_iter().nth(n - 1).into_iter().collect(),
        Some((n, true)) => values.into_iter().rev().nth(n - 1).into_iter().collect(),
    }
}

fn apply_modifiers(mut value: String, modifiers: &[String]) -> String {
    // Modifiers apply in the precedence order of RFC 5229, not as written.
    for modifier in ["lower", "upper", "lowerfirst", "upperfirst", "quotewildcard", "length"] {
        if !modifiers.iter().any(|m| m == modifier) {
            continue;
        }
        value = match modifier {
            "lower" => value.to_lowercase(),
            "upper" => value.to_uppercase(),
            "lowerfirst" | "upperfirst" => {
                let mut chars = value.chars();
                match chars.next() {
                    Some(first) if modifier == "lowerfirst" => first.to_lowercase().chain(chars).collect(),
                    Some(first) => first.to_uppercase().chain(chars).collect(),
                    None => value,
                }
            }
            "quotewildcard" => value.chars().flat_map(|c| if matches!(c, '*' | '?' | '\\') { vec!['\\', c] } else { vec![c] }).collect(),
            _ => value.chars().count().to_string(),
        };
    }
    value.truncate(MAX_VARIABLE_BYTES);
    value
}

/// The header block as (name, raw value) pairs, folding kept.
fn split_headers(raw: &[u8]) -> Vec<(String, String)> {
    let head = String::from_utf8_lossy(&raw[..find_header_end(raw)]).into_owned();
    let mut out: Vec<(String, String)> = Vec::new();
    for line in head.split_inclusive('\n') {
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = out.last_mut() {
                value.push_str(line);
            }
        } else if let Some((name, value)) = line.split_once(':') {
            out.push((name.trim().to_owned(), value.to_owned()));
        }
    }
    for (_, value) in &mut out {
        *value = value.trim_end_matches(['\r', '\n']).to_owned();
    }
    out
}

fn unfold(value: &str) -> String {
    value.replace(['\r', '\n'], "").trim().to_owned()
}

/// Header values (decoded where it helps) and the addresses in address headers.
fn index_headers(raw: &[u8]) -> (HashMap<String, Vec<String>>, HashMap<String, Vec<String>>) {
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();
    let mut addresses: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(message) = MessageParser::default().parse_headers(raw) {
        for (name, value) in message.headers_raw() {
            headers.entry(name.to_ascii_lowercase()).or_default().push(unfold(value));
        }
        // Decoded forms, so that tests see the text users see.
        if let Some(subject) = message.subject() {
            headers.entry("subject".into()).or_default().push(subject.to_owned());
        }
        for (name, list) in [("from", message.from()), ("to", message.to()), ("cc", message.cc()), ("bcc", message.bcc()), ("sender", message.sender()), ("reply-to", message.reply_to())] {
            if let Some(list) = list {
                addresses.insert(name.into(), list.iter().filter_map(|a| a.address()).map(str::to_lowercase).collect());
                let names: Vec<String> = list.iter().filter_map(|a| a.name()).map(str::to_owned).collect();
                headers.entry(name.into()).or_default().extend(names);
            }
        }
    }
    (headers, addresses)
}

/// The MIME parts in depth-first order; part 0 is the message itself.
fn mime_parts(raw: &[u8]) -> Vec<MimePart> {
    let Some(message) = MessageParser::default().parse(raw) else { return vec![MimePart::default()] };
    let source = message.raw_message();
    let mut parts = Vec::new();
    for part in message.parts.iter().take(MAX_PARTS) {
        let headers = part
            .headers
            .iter()
            .map(|h| (h.name.as_str().to_owned(), unfold(&String::from_utf8_lossy(source.get(h.offset_start as usize..h.offset_end as usize).unwrap_or_default()))))
            .collect();
        let (ctype, subtype, params) = match part.content_type() {
            Some(ct) => (
                ct.ctype().to_ascii_lowercase(),
                ct.subtype().unwrap_or_default().to_ascii_lowercase(),
                ct.attributes().map(|attrs| attrs.iter().map(|a| (a.name.to_ascii_lowercase(), a.value.to_string())).collect()).unwrap_or_default(),
            ),
            None => ("text".to_owned(), "plain".to_owned(), Vec::new()),
        };
        let children = match &part.body {
            mail_parser::PartType::Multipart(children) => children.iter().map(|&c| c as usize).filter(|&c| c < MAX_PARTS).collect(),
            _ => Vec::new(),
        };
        let text = match &part.body {
            mail_parser::PartType::Text(text) => Some(text.to_string()),
            mail_parser::PartType::Html(html) => Some(mail_parser::decoders::html::html_to_text(html)),
            _ => None,
        };
        parts.push(MimePart { headers, ctype, subtype, params, text, children });
    }
    if parts.is_empty() {
        parts.push(MimePart::default());
    }
    parts
}

impl Runtime<'_> {
    /// Replaces `${name}` and `${N}` references. Unknown variables expand to nothing.
    fn expand(&self, text: &str) -> String {
        if !self.expand_variables || !has_variable(text) {
            return text.to_owned();
        }
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find("${") {
            out.push_str(&rest[..start]);
            let Some(end) = rest[start..].find('}') else {
                out.push_str(&rest[start..]);
                return out;
            };
            let name = rest[start + 2..start + end].to_ascii_lowercase();
            match name.parse::<usize>() {
                Ok(index) => out.push_str(self.captures.borrow().get(index).map_or("", String::as_str)),
                Err(_) => out.push_str(self.variables.get(&name).map_or("", String::as_str)),
            }
            rest = &rest[start + end + 1..];
        }
        out.push_str(rest);
        out.truncate(MAX_VARIABLE_BYTES);
        out
    }

    fn in_list(&self, list: &str, value: &str) -> bool {
        valid_ext_list(list) && self.env.context.contacts.contains(&value.trim().trim_matches(['<', '>']).to_lowercase())
    }

    fn any(&self, values: impl Iterator<Item = String>, keys: &[String], spec: &Spec) -> bool {
        let values: Vec<String> = values.collect();
        match spec.how {
            Match::Count(rel) => {
                let count = values.len().to_string();
                keys.iter().any(|key| rel.holds(order(spec.cmp, &count, &self.expand(key))))
            }
            Match::List => keys.iter().any(|key| {
                let key = self.expand(key);
                values.iter().any(|value| self.in_list(&key, value))
            }),
            _ => {
                for key in keys {
                    let key = self.expand(key);
                    for value in &values {
                        if let Some(captures) = compare(spec.how, spec.cmp, value, &key) {
                            if !captures.is_empty() {
                                *self.captures.borrow_mut() = captures;
                            }
                            return true;
                        }
                    }
                }
                false
            }
        }
    }

    /// The parts a `:mime` test looks at: the current one, or every part with `:anychild`.
    fn mime_targets(&self, spec: &Spec) -> Vec<usize> {
        let current = self.current_part.unwrap_or(0);
        if spec.any_child { self.descendants(current) } else { vec![current] }
    }

    fn descendants(&self, part: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut stack: Vec<usize> = self.parts.get(part).map(|p| p.children.iter().rev().copied().collect()).unwrap_or_default();
        while let Some(next) = stack.pop() {
            if out.len() >= MAX_PARTS || out.contains(&next) {
                break;
            }
            out.push(next);
            if let Some(p) = self.parts.get(next) {
                stack.extend(p.children.iter().rev().copied());
            }
        }
        out
    }

    /// Header values for a header test, from the message or (with `:mime`) its parts.
    fn header_values(&self, names: &[String], spec: &Spec) -> Vec<String> {
        let names: Vec<String> = names.iter().map(|n| self.expand(n).to_ascii_lowercase()).collect();
        let Some(option) = &spec.mime else {
            return indexed(names.iter().filter_map(|n| self.headers.get(n)).flatten().cloned().collect(), spec.index);
        };
        let mut out = Vec::new();
        for part in self.mime_targets(spec).into_iter().filter_map(|i| self.parts.get(i)) {
            for name in &names {
                if name == "content-type" && *option != MimeOption::Value {
                    match option {
                        MimeOption::Type => out.push(part.ctype.clone()),
                        MimeOption::Subtype => out.push(part.subtype.clone()),
                        MimeOption::ContentType => out.push(format!("{}/{}", part.ctype, part.subtype)),
                        MimeOption::Param(wanted) => out.extend(part.params.iter().filter(|(n, _)| wanted.contains(n)).map(|(_, v)| v.clone())),
                        MimeOption::Value => {}
                    }
                    continue;
                }
                out.extend(part.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()));
            }
        }
        out
    }

    fn test(&self, test: &Test) -> bool {
        let context = self.env.context;
        match test {
            Test::True => true,
            Test::False => false,
            Test::Not(inner) => !self.test(inner),
            Test::AllOf(tests) => tests.iter().all(|t| self.test(t)),
            Test::AnyOf(tests) => tests.iter().any(|t| self.test(t)),
            Test::Exists { names, spec } => match spec.mime {
                None => names.iter().all(|n| self.headers.contains_key(&self.expand(n).to_ascii_lowercase())),
                Some(_) => self.mime_targets(spec).iter().filter_map(|&i| self.parts.get(i)).any(|part| names.iter().all(|n| part.headers.iter().any(|(h, _)| h.eq_ignore_ascii_case(&self.expand(n))))),
            },
            Test::Size { over, limit } => {
                let size = self.env.raw.len() as u64;
                if *over { size > *limit } else { size < *limit }
            }
            Test::Header { names, keys, spec } => self.any(self.header_values(names, spec).into_iter(), keys, spec),
            Test::Address { names, keys, spec } => {
                let values: Vec<String> = if spec.mime.is_some() {
                    // Addresses in the part's headers.
                    self.header_values(names, spec).iter().flat_map(|v| v.split(',').map(str::to_owned).collect::<Vec<_>>()).filter_map(|a| {
                        let a = a.rsplit('<').next().unwrap_or(&a).trim_end_matches('>').trim().to_lowercase();
                        a.contains('@').then_some(a)
                    }).collect()
                } else {
                    indexed(names.iter().filter_map(|n| self.addresses.get(&self.expand(n).to_ascii_lowercase())).flatten().cloned().collect(), spec.index)
                };
                self.any(values.into_iter().filter_map(|a| address_part(&a, spec.part)), keys, spec)
            }
            Test::Envelope { names, keys, spec } => {
                let values = names.iter().map(|n| if n.eq_ignore_ascii_case("from") { self.env.from } else { self.env.to }).filter_map(|a| address_part(a, spec.part));
                self.any(values, keys, spec)
            }
            Test::Body { keys, spec } => {
                let body = String::from_utf8_lossy(self.body).trim().to_owned();
                self.any(std::iter::once(body), keys, spec)
            }
            Test::Str { sources, keys, spec } => {
                let values: Vec<String> = sources.iter().map(|s| self.expand(s)).collect();
                // RFC 5229: with :count, empty strings are not counted.
                let values: Vec<String> = if matches!(spec.how, Match::Count(_)) { values.into_iter().filter(|v| !v.is_empty()).collect() } else { values };
                self.any(values.into_iter(), keys, spec)
            }
            Test::Date { header, part, keys, spec } => {
                let raw_values = indexed(self.headers.get(&self.expand(header).to_ascii_lowercase()).cloned().unwrap_or_default(), spec.index);
                let values = raw_values.iter().filter_map(|v| parse_date(v)).map(|when| date_part(in_zone(when, spec.zone), part));
                self.any(values, keys, spec)
            }
            Test::CurrentDate { part, keys, spec } => {
                let Ok(now) = time::OffsetDateTime::from_unix_timestamp(context.now) else { return false };
                self.any(std::iter::once(date_part(in_zone(now, spec.zone), part)), keys, spec)
            }
            Test::Environment { name, keys, spec } => {
                let value = match name.as_str() {
                    "domain" => Some(context.domain.clone()),
                    "host" => Some(context.host.clone()),
                    "location" => Some("MDA".to_owned()),
                    "name" => Some("unoMail".to_owned()),
                    "phase" => Some("during".to_owned()),
                    "version" => Some(env!("CARGO_PKG_VERSION").to_owned()),
                    "remote-ip" if !context.remote_ip.is_empty() => Some(context.remote_ip.clone()),
                    _ => None,
                };
                self.any(value.into_iter(), keys, spec)
            }
            Test::Ihave(extensions) => extensions.iter().all(|e| SUPPORTED.contains(&e.as_str())),
            Test::Spam { keys, spec } => self.any(std::iter::once(context.spam.to_string()), keys, spec),
            Test::Virus { keys, spec } => self.any(std::iter::once(context.virus.to_string()), keys, spec),
            Test::Duplicate { handle, header, unique_id, seconds, last } => {
                let id = match (unique_id, header) {
                    (Some(id), _) => Some(self.expand(id)),
                    (None, Some(header)) => self.headers.get(header).and_then(|v| v.first().cloned()),
                    (None, None) => self.headers.get("message-id").and_then(|v| v.first().cloned()),
                };
                let Some(id) = id.filter(|id| !id.is_empty()) else { return false };
                let key = crate::util::sha256_hex(format!("{}\0{id}", self.expand(handle)).as_bytes())[..32].to_owned();
                let mut recorded = self.duplicate_keys.borrow_mut();
                let seen = context.duplicates.contains(&key) || recorded.iter().any(|(k, _)| *k == key);
                // Recorded when first seen; `:last` restarts the period on every duplicate.
                if !seen || *last {
                    recorded.retain(|(k, _)| *k != key);
                    recorded.push((key, *seconds));
                }
                seen
            }
            Test::MailboxExists(names) => names.iter().all(|n| {
                let n = self.expand(n);
                context.mailboxes.iter().any(|m| m.name == n || (n.eq_ignore_ascii_case("inbox") && m.role.as_deref() == Some("inbox")))
            }),
            Test::SpecialUseExists { mailbox, uses } => {
                let roles: Vec<Option<&str>> = uses.iter().map(|u| special_use_role(&self.expand(u))).collect();
                match mailbox {
                    Some(name) => {
                        let name = self.expand(name);
                        context.mailboxes.iter().find(|m| m.name == name).is_some_and(|m| roles.iter().all(|r| r.is_some() && m.role.as_deref() == *r))
                    }
                    None => roles.iter().all(|r| r.is_some() && context.mailboxes.iter().any(|m| m.role.as_deref() == *r)),
                }
            }
            Test::MailboxIdExists(ids) => ids.iter().all(|id| context.mailboxes.iter().any(|m| m.id == self.expand(id))),
            Test::ValidNotifyMethod(methods) => methods.iter().all(|m| mailto_target(&self.expand(m)).is_some()),
            Test::NotifyMethodCapability { method, capability, keys, spec } => {
                // Whether the recipient of a mail notification is online cannot be known.
                let value = (mailto_target(&self.expand(method)).is_some() && capability == "online").then(|| "maybe".to_owned());
                self.any(value.into_iter(), keys, spec)
            }
            Test::ValidExtList(names) => names.iter().all(|n| valid_ext_list(&self.expand(n))),
        }
    }

    fn with_flags(&self, explicit: &[String]) -> Vec<String> {
        if explicit.is_empty() { self.flags.clone() } else { explicit.iter().map(|f| self.expand(f)).collect() }
    }

    fn expand_fcc(&self, fcc: &Option<Fcc>) -> Option<Fcc> {
        let fcc = fcc.as_ref()?;
        let mailbox = self.expand(&fcc.mailbox);
        crate::store::validate_mailbox_name(&mailbox).ok()?;
        Some(Fcc { mailbox, create: fcc.create, flags: fcc.flags.iter().map(|f| self.expand(f)).collect() })
    }

    /// Rebuilds the header indexes after `editheader` changed the header block.
    fn reindex(&mut self) {
        let raw = self.edited_message();
        let (headers, addresses) = index_headers(&raw);
        self.headers = headers;
        self.addresses = addresses;
        self.edited = true;
    }

    fn edited_message(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.env.raw.len() + 256);
        for (name, value) in &self.header_list {
            out.extend_from_slice(name.as_bytes());
            out.push(b':');
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        // The body begins with the blank line that ends the header block, when there is one.
        if !self.body.starts_with(b"\r\n") && !self.body.starts_with(b"\n") {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(self.body);
        out
    }

    fn run(&mut self, commands: &[Command]) -> Flow {
        for command in commands {
            match command {
                Command::If(branches) => {
                    for (test, block) in branches {
                        if test.as_ref().is_none_or(|t| self.test(t)) {
                            match self.run(block) {
                                Flow::Continue => {}
                                other => return other,
                            }
                            break;
                        }
                    }
                }
                Command::Stop => return Flow::Stop,
                Command::Return => return Flow::Return,
                Command::Error => {
                    self.failed = true;
                    return Flow::Stop;
                }
                Command::Include { commands, once } => {
                    if let Some(name) = once {
                        if self.included_once.contains(name) {
                            continue;
                        }
                        self.included_once.push(name.clone());
                    }
                    // `return` only leaves the included script; `stop` ends everything.
                    match self.run(commands) {
                        Flow::Stop => return Flow::Stop,
                        Flow::Break(name) => return Flow::Break(name),
                        _ => {}
                    }
                }
                Command::Keep { flags } => {
                    self.explicit_keep = true;
                    self.outcome.keep = Some(self.with_flags(flags));
                }
                Command::Discard => self.implicit_keep = false,
                Command::FileInto { mailbox, copy, create, flags, special_use, mailbox_id } => {
                    let mailbox = self.expand(mailbox);
                    // Names built from variables are checked here instead of at compile time.
                    if crate::store::validate_mailbox_name(&mailbox).is_ok() {
                        let target = FileInto {
                            mailbox,
                            special_use: special_use.as_ref().map(|u| self.expand(u)).filter(|u| special_use_role(u).is_some()),
                            mailbox_id: mailbox_id.as_ref().map(|id| self.expand(id)),
                            create: *create,
                            flags: self.with_flags(flags),
                        };
                        if self.outcome.fileinto.len() < MAX_FILEINTO && !self.outcome.fileinto.iter().any(|f| f.mailbox == target.mailbox && f.special_use == target.special_use && f.mailbox_id == target.mailbox_id) {
                            self.outcome.fileinto.push(target);
                        }
                        self.implicit_keep &= *copy;
                    }
                }
                Command::Redirect { address, copy } => {
                    if let Some(address) = Address::parse(&self.expand(address)).map(|a| a.to_string()) {
                        if self.outcome.redirect.len() < MAX_REDIRECTS && !self.outcome.redirect.contains(&address) {
                            self.outcome.redirect.push(address);
                        }
                        self.implicit_keep &= *copy;
                    }
                }
                Command::Flags { op, flags } => {
                    // Flag lists may be given as separate strings or space-separated.
                    let flags: Vec<String> = flags.iter().map(|f| self.expand(f)).flat_map(|f| f.split_whitespace().map(str::to_owned).collect::<Vec<_>>()).collect();
                    match op {
                        FlagOp::Set => self.flags = flags,
                        FlagOp::Add => {
                            for flag in flags {
                                if !self.flags.iter().any(|f| f.eq_ignore_ascii_case(&flag)) {
                                    self.flags.push(flag);
                                }
                            }
                        }
                        FlagOp::Remove => self.flags.retain(|f| !flags.iter().any(|r| r.eq_ignore_ascii_case(f))),
                    }
                }
                Command::Set { name, value, modifiers } => {
                    let value = apply_modifiers(self.expand(value), modifiers);
                    if self.variables.len() < MAX_VARIABLES || self.variables.contains_key(name) {
                        self.variables.insert(name.clone(), value);
                    }
                }
                Command::Vacation(vacation) => {
                    let reason = self.expand(&vacation.reason);
                    // A reason built from variables is checked now instead of at compile time.
                    if vacation.mime && check_mime_entity(&reason).is_err() {
                        continue;
                    }
                    self.outcome.vacation = Some(Vacation {
                        mime: vacation.mime,
                        days: vacation.days,
                        seconds: vacation.seconds,
                        fcc: self.expand_fcc(&vacation.fcc),
                        subject: crate::util::sanitize_line(&self.expand(&vacation.subject)),
                        reason,
                        addresses: vacation.addresses.clone(),
                        handle: self.expand(&vacation.handle),
                    });
                }
                Command::Reject { reason } => {
                    self.outcome.reject = Some(crate::util::sanitize_line(&self.expand(reason)));
                    self.implicit_keep = false;
                }
                Command::AddHeader { name, value, last } => {
                    let (name, value) = (self.expand(name), self.expand(value));
                    if self.edits >= MAX_HEADER_EDITS || !editable_header(&name) || value.contains(['\r', '\n']) || value.len() > 998 {
                        continue;
                    }
                    self.edits += 1;
                    let entry = (name, format!(" {value}"));
                    if *last { self.header_list.push(entry) } else { self.header_list.insert(0, entry) }
                    self.reindex();
                }
                Command::DeleteHeader { name, values, spec } => {
                    let name = self.expand(name);
                    if self.edits >= MAX_HEADER_EDITS || !editable_header(&name) {
                        continue;
                    }
                    self.edits += 1;
                    let positions: Vec<usize> = self.header_list.iter().enumerate().filter(|(_, (n, _))| n.eq_ignore_ascii_case(&name)).map(|(i, _)| i).collect();
                    let candidates: Vec<usize> = match spec.index {
                        None => positions,
                        Some((n, false)) => positions.into_iter().nth(n - 1).into_iter().collect(),
                        Some((n, true)) => positions.into_iter().rev().nth(n - 1).into_iter().collect(),
                    };
                    let doomed: Vec<usize> = candidates
                        .into_iter()
                        .filter(|&i| values.is_empty() || self.any(std::iter::once(unfold(&self.header_list[i].1)), values, spec))
                        .collect();
                    if doomed.is_empty() {
                        continue;
                    }
                    for i in doomed.into_iter().rev() {
                        self.header_list.remove(i);
                    }
                    self.reindex();
                }
                Command::Notify { method, importance, message, fcc } => {
                    let Some(target) = mailto_target(&self.expand(method)) else { continue };
                    let to = target.to_string();
                    if self.outcome.notify.len() >= MAX_NOTIFY || self.outcome.notify.iter().any(|n| n.to == to) {
                        continue;
                    }
                    let subject = self.headers.get("subject").and_then(|s| s.last().cloned()).unwrap_or_default();
                    let from = self.addresses.get("from").and_then(|f| f.first().cloned()).unwrap_or_default();
                    let text = message.as_ref().map(|m| self.expand(m)).unwrap_or_else(|| format!("{from}: {subject}"));
                    self.outcome.notify.push(Notification {
                        to,
                        subject: crate::util::sanitize_line(&text.chars().take(200).collect::<String>()),
                        message: text.chars().take(2000).collect(),
                        importance: *importance,
                        fcc: self.expand_fcc(fcc),
                    });
                }
                Command::ForEveryPart { name, commands } => {
                    let saved = self.current_part;
                    let children = self.descendants(saved.unwrap_or(0));
                    let mut flow = Flow::Continue;
                    for part in children {
                        self.current_part = Some(part);
                        match self.run(commands) {
                            Flow::Continue => {}
                            // An unnamed break, or one naming this loop, ends it.
                            Flow::Break(None) => break,
                            Flow::Break(Some(target)) if name.as_deref() == Some(target.as_str()) => break,
                            other => {
                                flow = other;
                                break;
                            }
                        }
                    }
                    self.current_part = saved;
                    if !matches!(flow, Flow::Continue) {
                        return flow;
                    }
                }
                Command::Break { name } => return Flow::Break(name.clone()),
                Command::ExtractText { name, first, modifiers } => {
                    let text = self.current_part.and_then(|i| self.parts.get(i)).and_then(|p| p.text.clone()).unwrap_or_default();
                    let text: String = match first {
                        Some(n) => text.chars().take(*n).collect(),
                        None => text,
                    };
                    let value = apply_modifiers(text, modifiers);
                    if self.variables.len() < MAX_VARIABLES || self.variables.contains_key(name) {
                        self.variables.insert(name.clone(), value);
                    }
                }
            }
        }
        Flow::Continue
    }
}

impl Script {
    /// Runs the script against a message. Evaluation cannot fail: every problem is caught
    /// when the script is compiled, and a script that fails at run time (`error`, or actions
    /// that cannot go together) leaves the message in the inbox.
    pub fn evaluate(&self, env: &Envelope<'_>) -> Outcome {
        let (headers, addresses) = index_headers(env.raw);
        let parts = if self.mime { mime_parts(env.raw) } else { vec![MimePart::default()] };
        let mut runtime = Runtime {
            env,
            headers,
            addresses,
            header_list: split_headers(env.raw),
            body: &env.raw[find_header_end(env.raw)..],
            edits: 0,
            edited: false,
            parts,
            current_part: None,
            flags: Vec::new(),
            implicit_keep: true,
            explicit_keep: false,
            failed: false,
            outcome: Outcome::default(),
            variables: HashMap::new(),
            captures: std::cell::RefCell::new(Vec::new()),
            duplicate_keys: std::cell::RefCell::new(Vec::new()),
            included_once: Vec::new(),
            expand_variables: self.variables,
        };
        runtime.run(&self.commands);
        // RFC 5429: reject cannot go with keeping or filing the message.
        let conflicting = runtime.outcome.reject.is_some() && (runtime.explicit_keep || !runtime.outcome.fileinto.is_empty());
        if runtime.failed || conflicting {
            return Outcome { keep: Some(Vec::new()), ..Default::default() };
        }
        if runtime.implicit_keep && runtime.outcome.keep.is_none() {
            runtime.outcome.keep = Some(runtime.flags.clone());
        }
        runtime.outcome.duplicates = runtime.duplicate_keys.take();
        if runtime.edited {
            runtime.outcome.edited = Some(runtime.edited_message());
        }
        runtime.outcome
    }
}

/// A stored script of an account.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Stored {
    #[serde(default = "default_name")]
    pub name: String,
    pub script: String,
    pub active: bool,
}

fn default_name() -> String {
    "main".into()
}

pub fn valid_script_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Every script of the account, by name.
pub async fn all(app: &crate::app::App, account_id: i64) -> sqlx::Result<Vec<Stored>> {
    let rows: Vec<(String, String, bool)> = sqlx::query_as("SELECT name, script, active FROM sieve_scripts WHERE account_id = ? ORDER BY name")
        .bind(account_id)
        .fetch_all(&app.db)
        .await?;
    Ok(rows.into_iter().map(|(name, script, active)| Stored { name, script, active }).collect())
}

pub async fn load(app: &crate::app::App, account_id: i64, name: &str) -> sqlx::Result<Stored> {
    Ok(all(app, account_id).await?.into_iter().find(|s| s.name == name).unwrap_or(Stored { name: name.to_owned(), ..Default::default() }))
}

/// Compiles `source` in the context of the account's other scripts and the administrator's
/// global scripts (for `include`).
pub fn compile_among(source: &str, name: &str, scripts: &[Stored], globals: &[Stored]) -> Result<Script, SieveError> {
    compile_with(source, &|wanted, global| {
        if global {
            globals.iter().find(|s| s.name == wanted).map(|s| s.script.clone())
        } else if wanted == name {
            // A script including itself by name must see its new text, not the stored one.
            Some(source.to_owned())
        } else {
            scripts.iter().find(|s| s.name == wanted).map(|s| s.script.clone())
        }
    })
}

const GLOBAL_PREFIX: &str = "sieve.global.";

/// Scripts provided by the administrator; users pull them in with `include :global "name"`.
pub async fn globals(app: &crate::app::App) -> sqlx::Result<Vec<Stored>> {
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT key, value FROM settings WHERE key LIKE 'sieve.global.%' ORDER BY key").fetch_all(&app.db).await?;
    Ok(rows.into_iter().filter_map(|(key, script)| key.strip_prefix(GLOBAL_PREFIX).map(|name| Stored { name: name.to_owned(), script, active: false })).collect())
}

/// Validates and stores a global script. It may include other global scripts only.
pub async fn save_global(app: &crate::app::App, name: &str, script: &str) -> Result<(), String> {
    let existing = globals(app).await.map_err(|_| "database error")?;
    if existing.len() >= 50 && !existing.iter().any(|s| s.name == name) {
        return Err("at most 50 global scripts can be stored".into());
    }
    compile_with(script, &|wanted, global| {
        if !global {
            None
        } else if wanted == name {
            Some(script.to_owned())
        } else {
            existing.iter().find(|s| s.name == wanted).map(|s| s.script.clone())
        }
    })
    .map_err(|e| e.to_string())?;
    crate::db::set_setting(&app.db, &format!("{GLOBAL_PREFIX}{name}"), script).await.map_err(|_| "database error".to_owned())
}

pub async fn delete_global(app: &crate::app::App, name: &str) -> sqlx::Result<bool> {
    Ok(sqlx::query("DELETE FROM settings WHERE key = ?").bind(format!("{GLOBAL_PREFIX}{name}")).execute(&app.db).await?.rows_affected() > 0)
}

/// Addresses outside this server that `script` (with the account's other scripts and the
/// global ones for `include`) may redirect mail to.
async fn external_targets(app: &crate::app::App, stored: &Stored, scripts: &[Stored], globals: &[Stored]) -> Vec<String> {
    let Ok(script) = compile_among(&stored.script, &stored.name, scripts, globals) else { return Vec::new() };
    let mut out = Vec::new();
    for target in script.redirect_targets() {
        let local = match Address::parse(&target) {
            Some(address) => !matches!(crate::smtp::delivery::resolve(app, &address).await, Ok(crate::smtp::delivery::Resolution::NotLocal) | Err(_)),
            // Built from variables: it could be anywhere.
            None => false,
        };
        if !local {
            out.push(target);
        }
    }
    out
}

/// Stores a script. At most one script per account is active.
///
/// Forwarding is how a stolen session keeps reading mail after the password was changed, so
/// the account is told whenever a script starts sending its mail somewhere new outside.
pub async fn save(app: &crate::app::App, account_id: i64, stored: &Stored) -> sqlx::Result<()> {
    let scripts = all(app, account_id).await?;
    let globals = globals(app).await?;
    let before = match scripts.iter().find(|s| s.name == stored.name) {
        Some(previous) => external_targets(app, previous, &scripts, &globals).await,
        None => Vec::new(),
    };
    let added: Vec<String> = external_targets(app, stored, &scripts, &globals).await.into_iter().filter(|t| !before.contains(t)).collect();
    let mut tx = app.db.begin().await?;
    if stored.active {
        sqlx::query("UPDATE sieve_scripts SET active = 0 WHERE account_id = ?").bind(account_id).execute(&mut *tx).await?;
    }
    sqlx::query(
        "INSERT INTO sieve_scripts (account_id, name, script, active, updated_at) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(account_id, name) DO UPDATE SET script = excluded.script, active = excluded.active, updated_at = excluded.updated_at",
    )
    .bind(account_id)
    .bind(&stored.name)
    .bind(&stored.script)
    .bind(stored.active)
    .bind(crate::util::now())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if !added.is_empty() {
        forwarding_notice(app, account_id, &stored.name, &added).await;
    }
    Ok(())
}

/// Puts a note about new forwarding into the account's inbox.
async fn forwarding_notice(app: &crate::app::App, account_id: i64, name: &str, targets: &[String]) {
    let Ok(Some(account)) = crate::auth::Account::by_id(&app.db, account_id).await else { return };
    let Some(address) = Address::parse(&account.email) else { return };
    let domain = address.domain.clone();
    let list: String = targets.iter().map(|t| format!("  {}\r\n", crate::util::sanitize_line(t))).collect();
    let raw = format!(
        "From: \"Mail server\" <postmaster@{domain}>\r\nTo: <{to}>\r\nSubject: Your mail is now forwarded to another address\r\nDate: {date}\r\nMessage-ID: <{id}@{domain}>\r\n\
         Auto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n\
         The mail filter \"{name}\" was changed and can now send your incoming mail on to:\r\n\r\n{list}\r\n\
         If you did not do this, someone else may have access to your account: change your password,\r\n\
         sign out your other sessions and remove the filter under Settings > Filters.\r\n",
        to = account.email,
        date = crate::smtp::delivery::rfc2822_now(),
        id = crate::util::random_token(),
        name = crate::util::sanitize_line(name),
    );
    // Stored straight into the inbox: delivering it would run the very filter it warns about.
    let Ok(Some(inbox)) = app.store.mailbox_by_role(account_id, "inbox").await else { return };
    if let Err(err) = app.store.append(account_id, inbox.id, raw.as_bytes(), crate::store::Flags::default(), None).await {
        tracing::warn!(%err, "forwarding notice not stored");
    }
}

pub async fn delete(app: &crate::app::App, account_id: i64, name: &str) -> sqlx::Result<bool> {
    Ok(sqlx::query("DELETE FROM sieve_scripts WHERE account_id = ? AND name = ?").bind(account_id).bind(name).execute(&app.db).await?.rows_affected() > 0)
}

/// The compiled active script of an account, if it has one. A stored script that no longer
/// compiles is ignored (mail is kept in the inbox) rather than blocking delivery.
pub async fn active_script(app: &crate::app::App, account_id: i64) -> Option<Script> {
    let scripts = all(app, account_id).await.ok()?;
    let active = scripts.iter().find(|s| s.active)?;
    let globals = globals(app).await.ok()?;
    compile_among(&active.script, &active.name, &scripts, &globals).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = b"From: \"Big Boss\" <boss@corp.example>\r\nTo: bob@example.org\r\nCc: team@example.org\r\n\
Subject: =?utf-8?q?Quarterly_r=C3=A9sum=C3=A9?=\r\nList-Id: <announce.lists.example>\r\nX-Spam-Status: Yes, score=9\r\n\r\nPlease buy cheap watches now.\r\n";

    fn run(script: &str) -> Outcome {
        compile(script).unwrap().evaluate(&Envelope::new("bounce+bob@mailer.example", "bob@example.org", MESSAGE))
    }

    fn filed(mailbox: &str, create: bool, flags: &[&str]) -> FileInto {
        FileInto { mailbox: mailbox.into(), special_use: None, mailbox_id: None, create, flags: flags.iter().map(|f| f.to_string()).collect() }
    }

    fn inbox() -> Outcome {
        Outcome { keep: Some(vec![]), ..Default::default() }
    }

    /// Runs a script with a delivery context.
    fn run_in(script: &str, raw: &[u8], context: &Context) -> Outcome {
        compile(script).unwrap_or_else(|e| panic!("{e}")).evaluate(&Envelope { from: "ann+news@remote.example", to: "bob+lists@example.org", raw, context })
    }

    fn context() -> Context {
        Context {
            spam: 7,
            virus: 1,
            now: 1_767_261_600, // 2026-01-01 10:00:00 UTC, a Thursday
            domain: "example.org".into(),
            host: "mail.example.org".into(),
            remote_ip: "192.0.2.7".into(),
            mailboxes: vec![
                MailboxInfo { id: "b1".into(), name: "INBOX".into(), role: Some("inbox".into()) },
                MailboxInfo { id: "b4".into(), name: "Spam".into(), role: Some("junk".into()) },
                MailboxInfo { id: "b9".into(), name: "Projects".into(), role: None },
            ],
            duplicates: ["seen-before".to_owned()].into_iter().collect(),
            contacts: ["boss@corp.example".to_owned()].into_iter().collect(),
        }
    }

    const MIXED: &[u8] = b"From: boss@corp.example\r\nTo: bob@example.org\r\nSubject: Report\r\nDate: Wed, 31 Dec 2025 23:30:00 -0200\r\n\
Message-ID: <r1@corp.example>\r\nReceived: from x\r\nX-Trace: one\r\nX-Trace: two\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nNumbers are up.\r\n\
--b\r\nContent-Type: application/pdf; name=\"report.pdf\"\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\n\r\nJVBERi0=\r\n--b--\r\n";

    #[test]
    fn relational_comparators_and_subaddresses() {
        let c = context();
        let filed_in = |script: &str| run_in(script, MIXED, &c).fileinto.into_iter().map(|f| f.mailbox).collect::<Vec<_>>();
        // :count counts values; :value compares them, numerically with i;ascii-numeric.
        assert_eq!(filed_in(r#"require ["fileinto", "relational"]; if header :count "ge" "X-Trace" "2" { fileinto "Traced"; }"#), ["Traced"]);
        // RFC 4790: a value without leading digits counts as positive infinity.
        assert_eq!(filed_in(r#"require ["fileinto", "relational", "comparator-i;ascii-numeric"]; if header :value "gt" :comparator "i;ascii-numeric" "X-Trace" "5" { fileinto "Infinite"; }"#), ["Infinite"]);
        assert_eq!(filed_in(r#"require ["fileinto", "relational", "comparator-i;ascii-numeric"]; if header :value "lt" :comparator "i;ascii-numeric" "X-Trace" "5" { fileinto "No"; }"#), Vec::<String>::new());
        assert_eq!(filed_in(r#"require ["fileinto", "relational"]; if header :value "lt" "Subject" "S" { fileinto "Early"; }"#), ["Early"]);
        // i;octet is case-sensitive.
        assert_eq!(filed_in(r#"require "fileinto"; if header :is :comparator "i;octet" "Subject" "report" { fileinto "No"; }"#), Vec::<String>::new());
        // :user / :detail of subaddress.
        assert_eq!(filed_in(r#"require ["fileinto", "envelope", "subaddress", "variables"]; if envelope :detail :matches "to" "*" { fileinto "${1}"; }"#), ["lists"]);
        assert_eq!(filed_in(r#"require ["fileinto", "envelope", "subaddress"]; if envelope :user "from" "ann" { fileinto "Ann"; }"#), ["Ann"]);
        assert!(compile(r#"require "relational"; if header :count "ge" :comparator "i;ascii-numeric" "x" "1" {}"#).is_err(), "numeric needs its require");
        assert!(compile(r#"if header :value "gt" "x" "1" {}"#).is_err());
    }

    #[test]
    fn dates_indexes_and_environment() {
        let c = context();
        let filed_in = |script: &str| run_in(script, MIXED, &c).fileinto.into_iter().map(|f| f.mailbox).collect::<Vec<_>>();
        // The header's date, in its own zone, in UTC, and in a chosen zone.
        assert_eq!(filed_in(r#"require ["fileinto", "date"]; if date :originalzone "date" "year" "2025" { fileinto "Old"; }"#), ["Old"]);
        assert_eq!(filed_in(r#"require ["fileinto", "date"]; if date "date" "date" "2026-01-01" { fileinto "New year"; }"#), ["New year"]);
        assert_eq!(filed_in(r#"require ["fileinto", "date"]; if date :zone "+0100" "date" "hour" "02" { fileinto "Two"; }"#), ["Two"]);
        assert_eq!(filed_in(r#"require ["fileinto", "date", "relational"]; if currentdate :value "ge" "date" "2026-01-01" { fileinto "Now"; }"#), ["Now"]);
        assert_eq!(filed_in(r#"require ["fileinto", "date"]; if currentdate "weekday" "4" { fileinto "Thursday"; }"#), ["Thursday"]);
        // :index picks one occurrence.
        assert_eq!(filed_in(r#"require ["fileinto", "index"]; if header :index 2 "X-Trace" "two" { fileinto "Second"; }"#), ["Second"]);
        assert_eq!(filed_in(r#"require ["fileinto", "index"]; if header :index 1 :last "X-Trace" "one" { fileinto "No"; }"#), Vec::<String>::new());
        assert_eq!(filed_in(r#"require ["fileinto", "environment"]; if environment "domain" "example.org" { fileinto "Ours"; }"#), ["Ours"]);
        assert_eq!(filed_in(r#"require ["fileinto", "environment"]; if environment :matches "name" "uno*" { fileinto "Us"; }"#), ["Us"]);
        assert_eq!(filed_in(r#"require ["fileinto", "ihave"]; if ihave "fileinto" { fileinto "Yes"; } if ihave "convert" { fileinto "No"; }"#), ["Yes"]);
        assert_eq!(run_in(r#"require ["ihave", "fileinto"]; fileinto "x"; error "broken";"#, MIXED, &c), inbox(), "error keeps the message");
        assert!(compile(r#"require "date"; if date "date" "fortnight" "1" {}"#).is_err());
    }

    #[test]
    fn spam_virus_lists_and_duplicates() {
        let c = context();
        let filed_in = |script: &str, raw: &[u8]| run_in(script, raw, &c).fileinto.into_iter().map(|f| f.mailbox).collect::<Vec<_>>();
        assert_eq!(filed_in(r#"require ["fileinto", "spamtest", "relational", "comparator-i;ascii-numeric"]; if spamtest :value "ge" :comparator "i;ascii-numeric" "6" { fileinto "Spam"; }"#, MIXED), ["Spam"]);
        assert_eq!(filed_in(r#"require ["fileinto", "virustest"]; if virustest "1" { fileinto "Clean"; }"#, MIXED), ["Clean"]);
        // extlists: the address book.
        assert_eq!(filed_in(r#"require ["fileinto", "extlists"]; if address :list "from" ":addrbook:default" { fileinto "Known"; }"#, MIXED), ["Known"]);
        assert_eq!(filed_in(r#"require ["fileinto", "extlists"]; if address :list "from" "urn:ietf:params:sieve:addrbook:default" { fileinto "Known"; }"#, b"From: stranger@far.example\r\n\r\nx"), Vec::<String>::new());
        assert!(compile(r#"require "extlists"; if address :list "from" "tag:nowhere" {}"#).is_err());
        // duplicate: a new message is recorded, one seen before is a duplicate.
        let outcome = run_in(r#"require ["duplicate", "fileinto"]; if duplicate { fileinto "Dupes"; }"#, MIXED, &c);
        assert!(outcome.fileinto.is_empty());
        assert_eq!(outcome.duplicates.len(), 1);
        let mut seen = c.clone();
        seen.duplicates.insert(outcome.duplicates[0].0.clone());
        assert_eq!(run_in(r#"require ["duplicate", "fileinto"]; if duplicate { fileinto "Dupes"; }"#, MIXED, &seen).fileinto[0].mailbox, "Dupes");
        let by_id = run_in(r#"require ["duplicate", "fileinto"]; if duplicate :uniqueid "x" :seconds 60 { }"#, MIXED, &c);
        assert_eq!(by_id.duplicates[0].1, 60);
    }

    #[test]
    fn mailboxes_by_special_use_and_id() {
        let c = context();
        let outcome = run_in(r#"require ["fileinto", "special-use", "mailboxid", "mailbox"];
            if specialuse_exists "\\Junk" { fileinto :specialuse "\\Junk" "Junk"; }
            if mailboxidexists "b9" { fileinto :mailboxid "b9" "Projects-fallback"; }
            if mailboxexists "Projects" { fileinto :copy "Projects"; }"#.replace(":copy ", "").as_str(), MIXED, &c);
        assert_eq!(outcome.fileinto[0].special_use.as_deref(), Some("\\Junk"));
        assert_eq!(outcome.fileinto[1].mailbox_id.as_deref(), Some("b9"));
        assert_eq!(outcome.fileinto.len(), 3);
        assert!(compile(r#"require ["fileinto", "special-use"]; fileinto :specialuse "\\Secret" "x";"#).is_err());
    }

    #[test]
    fn header_edits_and_their_limits() {
        let c = context();
        let outcome = run_in(r#"require ["editheader", "fileinto"];
            addheader "X-Sorted" "yes";
            addheader :last "X-Tail" "end";
            deleteheader "X-Trace";
            if exists "X-Sorted" { fileinto "Sorted"; }"#, MIXED, &c);
        let edited = String::from_utf8(outcome.edited.clone().unwrap()).unwrap();
        assert!(edited.starts_with("X-Sorted: yes\r\nFrom: boss@corp.example\r\n"), "{edited}");
        assert!(!edited.contains("X-Trace") && edited.contains("X-Tail: end\r\n\r\n--b"), "{edited}");
        assert_eq!(outcome.fileinto[0].mailbox, "Sorted", "tests see the edits");
        let one = run_in(r#"require ["editheader", "index"]; deleteheader :index 1 "X-Trace";"#, MIXED, &c).edited.unwrap();
        assert!(String::from_utf8(one).unwrap().contains("X-Trace: two") );
        let by_value = run_in(r#"require "editheader"; deleteheader :contains "X-Trace" "tw";"#, MIXED, &c).edited.unwrap();
        assert!(String::from_utf8(by_value).unwrap().contains("X-Trace: one\r\nMIME"));
        for protected in ["Received", "X-Unomail-Filter", "DKIM-Signature", "Return-Path"] {
            assert!(compile(&format!(r#"require "editheader"; deleteheader "{protected}";"#)).is_err(), "{protected}");
            assert!(compile(&format!(r#"require "editheader"; addheader "{protected}" "x";"#)).is_err(), "{protected}");
        }
        // A line break smuggled in through an encoding is refused, at compile time and at run time.
        assert!(compile(r#"require ["editheader", "encoded-character"]; addheader "X-A" "one${hex:0D 0A}Bcc: evil@example.org";"#).is_err());
        let smuggled = run_in(r#"require ["editheader", "variables", "encoded-character"]; set "v" "one${hex:0D 0A}Bcc: evil@example.org"; addheader "X-A" "${v}";"#, MIXED, &c);
        assert_eq!(smuggled.edited, None);
        assert_eq!(run_in("keep;", MIXED, &c).edited, None);
    }

    #[test]
    fn reject_notify_and_fcc() {
        let c = context();
        let rejected = run_in(r#"require "reject"; reject "Not here, please.";"#, MIXED, &c);
        assert_eq!((rejected.reject.as_deref(), rejected.keep), (Some("Not here, please."), None));
        assert_eq!(run_in(r#"require ["reject", "fileinto"]; fileinto "x"; reject "no";"#, MIXED, &c), inbox(), "reject cannot go with fileinto");
        assert!(compile(r#"require "ereject"; ereject "550 nope";"#).is_ok());

        let notified = run_in(r#"require ["enotify", "variables", "fcc"];
            if valid_notify_method "mailto:bob@phone.example" {
                notify :importance "1" :message "From ${from}" :fcc "Sent" "mailto:bob@phone.example?subject=x";
            }
            set "from" "boss";"#, MIXED, &c);
        assert_eq!(notified.notify.len(), 1);
        assert_eq!(notified.notify[0].to, "bob@phone.example");
        assert_eq!(notified.notify[0].importance, 1);
        assert_eq!(notified.notify[0].fcc.as_ref().map(|f| f.mailbox.as_str()), Some("Sent"));
        assert!(compile(r#"require "enotify"; notify "xmpp:bob@chat.example";"#).is_err(), "only mailto");
        let vacation = run_in(r#"require ["vacation", "vacation-seconds", "fcc"]; vacation :seconds 7200 :fcc "Sent" "Away.";"#, MIXED, &c).vacation.unwrap();
        assert_eq!((vacation.seconds, vacation.fcc.map(|f| f.mailbox)), (Some(7200), Some("Sent".to_owned())));
        assert!(compile(r#"require "vacation"; vacation :seconds 60 "x";"#).is_err(), ":seconds needs vacation-seconds");
    }

    #[test]
    fn mime_parts_loops_and_extracted_text() {
        let c = context();
        let filed_in = |script: &str| run_in(script, MIXED, &c).fileinto.into_iter().map(|f| f.mailbox).collect::<Vec<_>>();
        assert_eq!(filed_in(r#"require ["fileinto", "mime"]; if header :mime :anychild :contenttype "Content-Type" "application/pdf" { fileinto "PDF"; }"#), ["PDF"]);
        assert_eq!(filed_in(r#"require ["fileinto", "mime"]; if header :mime :anychild :param "name" "Content-Type" "report.pdf" { fileinto "Named"; }"#), ["Named"]);
        assert_eq!(filed_in(r#"require ["fileinto", "mime"]; if header :mime :type "Content-Type" "multipart" { fileinto "Multi"; }"#), ["Multi"]);
        assert_eq!(filed_in(r#"require ["fileinto", "foreverypart", "mime", "extracttext", "variables"];
            foreverypart {
                if header :mime :subtype "Content-Type" "plain" {
                    extracttext :first 7 "text";
                    fileinto "Text: ${text}";
                    break;
                }
            }"#), ["Text: Numbers"]);
        assert!(compile(r#"require ["foreverypart"]; break;"#).is_err(), "break outside a loop");
        assert!(compile(r#"require ["foreverypart"]; foreverypart :name "a" { break :name "b"; }"#).is_err());
        assert!(compile(r#"require ["extracttext", "variables"]; extracttext "x";"#).is_err(), "extracttext only inside foreverypart");
    }

    #[test]
    fn encoded_characters() {
        let c = context();
        let filed = run_in(r#"require ["fileinto", "encoded-character"]; fileinto "${hex:52 65}${unicode:70 6F}rt";"#, MIXED, &c);
        assert_eq!(filed.fileinto[0].mailbox, "Report");
        assert!(compile(r#"require "encoded-character"; keep :flags "${hex:zz}";"#).is_err());
    }

    #[test]
    fn implicit_keep_and_basic_actions() {
        assert_eq!(run(""), inbox());
        assert_eq!(run("# just a comment\n/* block\ncomment */ keep;"), inbox());
        assert_eq!(run("discard;"), Outcome::default());
        assert_eq!(run("require \"fileinto\"; fileinto \"Work\";").fileinto, vec![filed("Work", false, &[])]);
        assert_eq!(run("require \"fileinto\"; fileinto \"Work\";").keep, None);
        let copy = run("require [\"fileinto\", \"copy\"]; fileinto :copy \"Work\";");
        assert_eq!((copy.keep, copy.fileinto.len()), (Some(vec![]), 1));
        assert_eq!(run("redirect \"Other@Example.NET\";").redirect, vec!["other@example.net"]);
        assert_eq!(run("discard; keep;"), inbox(), "an explicit keep wins over discard");
        assert_eq!(run("stop; discard;"), inbox());
    }

    #[test]
    fn tests_and_control_flow() {
        let script = r#"
            require ["fileinto", "envelope", "body", "imap4flags", "mailbox"];
            if header :contains "subject" "résumé" { addflag "\\Flagged"; }
            if allof (address :domain :is "from" "corp.example", not exists "X-Missing") {
                fileinto :create "Boss";
            } elsif true {
                discard;
            } else {
                keep;
            }
            if anyof (size :over 1M, envelope :localpart :matches "from" "bounce+*") { addflag ["$bulk", "seen-it"]; }
            if body :contains "cheap watches" { fileinto :flags "\\Seen" "Junk"; stop; }
            fileinto "Never";
        "#;
        let outcome = run(script);
        assert_eq!(outcome.keep, None);
        assert_eq!(
            outcome.fileinto,
            vec![filed("Boss", true, &["\\Flagged"]), filed("Junk", false, &["\\Seen"])]
        );

        assert_eq!(run("if header :is \"X-Spam-Status\" \"yes, SCORE=9\" { discard; }"), Outcome::default(), "comparisons ignore case");
        assert_eq!(run("if header :matches \"list-id\" \"<*.lists.example>\" { discard; }"), Outcome::default());
        assert_eq!(run("if header :matches \"list-id\" \"<?.lists.example>\" { discard; }"), inbox());
        assert_eq!(run("if address :localpart \"to\" \"bob\" { discard; }"), Outcome::default());
        assert_eq!(run("if address :is [\"to\", \"cc\"] \"team@example.org\" { discard; }"), Outcome::default());
        assert_eq!(run("if header :contains \"from\" \"big boss\" { discard; }"), Outcome::default(), "display names are searchable");
        assert_eq!(run("if size :under 10K { discard; }"), Outcome::default());
        assert_eq!(run("if exists [\"from\", \"x-nope\"] { discard; }"), inbox());
        assert_eq!(run("require \"imap4flags\"; setflag \"a b\"; removeflag \"A\"; keep;").keep, Some(vec!["b".to_owned()]));
        assert_eq!(run("if false { discard; } else { redirect \"a@b.example\"; }").redirect.len(), 1);
    }

    #[test]
    fn multi_line_strings_and_escapes() {
        let script = "if header :is \"subject\" text:\nline one\n..dot\n.\n { discard; }\nif header :contains \"from\" \"\\\"Big Boss\\\"\" { discard; }";
        assert_eq!(run(script), Outcome::default());
    }

    #[test]
    fn regular_expressions() {
        assert_eq!(run("require \"regex\"; if header :regex \"x-spam-status\" \"score=([0-9]+)\" { discard; }"), Outcome::default());
        assert_eq!(run("require \"regex\"; if header :regex \"x-spam-status\" \"^no\" { discard; }"), inbox());
        assert_eq!(run("require \"regex\"; if address :regex :localpart \"from\" \"^b[aeiou]ss$\" { discard; }"), Outcome::default());
        assert_eq!(compile("if header :regex \"a\" \"b\" { keep; }").unwrap_err().to_string(), "line 1: :regex needs: require \"regex\";");
        assert!(compile("require \"regex\"; if header :regex \"a\" \"(unclosed\" { keep; }").unwrap_err().message.starts_with("invalid regular expression"));
        // Catastrophic patterns cannot stall delivery: matching is linear time.
        let started = std::time::Instant::now();
        run("require \"regex\"; if header :regex \"subject\" \"(a+)+(b+)+(c+)+$\" { discard; }");
        assert!(started.elapsed().as_secs() < 2);
    }

    #[test]
    fn variables_and_match_captures() {
        let script = r#"
            require ["variables", "fileinto", "regex", "envelope"];
            set "folder" "Lists";
            if header :matches "list-id" "<*.lists.example>" { set :upperfirst "list" "${1}"; fileinto "${folder}/${list}"; }
            if header :regex "x-spam-status" "score=([0-9]+)" { set "score" "${1}"; }
            if string :is "${score}" "9" { redirect "quarantine+${SCORE}@example.net"; }
            set :length "len" "${folder}";
            if string "${len}" "5" { set :upper "shout" "ok ${undefined}!"; }
            if string :matches "${shout}" "OK *" { fileinto "Seen-${0}"; }
        "#;
        let outcome = run(script);
        assert_eq!(outcome.fileinto.iter().map(|f| f.mailbox.as_str()).collect::<Vec<_>>(), ["Lists/Announce", "Seen-OK !"]);
        assert_eq!(outcome.redirect, ["quarantine+9@example.net"]);

        // Without the extension "${x}" is plain text, and names built at run time are validated.
        assert_eq!(run("require \"fileinto\"; fileinto \"a${b}\";").fileinto[0].mailbox, "a${b}");
        assert_eq!(run("require [\"variables\", \"fileinto\"]; set \"x\" \"bad%name\"; fileinto \"${x}\";"), inbox(), "an invalid computed folder falls back to keep");
        assert_eq!(run("require \"variables\"; set \"x\" \"nonsense\"; redirect \"${x}\";"), inbox());
        assert_eq!(run("require \"variables\"; set :quotewildcard \"q\" \"a*b\"; if string \"${q}\" \"a\\\\*b\" { discard; }"), Outcome::default());
        assert_eq!(compile("set \"a\" \"b\";").unwrap_err().to_string(), "line 1: set needs: require \"variables\";");
        assert!(compile("require \"variables\"; set \"1x\" \"b\";").is_err());
    }

    #[test]
    fn vacation_action() {
        let outcome = run("require [\"vacation\", \"variables\"]; set \"who\" \"Bob\"; vacation :days 3 :subject \"Away\r\nBcc: x@y\" :addresses [\"Bob.Alt@example.org\"] :handle \"h1\" \"${who} is away.\";");
        let vacation = outcome.vacation.expect("vacation requested");
        assert_eq!((vacation.days, vacation.reason.as_str(), vacation.handle.as_str()), (3, "Bob is away.", "h1"));
        assert_eq!(vacation.subject, "AwayBcc: x@y", "header injection through the subject is impossible");
        assert_eq!(vacation.addresses, ["bob.alt@example.org"]);
        assert_eq!(outcome.keep, Some(vec![]), "vacation does not cancel the implicit keep");
        for (script, expected) in [
            ("vacation \"x\";", "vacation needs: require \"vacation\";"),
            ("require \"vacation\"; vacation :days 0 \"x\";", ":days must be between 1 and 90"),
            ("require \"vacation\"; vacation :mime \"x\";", "a :mime reason needs MIME headers, a blank line and a body"),
            ("require \"vacation\"; vacation :mime \"Bcc: evil@example.net\nContent-Type: text/plain\n\nhi\";", "only Content-* headers are allowed in a :mime reason"),
            ("require \"vacation\"; vacation :mime \"Content-Disposition: inline\n\nhi\";", "a :mime reason needs a Content-Type header"),
            ("require \"vacation\"; vacation \"  \";", "the vacation reason must be between 1 and 10000 characters"),
        ] {
            assert_eq!(compile(script).unwrap_err().message, expected, "{script}");
        }
    }

    #[test]
    fn vacation_mime_reason() {
        let outcome = run("require \"vacation\"; vacation :mime \"Content-Type: text/html; charset=utf-8\n\n<p>Away</p>\";");
        let vacation = outcome.vacation.unwrap();
        assert!(vacation.mime && vacation.reason.contains("<p>Away</p>"));
        assert!(check_mime_entity("Content-Type: multipart/alternative;\r\n boundary=x\r\n\r\n--x--").is_ok());
        assert!(check_mime_entity("Content-Type: text/plain\n\n   ").is_err());
    }

    #[test]
    fn included_scripts() {
        let library = |name: &str, global: bool| -> Option<String> {
            if global {
                return (name == "policy").then(|| "if size :over 1G { discard; stop; }".to_owned());
            }
            match name {
                "spam" => Some("require [\"imap4flags\", \"include\"]; if header :contains \"x-spam-status\" \"yes\" { addflag \"junk-ish\"; return; } discard;".into()),
                "lists" => Some("require \"fileinto\"; if exists \"list-id\" { fileinto \"Lists\"; stop; }".into()),
                "loop-a" => Some("require \"include\"; include \"loop-b\";".into()),
                "loop-b" => Some("require \"include\"; include \"loop-a\";".into()),
                "broken" => Some("keep".into()),
                _ => None,
            }
        };
        let env = Envelope::new("a@b.example", "bob@example.org", MESSAGE);
        let script = "require [\"include\", \"imap4flags\"]; include :personal \"spam\"; include :once \"spam\"; include :once \"spam\"; include \"lists\"; discard;";
        // The first include is unconditional and :once only guards later :once includes.
        let outcome = compile_with(script, &library).unwrap().evaluate(&env);
        assert_eq!(outcome.fileinto, vec![filed("Lists", false, &["junk-ish"])], "return leaves the include, stop ends the run");
        assert_eq!(outcome.keep, None);

        assert_eq!(compile_with("require \"include\"; include :optional \"missing\"; keep;", &library).unwrap().evaluate(&env), inbox());
        // Global scripts are a separate namespace provided by the administrator.
        assert_eq!(compile_with("require \"include\"; include :global \"policy\"; include :personal :optional \"policy\";", &library).unwrap().evaluate(&env), inbox());
        for (script, expected) in [
            ("include \"spam\";", "line 1: include needs: require \"include\";"),
            ("require \"include\"; include \"missing\";", "line 1: included script \"missing\" does not exist"),
            ("require \"include\"; include :global \"x\";", "line 1: included script \"x\" does not exist"),
            ("require \"include\"; include :global \"spam\";", "line 1: included script \"spam\" does not exist"),
            ("require \"include\"; include \"loop-a\";", "line 1: in included script \"loop-a\": line 1: in included script \"loop-b\": line 1: script \"loop-a\" includes itself"),
            ("require \"include\";\ninclude \"broken\";", "line 2: in included script \"broken\": line 1: expected ';'"),
            ("return;", "line 1: return needs: require \"include\";"),
        ] {
            assert_eq!(compile_with(script, &library).unwrap_err().to_string(), expected, "{script}");
        }
    }

    #[test]
    fn invalid_scripts_are_rejected_with_a_line_number() {
        for (script, expected) in [
            ("keep", "line 1: expected ';'"),
            ("\n\nfrobnicate;", "line 3: unknown command \"frobnicate\""),
            ("fileinto \"x\";", "line 1: fileinto needs: require \"fileinto\";"),
            ("require \"convert\";", "line 1: unsupported extension \"convert\""),
            ("if bogus { keep; }", "line 1: unknown test \"bogus\""),
            ("if true { keep;", "line 1: expected '}'"),
            ("redirect \"not an address\";", "line 1: invalid redirect address"),
            ("require \"fileinto\"; fileinto \"a%b\";", "line 1: invalid mailbox name"),
            ("if size :huge 1 { keep; }", "line 1: size needs :over or :under"),
            ("if header :bogus \"a\" \"b\" { keep; }", "line 1: unsupported tag :bogus"),
            ("keep; \"unterminated", "line 1: unterminated string"),
            ("if envelope \"from\" \"x\" { keep; }", "line 1: the envelope test needs: require \"envelope\";"),
            ("if size :over 99999999999999999999 { keep; }", "line 1: number too large"),
            ("keep; @", "line 1: unexpected character '@'"),
        ] {
            assert_eq!(compile(script).unwrap_err().to_string(), expected, "{script}");
        }
        let deep = format!("if {} true {{ keep; }}", "not ".repeat(40));
        assert!(compile(&deep).unwrap_err().message.contains("nested too deeply"));
        assert!(compile(&"#".repeat(MAX_SCRIPT_BYTES + 1)).is_err());
    }

    #[test]
    fn resource_limits_hold() {
        let many: String = (0..20).map(|i| format!("redirect \"u{i}@example.net\";")).collect();
        assert_eq!(run(&many).redirect.len(), MAX_REDIRECTS, "a script cannot fan a message out without bound");
        // A pathological glob finishes quickly instead of backtracking forever.
        let pattern = "*a".repeat(30);
        let started = std::time::Instant::now();
        run(&format!("if header :matches \"subject\" \"{pattern}b\" {{ discard; }}"));
        assert!(started.elapsed().as_secs() < 2);
        // Variables cannot grow without bound.
        let grow: String = std::iter::once("require \"variables\"; set \"v\" \"xxxxxxxxxx\";".to_owned()).chain((0..30).map(|_| "set \"v\" \"${v}${v}\";".to_owned())).collect();
        let started = std::time::Instant::now();
        run(&grow);
        assert!(started.elapsed().as_secs() < 2);
        assert!(valid_script_name("vacation-2026.sieve") && !valid_script_name("../x") && !valid_script_name(""));
    }
}
