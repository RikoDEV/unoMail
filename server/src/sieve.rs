//! Sieve mail filtering (RFC 5228) with the `fileinto`, `envelope`, `imap4flags`, `copy`,
//! `body`, `mailbox`, `regex`, `variables`, `vacation` and `include` extensions. Scripts are parsed and validated when saved and
//! interpreted at delivery time under strict resource limits.

use std::collections::HashMap;

use mail_parser::MessageParser;

use crate::{security::authn::find_header_end, util::Address};

pub const MAX_SCRIPT_BYTES: usize = 64 * 1024;
const MAX_DEPTH: usize = 16;
pub const MAX_REDIRECTS: usize = 5;
const MAX_FILEINTO: usize = 10;
const MAX_INCLUDE_DEPTH: usize = 5;
const MAX_VARIABLES: usize = 100;
const MAX_VARIABLE_BYTES: usize = 4000;
pub const SUPPORTED: [&str; 11] = [
    "fileinto", "envelope", "imap4flags", "copy", "body", "mailbox", "regex", "variables", "vacation", "include", "comparator-i;ascii-casemap",
];

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

#[derive(Debug, Clone, Copy, PartialEq)]
enum Match {
    Is,
    Contains,
    Matches,
    Regex,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Part {
    All,
    Local,
    Domain,
}

#[derive(Debug, Clone)]
enum Test {
    True,
    False,
    Not(Box<Test>),
    AllOf(Vec<Test>),
    AnyOf(Vec<Test>),
    Exists(Vec<String>),
    Size { over: bool, limit: u64 },
    Header { names: Vec<String>, keys: Vec<String>, how: Match },
    Address { part: Part, names: Vec<String>, keys: Vec<String>, how: Match },
    Envelope { part: Part, names: Vec<String>, keys: Vec<String>, how: Match },
    Body { keys: Vec<String>, how: Match },
    /// `string` test of the variables extension.
    Str { sources: Vec<String>, keys: Vec<String>, how: Match },
}

#[derive(Debug, Clone)]
enum Command {
    If(Vec<(Option<Test>, Vec<Command>)>),
    Stop,
    /// Leaves the current included script.
    Return,
    Keep { flags: Vec<String> },
    Discard,
    FileInto { mailbox: String, copy: bool, create: bool, flags: Vec<String> },
    Redirect { address: String, copy: bool },
    Flags { op: FlagOp, flags: Vec<String> },
    Set { name: String, value: String, modifiers: Vec<String> },
    Vacation(Vacation),
    /// The commands of an included script; `once` scripts carry their name.
    Include { commands: Vec<Command>, once: Option<String> },
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
        Ok(out)
    }

    /// Parses the tagged arguments shared by header-like tests.
    fn match_tags(&mut self, allow_part: bool) -> Result<(Match, Part), SieveError> {
        let (mut how, mut part) = (Match::Is, Part::All);
        while let Some(Token::Tag(tag)) = self.peek().cloned() {
            self.pos += 1;
            match tag.as_str() {
                "is" => how = Match::Is,
                "contains" => how = Match::Contains,
                "matches" => how = Match::Matches,
                "regex" => {
                    self.need("regex", ":regex")?;
                    how = Match::Regex;
                }
                "comparator" => {
                    let name = self.string()?;
                    if name != "i;ascii-casemap" {
                        return self.err("only the i;ascii-casemap comparator is supported");
                    }
                }
                "all" if allow_part => part = Part::All,
                "localpart" if allow_part => part = Part::Local,
                "domain" if allow_part => part = Part::Domain,
                "text" | "raw" if !allow_part => {}
                other => return self.err(format!("unsupported tag :{other}")),
            }
        }
        Ok((how, part))
    }

    /// Key list of a test; regular expressions are compiled once here to report mistakes.
    fn keys(&mut self, how: Match) -> Result<Vec<String>, SieveError> {
        let keys = self.string_list()?;
        if how == Match::Regex {
            for key in keys.iter().filter(|k| !self.dynamic(k)) {
                if let Err(err) = build_regex(key) {
                    return self.err(format!("invalid regular expression: {err}"));
                }
            }
        }
        Ok(keys)
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
            "exists" => Test::Exists(self.string_list()?),
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
                let (how, _) = self.match_tags(false)?;
                Test::Header { names: self.string_list()?, keys: self.keys(how)?, how }
            }
            "address" | "envelope" => {
                if name == "envelope" {
                    self.need("envelope", "the envelope test")?;
                }
                let (how, part) = self.match_tags(true)?;
                let (names, keys) = (self.string_list()?, self.keys(how)?);
                if name == "envelope" {
                    if let Some(bad) = names.iter().find(|n| !matches!(n.to_ascii_lowercase().as_str(), "from" | "to")) {
                        return self.err(format!("unknown envelope part \"{bad}\""));
                    }
                    Test::Envelope { part, names, keys, how }
                } else {
                    Test::Address { part, names, keys, how }
                }
            }
            "body" => {
                self.need("body", "the body test")?;
                let (how, _) = self.match_tags(false)?;
                Test::Body { keys: self.keys(how)?, how }
            }
            "string" => {
                self.need("variables", "the string test")?;
                let (how, _) = self.match_tags(false)?;
                Test::Str { sources: self.string_list()?, keys: self.keys(how)?, how }
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
        let mut inner = Parser { tokens: tokenize(&source).map_err(wrap)?, pos: 0, required: Vec::new(), loader: self.loader, including, uses_variables: false };
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
                let (mut copy, mut create, mut flags) = (false, false, Vec::new());
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
                        other => return self.err(format!("unsupported tag :{other}")),
                    }
                }
                let mailbox = self.string()?;
                if !self.dynamic(&mailbox) && crate::store::validate_mailbox_name(&mailbox).is_err() {
                    return self.err("invalid mailbox name");
                }
                Command::FileInto { mailbox, copy, create, flags }
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
                let valid = !name.is_empty() && name.len() <= 64 && !name.starts_with(|c: char| c.is_ascii_digit()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
                if !valid {
                    return self.err("invalid variable name");
                }
                Command::Set { name, value: self.string()?, modifiers }
            }
            "vacation" => Command::Vacation(self.vacation()?),
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
    let mut parser = Parser { tokens: tokenize(source)?, pos: 0, required: Vec::new(), loader, including: Vec::new(), uses_variables: false };
    let mut commands = Vec::new();
    while parser.peek().is_some() {
        if let Some(command) = parser.command(0)? {
            commands.push(command);
        }
    }
    let variables = parser.uses_variables || parser.has("variables");
    Ok(Script { commands, variables })
}

/// What should happen to a message after the script ran.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Deliver to the inbox (with these flags).
    pub keep: Option<Vec<String>>,
    /// (mailbox, create if missing, flags)
    pub fileinto: Vec<(String, bool, Vec<String>)>,
    pub redirect: Vec<String>,
    pub vacation: Option<Vacation>,
}

pub struct Envelope<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub raw: &'a [u8],
}

enum Flow {
    Continue,
    Return,
    Stop,
}

struct Runtime<'a> {
    env: &'a Envelope<'a>,
    headers: HashMap<String, Vec<String>>,
    addresses: HashMap<String, Vec<String>>,
    flags: Vec<String>,
    implicit_keep: bool,
    outcome: Outcome,
    variables: HashMap<String, String>,
    /// `${0}`..`${9}` from the most recent successful :matches or :regex test.
    captures: std::cell::RefCell<Vec<String>>,
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

fn build_regex(pattern: &str) -> Result<regex::Regex, String> {
    // The regex crate guarantees linear-time matching; the size limit bounds compilation.
    regex::RegexBuilder::new(pattern).case_insensitive(true).size_limit(1 << 20).build().map_err(|e| e.to_string().lines().last().unwrap_or("syntax error").trim().to_owned())
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

/// Compares `value` against `key`; returns the captured groups for wildcard and regex matches.
fn compare(how: Match, value: &str, key: &str) -> Option<Vec<String>> {
    match how {
        Match::Is => (value.to_lowercase() == key.to_lowercase()).then(Vec::new),
        Match::Contains => value.to_lowercase().contains(&key.to_lowercase()).then(Vec::new),
        Match::Matches | Match::Regex => {
            let pattern = if how == Match::Matches { glob_to_regex(key) } else { key.to_owned() };
            let regex = build_regex(&pattern).ok()?;
            let value: String = value.chars().take(8192).collect();
            let found = regex.captures(&value)?;
            Some(found.iter().take(10).map(|group| group.map_or(String::new(), |m| m.as_str().to_owned())).collect())
        }
    }
}

fn address_part(address: &str, part: Part) -> String {
    match (part, address.rsplit_once('@')) {
        (Part::All, _) | (_, None) => address.to_owned(),
        (Part::Local, Some((local, _))) => local.to_owned(),
        (Part::Domain, Some((_, domain))) => domain.to_owned(),
    }
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

    fn any(&self, values: impl Iterator<Item = String>, keys: &[String], how: Match) -> bool {
        let values: Vec<String> = values.collect();
        for key in keys {
            let key = self.expand(key);
            for value in &values {
                if let Some(captures) = compare(how, value, &key) {
                    if !captures.is_empty() {
                        *self.captures.borrow_mut() = captures;
                    }
                    return true;
                }
            }
        }
        false
    }

    fn test(&self, test: &Test) -> bool {
        match test {
            Test::True => true,
            Test::False => false,
            Test::Not(inner) => !self.test(inner),
            Test::AllOf(tests) => tests.iter().all(|t| self.test(t)),
            Test::AnyOf(tests) => tests.iter().any(|t| self.test(t)),
            Test::Exists(names) => names.iter().all(|n| self.headers.contains_key(&n.to_ascii_lowercase())),
            Test::Size { over, limit } => {
                let size = self.env.raw.len() as u64;
                if *over { size > *limit } else { size < *limit }
            }
            Test::Header { names, keys, how } => {
                let values = names.iter().filter_map(|n| self.headers.get(&n.to_ascii_lowercase())).flatten().cloned();
                self.any(values, keys, *how)
            }
            Test::Address { part, names, keys, how } => {
                let values = names.iter().filter_map(|n| self.addresses.get(&n.to_ascii_lowercase())).flatten().map(|a| address_part(a, *part));
                self.any(values, keys, *how)
            }
            Test::Envelope { part, names, keys, how } => {
                let values = names.iter().map(|n| if n.eq_ignore_ascii_case("from") { self.env.from } else { self.env.to }).map(|a| address_part(a, *part));
                self.any(values, keys, *how)
            }
            Test::Body { keys, how } => {
                let body = String::from_utf8_lossy(&self.env.raw[find_header_end(self.env.raw)..]).trim().to_owned();
                self.any(std::iter::once(body), keys, *how)
            }
            Test::Str { sources, keys, how } => {
                let values: Vec<String> = sources.iter().map(|s| self.expand(s)).collect();
                self.any(values.into_iter(), keys, *how)
            }
        }
    }

    fn with_flags(&self, explicit: &[String]) -> Vec<String> {
        if explicit.is_empty() { self.flags.clone() } else { explicit.iter().map(|f| self.expand(f)).collect() }
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
                Command::Include { commands, once } => {
                    if let Some(name) = once {
                        if self.included_once.contains(name) {
                            continue;
                        }
                        self.included_once.push(name.clone());
                    }
                    // `return` only leaves the included script; `stop` ends everything.
                    if let Flow::Stop = self.run(commands) {
                        return Flow::Stop;
                    }
                }
                Command::Keep { flags } => self.outcome.keep = Some(self.with_flags(flags)),
                Command::Discard => self.implicit_keep = false,
                Command::FileInto { mailbox, copy, create, flags } => {
                    let mailbox = self.expand(mailbox);
                    // Names built from variables are checked here instead of at compile time.
                    if crate::store::validate_mailbox_name(&mailbox).is_ok() {
                        if self.outcome.fileinto.len() < MAX_FILEINTO && !self.outcome.fileinto.iter().any(|(m, ..)| *m == mailbox) {
                            self.outcome.fileinto.push((mailbox, *create, self.with_flags(flags)));
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
                    let mut value = self.expand(value);
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
                        subject: crate::util::sanitize_line(&self.expand(&vacation.subject)),
                        reason,
                        addresses: vacation.addresses.clone(),
                        handle: self.expand(&vacation.handle),
                    });
                }
            }
        }
        Flow::Continue
    }
}

impl Script {
    /// Runs the script against a message. Evaluation cannot fail: every problem is caught
    /// when the script is compiled.
    pub fn evaluate(&self, env: &Envelope<'_>) -> Outcome {
        let mut headers: HashMap<String, Vec<String>> = HashMap::new();
        let mut addresses: HashMap<String, Vec<String>> = HashMap::new();
        if let Some(message) = MessageParser::default().parse_headers(env.raw) {
            for (name, value) in message.headers_raw() {
                let value: String = value.replace(['\r', '\n'], "").trim().to_owned();
                headers.entry(name.to_ascii_lowercase()).or_default().push(value);
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
        let mut runtime = Runtime {
            env,
            headers,
            addresses,
            flags: Vec::new(),
            implicit_keep: true,
            outcome: Outcome::default(),
            variables: HashMap::new(),
            captures: std::cell::RefCell::new(Vec::new()),
            included_once: Vec::new(),
            expand_variables: self.variables,
        };
        runtime.run(&self.commands);
        if runtime.implicit_keep && runtime.outcome.keep.is_none() {
            runtime.outcome.keep = Some(runtime.flags.clone());
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

/// Stores a script. At most one script per account is active.
pub async fn save(app: &crate::app::App, account_id: i64, stored: &Stored) -> sqlx::Result<()> {
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
    tx.commit().await
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
        compile(script).unwrap().evaluate(&Envelope { from: "bounce+bob@mailer.example", to: "bob@example.org", raw: MESSAGE })
    }

    fn inbox() -> Outcome {
        Outcome { keep: Some(vec![]), ..Default::default() }
    }

    #[test]
    fn implicit_keep_and_basic_actions() {
        assert_eq!(run(""), inbox());
        assert_eq!(run("# just a comment\n/* block\ncomment */ keep;"), inbox());
        assert_eq!(run("discard;"), Outcome::default());
        assert_eq!(run("require \"fileinto\"; fileinto \"Work\";").fileinto, vec![("Work".to_owned(), false, vec![])]);
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
            vec![
                ("Boss".to_owned(), true, vec!["\\Flagged".to_owned()]),
                ("Junk".to_owned(), false, vec!["\\Seen".to_owned()]),
            ]
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
        assert_eq!(outcome.fileinto.iter().map(|(m, ..)| m.as_str()).collect::<Vec<_>>(), ["Lists/Announce", "Seen-OK !"]);
        assert_eq!(outcome.redirect, ["quarantine+9@example.net"]);

        // Without the extension "${x}" is plain text, and names built at run time are validated.
        assert_eq!(run("require \"fileinto\"; fileinto \"a${b}\";").fileinto[0].0, "a${b}");
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
        let env = Envelope { from: "a@b.example", to: "bob@example.org", raw: MESSAGE };
        let script = "require [\"include\", \"imap4flags\"]; include :personal \"spam\"; include :once \"spam\"; include :once \"spam\"; include \"lists\"; discard;";
        // The first include is unconditional and :once only guards later :once includes.
        let outcome = compile_with(script, &library).unwrap().evaluate(&env);
        assert_eq!(outcome.fileinto, vec![("Lists".to_owned(), false, vec!["junk-ish".to_owned()])], "return leaves the include, stop ends the run");
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
            ("require \"spamtest\";", "line 1: unsupported extension \"spamtest\""),
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
