//! IMAP command tokenizer, sequence sets and response string encoding.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    Atom(String),
    /// Quoted string or literal.
    Str(Vec<u8>),
    List(Vec<Arg>),
}

impl Arg {
    /// The argument as text, for atoms and strings alike (astring).
    pub fn text(&self) -> Option<String> {
        match self {
            Arg::Atom(a) => Some(a.clone()),
            Arg::Str(s) => String::from_utf8(s.clone()).ok(),
            Arg::List(_) => None,
        }
    }

    pub fn atom_upper(&self) -> Option<String> {
        match self {
            Arg::Atom(a) => Some(a.to_ascii_uppercase()),
            _ => None,
        }
    }
}

/// A literal announced at the end of a line: `{123}` (synchronizing) or `{123+}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiteralRequest {
    pub len: usize,
    pub sync: bool,
}

/// Incremental tokenizer: fed line by line, with literals supplied in between.
#[derive(Default)]
pub struct Tokenizer {
    stack: Vec<Vec<Arg>>,
    top: Vec<Arg>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SyntaxError;

impl Tokenizer {
    fn push(&mut self, arg: Arg) {
        self.stack.last_mut().unwrap_or(&mut self.top).push(arg);
    }

    /// Tokenizes one line. Returns the literal the client announced at its end, if any.
    pub fn feed(&mut self, line: &[u8]) -> Result<Option<LiteralRequest>, SyntaxError> {
        let mut i = 0;
        while i < line.len() {
            match line[i] {
                b' ' => i += 1,
                b'(' => {
                    if self.stack.len() >= 16 {
                        return Err(SyntaxError);
                    }
                    self.stack.push(Vec::new());
                    i += 1;
                }
                b')' => {
                    let list = self.stack.pop().ok_or(SyntaxError)?;
                    self.push(Arg::List(list));
                    i += 1;
                }
                b'"' => {
                    let mut out = Vec::new();
                    i += 1;
                    loop {
                        match line.get(i) {
                            Some(b'"') => break,
                            Some(b'\\') => {
                                out.push(*line.get(i + 1).ok_or(SyntaxError)?);
                                i += 2;
                            }
                            Some(b) => {
                                out.push(*b);
                                i += 1;
                            }
                            None => return Err(SyntaxError),
                        }
                    }
                    i += 1;
                    self.push(Arg::Str(out));
                }
                // `~{n}` is a literal8 (RFC 3516): binary content, read like any literal.
                b'{' | b'~' if line[i] == b'{' || line.get(i + 1) == Some(&b'{') => {
                    let i = if line[i] == b'~' { i + 1 } else { i };
                    // A literal marker is only valid as the very last thing on the line.
                    let rest = std::str::from_utf8(&line[i + 1..]).map_err(|_| SyntaxError)?;
                    let body = rest.strip_suffix('}').ok_or(SyntaxError)?;
                    let (digits, sync) = match body.strip_suffix('+') {
                        Some(d) => (d, false),
                        None => (body, true),
                    };
                    if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(SyntaxError);
                    }
                    return Ok(Some(LiteralRequest { len: digits.parse().map_err(|_| SyntaxError)?, sync }));
                }
                _ => {
                    // Atom. Square brackets may enclose spaces and parentheses, as in
                    // BODY[HEADER.FIELDS (From To)]<0.100>.
                    let start = i;
                    let mut depth = 0usize;
                    while i < line.len() {
                        match line[i] {
                            b'[' => depth += 1,
                            b']' => depth = depth.saturating_sub(1),
                            b' ' | b'(' | b')' if depth == 0 => break,
                            _ => {}
                        }
                        i += 1;
                    }
                    let atom = std::str::from_utf8(&line[start..i]).map_err(|_| SyntaxError)?;
                    self.push(Arg::Atom(atom.to_owned()));
                }
            }
        }
        Ok(None)
    }

    pub fn feed_literal(&mut self, data: Vec<u8>) {
        self.push(Arg::Str(data));
    }

    pub fn finish(self) -> Result<Vec<Arg>, SyntaxError> {
        if self.stack.is_empty() { Ok(self.top) } else { Err(SyntaxError) }
    }
}

/// A parsed sequence set such as `1:3,7,10:*`. `u32::MAX` stands for `*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceSet(pub Vec<(u32, u32)>);

impl SequenceSet {
    pub fn parse(text: &str) -> Option<Self> {
        let number = |s: &str| -> Option<u32> {
            if s == "*" {
                Some(u32::MAX)
            } else {
                s.parse::<u32>().ok().filter(|n| *n > 0)
            }
        };
        let mut ranges = Vec::new();
        for part in text.split(',') {
            let range = match part.split_once(':') {
                Some((a, b)) => {
                    let (a, b) = (number(a)?, number(b)?);
                    (a.min(b), a.max(b))
                }
                None => {
                    let n = number(part)?;
                    (n, n)
                }
            };
            ranges.push(range);
        }
        (!ranges.is_empty() && ranges.len() <= 1000).then_some(SequenceSet(ranges))
    }

    /// True when `value` is in the set, with `*` meaning `max` (the highest existing number).
    pub fn contains(&self, value: u32, max: u32) -> bool {
        self.0.iter().any(|(lo, hi)| {
            let lo = if *lo == u32::MAX { max } else { *lo };
            let hi = if *hi == u32::MAX { max } else { *hi };
            // "n:*" always includes the last message, even when n is beyond it.
            let (lo, hi) = (lo.min(hi), lo.max(hi));
            value >= lo && value <= hi
        })
    }
}

/// Encodes bytes as an IMAP string: quoted when safely possible, otherwise as a literal.
pub fn string(out: &mut Vec<u8>, data: &[u8]) {
    let quotable = data.len() < 500 && data.iter().all(|b| (0x20..0x7f).contains(b) && *b != b'"' && *b != b'\\');
    if quotable {
        out.push(b'"');
        out.extend_from_slice(data);
        out.push(b'"');
    } else {
        out.extend_from_slice(format!("{{{}}}\r\n", data.len()).as_bytes());
        out.extend_from_slice(data);
    }
}

pub fn nstring(out: &mut Vec<u8>, data: Option<&[u8]>) {
    match data {
        Some(d) => string(out, d),
        None => out.extend_from_slice(b"NIL"),
    }
}

/// Matches a mailbox name against a LIST pattern (`*` matches anything, `%` anything but `/`).
pub fn list_match(pattern: &str, name: &str) -> bool {
    fn inner(p: &[u8], n: &[u8]) -> bool {
        match p.split_first() {
            None => n.is_empty(),
            Some((b'*', rest)) => (0..=n.len()).any(|i| inner(rest, &n[i..])),
            Some((b'%', rest)) => (0..=n.len()).take_while(|i| *i == 0 || n[i - 1] != b'/').any(|i| inner(rest, &n[i..])),
            Some((c, rest)) => n.split_first().is_some_and(|(d, n_rest)| c == d && inner(rest, n_rest)),
        }
    }
    // Patterns are client supplied; bound the work of the backtracking matcher.
    pattern.len() <= 200 && pattern.bytes().filter(|b| matches!(b, b'*' | b'%')).count() <= 8 && inner(pattern.as_bytes(), name.as_bytes())
}

/// Formats UIDs as a compact sequence set, e.g. `1:3,7`. The input must be sorted.
pub fn uid_set(uids: &[i64]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < uids.len() {
        let start = uids[i];
        let mut end = start;
        while i + 1 < uids.len() && uids[i + 1] == end + 1 {
            i += 1;
            end = uids[i];
        }
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&if start == end { start.to_string() } else { format!("{start}:{end}") });
        i += 1;
    }
    out
}

const UTF7_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

/// Encodes a mailbox name in modified UTF-7 (RFC 3501 section 5.1.3).
pub fn utf7_encode(name: &str) -> String {
    let mut out = String::new();
    let mut pending: Vec<u16> = Vec::new();
    let flush = |pending: &mut Vec<u16>, out: &mut String| {
        if pending.is_empty() {
            return;
        }
        let bytes: Vec<u8> = pending.iter().flat_map(|u| u.to_be_bytes()).collect();
        out.push('&');
        for chunk in bytes.chunks(3) {
            let n = (u32::from(chunk[0]) << 16) | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8) | u32::from(*chunk.get(2).unwrap_or(&0));
            for i in 0..=chunk.len() {
                out.push(UTF7_ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        out.push('-');
        pending.clear();
    };
    for c in name.chars() {
        if (' '..='~').contains(&c) {
            flush(&mut pending, &mut out);
            out.push(c);
            if c == '&' {
                out.push('-');
            }
        } else {
            let mut buf = [0u16; 2];
            pending.extend_from_slice(c.encode_utf16(&mut buf));
        }
    }
    flush(&mut pending, &mut out);
    out
}

/// Decodes modified UTF-7. Input that is not valid modified UTF-7 is returned unchanged, so
/// clients that send raw UTF-8 names keep working.
pub fn utf7_decode(name: &str) -> String {
    fn decode(name: &str) -> Option<String> {
        let mut out = String::new();
        let mut rest = name;
        while let Some(pos) = rest.find('&') {
            out.push_str(&rest[..pos]);
            let end = pos + rest[pos..].find('-')?;
            let encoded = &rest[pos + 1..end];
            if encoded.is_empty() {
                out.push('&');
            } else {
                let mut bits: u32 = 0;
                let mut count = 0;
                let mut bytes = Vec::new();
                for b in encoded.bytes() {
                    bits = (bits << 6) | UTF7_ALPHABET.iter().position(|c| *c == b)? as u32;
                    count += 6;
                    if count >= 8 {
                        count -= 8;
                        bytes.push((bits >> count) as u8);
                        bits &= (1 << count) - 1;
                    }
                }
                if bytes.len() % 2 != 0 || bits != 0 {
                    return None;
                }
                let units: Vec<u16> = bytes.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                out.push_str(&String::from_utf16(&units).ok()?);
            }
            rest = &rest[end + 1..];
        }
        out.push_str(rest);
        Some(out)
    }
    if !name.is_ascii() {
        return name.to_owned();
    }
    decode(name).unwrap_or_else(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_commands_do_not_panic() {
        for line in crate::fuzzing::inputs(9, 4000, 12) {
            let mut tokenizer = Tokenizer::default();
            if let Ok(Some(literal)) = tokenizer.feed(&line) {
                // The session refuses big literals before reading them; feed a small one.
                tokenizer.feed_literal(vec![b'x'; literal.len.min(16)]);
            }
            let _ = tokenizer.finish();
            let text = String::from_utf8_lossy(&line);
            if let Some(set) = SequenceSet::parse(&text) {
                let _ = set.contains(1, u32::MAX);
            }
            let _ = utf7_decode(&text);
            let _ = list_match(&text, "INBOX/Sub");
        }
    }

    fn tokens(line: &str) -> Vec<Arg> {
        let mut t = Tokenizer::default();
        assert_eq!(t.feed(line.as_bytes()), Ok(None));
        t.finish().unwrap()
    }

    fn atom(s: &str) -> Arg {
        Arg::Atom(s.into())
    }

    #[test]
    fn tokenizes_atoms_strings_and_lists() {
        assert_eq!(
            tokens(r#"a1 LOGIN "bob@example.org" "pa\"ss\\word""#),
            vec![atom("a1"), atom("LOGIN"), Arg::Str(b"bob@example.org".to_vec()), Arg::Str(b"pa\"ss\\word".to_vec())]
        );
        assert_eq!(
            tokens("a2 UID FETCH 1:* (FLAGS BODY.PEEK[HEADER.FIELDS (From To)]<0.100>)"),
            vec![
                atom("a2"), atom("UID"), atom("FETCH"), atom("1:*"),
                Arg::List(vec![atom("FLAGS"), atom("BODY.PEEK[HEADER.FIELDS (From To)]<0.100>")]),
            ]
        );
        assert_eq!(tokens("a STORE 1 +FLAGS (\\Seen (nested))"), vec![atom("a"), atom("STORE"), atom("1"), atom("+FLAGS"), Arg::List(vec![atom("\\Seen"), Arg::List(vec![atom("nested")])])]);
    }

    #[test]
    fn literals_and_errors() {
        let mut t = Tokenizer::default();
        assert_eq!(t.feed(b"a APPEND INBOX (\\Seen) {11}"), Ok(Some(LiteralRequest { len: 11, sync: true })));
        t.feed_literal(b"hello world".to_vec());
        assert_eq!(t.feed(b""), Ok(None));
        assert_eq!(t.finish().unwrap()[4], Arg::Str(b"hello world".to_vec()));

        let mut t = Tokenizer::default();
        assert_eq!(t.feed(b"a LOGIN {3+}"), Ok(Some(LiteralRequest { len: 3, sync: false })));

        for bad in ["a LOGIN \"unterminated", "a X {12", "a X {abc}", "a X {-1}", "a X {99999999999}", "a X )"] {
            assert!(Tokenizer::default().feed(bad.as_bytes()).is_err(), "{bad}");
        }
        let mut t = Tokenizer::default();
        t.feed(b"a X (unclosed").unwrap();
        assert!(t.finish().is_err());
        let deep = format!("a X {}", "(".repeat(40));
        assert!(Tokenizer::default().feed(deep.as_bytes()).is_err(), "nesting depth is bounded");
    }

    #[test]
    fn sequence_sets() {
        let set = SequenceSet::parse("1:3,7,10:*").unwrap();
        for (value, expected) in [(1, true), (3, true), (4, false), (7, true), (9, false), (10, true), (15, true)] {
            assert_eq!(set.contains(value, 15), expected, "{value}");
        }
        assert!(SequenceSet::parse("*").unwrap().contains(5, 5));
        assert!(!SequenceSet::parse("*").unwrap().contains(4, 5));
        assert!(SequenceSet::parse("5:2").unwrap().contains(3, 10));
        // RFC 3501: "20:*" on a 15-message mailbox still selects the last message.
        assert!(SequenceSet::parse("20:*").unwrap().contains(15, 15));
        for bad in ["", "0", "a", "1:", "1,,2", "-1", "1:2:3"] {
            assert!(SequenceSet::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn string_encoding() {
        let enc = |d: &[u8]| {
            let mut out = Vec::new();
            string(&mut out, d);
            String::from_utf8_lossy(&out).into_owned()
        };
        assert_eq!(enc(b"hello"), "\"hello\"");
        assert_eq!(enc(b""), "\"\"");
        assert_eq!(enc(b"say \"hi\""), "{8}\r\nsay \"hi\"");
        // Line breaks can never appear inside a quoted string, so responses cannot be forged.
        assert_eq!(enc(b"a\r\n* OK injected"), "{16}\r\na\r\n* OK injected");
        assert_eq!(enc("zażółć".as_bytes()), "{10}\r\nzażółć");
    }

    #[test]
    fn modified_utf7_round_trip() {
        for (plain, encoded) in [
            ("INBOX", "INBOX"),
            ("Entwürfe", "Entw&APw-rfe"),
            ("R&D", "R&-D"),
            ("日本語", "&ZeVnLIqe-"),
            ("Work/Zażółć gęślą", "Work/Za&AXwA8wFCAQc- g&ARkBWw-l&AQU-"),
            ("😀 fun", "&2D3eAA- fun"),
        ] {
            assert_eq!(utf7_encode(plain), encoded, "{plain}");
            assert_eq!(utf7_decode(encoded), plain, "{encoded}");
        }
        // Raw UTF-8 and malformed sequences pass through untouched.
        assert_eq!(utf7_decode("Entwürfe"), "Entwürfe");
        assert_eq!(utf7_decode("broken &xyz"), "broken &xyz");
        assert_eq!(utf7_decode("bad &!!!-"), "bad &!!!-");
    }

    #[test]
    fn uid_sets() {
        assert_eq!(uid_set(&[]), "");
        assert_eq!(uid_set(&[5]), "5");
        assert_eq!(uid_set(&[1, 2, 3, 7, 9, 10]), "1:3,7,9:10");
    }

    #[test]
    fn list_patterns() {
        assert!(list_match("*", "Work/Projects"));
        assert!(list_match("%", "Work"));
        assert!(!list_match("%", "Work/Projects"));
        assert!(list_match("Work/%", "Work/Projects"));
        assert!(!list_match("Work/%", "Work/Projects/Old"));
        assert!(list_match("INBOX", "INBOX"));
        assert!(!list_match("INBOX", "INBOX2"));
        assert!(list_match("*jects", "Work/Projects"));
        assert!(!list_match(&"*a".repeat(50), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"), "pathological patterns are refused");
    }
}
