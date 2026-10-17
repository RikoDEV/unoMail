//! FETCH data items: envelope, body structure and body sections.

use mail_parser::{Address, HeaderValue, Message as Parsed, MessagePart, MimeHeaders, PartType};

use super::parse::{nstring, string};
use crate::security::authn::find_header_end;

fn unfold(value: &str) -> String {
    value.replace(['\r', '\n'], "").trim().to_owned()
}

fn address_list(out: &mut Vec<u8>, list: Option<&Address<'_>>) {
    let entries: Vec<_> = list.map(|l| l.iter().filter(|a| a.address().is_some()).collect()).unwrap_or_default();
    if entries.is_empty() {
        out.extend_from_slice(b"NIL");
        return;
    }
    out.push(b'(');
    for entry in entries {
        let address = entry.address().unwrap_or_default();
        let (mailbox, host) = address.rsplit_once('@').unwrap_or((address, ""));
        out.push(b'(');
        nstring(out, entry.name().map(str::as_bytes));
        out.extend_from_slice(b" NIL ");
        string(out, mailbox.as_bytes());
        out.push(b' ');
        string(out, host.as_bytes());
        out.push(b')');
    }
    out.push(b')');
}

fn first_text(value: &HeaderValue<'_>) -> Option<String> {
    value.as_text_list().and_then(|l| l.first().map(|s| format!("<{s}>"))).or_else(|| value.as_text().map(|s| format!("<{s}>")))
}

/// ENVELOPE: (date subject from sender reply-to to cc bcc in-reply-to message-id)
pub fn envelope(out: &mut Vec<u8>, msg: &Parsed<'_>) {
    out.push(b'(');
    nstring(out, msg.header_raw("Date").map(unfold).as_deref().map(str::as_bytes));
    out.push(b' ');
    nstring(out, msg.header_raw("Subject").map(unfold).as_deref().map(str::as_bytes));
    out.push(b' ');
    address_list(out, msg.from());
    out.push(b' ');
    address_list(out, msg.sender().or(msg.from()));
    out.push(b' ');
    address_list(out, msg.reply_to().or(msg.from()));
    for list in [msg.to(), msg.cc(), msg.bcc()] {
        out.push(b' ');
        address_list(out, list);
    }
    out.push(b' ');
    nstring(out, first_text(msg.in_reply_to()).as_deref().map(str::as_bytes));
    out.push(b' ');
    nstring(out, msg.message_id().map(|id| format!("<{id}>")).as_deref().map(str::as_bytes));
    out.push(b')');
}

fn part_bytes<'a>(raw: &'a [u8], part: &MessagePart<'_>) -> &'a [u8] {
    raw.get(part.offset_body as usize..part.offset_end as usize).unwrap_or(&[])
}

fn params(out: &mut Vec<u8>, attributes: Option<&[mail_parser::Attribute<'_>]>) {
    match attributes.filter(|a| !a.is_empty()) {
        Some(attributes) => {
            out.push(b'(');
            for (i, attribute) in attributes.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                string(out, attribute.name.as_bytes());
                out.push(b' ');
                string(out, attribute.value.as_bytes());
            }
            out.push(b')');
        }
        None => out.extend_from_slice(b"NIL"),
    }
}

/// BODYSTRUCTURE of `part`, recursing into multiparts. `extended` adds the extension fields.
pub fn body_structure(out: &mut Vec<u8>, msg: &Parsed<'_>, raw: &[u8], part: &MessagePart<'_>, extended: bool, depth: usize) {
    let content_type = part.content_type();
    if let PartType::Multipart(children) = &part.body
        && depth < 20
    {
        out.push(b'(');
        for child in children {
            if let Some(child) = msg.parts.get(*child as usize) {
                body_structure(out, msg, raw, child, extended, depth + 1);
            }
        }
        out.push(b' ');
        string(out, content_type.and_then(|c| c.subtype()).unwrap_or("mixed").to_ascii_uppercase().as_bytes());
        if extended {
            out.push(b' ');
            params(out, content_type.and_then(|c| c.attributes()));
            out.extend_from_slice(b" NIL NIL");
        }
        out.push(b')');
        return;
    }
    let (ctype, subtype) = match content_type {
        Some(c) => (c.ctype().to_ascii_uppercase(), c.subtype().unwrap_or("PLAIN").to_ascii_uppercase()),
        None => ("TEXT".to_owned(), "PLAIN".to_owned()),
    };
    let body = part_bytes(raw, part);
    out.push(b'(');
    string(out, ctype.as_bytes());
    out.push(b' ');
    string(out, subtype.as_bytes());
    out.push(b' ');
    params(out, content_type.and_then(|c| c.attributes()));
    out.push(b' ');
    nstring(out, part.content_id().map(|id| format!("<{id}>")).as_deref().map(str::as_bytes));
    out.push(b' ');
    nstring(out, part.content_description().map(str::as_bytes));
    out.push(b' ');
    string(out, part.content_transfer_encoding().unwrap_or("7BIT").to_ascii_uppercase().as_bytes());
    out.extend_from_slice(format!(" {}", body.len()).as_bytes());
    if ctype == "TEXT" {
        out.extend_from_slice(format!(" {}", body.iter().filter(|b| **b == b'\n').count()).as_bytes());
    }
    if extended {
        out.extend_from_slice(b" NIL ");
        match part.content_disposition() {
            Some(disposition) => {
                out.push(b'(');
                string(out, disposition.ctype().to_ascii_uppercase().as_bytes());
                out.push(b' ');
                params(out, disposition.attributes());
                out.push(b')');
            }
            None => out.extend_from_slice(b"NIL"),
        }
        out.extend_from_slice(b" NIL");
    }
    out.push(b')');
}

/// A parsed `BODY[...]` section specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub path: Vec<u32>,
    pub kind: SectionKind,
    /// `<start.length>` partial range.
    pub partial: Option<(usize, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionKind {
    /// The whole message or part.
    All,
    Header,
    Text,
    Mime,
    HeaderFields { names: Vec<String>, not: bool },
}

impl Section {
    /// Parses the text between the brackets plus an optional `<a.b>` suffix.
    pub fn parse(spec: &str, partial: &str) -> Option<Section> {
        let mut path = Vec::new();
        let mut rest = spec;
        // Leading part numbers: "1.2.HEADER" -> [1, 2] + "HEADER".
        loop {
            let (head, tail) = rest.split_once('.').unwrap_or((rest, ""));
            match head.parse::<u32>() {
                Ok(n) if n > 0 && path.len() < 20 => {
                    path.push(n);
                    rest = tail;
                    if rest.is_empty() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let upper = rest.to_ascii_uppercase();
        let kind = if upper.is_empty() {
            SectionKind::All
        } else if upper == "HEADER" {
            SectionKind::Header
        } else if upper == "TEXT" {
            SectionKind::Text
        } else if upper == "MIME" && !path.is_empty() {
            SectionKind::Mime
        } else {
            let fields = upper.strip_prefix("HEADER.FIELDS")?;
            let (not, list) = match fields.strip_prefix(".NOT") {
                Some(list) => (true, list),
                None => (false, fields),
            };
            let list = list.trim().strip_prefix('(')?.strip_suffix(')')?;
            let names: Vec<String> = list.split_whitespace().map(|n| n.trim_matches('"').to_owned()).collect();
            if names.is_empty() || names.len() > 50 {
                return None;
            }
            SectionKind::HeaderFields { names, not }
        };
        let partial = if partial.is_empty() {
            None
        } else {
            let inner = partial.strip_prefix('<')?.strip_suffix('>')?;
            let (start, len) = inner.split_once('.')?;
            Some((start.parse().ok()?, len.parse().ok()?))
        };
        Some(Section { path, kind, partial })
    }

    /// The canonical name used in the response, e.g. `BODY[1.HEADER]<0>`.
    pub fn response_name(&self) -> String {
        let mut spec: Vec<String> = self.path.iter().map(u32::to_string).collect();
        match &self.kind {
            SectionKind::All => {}
            SectionKind::Header => spec.push("HEADER".into()),
            SectionKind::Text => spec.push("TEXT".into()),
            SectionKind::Mime => spec.push("MIME".into()),
            SectionKind::HeaderFields { names, not } => {
                spec.push(format!("HEADER.FIELDS{} ({})", if *not { ".NOT" } else { "" }, names.join(" ")));
            }
        }
        let partial = self.partial.map(|(start, _)| format!("<{start}>")).unwrap_or_default();
        format!("BODY[{}]{partial}", spec.join("."))
    }
}

/// Keeps (or drops, with `not`) the named header fields; always ends with the blank line.
fn filter_headers(headers: &[u8], names: &[String], not: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut keep = false;
    for line in headers.split_inclusive(|b| *b == b'\n') {
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        if !matches!(line.first(), Some(b' ' | b'\t')) {
            let name = line.split(|b| *b == b':').next().unwrap_or(&[]);
            let listed = names.iter().any(|n| n.as_bytes().eq_ignore_ascii_case(name));
            keep = listed != not;
        }
        if keep {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn resolve_part<'a, 'x>(msg: &'a Parsed<'x>, path: &[u32]) -> Option<&'a MessagePart<'x>> {
    let mut part = msg.parts.first()?;
    for number in path {
        part = match &part.body {
            PartType::Multipart(children) => msg.parts.get(*children.get(*number as usize - 1)? as usize)?,
            // A non-multipart message has exactly one part: itself.
            _ if *number == 1 => part,
            _ => return None,
        };
    }
    Some(part)
}

/// Extracts the bytes selected by `section` from the raw message.
pub fn section_bytes(raw: &[u8], msg: &Parsed<'_>, section: &Section) -> Option<Vec<u8>> {
    // The header block includes the blank line that terminates it.
    let split = find_header_end(raw);
    let header_end = if raw[split..].starts_with(b"\r\n") {
        split + 2
    } else if raw[split..].starts_with(b"\n") {
        split + 1
    } else {
        split
    };
    let data: Vec<u8> = if section.path.is_empty() {
        match &section.kind {
            SectionKind::All => raw.to_vec(),
            SectionKind::Header => raw[..header_end].to_vec(),
            SectionKind::Text => raw[header_end..].to_vec(),
            SectionKind::HeaderFields { names, not } => filter_headers(&raw[..header_end], names, *not),
            SectionKind::Mime => return None,
        }
    } else {
        let part = resolve_part(msg, &section.path)?;
        let (header_start, body_start, end) = (part.offset_header as usize, part.offset_body as usize, part.offset_end as usize);
        match &section.kind {
            SectionKind::All | SectionKind::Text => raw.get(body_start..end)?.to_vec(),
            SectionKind::Mime | SectionKind::Header => raw.get(header_start..body_start)?.to_vec(),
            SectionKind::HeaderFields { names, not } => filter_headers(raw.get(header_start..body_start)?, names, *not),
        }
    };
    Some(match section.partial {
        Some((start, len)) => data.get(start.min(data.len())..(start.saturating_add(len)).min(data.len())).unwrap_or(&[]).to_vec(),
        None => data,
    })
}

#[cfg(test)]
mod tests {
    use mail_parser::MessageParser;

    use super::*;

    const SIMPLE: &[u8] = b"From: Alice <alice@example.org>\r\nTo: bob@example.org\r\nSubject: Hi there\r\nDate: Mon, 05 Oct 2026 10:00:00 +0000\r\nMessage-ID: <id1@example.org>\r\n\r\nHello\r\nWorld\r\n";
    const MULTI: &[u8] = b"From: a@example.org\r\nSubject: Files\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBody text\r\n--B\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\nContent-Disposition: attachment; filename=\"a.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n--B--\r\n";

    fn text(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn envelope_of_simple_message() {
        let msg = MessageParser::default().parse(SIMPLE).unwrap();
        let mut out = Vec::new();
        envelope(&mut out, &msg);
        assert_eq!(
            text(out),
            r#"("Mon, 05 Oct 2026 10:00:00 +0000" "Hi there" (("Alice" NIL "alice" "example.org")) (("Alice" NIL "alice" "example.org")) (("Alice" NIL "alice" "example.org")) ((NIL NIL "bob" "example.org")) NIL NIL NIL "<id1@example.org>")"#
        );
    }

    #[test]
    fn body_structures() {
        let msg = MessageParser::default().parse(SIMPLE).unwrap();
        let mut out = Vec::new();
        body_structure(&mut out, &msg, SIMPLE, &msg.parts[0], false, 0);
        assert_eq!(text(out), r#"("TEXT" "PLAIN" NIL NIL NIL "7BIT" 14 2)"#);

        let msg = MessageParser::default().parse(MULTI).unwrap();
        let mut out = Vec::new();
        body_structure(&mut out, &msg, MULTI, &msg.parts[0], true, 0);
        let structure = text(out);
        assert!(structure.starts_with(r#"(("TEXT" "PLAIN" ("charset" "utf-8") NIL NIL "7BIT" "#), "{structure}");
        assert!(structure.contains(r#"("APPLICATION" "PDF" ("name" "a.pdf") NIL NIL "BASE64" "#), "{structure}");
        assert!(structure.contains(r#"("ATTACHMENT" ("filename" "a.pdf"))"#), "{structure}");
        assert!(structure.ends_with(r#" "MIXED" ("boundary" "B") NIL NIL)"#), "{structure}");
    }

    #[test]
    fn section_parsing() {
        assert_eq!(Section::parse("", ""), Some(Section { path: vec![], kind: SectionKind::All, partial: None }));
        assert_eq!(Section::parse("1.2.MIME", "<0.10>"), Some(Section { path: vec![1, 2], kind: SectionKind::Mime, partial: Some((0, 10)) }));
        let fields = Section::parse("HEADER.FIELDS (From \"To\")", "").unwrap();
        assert_eq!(fields.kind, SectionKind::HeaderFields { names: vec!["FROM".into(), "TO".into()], not: false });
        assert_eq!(fields.response_name(), "BODY[HEADER.FIELDS (FROM TO)]");
        assert_eq!(Section::parse("2.header", "<5.1>").unwrap().response_name(), "BODY[2.HEADER]<5>");
        for (spec, partial) in [("BOGUS", ""), ("MIME", ""), ("HEADER.FIELDS ()", ""), ("HEADER.FIELDS From", ""), ("", "<x.y>"), ("", "0.5")] {
            assert!(Section::parse(spec, partial).is_none(), "{spec:?} {partial:?}");
        }
    }

    #[test]
    fn section_extraction() {
        let msg = MessageParser::default().parse(SIMPLE).unwrap();
        let get = |spec: &str, partial: &str| text(section_bytes(SIMPLE, &msg, &Section::parse(spec, partial).unwrap()).unwrap());
        assert_eq!(get("", "").as_bytes(), SIMPLE);
        assert_eq!(get("TEXT", ""), "Hello\r\nWorld\r\n");
        assert!(get("HEADER", "").ends_with("Message-ID: <id1@example.org>\r\n\r\n"));
        assert_eq!(get("HEADER.FIELDS (subject TO)", ""), "To: bob@example.org\r\nSubject: Hi there\r\n\r\n");
        assert!(!get("HEADER.FIELDS.NOT (subject)", "").contains("Subject"));
        assert_eq!(get("TEXT", "<2.5>"), "llo\r\n");
        assert_eq!(get("TEXT", "<500.5>"), "");
        assert_eq!(get("1", ""), "Hello\r\nWorld\r\n");
        assert!(section_bytes(SIMPLE, &msg, &Section::parse("2", "").unwrap()).is_none());

        let msg = MessageParser::default().parse(MULTI).unwrap();
        let get = |spec: &str| text(section_bytes(MULTI, &msg, &Section::parse(spec, "").unwrap()).unwrap());
        assert_eq!(get("1").trim_end(), "Body text");
        assert_eq!(get("2").trim_end(), "QUJD");
        assert!(get("2.MIME").contains("Content-Disposition: attachment"));
        assert!(section_bytes(MULTI, &msg, &Section::parse("3", "").unwrap()).is_none());
    }
}
