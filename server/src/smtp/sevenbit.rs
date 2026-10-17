//! Conversion of 8-bit message bodies to 7-bit form, for receiving servers that do not offer
//! the 8BITMIME extension (RFC 6152 section 3: such mail must be converted or returned).
//!
//! Every body part carrying 8-bit text is re-encoded as quoted-printable (RFC 2045 6.7) and
//! its `Content-Transfer-Encoding` set accordingly. Header fields cannot be converted this way
//! (they need SMTPUTF8), and neither can an attached message (message/rfc822 must not be
//! encoded): such mail cannot be converted.

use mail_parser::{MessageParser, PartType};

/// The message in 7-bit form, or `None` when it cannot be converted.
pub fn downconvert(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.is_ascii() {
        return Some(raw.to_vec());
    }
    let message = MessageParser::default().parse(raw)?;
    // (header start, body start, body end) of each part to convert, last first, so that
    // splicing one does not move the others.
    let mut leaves: Vec<(usize, usize, usize)> = message
        .parts
        .iter()
        .filter(|part| matches!(part.body, PartType::Text(_) | PartType::Html(_) | PartType::Binary(_) | PartType::InlineBinary(_)))
        .map(|part| (part.offset_header as usize, part.offset_body as usize, part.offset_end as usize))
        .filter(|(header, body, end)| header <= body && body <= end && *end <= raw.len() && !raw[*body..*end].is_ascii())
        .collect();
    leaves.sort_by_key(|leaf| std::cmp::Reverse(leaf.0));
    let mut out = raw.to_vec();
    for (header, body, end) in leaves {
        let fields = &raw[header..body];
        let encoding = header_value(fields, "content-transfer-encoding").unwrap_or_default();
        // An encoded body has no 8-bit bytes of its own; one that has them is broken.
        if !matches!(encoding.as_str(), "" | "7bit" | "8bit" | "binary") {
            return None;
        }
        let mut part = with_encoding(fields, "quoted-printable");
        part.extend_from_slice(&quoted_printable(&raw[body..end]));
        out.splice(header..end, part);
    }
    out.is_ascii().then_some(out)
}

/// The value of the first header field `name` (lower-case) in a header block, lower-cased.
fn header_value(fields: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(fields);
    let mut value: Option<String> = None;
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        match &mut value {
            Some(v) if line.starts_with([' ', '\t']) => v.push_str(line),
            Some(_) => break,
            None => {
                if let Some((field, rest)) = line.split_once(':')
                    && field.trim().eq_ignore_ascii_case(name)
                {
                    value = Some(rest.to_owned());
                }
            }
        }
    }
    value.map(|v| v.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
}

/// A part's header block (ending in its empty line) with `Content-Transfer-Encoding` replaced.
fn with_encoding(fields: &[u8], encoding: &str) -> Vec<u8> {
    let (head, separator): (&[u8], &[u8]) = if let Some(head) = fields.strip_suffix(b"\r\n\r\n") {
        (head, b"\r\n\r\n")
    } else if let Some(head) = fields.strip_suffix(b"\n\n") {
        (head, b"\n\n")
    } else {
        (fields, b"")
    };
    let newline: &[u8] = if separator == b"\n\n" { b"\n" } else { b"\r\n" };
    let mut out = Vec::with_capacity(fields.len() + 48);
    let mut skipping = false;
    for line in head.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let continued = line.first().is_some_and(|b| *b == b' ' || *b == b'\t');
        if !continued {
            skipping = line.len() >= 26 && line[..26].eq_ignore_ascii_case(b"content-transfer-encoding:");
        }
        if skipping || (line.is_empty() && out.is_empty()) {
            continue;
        }
        out.extend_from_slice(line);
        out.extend_from_slice(newline);
    }
    out.extend_from_slice(format!("Content-Transfer-Encoding: {encoding}").as_bytes());
    out.extend_from_slice(if separator.is_empty() { b"\r\n\r\n" } else { separator });
    out
}

/// Quoted-printable encoding of a body (RFC 2045 6.7): line breaks are kept as such, lines
/// stay within 76 characters, and whitespace at the end of a line is encoded.
pub fn quoted_printable(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + body.len() / 4);
    let lines: Vec<&[u8]> = body.split(|b| *b == b'\n').collect();
    for (index, line) in lines.iter().enumerate() {
        let last = index + 1 == lines.len();
        let line = if last { *line } else { line.strip_suffix(b"\r").unwrap_or(line) };
        let mut width = 0;
        for (at, byte) in line.iter().enumerate() {
            let at_end = at + 1 == line.len();
            let literal = matches!(byte, b'!'..=b'<' | b'>'..=b'~') || (matches!(byte, b' ' | b'\t') && !at_end);
            let piece = if literal { vec![*byte] } else { format!("={byte:02X}").into_bytes() };
            // Room for a soft line break ("=") within the 76 characters.
            if width + piece.len() > 75 {
                out.extend_from_slice(b"=\r\n");
                width = 0;
            }
            width += piece.len();
            out.extend_from_slice(&piece);
        }
        if !last {
            out.extend_from_slice(b"\r\n");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_lines_within_limits() {
        let encoded = quoted_printable("Zażółć gęślą jaźń = ok \r\nnext\t\r\n".as_bytes());
        let text = String::from_utf8(encoded).unwrap();
        assert!(text.starts_with("Za=C5=BC=C3=B3=C5=82=C4=87 g"), "{text}");
        assert!(text.contains("=3D ok=20\r\nnext=09\r\n"), "{text}");
        let long = quoted_printable("ą".repeat(100).as_bytes());
        assert!(String::from_utf8(long).unwrap().split("\r\n").all(|line| line.len() <= 76));
    }

    #[test]
    fn converts_each_8bit_part_and_keeps_the_rest() {
        let raw = "From: a@example.org\r\nSubject: hi\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nCześć\r\n--b\r\nContent-Type: text/plain\r\n\r\nplain\r\n--b--\r\n";
        let out = String::from_utf8(downconvert(raw.as_bytes()).unwrap()).unwrap();
        assert!(out.contains("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nCze=C5=9B=C4=87\r\n--b\r\n"), "{out}");
        assert!(!out.contains("8bit"));
        assert!(out.contains("Content-Type: text/plain\r\n\r\nplain\r\n--b--"), "{out}");
        let parsed = MessageParser::default().parse(out.as_bytes()).unwrap();
        assert_eq!(parsed.body_text(0).unwrap(), "Cześć");
    }

    #[test]
    fn converts_a_single_part_message() {
        let raw = "From: a@example.org\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nżółw\r\n";
        let out = String::from_utf8(downconvert(raw.as_bytes()).unwrap()).unwrap();
        assert_eq!(out, "From: a@example.org\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=C5=BC=C3=B3=C5=82w\r\n");
    }

    #[test]
    fn refuses_what_cannot_be_converted() {
        assert_eq!(downconvert("Subject: żółw\r\n\r\nx\r\n".as_bytes()), None, "header fields need SMTPUTF8");
        assert_eq!(downconvert(b"Subject: x\r\n\r\nascii\r\n"), Some(b"Subject: x\r\n\r\nascii\r\n".to_vec()));
    }
}
