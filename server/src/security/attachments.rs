//! Attachment policy: messages carrying programs (`.exe`, `.js`, `.scr`, ...) are refused, the
//! way the large mail providers do it. The check works on file names, which is what decides
//! how the recipient's computer opens a file; it looks into attached messages and into the
//! file list of ZIP archives, which costs nothing to read. Other archive formats and
//! password-protected contents are left to the virus scanner.

use std::io::Cursor;

use mail_parser::{Message, MessageParser, MimeHeaders, PartType};

/// File types that run code when opened. Mirrors the "dangerous" list of the web client
/// (web/src/mail/risk.ts), limited to the types no one needs to mail around: developer formats
/// such as `.sh` or `.deb` are flagged in the client but not refused.
const BLOCKED: &[&str] = &[
    "ade", "adp", "apk", "app", "application", "appx", "appxbundle", "bat", "chm", "cmd", "com", "cpl", "diagcab", "dll", "exe", "gadget", "hta", "inf", "ins",
    "isp", "jar", "jnlp", "js", "jse", "lib", "lnk", "mde", "msc", "msi", "msix", "msixbundle", "msp", "mst", "nsh", "pif", "ps1", "psm1", "reg", "scf", "scr",
    "sct", "shb", "sys", "vb", "vbe", "vbs", "vxd", "ws", "wsc", "wsf", "wsh", "xll",
];

/// How deep attached messages are followed (each level can hold more attachments).
const MAX_DEPTH: usize = 8;
/// ZIP entries looked at per archive; an archive with more is judged by the first ones.
const MAX_ZIP_ENTRIES: usize = 10_000;

/// Characters that change how a name is displayed: "invoice\u{202e}fdp.exe" reads as
/// "invoiceexe.pdf".
fn has_display_controls(name: &str) -> bool {
    name.chars().any(|c| matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}'))
}

/// Whether a file of this name would run code when opened.
pub fn is_blocked_name(name: &str) -> bool {
    if has_display_controls(name) {
        return true;
    }
    // Windows ignores trailing dots and spaces: "setup.exe. " is "setup.exe".
    let trimmed = name.trim().trim_end_matches(['.', ' ']).to_ascii_lowercase();
    // Only the last path component counts ("folder/setup.exe" inside an archive).
    let file = trimmed.rsplit(['/', '\\']).next().unwrap_or_default();
    match file.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() || file.starts_with('.') => BLOCKED.contains(&extension),
        _ => false,
    }
}

fn is_zip(name: Option<&str>, content_type: Option<(&str, Option<&str>)>, data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04")
        || name.is_some_and(|n| n.to_ascii_lowercase().ends_with(".zip"))
        || content_type.is_some_and(|(kind, sub)| kind.eq_ignore_ascii_case("application") && sub.is_some_and(|s| s.eq_ignore_ascii_case("zip") || s.eq_ignore_ascii_case("x-zip-compressed")))
}

/// Names inside a ZIP archive that would be refused as attachments.
fn blocked_in_zip(data: &[u8]) -> Option<String> {
    let archive = zip::ZipArchive::new(Cursor::new(data)).ok()?;
    archive.file_names().take(MAX_ZIP_ENTRIES).filter_map(Result::ok).find(|name| is_blocked_name(name)).map(|name| name.into_owned())
}

fn find_blocked(message: &Message<'_>, depth: usize) -> Option<String> {
    for part in &message.parts {
        let name = part.attachment_name();
        if let Some(name) = name
            && is_blocked_name(name)
        {
            return Some(name.to_owned());
        }
        match &part.body {
            PartType::Message(inner) if depth < MAX_DEPTH => {
                if let Some(found) = find_blocked(inner, depth + 1) {
                    return Some(found);
                }
            }
            PartType::Binary(_) | PartType::InlineBinary(_) => {
                let content_type = part.content_type().map(|ct| (ct.ctype(), ct.subtype()));
                let data = part.contents();
                if is_zip(name, content_type, data)
                    && let Some(inner) = blocked_in_zip(data)
                {
                    return Some(format!("{} in {}", inner, name.unwrap_or("an archive")));
                }
            }
            _ => {}
        }
    }
    None
}

/// The first attachment (or archive member) of a raw message that runs code when opened.
pub fn blocked_attachment(raw: &[u8]) -> Option<String> {
    let message = MessageParser::default().parse(raw)?;
    find_blocked(&message, 0).map(|name| crate::util::sanitize_line(&name).chars().take(120).collect())
}

/// The SMTP reply refusing a message that carries a program.
pub fn refusal(name: &str) -> String {
    format!("552 5.7.0 Message refused: it contains an executable attachment ({name}), which this server does not accept for security reasons")
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn message_with(name: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(body);
        format!(
            "From: a@example.org\r\nTo: b@example.org\r\nSubject: x\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b1\r\nContent-Type: {content_type}\r\nContent-Disposition: attachment; filename=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n--b1--\r\n"
        )
        .into_bytes()
    }

    fn zip_of(names: &[&str]) -> Vec<u8> {
        let mut out = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for name in names {
            out.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            out.write_all(b"data").unwrap();
        }
        out.finish().unwrap().into_inner()
    }

    #[test]
    fn programs_and_disguised_programs_are_recognised() {
        for name in ["setup.exe", "Invoice.PDF.EXE", "report.js", "shortcut.lnk", "setup.exe. ", "folder/run.bat", "invoice\u{202e}fdp.txt", ".exe"] {
            assert!(is_blocked_name(name), "{name:?}");
        }
        for name in ["report.pdf", "photo.jpg", "budget.xlsx", "README", "exe", "notes.exe.txt", "script.sh", "archive.zip", ""] {
            assert!(!is_blocked_name(name), "{name:?}");
        }
    }

    #[test]
    fn attachments_attached_messages_and_zip_members_are_checked() {
        assert_eq!(blocked_attachment(&message_with("setup.exe", "application/octet-stream", b"MZ")).as_deref(), Some("setup.exe"));
        assert_eq!(blocked_attachment(&message_with("report.pdf", "application/pdf", b"%PDF")), None);

        let zipped = message_with("invoice.zip", "application/zip", &zip_of(&["readme.txt", "docs/invoice.pdf.scr"]));
        assert_eq!(blocked_attachment(&zipped).as_deref(), Some("docs/invoice.pdf.scr in invoice.zip"));
        // Recognised by its contents too, whatever the name says.
        let renamed = message_with("photos.dat", "application/octet-stream", &zip_of(&["run.vbs"]));
        assert_eq!(blocked_attachment(&renamed).as_deref(), Some("run.vbs in photos.dat"));
        assert_eq!(blocked_attachment(&message_with("photos.zip", "application/zip", &zip_of(&["a.jpg", "b.png"]))), None);
        assert_eq!(blocked_attachment(&message_with("broken.zip", "application/zip", b"PK\x03\x04garbage")), None);

        let inner = String::from_utf8(message_with("tool.exe", "application/octet-stream", b"MZ")).unwrap();
        let forwarded = format!(
            "From: c@example.org\r\nTo: d@example.org\r\nSubject: Fwd\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"outer\"\r\n\r\n--outer\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--outer\r\nContent-Type: message/rfc822\r\n\r\n{inner}\r\n--outer--\r\n"
        );
        assert_eq!(blocked_attachment(forwarded.as_bytes()).as_deref(), Some("tool.exe"));
        assert_eq!(blocked_attachment(b"From: a@example.org\r\nSubject: plain\r\n\r\nno attachments\r\n"), None);
    }

    #[test]
    fn the_name_in_the_reply_cannot_break_the_line() {
        let raw = message_with("a\r\nb.exe", "application/octet-stream", b"MZ");
        if let Some(name) = blocked_attachment(&raw) {
            assert!(!name.contains('\r') && !name.contains('\n'));
            assert!(!refusal(&name).contains('\n'));
        }
    }
}
