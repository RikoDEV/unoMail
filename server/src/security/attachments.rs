//! Attachment policy: messages carrying programs (`.exe`, `.js`, `.scr`, ...) are refused, the
//! way the large mail providers do it. The check works on file names, which is what decides
//! how the recipient's computer opens a file; it looks into attached messages, into the file
//! list of ZIP archives and into ZIP archives inside those. Other archive formats and
//! password-protected contents are left to the virus scanner.
//!
//! Whatever is too deep or too large to look at is refused rather than let through: an
//! attacker would otherwise only need to hide the program one level further down.

use std::io::{Cursor, Read};

use mail_parser::{Message, MessageParser, MimeHeaders, PartType};

/// File types that run code when opened. Mirrors the "dangerous" list of the web client
/// (web/src/mail/risk.ts), limited to the types no one needs to mail around: developer formats
/// such as `.sh` or `.deb` are flagged in the client but not refused.
const BLOCKED: &[&str] = &[
    "ade", "adp", "apk", "app", "application", "appx", "appxbundle", "bat", "chm", "cmd", "com", "cpl", "diagcab", "dll", "exe", "gadget", "hta", "inf", "ins",
    "isp", "jar", "jnlp", "js", "jse", "lib", "lnk", "mde", "msc", "msi", "msix", "msixbundle", "msp", "mst", "nsh", "pif", "ps1", "psm1", "reg", "scf", "scr",
    "sct", "shb", "sys", "vb", "vbe", "vbs", "vxd", "ws", "wsc", "wsf", "wsh", "xll",
];

/// How deep attached messages and archives inside archives are followed.
const MAX_DEPTH: usize = 8;
/// ZIP entries per archive; an archive with more is refused.
const MAX_ZIP_ENTRIES: usize = 10_000;
/// Bytes unpacked from nested archives per message, against archive bombs.
const MAX_UNPACKED: u64 = 64 * 1024 * 1024;

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

/// Names inside a ZIP archive (and the archives in it) that would be refused as attachments.
fn blocked_in_zip(data: &[u8], depth: usize, budget: &mut u64) -> Option<String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(data)).ok()?;
    if archive.len() > MAX_ZIP_ENTRIES {
        return Some(format!("an archive of more than {MAX_ZIP_ENTRIES} files"));
    }
    if let Some(name) = archive.file_names().filter_map(Result::ok).find(|name| is_blocked_name(name)) {
        return Some(name.into_owned());
    }
    for index in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(index) else { continue };
        let Ok(name) = entry.name().map(|name| name.into_owned()) else { continue };
        if !name.to_ascii_lowercase().ends_with(".zip") {
            continue;
        }
        if depth >= MAX_DEPTH {
            return Some(format!("{name}, archives nested too deeply"));
        }
        if entry.size() > *budget {
            return Some(format!("{name}, too large to unpack"));
        }
        let mut inner = Vec::with_capacity(entry.size() as usize);
        // The declared size can lie; never read past what is left of the budget.
        if (&mut entry).take(*budget + 1).read_to_end(&mut inner).is_err() {
            continue;
        }
        if inner.len() as u64 > *budget {
            return Some(format!("{name}, too large to unpack"));
        }
        *budget -= inner.len() as u64;
        if let Some(found) = blocked_in_zip(&inner, depth + 1, budget) {
            return Some(format!("{found} in {name}"));
        }
    }
    None
}

fn find_blocked(message: &Message<'_>, depth: usize, budget: &mut u64) -> Option<String> {
    for part in &message.parts {
        let name = part.attachment_name();
        if let Some(name) = name
            && is_blocked_name(name)
        {
            return Some(name.to_owned());
        }
        match &part.body {
            PartType::Message(_) if depth >= MAX_DEPTH => return Some("attached messages nested too deeply".into()),
            PartType::Message(inner) => {
                if let Some(found) = find_blocked(inner, depth + 1, budget) {
                    return Some(found);
                }
            }
            PartType::Binary(_) | PartType::InlineBinary(_) => {
                let content_type = part.content_type().map(|ct| (ct.ctype(), ct.subtype()));
                let data = part.contents();
                if is_zip(name, content_type, data)
                    && let Some(inner) = blocked_in_zip(data, depth, budget)
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
    find_blocked(&message, 0, &mut MAX_UNPACKED.clone()).map(|name| crate::util::sanitize_line(&name).chars().take(120).collect())
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

    fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in entries {
            out.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            out.write_all(data).unwrap();
        }
        out.finish().unwrap().into_inner()
    }

    #[test]
    fn programs_cannot_hide_past_the_limits() {
        // In an archive inside an archive.
        let inner = zip_of(&["setup.exe"]);
        let outer = zip_with(&[("readme.txt", b"hi"), ("more.zip", &inner)]);
        assert_eq!(blocked_attachment(&message_with("files.zip", "application/zip", &outer)).as_deref(), Some("setup.exe in more.zip in files.zip"));
        let harmless = zip_with(&[("more.zip", &zip_of(&["a.jpg"]))]);
        assert_eq!(blocked_attachment(&message_with("files.zip", "application/zip", &harmless)), None);

        // Behind more entries than are read.
        let names: Vec<String> = (0..=MAX_ZIP_ENTRIES).map(|i| format!("{i}.txt")).collect();
        let crowded = zip_of(&names.iter().map(String::as_str).collect::<Vec<_>>());
        assert!(blocked_attachment(&message_with("many.zip", "application/zip", &crowded)).is_some());

        // Deeper than archives are followed.
        let mut nested = zip_of(&["a.txt"]);
        for _ in 0..=MAX_DEPTH {
            nested = zip_with(&[("next.zip", &nested)]);
        }
        assert!(blocked_attachment(&message_with("deep.zip", "application/zip", &nested)).unwrap().contains("nested too deeply"));

        // Deeper than attached messages are followed.
        let mut raw = String::from_utf8(message_with("a.txt", "text/plain", b"x")).unwrap();
        for _ in 0..=MAX_DEPTH {
            raw = format!("From: a@example.org\r\nSubject: Fwd\r\nMIME-Version: 1.0\r\nContent-Type: message/rfc822\r\n\r\n{raw}");
        }
        assert!(blocked_attachment(raw.as_bytes()).is_some());
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
