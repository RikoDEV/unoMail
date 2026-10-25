//! Where server plug-ins meet the mail server: the mail hooks, their own API routes and
//! scheduled jobs. Each turns server events into JSON for `wasm::invoke` and checks the
//! answer before anything acts on it.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

use serde_json::{Value, json};

use super::{Installed, wasm};
use crate::{app::App, milter::Verdict};

const MAX_HEADER_CHANGES: usize = 20;
const MAX_BODY_FOR_PLUGINS: usize = 1024 * 1024;

/// Headers plug-ins may not add or change: who a message is from and to, and the records of
/// how it travelled and was authenticated.
const PROTECTED_HEADERS: &[&str] = &[
    "from", "sender", "reply-to", "to", "cc", "bcc", "date", "message-id", "return-path", "received", "dkim-signature", "authentication-results", "arc-seal",
    "arc-message-signature", "arc-authentication-results", "content-type", "content-transfer-encoding", "mime-version",
];

/// Installed, enabled plug-ins with a server module that hooks `hook`, in a stable order.
async fn hooked(app: &App, hook: &str) -> Vec<Installed> {
    let Ok(packages) = super::list(&app.db).await else { return Vec::new() };
    packages
        .into_iter()
        .filter(|p| p.enabled && p.kind == "plugin" && !wasm::is_suspended(&p.id))
        .filter(|p| p.manifest()["server"]["hooks"].as_array().is_some_and(|hooks| hooks.iter().any(|h| h == hook)))
        .collect()
}

/// The administrator's settings as the server module receives them, secrets included.
fn admin_settings(app: &App, package: &Installed) -> Value {
    let stored: Value = serde_json::from_str(&package.admin_settings).unwrap_or(json!({}));
    super::open_settings(&package.manifest()["settings"], "admin", &stored, true, |s| app.secrets.open(s))
}

fn header_section(raw: &[u8]) -> (&[u8], &[u8]) {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 2).or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|p| p + 1)).unwrap_or(raw.len());
    raw.split_at(end)
}

/// The message's headers as `[name, value]` pairs, unfolded.
fn headers(raw: &[u8]) -> Vec<(String, String)> {
    let (head, _) = header_section(raw);
    let text = String::from_utf8_lossy(head);
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.split('\n').map(|l| l.trim_end_matches('\r')) {
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = out.last_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
        } else if let Some((name, value)) = line.split_once(':') {
            out.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    out
}

fn valid_header(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name.len() <= 76
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !PROTECTED_HEADERS.contains(&name.to_ascii_lowercase().as_str())
        && value.len() <= 998
        && !value.chars().any(|c| c == '\r' || c == '\n' || c == '\0')
}

fn header_pairs(value: &Value) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for pair in value.as_array().into_iter().flatten() {
        let (Some(name), Some(text)) = (pair[0].as_str(), pair[1].as_str()) else { return Err("headers must be [name, value] pairs".into()) };
        if !valid_header(name, text) {
            return Err(format!("the header {} cannot be set", crate::util::sanitize_line(name)));
        }
        out.push((name.to_owned(), text.to_owned()));
    }
    if out.len() > MAX_HEADER_CHANGES {
        return Err("too many header changes".into());
    }
    Ok(out)
}

/// Adds headers at the top and replaces (all occurrences of) the ones in `set`.
pub fn edit_headers(raw: &[u8], add: &[(String, String)], set: &[(String, String)]) -> Vec<u8> {
    let (head, body) = header_section(raw);
    let crlf = head.windows(2).any(|w| w == b"\r\n");
    let newline = if crlf { "\r\n" } else { "\n" };
    let replaced: Vec<String> = set.iter().map(|(name, _)| name.to_ascii_lowercase()).collect();
    let mut out = String::new();
    for (name, value) in add.iter().chain(set) {
        out.push_str(&format!("{name}: {value}{newline}"));
    }
    let text = String::from_utf8_lossy(head);
    let mut skipping = false;
    for line in text.split_inclusive('\n') {
        let continuation = line.starts_with([' ', '\t']);
        if !continuation {
            skipping = line.split_once(':').is_some_and(|(name, _)| replaced.contains(&name.trim().to_ascii_lowercase()));
        }
        if !skipping {
            out.push_str(line);
        }
    }
    let mut message = out.into_bytes();
    message.extend_from_slice(body);
    message
}

/// One plug-in's answer to a mail hook.
#[derive(Debug, PartialEq)]
enum Answer {
    Accept { add: Vec<(String, String)>, set: Vec<(String, String)>, quarantine: Option<String> },
    Reject(String),
    TempFail(String),
    Discard,
}

fn reply(value: &Value, class: char, fallback: &str) -> String {
    match value.as_str() {
        Some(text) if text.starts_with(class) && text.len() <= 300 && text.bytes().take(3).all(|b| b.is_ascii_digit()) && !text.contains(['\r', '\n']) => text.to_owned(),
        _ => fallback.to_owned(),
    }
}

fn parse_answer(answer: &Value, outgoing: bool) -> Result<Answer, String> {
    let add = header_pairs(&answer["addHeaders"])?;
    let set = header_pairs(&answer["setHeaders"])?;
    match answer["action"].as_str().unwrap_or("accept") {
        "accept" => Ok(Answer::Accept { add, set, quarantine: None }),
        "quarantine" if !outgoing => Ok(Answer::Accept { add, set, quarantine: Some(crate::util::sanitize_line(answer["reason"].as_str().unwrap_or("plug-in"))) }),
        "reject" => Ok(Answer::Reject(reply(&answer["reply"], '5', "550 5.7.1 Message rejected"))),
        "tempfail" => Ok(Answer::TempFail(reply(&answer["reply"], '4', "451 4.7.1 Please try again later"))),
        "discard" if !outgoing => Ok(Answer::Discard),
        other => Err(format!("unknown action: {}", crate::util::sanitize_line(other))),
    }
}

/// Runs the mail hook (`mail:incoming` or `mail:outgoing`) of every plug-in that has it, in
/// turn, each seeing the message as the previous one left it.
pub async fn mail(app: &App, outgoing: bool, sender: &str, recipients: &[String], ip: IpAddr, raw: &[u8]) -> Verdict {
    let hook = if outgoing { "mail:outgoing" } else { "mail:incoming" };
    let packages = hooked(app, hook).await;
    let mut message = raw.to_vec();
    let mut quarantine = None;
    for package in packages {
        let manifest = package.manifest();
        let with_body = manifest["permissions"].as_array().is_some_and(|p| p.iter().any(|p| p == "server:mail-body"));
        let mut event = json!({
            "event": hook,
            "envelope": { "sender": sender, "recipients": recipients, "ip": ip.to_string() },
            "headers": headers(&message).into_iter().map(|(n, v)| json!([n, v])).collect::<Vec<_>>(),
        });
        if with_body {
            let (_, body) = header_section(&message);
            event["body"] = json!(String::from_utf8_lossy(&body[..body.len().min(MAX_BODY_FOR_PLUGINS)]));
        }
        let call = wasm::Call { admin_settings: admin_settings(app, &package), user_settings: json!({}), user: None, purpose: wasm::Purpose::Mail, event, package };
        let fail_closed = call.package.fail_closed;
        let id = call.package.id.clone();
        let answer = wasm::invoke(app, call).await.and_then(|answer| parse_answer(&answer, outgoing));
        match answer {
            Ok(Answer::Accept { add, set, quarantine: q }) => {
                if !add.is_empty() || !set.is_empty() {
                    message = edit_headers(&message, &add, &set);
                }
                quarantine = quarantine.or(q);
            }
            Ok(Answer::Reject(reply)) => {
                tracing::info!(package = %id, %reply, "message rejected by a plug-in");
                return Verdict::Reject(reply);
            }
            Ok(Answer::TempFail(reply)) => return Verdict::TempFail(reply),
            Ok(Answer::Discard) => return Verdict::Discard,
            // A plug-in that fails is passed over, unless the administrator chose otherwise.
            Err(error) if fail_closed => {
                tracing::warn!(package = %id, %error, "plug-in failed; message deferred");
                return Verdict::TempFail("451 4.3.0 Temporary processing failure".into());
            }
            Err(error) => tracing::warn!(package = %id, %error, "plug-in failed; message passed on"),
        }
    }
    Verdict::Deliver { message, quarantine }
}

/// A request to a plug-in's own routes (`/api/x/<id>/<path>`), answered by its module.
pub async fn route(app: &App, package: Installed, request: Value, user: i64, user_settings: Value) -> Result<(u16, Value), String> {
    let call = wasm::Call { admin_settings: admin_settings(app, &package), user_settings, user: Some(user), purpose: wasm::Purpose::Route, event: request, package };
    let answer = wasm::invoke(app, call).await?;
    let status = answer["status"].as_u64().filter(|s| (200..=599).contains(s)).unwrap_or(200) as u16;
    Ok((status, answer.get("json").cloned().unwrap_or(Value::Null)))
}

static LAST_RUN: LazyLock<Mutex<HashMap<(String, String), Instant>>> = LazyLock::new(Mutex::default);

/// Runs the scheduled jobs of server plug-ins as they come due.
pub async fn run_schedules(app: crate::app::AppState) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let Ok(packages) = super::list(&app.db).await else { continue };
        for package in packages.into_iter().filter(|p| p.enabled && p.kind == "plugin") {
            let manifest = package.manifest();
            for job in manifest["server"]["schedule"].as_array().into_iter().flatten() {
                let (Some(job_id), Some(every)) = (job["id"].as_str(), job["everyMinutes"].as_u64()) else { continue };
                let key = (package.id.clone(), job_id.to_owned());
                let due = {
                    let mut last = LAST_RUN.lock().unwrap_or_else(|e| e.into_inner());
                    let started = *last.entry(key.clone()).or_insert_with(Instant::now);
                    let due = started.elapsed() >= Duration::from_secs(every * 60);
                    if due {
                        last.insert(key, Instant::now());
                    }
                    due
                };
                if due {
                    let call = wasm::Call { admin_settings: admin_settings(&app, &package), user_settings: json!({}), user: None, purpose: wasm::Purpose::Schedule, event: json!({ "event": "schedule", "id": job_id }), package: package.clone() };
                    if let Err(error) = wasm::invoke(&app, call).await {
                        tracing::warn!(package = %package.id, job = job_id, %error, "scheduled plug-in job failed");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_are_added_and_replaced_but_never_the_protected_ones() {
        let raw = b"From: a@example.org\r\nSubject: Hello\r\n  world\r\nX-Old: 1\r\n\r\nBody\r\n";
        let edited = edit_headers(raw, &[("X-Tag".into(), "external".into())], &[("Subject".into(), "[EXTERNAL] Hello world".into())]);
        let text = String::from_utf8(edited).unwrap();
        assert!(text.starts_with("X-Tag: external\r\nSubject: [EXTERNAL] Hello world\r\nFrom: a@example.org\r\nX-Old: 1\r\n\r\nBody"), "{text}");
        assert!(header_pairs(&json!([["From", "evil@example.org"]])).is_err());
        assert!(header_pairs(&json!([["X-Ok", "a\r\nBcc: x@example.org"]])).is_err());
        assert!(header_pairs(&json!([["Bad Name", "x"]])).is_err());
    }

    #[test]
    fn answers_map_onto_verdicts() {
        assert_eq!(parse_answer(&json!({ "action": "reject", "reply": "554 5.7.1 No thanks" }), false).unwrap(), Answer::Reject("554 5.7.1 No thanks".into()));
        // A reply of the wrong class, or with line breaks, gets the default.
        assert_eq!(parse_answer(&json!({ "action": "reject", "reply": "250 ok" }), false).unwrap(), Answer::Reject("550 5.7.1 Message rejected".into()));
        assert_eq!(parse_answer(&json!({ "action": "tempfail", "reply": "451 4.7.1 later\r\n250 ok" }), false).unwrap(), Answer::TempFail("451 4.7.1 Please try again later".into()));
        assert!(parse_answer(&json!({ "action": "discard" }), true).is_err(), "sent mail is never dropped silently");
        assert!(parse_answer(&json!({ "action": "explode" }), false).is_err());
        assert_eq!(parse_answer(&json!({}), false).unwrap(), Answer::Accept { add: vec![], set: vec![], quarantine: None });
    }
}
