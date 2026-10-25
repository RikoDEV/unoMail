//! Delivery status notifications (RFC 3461, RFC 3464): what a sender asked to be told about
//! each recipient (`NOTIFY`, `ORCPT` on RCPT; `RET`, `ENVID` on MAIL), and the reports sent.

use std::collections::HashMap;

use crate::{
    security::authn::find_header_end,
    smtp::delivery::rfc2822_now,
    util::{random_token, sanitize_line},
};

const MAX_REPORT_HEADER_BYTES: usize = 16 * 1024;
/// A full message is returned only up to this size; larger ones get their headers back.
const MAX_RETURNED_BYTES: usize = 1024 * 1024;

/// What the sender asked for one recipient. Every field is optional; nothing asked means the
/// default: failures are reported, with the headers of the message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dsn {
    /// `NEVER`, or a comma-separated subset of `SUCCESS`, `FAILURE`, `DELAY` (upper case).
    pub notify: Option<String>,
    /// `FULL` or `HDRS`.
    pub ret: Option<String>,
    /// Envelope identifier, as xtext.
    pub envid: Option<String>,
    /// Original recipient, `rfc822;address` with the address as xtext.
    pub orcpt: Option<String>,
    /// The sender demanded verified encryption all the way (REQUIRETLS, RFC 8689). Not a DSN
    /// parameter, but it travels with them from the transaction to the queue.
    pub require_tls: bool,
    /// Other transaction parameters that only matter when the message is queued.
    pub queueing: Queueing,
}

/// What MAIL FROM asked of the queue: FUTURERELEASE (RFC 4865), DELIVERBY (RFC 2852) and
/// MT-PRIORITY (RFC 6710).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Queueing {
    /// Not to be sent before this Unix time.
    pub hold_until: Option<i64>,
    /// `BY=n;R`: returned as undeliverable if not delivered by this Unix time.
    pub deliver_by: Option<i64>,
    /// -9 to 9.
    pub priority: i8,
}

impl Dsn {
    fn wants(&self, what: &str) -> bool {
        self.notify.as_deref().is_some_and(|n| n.split(',').any(|v| v == what))
    }

    /// Failures are reported unless the sender said otherwise.
    pub fn wants_failure(&self) -> bool {
        self.notify.is_none() || self.wants("FAILURE")
    }

    pub fn wants_delay(&self) -> bool {
        self.wants("DELAY")
    }

    pub fn wants_success(&self) -> bool {
        self.wants("SUCCESS")
    }

    /// Whether no notification parameters were given (REQUIRETLS does not count).
    pub fn is_empty(&self) -> bool {
        self.notify.is_none() && self.ret.is_none() && self.envid.is_none() && self.orcpt.is_none()
    }
}

/// The DSN parameters of one SMTP transaction, by recipient.
#[derive(Debug, Clone, Default)]
pub struct Request {
    pub ret: Option<String>,
    pub envid: Option<String>,
    /// REQUIRETLS was given on MAIL FROM.
    pub require_tls: bool,
    pub queueing: Queueing,
    /// Lower-cased recipient address → (NOTIFY, ORCPT).
    pub recipients: HashMap<String, (Option<String>, Option<String>)>,
}

impl Request {
    pub fn for_recipient(&self, recipient: &str) -> Dsn {
        let (notify, orcpt) = self.recipients.get(&recipient.to_ascii_lowercase()).cloned().unwrap_or_default();
        Dsn { notify, ret: self.ret.clone(), envid: self.envid.clone(), orcpt, require_tls: self.require_tls, queueing: self.queueing }
    }
}

tokio::task_local! {
    /// Set while a message received over SMTP is accepted, so that queueing and immediate
    /// failures see what its sender asked for.
    pub static REQUEST: Request;
}

/// What the current SMTP transaction asked for `recipient`; nothing outside of one.
pub fn current(recipient: &str) -> Dsn {
    REQUEST.try_with(|request| request.for_recipient(recipient)).unwrap_or_default()
}

/// Validates a `NOTIFY` value: `NEVER` alone, or any of `SUCCESS`, `FAILURE`, `DELAY`.
pub fn parse_notify(value: &str) -> Option<String> {
    let mut items: Vec<String> = value.split(',').map(|v| v.trim().to_ascii_uppercase()).collect();
    if items.iter().any(|v| v == "NEVER") {
        return (items.len() == 1).then(|| "NEVER".to_owned());
    }
    if items.is_empty() || items.iter().any(|v| !matches!(v.as_str(), "SUCCESS" | "FAILURE" | "DELAY")) {
        return None;
    }
    items.sort();
    items.dedup();
    Some(items.join(","))
}

pub fn parse_ret(value: &str) -> Option<String> {
    let value = value.to_ascii_uppercase();
    matches!(value.as_str(), "FULL" | "HDRS").then_some(value)
}

/// Whether `value` is valid xtext (RFC 3461 section 4): printable ASCII, `+` and `=` only as
/// part of `+XX` escapes.
pub fn valid_xtext(value: &str, max: usize) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > max {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                if !(bytes.get(i + 1).is_some_and(|b| b.is_ascii_hexdigit()) && bytes.get(i + 2).is_some_and(|b| b.is_ascii_hexdigit())) {
                    return false;
                }
                i += 3;
            }
            b'!'..=b'~' if bytes[i] != b'=' => i += 1,
            _ => return false,
        }
    }
    true
}

/// Decodes xtext for display, keeping only printable characters.
pub fn decode_xtext(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+'
            && let Some(byte) = value.get(i + 1..i + 3).and_then(|hex| u8::from_str_radix(hex, 16).ok())
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).chars().filter(|c| !c.is_control()).collect()
}

/// Encodes an address as xtext, for an `ORCPT` we add ourselves.
pub fn encode_xtext(value: &str) -> String {
    value.bytes().map(|b| if (b'!'..=b'~').contains(&b) && b != b'+' && b != b'=' { (b as char).to_string() } else { format!("+{b:02X}") }).collect()
}

/// The `ORCPT` value: `addr-type;xtext`, with a known address type.
pub fn parse_orcpt(value: &str) -> Option<String> {
    let (kind, address) = value.split_once(';')?;
    (kind.eq_ignore_ascii_case("rfc822") && valid_xtext(address, 500)).then(|| format!("rfc822;{address}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Failed,
    Delayed,
    Delivered,
    Relayed,
}

impl Action {
    fn as_str(self) -> &'static str {
        match self {
            Action::Failed => "failed",
            Action::Delayed => "delayed",
            Action::Delivered => "delivered",
            Action::Relayed => "relayed",
        }
    }
}

/// Builds a delivery status notification (RFC 3464) about one recipient.
pub fn build(hostname: &str, original_sender: &str, recipient: &str, action: Action, reason: &str, original: &[u8], dsn: &Dsn) -> Vec<u8> {
    let boundary = format!("dsn-{}", random_token());
    let reason = sanitize_line(reason);
    let (subject, explanation, status) = match action {
        Action::Failed => (
            "Undelivered Mail Returned to Sender",
            "Your message could not be delivered to the following recipient:",
            if reason.starts_with('4') { "4.0.0" } else { "5.0.0" },
        ),
        Action::Delayed => ("Delayed Mail (still being retried)", "Your message has not been delivered yet to the following recipient. Delivery will be retried; you do not need to send it again:", "4.0.0"),
        Action::Delivered => ("Successful Mail Delivery Report", "Your message was delivered to the mailbox of the following recipient:", "2.0.0"),
        Action::Relayed => (
            "Successful Mail Delivery Report",
            "Your message was handed on to the following recipient's mail server, which does not send delivery notifications itself:",
            "2.0.0",
        ),
    };
    let mut per_message = format!("Reporting-MTA: dns; {hostname}\r\n");
    if let Some(envid) = &dsn.envid {
        per_message.push_str(&format!("Original-Envelope-Id: {}\r\n", sanitize_line(envid)));
    }
    per_message.push_str(&format!("Arrival-Date: {}\r\n", rfc2822_now()));
    let mut per_recipient = String::new();
    if let Some(orcpt) = &dsn.orcpt {
        per_recipient.push_str(&format!("Original-Recipient: {}\r\n", sanitize_line(orcpt)));
    }
    per_recipient.push_str(&format!("Final-Recipient: rfc822; {recipient}\r\nAction: {}\r\nStatus: {status}\r\n", action.as_str()));
    if !reason.is_empty() {
        per_recipient.push_str(&format!("Diagnostic-Code: smtp; {reason}\r\n"));
    }
    let shown_recipient = dsn.orcpt.as_deref().and_then(|o| o.split_once(';')).map(|(_, a)| decode_xtext(a)).filter(|a| !a.is_empty()).unwrap_or_else(|| recipient.to_owned());
    let reason_line = if reason.is_empty() { String::new() } else { format!("{}: {reason}\r\n\r\n", if action == Action::Failed { "Reason" } else { "Details" }) };
    let full = dsn.ret.as_deref() == Some("FULL") && original.len() <= MAX_RETURNED_BYTES;
    let mut out = format!(
        "From: Mail Delivery System <MAILER-DAEMON@{hostname}>\r\n\
         To: <{original_sender}>\r\n\
         Subject: {subject}\r\n\
         Date: {date}\r\n\
         Message-ID: <{id}@{hostname}>\r\n\
         Auto-Submitted: auto-replied\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/report; report-type=delivery-status; boundary=\"{boundary}\"\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         This is the mail system at {hostname}.\r\n\
         \r\n\
         {explanation}\r\n\
         \r\n\
         \x20   <{shown_recipient}>\r\n\
         \r\n\
         {reason_line}\
         --{boundary}\r\n\
         Content-Type: message/delivery-status\r\n\
         \r\n\
         {per_message}\
         \r\n\
         {per_recipient}\
         \r\n\
         --{boundary}\r\n\
         Content-Type: {returned}\r\n\
         \r\n",
        date = rfc2822_now(),
        id = random_token(),
        returned = if full { "message/rfc822" } else { "text/rfc822-headers" },
    )
    .into_bytes();
    let returned = if full { original } else { &original[..find_header_end(original).min(MAX_REPORT_HEADER_BYTES)] };
    out.extend_from_slice(returned);
    if !returned.ends_with(b"\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    out
}

/// The parameters to pass on to a receiving server that supports DSN itself: `(MAIL, RCPT)`.
pub fn smtp_parameters(dsn: &Dsn, recipient: &str) -> (String, String) {
    let mut mail = String::new();
    if let Some(ret) = &dsn.ret {
        mail.push_str(&format!(" RET={ret}"));
    }
    if let Some(envid) = &dsn.envid {
        mail.push_str(&format!(" ENVID={envid}"));
    }
    let mut rcpt = String::new();
    if let Some(notify) = &dsn.notify {
        rcpt.push_str(&format!(" NOTIFY={notify}"));
    }
    match &dsn.orcpt {
        Some(orcpt) => rcpt.push_str(&format!(" ORCPT={orcpt}")),
        None if recipient.is_ascii() => rcpt.push_str(&format!(" ORCPT=rfc822;{}", encode_xtext(recipient))),
        None => {}
    }
    (mail, rcpt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_parameters_do_not_panic_or_inject_lines() {
        for text in crate::fuzzing::texts(2, 4000, 8) {
            let _ = parse_notify(&text);
            let _ = parse_ret(&text);
            let _ = valid_xtext(&text, 100);
            assert!(!decode_xtext(&text).chars().any(|c| c.is_control()), "decoded xtext stays on one line");
            if let Some(orcpt) = parse_orcpt(&text) {
                assert!(!orcpt.contains(['\r', '\n']));
            }
            let dsn = Dsn { notify: parse_notify(&text), ret: parse_ret(&text), envid: valid_xtext(&text, 100).then(|| text.clone()), orcpt: parse_orcpt(&text), require_tls: false, ..Default::default() };
            let report = build("mx.example", "a@b.example", "c@d.example", Action::Failed, &text, text.as_bytes(), &dsn);
            let head = String::from_utf8_lossy(&report[..report.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(report.len())]).into_owned();
            assert!(!head.contains("\nInjected"), "no header injection");
        }
    }


    #[test]
    fn parameters() {
        assert_eq!(parse_notify("success,failure"), Some("FAILURE,SUCCESS".into()));
        assert_eq!(parse_notify("NEVER"), Some("NEVER".into()));
        assert_eq!(parse_notify("NEVER,SUCCESS"), None);
        assert_eq!(parse_notify("SOMETIMES"), None);
        assert_eq!(parse_notify(""), None);
        assert_eq!(parse_ret("hdrs"), Some("HDRS".into()));
        assert_eq!(parse_ret("BODY"), None);
        assert!(valid_xtext("QQ314159", 100) && valid_xtext("a+2Bb", 100));
        assert!(!valid_xtext("a+2", 100) && !valid_xtext("a=b", 100) && !valid_xtext("a b", 100) && !valid_xtext("", 100) && !valid_xtext("a+zz", 100));
        assert_eq!(decode_xtext("bob+2Bnews@example.org"), "bob+news@example.org");
        assert_eq!(encode_xtext("bob+news=x@example.org"), "bob+2Bnews+3Dx@example.org");
        assert_eq!(parse_orcpt("rfc822;bob@example.org"), Some("rfc822;bob@example.org".into()));
        assert_eq!(parse_orcpt("x400;something"), None);

        let dsn = Dsn::default();
        assert!(dsn.wants_failure() && !dsn.wants_success() && !dsn.wants_delay());
        let never = Dsn { notify: Some("NEVER".into()), ..Dsn::default() };
        assert!(!never.wants_failure() && !never.wants_success());
        let all = Dsn { notify: Some("DELAY,FAILURE,SUCCESS".into()), ..Dsn::default() };
        assert!(all.wants_failure() && all.wants_success() && all.wants_delay());

        let passed = Dsn { notify: Some("FAILURE,SUCCESS".into()), ret: Some("HDRS".into()), envid: Some("QQ314159".into()), orcpt: None, require_tls: false, ..Default::default() };
        assert_eq!(smtp_parameters(&passed, "bob@example.org"), (" RET=HDRS ENVID=QQ314159".into(), " NOTIFY=FAILURE,SUCCESS ORCPT=rfc822;bob@example.org".into()));
    }

    #[test]
    fn reports() {
        let original = b"Subject: Hi\r\nFrom: a@b.example\r\n\r\nSecret body\r\n";
        let dsn = Dsn { notify: Some("SUCCESS".into()), ret: Some("FULL".into()), envid: Some("ID+2B1".into()), orcpt: Some("rfc822;list+2Bx@example.org".into()), require_tls: false, ..Default::default() };
        let report = String::from_utf8(build("mx.example", "a@b.example", "bob@example.org", Action::Delivered, "", original, &dsn)).unwrap();
        assert!(report.contains("Subject: Successful Mail Delivery Report\r\n"));
        assert!(report.contains("Original-Envelope-Id: ID+2B1\r\n"));
        assert!(report.contains("Original-Recipient: rfc822;list+2Bx@example.org\r\nFinal-Recipient: rfc822; bob@example.org\r\nAction: delivered\r\nStatus: 2.0.0\r\n"));
        assert!(report.contains("    <list+x@example.org>"), "the recipient as the sender wrote it");
        assert!(report.contains("Content-Type: message/rfc822\r\n\r\nSubject: Hi") && report.contains("Secret body"), "RET=FULL returns the message");

        let report = String::from_utf8(build("mx.example", "a@b.example", "bob@example.org", Action::Delayed, "451 4.4.1 no answer", original, &Dsn::default())).unwrap();
        assert!(report.contains("Action: delayed\r\nStatus: 4.0.0\r\nDiagnostic-Code: smtp; 451 4.4.1 no answer\r\n"));
        assert!(report.contains("text/rfc822-headers") && !report.contains("Secret body"));
    }
}
