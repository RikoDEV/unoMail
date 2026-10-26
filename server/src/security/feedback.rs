//! Feedback reports in the Abuse Reporting Format (ARF, RFC 5965).
//!
//! Outgoing: authentication-failure reports (RFC 6591) for DMARC (RFC 9991, the `ruf`
//! addresses), DKIM (RFC 6651, a signature with `r=y` and a key with `ra=`) and SPF
//! (RFC 6652, the `ra=` modifier). They show the sending domain the headers of a message that
//! failed, with the recipients' addresses redacted (RFC 6590), at most once an hour per
//! domain, and only when the administrator turned them on: they tell another party about
//! mail sent to this server's users.
//!
//! Incoming: feedback reports sent to hosted domains (complaints, `not-spam` (RFC 6430) and
//! failure reports) are stored for the administrators, from verified senders only.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{LazyLock, Mutex},
};

use mail_auth::report::{AuthFailureType, Feedback, FeedbackType, IdentityAlignment};

use crate::{app::App, util::now};

const REPORT_INTERVAL_SECS: i64 = 3600;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const KEEP_DAYS: i64 = 90;

/// What failed, and where the report goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReport {
    pub kind: Kind,
    /// The domain the report is about (the From domain, the signing domain, the SPF domain).
    pub domain: String,
    /// Destination addresses (bare, without `mailto:`).
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// DMARC failed; whether DKIM and SPF were each aligned.
    Dmarc { dkim_aligned: bool, spf_aligned: bool },
    Dkim,
    Spf,
}

static LAST_SENT: LazyLock<Mutex<HashMap<(String, &'static str), i64>>> = LazyLock::new(Mutex::default);

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Dmarc { .. } => "dmarc",
        Kind::Dkim => "dkim",
        Kind::Spf => "spf",
    }
}

/// Whether a report about `domain` of this kind may be sent now (and notes it as sent).
fn claim(domain: &str, kind: Kind) -> bool {
    let mut last = LAST_SENT.lock().unwrap_or_else(|e| e.into_inner());
    let key = (domain.to_ascii_lowercase(), kind_name(kind));
    let now = now();
    if last.get(&key).is_some_and(|&at| now - at < REPORT_INTERVAL_SECS) {
        return false;
    }
    last.insert(key, now);
    last.retain(|_, at| now - *at < REPORT_INTERVAL_SECS);
    true
}

/// The header block with the recipients' local parts redacted (RFC 6590) and Bcc left out.
pub fn redacted_headers(raw: &[u8]) -> String {
    let end = crate::security::authn::find_header_end(raw).min(MAX_HEADER_BYTES);
    let head = String::from_utf8_lossy(&raw[..end]);
    let mut out = String::new();
    let mut current: Option<String> = None;
    let flush = |field: Option<String>, out: &mut String| {
        let Some(field) = field else { return };
        let name = field.split(':').next().unwrap_or_default().trim().to_ascii_lowercase();
        match name.as_str() {
            "bcc" => {}
            "to" | "cc" | "delivered-to" | "x-original-to" | "envelope-to" => out.push_str(&redact_addresses(&field)),
            _ => out.push_str(&field),
        }
    };
    for line in head.split_inclusive('\n') {
        if line.starts_with([' ', '\t']) {
            if let Some(field) = &mut current {
                field.push_str(line);
            }
        } else {
            flush(current.take(), &mut out);
            current = Some(line.to_owned());
        }
    }
    flush(current, &mut out);
    out
}

/// Replaces the local part of every address in a header field with `redacted`.
fn redact_addresses(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let (name, value) = field.split_once(':').unwrap_or(("", field));
    out.push_str(name);
    out.push(':');
    let bytes: Vec<char> = value.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '@' {
            // Walk back over the local part already copied, and replace it.
            let mut start = out.len();
            while let Some(c) = out[..start].chars().next_back() {
                if c.is_alphanumeric() || "._%+-'=!#$&*/?^`{|}~".contains(c) {
                    start -= c.len_utf8();
                } else {
                    break;
                }
            }
            if start < out.len() {
                out.truncate(start);
                out.push_str("redacted");
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Sends the failure reports a delivery produced, when the administrator allows it.
#[allow(clippy::too_many_arguments)]
pub async fn send(app: &App, reports: &[PendingReport], ip: IpAddr, mail_from: &str, recipient: &str, raw: &[u8], authentication_results: &str) {
    if reports.is_empty() || !app.rt().auth_failure_reports {
        return;
    }
    let Some((sender, sender_domain)) = crate::smtp::transport::report_sender(app).await else { return };
    let headers = redacted_headers(raw);
    let recipient_domain = recipient.rsplit_once('@').map_or("", |(_, d)| d).to_owned();
    for report in reports {
        if !claim(&report.domain, report.kind) {
            continue;
        }
        let (auth_failure, alignment) = match report.kind {
            Kind::Dmarc { dkim_aligned, spf_aligned } => (
                AuthFailureType::Dmarc,
                match (dkim_aligned, spf_aligned) {
                    (true, true) => IdentityAlignment::DkimSpf,
                    (true, false) => IdentityAlignment::Dkim,
                    (false, true) => IdentityAlignment::Spf,
                    (false, false) => IdentityAlignment::None,
                },
            ),
            Kind::Dkim => (AuthFailureType::Signature, IdentityAlignment::Unspecified),
            Kind::Spf => (AuthFailureType::Spf, IdentityAlignment::Unspecified),
        };
        let feedback = Feedback::new(FeedbackType::AuthFailure)
            .with_version(1)
            .with_user_agent("unoMail")
            .with_arrival_date(now())
            .with_source_ip(ip)
            .with_reporting_mta(app.cfg.hostname.clone())
            .with_original_mail_from(mail_from.to_owned())
            .with_original_rcpt_to(format!("redacted@{recipient_domain}"))
            .with_reported_domain(report.domain.clone())
            .with_auth_failure(auth_failure)
            .with_identity_alignment(alignment)
            .with_authentication_results(authentication_results.trim_end().trim_start_matches("Authentication-Results:").trim().to_owned())
            .with_headers(headers.clone());
        for address in report.addresses.iter().take(3) {
            let Some((_, address_domain)) = address.rsplit_once('@') else { continue };
            // DMARC: an address outside the domain must say it accepts reports for it.
            if matches!(report.kind, Kind::Dmarc { .. }) && !crate::dmarc_outgoing::destination_allowed(app, &report.domain, address_domain).await {
                tracing::info!(domain = report.domain, address, "failure report address not authorized by its domain");
                continue;
            }
            let subject = format!("Authentication failure report for {}", report.domain);
            let mut message = Vec::new();
            if let Err(err) = feedback.write_rfc5322(("unoMail", sender.as_str()), address.as_str(), subject.as_str(), &mut message) {
                tracing::info!(%err, "failure report could not be written");
                continue;
            }
            if let Err(err) = crate::smtp::transport::send_system_mail(app, &sender_domain, address, message).await {
                tracing::info!(%err, domain = report.domain, "failure report not sent");
            }
        }
    }
}

/// Stores a feedback report found in mail to a hosted domain; true when it was one.
pub async fn ingest_mail(app: &App, raw: &[u8], reporter: &str) -> bool {
    let Ok(feedback) = Feedback::parse_rfc5322(raw) else { return false };
    let feedback_type = match feedback.feedback_type() {
        FeedbackType::Abuse => "abuse",
        FeedbackType::AuthFailure => "auth-failure",
        FeedbackType::Fraud => "fraud",
        FeedbackType::NotSpam => "not-spam",
        FeedbackType::Virus => "virus",
        FeedbackType::Other => "other",
    };
    let auth_failure = match feedback.auth_failure() {
        AuthFailureType::Adsp => "adsp",
        AuthFailureType::BodyHash => "bodyhash",
        AuthFailureType::Revoked => "revoked",
        AuthFailureType::Signature => "signature",
        AuthFailureType::Spf => "spf",
        AuthFailureType::Dmarc => "dmarc",
        AuthFailureType::Unspecified => "",
    };
    let headers = feedback.headers().unwrap_or_default();
    let field = |name: &str| {
        headers.lines().find_map(|line| line.split_once(':').filter(|(n, _)| n.trim().eq_ignore_ascii_case(name)).map(|(_, v)| crate::util::sanitize_line(v.trim())))
    };
    let clip = |s: &str| crate::util::sanitize_line(&s.chars().take(300).collect::<String>());
    let result = sqlx::query(
        "INSERT INTO feedback_reports (received_at, reporter, feedback_type, auth_failure, source_ip, reported_domain, original_from, original_rcpt, subject, incidents, user_agent)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(now())
    .bind(clip(reporter))
    .bind(feedback_type)
    .bind(auth_failure)
    .bind(feedback.source_ip().map(|ip| ip.to_string()).unwrap_or_default())
    .bind(feedback.reported_domain().first().map(|d| clip(d)).unwrap_or_default())
    .bind(feedback.original_mail_from().map(clip).or_else(|| field("from")).unwrap_or_default())
    .bind(feedback.original_rcpt_to().map(clip).unwrap_or_default())
    .bind(field("subject").map(|s| clip(&s)).unwrap_or_default())
    .bind(i64::from(feedback.incidents().max(1)))
    .bind(feedback.user_agent().map(clip).unwrap_or_default())
    .execute(&app.db)
    .await;
    if let Err(err) = result {
        tracing::warn!(error = %err, "feedback report not stored");
        return false;
    }
    let _ = sqlx::query("DELETE FROM feedback_reports WHERE received_at < ?").bind(now() - KEEP_DAYS * 86400).execute(&app.db).await;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipients_are_redacted_and_bcc_left_out() {
        let raw = b"From: ann@remote.example\r\nTo: Bob <bob.smith+x@example.org>, carol@example.org\r\nCc: dave@example.org\r\nBcc: secret@example.org\r\nSubject: hi\r\n\r\nbody";
        let headers = redacted_headers(raw);
        assert!(headers.contains("From: ann@remote.example"), "{headers}");
        assert!(headers.contains("To: Bob <redacted@example.org>, redacted@example.org"), "{headers}");
        assert!(headers.contains("Cc: redacted@example.org"), "{headers}");
        assert!(!headers.contains("secret") && !headers.contains("body"), "{headers}");
    }

    #[test]
    fn reports_about_a_domain_go_out_at_most_hourly() {
        let kind = Kind::Dkim;
        assert!(claim("hourly.example", kind));
        assert!(!claim("hourly.example", kind));
        assert!(claim("hourly.example", Kind::Spf), "other kinds are separate");
    }

    #[test]
    fn feedback_reports_are_recognized() {
        let report = Feedback::new(FeedbackType::Abuse)
            .with_source_ip("192.0.2.1".parse().unwrap())
            .with_reported_domain("example.org")
            .with_headers("From: spammer@example.org\r\nSubject: Buy now\r\n");
        let mut message = Vec::new();
        report.write_rfc5322(("FBL", "fbl@isp.example"), "abuse@example.org", "Complaint", &mut message).unwrap();
        let parsed = Feedback::parse_rfc5322(&message).unwrap();
        assert_eq!(parsed.feedback_type(), FeedbackType::Abuse);
        assert_eq!(parsed.reported_domain().first().map(|d| d.as_ref()), Some("example.org"));
    }
}
