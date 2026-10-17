//! What the server found out about a stored message when it arrived: whether the sender was
//! authenticated (SPF, DKIM, DMARC), whether the connection was encrypted, and whether a virus
//! scanner objected. The facts are read back from the headers this server added on delivery;
//! headers of the same names written by anybody else were removed then, so they can be trusted.

use serde::Serialize;

/// Header marking a message in which the virus scanner found something.
pub const VIRUS_HEADER: &str = "X-Virus-Status";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// `remote`: received from another server. `submitted`: sent by a signed-in user of this
    /// server. `unknown`: imported, or stored before such facts were recorded.
    pub origin: &'static str,
    /// `verified`: DMARC passed, the visible sender is genuine. `partial`: SPF or DKIM passed
    /// but nothing ties them to the visible sender. `unverified`: nothing could be checked.
    /// `failed`: a check failed. `internal` and `unknown` as for `origin`.
    pub verdict: &'static str,
    pub spf: Option<String>,
    pub dkim: Option<String>,
    pub dmarc: Option<String>,
    /// Domain of the envelope sender, which SPF checked ("mailed-by").
    pub mailed_by: Option<String>,
    /// Domains whose DKIM signature verified ("signed-by").
    pub signed_by: Vec<String>,
    /// Domain of the visible sender as DMARC evaluated it.
    pub from_domain: Option<String>,
    /// Whether the message arrived over an encrypted connection.
    pub tls: Option<bool>,
    /// Name of the malware the scanner reported, if any.
    pub virus: Option<String>,
    /// The failed checks in words, for a warning.
    pub problems: Vec<String>,
}

/// The header fields of a message, unfolded: (lower-case name, value).
fn headers(raw: &[u8]) -> Vec<(String, String)> {
    let end = super::authn::find_header_end(raw);
    let text = String::from_utf8_lossy(&raw[..end]);
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = out.last_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
        } else if let Some((name, value)) = line.split_once(':') {
            out.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    out
}

/// Removes RFC 5322 comments (parenthesised text) from a header value.
fn without_comments(value: &str) -> String {
    let (mut out, mut depth) = (String::with_capacity(value.len()), 0usize);
    for c in value.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

fn domain_of(value: &str) -> Option<String> {
    let value = value.trim().trim_matches(['<', '>', '"']);
    let domain = value.rsplit_once('@').map_or(value, |(_, domain)| domain).trim_end_matches('.').to_ascii_lowercase();
    (!domain.is_empty() && domain.len() <= 253 && domain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')).then_some(domain)
}

/// One `method=result prop=value ...` clause of an Authentication-Results header.
struct Clause {
    method: String,
    result: String,
    props: Vec<(String, String)>,
}

fn clauses(value: &str) -> Vec<Clause> {
    without_comments(value)
        .split(';')
        .skip(1)
        .filter_map(|part| {
            let mut tokens = part.split_whitespace().filter_map(|token| token.split_once('='));
            let (method, result) = tokens.next()?;
            Some(Clause { method: method.to_ascii_lowercase(), result: result.to_ascii_lowercase(), props: tokens.map(|(k, v)| (k.to_ascii_lowercase(), v.to_owned())).collect() })
        })
        .collect()
}

pub fn summarize(raw: &[u8], hostname: &str) -> Summary {
    let headers = headers(raw);
    let mut summary = Summary { origin: "unknown", verdict: "unknown", ..Default::default() };

    summary.virus = headers.iter().find(|(name, _)| name.eq_ignore_ascii_case(VIRUS_HEADER)).and_then(|(_, value)| {
        let value = without_comments_keep(value);
        value.to_ascii_lowercase().starts_with("infected").then(|| value.split_once(char::is_whitespace).map_or("", |(_, name)| name).trim().chars().filter(|c| c.is_ascii_alphanumeric() || ".-_/".contains(*c)).take(100).collect())
    });

    // The topmost Received line is the one this server wrote (if it received the message at all).
    if let Some((_, received)) = headers.iter().find(|(name, _)| name == "received") {
        let lower = received.to_ascii_lowercase();
        if let Some(position) = lower.find(&format!("by {} with ", hostname.to_ascii_lowercase())) {
            let protocol = lower[position..].split_whitespace().nth(3).unwrap_or("");
            summary.tls = Some(protocol.starts_with("esmtps"));
            summary.origin = if protocol == "esmtpsa" || protocol == "esmtpa" { "submitted" } else { "remote" };
        }
    }

    let results = headers.iter().find(|(name, value)| name == "authentication-results" && value.split(';').next().is_some_and(|id| id.trim().eq_ignore_ascii_case(hostname)));
    let Some((_, results)) = results else {
        if summary.origin == "submitted" {
            summary.verdict = "internal";
        }
        return finish(summary);
    };
    summary.origin = "remote";
    let mut dkim_results: Vec<String> = Vec::new();
    for clause in clauses(results) {
        let prop = |name: &str| clause.props.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str());
        match clause.method.as_str() {
            "spf" if summary.spf.is_none() => {
                summary.spf = Some(clause.result.clone());
                summary.mailed_by = prop("smtp.mailfrom").and_then(domain_of).or_else(|| prop("smtp.helo").and_then(domain_of));
            }
            "dkim" => {
                if clause.result == "pass"
                    && let Some(domain) = prop("header.d").and_then(domain_of)
                    && !summary.signed_by.contains(&domain)
                {
                    summary.signed_by.push(domain);
                }
                dkim_results.push(clause.result.clone());
            }
            "dmarc" if summary.dmarc.is_none() => {
                summary.dmarc = Some(clause.result.clone());
                summary.from_domain = prop("header.from").and_then(domain_of);
            }
            _ => {}
        }
    }
    // Several signatures: one that verifies is enough; otherwise the first tells what went wrong.
    summary.dkim = if dkim_results.iter().any(|result| result == "pass") { Some("pass".into()) } else { dkim_results.into_iter().next() };

    let is = |value: &Option<String>, wanted: &[&str]| value.as_deref().is_some_and(|v| wanted.contains(&v));
    let (spf_pass, dkim_pass) = (is(&summary.spf, &["pass"]), is(&summary.dkim, &["pass"]));
    let sender = summary.from_domain.clone().or_else(|| summary.mailed_by.clone()).unwrap_or_else(|| "the sender's domain".into());
    if is(&summary.dmarc, &["fail"]) {
        summary.problems.push(format!("DMARC: the message does not come from where {sender} says its mail comes from"));
    }
    if is(&summary.spf, &["fail", "softfail"]) {
        summary.problems.push(format!("SPF: the server that sent it is not one {} sends mail from", summary.mailed_by.as_deref().unwrap_or(&sender)));
    }
    if is(&summary.dkim, &["fail", "permerror", "policy"]) {
        summary.problems.push("DKIM: the signature does not match; the message may have been altered on the way".into());
    }
    summary.verdict = if is(&summary.dmarc, &["pass"]) {
        "verified"
    } else if is(&summary.dmarc, &["fail"]) || (!dkim_pass && is(&summary.spf, &["fail", "softfail"])) || (!spf_pass && is(&summary.dkim, &["fail", "permerror", "policy"])) {
        "failed"
    } else if spf_pass || dkim_pass {
        "partial"
    } else {
        "unverified"
    };
    // Problems that did not decide the verdict (a broken signature next to a good one) are not worth a warning.
    if summary.verdict == "verified" {
        summary.problems.clear();
    }
    finish(summary)
}

/// Like [`without_comments`], but keeps the text inside parentheses (the scanner's finding).
fn without_comments_keep(value: &str) -> String {
    value.replace(['(', ')', ';', '='], " ").split_whitespace().collect::<Vec<_>>().join(" ")
}

fn finish(mut summary: Summary) -> Summary {
    if let Some(name) = &summary.virus {
        summary.problems.insert(0, format!("The virus scanner found malware in this message{}", if name.is_empty() { String::new() } else { format!(": {name}") }));
    }
    summary
}

/// The header added to a message the scanner objected to but that is delivered nonetheless.
pub fn virus_header(name: &str) -> String {
    let name: String = name.chars().filter(|c| c.is_ascii_alphanumeric() || ".-_/".contains(*c)).take(100).collect();
    format!("{VIRUS_HEADER}: Infected ({name})\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "mail.example.com";

    fn message(headers: &str) -> Vec<u8> {
        format!("{headers}From: Anna <anna@partner.example>\r\nSubject: Hi\r\n\r\nAuthentication-Results: {HOST}; dmarc=pass\r\n").into_bytes()
    }

    #[test]
    fn a_genuine_message() {
        let raw = message(
            "Return-Path: <bounce@mailer.partner.example>\r\nReceived: from out.partner.example ([203.0.113.9])\r\n\tby mail.example.com with ESMTPS id abc;\r\n\tTue, 13 Oct 2026 10:00:00 +0000\r\n\
Authentication-Results: mail.example.com;\r\n\tdkim=fail (body hash) header.d=broken.example header.s=s1;\r\n\tdkim=pass header.d=partner.example header.s=s2 header.b=abcd;\r\n\
\tspf=pass (sender is authorized) smtp.mailfrom=bounce@mailer.partner.example smtp.helo=out.partner.example;\r\n\tdmarc=pass header.from=partner.example policy.dmarc=reject\r\n",
        );
        let summary = summarize(&raw, HOST);
        assert_eq!((summary.origin, summary.verdict), ("remote", "verified"));
        assert_eq!((summary.spf.as_deref(), summary.dkim.as_deref(), summary.dmarc.as_deref()), (Some("pass"), Some("pass"), Some("pass")));
        assert_eq!((summary.mailed_by.as_deref(), summary.from_domain.as_deref(), summary.tls), (Some("mailer.partner.example"), Some("partner.example"), Some(true)));
        assert_eq!(summary.signed_by, ["partner.example"], "only signatures that verified");
        assert!(summary.problems.is_empty() && summary.virus.is_none());
    }

    #[test]
    fn failures_are_named() {
        let spoofed = message(
            "Received: from evil.example ([198.51.100.7])\r\n\tby mail.example.com with ESMTP id abc; Tue, 13 Oct 2026 10:00:00 +0000\r\n\
Authentication-Results: mail.example.com; dkim=none; spf=softfail smtp.mailfrom=anna@partner.example; dmarc=fail header.from=partner.example\r\n",
        );
        let summary = summarize(&spoofed, HOST);
        assert_eq!((summary.verdict, summary.tls), ("failed", Some(false)));
        assert_eq!(summary.problems.len(), 2);
        assert!(summary.problems[0].starts_with("DMARC:") && summary.problems[0].contains("partner.example") && summary.problems[1].starts_with("SPF:"));

        let cases = [
            ("dkim=none; spf=none smtp.mailfrom=a@x.example; dmarc=none header.from=x.example", "unverified", 0),
            ("dkim=none; spf=pass smtp.mailfrom=a@x.example; dmarc=none header.from=y.example", "partial", 0),
            ("dkim=pass header.d=x.example; spf=fail smtp.mailfrom=a@fwd.example; dmarc=none", "partial", 1),
            ("dkim=fail header.d=x.example; spf=none; dmarc=none", "failed", 1),
            ("dkim=fail header.d=x.example; spf=pass smtp.mailfrom=a@x.example; dmarc=pass header.from=x.example", "verified", 0),
            ("dkim=none; spf=fail smtp.mailfrom=a@x.example; dmarc=none", "failed", 1),
            ("dkim=temperror; spf=temperror; dmarc=temperror", "unverified", 0),
        ];
        for (results, verdict, problems) in cases {
            let summary = summarize(&message(&format!("Authentication-Results: {HOST}; {results}\r\n")), HOST);
            assert_eq!((summary.verdict, summary.problems.len()), (verdict, problems), "{results}");
        }
    }

    #[test]
    fn only_this_servers_own_headers_count() {
        // Results stated by another server, or placed in the body, say nothing.
        let foreign = message("Authentication-Results: mx.other.example; dmarc=pass header.from=partner.example\r\n");
        assert_eq!(summarize(&foreign, HOST).verdict, "unknown");
        assert_eq!(summarize(b"Subject: x\r\n\r\nbody", HOST), Summary { origin: "unknown", verdict: "unknown", ..Default::default() });
        // Sent by a signed-in user of this server: nothing to verify, nothing to warn about.
        let internal = message("Return-Path: <bob@example.com>\r\nReceived: by mail.example.com with ESMTPSA id x;\r\n\tTue, 13 Oct 2026 10:00:00 +0000\r\n");
        let summary = summarize(&internal, HOST);
        assert_eq!((summary.origin, summary.verdict, summary.tls), ("submitted", "internal", Some(true)));
        // A relay's Received line further down is not ours.
        let relayed = message("Received: from a by relay.other.example with ESMTPS id 1; date\r\n");
        assert_eq!(summarize(&relayed, HOST).tls, None);
    }

    #[test]
    fn a_virus_finding_comes_first() {
        let raw = message(&format!("{}Authentication-Results: {HOST}; dkim=none; spf=pass smtp.mailfrom=a@x.example; dmarc=pass header.from=x.example\r\n", virus_header("Eicar-Signature\r\nX: y")));
        let summary = summarize(&raw, HOST);
        assert_eq!(summary.virus.as_deref(), Some("Eicar-SignatureXy"), "the name cannot carry a line break");
        assert_eq!(summary.verdict, "verified", "who sent it and what it carries are separate questions");
        assert_eq!(summary.problems, ["The virus scanner found malware in this message: Eicar-SignatureXy"]);
        assert_eq!(summarize(&message("X-Virus-Status: Clean\r\n"), HOST).virus, None);
        assert_eq!(summarize(&message("X-Virus-Status: Infected\r\n"), HOST).virus.as_deref(), Some(""));
    }
}
