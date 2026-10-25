//! Inbound sender authentication: SPF, DKIM and DMARC evaluation.

use std::net::IpAddr;

use mail_auth::{
    AuthenticatedMessage, AuthenticationResults, DkimResult, DmarcResult, MessageAuthenticator, SpfResult,
    arc::ArcSealer,
    common::headers::HeaderWriter,
    dmarc::{Policy, verify::DmarcParameters},
    spf::verify::SpfParameters,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Accept,
    /// DMARC failed under `p=quarantine`: deliver to the Junk folder.
    Quarantine,
    /// DMARC failed under `p=reject`, or SPF hard-failed without any DMARC policy.
    Reject,
}

#[derive(Debug)]
pub struct Verdict {
    /// Complete `Authentication-Results` header, CRLF terminated.
    pub header: String,
    pub disposition: Disposition,
    pub summary: String,
    /// `ARC-Seal`, `ARC-Message-Signature` and `ARC-Authentication-Results` for a copy that is
    /// forwarded, when a sealing key was given and the chain may be extended.
    pub arc_headers: Option<String>,
    /// What DMARC found, for the aggregate reports sent to the sender's domain.
    pub dmarc: Option<DmarcObservation>,
    /// SPF passed for the envelope sender: notices to it reach whoever sent the message.
    pub spf_pass: bool,
    /// DKIM or SPF passed in alignment with the From domain (DMARC pass): the visible author
    /// is who the message says.
    pub author_aligned: bool,
    /// Failure reports the sending domains asked for (DMARC `ruf`, DKIM and SPF `ra=`).
    pub failure_reports: Vec<crate::security::feedback::PendingReport>,
}

/// One DMARC evaluation as aggregate reports (RFC 7489 appendix C) record it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcObservation {
    /// The visible sender's domain, whose policy was applied.
    pub header_from: String,
    /// What was done: none, quarantine or reject.
    pub disposition: &'static str,
    /// Whether DKIM and SPF passed in alignment.
    pub dkim: &'static str,
    pub spf: &'static str,
    pub dkim_domain: String,
    pub dkim_result: String,
    pub spf_domain: String,
    pub spf_result: String,
    /// Why the policy was not applied (a trusted forwarder vouched for the message).
    pub override_reason: Option<&'static str>,
    /// The published policy (`PolicyPublished` as JSON) and its aggregate report addresses.
    pub policy: String,
    pub rua: Vec<String>,
}

fn dmarc_label(result: &DmarcResult) -> &'static str {
    match result {
        DmarcResult::Pass => "pass",
        DmarcResult::Fail(_) => "fail",
        DmarcResult::TempError(_) => "temperror",
        DmarcResult::PermError(_) => "permerror",
        DmarcResult::None => "none",
    }
}

fn spf_label(result: SpfResult) -> &'static str {
    match result {
        SpfResult::Pass => "pass",
        SpfResult::Fail => "fail",
        SpfResult::SoftFail => "softfail",
        SpfResult::Neutral => "neutral",
        SpfResult::TempError => "temperror",
        SpfResult::PermError => "permerror",
        SpfResult::None => "none",
    }
}

/// Whether `domain` is one of the ARC sealers trusted to vouch for forwarded mail (or below one).
pub fn trusted_sealer(domain: &str, trusted: &[String]) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    trusted.iter().any(|t| domain == *t || domain.ends_with(&format!(".{t}")))
}

/// What to do with a message given its DMARC policy and results.
fn decide(policy: Policy, aligned: bool, dmarc_failed: bool, spf_failed: bool, arc_vouches: bool) -> Disposition {
    let policy_applies = dmarc_failed && !arc_vouches;
    match policy {
        Policy::Reject if policy_applies => Disposition::Reject,
        Policy::Quarantine if policy_applies => Disposition::Quarantine,
        // No DMARC record published: honour an explicit SPF `-all` (unless ARC vouches).
        Policy::Unspecified if spf_failed && !aligned && !arc_vouches => Disposition::Reject,
        _ => Disposition::Accept,
    }
}

/// Evaluates SPF, DKIM, DMARC and ARC for a message received from `ip`.
///
/// `mail_from` is the envelope sender (empty for bounces). When DMARC fails but the message
/// carries a valid ARC chain last sealed by one of the `trusted_sealers` (a mailing list or a
/// forwarder the operator trusts), the policy is not applied. With `sealer`, the verdict also
/// carries the ARC set for a forwarded copy. Returns `None` when the message cannot be parsed
/// at all, which callers treat as a rejection.
#[allow(clippy::too_many_arguments)]
pub async fn verify(
    authenticator: &MessageAuthenticator,
    hostname: &str,
    ip: IpAddr,
    helo: &str,
    mail_from: &str,
    raw: &[u8],
    trusted_sealers: &[String],
    sealer: Option<crate::security::dkim::ArcSealKey>,
) -> Option<Verdict> {
    let message = AuthenticatedMessage::parse(raw)?;
    let dkim = authenticator.verify_dkim(&message).await;
    let arc = authenticator.verify_arc(&message).await;

    let spf = if mail_from.is_empty() {
        authenticator.verify_spf(SpfParameters::verify_ehlo(ip, helo, hostname)).await
    } else {
        authenticator.verify_spf(SpfParameters::verify_mail_from(ip, helo, hostname, mail_from)).await
    };
    let mail_from_domain = mail_from.rsplit_once('@').map_or(helo, |(_, d)| d);
    let dmarc = authenticator.verify_dmarc(DmarcParameters::new(&message, &dkim, mail_from_domain, &spf)).await;

    let aligned = matches!(dmarc.spf_result(), DmarcResult::Pass) || matches!(dmarc.dkim_result(), DmarcResult::Pass);
    let dmarc_failed =
        !aligned && (matches!(dmarc.spf_result(), DmarcResult::Fail(_)) || matches!(dmarc.dkim_result(), DmarcResult::Fail(_)));
    // A trusted intermediary (a list, a forwarder) that sealed a passing ARC chain vouches for
    // what the message looked like before it changed it.
    let arc_sealer = arc.sets().last().map(|set| set.seal.header.d.clone());
    let arc_vouches = dmarc_failed && *arc.result() == DkimResult::Pass && arc_sealer.as_deref().is_some_and(|d| trusted_sealer(d, trusted_sealers));
    let disposition = decide(dmarc.policy(), aligned, dmarc_failed, spf.result() == SpfResult::Fail, arc_vouches);

    let results = AuthenticationResults::new(hostname)
        .with_dkim_results(&dkim, message.from())
        .with_spf_mailfrom_result(&spf, ip, mail_from, helo)
        .with_arc_result(&arc, ip)
        .with_dmarc_result(&dmarc);
    let header = results.to_header();

    // Sealing the forwarded copy: our findings, signed, so the next hop can rely on them.
    let arc_headers = sealer.filter(|_| arc.can_be_sealed()).and_then(|key| {
        let headers = ["From", "To", "Cc", "Subject", "Date", "Message-ID", "Reply-To", "MIME-Version", "Content-Type", "DKIM-Signature"];
        let set = match key.key {
            crate::security::dkim::SealKey::Rsa(rsa) => ArcSealer::from_key(rsa).domain(&key.domain).selector(&key.selector).headers(headers).seal(&message, &results, &arc).map(|set| set.to_header()),
            crate::security::dkim::SealKey::Ed25519(ed) => ArcSealer::from_key(ed).domain(&key.domain).selector(&key.selector).headers(headers).seal(&message, &results, &arc).map(|set| set.to_header()),
        };
        set.map_err(|err| tracing::debug!(%err, "ARC sealing failed")).ok()
    });

    let observation = dmarc.dmarc_record().map(|record| {
        let signature = dkim.iter().find(|output| *output.result() == DkimResult::Pass).or_else(|| dkim.first());
        DmarcObservation {
            header_from: dmarc.domain().to_ascii_lowercase(),
            disposition: match disposition {
                Disposition::Reject => "reject",
                Disposition::Quarantine => "quarantine",
                Disposition::Accept => "none",
            },
            dkim: if matches!(dmarc.dkim_result(), DmarcResult::Pass) { "pass" } else { "fail" },
            spf: if matches!(dmarc.spf_result(), DmarcResult::Pass) { "pass" } else { "fail" },
            dkim_domain: signature.and_then(|s| s.signature()).map(|s| s.d.clone()).unwrap_or_default(),
            dkim_result: signature.map_or("none", |s| match s.result() {
                DkimResult::Pass => "pass",
                DkimResult::Neutral(_) => "neutral",
                DkimResult::Fail(_) => "fail",
                DkimResult::PermError(_) => "permerror",
                DkimResult::TempError(_) => "temperror",
                DkimResult::None => "none",
            }).to_owned(),
            spf_domain: spf.domain().to_owned(),
            spf_result: spf_label(spf.result()).to_owned(),
            override_reason: arc_vouches.then_some("trusted_forwarder"),
            policy: serde_json::to_string(&mail_auth::report::PolicyPublished::from_record(dmarc.domain().to_ascii_lowercase(), record)).unwrap_or_default(),
            rua: record.rua().iter().map(|uri| uri.uri().to_owned()).filter(|uri| uri.to_ascii_lowercase().starts_with("mailto:")).take(5).collect(),
        }
    });

    let summary = format!(
        "spf={:?} dmarc-spf={} dmarc-dkim={} policy={:?}{}",
        spf.result(),
        dmarc_label(dmarc.spf_result()),
        dmarc_label(dmarc.dkim_result()),
        dmarc.policy(),
        if arc_vouches { format!(" arc-override={}", arc_sealer.unwrap_or_default()) } else { String::new() }
    );
    let spf_pass = spf.result() == SpfResult::Pass && !mail_from.is_empty();

    use crate::security::feedback::{Kind, PendingReport};
    let mut failure_reports = Vec::new();
    if dmarc_failed && !arc_vouches
        && let Some(record) = dmarc.dmarc_record()
    {
        let addresses: Vec<String> = record.ruf.iter().filter_map(|uri| uri.uri().strip_prefix("mailto:").map(|a| a.split('!').next().unwrap_or_default().to_owned())).filter(|a| a.contains('@')).collect();
        if !addresses.is_empty() {
            failure_reports.push(PendingReport {
                kind: Kind::Dmarc { dkim_aligned: matches!(dmarc.dkim_result(), DmarcResult::Pass), spf_aligned: matches!(dmarc.spf_result(), DmarcResult::Pass) },
                domain: dmarc.domain().to_ascii_lowercase(),
                addresses,
            });
        }
    }
    // RFC 6651: a failing signature with `r=y` whose key names a report address.
    for output in dkim.iter().filter(|o| matches!(o.result(), DkimResult::Fail(_))) {
        if let (Some(address), Some(signature)) = (output.failure_report_addr(), output.signature()) {
            // mail-auth gives the full address: the key's `ra=` at the signing domain.
            failure_reports.push(PendingReport { kind: Kind::Dkim, domain: signature.d.to_ascii_lowercase(), addresses: vec![address.to_owned()] });
        }
    }
    // RFC 6652: an SPF failure, where the record's `ra=` modifier asks for reports.
    if spf.result() == SpfResult::Fail
        && let Some(address) = spf.report_address()
    {
        let domain = spf.domain().to_ascii_lowercase();
        let address = if address.contains('@') { address.to_owned() } else { format!("{address}@{domain}") };
        failure_reports.push(PendingReport { kind: Kind::Spf, domain, addresses: vec![address] });
    }
    Some(Verdict { header, disposition, summary, arc_headers, dmarc: observation, spf_pass, author_aligned: aligned, failure_reports })
}

/// Removes `Authentication-Results` headers that claim to come from us. Without this a sender
/// could pre-seed a forged "pass" result that mail clients and filters would trust. The same
/// goes for the virus scanner's verdict, which only this server may state.
pub fn strip_forged_results(raw: &[u8], hostname: &str) -> Vec<u8> {
    let header_end = find_header_end(raw);
    let (headers, body) = raw.split_at(header_end);
    let mut out = Vec::with_capacity(raw.len());
    let mut skipping = false;
    for line in headers.split_inclusive(|b| *b == b'\n') {
        let continuation = matches!(line.first(), Some(b' ' | b'\t'));
        if !continuation {
            let text = String::from_utf8_lossy(line).to_ascii_lowercase();
            skipping = text.starts_with("x-virus-status:")
                || text.strip_prefix("authentication-results:").is_some_and(|value| {
                    let authserv = value.trim().split(';').next().unwrap_or("").trim();
                    authserv.eq_ignore_ascii_case(hostname)
                });
        }
        if !skipping {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(body);
    out
}

/// Offset of the blank line separating headers from the body (or the message length).
pub fn find_header_end(raw: &[u8]) -> usize {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 2)
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|p| p + 1))
        .unwrap_or(raw.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_headers_are_stripped_without_panicking() {
        for raw in crate::fuzzing::inputs(7, 3000, 16) {
            let stripped = strip_forged_results(&raw, "mail.example.com");
            assert!(stripped.len() <= raw.len());
            assert!(find_header_end(&raw) <= raw.len());
        }
    }


    #[test]
    fn strips_only_our_own_authserv_id() {
        let raw = b"Received: from x\r\nAuthentication-Results: mail.example.com;\r\n\tdkim=pass header.d=evil.test\r\n\
Authentication-Results: other.example.net; spf=pass\r\nSubject: hi\r\n\r\nAuthentication-Results: mail.example.com; body\r\n";
        let out = String::from_utf8(strip_forged_results(raw, "mail.example.com")).unwrap();
        assert!(!out.contains("dkim=pass header.d=evil.test"));
        assert!(out.contains("Authentication-Results: other.example.net; spf=pass\r\n"));
        assert!(out.contains("Subject: hi\r\n\r\nAuthentication-Results: mail.example.com; body\r\n"), "body is untouched");
        assert!(out.starts_with("Received: from x\r\n"));
        let claimed = String::from_utf8(strip_forged_results(b"X-Virus-Status: Clean\r\n\t(trust me)\r\nSubject: hi\r\n\r\nX-Virus-Status: body\r\n", "mail.example.com")).unwrap();
        assert_eq!(claimed, "Subject: hi\r\n\r\nX-Virus-Status: body\r\n");
    }

    #[test]
    fn strip_is_case_insensitive() {
        let raw = b"AUTHENTICATION-RESULTS: MAIL.EXAMPLE.COM; dmarc=pass\r\nSubject: x\r\n\r\nbody";
        assert_eq!(strip_forged_results(raw, "mail.example.com"), b"Subject: x\r\n\r\nbody");
    }

    #[test]
    fn trusted_forwarders_can_vouch_for_failing_mail() {
        let trusted: Vec<String> = ["google.com".into(), "lists.example.org".into()].into();
        assert!(trusted_sealer("google.com", &trusted) && trusted_sealer("GOOGLE.com.", &trusted) && trusted_sealer("mx.google.com", &trusted));
        assert!(!trusted_sealer("notgoogle.com", &trusted) && !trusted_sealer("example.org", &trusted) && !trusted_sealer("", &trusted));

        assert_eq!(decide(Policy::Reject, false, true, false, false), Disposition::Reject);
        assert_eq!(decide(Policy::Reject, false, true, false, true), Disposition::Accept, "a trusted ARC seal overrides");
        assert_eq!(decide(Policy::Quarantine, false, true, false, false), Disposition::Quarantine);
        assert_eq!(decide(Policy::Quarantine, false, true, false, true), Disposition::Accept);
        assert_eq!(decide(Policy::Reject, true, false, false, false), Disposition::Accept);
        assert_eq!(decide(Policy::None, false, true, true, false), Disposition::Accept);
        assert_eq!(decide(Policy::Unspecified, false, false, true, false), Disposition::Reject, "SPF -all without DMARC");
        assert_eq!(decide(Policy::Unspecified, false, false, true, true), Disposition::Accept);
    }

    #[tokio::test]
    async fn forwarded_copies_are_sealed() {
        let pem = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let ed = mail_auth::common::crypto::Ed25519Key::from_pkcs8_der(pem.serialized_der()).unwrap();
        let raw = b"From: Alice <alice@sender.example>\r\nTo: list@example.org\r\nSubject: hi\r\nDate: Tue, 13 Oct 2026 10:00:00 +0000\r\nMessage-ID: <1@sender.example>\r\n\r\nHello\r\n";
        let message = AuthenticatedMessage::parse(raw).unwrap();
        let resolver = MessageAuthenticator::new_cloudflare_tls().unwrap();
        // No ARC headers yet: nothing to look up, the chain starts here.
        let arc = resolver.verify_arc(&message).await;
        assert!(arc.can_be_sealed());
        let results = AuthenticationResults::new("mx.example.org");
        let headers = ArcSealer::from_key(ed).domain("example.org").selector("s1").headers(["From", "To", "Subject"]).seal(&message, &results, &arc).unwrap().to_header();
        assert!(headers.contains("ARC-Seal: i=1; a=ed25519-sha256; s=s1; d=example.org; cv=none;"), "{headers}");
        assert!(headers.contains("ARC-Message-Signature: i=1;"), "{headers}");
        assert!(headers.contains("ARC-Authentication-Results: i=1; mx.example.org"), "{headers}");
    }

    #[test]
    fn header_end() {
        assert_eq!(find_header_end(b"A: b\r\n\r\nbody"), 6);
        assert_eq!(find_header_end(b"A: b\n\nbody"), 5);
        assert_eq!(find_header_end(b"A: b"), 4);
    }
}
