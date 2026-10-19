//! DNS and server health diagnostics: which records a domain needs and whether they are live.

use std::{net::{IpAddr, SocketAddr}, time::Duration};

use ipnet::IpNet;
use serde::Serialize;

use crate::{
    app::App,
    dns::{self, DnsError},
    security::{dkim::DkimKey, reputation},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Warning,
    Error,
    /// The check could not be performed (no resolver, lookup failure).
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: String,
    pub title: String,
    pub status: Status,
    pub message: String,
    /// The DNS record the administrator should publish.
    pub record_type: String,
    pub record_name: String,
    pub record_value: String,
    pub found: Vec<String>,
}

type Eval = (Status, String);

pub fn eval_mx(hosts: &[(u16, String)], hostname: &str) -> Eval {
    if hosts.is_empty() {
        return (Status::Error, "No MX record found; other servers cannot deliver mail to this domain.".into());
    }
    if hosts.iter().any(|(_, h)| h.eq_ignore_ascii_case(hostname)) {
        (Status::Ok, "MX points to this server.".into())
    } else {
        (Status::Error, format!("MX records do not include {hostname}."))
    }
}

fn spf_network(term: &str) -> Option<IpNet> {
    let term = term.strip_prefix('+').unwrap_or(term);
    let value = term.strip_prefix("ip4:").or_else(|| term.strip_prefix("ip6:"))?;
    value.parse().ok().or_else(|| value.parse::<IpAddr>().ok().map(Into::into))
}

pub fn eval_spf(records: &[String], server_ips: &[IpAddr]) -> Eval {
    let spf: Vec<&String> = records.iter().filter(|r| r.to_ascii_lowercase().starts_with("v=spf1")).collect();
    match spf.as_slice() {
        [] => (Status::Error, "No SPF record found.".into()),
        [record] => {
            let lower = record.to_ascii_lowercase();
            let terms: Vec<&str> = lower.split_whitespace().collect();
            if terms.iter().any(|t| matches!(*t, "+all" | "all")) {
                (Status::Error, "SPF record ends in +all, which authorizes every server on the internet.".into())
            } else if server_ips.is_empty() {
                (Status::Warning, "The server's public IP address could not be determined, so this SPF record cannot be verified.".into())
            } else if let Some(ip) = server_ips.iter().find(|ip| !terms.iter().filter_map(|term| spf_network(term)).any(|network| network.contains(*ip))) {
                (Status::Error, format!("SPF record does not authorize this server's IP address {ip}."))
            } else if terms.contains(&"?all") {
                (Status::Warning, "SPF record uses ?all (neutral); use ~all or -all.".into())
            } else if !terms.contains(&"-all") {
                (Status::Warning, "SPF record does not end in -all, so other servers are not explicitly forbidden.".into())
            } else {
                (Status::Ok, "SPF record authorizes this server's IP addresses and rejects all others.".into())
            }
        }
        _ => (Status::Error, "Multiple SPF records found; receivers treat this as a permanent error.".into()),
    }
}

fn tag_value<'a>(record: &'a str, name: &str) -> Option<&'a str> {
    record
        .split(';')
        .filter_map(|tag| tag.trim().split_once('='))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}

fn has_report_address(value: &str, address: &str) -> bool {
    value.split(',').any(|uri| uri.trim().eq_ignore_ascii_case(address))
}

pub fn eval_dkim(records: &[String], expected_public_key: &str) -> Eval {
    let normalize = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    let Some(record) = records.iter().find(|r| r.contains("p=")) else {
        return (Status::Error, "DKIM record not found.".into());
    };
    let published = normalize(record);
    let key = published.split(';').find_map(|tag| tag.strip_prefix("p=")).unwrap_or("");
    if key == normalize(expected_public_key) {
        (Status::Ok, "DKIM public key is published.".into())
    } else if key.is_empty() {
        (Status::Error, "DKIM record is published with an empty key (revoked).".into())
    } else {
        (Status::Error, "Published DKIM key does not match the key used for signing.".into())
    }
}

pub fn eval_dmarc(records: &[String], domain: &str) -> Eval {
    let dmarc: Vec<&String> = records.iter().filter(|r| r.to_ascii_lowercase().starts_with("v=dmarc1")).collect();
    match dmarc.as_slice() {
        [] => (Status::Error, "No DMARC record found.".into()),
        [record] => {
            let policy = tag_value(record, "p").map(str::to_ascii_lowercase);
            match policy.as_deref() {
                Some("reject" | "quarantine") if tag_value(record, "rua").is_some_and(|value| has_report_address(value, &format!("mailto:postmaster@{domain}"))) => {
                    (Status::Ok, "DMARC policy is enforced and aggregate reports are sent here.".into())
                }
                Some("reject" | "quarantine") => (Status::Warning, format!("DMARC is enforced, but aggregate reports are not sent to postmaster@{domain}.")),
                Some("none") => (Status::Warning, "DMARC policy is p=none: failures are reported but not acted on.".into()),
                _ => (Status::Error, "DMARC record has no valid policy (p=) tag.".into()),
            }
        }
        _ => (Status::Error, "Multiple DMARC records found.".into()),
    }
}

pub fn eval_tlsrpt(records: &[String], domain: &str) -> Eval {
    let tlsrpt: Vec<&String> = records.iter().filter(|record| record.to_ascii_lowercase().replace(' ', "").starts_with("v=tlsrptv1")).collect();
    match tlsrpt.as_slice() {
        [] => (Status::Warning, "No TLS reporting record: you will not hear when other servers fail to reach yours securely.".into()),
        [record] if tag_value(record, "rua").is_some_and(|value| has_report_address(value, &format!("mailto:postmaster@{domain}"))) => {
            (Status::Ok, "Other servers report TLS problems to this domain's postmaster.".into())
        }
        [_] => (Status::Warning, format!("The TLS reporting record does not send reports to postmaster@{domain}.")),
        _ => (Status::Error, "Multiple TLS reporting records found.".into()),
    }
}

fn recommended_spf(hostname: &str, ips: &[IpAddr]) -> String {
    if ips.is_empty() {
        return format!("v=spf1 a:{hostname} -all");
    }
    let mechanisms = ips
        .iter()
        .map(|ip| match ip {
            IpAddr::V4(ip) => format!("ip4:{ip}"),
            IpAddr::V6(ip) => format!("ip6:{ip}"),
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!("v=spf1 {mechanisms} -all")
}

pub fn eval_ptr(names: &[String], hostname: &str) -> Eval {
    if names.iter().any(|n| n.eq_ignore_ascii_case(hostname)) {
        (Status::Ok, "Reverse DNS matches the server hostname.".into())
    } else if names.is_empty() {
        (Status::Error, "No reverse DNS (PTR) record; many receivers reject mail from such addresses.".into())
    } else {
        (Status::Warning, format!("Reverse DNS does not match the server hostname {hostname}."))
    }
}

/// Whether an SRV record (`priority weight port target`) sends clients to `port` on `hostname`.
pub fn eval_srv(records: &[String], port: u16, hostname: &str) -> Eval {
    let points_here = |record: &String| {
        let parts: Vec<&str> = record.split_whitespace().collect();
        parts.len() == 4 && parts[2] == port.to_string() && parts[3].eq_ignore_ascii_case(hostname)
    };
    if records.is_empty() {
        (Status::Warning, "Optional: lets mail programs find this server on their own.".into())
    } else if records.iter().any(points_here) {
        (Status::Ok, "Mail programs find this server.".into())
    } else {
        (Status::Warning, format!("The record does not point to port {port} on {hostname}."))
    }
}

fn lookup_failed<T>(result: Result<Vec<T>, DnsError>) -> Result<Vec<T>, Eval> {
    match result {
        Ok(v) => Ok(v),
        Err(DnsError::NotFound) => Ok(Vec::new()),
        Err(DnsError::Temporary(e)) => Err((Status::Unknown, format!("DNS lookup failed: {e}"))),
    }
}

fn check(id: &str, title: &str, rtype: &str, name: String, value: String, eval: Eval, found: Vec<String>) -> Check {
    Check {
        id: id.into(),
        title: title.into(),
        status: eval.0,
        message: eval.1,
        record_type: rtype.into(),
        record_name: name,
        record_value: value,
        found,
    }
}

const NO_RESOLVER: &str = "Live DNS checks are unavailable.";

/// The records `domain` needs, each annotated with the result of a live lookup.
/// `3 1 1 <sha256 of the key>` for the server's current certificate.
async fn tlsa_value(app: &App) -> Option<String> {
    let pem: String = sqlx::query_scalar("SELECT cert_pem FROM certificates WHERE id = ?").bind(app.tls.info().id).fetch_optional(&app.db).await.ok().flatten()?;
    let block = x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes()).flatten().next()?;
    let certificate = block.parse_x509().ok()?;
    let digest = ring::digest::digest(&ring::digest::SHA256, certificate.public_key().raw);
    Some(format!("3 1 1 {}", digest.as_ref().iter().map(|b| format!("{b:02x}")).collect::<String>()))
}

pub async fn domain_report(app: &App, domain: &str, keys: &[DkimKey], mta_sts_mode: &str) -> Vec<Check> {
    let hostname = &app.cfg.hostname;
    let resolver = app.authenticator.as_ref();
    let unknown = || (Status::Unknown, NO_RESOLVER.to_owned());
    let mut checks = Vec::new();

    let (eval, found) = match resolver {
        Some(r) => match dns::mx(r, domain).await {
            Ok(hosts) => (eval_mx(&hosts, hostname), hosts.iter().map(|(p, h)| format!("{p} {h}")).collect()),
            Err(e) => ((Status::Unknown, format!("DNS lookup failed: {e}")), Vec::new()),
        },
        None => (unknown(), Vec::new()),
    };
    checks.push(check("mx", "MX record", "MX", domain.to_owned(), format!("10 {hostname}."), eval, found));

    let txt = |name: String| async move {
        match resolver {
            Some(r) => lookup_failed(dns::txt(r, &name).await),
            None => Err((Status::Unknown, NO_RESOLVER.to_owned())),
        }
    };

    let mut server_ips = match resolver {
        Some(r) => dns::ips(r, hostname).await.unwrap_or_default().into_iter().filter(|ip| !reputation::is_private(*ip)).collect::<Vec<_>>(),
        None => Vec::new(),
    };
    server_ips.sort_by_key(ToString::to_string);
    server_ips.dedup();

    let (eval, found) = match txt(domain.to_owned()).await {
        Ok(records) => (eval_spf(&records, &server_ips), records.into_iter().filter(|r| r.to_ascii_lowercase().starts_with("v=spf1")).collect()),
        Err(eval) => (eval, Vec::new()),
    };
    checks.push(check("spf", "SPF record", "TXT", domain.to_owned(), recommended_spf(hostname, &server_ips), eval, found));

    for key in keys.iter().filter(|k| k.active) {
        let name = key.dns_name(domain);
        let (eval, found) = match txt(name.clone()).await {
            Ok(records) => (eval_dkim(&records, &key.public_key), records),
            Err(eval) => (eval, Vec::new()),
        };
        checks.push(check(&format!("dkim:{}", key.selector), &format!("DKIM key ({})", key.selector), "TXT", name, key.dns_value(), eval, found));
    }
    if !keys.iter().any(|k| k.active) {
        checks.push(check(
            "dkim",
            "DKIM key",
            "TXT",
            format!("<selector>._domainkey.{domain}"),
            String::new(),
            (Status::Error, "No active DKIM key: outgoing mail for this domain is not signed.".into()),
            Vec::new(),
        ));
    }

    let dmarc_name = format!("_dmarc.{domain}");
    let (eval, found) = match txt(dmarc_name.clone()).await {
        Ok(records) => (eval_dmarc(&records, domain), records),
        Err(eval) => (eval, Vec::new()),
    };
    checks.push(check(
        "dmarc",
        "DMARC policy",
        "TXT",
        dmarc_name,
        format!("v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}"),
        eval,
        found,
    ));

    // MTA-STS: the record announcing the policy, the host serving it, and its certificate.
    if let Some(policy) = crate::smtp::transport::policy_for_hosted(mta_sts_mode, hostname) {
        let id = crate::smtp::transport::policy_id(&policy);
        let name = format!("_mta-sts.{domain}");
        let (eval, found) = match txt(name.clone()).await {
            Ok(records) => {
                let ours: Vec<String> = records.into_iter().filter(|r| r.to_ascii_lowercase().replace(' ', "").starts_with("v=stsv1")).collect();
                let eval = if ours.iter().any(|r| r.replace(' ', "").contains(&format!("id={id}"))) {
                    (Status::Ok, format!("The {mta_sts_mode} policy is announced."))
                } else if ours.is_empty() {
                    (Status::Error, "No MTA-STS record: senders do not know about the policy.".into())
                } else {
                    (Status::Warning, "The record has another id: senders keep using the policy they saw before. Publish the new id.".into())
                };
                (eval, ours)
            }
            Err(eval) => (eval, Vec::new()),
        };
        checks.push(check("mta-sts", "MTA-STS record", "TXT", name, format!("v=STSv1; id={id}"), eval, found));
        let policy_host = format!("mta-sts.{domain}");
        let (eval, found) = match resolver {
            Some(r) => match (dns::ips(r, &policy_host).await, dns::ips(r, hostname).await) {
                (Ok(theirs), Ok(ours)) if theirs.iter().any(|ip| ours.contains(ip)) => {
                    let covered = app.tls.info().domains.iter().any(|d| crate::tls::san_matches(d, &policy_host));
                    if covered {
                        ((Status::Ok, "The policy is served by this server.".into()), theirs.iter().map(ToString::to_string).collect())
                    } else {
                        ((Status::Error, format!("The certificate does not cover {policy_host}: add the name in Certificates, or senders cannot read the policy.")), theirs.iter().map(ToString::to_string).collect())
                    }
                }
                (Ok(theirs), _) if !theirs.is_empty() => ((Status::Error, format!("{policy_host} points elsewhere; the policy is served by {hostname}.")), theirs.iter().map(ToString::to_string).collect()),
                _ => ((Status::Error, format!("{policy_host} does not resolve.")), Vec::new()),
            },
            None => (unknown(), Vec::new()),
        };
        checks.push(check("mta-sts-host", "MTA-STS policy host", "CNAME", policy_host, format!("{hostname}."), eval, found));
    }
    let tlsrpt_name = format!("_smtp._tls.{domain}");
    let (eval, found) = match txt(tlsrpt_name.clone()).await {
        Ok(records) => {
            let ours: Vec<String> = records.into_iter().filter(|r| r.to_ascii_lowercase().replace(' ', "").starts_with("v=tlsrptv1")).collect();
            let eval = eval_tlsrpt(&ours, domain);
            (eval, ours)
        }
        Err(eval) => (eval, Vec::new()),
    };
    checks.push(check("tls-rpt", "TLS reporting (TLS-RPT)", "TXT", tlsrpt_name, format!("v=TLSRPTv1; rua=mailto:postmaster@{domain}"), eval, found));

    // DANE: a TLSA record for the server's certificate key, for senders that check it.
    if let Some(value) = tlsa_value(app).await {
        let name = format!("_25._tcp.{hostname}");
        let (eval, found) = match resolver {
            Some(r) => match lookup_failed(dns::tlsa(r, &name).await) {
                Ok(records) if records.iter().any(|record| record.eq_ignore_ascii_case(&value)) => ((Status::Ok, "DANE is published for the current key. Keep the key when renewing the certificate, or update the record first.".into()), records),
                Ok(records) if !records.is_empty() => ((Status::Error, "The TLSA record does not match the current certificate: DANE senders will refuse to deliver.".into()), records),
                Ok(_) => ((Status::Warning, "Optional: with DNSSEC on the zone, a TLSA record lets senders verify this server (DANE).".into()), Vec::new()),
                Err(eval) => (eval, Vec::new()),
            },
            None => (unknown(), Vec::new()),
        };
        checks.push(check("dane", "DANE (TLSA)", "TLSA", name, value, eval, found));
    }

    // Reverse DNS of the address our hostname resolves to.
    let (eval, found) = match resolver {
        Some(r) => match dns::ips(r, hostname).await {
            Ok(ips) if !ips.is_empty() => match lookup_failed(dns::ptr(r, ips[0]).await) {
                Ok(names) => (eval_ptr(&names, hostname), names),
                Err(eval) => (eval, Vec::new()),
            },
            Ok(_) | Err(DnsError::NotFound) => ((Status::Error, format!("{hostname} does not resolve to an address.")), Vec::new()),
            Err(e) => ((Status::Unknown, format!("DNS lookup failed: {e}")), Vec::new()),
        },
        None => (unknown(), Vec::new()),
    };
    checks.push(check("ptr", "Reverse DNS (PTR)", "PTR", "<server IP address>".into(), format!("{hostname}."), eval, found));

    // Certificate presented on the mail and web ports.
    let cert = app.tls.info();
    let covers = cert.domains.iter().any(|d| crate::tls::san_matches(d, hostname));
    let eval = match (cert.kind, covers, cert.seconds_remaining()) {
        (crate::tls::CertKind::SelfSigned, _, _) => (Status::Warning, "The server uses a self-signed certificate.".into()),
        (_, false, _) => (Status::Error, format!("The certificate is not valid for {hostname}.")),
        (_, _, remaining) if remaining < crate::tls::RENEW_BEFORE_SECS => {
            (Status::Warning, format!("The certificate expires in {} days.", remaining / 86400))
        }
        _ => (Status::Ok, "A valid certificate is installed.".into()),
    };
    checks.push(check("tls", "TLS certificate", "", String::new(), String::new(), eval, cert.domains.clone()));

    // Optional client auto-configuration (Outlook, Apple Mail, Thunderbird).
    for prefix in ["autoconfig", "autodiscover"] {
        let name = format!("{prefix}.{domain}");
        let (eval, found) = match resolver {
            Some(r) => match (lookup_failed(dns::ips(r, &name).await), dns::ips(r, hostname).await) {
                (Ok(theirs), Ok(ours)) if theirs.iter().any(|ip| ours.contains(ip)) => ((Status::Ok, "Mail programs find their settings here.".into()), theirs.iter().map(ToString::to_string).collect()),
                (Ok(theirs), _) if !theirs.is_empty() => ((Status::Warning, format!("{name} points elsewhere; the settings are served by {hostname}.")), theirs.iter().map(ToString::to_string).collect()),
                (Ok(_), _) => ((Status::Warning, "Optional: lets mail programs set themselves up from the address alone.".into()), Vec::new()),
                (Err(eval), _) => (eval, Vec::new()),
            },
            None => (unknown(), Vec::new()),
        };
        checks.push(check(prefix, &format!("Client autoconfiguration ({prefix})"), "CNAME", name, format!("{hostname}."), eval, found));
    }
    for (service, priority, port) in [("submission", 0, 587), ("imaps", 0, 993), ("pop3s", 10, 995)] {
        let name = format!("_{service}._tcp.{domain}");
        let (eval, found) = match resolver {
            Some(r) => match lookup_failed(dns::srv(r, &name).await) {
                Ok(records) => (eval_srv(&records, port, hostname), records),
                Err(eval) => (eval, Vec::new()),
            },
            None => (unknown(), Vec::new()),
        };
        checks.push(check(&format!("srv:{service}"), &format!("Client autoconfiguration ({service})"), "SRV", name, format!("{priority} 1 {port} {hostname}."), eval, found));
    }

    checks
}

#[derive(Debug, Serialize)]
pub struct PortCheck {
    pub name: &'static str,
    pub port: u16,
    pub listening: bool,
}

#[derive(Debug, Serialize)]
pub struct ServerReport {
    pub hostname: String,
    pub ports: Vec<PortCheck>,
    pub public_addresses: Vec<String>,
    /// Blocklists that currently list one of the server's public addresses.
    pub blocklisted: Vec<String>,
    pub blocklists_checked: Vec<String>,
    pub outbound_port_25: Status,
    pub outbound_message: String,
    pub rspamd: Status,
    /// Whether incoming mail is scanned for malware.
    pub virus_scanner: Status,
    pub virus_message: String,
    /// 0-100 summary of the checks above.
    pub score: u8,
}

async fn port_open(addr: SocketAddr) -> bool {
    matches!(tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(addr)).await, Ok(Ok(_)))
}

/// Connectivity tests for the server itself: listening ports, blocklist status of its public
/// addresses, and whether outbound port 25 is usable (many hosting providers block it).
pub async fn server_report(app: &App, bound: &[(&'static str, SocketAddr)]) -> ServerReport {
    let mut ports = Vec::new();
    for (name, addr) in bound {
        let target = if addr.ip().is_unspecified() { SocketAddr::new([127, 0, 0, 1].into(), addr.port()) } else { *addr };
        ports.push(PortCheck { name, port: addr.port(), listening: port_open(target).await });
    }

    let mut public_addresses = Vec::new();
    let mut blocklisted = Vec::new();
    let (mut outbound, mut outbound_message) = (Status::Unknown, NO_RESOLVER.to_owned());
    if let Some(resolver) = &app.authenticator {
        if let Ok(ips) = dns::ips(resolver, &app.cfg.hostname).await {
            for ip in ips {
                public_addresses.push(ip.to_string());
                blocklisted.extend(reputation::dnsbl_listings(app, ip).await);
            }
        }
        // A well-known, highly available MX is used as the reachability probe.
        (outbound, outbound_message) = match dns::mx(resolver, "gmail.com").await {
            Ok(hosts) if !hosts.is_empty() => match dns::ips(resolver, &hosts[0].1).await {
                Ok(ips) if !ips.is_empty() => {
                    if port_open(SocketAddr::new(ips[0], 25)).await {
                        (Status::Ok, "Outbound connections on port 25 work.".into())
                    } else {
                        (Status::Error, "Outbound port 25 appears to be blocked; configure a relay host.".into())
                    }
                }
                _ => (Status::Unknown, "Could not resolve the probe host.".into()),
            },
            _ => (Status::Unknown, "Could not resolve the probe host.".into()),
        };
    }
    if app.rt().route().is_some() {
        (outbound, outbound_message) = (Status::Ok, "Outbound mail is sent through the configured default route.".into());
    }
    blocklisted.sort();
    blocklisted.dedup();

    let rspamd = match &app.cfg.rspamd_url {
        Some(url) => match app.filter_http.get(format!("{}/ping", url.trim_end_matches('/'))).send().await {
            Ok(resp) if resp.status().is_success() => Status::Ok,
            _ => Status::Error,
        },
        None => Status::Warning,
    };

    // Rspamd scans attachments only when its antivirus module is set up, which cannot be
    // seen from here; ClamAV configured directly can be asked.
    let (virus_scanner, virus_message) = match &app.cfg.clamav_addr {
        Some(addr) if crate::security::clamav::ping(addr).await => (Status::Ok, "ClamAV is reachable; incoming mail is scanned for malware.".to_owned()),
        Some(_) => (Status::Error, "ClamAV is configured but does not answer; incoming mail is deferred until it returns.".to_owned()),
        None if rspamd == Status::Ok => {
            (Status::Unknown, "No ClamAV address is configured. Mail is scanned only if Rspamd's antivirus module is set up; set UNOMAIL_CLAMAV_ADDR to be sure.".to_owned())
        }
        None => (Status::Warning, "Incoming mail is not scanned for malware. Programs are refused by name, but infected documents get through; set UNOMAIL_CLAMAV_ADDR.".to_owned()),
    };

    let mut score: i32 = 100;
    score -= 15 * ports.iter().filter(|p| !p.listening).count() as i32;
    score -= 30 * blocklisted.len().min(2) as i32;
    if outbound == Status::Error {
        score -= 30;
    }
    if rspamd != Status::Ok {
        score -= 10;
    }
    if app.tls.info().kind == crate::tls::CertKind::SelfSigned {
        score -= 15;
    }
    ServerReport {
        hostname: app.cfg.hostname.clone(),
        ports,
        public_addresses,
        blocklisted,
        blocklists_checked: app.rt().dnsbl_zones.clone(),
        outbound_port_25: outbound,
        outbound_message,
        rspamd,
        virus_scanner,
        virus_message,
        score: score.clamp(0, 100) as u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn srv() {
        let host = "mail.example.com";
        assert_eq!(eval_srv(&[], 993, host).0, Status::Warning);
        assert_eq!(eval_srv(&s(&["0 1 993 mail.example.com"]), 993, host).0, Status::Ok);
        assert_eq!(eval_srv(&s(&["0 1 143 mail.example.com"]), 993, host).0, Status::Warning);
        assert_eq!(eval_srv(&s(&["0 1 993 other.example.net"]), 993, host).0, Status::Warning);
    }

    #[test]
    fn mx() {
        assert_eq!(eval_mx(&[], "mail.example.com").0, Status::Error);
        assert_eq!(eval_mx(&[(10, "MAIL.example.com".into())], "mail.example.com").0, Status::Ok);
        assert_eq!(eval_mx(&[(10, "other.example.net".into())], "mail.example.com").0, Status::Error);
    }

    #[test]
    fn spf() {
        let ips = ["203.0.113.10".parse().unwrap(), "2001:db8::10".parse().unwrap()];
        assert_eq!(eval_spf(&s(&["v=spf1 ip4:203.0.113.10 ip6:2001:db8::10 -all"]), &ips).0, Status::Ok);
        assert_eq!(eval_spf(&s(&["v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/64 -all"]), &ips).0, Status::Ok);
        assert_eq!(eval_spf(&s(&["v=spf1 mx -all"]), &ips).0, Status::Error);
        assert_eq!(eval_spf(&s(&["v=spf1 include:sender.example -all"]), &ips).0, Status::Error);
        assert_eq!(eval_spf(&s(&["v=spf1 ip4:203.0.113.10 +all"]), &ips).0, Status::Error);
        assert_eq!(eval_spf(&s(&["v=spf1 ip4:203.0.113.10 ip6:2001:db8::10 ?all"]), &ips).0, Status::Warning);
        assert_eq!(eval_spf(&s(&["v=spf1 ip4:203.0.113.10 ip6:2001:db8::10"]), &ips).0, Status::Warning);
        assert_eq!(eval_spf(&s(&["v=spf1 ip4:203.0.113.10 -all", "v=spf1 -all"]), &ips).0, Status::Error);
        assert_eq!(eval_spf(&s(&["google-site-verification=x"]), &ips).0, Status::Error);
        assert_eq!(recommended_spf("mail.example.com", &ips), "v=spf1 ip4:203.0.113.10 ip6:2001:db8::10 -all");
        assert_eq!(recommended_spf("mail.example.com", &[]), "v=spf1 a:mail.example.com -all");
    }

    #[test]
    fn dkim() {
        assert_eq!(eval_dkim(&s(&["v=DKIM1; k=rsa; p=ABC DEF"]), "ABCDEF").0, Status::Ok);
        assert_eq!(eval_dkim(&s(&["v=DKIM1; k=rsa; p=OTHER"]), "ABCDEF").0, Status::Error);
        assert_eq!(eval_dkim(&s(&["v=DKIM1; p="]), "ABCDEF").0, Status::Error);
        assert_eq!(eval_dkim(&[], "ABCDEF").0, Status::Error);
    }

    #[test]
    fn dmarc() {
        let domain = "example.com";
        assert_eq!(eval_dmarc(&s(&["v=DMARC1; p=reject; rua=mailto:postmaster@example.com"]), domain).0, Status::Ok);
        assert_eq!(eval_dmarc(&s(&["v=DMARC1;p=quarantine"]), domain).0, Status::Warning);
        assert_eq!(eval_dmarc(&s(&["v=DMARC1; p=none"]), domain).0, Status::Warning);
        // sp= must not be mistaken for p=.
        assert_eq!(eval_dmarc(&s(&["v=DMARC1; sp=reject"]), domain).0, Status::Error);
        assert_eq!(eval_dmarc(&[], domain).0, Status::Error);
        assert_eq!(eval_dmarc(&s(&["v=DMARC1; p=none", "v=DMARC1; p=reject"]), domain).0, Status::Error);
    }

    #[test]
    fn tls_reporting() {
        let domain = "example.com";
        assert_eq!(eval_tlsrpt(&s(&["v=TLSRPTv1; rua=mailto:postmaster@example.com"]), domain).0, Status::Ok);
        assert_eq!(eval_tlsrpt(&s(&["v=TLSRPTv1; rua=mailto:elsewhere@example.net"]), domain).0, Status::Warning);
        assert_eq!(eval_tlsrpt(&s(&["v=TLSRPTv1"]), domain).0, Status::Warning);
        assert_eq!(eval_tlsrpt(&s(&["v=TLSRPTv1", "v=TLSRPTv1; rua=mailto:postmaster@example.com"]), domain).0, Status::Error);
    }

    #[test]
    fn ptr() {
        assert_eq!(eval_ptr(&s(&["mail.example.com"]), "mail.example.com").0, Status::Ok);
        assert_eq!(eval_ptr(&s(&["host-1-2-3-4.isp.example"]), "mail.example.com").0, Status::Warning);
        assert_eq!(eval_ptr(&[], "mail.example.com").0, Status::Error);
    }
}
