//! DNS and server health diagnostics: which records a domain needs and whether they are live.

use std::{
    net::{IpAddr, SocketAddr},
    sync::LazyLock,
    time::Duration,
};

use mail_auth::{MessageAuthenticator, SpfResult, spf::verify::SpfParameters};
use serde::{Serialize, Serializer, ser::SerializeStruct};

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

/// A text for the administrator: English with `{{name}}` placeholders, and their values.
///
/// The web client translates it with the English text as the key, so the values must stay out
/// of the key. Every key is listed in `web/src/admin/serverTexts.ts` (checked by a test below).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Text {
    pub key: &'static str,
    pub params: Vec<(&'static str, String)>,
}

/// `text!("Reverse DNS does not match the server hostname {{hostname}}.", hostname = name)`
macro_rules! text {
    ($key:literal $(, $name:ident = $value:expr)* $(,)?) => {
        Text { key: $key, params: vec![$((stringify!($name), $value.to_string())),*] }
    };
}

impl Text {
    /// The English text with the values filled in.
    pub fn render(&self) -> String {
        self.params.iter().fold(self.key.to_owned(), |text, (name, value)| text.replace(&format!("{{{{{name}}}}}"), value))
    }

    fn params_map(&self) -> std::collections::BTreeMap<&'static str, &str> {
        self.params.iter().map(|(name, value)| (*name, value.as_str())).collect()
    }
}

/// Fields that hold no values (`outbound_message`) are sent as the English text, which is also
/// the translation key.
impl Serialize for Text {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.render())
    }
}

#[derive(Debug, Clone)]
pub struct Check {
    pub id: String,
    pub title: Text,
    pub status: Status,
    pub message: Text,
    /// The DNS record the administrator should publish.
    pub record_type: String,
    pub record_name: String,
    pub record_value: String,
    pub found: Vec<String>,
}

/// `title` and `message` are the English texts; `*_key` and `*_params` let the client translate them.
impl Serialize for Check {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct("Check", 12)?;
        out.serialize_field("id", &self.id)?;
        out.serialize_field("title", &self.title.render())?;
        out.serialize_field("title_key", self.title.key)?;
        out.serialize_field("title_params", &self.title.params_map())?;
        out.serialize_field("status", &self.status)?;
        out.serialize_field("message", &self.message.render())?;
        out.serialize_field("message_key", self.message.key)?;
        out.serialize_field("message_params", &self.message.params_map())?;
        out.serialize_field("record_type", &self.record_type)?;
        out.serialize_field("record_name", &self.record_name)?;
        out.serialize_field("record_value", &self.record_value)?;
        out.serialize_field("found", &self.found)?;
        out.end()
    }
}

type Eval = (Status, Text);

pub fn eval_mx(hosts: &[(u16, String)], hostname: &str) -> Eval {
    if hosts.is_empty() {
        return (Status::Error, text!("No MX record found; other servers cannot deliver mail to this domain."));
    }
    if hosts.iter().any(|(_, h)| h.eq_ignore_ascii_case(hostname)) {
        (Status::Ok, text!("MX points to this server."))
    } else {
        (Status::Error, text!("MX records do not include {{hostname}}.", hostname = hostname))
    }
}

/// Judges the domain's SPF record. `verdicts` holds, for each public address of this server,
/// what SPF evaluation (with every `a`, `mx`, `include` and `redirect` followed) says about it.
pub fn eval_spf(records: &[String], verdicts: &[(IpAddr, SpfResult)]) -> Eval {
    let spf: Vec<&String> = records.iter().filter(|r| r.to_ascii_lowercase().starts_with("v=spf1")).collect();
    match spf.as_slice() {
        [] => (Status::Error, text!("No SPF record found.")),
        [record] => {
            let lower = record.to_ascii_lowercase();
            let terms: Vec<&str> = lower.split_whitespace().collect();
            if terms.iter().any(|t| matches!(*t, "+all" | "all")) {
                return (Status::Error, text!("SPF record ends in +all, which authorizes every server on the internet."));
            }
            if verdicts.is_empty() {
                return (Status::Warning, text!("The server's public IP address could not be determined, so this SPF record cannot be verified."));
            }
            if verdicts.iter().any(|(_, result)| *result == SpfResult::PermError) {
                return (Status::Error, text!("SPF record is invalid or needs more than 10 DNS lookups, so receivers treat it as a permanent error."));
            }
            if let Some((ip, _)) = verdicts.iter().find(|(_, result)| *result == SpfResult::TempError) {
                return (Status::Unknown, text!("SPF for {{ip}} could not be evaluated because a DNS lookup failed.", ip = ip));
            }
            if let Some((ip, _)) = verdicts.iter().find(|(_, result)| *result != SpfResult::Pass) {
                return (Status::Error, text!("SPF record does not authorize this server's IP address {{ip}}.", ip = ip));
            }
            if terms.contains(&"?all") {
                (Status::Warning, text!("SPF record uses ?all (neutral); use ~all or -all."))
            } else if !terms.contains(&"-all") {
                (Status::Warning, text!("SPF record does not end in -all, so other servers are not explicitly forbidden."))
            } else {
                (Status::Ok, text!("SPF record authorizes this server's IP addresses and rejects all others."))
            }
        }
        _ => (Status::Error, text!("Multiple SPF records found; receivers treat this as a permanent error.")),
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
        return (Status::Error, text!("DKIM record not found."));
    };
    let published = normalize(record);
    let key = published.split(';').find_map(|tag| tag.strip_prefix("p=")).unwrap_or("");
    if key == normalize(expected_public_key) {
        (Status::Ok, text!("DKIM public key is published."))
    } else if key.is_empty() {
        (Status::Error, text!("DKIM record is published with an empty key (revoked)."))
    } else {
        (Status::Error, text!("Published DKIM key does not match the key used for signing."))
    }
}

pub fn eval_dmarc(records: &[String], domain: &str) -> Eval {
    let dmarc: Vec<&String> = records.iter().filter(|r| r.to_ascii_lowercase().starts_with("v=dmarc1")).collect();
    match dmarc.as_slice() {
        [] => (Status::Error, text!("No DMARC record found.")),
        [record] => {
            let policy = tag_value(record, "p").map(str::to_ascii_lowercase);
            match policy.as_deref() {
                Some("reject" | "quarantine") if tag_value(record, "rua").is_some_and(|value| has_report_address(value, &format!("mailto:postmaster@{domain}"))) => {
                    (Status::Ok, text!("DMARC policy is enforced and aggregate reports are sent here."))
                }
                Some("reject" | "quarantine") => (Status::Warning, text!("DMARC is enforced, but aggregate reports are not sent to postmaster@{{domain}}.", domain = domain)),
                Some("none") => (Status::Warning, text!("DMARC policy is p=none: failures are reported but not acted on.")),
                _ => (Status::Error, text!("DMARC record has no valid policy (p=) tag.")),
            }
        }
        _ => (Status::Error, text!("Multiple DMARC records found.")),
    }
}

pub fn eval_tlsrpt(records: &[String], domain: &str) -> Eval {
    let tlsrpt: Vec<&String> = records.iter().filter(|record| record.to_ascii_lowercase().replace(' ', "").starts_with("v=tlsrptv1")).collect();
    match tlsrpt.as_slice() {
        [] => (Status::Warning, text!("No TLS reporting record: you will not hear when other servers fail to reach yours securely.")),
        [record] if tag_value(record, "rua").is_some_and(|value| has_report_address(value, &format!("mailto:postmaster@{domain}"))) => {
            (Status::Ok, text!("Other servers report TLS problems to this domain's postmaster."))
        }
        [_] => (Status::Warning, text!("The TLS reporting record does not send reports to postmaster@{{domain}}.", domain = domain)),
        _ => (Status::Error, text!("Multiple TLS reporting records found.")),
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
        (Status::Ok, text!("Reverse DNS matches the server hostname."))
    } else if names.is_empty() {
        (Status::Error, text!("No reverse DNS (PTR) record; many receivers reject mail from such addresses."))
    } else {
        (Status::Warning, text!("Reverse DNS does not match the server hostname {{hostname}}.", hostname = hostname))
    }
}

/// Whether an SRV record (`priority weight port target`) sends clients to `port` on `hostname`.
pub fn eval_srv(records: &[String], port: u16, hostname: &str) -> Eval {
    let points_here = |record: &String| {
        let parts: Vec<&str> = record.split_whitespace().collect();
        parts.len() == 4 && parts[2] == port.to_string() && parts[3].eq_ignore_ascii_case(hostname)
    };
    if records.is_empty() {
        (Status::Warning, text!("Optional: lets mail programs find this server on their own."))
    } else if records.iter().any(points_here) {
        (Status::Ok, text!("Mail programs find this server."))
    } else {
        (Status::Warning, text!("The record does not point to port {{port}} on {{hostname}}.", port = port, hostname = hostname))
    }
}

fn lookup_error(error: impl std::fmt::Display) -> Eval {
    (Status::Unknown, text!("DNS lookup failed: {{error}}", error = error))
}

fn lookup_failed<T>(result: Result<Vec<T>, DnsError>) -> Result<Vec<T>, Eval> {
    match result {
        Ok(v) => Ok(v),
        Err(DnsError::NotFound) => Ok(Vec::new()),
        Err(DnsError::Temporary(e)) => Err(lookup_error(e)),
    }
}

fn only_public(mut ips: Vec<IpAddr>) -> Vec<IpAddr> {
    ips.retain(|ip| !reputation::is_private(*ip));
    ips.sort_by_key(ToString::to_string);
    ips.dedup();
    ips
}

/// Resolvers that see the internet's view of DNS. Inside a container the system resolver may
/// answer the server's own hostname from `/etc/hosts` with a bridge address, and an SPF `a:`
/// mechanism naming the server would then resolve to that too. DNS over TLS comes first; plain
/// DNS to the same service helps where port 853 is blocked.
static PUBLIC_RESOLVERS: LazyLock<Vec<MessageAuthenticator>> = LazyLock::new(|| {
    [MessageAuthenticator::new_cloudflare_tls(), MessageAuthenticator::new_cloudflare()]
        .into_iter()
        .filter_map(|resolver| resolver.inspect_err(|err| tracing::debug!(%err, "public DNS resolver unavailable")).ok())
        .collect()
});

/// The server's public addresses (IPv4 and IPv6), and the resolver that found them, to be used
/// for checks that must see the same public view.
async fn public_host_ips<'a>(resolver: Option<&'a MessageAuthenticator>, hostname: &str) -> (Vec<IpAddr>, Option<&'a MessageAuthenticator>) {
    let Some(system) = resolver else { return (Vec::new(), None) };
    for public in PUBLIC_RESOLVERS.iter() {
        match dns::all_ips(public, hostname).await {
            Ok(ips) if !only_public(ips.clone()).is_empty() => return (only_public(ips), Some(public)),
            Ok(ips) => tracing::info!(hostname, ?ips, "public DNS has no public address for the server hostname"),
            Err(err) => tracing::info!(hostname, ?err, "public DNS lookup of the server hostname failed"),
        }
    }
    let ips = only_public(dns::all_ips(system, hostname).await.unwrap_or_default());
    if ips.is_empty() {
        tracing::warn!(hostname, "the server's public IP address could not be determined: the hostname resolves to no public address");
    }
    (ips, Some(system))
}

/// What SPF says about mail from `domain` sent by each of `ips`.
async fn spf_verdicts(resolver: &MessageAuthenticator, hostname: &str, domain: &str, ips: &[IpAddr]) -> Vec<(IpAddr, SpfResult)> {
    let sender = format!("postmaster@{domain}");
    let mut verdicts = Vec::with_capacity(ips.len());
    for ip in ips {
        let output = resolver.verify_spf(SpfParameters::verify_mail_from(*ip, hostname, hostname, &sender)).await;
        verdicts.push((*ip, output.result()));
    }
    verdicts
}

fn check(id: &str, title: Text, rtype: &str, name: String, value: String, eval: Eval, found: Vec<String>) -> Check {
    Check {
        id: id.into(),
        title,
        status: eval.0,
        message: eval.1,
        record_type: rtype.into(),
        record_name: name,
        record_value: value,
        found,
    }
}

fn no_resolver() -> Text {
    text!("Live DNS checks are unavailable.")
}

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
    let unknown = || (Status::Unknown, no_resolver());
    let mut checks = Vec::new();

    let (eval, found) = match resolver {
        Some(r) => match dns::mx(r, domain).await {
            Ok(hosts) => (eval_mx(&hosts, hostname), hosts.iter().map(|(p, h)| format!("{p} {h}")).collect()),
            Err(e) => (lookup_error(e), Vec::new()),
        },
        None => (unknown(), Vec::new()),
    };
    checks.push(check("mx", text!("MX record"), "MX", domain.to_owned(), format!("10 {hostname}."), eval, found));

    let txt = |name: String| async move {
        match resolver {
            Some(r) => lookup_failed(dns::txt(r, &name).await),
            None => Err((Status::Unknown, no_resolver())),
        }
    };

    let (server_ips, public) = public_host_ips(resolver, hostname).await;

    let (eval, found) = match txt(domain.to_owned()).await {
        Ok(records) => {
            let verdicts = match public {
                Some(public) => spf_verdicts(public, hostname, domain, &server_ips).await,
                None => Vec::new(),
            };
            (eval_spf(&records, &verdicts), records.into_iter().filter(|r| r.to_ascii_lowercase().starts_with("v=spf1")).collect())
        }
        Err(eval) => (eval, Vec::new()),
    };
    checks.push(check("spf", text!("SPF record"), "TXT", domain.to_owned(), recommended_spf(hostname, &server_ips), eval, found));

    for key in keys.iter().filter(|k| k.active) {
        let name = key.dns_name(domain);
        let (eval, found) = match txt(name.clone()).await {
            Ok(records) => (eval_dkim(&records, &key.public_key), records),
            Err(eval) => (eval, Vec::new()),
        };
        checks.push(check(&format!("dkim:{}", key.selector), text!("DKIM key ({{selector}})", selector = key.selector), "TXT", name, key.dns_value(), eval, found));
    }
    if !keys.iter().any(|k| k.active) {
        checks.push(check(
            "dkim",
            text!("DKIM key"),
            "TXT",
            format!("<selector>._domainkey.{domain}"),
            String::new(),
            (Status::Error, text!("No active DKIM key: outgoing mail for this domain is not signed.")),
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
        text!("DMARC policy"),
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
                    (Status::Ok, text!("The {{mode}} policy is announced.", mode = mta_sts_mode))
                } else if ours.is_empty() {
                    (Status::Error, text!("No MTA-STS record: senders do not know about the policy."))
                } else {
                    (Status::Warning, text!("The record has another id: senders keep using the policy they saw before. Publish the new id."))
                };
                (eval, ours)
            }
            Err(eval) => (eval, Vec::new()),
        };
        checks.push(check("mta-sts", text!("MTA-STS record"), "TXT", name, format!("v=STSv1; id={id}"), eval, found));
        let policy_host = format!("mta-sts.{domain}");
        let (eval, found) = match resolver {
            Some(r) => match (dns::ips(r, &policy_host).await, dns::ips(r, hostname).await) {
                (Ok(theirs), Ok(ours)) if theirs.iter().any(|ip| ours.contains(ip)) => {
                    let covered = app.tls.info().domains.iter().any(|d| crate::tls::san_matches(d, &policy_host));
                    if covered {
                        ((Status::Ok, text!("The policy is served by this server.")), theirs.iter().map(ToString::to_string).collect())
                    } else {
                        ((Status::Error, text!("The certificate does not cover {{host}}: add the name in Certificates, or senders cannot read the policy.", host = policy_host)), theirs.iter().map(ToString::to_string).collect())
                    }
                }
                (Ok(theirs), _) if !theirs.is_empty() => ((Status::Error, text!("{{host}} points elsewhere; the policy is served by {{hostname}}.", host = policy_host, hostname = hostname)), theirs.iter().map(ToString::to_string).collect()),
                _ => ((Status::Error, text!("{{host}} does not resolve.", host = policy_host)), Vec::new()),
            },
            None => (unknown(), Vec::new()),
        };
        checks.push(check("mta-sts-host", text!("MTA-STS policy host"), "CNAME", policy_host, format!("{hostname}."), eval, found));
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
    checks.push(check("tls-rpt", text!("TLS reporting (TLS-RPT)"), "TXT", tlsrpt_name, format!("v=TLSRPTv1; rua=mailto:postmaster@{domain}"), eval, found));

    // DANE: a TLSA record for the server's certificate key, for senders that check it.
    if let Some(value) = tlsa_value(app).await {
        let name = format!("_25._tcp.{hostname}");
        let (eval, found) = match resolver {
            Some(r) => match lookup_failed(dns::tlsa(r, &name).await) {
                Ok(records) if records.iter().any(|record| record.eq_ignore_ascii_case(&value)) => ((Status::Ok, text!("DANE is published for the current key. Keep the key when renewing the certificate, or update the record first.")), records),
                Ok(records) if !records.is_empty() => ((Status::Error, text!("The TLSA record does not match the current certificate: DANE senders will refuse to deliver.")), records),
                Ok(_) => ((Status::Warning, text!("Optional: with DNSSEC on the zone, a TLSA record lets senders verify this server (DANE).")), Vec::new()),
                Err(eval) => (eval, Vec::new()),
            },
            None => (unknown(), Vec::new()),
        };
        checks.push(check("dane", text!("DANE (TLSA)"), "TLSA", name, value, eval, found));
    }

    // Reverse DNS of the server's public address (the one other servers see it connect from).
    let (eval, found) = match resolver {
        Some(r) => match server_ips.first() {
            Some(ip) => match lookup_failed(dns::ptr(r, *ip).await) {
                Ok(names) => (eval_ptr(&names, hostname), names),
                Err(eval) => (eval, Vec::new()),
            },
            None => match dns::ips(r, hostname).await {
                Ok(ips) if !ips.is_empty() => match lookup_failed(dns::ptr(r, ips[0]).await) {
                    Ok(names) => (eval_ptr(&names, hostname), names),
                    Err(eval) => (eval, Vec::new()),
                },
                Ok(_) | Err(DnsError::NotFound) => ((Status::Error, text!("{{hostname}} does not resolve to an address.", hostname = hostname)), Vec::new()),
                Err(e) => (lookup_error(e), Vec::new()),
            },
        },
        None => (unknown(), Vec::new()),
    };
    checks.push(check("ptr", text!("Reverse DNS (PTR)"), "PTR", "<server IP address>".into(), format!("{hostname}."), eval, found));

    // Certificate presented on the mail and web ports.
    let cert = app.tls.info();
    let covers = cert.domains.iter().any(|d| crate::tls::san_matches(d, hostname));
    let eval = match (cert.kind, covers, cert.seconds_remaining()) {
        (crate::tls::CertKind::SelfSigned, _, _) => (Status::Warning, text!("The server uses a self-signed certificate.")),
        (_, false, _) => (Status::Error, text!("The certificate is not valid for {{hostname}}.", hostname = hostname)),
        (_, _, remaining) if remaining < crate::tls::RENEW_BEFORE_SECS => {
            (Status::Warning, text!("The certificate expires in {{count}} days.", count = remaining / 86400))
        }
        _ => (Status::Ok, text!("A valid certificate is installed.")),
    };
    checks.push(check("tls", text!("TLS certificate"), "", String::new(), String::new(), eval, cert.domains.clone()));

    // Optional client auto-configuration (Outlook, Apple Mail, Thunderbird).
    for prefix in ["autoconfig", "autodiscover"] {
        let name = format!("{prefix}.{domain}");
        let (eval, found) = match resolver {
            Some(r) => match (lookup_failed(dns::ips(r, &name).await), dns::ips(r, hostname).await) {
                (Ok(theirs), Ok(ours)) if theirs.iter().any(|ip| ours.contains(ip)) => ((Status::Ok, text!("Mail programs find their settings here.")), theirs.iter().map(ToString::to_string).collect()),
                (Ok(theirs), _) if !theirs.is_empty() => ((Status::Warning, text!("{{host}} points elsewhere; the settings are served by {{hostname}}.", host = name, hostname = hostname)), theirs.iter().map(ToString::to_string).collect()),
                (Ok(_), _) => ((Status::Warning, text!("Optional: lets mail programs set themselves up from the address alone.")), Vec::new()),
                (Err(eval), _) => (eval, Vec::new()),
            },
            None => (unknown(), Vec::new()),
        };
        checks.push(check(prefix, text!("Client autoconfiguration ({{service}})", service = prefix), "CNAME", name, format!("{hostname}."), eval, found));
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
        checks.push(check(&format!("srv:{service}"), text!("Client autoconfiguration ({{service}})", service = service), "SRV", name, format!("{priority} 1 {port} {hostname}."), eval, found));
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
    pub outbound_message: Text,
    pub rspamd: Status,
    /// Whether incoming mail is scanned for malware.
    pub virus_scanner: Status,
    pub virus_message: Text,
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
    let (mut outbound, mut outbound_message) = (Status::Unknown, no_resolver());
    if let Some(resolver) = &app.authenticator {
        for ip in public_host_ips(Some(resolver), &app.cfg.hostname).await.0 {
            public_addresses.push(ip.to_string());
            blocklisted.extend(reputation::dnsbl_listings(app, ip).await);
        }
        // A well-known, highly available MX is used as the reachability probe.
        (outbound, outbound_message) = match dns::mx(resolver, "gmail.com").await {
            Ok(hosts) if !hosts.is_empty() => match dns::ips(resolver, &hosts[0].1).await {
                Ok(ips) if !ips.is_empty() => {
                    if port_open(SocketAddr::new(ips[0], 25)).await {
                        (Status::Ok, text!("Outbound connections on port 25 work."))
                    } else {
                        (Status::Error, text!("Outbound port 25 appears to be blocked; configure a relay host."))
                    }
                }
                _ => (Status::Unknown, text!("Could not resolve the probe host.")),
            },
            _ => (Status::Unknown, text!("Could not resolve the probe host.")),
        };
    }
    if app.rt().route().is_some() {
        (outbound, outbound_message) = (Status::Ok, text!("Outbound mail is sent through the configured default route."));
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
        Some(addr) if crate::security::clamav::ping(addr).await => (Status::Ok, text!("ClamAV is reachable; incoming mail is scanned for malware.")),
        Some(_) => (Status::Error, text!("ClamAV is configured but does not answer; incoming mail is deferred until it returns.")),
        None if rspamd == Status::Ok => {
            (Status::Unknown, text!("No ClamAV address is configured. Mail is scanned only if Rspamd's antivirus module is set up; set UNOMAIL_CLAMAV_ADDR to be sure."))
        }
        None => (Status::Warning, text!("Incoming mail is not scanned for malware. Programs are refused by name, but infected documents get through; set UNOMAIL_CLAMAV_ADDR.")),
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
        let ips: [IpAddr; 2] = ["203.0.113.10".parse().unwrap(), "2001:db8::10".parse().unwrap()];
        let pass = [(ips[0], SpfResult::Pass), (ips[1], SpfResult::Pass)];
        // `a`, `mx` and `include` are judged by the evaluation, not by the record's text.
        assert_eq!(eval_spf(&s(&["v=spf1 a:mail.example.com -all"]), &pass).0, Status::Ok);
        assert_eq!(eval_spf(&s(&["v=spf1 mx -all"]), &pass).0, Status::Ok);
        let ipv6_missing = eval_spf(&s(&["v=spf1 ip4:203.0.113.10 -all"]), &[(ips[0], SpfResult::Pass), (ips[1], SpfResult::Fail)]);
        assert_eq!(ipv6_missing, (Status::Error, text!("SPF record does not authorize this server's IP address {{ip}}.", ip = "2001:db8::10")));
        assert_eq!(eval_spf(&s(&["v=spf1 ip4:203.0.113.10 ~all"]), &[(ips[0], SpfResult::SoftFail)]).0, Status::Error);
        assert_eq!(eval_spf(&s(&["v=spf1 include:broken.example -all"]), &[(ips[0], SpfResult::PermError)]).0, Status::Error);
        assert_eq!(eval_spf(&s(&["v=spf1 include:slow.example -all"]), &[(ips[0], SpfResult::TempError)]).0, Status::Unknown);
        assert_eq!(eval_spf(&s(&["v=spf1 ip4:203.0.113.10 +all"]), &pass).0, Status::Error);
        assert_eq!(eval_spf(&s(&["v=spf1 mx ?all"]), &pass).0, Status::Warning);
        assert_eq!(eval_spf(&s(&["v=spf1 mx ~all"]), &pass).0, Status::Warning);
        assert_eq!(eval_spf(&s(&["v=spf1 mx -all"]), &[]).0, Status::Warning, "addresses unknown");
        assert_eq!(eval_spf(&s(&["v=spf1 ip4:203.0.113.10 -all", "v=spf1 -all"]), &pass).0, Status::Error);
        assert_eq!(eval_spf(&s(&["google-site-verification=x"]), &pass).0, Status::Error);
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

    #[test]
    fn texts_render_and_serialize_with_their_values() {
        let message = text!("The record does not point to port {{port}} on {{hostname}}.", port = 993, hostname = "mail.example.com");
        assert_eq!(message.render(), "The record does not point to port 993 on mail.example.com.");
        let check = check("srv", text!("Client autoconfiguration ({{service}})", service = "imaps"), "SRV", String::new(), String::new(), (Status::Warning, message), Vec::new());
        let json = serde_json::to_value(&check).unwrap();
        assert_eq!(json["title"], "Client autoconfiguration (imaps)");
        assert_eq!(json["title_key"], "Client autoconfiguration ({{service}})");
        assert_eq!(json["message_key"], "The record does not point to port {{port}} on {{hostname}}.");
        assert_eq!(json["message_params"], serde_json::json!({ "port": "993", "hostname": "mail.example.com" }));
    }

    /// The web client translates these texts; each must be listed for its translation test.
    #[test]
    fn every_text_is_listed_for_translation() {
        let catalog = include_str!("../../web/src/admin/serverTexts.ts");
        let source = include_str!("diagnostics.rs");
        let keys: Vec<&str> = source.split("text!(\"").skip(1).filter_map(|rest| rest.split_once('"').map(|(key, _)| key)).filter(|key| !key.is_empty()).collect();
        assert!(keys.len() > 60, "found {} texts", keys.len());
        let missing: Vec<&&str> = keys.iter().filter(|key| !catalog.contains(&format!("\"{key}\""))).collect();
        assert!(missing.is_empty(), "add to web/src/admin/serverTexts.ts: {missing:#?}");
    }

    #[test]
    fn public_addresses_exclude_container_networks() {
        let ips = vec![
            "172.18.0.2".parse().unwrap(),
            "10.0.0.4".parse().unwrap(),
            "203.0.113.20".parse().unwrap(),
            "2001:db8::20".parse().unwrap(),
            "203.0.113.20".parse().unwrap(),
        ];
        assert_eq!(only_public(ips), ["2001:db8::20".parse::<IpAddr>().unwrap(), "203.0.113.20".parse::<IpAddr>().unwrap()]);
    }
}
