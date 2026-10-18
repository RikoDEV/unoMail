//! How securely outgoing mail travels, and what is reported about it.
//!
//! - MTA-STS (RFC 8461): receiving domains that publish a policy are only sent to over TLS
//!   with a certificate valid for an MX host the policy names (mode `enforce`), or are
//!   watched for failures (`testing`). Policies are fetched over HTTPS and cached.
//! - DANE for SMTP (RFC 7672): when the MX host's TLSA records are DNSSEC-signed (and so is
//!   the MX lookup), the certificate must match them. DANE takes precedence over MTA-STS.
//! - SMTP TLS reporting (RFC 8460): the outcome of every session is counted per receiving
//!   domain and reported once a day to the domains asking for it; reports other servers send
//!   about our domains are stored for the admin panel.
//!
//! Publishing MTA-STS policies for hosted domains is in [`policy_for_hosted`].

use std::{
    io::{Read, Write},
    sync::{Arc, LazyLock},
};

use hickory_resolver::{
    TokioResolver,
    proto::rr::{RData, RecordType},
};
use parking_lot::Mutex;
use ring::digest;
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

use crate::{app::App, util::now};

// --- MTA-STS policies -------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StsMode {
    Enforce,
    Testing,
    None,
}

impl StsMode {
    fn as_str(self) -> &'static str {
        match self {
            StsMode::Enforce => "enforce",
            StsMode::Testing => "testing",
            StsMode::None => "none",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "enforce" => Some(StsMode::Enforce),
            "testing" => Some(StsMode::Testing),
            "none" => Some(StsMode::None),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StsPolicy {
    pub id: String,
    pub mode: StsMode,
    /// MX host patterns, e.g. `mail.example.org` or `*.example.org`.
    pub mx: Vec<String>,
    pub max_age: i64,
}

impl StsPolicy {
    /// The policy as it reads in a TLS report (`policy-string`).
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec!["version: STSv1".to_owned(), format!("mode: {}", self.mode.as_str())];
        out.extend(self.mx.iter().map(|mx| format!("mx: {mx}")));
        out.push(format!("max_age: {}", self.max_age));
        out
    }

    pub fn allows(&self, host: &str) -> bool {
        self.mx.iter().any(|pattern| mx_matches(pattern, host))
    }
}

/// Reads a policy file (`version: STSv1`, `mode`, `mx`, `max_age`).
pub fn parse_policy(text: &str) -> Option<(StsMode, Vec<String>, i64)> {
    let (mut version, mut mode, mut mx, mut max_age) = (false, None, Vec::new(), None);
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        match key.trim() {
            "version" => version = value == "STSv1",
            "mode" => mode = StsMode::parse(value),
            "mx" if mx.len() < 64 => mx.push(value.trim_end_matches('.').to_ascii_lowercase()),
            "max_age" => max_age = value.parse::<i64>().ok().filter(|age| (0..=31_557_600).contains(age)),
            _ => {}
        }
    }
    let mode = mode?;
    (version && max_age.is_some() && (mode == StsMode::None || !mx.is_empty())).then(|| (mode, mx, max_age.unwrap_or(0)))
}

/// `*.example.org` matches exactly one label in front of `example.org`.
pub fn mx_matches(pattern: &str, host: &str) -> bool {
    let (pattern, host) = (pattern.trim_end_matches('.').to_ascii_lowercase(), host.trim_end_matches('.').to_ascii_lowercase());
    match pattern.strip_prefix("*.") {
        Some(parent) => host.split_once('.').is_some_and(|(label, rest)| !label.is_empty() && rest == parent),
        None => pattern == host,
    }
}

/// The `id` of a domain's `_mta-sts` record, if it publishes one.
async fn sts_record(app: &App, domain: &str) -> Option<String> {
    let resolver = app.authenticator.as_ref()?;
    let records = crate::dns::txt(resolver, &format!("_mta-sts.{domain}")).await.ok()?;
    records.iter().find_map(|record| {
        let tags: Vec<(&str, &str)> = record.split(';').filter_map(|part| part.split_once('=')).map(|(k, v)| (k.trim(), v.trim())).collect();
        (tags.first() == Some(&("v", "STSv1"))).then(|| tags.iter().find(|(k, _)| *k == "id").map(|(_, v)| (*v).to_owned())).flatten()
    })
}

/// The MTA-STS policy of a receiving domain: from the cache while it is current, else fetched.
/// `Err` carries a fetch failure worth reporting (the domain announced a policy that could not
/// be read).
pub async fn sts_policy(app: &App, domain: &str) -> Result<Option<StsPolicy>, String> {
    let cached: Option<(String, String, String, i64, i64)> = sqlx::query_as("SELECT policy_id, mode, mx, max_age, expires_at FROM mta_sts_cache WHERE domain = ?").bind(domain).fetch_optional(&app.db).await.map_err(|e| e.to_string())?;
    let cached = cached.filter(|(.., expires)| *expires > now()).and_then(|(id, mode, mx, max_age, _)| {
        Some(StsPolicy { id, mode: StsMode::parse(&mode)?, mx: serde_json::from_str(&mx).ok()?, max_age })
    });
    let announced = sts_record(app, domain).await;
    match (announced, cached) {
        // Nothing announced and nothing remembered: no policy.
        (None, None) => Ok(None),
        // A remembered policy stays in force until it expires, even if the record is gone.
        (None, Some(policy)) => Ok(Some(policy)),
        (Some(id), Some(policy)) if id == policy.id => Ok(Some(policy)),
        (Some(id), previous) => match fetch_policy(app, domain).await {
            Ok((mode, mx, max_age)) => {
                let policy = StsPolicy { id, mode, mx, max_age };
                let _ = sqlx::query("INSERT INTO mta_sts_cache (domain, policy_id, mode, mx, max_age, fetched_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(domain) DO UPDATE SET policy_id = excluded.policy_id, mode = excluded.mode, mx = excluded.mx, max_age = excluded.max_age, fetched_at = excluded.fetched_at, expires_at = excluded.expires_at")
                    .bind(domain)
                    .bind(&policy.id)
                    .bind(policy.mode.as_str())
                    .bind(serde_json::to_string(&policy.mx).unwrap_or_default())
                    .bind(policy.max_age)
                    .bind(now())
                    .bind(now() + policy.max_age.max(86_400))
                    .execute(&app.db)
                    .await;
                Ok(Some(policy))
            }
            // A new policy could not be read: the one remembered still applies.
            Err(err) => match previous {
                Some(policy) => Ok(Some(policy)),
                None => Err(err),
            },
        },
    }
}

async fn fetch_policy(app: &App, domain: &str) -> Result<(StsMode, Vec<String>, i64), String> {
    let url = reqwest::Url::parse(&format!("https://mta-sts.{domain}/.well-known/mta-sts.txt")).map_err(|_| "invalid policy address".to_owned())?;
    // No redirects (RFC 8461 3.3): the address itself must serve the policy.
    let data = crate::api::mailboxes::fetch_public_strict(app, url, &[443], 64 * 1024, "text/plain").await.map_err(|err| format!("policy fetch failed: {err}"))?;
    let text = String::from_utf8(data).map_err(|_| "the policy is not text".to_owned())?;
    parse_policy(&text).ok_or_else(|| "the policy is invalid".to_owned())
}

/// The policy file this server publishes for a hosted domain (`mta-sts.<domain>`).
pub fn policy_for_hosted(mode: &str, hostname: &str) -> Option<String> {
    let mode = StsMode::parse(mode).filter(|m| *m != StsMode::None)?;
    Some(format!("version: STSv1\nmode: {}\nmx: {hostname}\nmax_age: {}\n", mode.as_str(), if mode == StsMode::Enforce { 604_800 } else { 86_400 }))
}

/// The `id` of a published policy: it changes whenever the policy does.
pub fn policy_id(policy: &str) -> String {
    crate::util::sha256_hex(policy.as_bytes())[..16].to_owned()
}

// --- DANE ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlsa {
    pub usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub data: Vec<u8>,
}

impl Tlsa {
    /// Only DANE-TA(2) and DANE-EE(3) apply to SMTP (RFC 7672 3.1); others are ignored.
    fn usable(&self) -> bool {
        matches!(self.usage, 2 | 3) && self.selector <= 1 && self.matching <= 2
    }
}

/// A validating resolver for DNSSEC: only its secure answers are trusted for DANE.
static VALIDATING: LazyLock<Option<TokioResolver>> = LazyLock::new(|| {
    let mut builder = TokioResolver::builder_tokio().ok()?;
    builder.options_mut().validate = true;
    builder.build().ok()
});

/// What DNS says about DANE for one MX host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dane {
    /// Not signed, or no usable TLSA records: other rules apply.
    None,
    Records(Vec<Tlsa>),
    /// The zone is signed but the answer could not be validated: do not send there now.
    Failed(String),
}

async fn secure_lookup(name: &str, kind: RecordType) -> Result<Option<Vec<RData>>, String> {
    let Some(resolver) = VALIDATING.as_ref() else { return Ok(None) };
    match resolver.lookup(name, kind).await {
        Ok(lookup) => {
            let answers: Vec<_> = lookup.answers().iter().filter(|record| record.record_type() == kind).collect();
            if answers.is_empty() || !answers.iter().all(|record| record.proof.is_secure()) {
                return Ok(None);
            }
            Ok(Some(answers.into_iter().map(|record| record.data.clone()).collect()))
        }
        Err(err) => {
            let text = err.to_string();
            if text.contains("no record") || text.contains("NXDomain") || text.contains("no records") || text.contains("NoRecordsFound") {
                Ok(None)
            } else {
                Err(text)
            }
        }
    }
}

/// DANE for delivery to `host`, an MX of `domain`. Applies only when the MX answer itself was
/// secure: otherwise an attacker could have swapped in a host of their choosing.
pub async fn dane_for(app: &App, domain: &str, host: &str) -> Dane {
    if app.authenticator.is_none() || !app.rt().dane_enabled {
        return Dane::None;
    }
    match secure_lookup(&format!("{domain}."), RecordType::MX).await {
        Ok(Some(_)) => {}
        _ => return Dane::None,
    }
    match secure_lookup(&format!("_25._tcp.{host}."), RecordType::TLSA).await {
        Ok(Some(records)) => {
            let usable: Vec<Tlsa> = records
                .iter()
                .filter_map(|data| match data {
                    RData::TLSA(tlsa) => Some(Tlsa { usage: u8::from(tlsa.cert_usage), selector: u8::from(tlsa.selector), matching: u8::from(tlsa.matching), data: tlsa.cert_data.clone() }),
                    _ => None,
                })
                .filter(Tlsa::usable)
                .collect();
            if usable.is_empty() { Dane::None } else { Dane::Records(usable) }
        }
        Ok(None) => Dane::None,
        Err(err) => Dane::Failed(err),
    }
}

/// The bytes a TLSA record of this selector and matching type compares with.
fn association(cert_der: &[u8], selector: u8, matching: u8) -> Option<Vec<u8>> {
    let selected = match selector {
        0 => cert_der.to_vec(),
        _ => X509Certificate::from_der(cert_der).ok()?.1.public_key().raw.to_vec(),
    };
    Some(match matching {
        0 => selected,
        1 => digest::digest(&digest::SHA256, &selected).as_ref().to_vec(),
        _ => digest::digest(&digest::SHA512, &selected).as_ref().to_vec(),
    })
}

fn name_matches(cert: &X509Certificate<'_>, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    cert.subject_alternative_name().ok().flatten().is_some_and(|san| {
        san.value.general_names.iter().any(|name| match name {
            GeneralName::DNSName(name) => crate::tls::san_matches(name, &host),
            _ => false,
        })
    })
}

/// Checks a server's certificate chain against TLSA records (RFC 7672 3.1).
pub fn dane_matches(records: &[Tlsa], end_entity: &[u8], intermediates: &[&[u8]], host: &str, at: i64) -> Result<(), &'static str> {
    // DANE-EE: the server's own certificate or key, whatever its name or dates.
    if records.iter().filter(|r| r.usage == 3).any(|r| association(end_entity, r.selector, r.matching).is_some_and(|a| a == r.data)) {
        return Ok(());
    }
    // DANE-TA: a certificate of the chain is the trust anchor; the leaf must be issued by it
    // (through the chain), be valid now and carry the MX host's name.
    let trust_anchors: Vec<&Tlsa> = records.iter().filter(|r| r.usage == 2).collect();
    if trust_anchors.is_empty() {
        return Err("the certificate does not match the TLSA records");
    }
    let (_, leaf) = X509Certificate::from_der(end_entity).map_err(|_| "unreadable certificate")?;
    let time = x509_parser::time::ASN1Time::from_timestamp(at).map_err(|_| "invalid time")?;
    if !leaf.validity().is_valid_at(time) {
        return Err("the certificate is expired");
    }
    if !name_matches(&leaf, host) {
        return Err("the certificate is for another host");
    }
    let chain: Vec<X509Certificate<'_>> = intermediates.iter().filter_map(|der| X509Certificate::from_der(der).ok().map(|(_, c)| c)).collect();
    let mut current = leaf;
    let mut current_der: &[u8] = end_entity;
    for _ in 0..8 {
        let anchored = trust_anchors.iter().any(|r| association(current_der, r.selector, r.matching).is_some_and(|a| a == r.data));
        if anchored && current_der != end_entity {
            return Ok(());
        }
        let Some(position) = chain.iter().position(|candidate| candidate.subject() == current.issuer() && current.verify_signature(Some(candidate.public_key())).is_ok()) else { break };
        current_der = intermediates[position];
        current = chain[position].clone();
    }
    Err("the certificate does not chain to the TLSA trust anchor")
}

// --- Verifying the certificate during the handshake --------------------------------------------

/// How the certificate of a receiving server is judged.
#[derive(Debug, Clone)]
pub enum Check {
    /// Any certificate; only recorded whether it would pass the web PKI (for reports).
    Observe,
    /// Valid in the web PKI for the host (MTA-STS enforce, or required by configuration).
    WebPki,
    /// Matching the TLSA records.
    Dane(Vec<Tlsa>),
}

/// A rustls verifier applying a [`Check`], noting why a certificate was not good enough.
#[derive(Debug)]
pub struct Verifier {
    check: Check,
    provider: Arc<rustls::crypto::CryptoProvider>,
    web_pki: Arc<dyn ServerCertVerifier>,
    /// Why the certificate failed the web PKI or DANE, for TLS reports.
    pub problem: Mutex<Option<(&'static str, String)>>,
}

impl Verifier {
    pub fn new(check: Check) -> Arc<Self> {
        let provider = crate::tls::provider();
        let roots = Arc::new(rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() });
        let web_pki = rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider.clone()).build().expect("the built-in roots are valid");
        Arc::new(Verifier { check, provider, web_pki, problem: Mutex::new(None) })
    }
}

/// The TLS-RPT result type for a web PKI failure.
fn result_type(err: &rustls::Error) -> &'static str {
    match err {
        rustls::Error::InvalidCertificate(rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. }) => "certificate-expired",
        rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName | rustls::CertificateError::NotValidForNameContext { .. }) => "certificate-host-mismatch",
        rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer) => "certificate-not-trusted",
        _ => "validation-failure",
    }
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], server_name: &ServerName<'_>, ocsp: &[u8], now: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        match &self.check {
            Check::Dane(records) => {
                let host = match server_name {
                    ServerName::DnsName(name) => name.as_ref().to_owned(),
                    _ => String::new(),
                };
                let chain: Vec<&[u8]> = intermediates.iter().map(|c| c.as_ref()).collect();
                dane_matches(records, end_entity, &chain, &host, now.as_secs() as i64).map(|()| ServerCertVerified::assertion()).map_err(|reason| {
                    *self.problem.lock() = Some(("validation-failure", reason.to_owned()));
                    rustls::Error::General(format!("DANE: {reason}"))
                })
            }
            Check::WebPki | Check::Observe => match self.web_pki.verify_server_cert(end_entity, intermediates, server_name, ocsp, now) {
                Ok(verified) => Ok(verified),
                Err(err) => {
                    *self.problem.lock() = Some((result_type(&err), err.to_string()));
                    if matches!(self.check, Check::Observe) { Ok(ServerCertVerified::assertion()) } else { Err(err) }
                }
            },
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

// --- TLS reporting: what we send -------------------------------------------------------------

/// The policy that applied to a session, as TLS-RPT names it.
#[derive(Debug, Clone)]
pub struct Applied {
    /// `tlsa`, `sts` or `no-policy-found`.
    pub policy_type: &'static str,
    pub policy_string: Vec<String>,
}

/// Counts the outcome of one session for the daily report to `domain`. `failure` is a
/// TLS-RPT result type.
pub async fn record(app: &App, domain: &str, applied: &Applied, mx_host: &str, receiving_ip: &str, failure: Option<&str>) {
    let day = now().div_euclid(86_400);
    let result = sqlx::query(
        "INSERT INTO tls_rpt_results (day, domain, policy_type, policy_string, mx_host, result_type, receiving_ip, count) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
         ON CONFLICT(day, domain, policy_type, mx_host, result_type, receiving_ip) DO UPDATE SET count = count + 1",
    )
    .bind(day)
    .bind(domain)
    .bind(applied.policy_type)
    .bind(applied.policy_string.join("\n"))
    .bind(mx_host)
    .bind(failure.unwrap_or("success"))
    .bind(receiving_ip)
    .execute(&app.db)
    .await;
    if let Err(err) = result {
        tracing::debug!(%err, "could not record a TLS reporting result");
    }
}

/// Where a domain wants its TLS reports: `mailto:` and `https:` addresses.
async fn report_addresses(app: &App, domain: &str) -> Vec<String> {
    let Some(resolver) = app.authenticator.as_ref() else { return Vec::new() };
    let records = crate::dns::txt(resolver, &format!("_smtp._tls.{domain}")).await.unwrap_or_default();
    records
        .iter()
        .filter(|record| record.to_ascii_lowercase().replace(' ', "").starts_with("v=tlsrptv1"))
        .flat_map(|record| record.split(';').filter_map(|part| part.trim().strip_prefix("rua=").map(str::to_owned)).collect::<Vec<_>>())
        .flat_map(|rua| rua.split(',').map(|uri| uri.trim().to_owned()).collect::<Vec<_>>())
        .filter(|uri| uri.starts_with("mailto:") || uri.starts_with("https://"))
        .take(5)
        .collect()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = encoder.write_all(data);
    encoder.finish().unwrap_or_default()
}

/// Builds the report for one domain and day (RFC 8460 section 4).
pub async fn build_report(app: &App, domain: &str, day: i64) -> sqlx::Result<Option<mail_auth::report::tlsrpt::TlsReport>> {
    use mail_auth::report::tlsrpt::{DateRange, FailureDetails, Policy, PolicyDetails, PolicyType, ResultType, Summary, TlsReport};
    let rows: Vec<(String, String, String, String, String, i64)> = sqlx::query_as("SELECT policy_type, policy_string, mx_host, result_type, receiving_ip, count FROM tls_rpt_results WHERE day = ? AND domain = ? ORDER BY policy_type, mx_host").bind(day).bind(domain).fetch_all(&app.db).await?;
    if rows.is_empty() {
        return Ok(None);
    }
    let mut policies: Vec<Policy> = Vec::new();
    for (policy_type, policy_string, mx_host, result, receiving_ip, count) in rows {
        let kind = match policy_type.as_str() {
            "tlsa" => PolicyType::Tlsa,
            "sts" => PolicyType::Sts,
            _ => PolicyType::NoPolicyFound,
        };
        let lines: Vec<String> = if policy_string.is_empty() { Vec::new() } else { policy_string.lines().map(str::to_owned).collect() };
        let index = match policies.iter().position(|p| p.policy.policy_type == kind && p.policy.policy_string == lines) {
            Some(index) => index,
            None => {
                policies.push(Policy {
                    policy: PolicyDetails { policy_type: kind, policy_string: lines, policy_domain: domain.to_owned(), mx_host: Vec::new() },
                    summary: Summary { total_success: 0, total_failure: 0 },
                    failure_details: Vec::new(),
                });
                policies.len() - 1
            }
        };
        let policy = &mut policies[index];
        if kind == PolicyType::Sts && !policy.policy.mx_host.contains(&mx_host) {
            policy.policy.mx_host.push(mx_host.clone());
        }
        let count = u32::try_from(count).unwrap_or(u32::MAX);
        if result == "success" {
            policy.summary.total_success = policy.summary.total_success.saturating_add(count);
        } else {
            policy.summary.total_failure = policy.summary.total_failure.saturating_add(count);
            let result_type: ResultType = serde_json::from_value(serde_json::Value::String(result)).unwrap_or(ResultType::Other);
            policy.failure_details.push(FailureDetails { result_type, receiving_mx_hostname: Some(mx_host), receiving_ip: receiving_ip.parse().ok(), failed_session_count: count, ..Default::default() });
        }
    }
    let organization = app.cfg.hostname.clone();
    Ok(Some(TlsReport {
        organization_name: Some(organization.clone()),
        date_range: DateRange { start_datetime: mail_parser::DateTime::from_timestamp(day * 86_400), end_datetime: mail_parser::DateTime::from_timestamp(day * 86_400 + 86_399) },
        contact_info: Some(format!("postmaster@{organization}")),
        report_id: format!("{day}.{domain}@{organization}"),
        policies,
    }))
}

/// The address and domain the server sends its own reports from: a hosted domain, so that
/// the report can be signed.
pub async fn report_sender(app: &App) -> Option<(String, String)> {
    let domains: Vec<String> = sqlx::query_scalar("SELECT name FROM domains WHERE enabled = 1 ORDER BY id").fetch_all(&app.db).await.ok()?;
    let hostname = app.cfg.hostname.to_ascii_lowercase();
    let domain = domains.iter().find(|d| hostname == **d || hostname.ends_with(&format!(".{d}"))).or_else(|| domains.first())?.clone();
    Some((format!("noreply-reports@{domain}"), domain))
}

/// Sends a finished message from the server itself: signed, queued, with a null return path.
pub async fn send_system_mail(app: &App, domain: &str, recipient: &str, raw: Vec<u8>) -> anyhow::Result<()> {
    let signed = crate::security::dkim::sign(&app.db, &app.secrets, domain, &raw).await.unwrap_or(raw);
    let Some(address) = crate::util::Address::parse(recipient) else { anyhow::bail!("invalid report address") };
    let hash = app.store.put_blob(&signed).await?;
    crate::smtp::delivery::enqueue(app, "", &address, &hash, signed.len(), None).await?;
    Ok(())
}

/// Sends yesterday's (and any missed) TLS reports. Run hourly; each day is reported once.
pub async fn send_reports(app: &App) {
    let today = now().div_euclid(86_400);
    let days: Vec<i64> = sqlx::query_scalar("SELECT DISTINCT day FROM tls_rpt_results WHERE day < ? AND day NOT IN (SELECT day FROM report_runs WHERE kind = 'tlsrpt') ORDER BY day").bind(today).fetch_all(&app.db).await.unwrap_or_default();
    let Some((sender, sender_domain)) = report_sender(app).await else { return };
    for day in days {
        let domains: Vec<String> = sqlx::query_scalar("SELECT DISTINCT domain FROM tls_rpt_results WHERE day = ?").bind(day).fetch_all(&app.db).await.unwrap_or_default();
        for domain in domains {
            let addresses = report_addresses(app, &domain).await;
            if addresses.is_empty() {
                continue;
            }
            let Ok(Some(report)) = build_report(app, &domain, day).await else { continue };
            let json = serde_json::to_vec(&report).unwrap_or_default();
            for address in addresses {
                let result = if let Some(mailbox) = address.strip_prefix("mailto:") {
                    let mut raw = Vec::new();
                    match report.write_rfc5322(&app.cfg.hostname, domain.as_str(), sender.as_str(), std::iter::once(mailbox), &mut raw) {
                        Ok(()) => send_system_mail(app, &sender_domain, mailbox, raw).await,
                        Err(err) => Err(anyhow::anyhow!("{err}")),
                    }
                } else {
                    post_report(app, &address, gzip(&json)).await
                };
                if let Err(err) = result {
                    tracing::info!(%err, domain, "TLS report not sent");
                }
            }
        }
        let _ = sqlx::query("INSERT OR IGNORE INTO report_runs (kind, day) VALUES ('tlsrpt', ?)").bind(day).execute(&app.db).await;
    }
    let _ = sqlx::query("DELETE FROM tls_rpt_results WHERE day < ?").bind(today - 7).execute(&app.db).await;
}

async fn post_report(app: &App, address: &str, body: Vec<u8>) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(address)?;
    let (host, addr) = crate::api::mailboxes::public_target(app, &url, &[443]).await.map_err(|e| anyhow::anyhow!("{e}"))?;
    let client = reqwest::Client::builder().use_preconfigured_tls((*crate::smtp::client::tls_config(true)).clone()).resolve(&host, addr).redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(20)).build()?;
    let response = client.post(url).header("content-type", "application/tlsrpt+gzip").body(body).send().await?;
    anyhow::ensure!(response.status().is_success(), "the report address answered {}", response.status());
    Ok(())
}

// --- TLS reporting: what others send about our domains ---------------------------------------

/// Stores a TLS report found in an incoming message, when the message is one.
pub async fn ingest_mail(app: &App, raw: &[u8]) {
    let head = String::from_utf8_lossy(&raw[..raw.len().min(8192)]).to_ascii_lowercase();
    if !head.contains("tlsrpt") && !head.contains("tls-report") && !head.contains("tls report") {
        return;
    }
    let Some(message) = mail_parser::MessageParser::default().parse(raw) else { return };
    use mail_parser::MimeHeaders;
    for part in message.parts.iter() {
        let kind = part.content_type().map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("")).to_ascii_lowercase()).unwrap_or_default();
        if !kind.starts_with("application/tlsrpt") {
            continue;
        }
        let data = part.contents();
        let json = if data.starts_with(&[0x1f, 0x8b]) {
            let mut out = Vec::new();
            if flate2::read::GzDecoder::new(data).take(10 * 1024 * 1024).read_to_end(&mut out).is_err() {
                continue;
            }
            out
        } else {
            data.to_vec()
        };
        match serde_json::from_slice::<mail_auth::report::tlsrpt::TlsReport>(&json) {
            Ok(report) => store_received(app, &report).await,
            Err(err) => tracing::info!(%err, "not a usable TLS report"),
        }
    }
}

/// Stores a received report: one row per policy, for domains hosted here.
pub async fn store_received(app: &App, report: &mail_auth::report::tlsrpt::TlsReport) {
    let reporter = report.organization_name.clone().unwrap_or_default().chars().filter(|c| !c.is_control()).take(200).collect::<String>();
    for policy in &report.policies {
        let domain = policy.policy.policy_domain.to_ascii_lowercase();
        if !crate::smtp::delivery::is_local_domain(app, &domain).await.unwrap_or(false) {
            continue;
        }
        let kind = serde_json::to_value(policy.policy.policy_type).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
        let details = serde_json::to_string(&policy.failure_details).unwrap_or_default();
        let stored = sqlx::query("INSERT OR IGNORE INTO tls_reports (reporter, report_id, domain, policy_type, date_begin, date_end, successes, failures, details, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(&reporter)
            .bind(report.report_id.chars().take(300).collect::<String>())
            .bind(&domain)
            .bind(kind)
            .bind(report.date_range.start_datetime.to_timestamp())
            .bind(report.date_range.end_datetime.to_timestamp())
            .bind(i64::from(policy.summary.total_success))
            .bind(i64::from(policy.summary.total_failure))
            .bind(details)
            .bind(now())
            .execute(&app.db)
            .await;
        if let Err(err) = stored {
            tracing::warn!(%err, "could not store a TLS report");
        }
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};

    use super::*;

    #[test]
    fn policies_and_mx_patterns() {
        let text = "version: STSv1\r\nmode: enforce\r\nmx: mail.example.org\r\nmx: *.backup.example.org\r\nmax_age: 604800\r\n";
        let (mode, mx, max_age) = parse_policy(text).unwrap();
        assert_eq!((mode, max_age), (StsMode::Enforce, 604_800));
        let policy = StsPolicy { id: "1".into(), mode, mx, max_age };
        assert!(policy.allows("mail.example.org") && policy.allows("MAIL.example.org.") && policy.allows("mx1.backup.example.org"));
        assert!(!policy.allows("a.b.backup.example.org") && !policy.allows("backup.example.org") && !policy.allows("evil.example"));
        assert_eq!(policy.lines(), ["version: STSv1", "mode: enforce", "mx: mail.example.org", "mx: *.backup.example.org", "max_age: 604800"]);
        for bad in ["mode: enforce\nmx: a\nmax_age: 1", "version: STSv1\nmode: sometimes\nmx: a\nmax_age: 1", "version: STSv1\nmode: enforce\nmax_age: 1", "version: STSv1\nmode: testing\nmx: a\nmax_age: -5"] {
            assert_eq!(parse_policy(bad), None, "{bad}");
        }
        assert!(parse_policy("version: STSv1\nmode: none\nmax_age: 86400").is_some());
        let published = policy_for_hosted("enforce", "mail.example.org").unwrap();
        assert_eq!(parse_policy(&published).unwrap().1, ["mail.example.org"]);
        assert_eq!(policy_for_hosted("none", "x"), None);
        assert_ne!(policy_id(&published), policy_id(&policy_for_hosted("testing", "mail.example.org").unwrap()));
    }

    #[test]
    fn dane_records_are_matched() {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, "Private CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec!["mx.example.org".to_owned()]).unwrap();
        leaf_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(90);
        let leaf = leaf_params.signed_by(&leaf_key, &Issuer::from_params(&ca_params, &ca_key)).unwrap();
        let (leaf_der, ca_der) = (leaf.der().to_vec(), ca.der().to_vec());
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let record = |usage: u8, selector: u8, matching: u8, cert: &[u8]| Tlsa { usage, selector, matching, data: association(cert, selector, matching).unwrap() };

        // DANE-EE by key digest (the usual "3 1 1"), by full certificate, by SHA-512.
        for ee in [record(3, 1, 1, &leaf_der), record(3, 0, 0, &leaf_der), record(3, 0, 2, &leaf_der)] {
            assert_eq!(dane_matches(&[ee], &leaf_der, &[], "anything.example", now), Ok(()), "names do not matter for DANE-EE");
        }
        assert!(dane_matches(&[record(3, 1, 1, &ca_der)], &leaf_der, &[], "mx.example.org", now).is_err());
        // DANE-TA: the chain must reach the anchor, and the name must fit.
        let ta = record(2, 1, 1, &ca_der);
        assert_eq!(dane_matches(std::slice::from_ref(&ta), &leaf_der, &[&ca_der], "mx.example.org", now), Ok(()));
        assert!(dane_matches(std::slice::from_ref(&ta), &leaf_der, &[&ca_der], "other.example.org", now).is_err());
        assert!(dane_matches(std::slice::from_ref(&ta), &leaf_der, &[], "mx.example.org", now).is_err(), "the anchor must be in the chain");
        assert!(dane_matches(std::slice::from_ref(&ta), &leaf_der, &[&ca_der], "mx.example.org", now + 100 * 86_400).is_err(), "expired");
        // A leaf that names itself as anchor is not a trust anchor.
        assert!(dane_matches(&[record(2, 1, 1, &leaf_der)], &leaf_der, &[], "mx.example.org", now).is_err());
        assert!(!Tlsa { usage: 1, selector: 1, matching: 1, data: vec![] }.usable(), "PKIX usages are not for SMTP");
    }
}
