//! DMARC aggregate reports (RFC 7489 appendix C): ingestion from uploads and from report
//! mail delivered to hosted domains, and the summaries shown in the admin panel.

use std::io::Read;

use mail_auth::report::{ActionDisposition, DmarcResult, Report};
use serde::Serialize;

use crate::{app::App, smtp::delivery::is_local_domain, util::{normalize_domain, now}};

/// Upper bound for a decompressed report; real ones are a few hundred kilobytes at most.
const MAX_REPORT_BYTES: usize = 20 * 1024 * 1024;
const MAX_RECORDS: usize = 50_000;

#[derive(Debug, PartialEq, Eq)]
pub enum Ingested {
    Stored { domain: String, records: usize },
    /// The same report (reporter + report id) was stored before.
    Duplicate,
}

fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    // `take` guards against decompression bombs.
    flate2::read::GzDecoder::new(data).take(MAX_REPORT_BYTES as u64 + 1).read_to_end(&mut out).map_err(|e| format!("invalid gzip data: {e}"))?;
    if out.len() > MAX_REPORT_BYTES {
        return Err("the report is too large".into());
    }
    Ok(out)
}

fn decompress_zip(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(data)).map_err(|e| format!("invalid zip archive: {e}"))?;
    for index in 0..archive.len().min(10) {
        let file = archive.by_index(index).map_err(|e| format!("invalid zip archive: {e}"))?;
        if !file.name().is_ok_and(|name| name.to_ascii_lowercase().ends_with(".xml")) {
            continue;
        }
        let mut out = Vec::new();
        file.take(MAX_REPORT_BYTES as u64 + 1).read_to_end(&mut out).map_err(|e| format!("invalid zip archive: {e}"))?;
        if out.len() > MAX_REPORT_BYTES {
            return Err("the report is too large".into());
        }
        return Ok(out);
    }
    Err("the archive contains no XML report".into())
}

/// Parses a report given as XML, gzip, zip, or a complete report e-mail.
pub fn parse(data: &[u8]) -> Result<Report, String> {
    let trimmed = data.iter().position(|b| !b.is_ascii_whitespace()).map_or(data, |start| &data[start..]);
    if data.starts_with(&[0x1f, 0x8b]) {
        Report::parse_xml(&decompress_gzip(data)?)
    } else if data.starts_with(b"PK") {
        Report::parse_xml(&decompress_zip(data)?)
    } else if trimmed.starts_with(b"<") {
        Report::parse_xml(data)
    } else {
        Report::parse_rfc5322(data, MAX_REPORT_BYTES).map_err(|e| format!("no DMARC report found in the message: {e:?}"))
    }
}

fn result_text(result: DmarcResult) -> &'static str {
    match result {
        DmarcResult::Pass => "pass",
        DmarcResult::Fail => "fail",
        DmarcResult::Unspecified => "none",
    }
}

fn disposition_text(disposition: ActionDisposition) -> &'static str {
    match disposition {
        ActionDisposition::Quarantine => "quarantine",
        ActionDisposition::Reject => "reject",
        _ => "none",
    }
}

/// Stores a parsed report. Reports about domains that are not hosted here are refused, so the
/// endpoint cannot be used to fill the database with arbitrary data.
pub async fn store(app: &App, report: &Report) -> Result<Ingested, String> {
    let domain = normalize_domain(report.domain()).ok_or("the report does not name a valid domain")?;
    if !is_local_domain(app, &domain).await.map_err(|_| "database error")? {
        return Err(format!("{domain} is not hosted on this server"));
    }
    let clip = |text: &str, max: usize| -> String { text.chars().filter(|c| !c.is_control()).take(max).collect() };
    let (org, report_id) = (clip(report.org_name(), 200), clip(report.report_id(), 200));
    if org.is_empty() || report_id.is_empty() {
        return Err("the report has no reporter name or report id".into());
    }
    if report.records().len() > MAX_RECORDS {
        return Err("the report has too many records".into());
    }
    let internal = |err: sqlx::Error| {
        tracing::error!(%err, "failed to store DMARC report");
        "database error".to_owned()
    };
    let mut tx = app.db.begin().await.map_err(internal)?;
    let inserted = sqlx::query(
        "INSERT OR IGNORE INTO dmarc_reports (org_name, report_id, domain, date_begin, date_end, policy, received_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&org)
    .bind(&report_id)
    .bind(&domain)
    .bind(report.date_range_begin() as i64)
    .bind(report.date_range_end() as i64)
    .bind(format!("{:?}", report.p()).to_ascii_lowercase())
    .bind(now())
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    if inserted.rows_affected() == 0 {
        return Ok(Ingested::Duplicate);
    }
    let id = inserted.last_insert_rowid();
    for record in report.records() {
        sqlx::query("INSERT INTO dmarc_records (report_id, source_ip, count, disposition, dkim, spf, header_from) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(id)
            .bind(record.source_ip().map(|ip| ip.to_string()).unwrap_or_default())
            .bind(i64::from(record.count()))
            .bind(disposition_text(record.action_disposition()))
            .bind(result_text(record.dmarc_dkim_result()))
            .bind(result_text(record.dmarc_spf_result()))
            .bind(clip(record.header_from(), 255))
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
    }
    tx.commit().await.map_err(internal)?;
    Ok(Ingested::Stored { domain, records: report.records().len() })
}

pub async fn ingest(app: &App, data: &[u8]) -> Result<Ingested, String> {
    let data = data.to_vec();
    // Decompression and XML parsing are CPU bound.
    let report = tokio::task::spawn_blocking(move || parse(&data)).await.map_err(|_| "report parsing failed")??;
    store(app, &report).await
}

/// How long received reports (DMARC and TLS) are kept.
const RETENTION_DAYS: i64 = 400;
/// Report messages accepted per sending domain and day: the big providers send one per domain
/// a day, so this is generous, but it bounds what a single sender can add.
const REPORTS_PER_SENDER_PER_DAY: u32 = 100;

static SENDERS: std::sync::LazyLock<parking_lot::Mutex<std::collections::HashMap<String, (i64, u32)>>> = std::sync::LazyLock::new(Default::default);

/// Today's report counts by sending domain, for a snapshot.
pub fn report_counts() -> std::collections::HashMap<String, (i64, u32)> {
    SENDERS.lock().clone()
}

pub fn restore_report_counts(counts: std::collections::HashMap<String, (i64, u32)>) {
    let today = crate::util::now() / 86400;
    let mut senders = SENDERS.lock();
    for (domain, (day, count)) in counts {
        if day == today {
            senders.entry(domain).or_insert((day, 0)).1 += count;
        }
    }
}

/// Whether a report message from `author_domain` (already authenticated) may be stored today.
pub fn report_allowed(author_domain: &str) -> bool {
    let today = crate::util::now() / 86400;
    let mut senders = SENDERS.lock();
    senders.retain(|_, (day, _)| *day == today);
    let entry = senders.entry(author_domain.to_ascii_lowercase()).or_insert((today, 0));
    entry.1 += 1;
    entry.1 <= REPORTS_PER_SENDER_PER_DAY
}

/// Drops received reports past their retention.
pub async fn prune(app: &App) {
    let cutoff = crate::util::now() - RETENTION_DAYS * 86400;
    let _ = sqlx::query("DELETE FROM dmarc_reports WHERE received_at < ?").bind(cutoff).execute(&app.db).await;
    let _ = sqlx::query("DELETE FROM tls_reports WHERE received_at < ?").bind(cutoff).execute(&app.db).await;
}

/// Called for every accepted inbound message: stores it when it is a DMARC aggregate report.
pub async fn ingest_mail(app: &App, raw: &[u8]) {
    // Cheap pre-filter on the headers; aggregate reports carry "Report Domain:" in the subject.
    let head = String::from_utf8_lossy(&raw[..raw.len().min(8192)]).to_ascii_lowercase();
    if !head.contains("report domain") && !head.contains("dmarc") {
        return;
    }
    match ingest(app, raw).await {
        Ok(Ingested::Stored { domain, records }) => tracing::info!(domain, records, "stored DMARC aggregate report"),
        Ok(Ingested::Duplicate) => {}
        Err(reason) => tracing::debug!(reason, "message is not a usable DMARC report"),
    }
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct ReportRow {
    pub id: i64,
    pub org_name: String,
    pub report_id: String,
    pub domain: String,
    pub date_begin: i64,
    pub date_end: i64,
    pub policy: String,
    pub received_at: i64,
    pub messages: i64,
    pub passed: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct RecordRow {
    pub source_ip: String,
    pub count: i64,
    pub disposition: String,
    pub dkim: String,
    pub spf: String,
    pub header_from: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SourceRow {
    pub source_ip: String,
    pub messages: i64,
    pub passed: i64,
    pub dkim_passed: i64,
    pub spf_passed: i64,
    pub rejected: i64,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct DomainSummary {
    pub domain: String,
    pub reports: i64,
    pub messages: i64,
    /// DMARC passes when either aligned DKIM or aligned SPF passes.
    pub passed: i64,
    pub quarantined: i64,
    pub rejected: i64,
}

/// `domains` is a JSON array of the domain names the caller may see.
pub async fn summary(app: &App, domains: &str, since: i64) -> sqlx::Result<Vec<DomainSummary>> {
    sqlx::query_as(
        "SELECT r.domain, COUNT(DISTINCT r.id) AS reports, COALESCE(SUM(c.count), 0) AS messages,
                COALESCE(SUM(CASE WHEN c.dkim = 'pass' OR c.spf = 'pass' THEN c.count ELSE 0 END), 0) AS passed,
                COALESCE(SUM(CASE WHEN c.disposition = 'quarantine' THEN c.count ELSE 0 END), 0) AS quarantined,
                COALESCE(SUM(CASE WHEN c.disposition = 'reject' THEN c.count ELSE 0 END), 0) AS rejected
         FROM dmarc_reports r LEFT JOIN dmarc_records c ON c.report_id = r.id
         WHERE r.domain IN (SELECT value FROM json_each(?)) AND r.date_end >= ?
         GROUP BY r.domain ORDER BY r.domain",
    )
    .bind(domains)
    .bind(since)
    .fetch_all(&app.db)
    .await
}

pub async fn sources(app: &App, domains: &str, since: i64) -> sqlx::Result<Vec<SourceRow>> {
    sqlx::query_as(
        "SELECT c.source_ip, SUM(c.count) AS messages,
                SUM(CASE WHEN c.dkim = 'pass' OR c.spf = 'pass' THEN c.count ELSE 0 END) AS passed,
                SUM(CASE WHEN c.dkim = 'pass' THEN c.count ELSE 0 END) AS dkim_passed,
                SUM(CASE WHEN c.spf = 'pass' THEN c.count ELSE 0 END) AS spf_passed,
                SUM(CASE WHEN c.disposition = 'reject' THEN c.count ELSE 0 END) AS rejected
         FROM dmarc_records c JOIN dmarc_reports r ON r.id = c.report_id
         WHERE r.domain IN (SELECT value FROM json_each(?)) AND r.date_end >= ?
         GROUP BY c.source_ip ORDER BY messages DESC LIMIT 100",
    )
    .bind(domains)
    .bind(since)
    .fetch_all(&app.db)
    .await
}

pub async fn reports(app: &App, domains: &str, since: i64) -> sqlx::Result<Vec<ReportRow>> {
    sqlx::query_as(
        "SELECT r.id, r.org_name, r.report_id, r.domain, r.date_begin, r.date_end, r.policy, r.received_at,
                COALESCE((SELECT SUM(count) FROM dmarc_records c WHERE c.report_id = r.id), 0) AS messages,
                COALESCE((SELECT SUM(count) FROM dmarc_records c WHERE c.report_id = r.id AND (c.dkim = 'pass' OR c.spf = 'pass')), 0) AS passed
         FROM dmarc_reports r
         WHERE r.domain IN (SELECT value FROM json_each(?)) AND r.date_end >= ?
         ORDER BY r.date_end DESC, r.id DESC LIMIT 500",
    )
    .bind(domains)
    .bind(since)
    .fetch_all(&app.db)
    .await
}

pub async fn records(app: &App, domains: &str, report_id: i64) -> sqlx::Result<Option<Vec<RecordRow>>> {
    let visible: Option<i64> = sqlx::query_scalar("SELECT 1 FROM dmarc_reports WHERE id = ? AND domain IN (SELECT value FROM json_each(?))")
        .bind(report_id)
        .bind(domains)
        .fetch_optional(&app.db)
        .await?;
    if visible.is_none() {
        return Ok(None);
    }
    Ok(Some(
        sqlx::query_as("SELECT source_ip, count, disposition, dkim, spf, header_from FROM dmarc_records WHERE report_id = ? ORDER BY count DESC LIMIT 5000")
            .bind(report_id)
            .fetch_all(&app.db)
            .await?,
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn one_sender_cannot_flood_the_report_tables() {
        for _ in 0..REPORTS_PER_SENDER_PER_DAY {
            assert!(report_allowed("flood.example"));
        }
        assert!(!report_allowed("FLOOD.example"), "the daily allowance is used up");
        assert!(report_allowed("google.com"), "others are not affected");
    }

    pub const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>bigmail.example</org_name><email>noreply-dmarc@bigmail.example</email>
    <report_id>rep-2026-10-11</report_id>
    <date_range><begin>1791676800</begin><end>1791763199</end></date_range>
  </report_metadata>
  <policy_published><domain>example.org</domain><adkim>r</adkim><aspf>r</aspf><p>quarantine</p><sp>none</sp><pct>100</pct></policy_published>
  <record>
    <row><source_ip>203.0.113.10</source_ip><count>40</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.org</header_from></identifiers>
    <auth_results><dkim><domain>example.org</domain><result>pass</result></dkim><spf><domain>example.org</domain><result>pass</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>198.51.100.66</source_ip><count>7</count>
      <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.org</header_from></identifiers>
    <auth_results><spf><domain>spoofer.example</domain><result>fail</result></spf></auth_results>
  </record>
</feedback>"#;

    pub fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn parses_plain_and_compressed_reports() {
        for data in [SAMPLE.as_bytes().to_vec(), gzip(SAMPLE.as_bytes())] {
            let report = parse(&data).unwrap();
            assert_eq!(report.domain(), "example.org");
            assert_eq!(report.org_name(), "bigmail.example");
            assert_eq!(report.records().len(), 2);
            assert_eq!(report.records()[1].count(), 7);
            assert_eq!(disposition_text(report.records()[1].action_disposition()), "quarantine");
            assert_eq!(result_text(report.records()[0].dmarc_dkim_result()), "pass");
        }
    }

    #[test]
    fn rejects_garbage_and_decompression_bombs() {
        assert!(parse(b"<html>not a report</html>").is_err());
        assert!(parse(b"From: a@b.example\r\nSubject: hello\r\n\r\nno report here").is_err());
        assert!(parse(&[0x1f, 0x8b, 0, 1, 2, 3]).is_err());
        assert!(parse(b"PK\x03\x04garbage").is_err());
        let bomb = gzip(&vec![b' '; MAX_REPORT_BYTES + 1024]);
        assert!(bomb.len() < 100_000);
        assert_eq!(parse(&bomb).unwrap_err(), "the report is too large");
    }
}
