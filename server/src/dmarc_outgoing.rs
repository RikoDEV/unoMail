//! DMARC aggregate reports sent by this server (RFC 7489 section 7.2): how mail claiming to
//! come from other domains fared here, once a day to the addresses their policy names.

use mail_auth::report::{
    ActionDisposition, DKIMAuthResult, DkimResult, DmarcResult, PolicyOverride, PolicyOverrideReason, PolicyPublished, Record, Report, SPFAuthResult,
    SPFDomainScope, SpfResult,
};

use crate::{app::App, security::authn::DmarcObservation, util::now};

/// Counts one evaluated message for the day's report to its sender's domain.
pub async fn record(app: &App, observation: &DmarcObservation, source_ip: &str, envelope_from: &str) {
    if observation.rua.is_empty() {
        return;
    }
    let day = now().div_euclid(86_400);
    let domain = &observation.header_from;
    let envelope_domain = envelope_from.rsplit_once('@').map_or(envelope_from, |(_, d)| d).to_ascii_lowercase();
    let counted = sqlx::query(
        "INSERT INTO dmarc_observations (day, domain, source_ip, envelope_from, disposition, dkim, spf, dkim_domain, dkim_result, spf_domain, spf_result, override_reason)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT DO UPDATE SET count = count + 1",
    )
    .bind(day)
    .bind(domain)
    .bind(source_ip)
    .bind(envelope_domain)
    .bind(observation.disposition)
    .bind(observation.dkim)
    .bind(observation.spf)
    .bind(&observation.dkim_domain)
    .bind(&observation.dkim_result)
    .bind(&observation.spf_domain)
    .bind(&observation.spf_result)
    .bind(observation.override_reason.unwrap_or(""))
    .execute(&app.db)
    .await;
    let policy = sqlx::query("INSERT INTO dmarc_policies (day, domain, policy, rua) VALUES (?, ?, ?, ?) ON CONFLICT DO UPDATE SET policy = excluded.policy, rua = excluded.rua")
        .bind(day)
        .bind(domain)
        .bind(&observation.policy)
        .bind(serde_json::to_string(&observation.rua).unwrap_or_default())
        .execute(&app.db)
        .await;
    if let Err(err) = counted.and(policy) {
        tracing::warn!(%err, "could not record a DMARC result");
    }
}

fn dkim_result(value: &str) -> DkimResult {
    match value {
        "pass" => DkimResult::Pass,
        "fail" => DkimResult::Fail,
        "neutral" => DkimResult::Neutral,
        "temperror" => DkimResult::TempError,
        "permerror" => DkimResult::PermError,
        _ => DkimResult::None,
    }
}

fn spf_result(value: &str) -> SpfResult {
    match value {
        "pass" => SpfResult::Pass,
        "fail" => SpfResult::Fail,
        "softfail" => SpfResult::SoftFail,
        "neutral" => SpfResult::Neutral,
        "temperror" => SpfResult::TempError,
        "permerror" => SpfResult::PermError,
        _ => SpfResult::None,
    }
}

fn aligned(value: &str) -> DmarcResult {
    if value == "pass" { DmarcResult::Pass } else { DmarcResult::Fail }
}

type Row = (String, String, String, String, String, String, String, String, String, String, i64);

/// The report for one domain and day, with the addresses it goes to.
pub async fn build_report(app: &App, domain: &str, day: i64) -> sqlx::Result<Option<(Report, Vec<String>)>> {
    let Some((policy, rua)): Option<(String, String)> = sqlx::query_as("SELECT policy, rua FROM dmarc_policies WHERE day = ? AND domain = ?").bind(day).bind(domain).fetch_optional(&app.db).await? else {
        return Ok(None);
    };
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT source_ip, envelope_from, disposition, dkim, spf, dkim_domain, dkim_result, spf_domain, spf_result, override_reason, count
         FROM dmarc_observations WHERE day = ? AND domain = ? ORDER BY count DESC, source_ip LIMIT 10000",
    )
    .bind(day)
    .bind(domain)
    .fetch_all(&app.db)
    .await?;
    if rows.is_empty() {
        return Ok(None);
    }
    let Ok(policy) = serde_json::from_str::<PolicyPublished>(&policy) else { return Ok(None) };
    let organization = app.cfg.hostname.clone();
    let mut report = Report::new()
        .with_org_name(organization.clone())
        .with_email(format!("postmaster@{organization}"))
        .with_report_id(format!("{day}.{domain}@{organization}"))
        .with_date_range_begin((day * 86_400) as u64)
        .with_date_range_end((day * 86_400 + 86_399) as u64)
        .with_policy_published(policy);
    for (source_ip, envelope_from, disposition, dkim, spf, dkim_domain, dkim_res, spf_domain, spf_res, override_reason, count) in rows {
        let mut record = Record::new()
            .with_count(u32::try_from(count).unwrap_or(u32::MAX))
            .with_action_disposition(match disposition.as_str() {
                "reject" => ActionDisposition::Reject,
                "quarantine" => ActionDisposition::Quarantine,
                _ => ActionDisposition::None,
            })
            .with_dmarc_dkim_result(aligned(&dkim))
            .with_dmarc_spf_result(aligned(&spf))
            .with_header_from(domain)
            .with_envelope_from(envelope_from)
            .with_spf_auth_result(SPFAuthResult::new().with_domain(spf_domain).with_scope(SPFDomainScope::MailFrom).with_result(spf_result(&spf_res)));
        if let Ok(ip) = source_ip.parse() {
            record = record.with_source_ip(ip);
        }
        if !dkim_domain.is_empty() {
            record = record.with_dkim_auth_result(DKIMAuthResult::new().with_domain(dkim_domain).with_result(dkim_result(&dkim_res)));
        }
        if override_reason == "trusted_forwarder" {
            record = record.with_policy_override_reason(PolicyOverrideReason::new(PolicyOverride::TrustedForwarder).with_comment("ARC chain sealed by a trusted intermediary"));
        }
        report = report.with_record(record);
    }
    let rua: Vec<String> = serde_json::from_str(&rua).unwrap_or_default();
    Ok(Some((report, rua)))
}

/// Whether a report about `domain` may go to an address at `rua_domain`: the same domain (or
/// one within the other), or one that says it accepts reports for it (RFC 7489 section 7.1).
pub async fn destination_allowed(app: &App, domain: &str, rua_domain: &str) -> bool {
    let (domain, rua_domain) = (domain.to_ascii_lowercase(), rua_domain.to_ascii_lowercase());
    if domain == rua_domain || domain.ends_with(&format!(".{rua_domain}")) || rua_domain.ends_with(&format!(".{domain}")) {
        return true;
    }
    let Some(resolver) = &app.authenticator else { return false };
    let name = format!("{domain}._report._dmarc.{rua_domain}");
    crate::dns::txt(resolver, &name).await.unwrap_or_default().iter().any(|record| record.trim_start().to_ascii_lowercase().starts_with("v=dmarc1"))
}

/// Sends yesterday's (and any missed) aggregate reports. Run hourly; each day is sent once.
pub async fn send_reports(app: &App) {
    let today = now().div_euclid(86_400);
    let days: Vec<i64> = sqlx::query_scalar("SELECT DISTINCT day FROM dmarc_policies WHERE day < ? AND day NOT IN (SELECT day FROM report_runs WHERE kind = 'dmarc') ORDER BY day")
        .bind(today)
        .fetch_all(&app.db)
        .await
        .unwrap_or_default();
    let Some((sender, sender_domain)) = crate::smtp::transport::report_sender(app).await else { return };
    for day in days {
        let domains: Vec<String> = sqlx::query_scalar("SELECT domain FROM dmarc_policies WHERE day = ?").bind(day).fetch_all(&app.db).await.unwrap_or_default();
        for domain in domains {
            let Ok(Some((report, rua))) = build_report(app, &domain, day).await else { continue };
            for uri in rua {
                // `mailto:reports@example.org!10m`: the size limit is ignored, reports are small.
                let mailbox = uri["mailto:".len().min(uri.len())..].split('!').next().unwrap_or_default().to_owned();
                let Some((_, rua_domain)) = mailbox.rsplit_once('@') else { continue };
                if !destination_allowed(app, &domain, rua_domain).await {
                    tracing::info!(domain, mailbox, "DMARC report address not authorized by its domain");
                    continue;
                }
                let mut raw = Vec::new();
                let result = match report.write_rfc5322(&app.cfg.hostname, sender.as_str(), std::iter::once(mailbox.as_str()), &mut raw) {
                    Ok(()) => crate::smtp::transport::send_system_mail(app, &sender_domain, &mailbox, raw).await,
                    Err(err) => Err(anyhow::anyhow!("{err}")),
                };
                if let Err(err) = result {
                    tracing::info!(%err, domain, "DMARC report not sent");
                }
            }
        }
        let _ = sqlx::query("INSERT OR IGNORE INTO report_runs (kind, day) VALUES ('dmarc', ?)").bind(day).execute(&app.db).await;
    }
    let _ = sqlx::query("DELETE FROM dmarc_observations WHERE day < ?").bind(today - 7).execute(&app.db).await;
    let _ = sqlx::query("DELETE FROM dmarc_policies WHERE day < ?").bind(today - 7).execute(&app.db).await;
}
