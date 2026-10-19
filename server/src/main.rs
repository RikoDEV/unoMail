//! unoMail server binary.

use std::{net::SocketAddr, time::Duration};

use anyhow::Context;
use mail_auth::MessageAuthenticator;
use tokio::net::TcpListener;
use unomail::{
    acme, api, imap, pop3,
    app::{App, AppState},
    config::Config,
    directory, http,
    security::outbound,
    smtp::{self, server::Mode},
    util::now,
};

async fn bind(cfg: &Config, port: u16, name: &str) -> anyhow::Result<TcpListener> {
    let addr = SocketAddr::new(cfg.bind, port);
    let listener = TcpListener::bind(addr).await.with_context(|| format!("cannot bind {name} listener on {addr}"))?;
    tracing::info!(%addr, "{name} listening");
    Ok(listener)
}

/// Daily reports to other domains (sent once per day, checked every hour).
async fn reports(app: AppState) {
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        if app.rt().tls_reports_enabled {
            unomail::smtp::transport::send_reports(&app).await;
        }
        if app.rt().dmarc_reports_enabled {
            unomail::dmarc_outgoing::send_reports(&app).await;
        }
    }
}

/// Periodic housekeeping: expired sessions, stale greylist entries, old logs, orphaned blobs.
async fn maintenance(app: AppState) {
    loop {
        tokio::time::sleep(Duration::from_secs(900)).await;
        app.limiter.prune();
        smtp::delivery::prune_greylist(&app).await;
        unomail::security::access::prune(&app).await;
        outbound::prune(&app).await;
        unomail::api::avatar::prune(&app).await;
        unomail::dmarc_reports::prune(&app).await;
        // Delivery and audit logs are kept as long as the administrator set.
        let cutoff = now() - app.rt().log_retention_days * 86400;
        for sql in [
            "DELETE FROM sessions WHERE expires_at <= ?",
            "DELETE FROM delivery_log WHERE ts < ?",
            "DELETE FROM audit_log WHERE ts < ?",
        ] {
            let bound = if sql.contains("sessions") { now() } else { cutoff };
            if let Err(err) = sqlx::query(sql).bind(bound).execute(&app.db).await {
                tracing::warn!(%err, "maintenance query failed");
            }
        }
        if let Err(err) = app.store.prune_changes(200_000).await {
            tracing::warn!(%err, "change log pruning failed");
        }
        if let Err(err) = unomail::jmap::objects::prune(&app.db, 200_000).await {
            tracing::warn!(%err, "JMAP change log pruning failed");
        }
        let expired = unomail::retention::run(&app).await;
        if expired > 0 {
            tracing::info!(expired, "emptied old messages from Trash and Junk");
        }
        match app.store.gc_blobs().await {
            Ok(removed) if removed > 0 => tracing::info!(removed, "removed unreferenced message blobs"),
            Ok(_) => {}
            Err(err) => tracing::warn!(%err, "blob garbage collection failed"),
        }
        unomail::db::checkpoint(&app.db).await;
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("cannot install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

const USAGE: &str = "usage: unomail [command]

Without a command, runs the server. Commands (configured by the same UNOMAIL_* variables):
  backup                      take a backup now (UNOMAIL_BACKUP_DIR or UNOMAIL_BACKUP_S3_*)
  backups                     list the snapshots at the backup target
  restore [SNAPSHOT] [--force]
                              restore a snapshot (default: the latest) into the data
                              directory; run with the server stopped
  migrate-blobs [--from DIR]  copy message contents into the configured store (e.g. from
                              the old blobs directory after switching to S3) and bring them
                              into the configured form (sealed with UNOMAIL_ENCRYPT_MAIL)
  help                        show this text";

/// One-off administrative commands.
async fn run_command(cfg: Config, command: &str, args: &[String]) -> anyhow::Result<()> {
    match command {
        "backup" => {
            let app = App::new(cfg, None).await?;
            let outcome = unomail::backup::run(&app).await?;
            println!("snapshot {}: {} new message files ({} bytes) copied, {} old snapshots removed", outcome.snapshot, outcome.blobs_copied, outcome.bytes_copied, outcome.snapshots_removed);
            if outcome.blobs_missing > 0 {
                println!("warning: {} message files were missing from the store", outcome.blobs_missing);
            }
        }
        "backups" => {
            let target = unomail::backup::Target::from_config(cfg.backup_target.as_ref().context("no backup target is configured")?)?;
            for id in target.snapshots().await? {
                match target.manifest(&id).await? {
                    Some(m) => println!("{id}  {} messages  database {} bytes{}", m.blobs, m.database_bytes, if m.encrypted_mail { "  (encrypted mail: needs blob.key)" } else { "" }),
                    None => println!("{id}"),
                }
            }
        }
        "restore" => {
            let force = args.iter().any(|a| a == "--force");
            let snapshot = args.iter().find(|a| !a.starts_with("--")).map(String::as_str);
            println!("{}", unomail::backup::restore(&cfg, snapshot, force).await?);
        }
        "migrate-blobs" => {
            let from = match args {
                [] => None,
                [flag, dir] if flag == "--from" => Some(std::path::PathBuf::from(dir)),
                _ => anyhow::bail!("{USAGE}"),
            };
            let app = App::new(cfg, None).await?;
            let written = unomail::backup::migrate_blobs(&app, from).await?;
            println!("{written} message files written to {}", app.store.blobs.describe());
        }
        "help" | "--help" | "-h" => println!("{USAGE}"),
        other => anyhow::bail!("unknown command {other:?}\n\n{USAGE}"),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_env("UNOMAIL_LOG").unwrap_or_else(|_| "info,rustls=error".into());
    {
        use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};
        let output = if std::env::var("UNOMAIL_LOG_FORMAT").is_ok_and(|v| v == "json") {
            tracing_subscriber::fmt::layer().json().boxed()
        } else {
            // Colour only when a person is watching; log collectors get plain text.
            let ansi = std::io::IsTerminal::is_terminal(&std::io::stdout());
            tracing_subscriber::fmt::layer().with_ansi(ansi).boxed()
        };
        // The same events also feed the system log viewer of the admin panel.
        // Spans go to an OpenTelemetry collector when one is configured.
        tracing_subscriber::registry().with(filter).with(output).with(unomail::logstream::SystemLogLayer).with(unomail::telemetry::from_env()).init();
    }
    // Libraries that build their own TLS configuration use the process-wide provider.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cfg = Config::from_env()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(command) = args.first() {
        return run_command(cfg, command, &args[1..]).await;
    }
    let authenticator = MessageAuthenticator::new_system_conf()
        .or_else(|err| {
            tracing::warn!(%err, "system DNS configuration is unusable, falling back to Cloudflare DNS");
            MessageAuthenticator::new_cloudflare_tls()
        })
        .context("cannot initialize a DNS resolver")?;
    let app = App::new(cfg, Some(authenticator)).await?;
    directory::bootstrap_admin(&app).await?;
    directory::ensure_postmasters(&app).await;
    unomail::import::recover(&app).await;

    // Bind everything before starting any service so misconfiguration fails fast.
    let cfg = &app.cfg;
    let smtp = bind(cfg, cfg.smtp_port, "SMTP").await?;
    let submission = bind(cfg, cfg.submission_port, "submission").await?;
    let smtps = bind(cfg, cfg.smtps_port, "SMTPS").await?;
    let imaps = bind(cfg, cfg.imaps_port, "IMAPS").await?;
    let imap_starttls = bind(cfg, cfg.imap_port, "IMAP").await?;
    let pop3s = bind(cfg, cfg.pop3s_port, "POP3S").await?;
    let sieve = if cfg.sieve_port == 0 { None } else { Some(bind(cfg, cfg.sieve_port, "ManageSieve").await?) };
    let lmtp = if cfg.lmtp_port == 0 { None } else { Some(bind(cfg, cfg.lmtp_port, "LMTP").await?) };
    let http_listener = bind(cfg, cfg.http_port, "HTTP").await?;
    let https_listener = bind(cfg, cfg.https_port, "HTTPS").await?;

    tokio::spawn(smtp::server::serve(app.clone(), Mode::Mx, smtp));
    tokio::spawn(smtp::server::serve(app.clone(), Mode::Submission, submission));
    tokio::spawn(smtp::server::serve(app.clone(), Mode::Smtps, smtps));
    tokio::spawn(imap::serve(app.clone(), imaps));
    tokio::spawn(imap::serve_starttls(app.clone(), imap_starttls));
    tokio::spawn(pop3::serve(app.clone(), pop3s));
    if let Some(lmtp) = lmtp {
        tokio::spawn(smtp::server::serve(app.clone(), Mode::Lmtp, lmtp));
    }
    if let Some(sieve) = sieve {
        tokio::spawn(unomail::managesieve::serve(app.clone(), sieve));
    }
    tokio::spawn(smtp::queue::run(app.clone()));
    tokio::spawn(unomail::search::backfill(app.clone()));
    tokio::spawn(unomail::jmap::push::run(app.clone()));
    tokio::spawn(unomail::jmap::submission::run(app.clone()));
    tokio::spawn(unomail::snooze::run(app.clone()));
    tokio::spawn(reports(app.clone()));
    tokio::spawn(unomail::backup::schedule(app.clone()));
    tokio::spawn(acme::renewal_loop(app.clone()));
    tokio::spawn(maintenance(app.clone()));
    tokio::spawn(unomail::sysstat::run(app.clone()));
    tokio::spawn(unomail::dailystats::run(app.clone()));
    tokio::spawn(unomail::security::reputation::monitor(app.clone()));
    tokio::spawn(unomail::security::reputation::report_offenders(app.clone()));

    let router = api::router(app.clone());
    let plain = if cfg.http_redirect { api::redirect_router(app.clone()) } else { router.clone() };
    tokio::spawn(http::serve(http_listener, plain, None));
    tokio::spawn(http::serve(https_listener, router, Some(app.tls.server_config(&[b"h2", b"http/1.1"]))));

    tracing::info!(hostname = cfg.hostname, "unoMail is ready");
    shutdown_signal().await;
    tracing::info!("shutting down");
    // The last minute of connection counts.
    unomail::dailystats::flush(&app).await;
    app.db.close().await;
    Ok(())
}
