//! Shared application state.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
};

use arc_swap::ArcSwap;
use mail_auth::MessageAuthenticator;
use parking_lot::Mutex;
use sqlx::SqlitePool;
use tokio::sync::Notify;

use crate::{auth::LoginLimiter, config::Config, settings::Runtime, store::Store, tls::TlsManager, util::now};

#[derive(Default)]
pub struct Metrics {
    pub smtp_connections: AtomicU64,
    pub imap_connections: AtomicU64,
    pub pop3_connections: AtomicU64,
    pub active_connections: AtomicI64,
    pub messages_received: AtomicU64,
    pub messages_delivered_local: AtomicU64,
    pub messages_sent: AtomicU64,
    pub messages_bounced: AtomicU64,
    pub messages_rejected: AtomicU64,
    pub spam_blocked: AtomicU64,
    pub auth_failures: AtomicU64,
    pub http_requests: AtomicU64,
    pub deliveries_deferred: AtomicU64,
    pub jmap_calls: AtomicU64,
    pub imap_commands: AtomicU64,
    pub http_duration: Histogram,
    pub delivery_duration: Histogram,
}

/// Upper bounds (seconds) of the latency buckets; Prometheus adds `+Inf`.
pub const LATENCY_BUCKETS: [f64; 11] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

/// A Prometheus histogram over [`LATENCY_BUCKETS`], updated without locks.
#[derive(Default)]
pub struct Histogram {
    /// Observations at or below each bound (not cumulative; summed when rendered).
    buckets: [AtomicU64; LATENCY_BUCKETS.len()],
    count: AtomicU64,
    /// Sum of all observations in microseconds.
    sum_micros: AtomicU64,
}

impl Histogram {
    pub fn observe(&self, elapsed: std::time::Duration) {
        let secs = elapsed.as_secs_f64();
        if let Some(index) = LATENCY_BUCKETS.iter().position(|bound| secs <= *bound) {
            self.buckets[index].fetch_add(1, Ordering::Relaxed);
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_micros.fetch_add(elapsed.as_micros().min(u128::from(u64::MAX)) as u64, Ordering::Relaxed);
    }

    /// The histogram in the Prometheus text format, under `name`.
    pub fn render(&self, name: &str, help: &str) -> String {
        let mut out = format!("# HELP {name} {help}\n# TYPE {name} histogram\n");
        let mut cumulative = 0;
        for (bound, bucket) in LATENCY_BUCKETS.iter().zip(&self.buckets) {
            cumulative += bucket.load(Ordering::Relaxed);
            out.push_str(&format!("{name}_bucket{{le=\"{bound}\"}} {cumulative}\n"));
        }
        let count = self.count.load(Ordering::Relaxed);
        out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {count}\n"));
        out.push_str(&format!("{name}_sum {}\n{name}_count {count}\n", self.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0));
        out
    }
}

impl Histogram {
    fn cells(&self) -> impl Iterator<Item = (String, &AtomicU64)> {
        self.buckets.iter().enumerate().map(|(i, b)| (format!("bucket{i}"), b)).chain([("count".to_string(), &self.count), ("sum_micros".to_string(), &self.sum_micros)])
    }
}

impl Metrics {
    /// Every cumulative counter by its stored name (the connection gauge is not one).
    fn cells(&self) -> Vec<(String, &AtomicU64)> {
        let mut cells: Vec<(String, &AtomicU64)> = [
            ("smtp_connections", &self.smtp_connections),
            ("imap_connections", &self.imap_connections),
            ("pop3_connections", &self.pop3_connections),
            ("messages_received", &self.messages_received),
            ("messages_delivered_local", &self.messages_delivered_local),
            ("messages_sent", &self.messages_sent),
            ("messages_bounced", &self.messages_bounced),
            ("messages_rejected", &self.messages_rejected),
            ("spam_blocked", &self.spam_blocked),
            ("auth_failures", &self.auth_failures),
            ("http_requests", &self.http_requests),
            ("deliveries_deferred", &self.deliveries_deferred),
            ("jmap_calls", &self.jmap_calls),
            ("imap_commands", &self.imap_commands),
        ]
        .into_iter()
        .map(|(name, cell)| (name.to_string(), cell))
        .collect();
        cells.extend(self.http_duration.cells().map(|(n, c)| (format!("http_duration.{n}"), c)));
        cells.extend(self.delivery_duration.cells().map(|(n, c)| (format!("delivery_duration.{n}"), c)));
        cells
    }

    /// Adds the counts saved by an earlier run.
    pub async fn load(&self, db: &SqlitePool) -> sqlx::Result<()> {
        let saved: HashMap<String, i64> = sqlx::query_as("SELECT name, value FROM metric_counters").fetch_all(db).await?.into_iter().collect();
        for (name, cell) in self.cells() {
            if let Some(value) = saved.get(&name) {
                cell.fetch_add(u64::try_from(*value).unwrap_or(0), Ordering::Relaxed);
            }
        }
        Ok(())
    }

    pub async fn save(&self, db: &SqlitePool) -> sqlx::Result<()> {
        let mut tx = db.begin().await?;
        for (name, cell) in self.cells() {
            sqlx::query("INSERT INTO metric_counters (name, value) VALUES (?, ?) ON CONFLICT (name) DO UPDATE SET value = excluded.value")
                .bind(name)
                .bind(i64::try_from(cell.load(Ordering::Relaxed)).unwrap_or(i64::MAX))
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await
    }

    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// Decrements the active connection gauge when a protocol session ends.
pub struct ConnectionGuard(Arc<App>, String);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
        let mut conns = self.0.connections.lock();
        if let Some(entry) = conns.get_mut(&self.1) {
            entry.active = entry.active.saturating_sub(1);
        }
    }
}

#[derive(Default)]
struct IpConnections {
    active: u32,
    window_start: i64,
    recent: u32,
}

pub const MAX_CONNECTIONS_PER_IP: u32 = 20;
pub const MAX_CONNECTIONS_PER_IP_PER_MINUTE: u32 = 60;

pub struct App {
    pub cfg: Config,
    /// Settings administrators can change while the server runs.
    pub settings: ArcSwap<Runtime>,
    pub db: SqlitePool,
    pub store: Store,
    pub tls: Arc<TlsManager>,
    pub limiter: LoginLimiter,
    /// SMTP abuse waiting to be reported to AbuseIPDB.
    pub abuse: crate::security::reputation::AbuseQueue,
    /// Passkey challenges waiting for an answer.
    pub challenges: crate::twofactor::Challenges,
    /// Single sign-on discovery, pending sign-ins and verified tokens.
    pub oauth: crate::oauth::Caches,
    pub metrics: Metrics,
    /// DNS-backed SPF/DKIM/DMARC verifier. `None` disables inbound sender authentication
    /// (used by tests, which must not depend on external DNS).
    pub authenticator: Option<MessageAuthenticator>,
    /// Wakes the outbound queue worker when new mail is enqueued.
    pub queue_wake: Notify,
    pub http: reqwest::Client,
    pub filter_http: reqwest::Client,
    pub filter_controller_http: reqwest::Client,
    /// Key for credentials that are stored encrypted (see `secretbox`).
    pub secrets: Arc<crate::secretbox::SecretBox>,
    /// Recently seen remote addresses and SMTP replies (dashboard).
    pub activity: crate::activity::Activity,
    /// SMTP blacklist and whitelist rules.
    pub access: crate::security::access::AccessList,
    /// Connection counts for the dashboard's daily statistics, not yet written.
    pub daily: crate::dailystats::Pending,
    pub started_at: i64,
    connections: Mutex<HashMap<String, IpConnections>>,
    /// Events waiting for the webhook worker, which starts with the first one.
    pub webhooks: std::sync::OnceLock<tokio::sync::mpsc::Sender<(&'static str, serde_json::Value)>>,
}

pub type AppState = Arc<App>;

/// The message store the configuration asks for: S3 or `<data>/blobs`, sealed or not.
pub fn blob_backend(cfg: &Config) -> anyhow::Result<crate::blobstore::Blobs> {
    use crate::blobstore::{Backend, Blobs};
    let backend = match &cfg.blob_s3 {
        Some(s3) => Backend::S3(crate::s3::S3::new(s3.clone())?),
        None => {
            let dir = cfg.data_dir.join("blobs");
            std::fs::create_dir_all(&dir)?;
            Backend::Disk(dir)
        }
    };
    // An existing key is always loaded, so mail sealed earlier stays readable after
    // encryption is switched off again.
    let key_exists = cfg.data_dir.join("blob.key").exists();
    let key = if cfg.encrypt_mail || key_exists { Some(crate::blobstore::load_key(&cfg.data_dir)?) } else { None };
    let blobs = Blobs::new(backend, key);
    Ok(if cfg.encrypt_mail { blobs } else { blobs.read_only_key() })
}

impl App {
    pub async fn new(cfg: Config, authenticator: Option<MessageAuthenticator>) -> anyhow::Result<AppState> {
        std::fs::create_dir_all(&cfg.data_dir)?;
        restrict_permissions(&cfg.data_dir);
        let db = crate::db::open(&cfg.data_dir.join("unomail.db")).await?;
        let store = Store::with_blobs(db.clone(), blob_backend(&cfg)?);
        let secrets = Arc::new(crate::secretbox::SecretBox::load(&cfg.data_dir)?);
        crate::secretbox::seal_plaintext(&db, &secrets).await?;
        let tls = TlsManager::load(db.clone(), secrets.clone(), &cfg.hostname).await?;
        let http = crate::outbound::builder()
            .timeout(std::time::Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let filter_client = |socket: &Option<std::path::PathBuf>| -> anyhow::Result<reqwest::Client> {
            let builder = crate::outbound::builder().no_proxy().timeout(std::time::Duration::from_secs(30)).redirect(reqwest::redirect::Policy::none());
            #[cfg(unix)]
            let builder = match socket { Some(path) => builder.unix_socket(path.clone()), None => builder };
            #[cfg(not(unix))]
            anyhow::ensure!(socket.is_none(), "Rspamd Unix sockets require Unix");
            Ok(builder.build()?)
        };
        let filter_http = filter_client(&cfg.rspamd_socket)?;
        let filter_controller_http = filter_client(&cfg.rspamd_controller_socket)?;
        let settings = ArcSwap::from_pointee(crate::settings::load(&db, &cfg).await?);
        let limiter = LoginLimiter::with_limits(settings.load().login_limits());
        limiter.load(&db).await?;
        let metrics = Metrics::default();
        metrics.load(&db).await?;
        let activity = crate::activity::Activity::default();
        let abuse = crate::security::reputation::AbuseQueue::default();
        if let Some(saved) = crate::snapshot::load(&db, "activity").await? {
            activity.restore(saved);
        }
        if let Some(saved) = crate::snapshot::load(&db, "abuse_pending").await? {
            abuse.restore(saved);
        }
        if let Some(saved) = crate::snapshot::load(&db, "login_offenders").await? {
            limiter.restore_offenders(saved);
        }
        if let Some(saved) = crate::snapshot::load(&db, "report_counts").await? {
            crate::dmarc_reports::restore_report_counts(saved);
        }
        if let Some(saved) = crate::snapshot::load(&db, "logs").await? {
            crate::logstream::restore(saved);
        }
        Ok(Arc::new(App {
            cfg,
            settings,
            db,
            store,
            tls,
            limiter,
            abuse,
            challenges: Default::default(),
            oauth: Default::default(),
            metrics,
            daily: Default::default(),
            authenticator,
            queue_wake: Notify::new(),
            http,
            filter_http,
            filter_controller_http,
            secrets,
            activity,
            access: Default::default(),
            started_at: now(),
            connections: Mutex::new(HashMap::new()),
            webhooks: std::sync::OnceLock::new(),
        }))
    }

    /// Writes the counters and login limiter state that must survive a restart.
    pub async fn save_state(&self) {
        if let Err(err) = self.metrics.save(&self.db).await {
            tracing::warn!(%err, "metric counters not saved");
        }
        if let Err(err) = self.limiter.save(&self.db).await {
            tracing::warn!(%err, "login limiter state not saved");
        }
        let snapshots = [
            ("activity", serde_json::to_value(self.activity.snapshot())),
            ("abuse_pending", serde_json::to_value(self.abuse.snapshot())),
            ("login_offenders", serde_json::to_value(self.limiter.pending_offenders())),
            ("report_counts", serde_json::to_value(crate::dmarc_reports::report_counts())),
            ("logs", serde_json::to_value(crate::logstream::snapshot())),
        ];
        for (name, value) in snapshots {
            let result = match value {
                Ok(value) => crate::snapshot::save(&self.db, name, &value).await,
                Err(err) => Err(sqlx::Error::Encode(Box::new(err))),
            };
            if let Err(err) = result {
                tracing::warn!(%err, name, "state snapshot not saved");
            }
        }
    }

    /// The current runtime settings.
    pub fn rt(&self) -> Arc<Runtime> {
        self.settings.load_full()
    }

    /// Registers a new protocol connection from `ip`, or refuses it when the address already
    /// holds too many connections or is connecting too quickly.
    pub fn accept_connection(self: &Arc<Self>, ip: IpAddr) -> Option<ConnectionGuard> {
        self.activity.connection(ip);
        let now = now();
        let mut conns = self.connections.lock();
        if self.metrics.active_connections.load(Ordering::Relaxed) >= 1024 { return None; }
        let network = crate::auth::network(ip);
        if conns.len() >= 50_000 {
            conns.retain(|_, c| c.active > 0 || now - c.window_start < 60);
            if conns.len() >= 50_000 && !conns.contains_key(&network) { return None; }
        }
        let entry = conns.entry(network.clone()).or_default();
        if now - entry.window_start >= 60 {
            entry.window_start = now;
            entry.recent = 0;
        }
        // Loopback is exempt: health checks, the bundled filter and tests all originate there.
        if !ip.is_loopback() && (entry.active >= MAX_CONNECTIONS_PER_IP || entry.recent >= MAX_CONNECTIONS_PER_IP_PER_MINUTE) {
            return None;
        }
        entry.active += 1;
        entry.recent += 1;
        self.metrics.active_connections.fetch_add(1, Ordering::Relaxed);
        Some(ConnectionGuard(self.clone(), network))
    }
}

/// The data directory holds private keys and mail; keep it private to the service user.
fn restrict_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(err) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)) {
            tracing::warn!(%err, "could not restrict permissions on the data directory");
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn metric_counters_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::open(&dir.path().join("t.db")).await.unwrap();
        let metrics = Metrics::default();
        Metrics::inc(&metrics.messages_sent);
        Metrics::inc(&metrics.messages_sent);
        metrics.http_duration.observe(std::time::Duration::from_millis(30));
        metrics.save(&db).await.unwrap();

        let restarted = Metrics::default();
        restarted.load(&db).await.unwrap();
        assert_eq!(Metrics::get(&restarted.messages_sent), 2);
        assert_eq!(restarted.http_duration.render("h", ""), metrics.http_duration.render("h", ""));
    }

    #[tokio::test]
    async fn snapshots_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::open(&dir.path().join("t.db")).await.unwrap();
        let ip: IpAddr = "198.51.100.4".parse().unwrap();
        let activity = crate::activity::Activity::default();
        activity.connection(ip);
        activity.reply(ip, "250 2.0.0 OK snapshot-marker");
        let abuse = crate::security::reputation::AbuseQueue::default();
        abuse.restore(vec![(ip, crate::security::reputation::Abuse::Spam)]);
        crate::snapshot::save(&db, "activity", &activity.snapshot()).await.unwrap();
        crate::snapshot::save(&db, "abuse_pending", &abuse.snapshot()).await.unwrap();

        let restarted = crate::activity::Activity::default();
        restarted.restore(crate::snapshot::load(&db, "activity").await.unwrap().unwrap());
        assert_eq!(restarted.recent_ips(10)[0].0, ip);
        assert_eq!(restarted.recent_replies(10)[0].text, "2.0.0 OK snapshot-marker");
        let queue = crate::security::reputation::AbuseQueue::default();
        queue.restore(crate::snapshot::load(&db, "abuse_pending").await.unwrap().unwrap());
        assert_eq!(queue.snapshot(), abuse.snapshot());
        assert_eq!(crate::snapshot::load::<Vec<i64>>(&db, "missing").await.unwrap(), None);
    }
}
