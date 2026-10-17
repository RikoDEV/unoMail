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

impl Metrics {
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
        let tls = TlsManager::load(db.clone(), &cfg.hostname).await?;
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(
                rustls::ClientConfig::builder_with_provider(crate::tls::provider())
                    .with_safe_default_protocol_versions()?
                    .with_root_certificates(rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() })
                    .with_no_client_auth(),
            )
            .timeout(std::time::Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let secrets = Arc::new(crate::secretbox::SecretBox::load(&cfg.data_dir)?);
        let filter_client = |socket: &Option<std::path::PathBuf>| -> anyhow::Result<reqwest::Client> {
            let builder = reqwest::Client::builder().no_proxy().timeout(std::time::Duration::from_secs(30)).redirect(reqwest::redirect::Policy::none())
                .use_preconfigured_tls((*crate::smtp::client::tls_config(true)).clone());
            #[cfg(unix)]
            let builder = match socket { Some(path) => builder.unix_socket(path.clone()), None => builder };
            #[cfg(not(unix))]
            anyhow::ensure!(socket.is_none(), "Rspamd Unix sockets require Unix");
            Ok(builder.build()?)
        };
        let filter_http = filter_client(&cfg.rspamd_socket)?;
        let filter_controller_http = filter_client(&cfg.rspamd_controller_socket)?;
        let settings = ArcSwap::from_pointee(crate::settings::load(&db, &cfg).await?);
        Ok(Arc::new(App {
            cfg,
            settings,
            db,
            store,
            tls,
            limiter: LoginLimiter::default(),
            abuse: Default::default(),
            challenges: Default::default(),
            oauth: Default::default(),
            metrics: Metrics::default(),
            daily: Default::default(),
            authenticator,
            queue_wake: Notify::new(),
            http,
            filter_http,
            filter_controller_http,
            secrets,
            activity: Default::default(),
            access: Default::default(),
            started_at: now(),
            connections: Mutex::new(HashMap::new()),
            webhooks: std::sync::OnceLock::new(),
        }))
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
