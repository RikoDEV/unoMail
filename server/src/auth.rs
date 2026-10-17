//! Password hashing, brute-force limiting and the credential check shared by every protocol.

use std::{collections::HashMap, net::IpAddr, sync::LazyLock};

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use parking_lot::Mutex;
use serde::Serialize;
use sqlx::SqlitePool;

use crate::util::now;

pub const MIN_PASSWORD_LEN: usize = 10;
pub const MAX_PASSWORD_LEN: usize = 256;

/// Hash verified when the account does not exist, so that response time does not reveal
/// which addresses are valid.
static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| hash_password_sync("unomail-dummy-password").expect("hashing a constant cannot fail"));

pub fn validate_new_password(password: &str) -> Result<(), &'static str> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err("password must be at least 10 characters long");
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err("password is too long");
    }
    if password.chars().any(|c| c.is_control()) {
        return Err("password must not contain control characters");
    }
    Ok(())
}

fn hash_password_sync(password: &str) -> anyhow::Result<String> {
    let hash = Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow::anyhow!("password hashing failed: {e}"))?;
    Ok(hash.to_string())
}

fn verify_password_sync(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

/// Argon2id is deliberately slow; keep it off the async executor.
pub async fn hash_password(password: &str) -> anyhow::Result<String> {
    let password = password.to_owned();
    tokio::task::spawn_blocking(move || hash_password_sync(&password)).await?
}

pub async fn verify_password(password: &str, hash: &str) -> bool {
    let (password, hash) = (password.to_owned(), hash.to_owned());
    tokio::task::spawn_blocking(move || verify_password_sync(&password, &hash)).await.unwrap_or(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "TEXT", rename_all = "snake_case")]
pub enum Role {
    User,
    DomainAdmin,
    SuperAdmin,
}

impl Role {
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "user" => Some(Role::User),
            "domain_admin" => Some(Role::DomainAdmin),
            "super_admin" => Some(Role::SuperAdmin),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::DomainAdmin => "domain_admin",
            Role::SuperAdmin => "super_admin",
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Account {
    pub id: i64,
    pub domain_id: i64,
    pub email: String,
    pub display_name: String,
    pub password_hash: String,
    pub role: Role,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub enabled: bool,
    pub imap_enabled: bool,
    pub pop3_enabled: bool,
    pub smtp_enabled: bool,
    pub outbound_blocked: bool,
}

const ACCOUNT_COLUMNS: &str = "SELECT a.id, a.domain_id, a.email, a.display_name, a.password_hash, a.role, a.quota_bytes, \
     a.used_bytes, a.enabled, a.imap_enabled, a.pop3_enabled, a.smtp_enabled, a.outbound_blocked FROM accounts a";

impl Account {
    pub async fn by_email(db: &SqlitePool, email: &str) -> sqlx::Result<Option<Account>> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!("{ACCOUNT_COLUMNS} WHERE a.email = ?")))
            .bind(email)
            .fetch_optional(db)
            .await
    }

    pub async fn by_id(db: &SqlitePool, id: i64) -> sqlx::Result<Option<Account>> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!("{ACCOUNT_COLUMNS} WHERE a.id = ?")))
            .bind(id)
            .fetch_optional(db)
            .await
    }

    /// Looks up an enabled account in an enabled domain by session token hash.
    pub async fn by_session(db: &SqlitePool, token_hash: &str) -> sqlx::Result<Option<(Account, String)>> {
        let sql = format!(
            "{ACCOUNT_COLUMNS} JOIN sessions s ON s.account_id = a.id JOIN domains d ON d.id = a.domain_id \
             WHERE s.token_hash = ? AND s.expires_at > ? AND a.enabled = 1 AND d.enabled = 1"
        );
        let Some(account) =
            sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(sql)).bind(token_hash).bind(now()).fetch_optional(db).await?
        else {
            return Ok(None);
        };
        let csrf: String = sqlx::query_scalar("SELECT csrf_token FROM sessions WHERE token_hash = ?")
            .bind(token_hash)
            .fetch_one(db)
            .await?;
        Ok(Some((account, csrf)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Web,
    Smtp,
    Imap,
    Pop3,
    /// CalDAV and CardDAV.
    Dav,
    /// JMAP with HTTP Basic authentication (programs; the web client uses its session).
    Jmap,
    /// ManageSieve.
    Sieve,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Web => "web",
            Protocol::Smtp => "smtp",
            Protocol::Imap => "imap",
            Protocol::Pop3 => "pop3",
            Protocol::Dav => "dav",
            Protocol::Jmap => "jmap",
            Protocol::Sieve => "sieve",
        }
    }

    /// The app password scope that covers this protocol.
    pub fn scope(self) -> Option<&'static str> {
        match self {
            Protocol::Web => None,
            Protocol::Smtp | Protocol::Imap | Protocol::Pop3 | Protocol::Sieve => Some("mail"),
            Protocol::Dav => Some("dav"),
            Protocol::Jmap => Some("jmap"),
        }
    }

    /// Whether the account lets this protocol in at all.
    pub fn allowed_for(self, account: &Account) -> bool {
        match self {
            Protocol::Web | Protocol::Dav | Protocol::Jmap => true,
            Protocol::Smtp => account.smtp_enabled,
            Protocol::Imap | Protocol::Sieve => account.imap_enabled,
            Protocol::Pop3 => account.pop3_enabled,
        }
    }
}

/// What a successful sign-in was made with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credential {
    Password,
    /// The app password with this id.
    AppPassword(i64),
}

/// How often a long-lived protocol connection checks that its sign-in still holds.
pub const RECHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// What a protocol connection (IMAP, POP3, ManageSieve, SMTP) signed in with. The connection
/// checks it again from time to time: disabling the mailbox, resetting its password or
/// revoking the app password it used ends it, as these end web sessions.
#[derive(Debug, Clone)]
pub struct Grant {
    account_id: i64,
    protocol: Protocol,
    /// `None` for a token from the identity provider, which only it could revoke.
    credential: Option<Credential>,
    password_hash: String,
    checked: std::time::Instant,
}

impl Grant {
    pub fn new(account: &Account, protocol: Protocol, credential: Option<Credential>) -> Grant {
        Grant { account_id: account.id, protocol, credential, password_hash: account.password_hash.clone(), checked: std::time::Instant::now() }
    }

    /// True while the sign-in holds. Failure to verify authorization closes the connection.
    pub async fn valid(&self, db: &SqlitePool) -> bool {
        let account = sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!("{ACCOUNT_COLUMNS} JOIN domains d ON d.id = a.domain_id WHERE a.id = ? AND d.enabled = 1")))
            .bind(self.account_id)
            .fetch_optional(db)
            .await;
        let account = match account {
            Ok(Some(account)) if account.enabled && self.protocol.allowed_for(&account) => account,
            Ok(_) => return false,
            Err(_) => return false,
        };
        match self.credential {
            Some(Credential::AppPassword(id)) => sqlx::query_scalar::<_, i64>("SELECT 1 FROM app_passwords WHERE id = ? AND account_id = ?")
                .bind(id)
                .bind(account.id)
                .fetch_optional(db)
                .await
                .is_ok_and(|row| row.is_some()),
            // A new password ends it, and so does a second factor set up since: programs then
            // need an app password.
            Some(Credential::Password) => {
                account.password_hash == self.password_hash
                    && (self.protocol == Protocol::Web || crate::twofactor::factors(db, account.id).await.is_ok_and(|f| !f.enabled()))
            }
            None => true,
        }
    }

    /// [`Grant::valid`], checked at most once per [`RECHECK_INTERVAL`].
    pub async fn recheck(&mut self, db: &SqlitePool) -> bool {
        if self.checked.elapsed() < RECHECK_INTERVAL {
            return true;
        }
        self.checked = std::time::Instant::now();
        self.valid(db).await
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    /// Wrong address/password, disabled account, or protocol not allowed. Deliberately
    /// indistinguishable to the client.
    Invalid,
    RateLimited,
    Internal,
}

const WINDOW_SECS: i64 = 15 * 60;
/// Wrong passwords for one account from one network before that network is locked out of it.
const MAX_FAILURES_PER_ACCOUNT_AND_IP: u32 = 5;
/// Failed logins from one network, whatever accounts they target (password spraying).
const MAX_FAILURES_PER_IP: u32 = 10;
/// Failed logins for one account from anywhere (distributed guessing). Deliberately higher,
/// and never escalated, so that strangers cannot keep the owner out for long.
const MAX_FAILURES_PER_ACCOUNT: u32 = 20;
/// Repeat offenders are locked out for longer each time, up to this.
const MAX_LOCK_SECS: i64 = 24 * 3600;
const MAX_LIMITER_ENTRIES: usize = 50_000;
/// From this many recent failures on, every further failure is answered slowly.
const TARPIT_AFTER: u32 = 3;
/// A network with this many recent failures is guessing passwords: it is offered for reporting.
const REPORT_AFTER: u32 = 5;
const MAX_PENDING_REPORTS: usize = 1000;

#[derive(Default)]
struct Attempts {
    failures: u32,
    window_start: i64,
    /// How often this key has been locked recently; each lock lasts four times the last.
    strikes: u32,
    locked_until: i64,
}

/// In-memory tracker of failed logins.
///
/// Three things are counted, each over a sliding window: failures from a network, failures
/// for an account from a network, and failures for an account overall. An attempt is counted
/// *before* the password is checked, so a burst of parallel guesses cannot slip through
/// between the check and the bookkeeping; a successful login takes its own count back.
#[derive(Default)]
pub struct LoginLimiter {
    entries: Mutex<HashMap<String, Attempts>>,
    /// Addresses that went past [`REPORT_AFTER`], with the protocol they guessed on.
    offenders: Mutex<Vec<(IpAddr, &'static str)>>,
}

/// The network an address belongs to for rate limiting: the address itself for IPv4, the /64
/// for IPv6, where one customer typically controls the whole prefix.
pub fn network(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

impl LoginLimiter {
    /// (key, allowed failures per window, whether repeated lockouts grow longer)
    fn keys(email: &str, ip: IpAddr) -> [(String, u32, bool); 3] {
        let net = network(ip);
        [
            (format!("ip:{net}"), MAX_FAILURES_PER_IP, true),
            (format!("pair:{email}|{net}"), MAX_FAILURES_PER_ACCOUNT_AND_IP, true),
            (format!("acct:{email}"), MAX_FAILURES_PER_ACCOUNT, false),
        ]
    }

    pub fn is_blocked(&self, email: &str, ip: IpAddr) -> bool {
        let now = now();
        let entries = self.entries.lock();
        Self::keys(email, ip).iter().any(|(key, max, _)| {
            entries.get(key).is_some_and(|a| a.locked_until > now || (now - a.window_start < WINDOW_SECS && a.failures >= *max))
        })
    }

    /// Registers a login attempt. Returns false when the attempt must be refused without even
    /// looking at the password.
    pub fn attempt(&self, email: &str, ip: IpAddr) -> bool {
        let now = now();
        let mut entries = self.entries.lock();
        let keys = Self::keys(email, ip);
        // Blocked networks cannot allocate a new account/pair for every request.
        if entries.get(&keys[0].0).is_some_and(|a| a.locked_until > now) { return false; }
        if entries.len() + keys.iter().filter(|(key, _, _)| !entries.contains_key(key)).count() > MAX_LIMITER_ENTRIES { return false; }
        let mut allowed = true;
        for (index, (key, max, escalate)) in keys.iter().enumerate() {
            let entry = entries.entry(key.clone()).or_default();
            if entry.locked_until > now {
                allowed = false;
                continue;
            }
            if now - entry.window_start >= WINDOW_SECS {
                entry.failures = 0;
                entry.window_start = now;
            }
            if entry.failures >= *max {
                // The allowance is used up: lock, for longer each time it happens again.
                entry.strikes = if *escalate { entry.strikes + 1 } else { 1 };
                entry.locked_until = now + (WINDOW_SECS << (2 * (entry.strikes - 1)).min(20)).min(MAX_LOCK_SECS);
                entry.failures = 0;
                entry.window_start = now;
                allowed = false;
                if index == 0 { return false; }
            }
        }
        if allowed {
            for (key, _, _) in &keys {
                entries.entry(key.clone()).or_default().failures += 1;
            }
        }
        allowed
    }

    /// Takes back the count of an attempt that turned out to be a successful login.
    pub fn forgive(&self, email: &str, ip: IpAddr) {
        let mut entries = self.entries.lock();
        let [(by_ip, _, _), (pair, _, _), (account, _, _)] = Self::keys(email, ip);
        entries.remove(&pair);
        entries.remove(&account);
        if let Some(entry) = entries.get_mut(&by_ip) {
            entry.failures = entry.failures.saturating_sub(1);
        }
    }

    /// Notes a failed login; a network that just went past [`REPORT_AFTER`] is kept for
    /// [`take_offenders`](Self::take_offenders).
    fn note_failure(&self, ip: IpAddr, protocol: Protocol) {
        if self.failures_from(ip) == REPORT_AFTER {
            let mut offenders = self.offenders.lock();
            if offenders.len() < MAX_PENDING_REPORTS {
                offenders.push((ip, protocol.as_str()));
            }
        }
    }

    /// The addresses caught guessing passwords since the last call.
    pub fn take_offenders(&self) -> Vec<(IpAddr, &'static str)> {
        std::mem::take(&mut *self.offenders.lock())
    }

    /// Recent failures from the network of `ip`.
    pub fn failures_from(&self, ip: IpAddr) -> u32 {
        self.entries.lock().get(&format!("ip:{}", network(ip))).map_or(0, |a| a.failures)
    }

    /// How long to hold back the answer to a failed login from `ip`: guessing gets slow well
    /// before it gets blocked.
    pub fn tarpit(&self, ip: IpAddr) -> std::time::Duration {
        let failures = self.failures_from(ip);
        std::time::Duration::from_millis(u64::from(failures.saturating_sub(TARPIT_AFTER - 1)).min(5) * 400)
    }

    pub fn prune(&self) {
        let now = now();
        // Entries are kept for a day so that a returning offender is recognised.
        self.entries.lock().retain(|_, a| a.locked_until > now || now - a.window_start < MAX_LOCK_SECS);
    }
}

/// Verifies credentials for `protocol`. Every protocol front-end must go through this function
/// so that lockouts, auditing and per-protocol toggles are applied uniformly.
pub async fn authenticate(
    db: &SqlitePool,
    limiter: &LoginLimiter,
    email: &str,
    password: &str,
    ip: IpAddr,
    protocol: Protocol,
) -> Result<Account, AuthError> {
    authenticate_with(db, limiter, email, password, ip, protocol).await.map(|(account, _)| account)
}

/// [`authenticate`], telling also which credential was used.
///
/// Programs (every protocol but the web sign-in) may use an app password of the right scope.
/// Once an account has a second sign-in factor, its password alone opens the web sign-in only
/// (which then asks for the second factor); programs need an app password.
pub async fn authenticate_with(
    db: &SqlitePool,
    limiter: &LoginLimiter,
    email: &str,
    password: &str,
    ip: IpAddr,
    protocol: Protocol,
) -> Result<(Account, Credential), AuthError> {
    let email = email.trim().to_lowercase();
    if email.len() > 320 || password.len() > MAX_PASSWORD_LEN {
        return Err(AuthError::Invalid);
    }
    if !limiter.attempt(&email, ip) {
        crate::db::audit(db, &crate::util::sanitize_line(&email), "login.rate_limited", protocol.as_str(), &ip.to_string(), "").await;
        return Err(AuthError::RateLimited);
    }

    let account = sqlx::query_as::<_, Account>(sqlx::AssertSqlSafe(format!(
        "{ACCOUNT_COLUMNS} JOIN domains d ON d.id = a.domain_id WHERE a.email = ? AND d.enabled = 1"
    )))
    .bind(&email)
    .fetch_optional(db)
    .await
    .map_err(|err| {
        tracing::error!(%err, "account lookup failed");
        AuthError::Internal
    })?;

    let allowed = account.as_ref().is_some_and(|a| a.enabled && protocol.allowed_for(a));
    let internal = |err: sqlx::Error| {
        tracing::error!(%err, "credential lookup failed");
        AuthError::Internal
    };

    // An app password: cheap to check (it is random, so a plain hash suffices), and never for
    // the web sign-in.
    if let (Some(account), Some(scope), Some(normalized)) = (account.as_ref().filter(|_| allowed), protocol.scope(), crate::twofactor::normalize_app_password(password)) {
        let found: Option<(i64, String)> = sqlx::query_as("SELECT id, scopes FROM app_passwords WHERE account_id = ? AND hash = ?")
            .bind(account.id)
            .bind(crate::twofactor::app_password_hash(&normalized))
            .fetch_optional(db)
            .await
            .map_err(internal)?;
        if let Some((id, scopes)) = found.filter(|(_, scopes)| scopes.split(',').any(|s| s == scope)) {
            let _ = scopes;
            sqlx::query("UPDATE app_passwords SET last_used_at = ?, last_ip = ? WHERE id = ?").bind(crate::util::now()).bind(ip.to_string()).bind(id).execute(db).await.map_err(internal)?;
            limiter.forgive(&email, ip);
            return Ok((account.clone(), Credential::AppPassword(id)));
        }
    }

    let hash = account.as_ref().map_or(DUMMY_HASH.as_str(), |a| a.password_hash.as_str());
    let password_ok = verify_password(password, hash).await;
    // With a second factor set up, programs must use an app password.
    let needs_app_password = match (&account, protocol) {
        (Some(account), protocol) if password_ok && protocol != Protocol::Web => crate::twofactor::factors(db, account.id).await.map_err(internal)?.enabled(),
        _ => false,
    };
    if needs_app_password {
        crate::db::audit(db, &email, "login.app_password_required", protocol.as_str(), &ip.to_string(), "").await;
    }

    match account {
        Some(account) if password_ok && allowed && !needs_app_password => {
            limiter.forgive(&email, ip);
            Ok((account, Credential::Password))
        }
        _ => {
            // The attempt was already counted; now make the guesser wait for the bad news.
            tokio::time::sleep(limiter.tarpit(ip)).await;
            crate::db::audit(db, &crate::util::sanitize_line(&email), "login.failed", protocol.as_str(), &ip.to_string(), "")
                .await;
            limiter.note_failure(ip, protocol);
            Err(AuthError::Invalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_networks_cannot_grow_the_limiter() {
        let limiter = LoginLimiter::default();
        let ip = "192.0.2.1".parse().unwrap();
        for i in 0..=MAX_FAILURES_PER_IP { limiter.attempt(&format!("user{i}@example.org"), ip); }
        let count = limiter.entries.lock().len();
        for i in 0..1000 { assert!(!limiter.attempt(&format!("fresh{i}@example.org"), ip)); }
        assert_eq!(limiter.entries.lock().len(), count);
    }

    #[test]
    fn hash_and_verify() {
        let hash = hash_password_sync("correct horse battery").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password_sync("correct horse battery", &hash));
        assert!(!verify_password_sync("wrong", &hash));
        assert!(!verify_password_sync("anything", "not-a-hash"));
    }

    #[test]
    fn password_policy() {
        assert!(validate_new_password("short").is_err());
        assert!(validate_new_password("long enough password").is_ok());
        assert!(validate_new_password("with\nnewline!!").is_err());
        assert!(validate_new_password(&"x".repeat(MAX_PASSWORD_LEN + 1)).is_err());
    }

    #[test]
    fn limiter_locks_an_account_for_the_guessing_network_only() {
        let limiter = LoginLimiter::default();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        for _ in 0..MAX_FAILURES_PER_ACCOUNT_AND_IP {
            assert!(limiter.attempt("a@example.com", ip));
        }
        assert!(limiter.is_blocked("a@example.com", ip));
        assert!(!limiter.attempt("a@example.com", ip), "the next guess is refused unseen");
        // Another account from the same address still works, until the address limit is hit.
        assert!(limiter.attempt("b@example.com", ip));
        // The owner, coming from elsewhere, is not locked out by a stranger's guesses.
        let owner: IpAddr = "198.51.100.20".parse().unwrap();
        assert!(limiter.attempt("a@example.com", owner));
        limiter.forgive("a@example.com", owner);
        assert!(!limiter.attempt("a@example.com", ip), "a success elsewhere does not unlock the guesser");
    }

    #[test]
    fn limiter_blocks_an_address_spraying_many_accounts() {
        let limiter = LoginLimiter::default();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        for i in 0..MAX_FAILURES_PER_IP {
            assert!(limiter.attempt(&format!("user{i}@example.com"), ip), "attempt {i}");
        }
        assert!(!limiter.attempt("fresh@example.com", ip), "every further account is refused");
        assert!(!limiter.attempt("another@example.com", ip));
        assert!(limiter.attempt("fresh@example.com", "203.0.113.10".parse().unwrap()));
    }

    #[test]
    fn limiter_counts_ipv6_by_prefix_and_caps_distributed_guessing() {
        let limiter = LoginLimiter::default();
        // Rotating through one /64 does not help.
        for i in 0..MAX_FAILURES_PER_IP {
            assert!(limiter.attempt(&format!("user{i}@example.com"), format!("2001:db8:1:2::{i:x}").parse().unwrap()));
        }
        assert!(!limiter.attempt("x@example.com", "2001:db8:1:2:ffff::1".parse().unwrap()));
        assert!(limiter.attempt("x@example.com", "2001:db8:1:3::1".parse().unwrap()), "a different /64 is a different network");

        // Many networks guessing one account are stopped by the per-account limit.
        let limiter = LoginLimiter::default();
        for i in 0..MAX_FAILURES_PER_ACCOUNT {
            assert!(limiter.attempt("victim@example.com", format!("198.51.100.{i}").parse().unwrap()));
        }
        assert!(!limiter.attempt("victim@example.com", "192.0.2.77".parse().unwrap()));
    }

    #[test]
    fn limiter_offers_guessing_networks_for_reporting_once() {
        let limiter = LoginLimiter::default();
        let ip: IpAddr = "203.0.113.40".parse().unwrap();
        for _ in 0..REPORT_AFTER - 1 {
            limiter.attempt("a@example.com", ip);
            limiter.note_failure(ip, Protocol::Imap);
        }
        assert!(limiter.take_offenders().is_empty(), "a few typos are not an attack");
        for _ in 0..3 {
            limiter.attempt("b@example.com", ip);
            limiter.note_failure(ip, Protocol::Imap);
        }
        assert_eq!(limiter.take_offenders(), [(ip, "imap")]);
        assert!(limiter.take_offenders().is_empty());
    }

    #[test]
    fn limiter_forgives_successes_escalates_repeat_offenders_and_slows_guessing() {
        let limiter = LoginLimiter::default();
        let ip: IpAddr = "203.0.113.30".parse().unwrap();
        // A user who logs in correctly many times is never limited.
        for _ in 0..100 {
            assert!(limiter.attempt("a@example.com", ip));
            limiter.forgive("a@example.com", ip);
        }
        assert_eq!(limiter.failures_from(ip), 0);
        assert_eq!(limiter.tarpit(ip), std::time::Duration::ZERO);

        // Failures are answered more and more slowly.
        for _ in 0..TARPIT_AFTER {
            limiter.attempt("a@example.com", ip);
        }
        assert_eq!(limiter.tarpit(ip), std::time::Duration::from_millis(400));
        limiter.attempt("a@example.com", ip);
        assert_eq!(limiter.tarpit(ip), std::time::Duration::from_millis(800));

        // Each lockout of the same key lasts four times as long as the previous one.
        let lock_secs = |limiter: &LoginLimiter| limiter.entries.lock().get("pair:a@example.com|203.0.113.30").unwrap().locked_until - now();
        assert!(limiter.attempt("a@example.com", ip));
        assert!(!limiter.attempt("a@example.com", ip));
        assert!((lock_secs(&limiter) - WINDOW_SECS).abs() <= 1);
        limiter.entries.lock().get_mut("pair:a@example.com|203.0.113.30").unwrap().locked_until = 0;
        limiter.entries.lock().get_mut("ip:203.0.113.30").unwrap().failures = 0;
        for _ in 0..MAX_FAILURES_PER_ACCOUNT_AND_IP {
            assert!(limiter.attempt("a@example.com", ip));
        }
        assert!(!limiter.attempt("a@example.com", ip));
        assert!((lock_secs(&limiter) - 4 * WINDOW_SECS).abs() <= 1);
    }
}
