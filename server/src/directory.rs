//! Domains, accounts and aliases: validated creation shared by the API and first-run bootstrap.

use sqlx::SqlitePool;

use crate::{
    app::App,
    auth::{self, Account, Role},
    error::{ApiError, ApiResult},
    util::{Address, normalize_domain, now, random_token},
};

pub const MAX_ALIAS_DESTINATIONS: usize = 50;

pub async fn create_domain(db: &SqlitePool, name: &str) -> ApiResult<i64> {
    let name = normalize_domain(name).ok_or_else(|| ApiError::bad("invalid domain name"))?;
    let id = sqlx::query("INSERT INTO domains (name, created_at) VALUES (?, ?)")
        .bind(&name)
        .bind(now())
        .execute(db)
        .await
        .map_err(|e| match ApiError::from(e) {
            ApiError::Conflict(_) => ApiError::Conflict("domain already exists".into()),
            other => other,
        })?
        .last_insert_rowid();
    Ok(id)
}

pub struct NewAccount<'a> {
    pub email: &'a str,
    pub password: &'a str,
    pub display_name: &'a str,
    pub role: Role,
    /// `None` uses the domain's default quota.
    pub quota_bytes: Option<i64>,
}

pub async fn create_account(app: &App, new: NewAccount<'_>) -> ApiResult<Account> {
    let address = Address::parse_local(new.email).ok_or_else(|| ApiError::bad("invalid e-mail address"))?;
    auth::validate_new_password(new.password).map_err(ApiError::bad)?;
    if new.display_name.chars().count() > 200 || new.display_name.chars().any(|c| c.is_control()) {
        return Err(ApiError::bad("invalid display name"));
    }
    if new.quota_bytes.is_some_and(|q| q < 0) {
        return Err(ApiError::bad("quota must not be negative"));
    }
    let email = address.to_string();

    let (domain_id, max_mailboxes, default_quota): (i64, i64, i64) =
        sqlx::query_as("SELECT id, max_mailboxes, default_quota_bytes FROM domains WHERE name = ?")
            .bind(&address.domain)
            .fetch_optional(&app.db)
            .await?
            .ok_or_else(|| ApiError::bad("domain is not hosted on this server"))?;
    if max_mailboxes > 0 {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE domain_id = ?").bind(domain_id).fetch_one(&app.db).await?;
        if count >= max_mailboxes {
            return Err(ApiError::Conflict("the domain has reached its mailbox limit".into()));
        }
    }
    let alias_exists: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM aliases WHERE source = ?").bind(&email).fetch_optional(&app.db).await?;
    if alias_exists.is_some() {
        return Err(ApiError::Conflict("an alias with this address already exists".into()));
    }

    let hash = auth::hash_password(new.password).await?;
    let id = sqlx::query(
        "INSERT INTO accounts (domain_id, local_part, email, display_name, password_hash, role, quota_bytes, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(domain_id)
    .bind(&address.local)
    .bind(&email)
    .bind(new.display_name)
    .bind(hash)
    .bind(new.role)
    .bind(new.quota_bytes.unwrap_or(default_quota))
    .bind(now())
    .execute(&app.db)
    .await
    .map_err(|e| match ApiError::from(e) {
        ApiError::Conflict(_) => ApiError::Conflict("a mailbox with this address already exists".into()),
        other => other,
    })?
    .last_insert_rowid();
    app.store.create_default_mailboxes(id).await?;
    crate::webhooks::emit(app, "account.created", serde_json::json!({ "email": email }));
    Account::by_id(&app.db, id).await?.ok_or(ApiError::NotFound)
}

/// Normalizes and validates alias destinations.
pub fn parse_destinations(destinations: &[String]) -> ApiResult<Vec<String>> {
    if destinations.is_empty() || destinations.len() > MAX_ALIAS_DESTINATIONS {
        return Err(ApiError::bad("an alias needs between 1 and 50 destinations"));
    }
    let mut out = Vec::with_capacity(destinations.len());
    for dest in destinations {
        let addr = Address::parse(dest).ok_or_else(|| ApiError::bad(format!("invalid destination address: {}", crate::util::sanitize_line(dest))))?;
        let addr = addr.to_string();
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    Ok(out)
}

pub async fn create_alias(db: &SqlitePool, source: &str, destinations: &[String]) -> ApiResult<i64> {
    let address = Address::parse_local(source).ok_or_else(|| ApiError::bad("invalid alias address"))?;
    let source = address.to_string();
    let destinations = parse_destinations(destinations)?;
    if destinations.contains(&source) {
        return Err(ApiError::bad("an alias cannot deliver to itself"));
    }
    let domain_id: i64 = sqlx::query_scalar("SELECT id FROM domains WHERE name = ?")
        .bind(&address.domain)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| ApiError::bad("domain is not hosted on this server"))?;
    let account_exists: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM accounts WHERE email = ?").bind(&source).fetch_optional(db).await?;
    if account_exists.is_some() {
        return Err(ApiError::Conflict("a mailbox with this address already exists".into()));
    }
    let id = sqlx::query("INSERT INTO aliases (domain_id, source, destinations, created_at) VALUES (?, ?, ?, ?)")
        .bind(domain_id)
        .bind(&source)
        .bind(serde_json::to_string(&destinations).map_err(anyhow::Error::from)?)
        .bind(now())
        .execute(db)
        .await
        .map_err(|e| match ApiError::from(e) {
            ApiError::Conflict(_) => ApiError::Conflict("alias already exists".into()),
            other => other,
        })?
        .last_insert_rowid();
    Ok(id)
}

/// Creates the first super administrator when the server has no accounts yet.
///
/// Without `UNOMAIL_ADMIN_PASSWORD` a random password is generated and printed once; there is
/// deliberately no built-in default credential.
pub async fn bootstrap_admin(app: &App) -> anyhow::Result<()> {
    let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts").fetch_one(&app.db).await?;
    if accounts > 0 {
        return Ok(());
    }
    let email = match &app.cfg.admin_email {
        Some(email) => email.clone(),
        None => {
            // mail.example.com -> admin@example.com
            let domain = app.cfg.hostname.split_once('.').map_or(app.cfg.hostname.as_str(), |(_, rest)| rest);
            let domain = if crate::util::is_valid_domain(domain) { domain } else { app.cfg.hostname.as_str() };
            format!("admin@{domain}")
        }
    };
    let Some(address) = Address::parse_local(&email) else {
        tracing::warn!(email, "cannot create the initial administrator: set UNOMAIL_ADMIN_EMAIL to a valid address");
        return Ok(());
    };
    let exists: Option<i64> =
        sqlx::query_scalar("SELECT id FROM domains WHERE name = ?").bind(&address.domain).fetch_optional(&app.db).await?;
    if exists.is_none() {
        create_domain(&app.db, &address.domain).await.map_err(|e| anyhow::anyhow!("cannot create domain: {e}"))?;
    }
    let generated = app.cfg.admin_password.is_none();
    let password = app.cfg.admin_password.clone().unwrap_or_else(random_token);
    create_account(
        app,
        NewAccount { email: &email, password: &password, display_name: "Administrator", role: Role::SuperAdmin, quota_bytes: None },
    )
    .await
    .map_err(|e| anyhow::anyhow!("cannot create the initial administrator: {e}"))?;
    if generated {
        // Printed to stderr directly so the secret does not end up in structured log sinks.
        eprintln!("\n=== unoMail initial administrator ===\n  e-mail:   {email}\n  password: {password}\n  Change this password after the first login.\n");
    }
    crate::db::audit(&app.db, "system", "account.bootstrap_admin", &email, "", "").await;
    Ok(())
}
