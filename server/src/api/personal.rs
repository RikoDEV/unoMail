//! Per-user web mail data: sender identities, the address book, response templates and
//! client preferences.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::header,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{JsonResult, Session, like_pattern};
use crate::{
    app::AppState,
    error::ApiError,
    smtp::submit::{hosted_domain, owns_address},
    util::{Address, normalize_domain, now, sanitize_line},
};

const MAX_IDENTITIES: i64 = 20;
const MAX_CONTACTS: i64 = 5000;
const MAX_GROUPS: i64 = 100;
const MAX_TEMPLATES: i64 = 100;
/// Signatures may carry small images (a logo) inline as data: URLs.
const MAX_SIGNATURE_BYTES: usize = 200_000;
const MAX_TEMPLATE_BYTES: usize = 100_000;
const MAX_PREFERENCES_BYTES: usize = 16 * 1024;
const MAX_PGP_KEY_BYTES: usize = 100_000;

fn text(value: &str, max: usize, what: &str) -> Result<String, ApiError> {
    let clean = sanitize_line(value.trim());
    if clean.chars().count() > max { Err(ApiError::bad(format!("{what} is too long"))) } else { Ok(clean) }
}

// --- Identities ----------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
pub struct IdentityRow {
    #[sqlx(skip)]
    pub masked: bool,
    #[sqlx(skip)]
    pub available: bool,
    pub id: i64,
    pub name: String,
    pub email: String,
    pub reply_to: String,
    /// The signature for new messages from this address (see [`signature_defaults`]).
    #[sqlx(skip)]
    pub signature_html: String,
    pub is_default: bool,
    /// The account's own address, which every account has and cannot remove.
    pub is_primary: bool,
    pub smtp_host: Option<String>,
    pub smtp_port: Option<i64>,
    pub smtp_security: Option<String>,
    pub smtp_username: String,
    pub smtp_password: String,
}

const IDENTITY_COLUMNS: &str = "id, name, email, reply_to, is_default, is_primary, smtp_host, smtp_port, smtp_security, smtp_username, smtp_password";

impl IdentityRow {
    fn view(&self) -> Value {
        let mut view = json!({
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "reply_to": self.reply_to,
            "signature_html": self.signature_html,
            "is_default": self.is_default,
            "primary": self.is_primary,
            // The stored password is never returned, only whether one is set.
            "smtp": self.smtp_host.as_ref().map(|host| json!({
                "host": host,
                "port": self.smtp_port,
                "security": self.smtp_security,
                "username": self.smtp_username,
                "has_password": !self.smtp_password.is_empty(),
            })),
        });
        if self.masked {
            view["masked"] = json!(true);
            view["available"] = json!(self.available);
        }
        view
    }
}

/// The identities of an account: its primary identity (its own address) first among equals,
/// then the ones the user added, then masked addresses without an identity of their own.
pub async fn identity_rows(state: &AppState, account: &crate::auth::Account) -> sqlx::Result<Vec<IdentityRow>> {
    ensure_primary(&state.db, account).await?;
    let mut rows: Vec<IdentityRow> =
        sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {IDENTITY_COLUMNS} FROM identities WHERE account_id = ? ORDER BY is_default DESC, is_primary DESC, id")))
            .bind(account.id)
            .fetch_all(&state.db)
            .await?;
    for row in &mut rows {
        row.available=true;
        if let Some(address)=Address::parse(&row.email)&& let Some(owned)=crate::masked_email::owned(state,account.id,&address).await?{row.masked=true;row.available=owned;}
    }
    let masks:Vec<(i64,String,bool,Option<i64>,bool)>=sqlx::query_as("SELECT m.id,m.email,m.enabled,m.expires_at,d.enabled FROM masked_addresses m JOIN domains d ON d.id=m.domain_id WHERE m.account_id=? ORDER BY m.id DESC").bind(account.id).fetch_all(&state.db).await?;
    for (id,email,enabled,expires,domain) in masks{
        if !rows.iter().any(|r|r.email==email){rows.push(IdentityRow{id:-id,name:String::new(),email:email.clone(),reply_to:email,signature_html:String::new(),is_default:false,is_primary:false,smtp_host:None,smtp_port:None,smtp_security:None,smtp_username:String::new(),smtp_password:String::new(),masked:true,available:enabled && domain && expires.is_none_or(|t|t>now())});}
    }
    let signatures = new_message_signatures(&state.db, account.id).await?;
    for row in &mut rows {
        row.signature_html = signatures.get(&row.id).cloned().unwrap_or_default();
    }
    Ok(rows)
}

/// Creates the account's primary identity if it has none yet (a new account), and keeps its
/// address the account's own (an administrator may rename the mailbox).
async fn ensure_primary(db: &sqlx::SqlitePool, account: &crate::auth::Account) -> sqlx::Result<()> {
    sqlx::query("UPDATE identities SET email = ? WHERE account_id = ? AND is_primary = 1 AND email != ?")
        .bind(&account.email)
        .bind(account.id)
        .bind(&account.email)
        .execute(db)
        .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO identities (account_id, name, email, is_default, is_primary, created_at)
         SELECT ?1, ?2, ?3, NOT EXISTS (SELECT 1 FROM identities WHERE account_id = ?1 AND is_default = 1), 1, ?4
         WHERE NOT EXISTS (SELECT 1 FROM identities WHERE account_id = ?1 AND is_primary = 1)",
    )
    .bind(account.id)
    .bind(&account.display_name)
    .bind(&account.email)
    .bind(now())
    .execute(db)
    .await?;
    Ok(())
}

/// The addresses an account may send from through this server: its own, the aliases that
/// deliver to it and its active masked addresses. Any other address needs its own SMTP server.
pub async fn sendable_addresses(state: &AppState, account: &crate::auth::Account) -> sqlx::Result<Vec<(String, &'static str)>> {
    let mut out = vec![(account.email.clone(), "own")];
    let aliases: Vec<(String, String)> = sqlx::query_as("SELECT source, destinations FROM aliases WHERE enabled = 1 AND destinations LIKE ? ESCAPE '\\'")
        .bind(like_pattern(&account.email))
        .fetch_all(&state.db)
        .await?;
    for (source, destinations) in aliases {
        let list: Vec<String> = serde_json::from_str(&destinations).unwrap_or_default();
        if list.iter().any(|d| d.eq_ignore_ascii_case(&account.email)) && !out.iter().any(|(email, _)| *email == source) {
            out.push((source, "alias"));
        }
    }
    let masks: Vec<String> = sqlx::query_scalar(
        "SELECT m.email FROM masked_addresses m JOIN domains d ON d.id = m.domain_id
         WHERE m.account_id = ? AND m.enabled = 1 AND d.enabled = 1 AND (m.expires_at IS NULL OR m.expires_at > ?) ORDER BY m.email",
    )
    .bind(account.id)
    .bind(now())
    .fetch_all(&state.db)
    .await?;
    out.extend(masks.into_iter().map(|email| (email, "masked")));
    Ok(out)
}

pub async fn identity_addresses(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let addresses = sendable_addresses(&state, &session.account).await?;
    Ok(Json(json!(addresses.into_iter().map(|(email, kind)| json!({ "email": email, "kind": kind })).collect::<Vec<_>>())))
}

#[derive(Deserialize)]
pub struct SmtpInput {
    host: String,
    port: u16,
    security: String,
    #[serde(default)]
    username: String,
    /// Omitted or `null` keeps the stored password.
    password: Option<String>,
}

#[derive(Deserialize)]
pub struct IdentityInput {
    #[serde(default)]
    name: String,
    email: String,
    #[serde(default)]
    reply_to: String,
    #[serde(default)]
    is_default: bool,
    smtp: Option<SmtpInput>,
}

pub async fn identities_list(State(state): State<AppState>, session: Session) -> JsonResult<Vec<Value>> {
    Ok(Json(identity_rows(&state, &session.account).await?.iter().map(IdentityRow::view).collect()))
}

async fn save_identity(state: &AppState, session: &Session, id: Option<i64>, input: IdentityInput) -> Result<Value, ApiError> {
    let address = Address::parse(&input.email).ok_or_else(|| ApiError::bad("invalid e-mail address"))?;
    let name = text(&input.name, 100, "the name")?;
    let reply_to = match input.reply_to.trim() {
        "" => String::new(),
        value => Address::parse(value).ok_or_else(|| ApiError::bad("invalid reply-to address"))?.to_string(),
    };
    let existing: Option<IdentityRow> = match id {
        Some(id) => Some(
            sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {IDENTITY_COLUMNS} FROM identities WHERE id = ? AND account_id = ?")))
                .bind(id)
                .bind(session.account.id)
                .fetch_optional(&state.db)
                .await?
                .ok_or(ApiError::NotFound)?,
        ),
        None => None,
    };
    let primary = existing.as_ref().is_some_and(|row| row.is_primary);
    if primary && address.to_string() != session.account.email {
        return Err(ApiError::bad("the address of your primary identity is your account's own address"));
    }
    if primary && input.smtp.is_some() {
        return Err(ApiError::bad("your own address is always sent by this server"));
    }
    // An address that sends through its own SMTP server has one server, shared by all of the
    // identities with that address: SMTP clients name only the address, not the identity.
    let sibling: Option<IdentityRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {IDENTITY_COLUMNS} FROM identities WHERE account_id = ? AND email = ? AND smtp_host IS NOT NULL AND id != ? ORDER BY id LIMIT 1"
    )))
    .bind(session.account.id)
    .bind(address.to_string())
    .bind(id.unwrap_or(0))
    .fetch_optional(&state.db)
    .await?;

    let smtp = match &input.smtp {
        None => None,
        Some(smtp) => {
            let host = smtp.host.trim().to_ascii_lowercase();
            if normalize_domain(&host).is_none() && host.parse::<std::net::IpAddr>().is_err() {
                return Err(ApiError::bad("invalid SMTP host name"));
            }
            if smtp.port == 0 {
                return Err(ApiError::bad("invalid SMTP port"));
            }
            // Credentials are only ever sent over an encrypted connection.
            let plain_allowed = state.cfg.identity_relay_allow_private;
            if !(matches!(smtp.security.as_str(), "tls" | "starttls") || (plain_allowed && smtp.security == "none")) {
                return Err(ApiError::bad("security must be \"tls\" or \"starttls\""));
            }
            let username = text(&smtp.username, 200, "the user name")?;
            let password = match &smtp.password {
                Some(password) if password.len() > 500 => return Err(ApiError::bad("the password is too long")),
                Some(password) => state.secrets.seal(password),
                // Keep the stored password only while it still goes to the same server.
                None => existing.iter().chain(&sibling).find(|e| e.smtp_host.as_deref() == Some(host.as_str())).map(|e| e.smtp_password.clone()).unwrap_or_default(),
            };
            Some((host, smtp.port as i64, smtp.security.clone(), username, password))
        }
    };
    let owned = owns_address(state, &session.account, &address).await?;
    // Another identity with this address already names its server: this one uses it too.
    let smtp = match (smtp, &sibling) {
        (None, Some(other)) if !owned => other.smtp_host.clone().map(|host| (host, other.smtp_port.unwrap_or(465), other.smtp_security.clone().unwrap_or_else(|| "tls".into()), other.smtp_username.clone(), other.smtp_password.clone())),
        (smtp, _) => smtp,
    };
    // Without a server of its own the identity is sent by us and must be an address the
    // account really owns; anything else would let users impersonate each other.
    if smtp.is_none() && !owned {
        return Err(ApiError::bad("this address does not belong to your account; add an SMTP server to send through its own provider"));
    }
    // An address in a domain hosted here belongs to someone on this server: an SMTP server of
    // the user's choosing (this one included) must not make it theirs.
    if smtp.is_some() && hosted_domain(&state.db, &address.domain).await? && !owned {
        return Err(ApiError::bad("this address belongs to another mailbox on this server"));
    }

    let email = address.to_string();
    let mut tx = state.db.begin().await?;
    if input.is_default {
        sqlx::query("UPDATE identities SET is_default = 0 WHERE account_id = ?").bind(session.account.id).execute(&mut *tx).await?;
    }
    let (host, port, security, username, password) = match smtp {
        Some((host, port, security, username, password)) => (Some(host), Some(port), Some(security), username, password),
        None => (None, None, None, String::new(), String::new()),
    };
    let saved_id = match id {
        Some(id) => {
            sqlx::query(
                "UPDATE identities SET name = ?, email = ?, reply_to = ?, is_default = ?, smtp_host = ?, smtp_port = ?,
                     smtp_security = ?, smtp_username = ?, smtp_password = ? WHERE id = ? AND account_id = ?",
            )
            .bind(&name)
            .bind(&email)
            .bind(&reply_to)
            .bind(input.is_default)
            .bind(&host)
            .bind(port)
            .bind(&security)
            .bind(&username)
            .bind(&password)
            .bind(id)
            .bind(session.account.id)
            .execute(&mut *tx)
            .await
            .map_err(conflict("an identity with this address already exists"))?;
            id
        }
        None => {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identities WHERE account_id = ?").bind(session.account.id).fetch_one(&mut *tx).await?;
            if count >= MAX_IDENTITIES {
                return Err(ApiError::Conflict(format!("at most {MAX_IDENTITIES} identities can be stored")));
            }
            sqlx::query(
                "INSERT INTO identities (account_id, name, email, reply_to, is_default, smtp_host, smtp_port, smtp_security,
                     smtp_username, smtp_password, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(session.account.id)
            .bind(&name)
            .bind(&email)
            .bind(&reply_to)
            .bind(input.is_default)
            .bind(&host)
            .bind(port)
            .bind(&security)
            .bind(&username)
            .bind(&password)
            .bind(now())
            .execute(&mut *tx)
            .await
            .map_err(conflict("an identity with this address already exists"))?
            .last_insert_rowid()
        }
    };
    if host.is_some() && !owned {
        sqlx::query("UPDATE identities SET smtp_host = ?, smtp_port = ?, smtp_security = ?, smtp_username = ?, smtp_password = ? WHERE account_id = ? AND email = ? AND id != ?")
            .bind(&host)
            .bind(port)
            .bind(&security)
            .bind(&username)
            .bind(&password)
            .bind(session.account.id)
            .bind(&email)
            .bind(saved_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    session.audit(state, "identity.saved", &email, host.as_deref().unwrap_or("")).await;
    let mut row: IdentityRow = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {IDENTITY_COLUMNS} FROM identities WHERE id = ?"))).bind(saved_id).fetch_one(&state.db).await?;
    row.signature_html = new_message_signatures(&state.db, session.account.id).await?.remove(&row.id).unwrap_or_default();
    Ok(row.view())
}

/// Maps a unique-constraint violation to a readable conflict.
fn conflict(message: &'static str) -> impl Fn(sqlx::Error) -> ApiError {
    move |err| match &err {
        sqlx::Error::Database(db) if db.is_unique_violation() => ApiError::Conflict(message.into()),
        _ => err.into(),
    }
}

pub async fn identity_create(State(state): State<AppState>, session: Session, Json(input): Json<IdentityInput>) -> JsonResult<Value> {
    Ok(Json(save_identity(&state, &session, None, input).await?))
}

pub async fn identity_update(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<IdentityInput>) -> JsonResult<Value> {
    Ok(Json(save_identity(&state, &session, Some(id), input).await?))
}

/// Deletes an identity the user added; the primary one stays. When the default goes, the
/// primary identity becomes the default.
pub async fn identity_delete(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    let mut tx = state.db.begin().await?;
    let removed = sqlx::query("DELETE FROM identities WHERE id = ? AND account_id = ? AND is_primary = 0").bind(id).bind(session.account.id).execute(&mut *tx).await?.rows_affected();
    if removed == 0 {
        let primary: Option<i64> = sqlx::query_scalar("SELECT 1 FROM identities WHERE id = ? AND account_id = ? AND is_primary = 1").bind(id).bind(session.account.id).fetch_optional(&mut *tx).await?;
        return Err(if primary.is_some() { ApiError::bad("your primary identity cannot be deleted") } else { ApiError::NotFound });
    }
    sqlx::query("DELETE FROM signature_defaults WHERE account_id = ? AND identity_id = ?").bind(session.account.id).bind(id).execute(&mut *tx).await?;
    sqlx::query("UPDATE identities SET is_default = 1 WHERE account_id = ?1 AND is_primary = 1 AND NOT EXISTS (SELECT 1 FROM identities WHERE account_id = ?1 AND is_default = 1)")
        .bind(session.account.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({ "ok": true })))
}

// --- Address book --------------------------------------------------------------------------

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Contact {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub phone: String,
    pub organization: String,
    pub notes: String,
    pub pgp_key: String,
    pub updated_at: i64,
}

const CONTACT_COLUMNS: &str = "id, name, email, phone, organization, notes, pgp_key, updated_at";

#[derive(Deserialize, Default)]
pub struct ContactInput {
    #[serde(default)]
    name: String,
    email: String,
    #[serde(default)]
    phone: String,
    #[serde(default)]
    organization: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    pgp_key: String,
}

struct CleanContact {
    name: String,
    email: String,
    phone: String,
    organization: String,
    notes: String,
    pgp_key: String,
}

fn clean_contact(input: &ContactInput) -> Result<CleanContact, ApiError> {
    let email = Address::parse(&input.email).ok_or_else(|| ApiError::bad("invalid e-mail address"))?.to_string();
    let pgp_key = input.pgp_key.trim();
    if pgp_key.len() > MAX_PGP_KEY_BYTES || (!pgp_key.is_empty() && !pgp_key.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
        return Err(ApiError::bad("the PGP key must be an armored public key"));
    }
    let notes: String = input.notes.chars().filter(|c| !c.is_control() || *c == '\n').take(2000).collect();
    Ok(CleanContact {
        name: text(&input.name, 200, "the name")?,
        email,
        phone: text(&input.phone, 50, "the phone number")?,
        organization: text(&input.organization, 200, "the organization")?,
        notes,
        pgp_key: pgp_key.to_owned(),
    })
}

#[derive(Deserialize)]
pub struct ContactQuery {
    q: Option<String>,
    group: Option<i64>,
}

pub async fn contacts_list(State(state): State<AppState>, session: Session, Query(query): Query<ContactQuery>) -> JsonResult<Vec<Contact>> {
    let pattern = query.q.as_deref().map(str::trim).filter(|q| !q.is_empty()).map(like_pattern);
    let rows = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {CONTACT_COLUMNS} FROM contacts c WHERE account_id = ?1
           AND (?2 IS NULL OR name LIKE ?2 ESCAPE '\\' OR email LIKE ?2 ESCAPE '\\' OR organization LIKE ?2 ESCAPE '\\')
           AND (?3 IS NULL OR EXISTS (SELECT 1 FROM contact_group_members g WHERE g.contact_id = c.id AND g.group_id = ?3))
         ORDER BY CASE WHEN name = '' THEN email ELSE name END COLLATE NOCASE LIMIT 5000"
    )))
    .bind(session.account.id)
    .bind(pattern)
    .bind(query.group)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}

/// Whether another contact of the account already has this address. (Cards synchronised from
/// a phone may share an address; the web client keeps its own entries unique.)
async fn address_taken(state: &AppState, account_id: i64, email: &str, except: Option<i64>) -> Result<bool, ApiError> {
    let found: Option<i64> = sqlx::query_scalar("SELECT id FROM contacts WHERE account_id = ? AND email = ? AND id IS NOT ? LIMIT 1").bind(account_id).bind(email).bind(except).fetch_optional(&state.db).await?;
    Ok(found.is_some())
}

async fn insert_contact(state: &AppState, account_id: i64, contact: &CleanContact) -> Result<i64, ApiError> {
    if address_taken(state, account_id, &contact.email, None).await? {
        return Err(ApiError::Conflict("a contact with this address already exists".into()));
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contacts WHERE account_id = ?").bind(account_id).fetch_one(&state.db).await?;
    if count >= MAX_CONTACTS {
        return Err(ApiError::Conflict(format!("the address book is limited to {MAX_CONTACTS} contacts")));
    }
    Ok(sqlx::query("INSERT INTO contacts (account_id, name, email, phone, organization, notes, pgp_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(account_id)
        .bind(&contact.name)
        .bind(&contact.email)
        .bind(&contact.phone)
        .bind(&contact.organization)
        .bind(&contact.notes)
        .bind(&contact.pgp_key)
        .bind(now())
        .bind(now())
        .execute(&state.db)
        .await
        .map_err(conflict("a contact with this address already exists"))?
        .last_insert_rowid())
}

async fn contact_by_id(state: &AppState, account_id: i64, id: i64) -> Result<Contact, ApiError> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {CONTACT_COLUMNS} FROM contacts WHERE id = ? AND account_id = ?")))
        .bind(id)
        .bind(account_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)
}

pub async fn contact_create(State(state): State<AppState>, session: Session, Json(input): Json<ContactInput>) -> JsonResult<Contact> {
    let id = insert_contact(&state, session.account.id, &clean_contact(&input)?).await?;
    Ok(Json(contact_by_id(&state, session.account.id, id).await?))
}

pub async fn contact_update(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<ContactInput>) -> JsonResult<Contact> {
    let contact = clean_contact(&input)?;
    // Only a changed address is checked: cards from a phone may already share one.
    let current: Option<String> = sqlx::query_scalar("SELECT email FROM contacts WHERE id = ? AND account_id = ?").bind(id).bind(session.account.id).fetch_optional(&state.db).await?;
    if current.as_deref() != Some(contact.email.as_str()) && address_taken(&state, session.account.id, &contact.email, Some(id)).await? {
        return Err(ApiError::Conflict("a contact with this address already exists".into()));
    }
    let changed = sqlx::query("UPDATE contacts SET name = ?, email = ?, phone = ?, organization = ?, notes = ?, pgp_key = ?, updated_at = ? WHERE id = ? AND account_id = ?")
        .bind(&contact.name)
        .bind(&contact.email)
        .bind(&contact.phone)
        .bind(&contact.organization)
        .bind(&contact.notes)
        .bind(&contact.pgp_key)
        .bind(now())
        .bind(id)
        .bind(session.account.id)
        .execute(&state.db)
        .await
        .map_err(conflict("a contact with this address already exists"))?
        .rows_affected();
    if changed == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(contact_by_id(&state, session.account.id, id).await?))
}

pub async fn contact_delete(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    let removed = sqlx::query("DELETE FROM contacts WHERE id = ? AND account_id = ?").bind(id).bind(session.account.id).execute(&state.db).await?.rows_affected();
    if removed == 0 { Err(ApiError::NotFound) } else { Ok(Json(json!({ "ok": true }))) }
}

// vCard (RFC 6350) import and export, limited to the fields the address book stores.

fn vcard_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\n', "\\n").replace(',', "\\,").replace(';', "\\;")
}

fn vcard_unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n' | 'N') => out.push('\n'),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

pub fn to_vcards(contacts: &[Contact]) -> String {
    let mut out = String::new();
    for contact in contacts {
        let name = if contact.name.is_empty() { &contact.email } else { &contact.name };
        out.push_str("BEGIN:VCARD\r\nVERSION:3.0\r\n");
        out.push_str(&format!("FN:{}\r\nEMAIL;TYPE=INTERNET:{}\r\n", vcard_escape(name), vcard_escape(&contact.email)));
        for (key, value) in [("TEL", &contact.phone), ("ORG", &contact.organization), ("NOTE", &contact.notes)] {
            if !value.is_empty() {
                out.push_str(&format!("{key}:{}\r\n", vcard_escape(value)));
            }
        }
        out.push_str("END:VCARD\r\n");
    }
    out
}

/// Parses vCards into contact inputs; cards without an e-mail address are skipped.
pub fn parse_vcards(data: &str) -> Vec<ContactInput> {
    // Unfold continuation lines first (a line starting with a space or tab continues the previous one).
    let mut lines: Vec<String> = Vec::new();
    for line in data.lines() {
        match line.strip_prefix([' ', '\t']) {
            Some(rest) if !lines.is_empty() => lines.last_mut().expect("checked non-empty").push_str(rest),
            _ => lines.push(line.to_owned()),
        }
    }
    let mut out = Vec::new();
    let mut current: Option<ContactInput> = None;
    for line in lines {
        let Some((key, value)) = line.split_once(':') else { continue };
        let name = key.split(';').next().unwrap_or("").rsplit('.').next().unwrap_or("").to_ascii_uppercase();
        let value = vcard_unescape(value.trim());
        match (name.as_str(), current.as_mut()) {
            ("BEGIN", _) if value.eq_ignore_ascii_case("VCARD") => current = Some(ContactInput::default()),
            ("END", Some(_)) => {
                if let Some(card) = current.take().filter(|c| !c.email.is_empty()) {
                    out.push(card);
                }
            }
            ("FN", Some(card)) => card.name = value,
            ("EMAIL", Some(card)) if card.email.is_empty() => card.email = value,
            ("TEL", Some(card)) if card.phone.is_empty() => card.phone = value,
            ("ORG", Some(card)) => card.organization = value.replace(';', " ").trim().to_owned(),
            ("NOTE", Some(card)) => card.notes = value,
            _ => {}
        }
    }
    out
}

pub async fn contacts_export(State(state): State<AppState>, session: Session) -> Result<Response, ApiError> {
    let contacts: Vec<Contact> = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {CONTACT_COLUMNS} FROM contacts WHERE account_id = ? ORDER BY id")))
        .bind(session.account.id)
        .fetch_all(&state.db)
        .await?;
    Ok(([(header::CONTENT_TYPE, "text/vcard; charset=utf-8"), (header::CONTENT_DISPOSITION, "attachment; filename=\"contacts.vcf\"")], to_vcards(&contacts)).into_response())
}

pub async fn contacts_import(State(state): State<AppState>, session: Session, body: String) -> JsonResult<Value> {
    let (mut imported, mut skipped) = (0, 0);
    for card in parse_vcards(&body).into_iter().take(MAX_CONTACTS as usize) {
        match clean_contact(&card) {
            Ok(contact) => match insert_contact(&state, session.account.id, &contact).await {
                Ok(_) => imported += 1,
                // Already present (or the address book is full): leave the existing entry alone.
                Err(ApiError::Conflict(_)) => skipped += 1,
                Err(err) => return Err(err),
            },
            Err(_) => skipped += 1,
        }
    }
    Ok(Json(json!({ "imported": imported, "skipped": skipped })))
}

// Groups.

pub async fn groups_list(State(state): State<AppState>, session: Session) -> JsonResult<Vec<Value>> {
    let rows: Vec<(i64, String, i64)> = sqlx::query_as(
        "SELECT g.id, g.name, (SELECT COUNT(*) FROM contact_group_members m WHERE m.group_id = g.id) FROM contact_groups g
         WHERE g.account_id = ? ORDER BY g.name COLLATE NOCASE",
    )
    .bind(session.account.id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows.into_iter().map(|(id, name, members)| json!({ "id": id, "name": name, "members": members })).collect()))
}

#[derive(Deserialize)]
pub struct GroupInput {
    name: String,
}

pub async fn group_create(State(state): State<AppState>, session: Session, Json(input): Json<GroupInput>) -> JsonResult<Value> {
    let name = text(&input.name, 100, "the group name")?;
    if name.is_empty() {
        return Err(ApiError::bad("a group needs a name"));
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM contact_groups WHERE account_id = ?").bind(session.account.id).fetch_one(&state.db).await?;
    if count >= MAX_GROUPS {
        return Err(ApiError::Conflict(format!("at most {MAX_GROUPS} groups can be stored")));
    }
    let id = sqlx::query("INSERT INTO contact_groups (account_id, name) VALUES (?, ?)")
        .bind(session.account.id)
        .bind(&name)
        .execute(&state.db)
        .await
        .map_err(conflict("a group with this name already exists"))?
        .last_insert_rowid();
    Ok(Json(json!({ "id": id, "name": name, "members": 0 })))
}

pub async fn group_update(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<GroupInput>) -> JsonResult<Value> {
    let name = text(&input.name, 100, "the group name")?;
    if name.is_empty() {
        return Err(ApiError::bad("a group needs a name"));
    }
    let changed = sqlx::query("UPDATE contact_groups SET name = ? WHERE id = ? AND account_id = ?")
        .bind(&name)
        .bind(id)
        .bind(session.account.id)
        .execute(&state.db)
        .await
        .map_err(conflict("a group with this name already exists"))?
        .rows_affected();
    if changed == 0 { Err(ApiError::NotFound) } else { Ok(Json(json!({ "id": id, "name": name }))) }
}

pub async fn group_delete(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    let removed = sqlx::query("DELETE FROM contact_groups WHERE id = ? AND account_id = ?").bind(id).bind(session.account.id).execute(&state.db).await?.rows_affected();
    if removed == 0 { Err(ApiError::NotFound) } else { Ok(Json(json!({ "ok": true }))) }
}

#[derive(Deserialize)]
pub struct MembersInput {
    contact_ids: Vec<i64>,
}

/// Replaces the members of a group. Contacts of other accounts are silently ignored.
pub async fn group_members_put(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<MembersInput>) -> JsonResult<Value> {
    let owned: Option<i64> = sqlx::query_scalar("SELECT id FROM contact_groups WHERE id = ? AND account_id = ?").bind(id).bind(session.account.id).fetch_optional(&state.db).await?;
    if owned.is_none() {
        return Err(ApiError::NotFound);
    }
    let ids = serde_json::to_string(&input.contact_ids).map_err(anyhow::Error::from)?;
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM contact_group_members WHERE group_id = ?").bind(id).execute(&mut *tx).await?;
    let members = sqlx::query(
        "INSERT INTO contact_group_members (group_id, contact_id)
         SELECT ?1, c.id FROM contacts c WHERE c.account_id = ?2 AND c.id IN (SELECT value FROM json_each(?3))",
    )
    .bind(id)
    .bind(session.account.id)
    .bind(ids)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(Json(json!({ "id": id, "members": members })))
}

pub async fn group_members_get(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Vec<i64>> {
    let ids = sqlx::query_scalar(
        "SELECT m.contact_id FROM contact_group_members m JOIN contact_groups g ON g.id = m.group_id WHERE g.id = ? AND g.account_id = ?",
    )
    .bind(id)
    .bind(session.account.id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(ids))
}

#[derive(Deserialize)]
pub struct SuggestQuery {
    q: String,
}

/// Recipient suggestions for the composer: the user's contacts and groups, the accounts of
/// their own domain (the shared directory) and, when configured, the LDAP directory.
pub async fn contacts_suggest(State(state): State<AppState>, session: Session, Query(query): Query<SuggestQuery>) -> JsonResult<Vec<Value>> {
    let needle = query.q.trim();
    if needle.is_empty() || needle.chars().count() > 100 {
        return Ok(Json(Vec::new()));
    }
    let pattern = like_pattern(needle);
    let mut out: Vec<Value> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    let groups: Vec<(i64, String)> = sqlx::query_as("SELECT id, name FROM contact_groups WHERE account_id = ? AND name LIKE ? ESCAPE '\\' ORDER BY name LIMIT 5")
        .bind(session.account.id)
        .bind(&pattern)
        .fetch_all(&state.db)
        .await?;
    for (id, name) in groups {
        let members: Vec<(String, String)> = sqlx::query_as(
            "SELECT c.name, c.email FROM contacts c JOIN contact_group_members m ON m.contact_id = c.id WHERE m.group_id = ? AND c.email != '' ORDER BY c.email LIMIT 500",
        )
        .bind(id)
        .fetch_all(&state.db)
        .await?;
        if !members.is_empty() {
            out.push(json!({ "source": "group", "name": name, "members": members.iter().map(|(n, e)| json!({ "name": n, "email": e })).collect::<Vec<_>>() }));
        }
    }

    let contacts: Vec<(String, String)> = sqlx::query_as(
        "SELECT name, email FROM contacts WHERE account_id = ?1 AND email != '' AND (name LIKE ?2 ESCAPE '\\' OR email LIKE ?2 ESCAPE '\\') ORDER BY name COLLATE NOCASE LIMIT 10",
    )
    .bind(session.account.id)
    .bind(&pattern)
    .fetch_all(&state.db)
    .await?;
    for (name, email) in contacts {
        if seen.insert(email.clone()) {
            out.push(json!({ "source": "contact", "name": name, "email": email }));
        }
    }

    let directory: Vec<(String, String)> = sqlx::query_as(
        "SELECT display_name, email FROM accounts WHERE domain_id = ?1 AND enabled = 1 AND id != ?2
           AND (display_name LIKE ?3 ESCAPE '\\' OR email LIKE ?3 ESCAPE '\\') ORDER BY email LIMIT 10",
    )
    .bind(session.account.domain_id)
    .bind(session.account.id)
    .bind(&pattern)
    .fetch_all(&state.db)
    .await?;
    for (name, email) in directory {
        if seen.insert(email.clone()) {
            out.push(json!({ "source": "directory", "name": name, "email": email }));
        }
    }

    for entry in crate::ldap::search(&state, needle).await.unwrap_or_default() {
        if seen.insert(entry.email.clone()) {
            out.push(json!({ "source": "ldap", "name": entry.name, "email": entry.email }));
        }
    }
    Ok(Json(out))
}

// --- Response templates --------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct Template {
    id: i64,
    name: String,
    subject: String,
    html: String,
    updated_at: i64,
}

#[derive(Deserialize)]
pub struct TemplateInput {
    name: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    html: String,
}

fn clean_template(input: &TemplateInput) -> Result<(String, String), ApiError> {
    let name = text(&input.name, 100, "the template name")?;
    if name.is_empty() {
        return Err(ApiError::bad("a template needs a name"));
    }
    if input.html.len() > MAX_TEMPLATE_BYTES {
        return Err(ApiError::bad("the template is too long"));
    }
    Ok((name, text(&input.subject, 500, "the subject")?))
}

pub async fn templates_list(State(state): State<AppState>, session: Session) -> JsonResult<Vec<Template>> {
    Ok(Json(
        sqlx::query_as("SELECT id, name, subject, html, updated_at FROM templates WHERE account_id = ? ORDER BY name COLLATE NOCASE")
            .bind(session.account.id)
            .fetch_all(&state.db)
            .await?,
    ))
}

pub async fn template_create(State(state): State<AppState>, session: Session, Json(input): Json<TemplateInput>) -> JsonResult<Value> {
    let (name, subject) = clean_template(&input)?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM templates WHERE account_id = ?").bind(session.account.id).fetch_one(&state.db).await?;
    if count >= MAX_TEMPLATES {
        return Err(ApiError::Conflict(format!("at most {MAX_TEMPLATES} templates can be stored")));
    }
    let id = sqlx::query("INSERT INTO templates (account_id, name, subject, html, updated_at) VALUES (?, ?, ?, ?, ?)")
        .bind(session.account.id)
        .bind(&name)
        .bind(&subject)
        .bind(&input.html)
        .bind(now())
        .execute(&state.db)
        .await
        .map_err(conflict("a template with this name already exists"))?
        .last_insert_rowid();
    Ok(Json(json!({ "id": id, "name": name, "subject": subject, "html": input.html })))
}

pub async fn template_update(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<TemplateInput>) -> JsonResult<Value> {
    let (name, subject) = clean_template(&input)?;
    let changed = sqlx::query("UPDATE templates SET name = ?, subject = ?, html = ?, updated_at = ? WHERE id = ? AND account_id = ?")
        .bind(&name)
        .bind(&subject)
        .bind(&input.html)
        .bind(now())
        .bind(id)
        .bind(session.account.id)
        .execute(&state.db)
        .await
        .map_err(conflict("a template with this name already exists"))?
        .rows_affected();
    if changed == 0 { Err(ApiError::NotFound) } else { Ok(Json(json!({ "id": id, "name": name, "subject": subject, "html": input.html }))) }
}

pub async fn template_delete(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    let removed = sqlx::query("DELETE FROM templates WHERE id = ? AND account_id = ?").bind(id).bind(session.account.id).execute(&state.db).await?.rows_affected();
    if removed == 0 { Err(ApiError::NotFound) } else { Ok(Json(json!({ "ok": true }))) }
}

// --- Signatures ----------------------------------------------------------------------------

const MAX_SIGNATURES: i64 = 50;

#[derive(Serialize, sqlx::FromRow)]
pub struct Signature {
    id: i64,
    name: String,
    html: String,
}

#[derive(Deserialize)]
pub struct SignatureInput {
    name: String,
    #[serde(default)]
    html: String,
}

fn clean_signature(input: &SignatureInput) -> Result<String, ApiError> {
    let name = text(&input.name, 100, "the signature name")?;
    if name.is_empty() {
        return Err(ApiError::bad("a signature needs a name"));
    }
    if input.html.len() > MAX_SIGNATURE_BYTES {
        return Err(ApiError::bad("the signature is too long"));
    }
    Ok(name)
}

/// The signature each sender identity uses for new messages, by identity id (a masked address
/// without an identity of its own by the negated id of the mask).
async fn new_message_signatures(db: &sqlx::SqlitePool, account_id: i64) -> sqlx::Result<std::collections::HashMap<i64, String>> {
    let rows: Vec<(i64, String)> = sqlx::query_as("SELECT d.identity_id, s.html FROM signature_defaults d JOIN signatures s ON s.id = d.new_signature_id WHERE d.account_id = ?")
        .bind(account_id)
        .fetch_all(db)
        .await?;
    Ok(rows.into_iter().collect())
}

/// The signatures, and which one every sender identity uses for new messages and for replies
/// and forwards (`null`: none).
pub async fn signatures_list(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let signatures: Vec<Signature> = sqlx::query_as("SELECT id, name, html FROM signatures WHERE account_id = ? ORDER BY name COLLATE NOCASE")
        .bind(session.account.id)
        .fetch_all(&state.db)
        .await?;
    let chosen: Vec<(i64, Option<i64>, Option<i64>)> = sqlx::query_as("SELECT identity_id, new_signature_id, reply_signature_id FROM signature_defaults WHERE account_id = ?")
        .bind(session.account.id)
        .fetch_all(&state.db)
        .await?;
    let mut defaults = serde_json::Map::new();
    for identity in identity_rows(&state, &session.account).await? {
        let (new, reply) = chosen.iter().find(|(id, ..)| *id == identity.id).map_or((None, None), |(_, new, reply)| (*new, *reply));
        defaults.insert(identity.id.to_string(), json!({ "new_signature_id": new, "reply_signature_id": reply }));
    }
    Ok(Json(json!({ "signatures": signatures, "defaults": defaults })))
}

pub async fn signature_create(State(state): State<AppState>, session: Session, Json(input): Json<SignatureInput>) -> JsonResult<Value> {
    let name = clean_signature(&input)?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM signatures WHERE account_id = ?").bind(session.account.id).fetch_one(&state.db).await?;
    if count >= MAX_SIGNATURES {
        return Err(ApiError::Conflict(format!("at most {MAX_SIGNATURES} signatures can be stored")));
    }
    let id = sqlx::query("INSERT INTO signatures (account_id, name, html, created_at) VALUES (?, ?, ?, ?)")
        .bind(session.account.id)
        .bind(&name)
        .bind(&input.html)
        .bind(now())
        .execute(&state.db)
        .await
        .map_err(conflict("a signature with this name already exists"))?
        .last_insert_rowid();
    Ok(Json(json!({ "id": id, "name": name, "html": input.html })))
}

pub async fn signature_update(State(state): State<AppState>, session: Session, Path(id): Path<i64>, Json(input): Json<SignatureInput>) -> JsonResult<Value> {
    let name = clean_signature(&input)?;
    let changed = sqlx::query("UPDATE signatures SET name = ?, html = ? WHERE id = ? AND account_id = ?")
        .bind(&name)
        .bind(&input.html)
        .bind(id)
        .bind(session.account.id)
        .execute(&state.db)
        .await
        .map_err(conflict("a signature with this name already exists"))?
        .rows_affected();
    if changed == 0 { Err(ApiError::NotFound) } else { Ok(Json(json!({ "id": id, "name": name, "html": input.html }))) }
}

/// Deletes a signature; addresses that used it go without one.
pub async fn signature_delete(State(state): State<AppState>, session: Session, Path(id): Path<i64>) -> JsonResult<Value> {
    let removed = sqlx::query("DELETE FROM signatures WHERE id = ? AND account_id = ?").bind(id).bind(session.account.id).execute(&state.db).await?.rows_affected();
    if removed == 0 { Err(ApiError::NotFound) } else { Ok(Json(json!({ "ok": true }))) }
}

#[derive(Deserialize)]
pub struct SignatureDefaultsInput {
    identity_id: i64,
    new_signature_id: Option<i64>,
    reply_signature_id: Option<i64>,
}

/// Chooses the signatures one sender identity uses.
pub async fn signature_defaults_put(State(state): State<AppState>, session: Session, Json(input): Json<SignatureDefaultsInput>) -> JsonResult<Value> {
    if !identity_rows(&state, &session.account).await?.iter().any(|identity| identity.id == input.identity_id) {
        return Err(ApiError::bad("not one of your sender identities"));
    }
    for id in [input.new_signature_id, input.reply_signature_id].into_iter().flatten() {
        let mine: Option<i64> = sqlx::query_scalar("SELECT 1 FROM signatures WHERE id = ? AND account_id = ?").bind(id).bind(session.account.id).fetch_optional(&state.db).await?;
        if mine.is_none() {
            return Err(ApiError::bad("unknown signature"));
        }
    }
    sqlx::query(
        "INSERT INTO signature_defaults (account_id, identity_id, new_signature_id, reply_signature_id) VALUES (?, ?, ?, ?)
         ON CONFLICT (account_id, identity_id) DO UPDATE SET new_signature_id = excluded.new_signature_id, reply_signature_id = excluded.reply_signature_id",
    )
    .bind(session.account.id)
    .bind(input.identity_id)
    .bind(input.new_signature_id)
    .bind(input.reply_signature_id)
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "identity_id": input.identity_id, "new_signature_id": input.new_signature_id, "reply_signature_id": input.reply_signature_id })))
}

// --- Preferences ---------------------------------------------------------------------------

pub async fn preferences_get(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let data: Option<String> = sqlx::query_scalar("SELECT data FROM preferences WHERE account_id = ?").bind(session.account.id).fetch_optional(&state.db).await?;
    Ok(Json(data.and_then(|json| serde_json::from_str(&json).ok()).unwrap_or_else(|| json!({}))))
}

/// What the web client loads right after signing in, in one request: the preferences, the
/// installed skins and the plug-ins that run in the browser (each as its own endpoint returns it).
pub async fn startup(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let Json(preferences) = preferences_get(State(state.clone()), session.clone()).await?;
    let Json(skins) = crate::api::extend::skins_get(State(state.clone()), session.clone()).await?;
    let Json(plugins) = crate::api::extend::plugins_get(State(state), session).await?;
    Ok(Json(json!({ "preferences": preferences, "skins": skins, "plugins": plugins })))
}

/// Stores the client's preferences. The server treats them as an opaque (but bounded) object.
pub async fn preferences_put(State(state): State<AppState>, session: Session, Json(data): Json<Value>) -> JsonResult<Value> {
    if !data.is_object() {
        return Err(ApiError::bad("preferences must be an object"));
    }
    let encoded = data.to_string();
    if encoded.len() > MAX_PREFERENCES_BYTES {
        return Err(ApiError::bad("preferences are too large"));
    }
    sqlx::query("INSERT INTO preferences (account_id, data) VALUES (?, ?) ON CONFLICT(account_id) DO UPDATE SET data = excluded.data")
        .bind(session.account.id)
        .bind(encoded)
        .execute(&state.db)
        .await?;
    Ok(Json(data))
}

// --- OpenPGP keys --------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PgpInput {
    public_key: String,
    /// Passphrase-protected armored private key; empty keeps the key on the user's device only.
    #[serde(default)]
    private_key: String,
}

pub async fn pgp_get(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let row: Option<(String, String, i64)> =
        sqlx::query_as("SELECT public_key, private_key, updated_at FROM pgp_keys WHERE account_id = ?").bind(session.account.id).fetch_optional(&state.db).await?;
    Ok(Json(match row {
        Some((public_key, private_key, updated_at)) => {
            let private_key = state.secrets.open(&private_key).ok_or_else(|| ApiError::bad("the stored private key cannot be decrypted; save it again"))?;
            json!({ "public_key": public_key, "private_key": private_key, "updated_at": updated_at })
        }
        None => Value::Null,
    }))
}

pub async fn pgp_put(State(state): State<AppState>, session: Session, Json(input): Json<PgpInput>) -> JsonResult<Value> {
    let (public_key, private_key) = (input.public_key.trim(), input.private_key.trim());
    if public_key.len() > MAX_PGP_KEY_BYTES || !public_key.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
        return Err(ApiError::bad("an armored public key is required"));
    }
    if private_key.len() > MAX_PGP_KEY_BYTES || (!private_key.is_empty() && !private_key.starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----")) {
        return Err(ApiError::bad("the private key must be an armored, passphrase-protected key"));
    }
    sqlx::query(
        "INSERT INTO pgp_keys (account_id, public_key, private_key, updated_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(account_id) DO UPDATE SET public_key = excluded.public_key, private_key = excluded.private_key, updated_at = excluded.updated_at",
    )
    .bind(session.account.id)
    .bind(public_key)
    .bind(state.secrets.seal(private_key))
    .bind(now())
    .execute(&state.db)
    .await?;
    session.audit(&state, "pgp.key_saved", &session.account.email, if private_key.is_empty() { "public only" } else { "with protected private key" }).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn pgp_delete(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    sqlx::query("DELETE FROM pgp_keys WHERE account_id = ?").bind(session.account.id).execute(&state.db).await?;
    session.audit(&state, "pgp.key_removed", &session.account.email, "").await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct PgpLookup {
    emails: String,
}

/// Public keys for a list of recipients: the user's contacts first, then keys published by
/// accounts on this server.
pub async fn pgp_lookup(State(state): State<AppState>, session: Session, Query(query): Query<PgpLookup>) -> JsonResult<Value> {
    let mut out = serde_json::Map::new();
    for email in query.emails.split(',').filter_map(Address::parse).take(100) {
        let email = email.to_string();
        let from_contact: Option<String> = sqlx::query_scalar("SELECT pgp_key FROM contacts WHERE account_id = ? AND email = ? AND pgp_key != ''")
            .bind(session.account.id)
            .bind(&email)
            .fetch_optional(&state.db)
            .await?;
        let key = match from_contact {
            Some(key) => Some(key),
            None => sqlx::query_scalar("SELECT k.public_key FROM pgp_keys k JOIN accounts a ON a.id = k.account_id WHERE a.email = ?").bind(&email).fetch_optional(&state.db).await?,
        };
        if let Some(key) = key {
            out.insert(email, Value::String(key));
        }
    }
    Ok(Json(Value::Object(out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcard_round_trip() {
        let contacts = vec![Contact {
            id: 1,
            name: "Doe; John, Jr.".into(),
            email: "john@example.org".into(),
            phone: "+48 123".into(),
            organization: "ACME".into(),
            notes: "line one\nline two".into(),
            pgp_key: String::new(),
            updated_at: 0,
        }];
        let text = to_vcards(&contacts);
        assert!(text.contains("FN:Doe\\; John\\, Jr.\r\n") && text.contains("NOTE:line one\\nline two\r\n"));
        let parsed = parse_vcards(&text);
        assert_eq!(parsed.len(), 1);
        assert_eq!((parsed[0].name.as_str(), parsed[0].email.as_str(), parsed[0].notes.as_str()), ("Doe; John, Jr.", "john@example.org", "line one\nline two"));
    }

    #[test]
    fn vcard_import_tolerates_real_world_files() {
        let data = "BEGIN:VCARD\nVERSION:4.0\nFN:Ann Example\nitem1.EMAIL;TYPE=work:ann@example.org\nEMAIL:second@example.org\nORG:Example;Sales\nNOTE:folded\n  line\nEND:VCARD\n\
                    BEGIN:VCARD\nFN:No Mail\nEND:VCARD\nEMAIL:outside@example.org\n";
        let parsed = parse_vcards(data);
        assert_eq!(parsed.len(), 1, "cards without an address and stray lines are ignored");
        assert_eq!(parsed[0].email, "ann@example.org", "the first address wins");
        assert_eq!(parsed[0].organization, "Example Sales");
        assert_eq!(parsed[0].notes, "folded line");
    }
}
