//! Storage of calendars and their objects.

use chrono_tz::Tz;
use serde::Serialize;
use sqlx::SqlitePool;

use super::ical;
use crate::util::{now, sha256_hex};

pub const MAX_CALENDARS: i64 = 50;
pub const MAX_OBJECTS: i64 = 20_000;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Calendar {
    pub id: i64,
    pub account_id: i64,
    pub slug: String,
    pub name: String,
    pub color: String,
    pub description: String,
    pub sync_token: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Object {
    pub id: i64,
    pub calendar_id: i64,
    pub name: String,
    pub uid: String,
    pub etag: String,
    pub data: String,
    pub component: String,
    pub summary: String,
    pub first_start: Option<i64>,
    pub last_end: Option<i64>,
    pub modified: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum CalendarError {
    #[error("{0}")]
    Invalid(String),
    #[error("another object in this calendar already uses this UID")]
    UidConflict,
    #[error("already exists")]
    Exists,
    #[error("limit reached")]
    Limit,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Prefix of the address under which a calendar shared by somebody else appears.
pub const SHARED_PREFIX: &str = "shared-";

pub fn valid_slug(slug: &str) -> bool {
    !slug.starts_with(SHARED_PREFIX) && !slug.is_empty() && slug.len() <= 64 && slug.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')) && !slug.starts_with('.')
}

/// Resource names come from clients and become part of URLs.
pub fn valid_object_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 255 && !name.starts_with('.') && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@' | b'+' | b'=' | b'~'))
}

pub fn valid_color(color: &str) -> bool {
    color.is_empty() || ((color.len() == 7 || color.len() == 9) && color.starts_with('#') && color[1..].bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The time zone in which an account reads times that name no zone ("floating" times). The
/// web client records the browser's zone in the preferences; without it, UTC.
pub async fn zone_of(db: &SqlitePool, account_id: i64) -> Tz {
    let data: Option<String> = sqlx::query_scalar("SELECT data FROM preferences WHERE account_id = ?").bind(account_id).fetch_optional(db).await.ok().flatten();
    data.and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok()).and_then(|prefs| prefs["timezone"].as_str()?.parse().ok()).unwrap_or(Tz::UTC)
}

/// A calendar as one account may use it: its own, or one shared by a colleague.
#[derive(Debug, Clone)]
pub struct Access {
    pub calendar: Calendar,
    /// Address of the account the calendar belongs to.
    pub owner: String,
    pub shared: bool,
    pub writable: bool,
}

impl Access {
    /// Last path segment under which the user reaches the calendar over CalDAV.
    pub fn slug(&self) -> String {
        if self.shared { format!("{SHARED_PREFIX}{}", self.calendar.id) } else { self.calendar.slug.clone() }
    }

    /// Name shown to the user: shared calendars say whose they are.
    pub fn title(&self) -> String {
        if self.shared { format!("{} ({})", self.calendar.name, self.owner) } else { self.calendar.name.clone() }
    }
}

/// A shared calendar's columns, the owner's address, and whether it may be written.
type SharedRow = (i64, i64, String, String, String, String, i64, String, i64);

/// Every calendar the account can see: its own first, then those shared with it by accounts
/// that are not disabled.
pub async fn accessible(db: &SqlitePool, account: &crate::auth::Account) -> sqlx::Result<Vec<Access>> {
    let mut out: Vec<Access> = list(db, account.id).await?.into_iter().map(|calendar| Access { calendar, owner: account.email.clone(), shared: false, writable: true }).collect();
    let rows: Vec<SharedRow> = sqlx::query_as(
        "SELECT c.id, c.account_id, c.slug, c.name, c.color, c.description, c.sync_token, a.email, s.writable
           FROM calendar_shares s JOIN calendars c ON c.id = s.calendar_id JOIN accounts a ON a.id = c.account_id
                JOIN domains d ON d.id = a.domain_id
          WHERE s.account_id = ? AND a.enabled = 1 AND d.enabled = 1 ORDER BY a.email, c.id",
    )
    .bind(account.id)
    .fetch_all(db)
    .await?;
    out.extend(rows.into_iter().map(|(id, account_id, slug, name, color, description, sync_token, owner, writable)| Access {
        calendar: Calendar { id, account_id, slug, name, color, description, sync_token },
        owner,
        shared: true,
        writable: writable != 0,
    }));
    Ok(out)
}

pub async fn access_by_id(db: &SqlitePool, account: &crate::auth::Account, id: i64) -> sqlx::Result<Option<Access>> {
    Ok(accessible(db, account).await?.into_iter().find(|access| access.calendar.id == id))
}

pub async fn access_by_slug(db: &SqlitePool, account: &crate::auth::Account, slug: &str) -> sqlx::Result<Option<Access>> {
    Ok(accessible(db, account).await?.into_iter().find(|access| access.slug() == slug))
}

/// With whom a calendar is shared: (account id, address, may write).
pub async fn shares(db: &SqlitePool, calendar_id: i64) -> sqlx::Result<Vec<(i64, String, bool)>> {
    let rows: Vec<(i64, String, i64)> = sqlx::query_as("SELECT a.id, a.email, s.writable FROM calendar_shares s JOIN accounts a ON a.id = s.account_id WHERE s.calendar_id = ? ORDER BY a.email")
        .bind(calendar_id)
        .fetch_all(db)
        .await?;
    Ok(rows.into_iter().map(|(id, email, writable)| (id, email, writable != 0)).collect())
}

/// Replaces the list of accounts a calendar is shared with.
pub async fn set_shares(db: &SqlitePool, calendar_id: i64, shares: &[(i64, bool)]) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM calendar_shares WHERE calendar_id = ?").bind(calendar_id).execute(&mut *tx).await?;
    for (account_id, writable) in shares {
        sqlx::query("INSERT OR REPLACE INTO calendar_shares (calendar_id, account_id, writable) VALUES (?, ?, ?)").bind(calendar_id).bind(account_id).bind(i64::from(*writable)).execute(&mut *tx).await?;
    }
    tx.commit().await
}

/// The object with a given UID in one of the account's own calendars (where invitations live).
pub async fn object_by_uid(db: &SqlitePool, account_id: i64, uid: &str) -> sqlx::Result<Option<(Calendar, Object)>> {
    for calendar in list(db, account_id).await? {
        let found: Option<Object> = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {OBJECT_COLUMNS} FROM calendar_objects WHERE calendar_id = ? AND uid = ?"))).bind(calendar.id).bind(uid).fetch_optional(db).await?;
        if let Some(object) = found {
            return Ok(Some((calendar, object)));
        }
    }
    Ok(None)
}

/// The calendars of an account. Every account has at least one; it is created on first use.
pub async fn list(db: &SqlitePool, account_id: i64) -> sqlx::Result<Vec<Calendar>> {
    let found: Vec<Calendar> = sqlx::query_as("SELECT id, account_id, slug, name, color, description, sync_token FROM calendars WHERE account_id = ? ORDER BY id").bind(account_id).fetch_all(db).await?;
    if !found.is_empty() {
        return Ok(found);
    }
    sqlx::query("INSERT OR IGNORE INTO calendars (account_id, slug, name, color, created_at) VALUES (?, 'personal', 'Personal', '#1a73e8', ?)").bind(account_id).bind(now()).execute(db).await?;
    sqlx::query_as("SELECT id, account_id, slug, name, color, description, sync_token FROM calendars WHERE account_id = ? ORDER BY id").bind(account_id).fetch_all(db).await
}

pub async fn by_slug(db: &SqlitePool, account_id: i64, slug: &str) -> sqlx::Result<Option<Calendar>> {
    Ok(list(db, account_id).await?.into_iter().find(|calendar| calendar.slug == slug))
}

pub async fn by_id(db: &SqlitePool, account_id: i64, id: i64) -> sqlx::Result<Option<Calendar>> {
    Ok(list(db, account_id).await?.into_iter().find(|calendar| calendar.id == id))
}

fn clean_name(name: &str) -> Result<String, CalendarError> {
    let name: String = name.trim().chars().filter(|c| !c.is_control()).collect();
    if name.is_empty() || name.chars().count() > 100 { Err(CalendarError::Invalid("a calendar needs a name of at most 100 characters".into())) } else { Ok(name) }
}

pub async fn create(db: &SqlitePool, account_id: i64, slug: &str, name: &str, color: &str, description: &str) -> Result<Calendar, CalendarError> {
    if !valid_slug(slug) {
        return Err(CalendarError::Invalid("invalid calendar address".into()));
    }
    if !valid_color(color) {
        return Err(CalendarError::Invalid("the colour must look like #rrggbb".into()));
    }
    let name = clean_name(name)?;
    let existing = list(db, account_id).await?;
    if existing.len() as i64 >= MAX_CALENDARS {
        return Err(CalendarError::Limit);
    }
    if existing.iter().any(|calendar| calendar.slug == slug) {
        return Err(CalendarError::Exists);
    }
    let description: String = description.chars().filter(|c| !c.is_control()).take(500).collect();
    sqlx::query("INSERT INTO calendars (account_id, slug, name, color, description, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(account_id)
        .bind(slug)
        .bind(&name)
        .bind(color.to_ascii_lowercase())
        .bind(description)
        .bind(now())
        .execute(db)
        .await?;
    Ok(by_slug(db, account_id, slug).await?.expect("the calendar was just created"))
}

/// Changes the display properties of a calendar; `None` leaves a property as it is.
pub async fn update(db: &SqlitePool, calendar: &Calendar, name: Option<&str>, color: Option<&str>, description: Option<&str>) -> Result<(), CalendarError> {
    let name = match name {
        Some(name) => clean_name(name)?,
        None => calendar.name.clone(),
    };
    let color = color.unwrap_or(&calendar.color);
    if !valid_color(color) {
        return Err(CalendarError::Invalid("the colour must look like #rrggbb".into()));
    }
    let description: String = description.unwrap_or(&calendar.description).chars().filter(|c| !c.is_control()).take(500).collect();
    sqlx::query("UPDATE calendars SET name = ?, color = ?, description = ?, sync_token = sync_token + 1 WHERE id = ?")
        .bind(name)
        .bind(color.to_ascii_lowercase())
        .bind(description)
        .bind(calendar.id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn delete(db: &SqlitePool, calendar: &Calendar) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM calendars WHERE id = ?").bind(calendar.id).execute(db).await?;
    Ok(())
}

const OBJECT_COLUMNS: &str = "id, calendar_id, name, uid, etag, data, component, summary, first_start, last_end, modified";

pub async fn objects(db: &SqlitePool, calendar_id: i64) -> sqlx::Result<Vec<Object>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {OBJECT_COLUMNS} FROM calendar_objects WHERE calendar_id = ? ORDER BY id"))).bind(calendar_id).fetch_all(db).await
}

pub async fn object(db: &SqlitePool, calendar_id: i64, name: &str) -> sqlx::Result<Option<Object>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {OBJECT_COLUMNS} FROM calendar_objects WHERE calendar_id = ? AND name = ?"))).bind(calendar_id).bind(name).fetch_optional(db).await
}

pub async fn object_by_id(db: &SqlitePool, calendar_id: i64, id: i64) -> sqlx::Result<Option<Object>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {OBJECT_COLUMNS} FROM calendar_objects WHERE calendar_id = ? AND id = ?"))).bind(calendar_id).bind(id).fetch_optional(db).await
}

/// Objects that may have an occurrence in `[from, to)`, optionally of one component type.
/// Recurring objects are matched by the span of their whole series. The index is coarse (and
/// was computed in the owner's time zone), so a day of margin is added on both sides; callers
/// confirm with the real expansion.
pub async fn in_range(db: &SqlitePool, calendar_id: i64, from: i64, to: i64, component: Option<&str>) -> sqlx::Result<Vec<Object>> {
    let (from, to) = (from.saturating_sub(86_400), to.saturating_add(86_400));
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {OBJECT_COLUMNS} FROM calendar_objects WHERE calendar_id = ?1 AND (?4 IS NULL OR component = ?4)
           AND first_start IS NOT NULL AND first_start < ?3 AND (last_end IS NULL OR last_end > ?2 OR (last_end = first_start AND first_start >= ?2))
         ORDER BY first_start"
    )))
    .bind(calendar_id)
    .bind(from)
    .bind(to)
    .bind(component)
    .fetch_all(db)
    .await
}

/// The merged periods inside `[from, to)` during which the calendars hold something that
/// takes time (events marked as free and cancelled ones do not count).
pub async fn busy(db: &SqlitePool, calendars: &[Calendar], from: i64, to: i64, zone: Tz) -> sqlx::Result<Vec<(i64, i64)>> {
    let mut periods: Vec<(i64, i64)> = Vec::new();
    for calendar in calendars {
        for object in in_range(db, calendar.id, from, to, Some("VEVENT")).await? {
            periods.extend(ical::occurrences(&object.data, from, to, zone).into_iter().filter(|o| o.busy && o.end > o.start).map(|o| (o.start.max(from), o.end.min(to))));
        }
    }
    periods.sort_unstable();
    let mut merged: Vec<(i64, i64)> = Vec::new();
    for (start, end) in periods {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    Ok(merged)
}

fn etag_of(data: &str) -> String {
    format!("\"{}\"", &sha256_hex(data.as_bytes())[..32])
}

/// Stores an object under `name`, replacing a previous version. Returns the object and whether
/// it is new. The data is validated but stored unchanged.
pub async fn put_object(db: &SqlitePool, calendar: &Calendar, name: &str, data: &str) -> Result<(Object, bool), CalendarError> {
    let zone = zone_of(db, calendar.account_id).await;
    if !valid_object_name(name) {
        return Err(CalendarError::Invalid("invalid object name".into()));
    }
    let info = ical::inspect(data, zone).map_err(CalendarError::Invalid)?;
    let mut tx = db.begin().await?;
    let existing: Option<i64> = sqlx::query_scalar("SELECT id FROM calendar_objects WHERE calendar_id = ? AND name = ?").bind(calendar.id).bind(name).fetch_optional(&mut *tx).await?;
    let same_uid: Option<String> = sqlx::query_scalar("SELECT name FROM calendar_objects WHERE calendar_id = ? AND uid = ?").bind(calendar.id).bind(&info.uid).fetch_optional(&mut *tx).await?;
    if same_uid.is_some_and(|other| other != name) {
        return Err(CalendarError::UidConflict);
    }
    if existing.is_none() {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM calendar_objects WHERE calendar_id = ?").bind(calendar.id).fetch_one(&mut *tx).await?;
        if count >= MAX_OBJECTS {
            return Err(CalendarError::Limit);
        }
    }
    let token: i64 = sqlx::query_scalar("UPDATE calendars SET sync_token = sync_token + 1 WHERE id = ? RETURNING sync_token").bind(calendar.id).fetch_one(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO calendar_objects (calendar_id, name, uid, etag, data, component, summary, first_start, last_end, modified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(calendar_id, name) DO UPDATE SET uid = excluded.uid, etag = excluded.etag, data = excluded.data, component = excluded.component,
             summary = excluded.summary, first_start = excluded.first_start, last_end = excluded.last_end, modified = excluded.modified",
    )
    .bind(calendar.id)
    .bind(name)
    .bind(&info.uid)
    .bind(etag_of(data))
    .bind(data)
    .bind(&info.component)
    .bind(&info.summary)
    .bind(info.first_start)
    .bind(info.last_end)
    .bind(token)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM calendar_tombstones WHERE calendar_id = ? AND name = ?").bind(calendar.id).bind(name).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((object(db, calendar.id, name).await?.expect("the object was just stored"), existing.is_none()))
}

pub async fn delete_object(db: &SqlitePool, calendar: &Calendar, name: &str) -> sqlx::Result<bool> {
    let mut tx = db.begin().await?;
    let removed = sqlx::query("DELETE FROM calendar_objects WHERE calendar_id = ? AND name = ?").bind(calendar.id).bind(name).execute(&mut *tx).await?.rows_affected();
    if removed > 0 {
        let token: i64 = sqlx::query_scalar("UPDATE calendars SET sync_token = sync_token + 1 WHERE id = ? RETURNING sync_token").bind(calendar.id).fetch_one(&mut *tx).await?;
        sqlx::query("INSERT OR REPLACE INTO calendar_tombstones (calendar_id, name, modified) VALUES (?, ?, ?)").bind(calendar.id).bind(name).bind(token).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(removed > 0)
}

/// Moves an object to another calendar of the same account, keeping its id (and name, so
/// CalDAV clients find it there). The old calendar remembers the name as removed.
pub async fn move_object(db: &SqlitePool, from: &Calendar, to: &Calendar, name: &str) -> Result<(), CalendarError> {
    let mut tx = db.begin().await?;
    let uid: Option<String> = sqlx::query_scalar("SELECT uid FROM calendar_objects WHERE calendar_id = ? AND name = ?").bind(from.id).bind(name).fetch_optional(&mut *tx).await?;
    let Some(uid) = uid else { return Err(CalendarError::Invalid("no such object".into())) };
    let clash: Option<i64> = sqlx::query_scalar("SELECT id FROM calendar_objects WHERE calendar_id = ? AND (uid = ? OR name = ?)").bind(to.id).bind(&uid).bind(name).fetch_optional(&mut *tx).await?;
    if clash.is_some() {
        return Err(CalendarError::UidConflict);
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM calendar_objects WHERE calendar_id = ?").bind(to.id).fetch_one(&mut *tx).await?;
    if count >= MAX_OBJECTS {
        return Err(CalendarError::Limit);
    }
    let old_token: i64 = sqlx::query_scalar("UPDATE calendars SET sync_token = sync_token + 1 WHERE id = ? RETURNING sync_token").bind(from.id).fetch_one(&mut *tx).await?;
    let new_token: i64 = sqlx::query_scalar("UPDATE calendars SET sync_token = sync_token + 1 WHERE id = ? RETURNING sync_token").bind(to.id).fetch_one(&mut *tx).await?;
    sqlx::query("UPDATE calendar_objects SET calendar_id = ?, modified = ? WHERE calendar_id = ? AND name = ?").bind(to.id).bind(new_token).bind(from.id).bind(name).execute(&mut *tx).await?;
    sqlx::query("INSERT OR REPLACE INTO calendar_tombstones (calendar_id, name, modified) VALUES (?, ?, ?)").bind(from.id).bind(name).bind(old_token).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM calendar_tombstones WHERE calendar_id = ? AND name = ?").bind(to.id).bind(name).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

/// What changed in a calendar after `token`: (objects added or modified, names removed).
pub async fn changes_since(db: &SqlitePool, calendar_id: i64, token: i64) -> sqlx::Result<(Vec<Object>, Vec<String>)> {
    let changed = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {OBJECT_COLUMNS} FROM calendar_objects WHERE calendar_id = ? AND modified > ? ORDER BY id"))).bind(calendar_id).bind(token).fetch_all(db).await?;
    let removed = sqlx::query_scalar("SELECT name FROM calendar_tombstones WHERE calendar_id = ? AND modified > ? ORDER BY name").bind(calendar_id).bind(token).fetch_all(db).await?;
    Ok((changed, removed))
}
