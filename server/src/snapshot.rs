//! JSON snapshots of in-memory state that should survive a restart: written with the other
//! state every minute and at shutdown, read back at startup.

use serde::{Serialize, de::DeserializeOwned};
use sqlx::SqlitePool;

pub async fn save(db: &SqlitePool, name: &str, value: &impl Serialize) -> sqlx::Result<()> {
    let json = serde_json::to_string(value).map_err(|err| sqlx::Error::Encode(Box::new(err)))?;
    sqlx::query("INSERT INTO state_snapshots (name, value) VALUES (?, ?) ON CONFLICT (name) DO UPDATE SET value = excluded.value")
        .bind(name)
        .bind(json)
        .execute(db)
        .await?;
    Ok(())
}

/// The saved value, or `None` when there is none or it no longer reads (after an upgrade).
pub async fn load<T: DeserializeOwned>(db: &SqlitePool, name: &str) -> sqlx::Result<Option<T>> {
    let json: Option<String> = sqlx::query_scalar("SELECT value FROM state_snapshots WHERE name = ?").bind(name).fetch_optional(db).await?;
    Ok(json.and_then(|json| match serde_json::from_str(&json) {
        Ok(value) => Some(value),
        Err(err) => {
            tracing::warn!(%err, name, "saved state ignored");
            None
        }
    }))
}
