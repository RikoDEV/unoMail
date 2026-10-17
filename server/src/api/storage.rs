//! Storage settings: a user's OpenPGP key for encryption at rest, and backups.

use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{JsonResult, Session};
use crate::{app::AppState, error::ApiError, openpgp};

/// Whether incoming mail is stored encrypted to the account's OpenPGP key (the one kept for
/// the web mail), and whether that key can be used for it.
pub async fn encryption(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let row: Option<(String, bool)> = sqlx::query_as("SELECT public_key, encrypt_incoming FROM pgp_keys WHERE account_id = ?").bind(session.account.id).fetch_optional(&state.db).await?;
    Ok(Json(match row {
        None => json!({ "enabled": false, "key": null, "problem": null }),
        Some((public_key, enabled)) => match openpgp::parse_certificate(public_key.as_bytes()) {
            Ok((_, info)) => json!({ "enabled": enabled, "key": info, "problem": null }),
            Err(problem) => json!({ "enabled": enabled, "key": null, "problem": problem }),
        },
    }))
}

#[derive(Deserialize)]
pub struct EncryptionInput {
    enabled: bool,
}

/// Starts or stops encrypting incoming mail. What was encrypted stays encrypted.
pub async fn encryption_set(State(state): State<AppState>, session: Session, Json(input): Json<EncryptionInput>) -> JsonResult<Value> {
    let public_key: Option<String> = sqlx::query_scalar("SELECT public_key FROM pgp_keys WHERE account_id = ?").bind(session.account.id).fetch_optional(&state.db).await?;
    if input.enabled {
        let Some(public_key) = public_key else { return Err(ApiError::bad("set up an OpenPGP key first")) };
        openpgp::parse_certificate(public_key.as_bytes()).map_err(ApiError::bad)?;
    }
    sqlx::query("UPDATE pgp_keys SET encrypt_incoming = ? WHERE account_id = ?").bind(input.enabled).bind(session.account.id).execute(&state.db).await?;
    session.audit(&state, if input.enabled { "pgp.encrypt_incoming_on" } else { "pgp.encrypt_incoming_off" }, &session.account.email, "").await;
    encryption(State(state), session).await
}

/// Backup configuration, snapshots at the target and recent runs.
pub async fn backups(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    session.require_super()?;
    let runs = crate::backup::runs(&state, 30).await?;
    let (target, snapshots, error) = match &state.cfg.backup_target {
        None => (None, Vec::new(), None),
        Some(cfg) => match crate::backup::Target::from_config(cfg) {
            Ok(target) => {
                let name = target.describe();
                match target.snapshots().await {
                    Ok(ids) => {
                        let mut list = Vec::new();
                        for id in ids.iter().rev() {
                            if let Ok(Some(manifest)) = target.manifest(id).await {
                                list.push(manifest);
                            }
                        }
                        (Some(name), list, None)
                    }
                    Err(err) => (Some(name), Vec::new(), Some(format!("{err:#}"))),
                }
            }
            Err(err) => (None, Vec::new(), Some(format!("{err:#}"))),
        },
    };
    Ok(Json(json!({
        "configured": state.cfg.backup_target.is_some(),
        "target": target,
        "hour": state.cfg.backup_hour,
        "keep": state.cfg.backup_keep,
        "storage": state.store.blobs.describe(),
        "encrypted_mail": state.store.blobs.encrypted(),
        "snapshots": snapshots,
        "runs": runs,
        "error": error,
    })))
}

/// Starts a backup now; its progress shows in the list of runs.
pub async fn backup_start(State(state): State<AppState>, session: Session) -> Result<(StatusCode, Json<Value>), ApiError> {
    session.require_super()?;
    if state.cfg.backup_target.is_none() {
        return Err(ApiError::bad("no backup target is configured (UNOMAIL_BACKUP_DIR or UNOMAIL_BACKUP_S3_BUCKET)"));
    }
    session.audit(&state, "backup.started", "", "").await;
    let app = state.clone();
    tokio::spawn(async move {
        let _ = crate::backup::run(&app).await;
    });
    Ok((StatusCode::ACCEPTED, Json(json!({ "started": true }))))
}
