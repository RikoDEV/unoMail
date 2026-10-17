//! The user's S/MIME certificate, and the certificates known for correspondents.

use axum::{
    Json,
    extract::{Query, State},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{JsonResult, Session};
use crate::{app::AppState, error::ApiError, smime, util::now};

pub async fn get(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let certificate: Option<String> = sqlx::query_scalar("SELECT certificate FROM smime_identities WHERE account_id = ?").bind(session.account.id).fetch_optional(&state.db).await?;
    let info = certificate.and_then(|c| STANDARD.decode(c).ok()).and_then(|der| smime::cert_info(&der));
    let known: Vec<(String, i64)> = sqlx::query_as("SELECT email, not_after FROM smime_certificates WHERE account_id = ? ORDER BY email").bind(session.account.id).fetch_all(&state.db).await?;
    Ok(Json(json!({
        "certificate": info,
        "correspondents": known.into_iter().map(|(email, not_after)| json!({ "email": email, "not_after": not_after })).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
pub struct Import {
    /// The PKCS #12 file, base64.
    file: String,
    password: String,
}

/// Imports a certificate and private key from a PKCS #12 file.
pub async fn import(State(state): State<AppState>, session: Session, Json(input): Json<Import>) -> JsonResult<Value> {
    let data = STANDARD.decode(input.file.trim()).map_err(|_| ApiError::bad("the file could not be read"))?;
    if data.len() > 64 * 1024 {
        return Err(ApiError::bad("the file is too large for a certificate"));
    }
    let (certificate, key, chain) = smime::import_p12_isolated(data, input.password).await.map_err(ApiError::bad)?;
    let info = smime::cert_info(&certificate).ok_or_else(|| ApiError::bad("the certificate cannot be read"))?;
    if !info.emails.iter().any(|e| e.eq_ignore_ascii_case(&session.account.email)) {
        return Err(ApiError::bad(format!("this certificate is for {}, not for {}", info.emails.join(", "), session.account.email)));
    }
    if info.not_after < now() {
        return Err(ApiError::bad("this certificate has expired"));
    }
    let chain: Vec<String> = chain.iter().map(|c| STANDARD.encode(c)).collect();
    sqlx::query(
        "INSERT INTO smime_identities (account_id, certificate, chain, key_sealed, created_at) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (account_id) DO UPDATE SET certificate = excluded.certificate, chain = excluded.chain, key_sealed = excluded.key_sealed, created_at = excluded.created_at",
    )
    .bind(session.account.id)
    .bind(STANDARD.encode(&certificate))
    .bind(serde_json::to_string(&chain).unwrap_or_default())
    .bind(state.secrets.seal(&STANDARD.encode(&key)))
    .bind(now())
    .execute(&state.db)
    .await?;
    session.audit(&state, "smime.certificate_set", &session.account.email, &info.fingerprint).await;
    Ok(Json(json!({ "certificate": info })))
}

pub async fn remove(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    sqlx::query("DELETE FROM smime_identities WHERE account_id = ?").bind(session.account.id).execute(&state.db).await?;
    session.audit(&state, "smime.certificate_removed", &session.account.email, "").await;
    Ok(Json(json!({ "certificate": null })))
}

#[derive(Deserialize)]
pub struct Lookup {
    emails: String,
}

/// Which of the addresses mail can be encrypted to.
pub async fn lookup(State(state): State<AppState>, session: Session, Query(query): Query<Lookup>) -> JsonResult<Value> {
    let emails: Vec<String> = query.emails.split(',').map(|e| e.trim().to_ascii_lowercase()).filter(|e| !e.is_empty()).take(100).collect();
    let known = smime::certificates(&state, session.account.id, &emails).await?;
    Ok(Json(json!(emails.iter().filter(|e| known.contains_key(*e)).collect::<Vec<_>>())))
}
