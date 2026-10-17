//! Certificate management: automated (ACME) and custom certificates.

use axum::{Json, extract::State};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{JsonResult, Session};
use crate::{
    acme::{self, AcmeConfig, Challenge},
    app::AppState,
    error::ApiError,
    tls::{self, CertKind},
};

/// PEM bundles are small; anything larger is not a certificate.
const MAX_PEM_BYTES: usize = 64 * 1024;

async fn status_json(state: &AppState) -> Result<Value, ApiError> {
    let info = state.tls.info();
    let config = acme::load_config(state).await?;
    Ok(json!({
        "certificate": {
            "kind": info.kind,
            "domains": info.domains,
            "issuer": info.issuer,
            "not_before": info.not_before,
            "not_after": info.not_after,
            "seconds_remaining": info.seconds_remaining(),
            "expires_soon": info.seconds_remaining() < tls::RENEW_BEFORE_SECS,
            "covers_hostname": info.domains.iter().any(|d| tls::san_matches(d, &state.cfg.hostname)),
        },
        "hostname": state.cfg.hostname,
        "mode": match (&config, info.kind) {
            (Some(_), _) => "acme",
            (None, CertKind::Custom) => "custom",
            (None, _) => "self_signed",
        },
        // The DNS provider token is write-only: it is never returned to the browser.
        "acme": config.as_ref().map(|c| json!({
            "domains": c.domains,
            "email": c.email,
            "challenge": c.challenge,
            "has_cloudflare_token": c.cloudflare_token.is_some(),
        })),
        "acme_last_error": acme::last_error(state).await,
        "acme_directory": state.cfg.acme_directory,
    }))
}

pub async fn status(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    session.require_super()?;
    Ok(Json(status_json(&state).await?))
}

#[derive(Deserialize)]
pub struct CustomCertificate {
    cert_pem: String,
    key_pem: String,
}

fn check_size(req: &CustomCertificate) -> Result<(), ApiError> {
    if req.cert_pem.len() > MAX_PEM_BYTES || req.key_pem.len() > MAX_PEM_BYTES {
        return Err(ApiError::TooLarge);
    }
    Ok(())
}

/// Dry run: reports what installing the certificate would do without changing anything.
pub async fn validate(State(state): State<AppState>, session: Session, Json(req): Json<CustomCertificate>) -> JsonResult<Value> {
    session.require_super()?;
    check_size(&req)?;
    Ok(Json(match tls::validate(&req.cert_pem, &req.key_pem, &state.cfg.hostname) {
        Ok(v) => json!({
            "valid": true,
            "domains": v.domains,
            "issuer": v.issuer,
            "not_before": v.not_before,
            "not_after": v.not_after,
            "warnings": v.warnings,
        }),
        Err(reason) => json!({ "valid": false, "error": reason }),
    }))
}

pub async fn install_custom(State(state): State<AppState>, session: Session, Json(req): Json<CustomCertificate>) -> JsonResult<Value> {
    session.require_super()?;
    check_size(&req)?;
    let (info, warnings) = state.tls.install(CertKind::Custom, &req.cert_pem, &req.key_pem).await.map_err(ApiError::bad)?;
    // A custom certificate overrides automation; otherwise the next renewal would replace it.
    acme::clear_config(&state).await?;
    session.audit(&state, "tls.custom_installed", &info.domains.join(","), &warnings.join("; ")).await;
    let mut status = status_json(&state).await?;
    status["warnings"] = json!(warnings);
    Ok(Json(status))
}

pub async fn self_signed(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    session.require_super()?;
    acme::clear_config(&state).await?;
    state.tls.reset_to_self_signed().await?;
    session.audit(&state, "tls.self_signed", &state.cfg.hostname, "").await;
    Ok(Json(status_json(&state).await?))
}

#[derive(Deserialize)]
pub struct AcmeRequest {
    domains: Vec<String>,
    email: String,
    #[serde(default)]
    challenge: Option<Challenge>,
    /// Omitted to keep the stored token.
    #[serde(default)]
    cloudflare_token: Option<String>,
}

/// Saves the ACME settings and immediately requests a certificate. The current certificate
/// stays active until the new one has been issued and validated.
pub async fn configure_acme(State(state): State<AppState>, session: Session, Json(req): Json<AcmeRequest>) -> JsonResult<Value> {
    session.require_super()?;
    let previous = acme::load_config(&state).await?;
    let config = AcmeConfig {
        domains: req.domains,
        email: req.email,
        challenge: req.challenge.unwrap_or(Challenge::Http01),
        cloudflare_token: req.cloudflare_token.filter(|t| !t.trim().is_empty()).or(previous.and_then(|p| p.cloudflare_token)),
    }
    .validated()
    .map_err(ApiError::bad)?;
    acme::save_config(&state, &config).await?;
    session.audit(&state, "tls.acme_configured", &config.domains.join(","), "").await;

    let issued = acme::issue(&state).await;
    let mut status = status_json(&state).await?;
    status["issued"] = json!(issued.is_ok());
    Ok(Json(status))
}

pub async fn renew_acme(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    session.require_super()?;
    if acme::load_config(&state).await?.is_none() {
        return Err(ApiError::bad("automatic certificates are not configured"));
    }
    session.audit(&state, "tls.acme_renew_requested", &state.cfg.hostname, "").await;
    let issued = acme::issue(&state).await;
    let mut status = status_json(&state).await?;
    status["issued"] = json!(issued.is_ok());
    Ok(Json(status))
}

pub async fn disable_acme(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    session.require_super()?;
    acme::clear_config(&state).await?;
    session.audit(&state, "tls.acme_disabled", &state.cfg.hostname, "").await;
    Ok(Json(status_json(&state).await?))
}
