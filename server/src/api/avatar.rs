//! The picture shown next to a sender: the brand logo its domain publishes (BIMI), or the
//! sender's Gravatar.
//!
//! Both come from elsewhere, so the server fetches them itself and keeps a copy: the reader's
//! browser never contacts the logo's host or Gravatar, and neither learns who read what when.
//! A picture lends a message credibility, so it is only shown where the message earned it:
//! a brand logo needs a DMARC pass under an enforced policy, a Gravatar a sender that was not
//! found to be forged.

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    app::AppState,
    error::ApiError,
    security::{bimi, summary},
    util::{now, sha256_hex},
};

const POSITIVE_TTL: i64 = 24 * 3600;
const NEGATIVE_TTL: i64 = 6 * 3600;
const MAX_CERTIFICATE_BYTES: usize = 512 * 1024;
const WEB_PORTS: [u16; 1] = [443];

/// A cached picture, or the cached knowledge that there is none.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Avatar {
    /// `bimi-verified`, `bimi`, `gravatar` or `none`.
    pub source: String,
    pub content_type: String,
    pub data: Vec<u8>,
    /// For a verified brand: "Organization (certified by Issuer)".
    pub detail: String,
}

impl Avatar {
    fn none() -> Self {
        Avatar { source: "none".into(), content_type: String::new(), data: Vec::new(), detail: String::new() }
    }
}

async fn cached(state: &AppState, key: &str) -> sqlx::Result<Option<Avatar>> {
    let row: Option<(String, String, Vec<u8>, String, i64)> = sqlx::query_as("SELECT source, content_type, data, detail, fetched_at FROM sender_avatars WHERE key = ?").bind(key).fetch_optional(&state.db).await?;
    Ok(row.filter(|(source, .., fetched)| now() - fetched < if source == "none" { NEGATIVE_TTL } else { POSITIVE_TTL }).map(|(source, content_type, data, detail, _)| Avatar { source, content_type, data, detail }))
}

async fn remember(state: &AppState, key: &str, avatar: &Avatar) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO sender_avatars (key, source, content_type, data, detail, fetched_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET source = excluded.source, content_type = excluded.content_type, data = excluded.data, detail = excluded.detail, fetched_at = excluded.fetched_at")
        .bind(key)
        .bind(&avatar.source)
        .bind(&avatar.content_type)
        .bind(&avatar.data)
        .bind(&avatar.detail)
        .bind(now())
        .execute(&state.db)
        .await?;
    Ok(())
}

async fn txt(state: &AppState, name: &str) -> Vec<String> {
    match &state.authenticator {
        Some(resolver) => crate::dns::txt(resolver, name).await.unwrap_or_default(),
        None => Vec::new(),
    }
}

async fn fetch(state: &AppState, url: &str, limit: usize, accept: &str) -> Option<Vec<u8>> {
    let url = reqwest::Url::parse(url).ok()?;
    super::mailboxes::fetch_public(state, url, &WEB_PORTS, limit, accept).await.ok()
}

/// Looks the brand logo of a domain up: DMARC policy, BIMI record, mark certificate, image.
async fn lookup_bimi(state: &AppState, domain: &str) -> Avatar {
    let names = bimi::candidates(domain);
    // BIMI is only for domains that tell receivers to act on DMARC failures.
    let mut enforced = false;
    for name in &names {
        let records = txt(state, &format!("_dmarc.{name}")).await;
        if let Some(record) = records.iter().find(|record| record.to_ascii_lowercase().starts_with("v=dmarc1")) {
            enforced = bimi::dmarc_enforced(record);
            break;
        }
    }
    if !enforced {
        return Avatar::none();
    }
    let mut record = None;
    for name in &names {
        if let Some(found) = txt(state, &format!("default._bimi.{name}")).await.iter().find_map(|text| bimi::parse_record(text)) {
            record = Some(found);
            break;
        }
    }
    let Some(record) = record else { return Avatar::none() };

    // A mark certificate vouches for the logo (and carries a copy of it).
    let mut mark = None;
    if let Some(location) = &record.authority
        && let Some(pem) = fetch(state, location, MAX_CERTIFICATE_BYTES, "application/x-pem-file, */*").await
    {
        match bimi::verify_mark(&pem, domain, &bimi::roots(&state.cfg.data_dir.join("bimi-roots")), now()) {
            Ok(verified) => mark = Some(verified),
            Err(reason) => tracing::debug!(%domain, %reason, "mark certificate not accepted"),
        }
    }
    let certified = mark.as_ref().and_then(|mark| mark.logo.clone());
    let logo = match certified {
        Some(logo) => Some(logo),
        None => match &record.logo {
            Some(location) => fetch(state, location, bimi::MAX_LOGO_BYTES, "image/svg+xml").await.and_then(|data| bimi::clean_svg(&data)),
            None => None,
        },
    };
    match (logo, mark) {
        (Some(logo), Some(mark)) => Avatar { source: "bimi-verified".into(), content_type: "image/svg+xml".into(), data: logo.into_bytes(), detail: format!("{} (certified by {})", mark.organization, mark.issuer) },
        (Some(logo), None) => Avatar { source: "bimi".into(), content_type: "image/svg+xml".into(), data: logo.into_bytes(), detail: String::new() },
        (None, _) => Avatar::none(),
    }
}

async fn lookup_gravatar(state: &AppState, email: &str) -> Avatar {
    let Some(base) = &state.cfg.gravatar_url else { return Avatar::none() };
    let url = format!("{}/{}?s=96&d=404&r=g", base.trim_end_matches('/'), sha256_hex(email.trim().to_lowercase().as_bytes()));
    let Some(parsed) = reqwest::Url::parse(&url).ok() else { return Avatar::none() };
    match super::mailboxes::fetch_public(state, parsed, &WEB_PORTS, 256 * 1024, "image/*").await {
        Ok(data) => match super::mailboxes::sniff_image(&data) {
            Some(content_type) => Avatar { source: "gravatar".into(), content_type: content_type.into(), data, detail: String::new() },
            None => Avatar::none(),
        },
        Err(_) => Avatar::none(),
    }
}

/// The picture for the sender of a message, given what the server knows about the message.
pub async fn for_sender(state: &AppState, from: &str, security: &summary::Summary) -> Result<Avatar, ApiError> {
    let from = from.trim().to_lowercase();
    let Some((_, domain)) = from.rsplit_once('@') else { return Ok(Avatar::none()) };
    // The brand logo: only for mail that passed DMARC for exactly the domain it shows.
    if security.verdict == "verified" && security.from_domain.as_deref().is_some_and(|checked| checked == domain || domain.ends_with(&format!(".{checked}"))) && crate::util::is_valid_domain(domain) {
        let key = format!("bimi:{domain}");
        let logo = match cached(state, &key).await? {
            Some(hit) => hit,
            None => {
                let found = lookup_bimi(state, domain).await;
                remember(state, &key, &found).await?;
                found
            }
        };
        if logo.source != "none" {
            return Ok(logo);
        }
    }
    // A Gravatar: not for mail whose sender could not be confirmed.
    if !matches!(security.verdict, "verified" | "partial" | "internal") {
        return Ok(Avatar::none());
    }
    let key = format!("gravatar:{from}");
    if let Some(hit) = cached(state, &key).await? {
        return Ok(hit);
    }
    let found = lookup_gravatar(state, &from).await;
    remember(state, &key, &found).await?;
    Ok(found)
}

#[derive(Deserialize)]
pub struct AvatarQuery {
    /// Set to get a description of the picture instead of the picture.
    info: Option<String>,
}

/// Serves an avatar, or its description as JSON.
pub fn respond(avatar: Avatar, query: &AvatarQuery) -> Response {
    if query.info.is_some() {
        return Json(json!({ "source": avatar.source, "verified": avatar.source == "bimi-verified", "detail": avatar.detail })).into_response();
    }
    if avatar.source == "none" {
        return (StatusCode::NOT_FOUND, [(header::CACHE_CONTROL, "private, max-age=3600")]).into_response();
    }
    let mut response = avatar.data.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(&avatar.content_type).unwrap_or(HeaderValue::from_static("application/octet-stream")));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=3600"));
    // An SVG opened on its own must stay a picture: no scripts, no requests.
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; sandbox"));
    headers.insert(header::CONTENT_DISPOSITION, HeaderValue::from_static("inline"));
    response
}

/// Removes cached pictures nobody asked for in a long time (run by the maintenance task).
pub async fn prune(state: &AppState) {
    let _ = sqlx::query("DELETE FROM sender_avatars WHERE fetched_at < ?").bind(now() - 30 * 86400).execute(&state.db).await;
}
