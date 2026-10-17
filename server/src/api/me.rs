//! Per-user settings and client auto-configuration.

use axum::{
    Json,
    body::Bytes,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{JsonResult, Session};
use crate::{
    app::AppState,
    diagnostics,
    error::ApiError,
    util::Address,
    vacation::{self, Vacation},
};

pub async fn vacation_get(State(state): State<AppState>, session: Session) -> JsonResult<Vacation> {
    Ok(Json(vacation::load(&state, session.account.id).await?))
}

pub async fn vacation_put(State(state): State<AppState>, session: Session, Json(settings): Json<Vacation>) -> JsonResult<Vacation> {
    settings.validate().map_err(ApiError::bad)?;
    vacation::save(&state, session.account.id, &settings).await?;
    session.audit(&state, "vacation.updated", &session.account.email, if settings.enabled { "enabled" } else { "disabled" }).await;
    Ok(Json(settings))
}

#[derive(Deserialize)]
pub struct ScriptQuery {
    name: Option<String>,
}

fn script_name(name: Option<&str>) -> Result<String, ApiError> {
    let name = name.unwrap_or("main");
    if crate::sieve::valid_script_name(name) { Ok(name.to_owned()) } else { Err(ApiError::bad("script names may contain letters, digits, '.', '-' and '_'")) }
}

/// One script (default: `main`).
pub async fn sieve_get(State(state): State<AppState>, session: Session, Query(query): Query<ScriptQuery>) -> JsonResult<crate::sieve::Stored> {
    Ok(Json(crate::sieve::load(&state, session.account.id, &script_name(query.name.as_deref())?).await?))
}

/// Names of the account's scripts and which one is active.
pub async fn sieve_list(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    let scripts = crate::sieve::all(&state, session.account.id).await?;
    Ok(Json(json!(scripts.iter().map(|s| json!({ "name": s.name, "active": s.active })).collect::<Vec<_>>())))
}

/// Saves a filter script. Scripts are compiled first (together with the scripts they include);
/// invalid ones are refused with the line number of the problem and never stored.
pub async fn sieve_put(State(state): State<AppState>, session: Session, Json(stored): Json<crate::sieve::Stored>) -> JsonResult<crate::sieve::Stored> {
    let name = script_name(Some(&stored.name))?;
    let scripts = crate::sieve::all(&state, session.account.id).await?;
    if scripts.len() >= 20 && !scripts.iter().any(|s| s.name == name) {
        return Err(ApiError::Conflict("at most 20 filter scripts can be stored".into()));
    }
    let globals = crate::sieve::globals(&state).await?;
    crate::sieve::compile_among(&stored.script, &name, &scripts, &globals).map_err(|err| ApiError::bad(err.to_string()))?;
    crate::sieve::save(&state, session.account.id, &stored).await?;
    session.audit(&state, "sieve.updated", &session.account.email, &format!("{name} {}", if stored.active { "active" } else { "inactive" })).await;
    Ok(Json(stored))
}

pub async fn sieve_delete(State(state): State<AppState>, session: Session, Query(query): Query<ScriptQuery>) -> JsonResult<Value> {
    let name = script_name(query.name.as_deref())?;
    if !crate::sieve::delete(&state, session.account.id, &name).await? {
        return Err(ApiError::NotFound);
    }
    session.audit(&state, "sieve.deleted", &session.account.email, &name).await;
    Ok(Json(json!({ "ok": true })))
}

/// Custom keywords (labels) in use by the account.
pub async fn labels(State(state): State<AppState>, session: Session) -> JsonResult<Vec<String>> {
    // Labels in use on messages, plus those the user defined but has not used yet.
    let mut names = state.store.keywords(session.account.id).await?;
    let defined: Vec<String> = sqlx::query_scalar("SELECT name FROM labels WHERE account_id = ?").bind(session.account.id).fetch_all(&state.db).await?;
    names.extend(defined);
    names.sort();
    names.dedup();
    Ok(Json(names))
}

/// Global filter scripts, available to every user through `include :global "name"`.
pub async fn sieve_global_list(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    session.require_super()?;
    let scripts = crate::sieve::globals(&state).await?;
    Ok(Json(json!(scripts.iter().map(|s| json!({ "name": s.name, "script": s.script })).collect::<Vec<_>>())))
}

#[derive(Deserialize)]
pub struct GlobalScript {
    name: String,
    script: String,
}

pub async fn sieve_global_put(State(state): State<AppState>, session: Session, Json(req): Json<GlobalScript>) -> JsonResult<Value> {
    session.require_super()?;
    let name = script_name(Some(&req.name))?;
    crate::sieve::save_global(&state, &name, &req.script).await.map_err(ApiError::bad)?;
    session.audit(&state, "sieve.global_updated", &name, "").await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn sieve_global_delete(State(state): State<AppState>, session: Session, Query(query): Query<ScriptQuery>) -> JsonResult<Value> {
    session.require_super()?;
    let name = script_name(query.name.as_deref())?;
    if !crate::sieve::delete_global(&state, &name).await? {
        return Err(ApiError::NotFound);
    }
    session.audit(&state, "sieve.global_deleted", &name, "").await;
    Ok(Json(json!({ "ok": true })))
}

fn label_name(name: &str) -> Result<String, ApiError> {
    let name = name.trim().to_ascii_lowercase();
    let valid = !name.is_empty() && name.len() <= 100 && !name.starts_with('$') && name.bytes().all(|b| b.is_ascii_graphic() && !b"(){]%*\"\\".contains(&b));
    if valid { Ok(name) } else { Err(ApiError::bad("invalid label name")) }
}

#[derive(Deserialize)]
pub struct RenameLabel {
    from: String,
    to: String,
}

/// Renames a label on every message that carries it.
pub async fn label_rename(State(state): State<AppState>, session: Session, Json(req): Json<RenameLabel>) -> JsonResult<Value> {
    let (from, to) = (label_name(&req.from)?, label_name(&req.to)?);
    let changed = state.store.rename_keyword(session.account.id, &from, Some(&to)).await?;
    // The definition (and its colour) moves with the name.
    sqlx::query("UPDATE OR REPLACE labels SET name = ? WHERE account_id = ? AND name = ?").bind(&to).bind(session.account.id).bind(&from).execute(&state.db).await?;
    Ok(Json(json!({ "changed": changed })))
}

#[derive(Deserialize)]
pub struct LabelQuery {
    name: String,
}

/// Deletes a label: removes it from every message (the messages themselves stay).
pub async fn label_delete(State(state): State<AppState>, session: Session, Query(query): Query<LabelQuery>) -> JsonResult<Value> {
    let name = label_name(&query.name)?;
    let changed = state.store.rename_keyword(session.account.id, &name, None).await?;
    sqlx::query("DELETE FROM labels WHERE account_id = ? AND name = ?").bind(session.account.id).bind(&name).execute(&state.db).await?;
    Ok(Json(json!({ "changed": changed })))
}

pub async fn server_diagnostics(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    session.require_super()?;
    let cfg = &state.cfg;
    let local = |port: u16| std::net::SocketAddr::new(cfg.bind, port);
    let ports = [
        ("SMTP", local(cfg.smtp_port)),
        ("Submission", local(cfg.submission_port)),
        ("SMTPS", local(cfg.smtps_port)),
        ("IMAPS", local(cfg.imaps_port)),
        ("IMAP", local(cfg.imap_port)),
        ("POP3S", local(cfg.pop3s_port)),
        ("HTTP", local(cfg.http_port)),
        ("HTTPS", local(cfg.https_port)),
    ];
    let report = diagnostics::server_report(&state, &ports).await;
    Ok(Json(json!(report)))
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

fn xml(body: String) -> Response {
    ([(header::CONTENT_TYPE, "application/xml; charset=utf-8")], body).into_response()
}

#[derive(Deserialize)]
pub struct AutoconfigQuery {
    #[serde(default, alias = "emailaddress")]
    email: Option<String>,
}

/// Thunderbird / Autoconfig (`config-v1.1.xml`).
pub async fn thunderbird(State(state): State<AppState>, Query(query): Query<AutoconfigQuery>) -> Response {
    let host = xml_escape(&state.cfg.hostname);
    let domain = query.email.as_deref().and_then(Address::parse).map_or_else(|| host.clone(), |a| xml_escape(&a.domain));
    xml(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="{domain}">
    <domain>{domain}</domain>
    <displayName>{domain} Mail</displayName>
    <displayShortName>{domain}</displayShortName>
    <incomingServer type="imap">
      <hostname>{host}</hostname><port>993</port><socketType>SSL</socketType>
      <authentication>password-cleartext</authentication><username>%EMAILADDRESS%</username>
    </incomingServer>
    <incomingServer type="pop3">
      <hostname>{host}</hostname><port>995</port><socketType>SSL</socketType>
      <authentication>password-cleartext</authentication><username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>{host}</hostname><port>465</port><socketType>SSL</socketType>
      <authentication>password-cleartext</authentication><username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>
"#
    ))
}

/// Extracts the text of the first `<EMailAddress>` element without a full XML parser: the
/// value is validated as an address afterwards, so nothing else from the request is used.
fn requested_address(body: &[u8]) -> Option<Address> {
    let text = std::str::from_utf8(body).ok()?;
    let lower = text.to_ascii_lowercase();
    let start = lower.find("<emailaddress>")? + "<emailaddress>".len();
    let end = start + lower[start..].find("</emailaddress>")?;
    Address::parse(text.get(start..end)?.trim())
}

/// Microsoft Outlook Autodiscover (POX).
pub async fn outlook(State(state): State<AppState>, body: Bytes) -> Response {
    if body.len() > 16 * 1024 {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let Some(address) = requested_address(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let (host, email) = (xml_escape(&state.cfg.hostname), xml_escape(&address.to_string()));
    xml(format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type><Server>{host}</Server><Port>993</Port><SSL>on</SSL>
        <LoginName>{email}</LoginName><SPA>off</SPA><AuthRequired>on</AuthRequired>
      </Protocol>
      <Protocol>
        <Type>POP3</Type><Server>{host}</Server><Port>995</Port><SSL>on</SSL>
        <LoginName>{email}</LoginName><SPA>off</SPA><AuthRequired>on</AuthRequired>
      </Protocol>
      <Protocol>
        <Type>SMTP</Type><Server>{host}</Server><Port>587</Port><Encryption>TLS</Encryption>
        <LoginName>{email}</LoginName><SPA>off</SPA><AuthRequired>on</AuthRequired>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>
"#
    ))
}

/// Apple Mail configuration profile (`.mobileconfig`).
pub async fn apple(State(state): State<AppState>, Query(query): Query<AutoconfigQuery>) -> Response {
    let Some(address) = query.email.as_deref().and_then(Address::parse) else {
        return (StatusCode::BAD_REQUEST, "an email query parameter with a valid address is required").into_response();
    };
    let (host, email) = (xml_escape(&state.cfg.hostname), xml_escape(&address.to_string()));
    let reversed: Vec<&str> = state.cfg.hostname.split('.').rev().collect();
    let id = xml_escape(&reversed.join("."));
    let (uuid_a, uuid_b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>EmailAccountType</key><string>EmailTypeIMAP</string>
      <key>EmailAddress</key><string>{email}</string>
      <key>IncomingMailServerAuthentication</key><string>EmailAuthPassword</string>
      <key>IncomingMailServerHostName</key><string>{host}</string>
      <key>IncomingMailServerPortNumber</key><integer>993</integer>
      <key>IncomingMailServerUseSSL</key><true/>
      <key>IncomingMailServerUsername</key><string>{email}</string>
      <key>OutgoingMailServerAuthentication</key><string>EmailAuthPassword</string>
      <key>OutgoingMailServerHostName</key><string>{host}</string>
      <key>OutgoingMailServerPortNumber</key><integer>465</integer>
      <key>OutgoingMailServerUseSSL</key><true/>
      <key>OutgoingMailServerUsername</key><string>{email}</string>
      <key>OutgoingPasswordSameAsIncomingPassword</key><true/>
      <key>PayloadDisplayName</key><string>{email}</string>
      <key>PayloadIdentifier</key><string>{id}.mail.{uuid_a}</string>
      <key>PayloadType</key><string>com.apple.mail.managed</string>
      <key>PayloadUUID</key><string>{uuid_a}</string>
      <key>PayloadVersion</key><integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key><string>{email} mail account</string>
  <key>PayloadIdentifier</key><string>{id}.profile.{uuid_b}</string>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>{uuid_b}</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
"#
    );
    (
        [(header::CONTENT_TYPE, "application/x-apple-aspen-config"), (header::CONTENT_DISPOSITION, "attachment; filename=\"mail.mobileconfig\"")],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outlook_request_parsing() {
        let body = b"<Autodiscover><Request><EMailAddress> Bob@Example.org </EMailAddress><AcceptableResponseSchema>x</AcceptableResponseSchema></Request></Autodiscover>";
        assert_eq!(requested_address(body).unwrap().to_string(), "bob@example.org");
        assert!(requested_address(b"<EMailAddress>not an address</EMailAddress>").is_none());
        assert!(requested_address(b"<EMailAddress>a@b.example").is_none());
        assert!(requested_address(b"<EMailAddress><x>a@b.example</x></EMailAddress>").is_none());
        assert!(requested_address(b"").is_none());
    }

    #[test]
    fn escaping() {
        assert_eq!(xml_escape("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&apos;");
    }
}
