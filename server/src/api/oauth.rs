//! HTTP side of single sign-on: starting and completing the browser flow, and its
//! administration.

use std::{
    sync::LazyLock,
    time::{Duration, Instant},
};

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ClientIp, JsonResult, Session};
use crate::{
    app::AppState,
    error::ApiError,
    expiring::Expiring,
    oauth::{self, OauthConfig},
    util::{ct_eq, random_token, sanitize_line},
};

const STATE_COOKIE: &str = "unomail_sso";
/// Carries the outcome of a finished flow (an error or a second-factor challenge) from the
/// callback to the sign-in page. The outcome itself stays on the server, so neither a link
/// nor another site can put words or a challenge on the sign-in page.
const RESULT_COOKIE: &str = "unomail_sso_result";
const RESULT_TTL: Duration = Duration::from_secs(300);
const MAX_RESULTS: usize = 10_000;
/// Outcomes waiting for one network (an address, or an IPv6 /64): anyone can produce error
/// outcomes, and must not crowd out everybody else's.
const MAX_RESULTS_PER_NETWORK: usize = 50;

/// id → (outcome, network of the browser).
static RESULTS: LazyLock<Expiring<(Value, String)>> = LazyLock::new(|| Expiring::new(RESULT_TTL, MAX_RESULTS));

fn state_cookie(state: &AppState, value: String, max_age_secs: i64) -> Cookie<'static> {
    Cookie::build((STATE_COOKIE, value))
        .path("/api/auth/oauth")
        .http_only(true)
        .secure(state.cfg.cookie_secure)
        // Lax, not Strict: the cookie has to come back on the provider's redirect to us.
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(max_age_secs))
        .build()
}

fn result_cookie(state: &AppState, value: String, max_age_secs: i64) -> Cookie<'static> {
    Cookie::build((RESULT_COOKIE, value))
        .path("/api/auth/oauth")
        .http_only(true)
        .secure(state.cfg.cookie_secure)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::seconds(max_age_secs))
        .build()
}

fn redirect(location: &str) -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, location.to_owned())]).into_response()
}

/// Sends the browser to the sign-in page, which picks `outcome` up from [`result`].
fn hand_over(state: &AppState, ip: std::net::IpAddr, jar: CookieJar, outcome: Value) -> (CookieJar, Response) {
    let id = random_token();
    let network = crate::auth::network(ip);
    if !RESULTS.insert_limited(id.clone(), (outcome, network.clone()), Instant::now() + RESULT_TTL, |(_, from)| *from == network, MAX_RESULTS_PER_NETWORK) {
        return (jar, redirect("/login"));
    }
    (jar.add(result_cookie(state, id, RESULT_TTL.as_secs() as i64)), redirect("/login?sso=1"))
}

fn failure(state: &AppState, ip: std::net::IpAddr, jar: CookieJar, reason: &str) -> (CookieJar, Response) {
    hand_over(state, ip, jar, json!({ "error": reason }))
}

/// Whether the login page should offer single sign-on (public).
pub async fn info(State(state): State<AppState>) -> JsonResult<Value> {
    Ok(Json(match oauth::active(&state).await {
        Some(config) => json!({ "enabled": true, "name": config.name }),
        None => json!({ "enabled": false }),
    }))
}

/// The outcome of this browser's last flow, once: `{"error": ...}`, `{"second_factor": ...}`
/// or `{}`.
pub async fn result(State(state): State<AppState>, jar: CookieJar) -> (CookieJar, Json<Value>) {
    let id = jar.get(RESULT_COOKIE).map(|c| c.value().to_owned()).unwrap_or_default();
    let jar = jar.remove(result_cookie(&state, String::new(), 0));
    let outcome = RESULTS.take(&id).map_or_else(|| json!({}), |(outcome, _)| outcome);
    (jar, Json(outcome))
}

pub async fn start(State(state): State<AppState>, ClientIp(ip): ClientIp, jar: CookieJar) -> (CookieJar, Response) {
    match oauth::begin(&state, ip).await {
        Ok((url, flow_state)) => (jar.add(state_cookie(&state, flow_state, 600)), redirect(&url)),
        Err(reason) => failure(&state, ip, jar, &reason),
    }
}

#[derive(Deserialize)]
pub struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub async fn callback(State(state): State<AppState>, ClientIp(ip): ClientIp, headers: HeaderMap, jar: CookieJar, Query(query): Query<Callback>) -> (CookieJar, Response) {
    let bound = jar.get(STATE_COOKIE).map(|c| c.value().to_owned()).unwrap_or_default();
    let jar = jar.remove(state_cookie(&state, String::new(), 0));
    if let Some(error) = &query.error {
        tracing::info!(error = %sanitize_line(error), "single sign-on was refused by the provider");
        return failure(&state, ip, jar, "The identity provider refused the sign-in.");
    }
    let (Some(code), Some(flow_state)) = (&query.code, &query.state) else {
        return failure(&state, ip, jar, "The sign-in response was incomplete.");
    };
    // The response must belong to a flow this very browser started; otherwise an attacker
    // could sign a victim into the attacker's mailbox.
    if bound.is_empty() || !ct_eq(bound.as_bytes(), flow_state.as_bytes()) {
        return failure(&state, ip, jar, "The sign-in attempt does not belong to this browser.");
    }
    let account = match oauth::finish(&state, flow_state, code, ip).await {
        Ok(account) => account,
        Err(reason) => {
            crate::db::audit(&state.db, "", "login.failed", "oauth", &ip.to_string(), &sanitize_line(&reason)).await;
            return failure(&state, ip, jar, &reason);
        }
    };
    // The provider stands in for the password only: a second factor set up here is still asked for.
    match super::signin::begin(&state, &account, ip).await {
        Ok(Some(second)) => {
            crate::db::audit(&state.db, &account.email, "login.password_ok", "oauth", &ip.to_string(), "second factor pending").await;
            return hand_over(&state, ip, jar, json!({ "second_factor": second }));
        }
        Ok(None) => {}
        Err(_) => return failure(&state, ip, jar, "The session could not be created."),
    }
    match super::auth::start_session(&state, &account, ip, &headers).await {
        Ok((token, _csrf)) => match super::auth::issue_session(&state, jar.clone(), token, &account).await {
            Ok(jar) => (jar, redirect("/")),
            Err(_) => failure(&state, ip, jar, "The session could not be created."),
        },
        Err(_) => failure(&state, ip, jar, "The session could not be created."),
    }
}

fn view(config: Option<&OauthConfig>, redirect_uri: String) -> Value {
    let mut out = match config {
        Some(config) => {
            let mut value = serde_json::to_value(config).unwrap_or_default();
            value["has_secret"] = json!(!config.client_secret.is_empty());
            value.as_object_mut().map(|o| o.remove("client_secret"));
            value
        }
        None => json!({ "enabled": false }),
    };
    // Shown to the administrator, who has to register it with the provider.
    out["redirect_uri"] = json!(redirect_uri);
    out
}

pub async fn config_get(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    session.require_super()?;
    Ok(Json(view(oauth::load(&state).await?.as_ref(), oauth::redirect_uri(&state))))
}

#[derive(Deserialize)]
pub struct ConfigInput {
    #[serde(flatten)]
    config: OauthConfig,
    /// A new client secret; omitted keeps the stored one.
    secret: Option<String>,
}

pub async fn config_put(State(state): State<AppState>, session: Session, Json(input): Json<ConfigInput>) -> JsonResult<Value> {
    session.require_super()?;
    let mut config = input.config;
    config.issuer = config.issuer.trim().trim_end_matches('/').to_owned();
    config.client_id = config.client_id.trim().to_owned();
    config.validate(state.cfg.allow_private_destinations).map_err(ApiError::bad)?;
    config.client_secret = match input.secret {
        Some(secret) => state.secrets.seal(&secret),
        None => oauth::load(&state).await?.map(|stored| stored.client_secret).unwrap_or_default(),
    };
    oauth::save(&state, &config).await?;
    session.audit(&state, "oauth.configured", &sanitize_line(&config.issuer), if config.enabled { "enabled" } else { "disabled" }).await;
    Ok(Json(view(Some(&config), oauth::redirect_uri(&state))))
}
