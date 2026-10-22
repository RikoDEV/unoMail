//! Captcha on the web sign-in page: hCaptcha, Cloudflare Turnstile and Google reCAPTCHA
//! (checked with the provider), or ALTCHA (a proof of work checked here, nothing leaves the
//! server).

use std::{
    net::IpAddr,
    sync::LazyLock,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    app::AppState,
    expiring::Expiring,
    util::{ct_eq, hmac_sha256, now, random_bytes, sha256_hex},
};

/// Seconds an ALTCHA challenge can be answered in.
const ALTCHA_TTL_SECS: i64 = 600;
/// Upper bound of the secret number; a browser tries half of them on average.
const ALTCHA_MAX_NUMBER: u64 = 100_000;
/// How many answered challenges can be remembered at once.
const MAX_SPENT: usize = 100_000;

/// Signs ALTCHA challenges. Challenges are short-lived, so a key per process is enough.
static ALTCHA_KEY: LazyLock<[u8; 32]> = LazyLock::new(random_bytes::<32>);
/// Answered challenges, remembered until they expire so that each is good for one sign-in.
static SPENT: LazyLock<Expiring<()>> = LazyLock::new(|| Expiring::new(Duration::from_secs(ALTCHA_TTL_SECS as u64), MAX_SPENT));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Hcaptcha,
    Turnstile,
    Recaptcha,
    Altcha,
}

impl Provider {
    pub fn parse(name: &str) -> Option<Provider> {
        Some(match name {
            "hcaptcha" => Provider::Hcaptcha,
            "turnstile" => Provider::Turnstile,
            "recaptcha" => Provider::Recaptcha,
            "altcha" => Provider::Altcha,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Provider::Hcaptcha => "hcaptcha",
            Provider::Turnstile => "turnstile",
            Provider::Recaptcha => "recaptcha",
            Provider::Altcha => "altcha",
        }
    }

    /// Whether answers are checked by the provider (with a site key and secret).
    pub fn hosted(self) -> bool {
        self != Provider::Altcha
    }

    fn verify_url(self) -> &'static str {
        match self {
            Provider::Hcaptcha => "https://api.hcaptcha.com/siteverify",
            Provider::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            Provider::Recaptcha => "https://www.google.com/recaptcha/api/siteverify",
            Provider::Altcha => "",
        }
    }

    /// Content security policy sources the widget needs: (scripts, frames, styles, connections).
    pub fn csp_sources(self) -> [&'static str; 4] {
        match self {
            Provider::Hcaptcha => ["https://hcaptcha.com https://*.hcaptcha.com"; 4],
            Provider::Turnstile => ["https://challenges.cloudflare.com", "https://challenges.cloudflare.com", "", ""],
            Provider::Recaptcha => ["https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/", "https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/", "", ""],
            Provider::Altcha => ["", "", "", ""],
        }
    }
}

/// What the sign-in page needs to show the captcha, or `{"provider": null}`.
pub fn widget(state: &AppState) -> Value {
    let rt = state.rt();
    match rt.captcha() {
        None => json!({ "provider": null }),
        Some(Provider::Altcha) => json!({ "provider": "altcha", "challenge": altcha_challenge() }),
        Some(provider) => json!({ "provider": provider.name(), "site_key": rt.captcha_site_key }),
    }
}

/// A new ALTCHA challenge (format of the ALTCHA widget, v1).
pub fn altcha_challenge() -> Value {
    let salt = format!("{}?expires={}", hex::encode(random_bytes::<12>()), now() + ALTCHA_TTL_SECS);
    let number = u64::from_le_bytes(random_bytes::<8>()) % ALTCHA_MAX_NUMBER;
    let challenge = sha256_hex(format!("{salt}{number}").as_bytes());
    let signature = hex::encode(hmac_sha256(&*ALTCHA_KEY, challenge.as_bytes()));
    json!({ "algorithm": "SHA-256", "challenge": challenge, "maxnumber": ALTCHA_MAX_NUMBER, "salt": salt, "signature": signature })
}

#[derive(Deserialize)]
struct AltchaPayload {
    algorithm: String,
    challenge: String,
    number: u64,
    salt: String,
    signature: String,
}

/// Checks an ALTCHA answer (base64 JSON) and spends its challenge.
fn altcha_verify(answer: &str) -> bool {
    let Some(payload) = STANDARD.decode(answer.trim()).ok().and_then(|json| serde_json::from_slice::<AltchaPayload>(&json).ok()) else { return false };
    let expected = hex::encode(hmac_sha256(&*ALTCHA_KEY, payload.challenge.as_bytes()));
    if payload.algorithm != "SHA-256" || !ct_eq(expected.as_bytes(), payload.signature.as_bytes()) {
        return false;
    }
    let Some(expires) = payload.salt.split_once("?expires=").and_then(|(_, at)| at.parse::<i64>().ok()) else { return false };
    let now = now();
    if expires <= now || payload.number > ALTCHA_MAX_NUMBER || sha256_hex(format!("{}{}", payload.salt, payload.number).as_bytes()) != payload.challenge {
        return false;
    }
    // When full of live challenges this refuses, rather than forget one that could be replayed.
    SPENT.insert_until(payload.challenge, (), Instant::now() + Duration::from_secs((expires - now) as u64))
}

#[derive(Deserialize)]
struct SiteVerify {
    success: bool,
}

/// Whether `answer` solves the configured captcha. Without one, everything passes.
pub async fn verify(state: &AppState, answer: Option<&str>, ip: IpAddr) -> bool {
    let rt = state.rt();
    let Some(provider) = rt.captcha() else { return true };
    let Some(answer) = answer.filter(|a| !a.is_empty() && a.len() <= 8192) else { return false };
    if provider == Provider::Altcha {
        return altcha_verify(answer);
    }
    let Some(secret) = state.secrets.open(&rt.captcha_secret_key) else {
        tracing::warn!("the captcha secret cannot be read; enter it again");
        return false;
    };
    let mut form = vec![("secret", secret), ("response", answer.to_owned()), ("remoteip", ip.to_string())];
    if provider == Provider::Hcaptcha {
        form.push(("sitekey", rt.captcha_site_key.clone()));
    }
    let response = match state.http.post(provider.verify_url()).form(&form).send().await {
        Ok(response) => response.json::<SiteVerify>().await,
        Err(err) => Err(err),
    };
    match response {
        Ok(result) => result.success,
        Err(err) => {
            tracing::warn!(provider = provider.name(), %err, "captcha verification failed");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solve(challenge: &Value) -> String {
        let salt = challenge["salt"].as_str().unwrap();
        let number = (0..=ALTCHA_MAX_NUMBER).find(|n| sha256_hex(format!("{salt}{n}").as_bytes()) == challenge["challenge"]).unwrap();
        let mut payload = challenge.clone();
        payload["number"] = json!(number);
        STANDARD.encode(payload.to_string())
    }

    #[test]
    fn altcha_answers_count_once() {
        let challenge = altcha_challenge();
        let answer = solve(&challenge);
        assert!(altcha_verify(&answer));
        assert!(!altcha_verify(&answer), "replayed");

        let mut forged = altcha_challenge();
        forged["signature"] = json!("00");
        assert!(!altcha_verify(&solve(&forged)));
        assert!(!altcha_verify("not base64"));
    }
}
