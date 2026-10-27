//! Rspamd HTTP client (`/checkv2`). Rspamd runs inside the container and provides spam
//! scoring, Bayes, fuzzy checks and ClamAV antivirus integration.

use std::net::IpAddr;

use serde::Deserialize;

use crate::app::App;

/// Symbol set by the ClamAV integration (see docker/rspamd/antivirus.conf).
pub const VIRUS_SYMBOL: &str = "CLAM_VIRUS";

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Accept,
    /// Deliver, but to the Junk folder.
    Junk,
    /// Temporary failure: ask the sender to retry later.
    Defer,
    Reject,
}

/// Content filter symbols that mean the message is phishing.
pub const PHISHING_SYMBOLS: &[&str] = &["PHISHING", "PHISHED_OPENPHISH", "PHISHED_PHISHTANK", "PHISHED_GENERIC_SERVICE"];

#[derive(Debug, Clone, PartialEq)]
pub struct ScanResult {
    pub action: Action,
    pub score: f64,
    pub required_score: f64,
    pub symbols: Vec<String>,
}

impl ScanResult {
    /// `X-Spam-*` headers describing the result, CRLF terminated.
    pub fn headers(&self) -> String {
        let flag = if matches!(self.action, Action::Accept) { "No" } else { "Yes" };
        let mut symbols = self.symbols.iter().map(|s| crate::util::sanitize_line(s)).collect::<Vec<_>>();
        symbols.truncate(30);
        format!(
            "X-Spam-Status: {flag}, score={:.2} required={:.2}\r\nX-Spam-Symbols: {}\r\n",
            self.score,
            self.required_score,
            symbols.join(",")
        )
    }
}

#[derive(Deserialize)]
struct Response {
    #[serde(default)]
    action: String,
    #[serde(default)]
    score: f64,
    #[serde(default)]
    required_score: f64,
    #[serde(default)]
    symbols: std::collections::HashMap<String, serde_json::Value>,
}

fn parse(body: &[u8]) -> Result<ScanResult, serde_json::Error> {
    let resp: Response = serde_json::from_slice(body)?;
    let action = match resp.action.as_str() {
        "reject" => Action::Reject,
        "soft reject" | "greylist" => Action::Defer,
        "add header" | "rewrite subject" => Action::Junk,
        _ => Action::Accept,
    };
    let mut symbols: Vec<String> = resp.symbols.into_keys().collect();
    symbols.sort();
    Ok(ScanResult { action, score: resp.score, required_score: resp.required_score, symbols })
}

pub struct ScanRequest<'a> {
    pub ip: IpAddr,
    pub helo: &'a str,
    pub sender: &'a str,
    pub recipients: &'a [String],
    /// Authenticated submitter, which makes Rspamd apply its outbound policy.
    pub user: Option<&'a str>,
    pub raw: &'a [u8],
}

/// The configured scanner could not be reached or returned garbage.
#[derive(Debug)]
pub struct Unavailable;

/// Scans a message. `Ok(None)` means no scanner is configured. An unreachable scanner is an
/// error: callers defer the message (or accept it unscanned when the `rspamd_fail_open` setting
/// is set) instead of silently skipping spam and virus checks.
pub async fn scan(app: &App, req: ScanRequest<'_>) -> Result<Option<ScanResult>, Unavailable> {
    let Some(base) = app.cfg.rspamd_url.as_deref() else { return Ok(None) };
    let mut builder = app
        .filter_http
        .post(format!("{}/checkv2", base.trim_end_matches('/')))
        .header("IP", req.ip.to_string())
        .header("Helo", crate::util::sanitize_line(req.helo))
        .header("From", crate::util::sanitize_line(req.sender))
        .header("Hostname", &app.cfg.hostname)
        .body(req.raw.to_vec());
    for rcpt in req.recipients {
        builder = builder.header("Rcpt", crate::util::sanitize_line(rcpt));
    }
    if let Some(user) = req.user {
        builder = builder.header("User", crate::util::sanitize_line(user));
    }
    if let Some(password) = &app.cfg.rspamd_password {
        builder = builder.header("Password", password);
    }
    let result = async {
        let resp = builder.send().await?.error_for_status()?;
        let body = resp.bytes().await?;
        anyhow::Ok(parse(&body)?)
    }
    .await;
    match result {
        Ok(scan) => Ok(Some(scan)),
        Err(err) if app.rt().rspamd_fail_open => {
            tracing::warn!(error = %err, "content filter unavailable, accepting message unscanned (fail-open)");
            Ok(None)
        }
        Err(err) => {
            tracing::warn!(error = %err, "content filter unavailable, deferring message");
            Err(Unavailable)
        }
    }
}

/// Flag of the locally trained fuzzy rule (see docker/rspamd/fuzzy_check.conf).
const FUZZY_FLAG: &str = "11";

/// Teaches the filter that a message is spam or ham: Bayes statistics and the local fuzzy
/// hash storage, so that near-identical copies are recognised for every mailbox.
pub(crate) async fn learn(app: &App, raw: Vec<u8>, spam: bool) {
    let Some(base) = app.cfg.rspamd_controller_url.as_deref().map(|u| u.trim_end_matches('/').to_owned()) else { return };
    let (bayes, fuzzy) = if spam { ("learnspam", "fuzzyadd") } else { ("learnham", "fuzzydel") };
    let mut requests = vec![app.filter_controller_http.post(format!("{base}/{bayes}"))];
    // The bundled deployment has no unauthenticated local UDP fuzzy writer.
    if app.cfg.rspamd_controller_socket.is_none() {
        requests.push(app.filter_controller_http.post(format!("{base}/{fuzzy}")).header("Flag", FUZZY_FLAG).header("Weight", "10"));
    }
    for request in requests.drain(..) {
        let request = match &app.cfg.rspamd_password {
            Some(password) => request.header("Password", password),
            None => request,
        };
        match request.body(raw.clone()).send().await {
            // 208: the filter already knew this message.
            Ok(response) if response.status().is_success() || response.status().as_u16() == 208 => {}
            Ok(response) => tracing::debug!(status = %response.status(), "filter training request was not accepted"),
            Err(err) => tracing::warn!(error = %err, "filter training failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_actions() {
        let r = parse(br#"{"action":"add header","score":7.5,"required_score":6.0,"symbols":{"BAYES_SPAM":{"score":5.1},"A":{}}}"#)
            .unwrap();
        assert_eq!(r.action, Action::Junk);
        assert_eq!(r.symbols, ["A", "BAYES_SPAM"]);
        assert_eq!(r.headers(), "X-Spam-Status: Yes, score=7.50 required=6.00\r\nX-Spam-Symbols: A,BAYES_SPAM\r\n");
        assert_eq!(parse(br#"{"action":"reject"}"#).unwrap().action, Action::Reject);
        assert_eq!(parse(br#"{"action":"soft reject"}"#).unwrap().action, Action::Defer);
        assert_eq!(parse(br#"{"action":"no action"}"#).unwrap().action, Action::Accept);
        assert_eq!(parse(br#"{}"#).unwrap().action, Action::Accept);
        assert!(parse(b"not json").is_err());
    }

    #[test]
    fn symbol_names_cannot_inject_headers() {
        let r = parse(br#"{"action":"reject","symbols":{"EVIL\r\nBcc: x@y":{}}}"#).unwrap();
        assert_eq!(r.headers().matches("\r\n").count(), 2);
    }
}
