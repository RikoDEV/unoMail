//! Configuration of the Rspamd spam filter from the admin panel, through Rspamd's own
//! controller API. Changes are stored by Rspamd (its dynamic configuration) and take effect
//! without a restart.

use axum::{Json, extract::State};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{JsonResult, Session};
use crate::{app::AppState, error::ApiError};

const HISTORY_ROWS: usize = 50;

fn controller(state: &AppState) -> Option<String> {
    state.cfg.rspamd_controller_url.as_deref().map(|url| url.trim_end_matches('/').to_owned())
}

async fn fetch(state: &AppState, base: &str, path: &str) -> Result<Value, String> {
    let mut request = state.filter_controller_http.get(format!("{base}/{path}"));
    if let Some(password) = &state.cfg.rspamd_password { request = request.header("Password", password); }
    let response = request.send().await.map_err(|_| "the spam filter cannot be reached".to_owned())?;
    if !response.status().is_success() {
        return Err(format!("the spam filter answered with HTTP {}", response.status().as_u16()));
    }
    response.json().await.map_err(|_| "the spam filter returned an unreadable answer".to_owned())
}

async fn send(state: &AppState, path: &str, body: Value) -> Result<(), ApiError> {
    let base = controller(state).ok_or_else(|| ApiError::bad("the spam filter is not configured on this server"))?;
    let request = state
        .filter_controller_http
        .post(format!("{base}/{path}"))
        .header("content-type", "application/json")
        .body(body.to_string());
    let request = match &state.cfg.rspamd_password { Some(password) => request.header("Password", password), None => request };
    let response = request.send()
        .await
        .map_err(|_| ApiError::bad("the spam filter cannot be reached"))?;
    if !response.status().is_success() {
        return Err(ApiError::bad(format!("the spam filter refused the change (HTTP {})", response.status().as_u16())));
    }
    Ok(())
}

/// Scan history rows reduced to what the panel shows. Everything in them originates from
/// mail and is therefore untrusted; it is passed on as data and rendered as text.
fn history_rows(history: &Value) -> Vec<Value> {
    let rows = history.get("rows").and_then(Value::as_array).or_else(|| history.as_array()).cloned().unwrap_or_default();
    let mut rows: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            let symbols = row.get("symbols").and_then(Value::as_object).map(|symbols| {
                let mut names: Vec<(String, f64)> = symbols.iter().map(|(name, detail)| (name.clone(), detail.get("score").and_then(Value::as_f64).unwrap_or(0.0))).collect();
                names.sort_by(|a, b| b.1.abs().total_cmp(&a.1.abs()));
                names.into_iter().take(8).map(|(name, score)| json!({ "name": name, "score": score })).collect::<Vec<_>>()
            });
            json!({
                "time": row.get("unix_time").cloned().unwrap_or(Value::Null),
                "ip": row.get("ip").cloned().unwrap_or(Value::Null),
                "action": row.get("action").cloned().unwrap_or(Value::Null),
                "score": row.get("score").cloned().unwrap_or(Value::Null),
                "required_score": row.get("required_score").cloned().unwrap_or(Value::Null),
                "sender": row.get("sender_mime").or_else(|| row.get("sender_smtp")).cloned().unwrap_or(Value::Null),
                "recipient": row.get("rcpt_smtp").or_else(|| row.get("rcpt_mime")).cloned().unwrap_or(Value::Null),
                "subject": row.get("subject").cloned().unwrap_or(Value::Null),
                "symbols": symbols,
            })
        })
        .collect();
    rows.sort_by(|a, b| b["time"].as_f64().unwrap_or(0.0).total_cmp(&a["time"].as_f64().unwrap_or(0.0)));
    rows.truncate(HISTORY_ROWS);
    rows
}

/// Status, thresholds, rule scores and recent verdicts of the spam filter.
pub async fn overview(State(state): State<AppState>, session: Session) -> JsonResult<Value> {
    session.require_super()?;
    let Some(base) = controller(&state) else {
        return Ok(Json(json!({ "configured": false, "available": false })));
    };
    let (stat, actions, symbols, history) =
        tokio::join!(fetch(&state, &base, "stat"), fetch(&state, &base, "actions"), fetch(&state, &base, "symbols"), fetch(&state, &base, "history"));
    match (stat, actions, symbols) {
        (Ok(stat), Ok(actions), Ok(symbols)) => Ok(Json(json!({
            "configured": true,
            "available": true,
            "stat": {
                "version": stat.get("version"), "scanned": stat.get("scanned"), "learned": stat.get("learned"),
                "actions": stat.get("actions"), "uptime": stat.get("uptime"), "fuzzy_hashes": stat.get("fuzzy_hashes"),
            },
            "actions": actions,
            "groups": symbols,
            "history": history.map(|h| history_rows(&h)).unwrap_or_default(),
        }))),
        (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => Ok(Json(json!({ "configured": true, "available": false, "error": error }))),
    }
}

#[derive(Deserialize)]
pub struct Thresholds {
    /// Score at which mail is refused.
    reject: f64,
    /// Score at which mail is marked as spam and filed into Junk.
    add_header: f64,
}

pub async fn actions_put(State(state): State<AppState>, session: Session, Json(input): Json<Thresholds>) -> JsonResult<Value> {
    session.require_super()?;
    let valid = |value: f64| value.is_finite() && (0.0..=1000.0).contains(&value);
    if !valid(input.reject) || !valid(input.add_header) {
        return Err(ApiError::bad("thresholds must be between 0 and 1000"));
    }
    if input.add_header >= input.reject {
        return Err(ApiError::bad("mail must be marked as spam at a lower score than it is rejected at"));
    }
    // Rspamd's order: reject, rewrite subject, add header, greylist. Greylisting is done by
    // unoMail itself and subjects are never rewritten, so both stay unset.
    send(&state, "saveactions", json!([input.reject, null, input.add_header, null])).await?;
    session.audit(&state, "spamfilter.thresholds", "rspamd", &format!("reject={} add_header={}", input.reject, input.add_header)).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct SymbolScore {
    name: String,
    value: f64,
}

/// Changes the score of one rule.
pub async fn symbol_put(State(state): State<AppState>, session: Session, Json(input): Json<SymbolScore>) -> JsonResult<Value> {
    session.require_super()?;
    if input.name.is_empty() || input.name.len() > 100 || !input.name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') {
        return Err(ApiError::bad("invalid rule name"));
    }
    if !input.value.is_finite() || !(-1000.0..=1000.0).contains(&input.value) {
        return Err(ApiError::bad("scores must be between -1000 and 1000"));
    }
    send(&state, "savesymbols", json!([{ "name": input.name, "value": input.value }])).await?;
    session.audit(&state, "spamfilter.rule_score", &input.name, &input.value.to_string()).await;
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_is_reduced_sorted_and_bounded() {
        let history = json!({ "version": 2, "rows": [
            { "unix_time": 10, "ip": "203.0.113.1", "action": "no action", "score": 1.5, "required_score": 15, "sender_mime": "a@x.example", "rcpt_smtp": ["b@y.example"], "subject": "old",
              "symbols": { "A": { "score": 0.1 }, "B": { "score": -3.0 }, "C": { "score": 2.0 } }, "user": "secret-internal-field" },
            { "unix_time": 20, "ip": "203.0.113.2", "action": "reject", "score": 30, "subject": "<script>alert(1)</script>" },
        ] });
        let rows = history_rows(&history);
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0]["subject"].as_str(), rows[0]["action"].as_str()), (Some("<script>alert(1)</script>"), Some("reject")), "newest first, content passed on as plain data");
        assert_eq!(rows[1]["symbols"][0]["name"], "B", "the heaviest rules come first");
        assert!(rows[1].get("user").is_none(), "only the listed fields are passed on");
        let many = json!({ "rows": (0..200).map(|n| json!({ "unix_time": n })).collect::<Vec<_>>() });
        assert_eq!(history_rows(&many).len(), HISTORY_ROWS);
        assert!(history_rows(&json!("nonsense")).is_empty());
    }
}
