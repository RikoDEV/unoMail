//! JMAP over WebSocket (RFC 8887): requests and responses on one connection, plus pushed
//! state changes once the client asks for them.

use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use super::{JmapUser, process};
use crate::app::AppState;

const MAX_MESSAGE: usize = 10 * 1024 * 1024;

/// The WebSocket URL announced in the session object.
pub fn url(state: &AppState) -> String {
    let base = state.cfg.public_url();
    let base = base.strip_prefix("https://").map(|rest| format!("wss://{rest}")).or_else(|| base.strip_prefix("http://").map(|rest| format!("ws://{rest}"))).unwrap_or(base);
    format!("{base}/jmap/ws")
}

/// Browsers send cookies with cross-site WebSocket requests: only this site's own pages (or
/// clients that are not browsers) may connect.
fn same_origin(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else { return true };
    let (Ok(origin), Ok(public)) = (reqwest::Url::parse(origin), reqwest::Url::parse(&state.cfg.public_url())) else { return false };
    origin.origin() == public.origin()
}

pub async fn upgrade(State(state): State<AppState>, user: JmapUser, headers: HeaderMap, ws: WebSocketUpgrade) -> Response {
    if !same_origin(&state, &headers) {
        return (StatusCode::FORBIDDEN, "cross-origin WebSocket connections are not allowed").into_response();
    }
    ws.protocols(["jmap"]).max_message_size(MAX_MESSAGE).on_upgrade(move |socket| session(state, user, socket))
}

fn request_error(id: &Value, kind: &str, detail: &str) -> Message {
    let mut error = json!({ "@type": "RequestError", "type": format!("urn:ietf:params:jmap:error:{kind}"), "status": 400, "detail": detail });
    if !id.is_null() {
        error["requestId"] = id.clone();
    }
    Message::Text(error.to_string().into())
}

async fn session(state: AppState, user: JmapUser, mut socket: WebSocket) {
    let ip = user.ip;
    let mut recheck = tokio::time::interval(crate::auth::RECHECK_INTERVAL);
    let mut changes = state.store.subscribe();
    // Push is off until the client enables it (RFC 8887 section 4.3.5).
    let mut push = false;
    let mut last_pushed = String::new();
    loop {
        tokio::select! {
            _ = recheck.tick() => {
                if user.auth.account(&state).await.is_none() { return; }
            }
            message = socket.recv() => {
                let Some(Ok(message)) = message else { return };
                let Some(account) = user.auth.account(&state).await else { return };
                let text = match message {
                    Message::Text(text) => text.to_string(),
                    Message::Binary(data) => match String::from_utf8(data.to_vec()) {
                        Ok(text) => text,
                        Err(_) => {
                            if socket.send(request_error(&Value::Null, "notJSON", "messages must be UTF-8 JSON")).await.is_err() { return }
                            continue;
                        }
                    },
                    Message::Close(_) => return,
                    _ => continue,
                };
                let Ok(object) = serde_json::from_str::<Value>(&text) else {
                    if socket.send(request_error(&Value::Null, "notJSON", "the message is not valid JSON")).await.is_err() { return }
                    continue;
                };
                let id = object.get("id").cloned().unwrap_or(Value::Null);
                let reply = match object["@type"].as_str() {
                    Some("Request") => match process(&state, &account, ip, user.auth.origin(), &object).await {
                        Ok(mut response) => {
                            response["@type"] = json!("Response");
                            if !id.is_null() {
                                response["requestId"] = id;
                            }
                            Message::Text(response.to_string().into())
                        }
                        Err((kind, detail)) => request_error(&id, kind, detail),
                    },
                    Some("WebSocketPushEnable") => {
                        push = true;
                        // A client that is behind gets the current state right away.
                        let current = state.store.account_state(account.id).await.map(|s| s.to_string()).unwrap_or_default();
                        if object["pushState"].as_str().is_some_and(|known| known != current) {
                            if let Some(change) = super::push::state_change(&state, account.id).await {
                                last_pushed = current.clone();
                                let mut change = change;
                                change["pushState"] = json!(current);
                                if socket.send(Message::Text(change.to_string().into())).await.is_err() { return }
                            }
                        } else {
                            last_pushed = current;
                        }
                        continue;
                    }
                    Some("WebSocketPushDisable") => {
                        push = false;
                        continue;
                    }
                    _ => request_error(&id, "notRequest", "unknown message type"),
                };
                if socket.send(reply).await.is_err() {
                    return;
                }
            }
            change = changes.recv(), if push => {
                let Some(account) = user.auth.account(&state).await else { return };
                match change {
                    Ok(change) if change.account_id != account.id => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                    _ => {}
                }
                let current = state.store.account_state(account.id).await.map(|s| s.to_string()).unwrap_or_default();
                if current == last_pushed {
                    continue;
                }
                if let Some(mut change) = super::push::state_change(&state, account.id).await {
                    change["pushState"] = json!(current);
                    last_pushed = current;
                    if socket.send(Message::Text(change.to_string().into())).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}
