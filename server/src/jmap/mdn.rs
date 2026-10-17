//! Read receipts: `MDN/send` (RFC 9007) builds a message disposition notification (RFC 8098)
//! for a message whose sender asked for one (`Disposition-Notification-To`).

use mail_parser::MessageParser;
use serde_json::{Map, Value, json};

use super::{Context, MethodResult, account_id, email, parse_id, set_error};
use crate::{
    smtp::{
        delivery::rfc2822_now,
        submit::{self, Outcome, Submission},
    },
    util::{Address, random_token, sanitize_line},
};

/// Whether the receipt address is the message's return path. RFC 8098 section 2.1: if they
/// differ, a receipt must not be sent without asking (anyone can name a third party).
pub fn requested_by_return_path(raw: &[u8]) -> bool {
    let Some(requested) = requested_by(raw) else { return false };
    let Some(parsed) = MessageParser::default().parse_headers(raw) else { return false };
    let Some(return_path) = parsed.header_raw("Return-Path") else { return false };
    let return_path = return_path.trim().trim_start_matches('<').trim_end_matches('>').trim();
    !return_path.is_empty() && return_path.eq_ignore_ascii_case(&requested)
}

/// The address a read receipt for `raw` goes to, if one was asked for.
pub fn requested_by(raw: &[u8]) -> Option<String> {
    let parsed = MessageParser::default().parse_headers(raw)?;
    let value = parsed.header_raw("Disposition-Notification-To")?.trim();
    let address = value.rsplit_once('<').map_or(value, |(_, rest)| rest.split('>').next().unwrap_or(""));
    Address::parse(address.trim()).map(|a| a.to_string())
}

pub async fn send(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let (mut sent, mut not_sent) = (Map::new(), Map::new());
    let mut email_updates = Map::new();
    for (creation_id, spec) in args.get("send").and_then(Value::as_object).into_iter().flatten() {
        match send_one(ctx, spec).await {
            Ok(message_id) => {
                sent.insert(creation_id.clone(), json!({ "finalRecipient": format!("rfc822; {}", ctx.account.email) }));
                // Remember that the receipt went out, so that nobody is asked twice.
                let patch = args.get("onSuccessUpdateEmail").and_then(|u| u.get(format!("#{creation_id}"))).and_then(Value::as_object).cloned()
                    .unwrap_or_else(|| Map::from_iter([("keywords/$mdnsent".to_owned(), Value::Bool(true))]));
                let result = email::apply_update(ctx, &format!("m{message_id}"), &patch).await;
                email_updates.insert(format!("m{message_id}"), result.err().unwrap_or(Value::Null));
            }
            Err(err) => {
                not_sent.insert(creation_id.clone(), err);
            }
        }
    }
    let null_if_empty = |map: Map<String, Value>| if map.is_empty() { Value::Null } else { Value::Object(map) };
    Ok(json!({ "accountId": account_id(ctx.account), "sent": null_if_empty(sent), "notSent": null_if_empty(not_sent), "emailUpdates": email_updates }))
}

async fn send_one(ctx: &Context<'_>, spec: &Value) -> Result<i64, Value> {
    let message_id = spec["forEmailId"].as_str().and_then(|id| parse_id(&ctx.resolve_id(id), 'm')).ok_or_else(|| set_error("notFound", "forEmailId is required"))?;
    let (message, _) = ctx.message(message_id).await.map_err(|_| set_error("serverFail", "internal error"))?.ok_or_else(|| set_error("notFound", "no such email"))?;
    let raw = ctx.app.store.read_blob(&message.blob_hash).await.map_err(|_| set_error("serverFail", "message content is missing"))?;
    let recipient = requested_by(&raw).and_then(|a| Address::parse(&a)).ok_or_else(|| set_error("mdnAlreadySent", "the sender did not ask for a read receipt"))?;
    let keywords: Vec<String> = serde_json::from_str(&message.keywords).unwrap_or_default();
    if keywords.iter().any(|k| k.eq_ignore_ascii_case("$mdnsent")) {
        return Err(set_error("mdnAlreadySent", "a receipt was sent already"));
    }
    let disposition = &spec["disposition"];
    let action = match disposition["actionMode"].as_str() {
        Some("automatic-action") => "automatic-action",
        _ => "manual-action",
    };
    if (action == "automatic-action" || disposition["sendingMode"].as_str() == Some("mdn-sent-automatically")) && !requested_by_return_path(&raw) {
        return Err(set_error("forbidden", "the receipt address is not the message's sender: ask the user first"));
    }
    let sending = match disposition["sendingMode"].as_str() {
        Some("mdn-sent-automatically") => "MDN-sent-automatically",
        _ => "MDN-sent-manually",
    };
    let kind = disposition["type"].as_str().filter(|kind| matches!(*kind, "displayed" | "deleted" | "dispatched" | "processed")).unwrap_or("displayed");
    let parsed = MessageParser::default().parse_headers(&raw);
    let subject = parsed.as_ref().and_then(|m| m.subject()).unwrap_or("").to_owned();
    let original_id = parsed.as_ref().and_then(|m| m.message_id()).map(str::to_owned);
    let me = Address::parse(&ctx.account.email).ok_or_else(|| set_error("forbiddenFrom", "invalid account address"))?;
    let boundary = format!("mdn-{}", random_token());
    let text = spec["textBody"].as_str().map(sanitize_text).unwrap_or_else(|| {
        format!("The message \"{}\" sent to {} was {kind} on {}.", sanitize_line(&subject), ctx.account.email, rfc2822_now())
    });
    let mut out = format!(
        "From: <{me}>\r\nTo: <{recipient}>\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: <{id}@{domain}>\r\nAuto-Submitted: {auto}\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/report; report-type=disposition-notification; boundary=\"{boundary}\"\r\n\r\n\
         --{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{text}\r\n\r\n\
         --{boundary}\r\nContent-Type: message/disposition-notification\r\n\r\n\
         Reporting-UA: {host}; unoMail\r\nFinal-Recipient: rfc822; {me}\r\n",
        subject = spec["subject"].as_str().map(sanitize_line).unwrap_or_else(|| format!("Read: {}", sanitize_line(&subject))),
        date = rfc2822_now(),
        id = random_token(),
        domain = me.domain,
        auto = if action == "automatic-action" { "auto-replied" } else { "no" },
        host = ctx.app.cfg.hostname,
    );
    if let Some(original) = original_id {
        out.push_str(&format!("Original-Message-ID: <{}>\r\n", sanitize_line(&original)));
    }
    out.push_str(&format!("Disposition: {action}/{sending}; {kind}\r\n\r\n--{boundary}--\r\n"));
    let recipients = [recipient];
    match submit::submit(ctx.app, Submission { account: ctx.account, sender: &me, recipients: &recipients, raw: out.as_bytes(), delegate: None, ip: ctx.ip }).await {
        Outcome::Accepted(_) => Ok(message_id),
        Outcome::Rejected(reply) => Err(set_error("forbiddenToSend", reply)),
        Outcome::Deferred(_) => Err(set_error("serverFail", "try again later")),
    }
}

fn sanitize_text(text: &str) -> String {
    text.chars().filter(|c| !c.is_control() || *c == '\n').take(5000).collect::<String>().replace('\n', "\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_receipts_only_to_the_return_path() {
        assert!(requested_by_return_path(b"Return-Path: <alice@b.example>\r\nDisposition-Notification-To: Alice <alice@b.example>\r\n\r\nx"));
        assert!(!requested_by_return_path(b"Return-Path: <alice@b.example>\r\nDisposition-Notification-To: victim@c.example\r\n\r\nx"));
        assert!(!requested_by_return_path(b"Return-Path: <>\r\nDisposition-Notification-To: victim@c.example\r\n\r\nx"));
        assert!(!requested_by_return_path(b"Disposition-Notification-To: victim@c.example\r\n\r\nx"));
    }

    #[test]
    fn receipts_are_requested_by_header() {
        assert_eq!(requested_by(b"From: a@b.example\r\nDisposition-Notification-To: Alice <alice@b.example>\r\n\r\nx").as_deref(), Some("alice@b.example"));
        assert_eq!(requested_by(b"From: a@b.example\r\n\r\nx"), None);
    }
}
