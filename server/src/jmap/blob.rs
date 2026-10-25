//! JMAP Blob management (RFC 9404): Blob/upload, Blob/get and Blob/lookup.
//!
//! Uploaded blobs land in the same `uploads` table as the HTTP upload endpoint, so they count
//! against the same pending space and can be attached or imported like any other upload.

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Map, Value, json};
use sha1::Digest as _;

use super::{Context, MethodError, MethodResult, account_id, set_error};

pub const CAPABILITY: &str = "urn:ietf:params:jmap:blob";
const MAX_DATA_SOURCES: usize = 64;
const TYPE_NAMES: &[&str] = &["Email", "Mailbox", "Thread"];

pub fn capability(max_size: usize) -> Value {
    json!({
        "maxSizeBlobSet": max_size,
        "maxDataSources": MAX_DATA_SOURCES,
        "supportedTypeNames": TYPE_NAMES,
        "supportedDigestAlgorithms": ["sha", "sha-256"],
    })
}

async fn load(ctx: &Context<'_>, blob_id: &str) -> Result<Option<(Vec<u8>, String)>, MethodError> {
    // `#key` names a blob created earlier in the same request.
    let blob_id = blob_id.strip_prefix('#').and_then(|k| ctx.created.get(k)).map(String::as_str).unwrap_or(blob_id);
    super::email::load_blob(ctx.app, ctx.account, blob_id).await.map_err(MethodError::server)
}

/// Clips `data` to `offset`/`length`; the flag tells whether the range ran past the end.
fn slice(data: &[u8], offset: Option<u64>, length: Option<u64>) -> (&[u8], bool) {
    let start = offset.unwrap_or(0) as usize;
    if start > data.len() {
        return (&[], true);
    }
    let rest = &data[start..];
    match length {
        Some(n) if (n as usize) <= rest.len() => (&rest[..n as usize], false),
        Some(_) => (rest, true),
        None => (rest, false),
    }
}

pub async fn upload(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let create = args.get("create").and_then(Value::as_object).cloned().unwrap_or_default();
    let max = ctx.app.rt().max_message_size;
    let mut created = Map::new();
    let mut not_created = Map::new();
    for (key, spec) in &create {
        match build(ctx, spec, max).await? {
            Ok(data) => {
                let content_type = spec["type"].as_str().filter(|v| v.len() <= 100 && v.parse::<mime::Mime>().is_ok()).unwrap_or("application/octet-stream").to_owned();
                let hash = ctx.app.store.put_blob(&data).await.map_err(MethodError::server)?;
                sqlx::query(
                    "INSERT INTO uploads (account_id, hash, content_type, size, created_at) VALUES (?, ?, ?, ?, ?)
                     ON CONFLICT(account_id, hash) DO UPDATE SET created_at = excluded.created_at, content_type = excluded.content_type",
                )
                .bind(ctx.account.id)
                .bind(&hash)
                .bind(&content_type)
                .bind(data.len() as i64)
                .bind(crate::util::now())
                .execute(&ctx.app.db)
                .await?;
                let id = format!("u{hash}");
                ctx.created.insert(key.clone(), id.clone());
                created.insert(key.clone(), json!({ "id": id, "type": content_type, "size": data.len() }));
            }
            Err(error) => {
                not_created.insert(key.clone(), error);
            }
        }
    }
    Ok(json!({ "accountId": account_id(ctx.account), "created": created, "notCreated": not_created }))
}

/// Concatenates a create's data sources, or the per-item error.
async fn build(ctx: &Context<'_>, spec: &Value, max: usize) -> Result<Result<Vec<u8>, Value>, MethodError> {
    let Some(sources) = spec["data"].as_array() else { return Ok(Err(set_error("invalidProperties", "data is missing"))) };
    if sources.is_empty() || sources.len() > MAX_DATA_SOURCES {
        return Ok(Err(set_error("tooManyDataSources", "between 1 and 64 data sources")));
    }
    let mut out = Vec::new();
    for source in sources {
        let chunk: Vec<u8> = if let Some(text) = source["data:asText"].as_str() {
            text.as_bytes().to_vec()
        } else if let Some(encoded) = source["data:asBase64"].as_str() {
            match STANDARD.decode(encoded) {
                Ok(data) => data,
                Err(_) => return Ok(Err(set_error("invalidProperties", "data:asBase64 is not base64"))),
            }
        } else if let Some(blob_id) = source["blobId"].as_str() {
            let Some((data, _)) = load(ctx, blob_id).await? else { return Ok(Err(set_error("blobNotFound", "no such blob"))) };
            let (part, past_end) = slice(&data, source["offset"].as_u64(), source["length"].as_u64());
            if past_end {
                return Ok(Err(set_error("invalidProperties", "range runs past the end of the blob")));
            }
            part.to_vec()
        } else {
            return Ok(Err(set_error("invalidProperties", "unknown data source")));
        };
        out.extend_from_slice(&chunk);
        if out.len() > max {
            return Ok(Err(set_error("tooLarge", "the blob is too large")));
        }
    }
    Ok(Ok(out))
}

pub async fn get(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let Some(ids) = args.get("ids").and_then(Value::as_array) else { return Err(MethodError::invalid("ids is required")) };
    if ids.len() > super::MAX_OBJECTS {
        return Err(MethodError("requestTooLarge", "too many ids".into()));
    }
    let properties: Vec<String> = match args.get("properties").and_then(Value::as_array) {
        Some(list) => list.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
        None => vec!["data".into(), "size".into()],
    };
    let (offset, length) = (args.get("offset").and_then(Value::as_u64), args.get("length").and_then(Value::as_u64));
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    for id in ids.iter().filter_map(Value::as_str) {
        let Some((data, _)) = load(ctx, id).await? else {
            not_found.push(id.to_owned());
            continue;
        };
        let (part, past_end) = slice(&data, offset, length);
        let mut item = Map::new();
        item.insert("id".into(), json!(id));
        for property in &properties {
            match property.as_str() {
                "size" => {
                    item.insert("size".into(), json!(data.len()));
                }
                "data:asText" | "data" => match std::str::from_utf8(part) {
                    Ok(text) => {
                        item.insert("data:asText".into(), json!(text));
                    }
                    Err(_) if property == "data" => {
                        item.insert("data:asBase64".into(), json!(STANDARD.encode(part)));
                    }
                    Err(_) => {
                        item.insert("data:asText".into(), Value::Null);
                        item.insert("isEncodingProblem".into(), json!(true));
                    }
                },
                "data:asBase64" => {
                    item.insert("data:asBase64".into(), json!(STANDARD.encode(part)));
                }
                "digest:sha" => {
                    item.insert("digest:sha".into(), json!(STANDARD.encode(sha1::Sha1::digest(part))));
                }
                "digest:sha-256" => {
                    item.insert("digest:sha-256".into(), json!(STANDARD.encode(sha2::Sha256::digest(part))));
                }
                other => return Err(MethodError::invalid(format!("unknown property {other}"))),
            }
        }
        if past_end {
            item.insert("isTruncated".into(), json!(true));
        }
        list.push(Value::Object(item));
    }
    Ok(json!({ "accountId": account_id(ctx.account), "list": list, "notFound": not_found }))
}

pub async fn lookup(ctx: &mut Context<'_>, args: &Map<String, Value>) -> MethodResult {
    let type_names: Vec<&str> = args.get("typeNames").and_then(Value::as_array).map(|l| l.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    if let Some(unknown) = type_names.iter().find(|t| !TYPE_NAMES.contains(t)) {
        return Err(MethodError("unknownDataType", format!("unsupported type {unknown}")));
    }
    let Some(ids) = args.get("ids").and_then(Value::as_array) else { return Err(MethodError::invalid("ids is required")) };
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    for id in ids.iter().filter_map(Value::as_str) {
        // Only message blobs belong to objects; a part's blob belongs to its message.
        let hash = id.split_once('.').map_or(id, |(h, _)| h);
        if load(ctx, id).await?.is_none() {
            not_found.push(id.to_owned());
            continue;
        }
        let rows: Vec<(i64, i64, i64)> = sqlx::query_as("SELECT id, mailbox_id, thread_id FROM messages WHERE account_id = ? AND blob_hash = ? LIMIT 1000")
            .bind(ctx.account.id)
            .bind(hash)
            .fetch_all(&ctx.app.db)
            .await?;
        let mut matched = Map::new();
        for name in &type_names {
            let mut values: Vec<String> = rows
                .iter()
                .map(|(m, b, t)| match *name {
                    "Email" => format!("m{m}"),
                    "Mailbox" => format!("b{b}"),
                    _ => format!("t{t}"),
                })
                .collect();
            values.sort();
            values.dedup();
            matched.insert((*name).to_owned(), json!(values));
        }
        list.push(json!({ "id": id, "matchedIds": matched }));
    }
    Ok(json!({ "accountId": account_id(ctx.account), "list": list, "notFound": not_found }))
}

#[cfg(test)]
mod tests {
    use super::slice;

    #[test]
    fn ranges_are_clipped() {
        assert_eq!(slice(b"hello", Some(1), Some(3)), (&b"ell"[..], false));
        assert_eq!(slice(b"hello", Some(3), Some(9)), (&b"lo"[..], true));
        assert_eq!(slice(b"hello", Some(9), None), (&b""[..], true));
        assert_eq!(slice(b"hello", None, None), (&b"hello"[..], false));
    }
}
