//! OpenTelemetry traces: the server's spans (HTTP requests, JMAP methods, IMAP commands,
//! received and delivered mail) are sent to a collector over OTLP/HTTP with JSON encoding.
//!
//! Off unless `UNOMAIL_OTLP_ENDPOINT` names a collector, e.g. `http://otel-collector:4318`;
//! spans go to `<endpoint>/v1/traces`. `UNOMAIL_OTLP_HEADERS` adds request headers
//! (`key=value,key2=value2`, for an API key) and `UNOMAIL_OTLP_SERVICE_NAME` replaces
//! `unomail` as the service name. Spans are batched; when the collector cannot keep up they
//! are dropped rather than slow the server down.

use std::{
    fmt::Write as _,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rand::RngCore;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tracing::{
    Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

const QUEUE: usize = 4096;
const BATCH: usize = 256;
const FLUSH_EVERY: Duration = Duration::from_secs(5);
/// Events kept per span (log lines inside it); more are counted, not kept.
const MAX_EVENTS: usize = 32;
const MAX_ATTRIBUTE_BYTES: usize = 1024;

/// A log line inside a span: (time in nanoseconds, message, fields).
type SpanEvent = (u128, String, Vec<(String, String)>);

/// A finished span on its way to the collector.
#[derive(Debug, Clone)]
pub struct SpanRecord {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    parent: Option<[u8; 8]>,
    name: &'static str,
    start: u128,
    end: u128,
    attributes: Vec<(String, String)>,
    events: Vec<SpanEvent>,
    error: bool,
}

/// Kept in the extensions of each live span.
struct Live {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    parent: Option<[u8; 8]>,
    start: u128,
    attributes: Vec<(String, String)>,
    events: Vec<SpanEvent>,
    error: bool,
}

fn now_nanos() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos())
}

#[derive(Default)]
struct Fields(Vec<(String, String)>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let mut text = format!("{value:?}");
        text.truncate(text.char_indices().nth(MAX_ATTRIBUTE_BYTES).map_or(text.len(), |(i, _)| i));
        self.0.push((field.name().to_owned(), text));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let end = value.char_indices().nth(MAX_ATTRIBUTE_BYTES).map_or(value.len(), |(i, _)| i);
        self.0.push((field.name().to_owned(), value[..end].to_owned()));
    }
}

/// The tracing layer that collects spans for export.
pub struct OtlpLayer {
    sender: mpsc::Sender<SpanRecord>,
}

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for OtlpLayer {
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let parent = span.parent().and_then(|parent| parent.extensions().get::<Live>().map(|live| (live.trace_id, live.span_id)));
        let mut rng = rand::thread_rng();
        let trace_id = parent.map(|(trace, _)| trace).unwrap_or_else(|| {
            let mut id = [0u8; 16];
            rng.fill_bytes(&mut id);
            id
        });
        let mut span_id = [0u8; 8];
        rng.fill_bytes(&mut span_id);
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        span.extensions_mut().insert(Live { trace_id, span_id, parent: parent.map(|(_, span)| span), start: now_nanos(), attributes: fields.0, events: Vec::new(), error: false });
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut fields = Fields::default();
        values.record(&mut fields);
        if let Some(live) = span.extensions_mut().get_mut::<Live>() {
            for (key, value) in fields.0 {
                live.attributes.retain(|(k, _)| *k != key);
                live.attributes.push((key, value));
            }
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.event_span(event) else { return };
        let mut fields = Fields::default();
        event.record(&mut fields);
        let mut extensions = span.extensions_mut();
        let Some(live) = extensions.get_mut::<Live>() else { return };
        if *event.metadata().level() == tracing::Level::ERROR {
            live.error = true;
        }
        if live.events.len() < MAX_EVENTS {
            let message = fields.0.iter().position(|(k, _)| k == "message").map(|i| fields.0.remove(i).1).unwrap_or_else(|| event.metadata().name().to_owned());
            fields.0.push(("level".into(), event.metadata().level().to_string()));
            live.events.push((now_nanos(), message, fields.0));
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let name = span.metadata().name();
        let Some(live) = span.extensions_mut().remove::<Live>() else { return };
        let record = SpanRecord {
            trace_id: live.trace_id,
            span_id: live.span_id,
            parent: live.parent,
            name,
            start: live.start,
            end: now_nanos(),
            attributes: live.attributes,
            events: live.events,
            error: live.error,
        };
        // A full queue means the collector is behind: the span is dropped.
        let _ = self.sender.try_send(record);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn attributes(list: &[(String, String)]) -> Value {
    Value::Array(list.iter().map(|(key, value)| json!({ "key": key, "value": { "stringValue": value } })).collect())
}

/// One OTLP/JSON export request (opentelemetry-proto `ExportTraceServiceRequest`).
pub fn export_body(service: &str, host: &str, spans: &[SpanRecord]) -> Value {
    let spans: Vec<Value> = spans
        .iter()
        .map(|span| {
            let mut out = json!({
                "traceId": hex(&span.trace_id),
                "spanId": hex(&span.span_id),
                "name": span.name,
                // SERVER for the outermost span of a request, INTERNAL inside it.
                "kind": if span.parent.is_none() { 2 } else { 1 },
                "startTimeUnixNano": span.start.to_string(),
                "endTimeUnixNano": span.end.to_string(),
                "attributes": attributes(&span.attributes),
                "events": span.events.iter().map(|(at, name, attrs)| json!({ "timeUnixNano": at.to_string(), "name": name, "attributes": attributes(attrs) })).collect::<Vec<_>>(),
                "status": { "code": if span.error { 2 } else { 0 } },
            });
            if let Some(parent) = span.parent {
                out["parentSpanId"] = json!(hex(&parent));
            }
            out
        })
        .collect();
    json!({
        "resourceSpans": [{
            "resource": { "attributes": attributes(&[("service.name".into(), service.into()), ("host.name".into(), host.into()), ("service.version".into(), env!("CARGO_PKG_VERSION").into())]) },
            "scopeSpans": [{ "scope": { "name": "unomail", "version": env!("CARGO_PKG_VERSION") }, "spans": spans }],
        }]
    })
}

/// `key=value,key=value` into header pairs; malformed entries are skipped.
pub fn parse_headers(text: &str) -> Vec<(String, String)> {
    text.split(',')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .filter(|(k, v)| !k.is_empty() && reqwest::header::HeaderName::from_bytes(k.as_bytes()).is_ok() && reqwest::header::HeaderValue::from_str(v).is_ok())
        .collect()
}

/// The layer and its exporter, when a collector is configured. Must be called inside the
/// Tokio runtime.
pub fn from_env() -> Option<OtlpLayer> {
    let endpoint = std::env::var("UNOMAIL_OTLP_ENDPOINT").ok().filter(|e| !e.trim().is_empty())?;
    let url = format!("{}/v1/traces", endpoint.trim().trim_end_matches('/'));
    if reqwest::Url::parse(&url).is_err() {
        eprintln!("UNOMAIL_OTLP_ENDPOINT is not a URL; traces are not exported");
        return None;
    }
    let headers = parse_headers(&std::env::var("UNOMAIL_OTLP_HEADERS").unwrap_or_default());
    let service = std::env::var("UNOMAIL_OTLP_SERVICE_NAME").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "unomail".into());
    let host = std::env::var("UNOMAIL_HOSTNAME").unwrap_or_default();
    let (sender, receiver) = mpsc::channel(QUEUE);
    tokio::spawn(export(receiver, url, headers, service, host));
    Some(OtlpLayer { sender })
}

async fn export(mut receiver: mpsc::Receiver<SpanRecord>, url: String, headers: Vec<(String, String)>, service: String, host: String) {
    let client = match reqwest::Client::builder().use_preconfigured_tls((*crate::smtp::client::tls_config(true)).clone()).timeout(Duration::from_secs(10)).build() {
        Ok(client) => client,
        Err(err) => {
            eprintln!("trace export disabled: {err}");
            return;
        }
    };
    let mut batch: Vec<SpanRecord> = Vec::with_capacity(BATCH);
    let mut ticker = tokio::time::interval(FLUSH_EVERY);
    let mut warned = false;
    loop {
        let closed = tokio::select! {
            received = receiver.recv() => match received {
                Some(span) => {
                    batch.push(span);
                    if batch.len() < BATCH {
                        continue;
                    }
                    false
                }
                None => true,
            },
            _ = ticker.tick() => false,
        };
        if !batch.is_empty() {
            let mut request = client.post(&url).json(&export_body(&service, &host, &batch));
            for (key, value) in &headers {
                request = request.header(key, value);
            }
            // Printed, not logged: a log line here would describe the exporter to itself.
            match request.send().await {
                Ok(response) if response.status().is_success() => warned = false,
                Ok(response) if !warned => {
                    eprintln!("trace export: the collector answered {}", response.status());
                    warned = true;
                }
                Err(err) if !warned => {
                    eprintln!("trace export failed: {err}");
                    warned = true;
                }
                _ => {}
            }
            batch.clear();
        }
        if closed {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn spans_become_otlp_json() {
        let (sender, mut receiver) = mpsc::channel(16);
        let subscriber = tracing_subscriber::registry().with(OtlpLayer { sender });
        tracing::subscriber::with_default(subscriber, || {
            let outer = tracing::info_span!("http.request", method = "GET");
            let _entered = outer.enter();
            let inner = tracing::info_span!("jmap.method", name = tracing::field::Empty);
            inner.record("name", "Email/get");
            inner.in_scope(|| tracing::error!(reason = "boom", "it failed"));
        });
        let inner = receiver.try_recv().unwrap();
        let outer = receiver.try_recv().unwrap();
        assert_eq!((inner.name, outer.name), ("jmap.method", "http.request"));
        assert_eq!(inner.trace_id, outer.trace_id, "children share the trace");
        assert_eq!(inner.parent, Some(outer.span_id));
        assert!(inner.error && !outer.error);
        let body = export_body("unomail", "mail.example", &[inner, outer]);
        let spans = &body["resourceSpans"][0]["scopeSpans"][0]["spans"];
        assert_eq!(spans[0]["attributes"], json!([{ "key": "name", "value": { "stringValue": "Email/get" } }]));
        assert_eq!(spans[0]["events"][0]["name"], "it failed");
        assert_eq!(spans[0]["status"]["code"], 2);
        assert_eq!(spans[1]["kind"], 2);
        assert!(spans[1].get("parentSpanId").is_none());
        assert_eq!(spans[0]["traceId"].as_str().unwrap().len(), 32);
    }

    #[test]
    fn headers_are_parsed_safely() {
        assert_eq!(parse_headers("x-api-key=abc, bad header=1,empty=,=v,ok=a=b"), vec![("x-api-key".into(), "abc".into()), ("empty".into(), String::new()), ("ok".into(), "a=b".into())]);
        assert!(parse_headers("x=a\r\nInjected: 1").is_empty());
    }
}
