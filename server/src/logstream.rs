//! Live log streaming: a process-wide bus carrying delivery, audit, system and SMTP log entries
//! to the admin panel, plus in-memory buffers of recent system log lines and SMTP replies.

use std::{
    collections::VecDeque,
    sync::{Arc, LazyLock, atomic::{AtomicI64, Ordering}},
};

use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::sync::broadcast;
use tracing::{Event, Level, Subscriber, field::{Field, Visit}};
use tracing_subscriber::{Layer, layer::Context};

const SYSTEM_BUFFER: usize = 2000;
const SMTP_BUFFER: usize = 2000;

#[derive(Debug, Clone)]
pub struct LogEvent {
    /// `delivery`, `audit`, `system` or `smtp`.
    pub kind: &'static str,
    pub entry: Value,
}

static BUS: LazyLock<broadcast::Sender<Arc<LogEvent>>> = LazyLock::new(|| broadcast::channel(1024).0);
static SYSTEM: LazyLock<Mutex<VecDeque<Value>>> = LazyLock::new(|| Mutex::new(VecDeque::with_capacity(SYSTEM_BUFFER)));
static SYSTEM_ID: AtomicI64 = AtomicI64::new(1);
static SMTP: LazyLock<Mutex<VecDeque<Value>>> = LazyLock::new(|| Mutex::new(VecDeque::with_capacity(SMTP_BUFFER)));
static SMTP_ID: AtomicI64 = AtomicI64::new(1);

pub fn publish(kind: &'static str, entry: Value) {
    // No receivers simply means nobody is watching.
    let _ = BUS.send(Arc::new(LogEvent { kind, entry }));
}

pub fn subscribe() -> broadcast::Receiver<Arc<LogEvent>> {
    BUS.subscribe()
}

/// The most recent system log lines, newest first.
pub fn recent_system(limit: usize, query: &str) -> Vec<Value> {
    recent(&SYSTEM, limit, query)
}

/// The most recent SMTP replies sent to clients, newest first.
pub fn recent_smtp(limit: usize, query: &str) -> Vec<Value> {
    recent(&SMTP, limit, query)
}

fn recent(buffer: &Mutex<VecDeque<Value>>, limit: usize, query: &str) -> Vec<Value> {
    let needle = query.to_lowercase();
    buffer
        .lock()
        .iter()
        .rev()
        .filter(|entry| needle.is_empty() || entry.to_string().to_lowercase().contains(&needle))
        .take(limit)
        .cloned()
        .collect()
}

fn push(buffer: &Mutex<VecDeque<Value>>, capacity: usize, entry: Value) {
    let mut buffer = buffer.lock();
    if buffer.len() >= capacity {
        buffer.pop_front();
    }
    buffer.push_back(entry);
}

pub fn record_system(level: &str, target: &str, message: &str) {
    let entry = json!({
        "id": SYSTEM_ID.fetch_add(1, Ordering::Relaxed),
        "ts": crate::util::now(),
        "level": level,
        "target": target,
        "message": crate::util::sanitize_line(message),
    });
    push(&SYSTEM, SYSTEM_BUFFER, entry.clone());
    publish("system", entry);
}

/// Records an SMTP reply line sent to `ip`; `text` must already be sanitized.
pub fn record_smtp(ip: &str, code: u16, text: &str) {
    let entry = json!({
        "id": SMTP_ID.fetch_add(1, Ordering::Relaxed),
        "ts": crate::util::now(),
        "ip": ip,
        "code": code,
        "text": text,
    });
    push(&SMTP, SMTP_BUFFER, entry.clone());
    publish("smtp", entry);
}

#[derive(Default)]
struct Collector(String);

impl Visit for Collector {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }
}

/// Tracing layer that mirrors log events into the system log buffer and stream. Per-message
/// `delivery` and `audit` events have their own streams and are not duplicated here.
pub struct SystemLogLayer;

impl<S: Subscriber> Layer<S> for SystemLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        if *meta.level() > Level::INFO || matches!(meta.target(), "audit" | "delivery") {
            return;
        }
        let mut collector = Collector::default();
        event.record(&mut collector);
        record_system(meta.level().as_str(), meta.target(), collector.0.trim());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_buffer_is_bounded_searchable_and_streamed() {
        let mut receiver = subscribe();
        record_system("WARN", "unomail::test", "disk almost\r\nfull marker-xyz");
        let hits = recent_system(10, "MARKER-XYZ");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["message"], "disk almostfull marker-xyz", "control characters are stripped");
        let mut seen = false;
        while let Ok(event) = receiver.try_recv() {
            seen |= event.kind == "system" && event.entry["message"].as_str().is_some_and(|m| m.contains("marker-xyz"));
        }
        assert!(seen);
        for i in 0..SYSTEM_BUFFER + 50 {
            record_system("INFO", "unomail::test", &format!("filler {i}"));
        }
        assert_eq!(SYSTEM.lock().len(), SYSTEM_BUFFER);
        assert!(recent_system(10, "marker-xyz").is_empty(), "old entries are evicted");
    }

    #[test]
    fn smtp_replies_are_searchable_and_streamed() {
        let mut receiver = subscribe();
        record_smtp("192.0.2.7", 550, "5.7.1 rejected smtp-marker-abc");
        let hits = recent_smtp(10, "SMTP-MARKER-ABC");
        assert_eq!(hits.len(), 1);
        assert_eq!((hits[0]["ip"].as_str(), hits[0]["code"].as_u64()), (Some("192.0.2.7"), Some(550)));
        let mut seen = false;
        while let Ok(event) = receiver.try_recv() {
            seen |= event.kind == "smtp" && event.entry["text"].as_str().is_some_and(|m| m.contains("smtp-marker-abc"));
        }
        assert!(seen);
    }
}
