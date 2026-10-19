//! Capacity monitoring: free space on the data volume and memory use, sampled once a minute
//! and kept for a week so the dashboard can show where they are heading.
//!
//! Memory is that of the container (or systemd unit) the server runs in, read from its cgroup,
//! and falls back to the whole host where there is none. It is split by bundled service.

use std::{path::Path, time::Duration};

use serde::{Serialize, Serializer};
use sysinfo::{Disks, MemoryRefreshKind, Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

use crate::{
    app::{App, AppState},
    util::now,
};

const INTERVAL: Duration = Duration::from_secs(60);
const RETENTION_SECS: i64 = 7 * 86400;
/// Charts never need more points than they have pixels.
pub const MAX_POINTS: i64 = 240;

/// The services the chart tells apart, in display order; `other` takes the rest.
pub const SERVICES: [&str; 5] = ["unomail", "rspamd", "clamav", "redis", "other"];

#[derive(Debug, Clone, Serialize, sqlx::FromRow, PartialEq, Eq)]
pub struct Sample {
    pub ts: i64,
    pub disk_free: i64,
    pub disk_total: i64,
    pub mem_used: i64,
    pub mem_total: i64,
    pub process: i64,
    /// Bytes per service as a JSON object, sent to the client as that object.
    #[serde(serialize_with = "raw_json")]
    pub services: Option<String>,
}

fn raw_json<S: Serializer>(value: &Option<String>, serializer: S) -> Result<S::Ok, S::Error> {
    value.as_deref().and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok()).serialize(serializer)
}

/// The service a process belongs to, by its name.
fn service_of(name: &str) -> &'static str {
    match name {
        "unomail" => "unomail",
        name if name.starts_with("rspamd") => "rspamd",
        "clamd" | "freshclam" => "clamav",
        name if name.starts_with("redis") => "redis",
        _ => "other",
    }
}

/// Used and total memory of this process's cgroup (v2), when it has a limit or usage of its
/// own: a container or a systemd unit. Used memory leaves out the page cache that can be
/// reclaimed, like `docker stats`. Elsewhere than on Linux the files are missing: `None`.
fn cgroup_memory() -> Option<(u64, Option<u64>)> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = cgroup.lines().find_map(|line| line.strip_prefix("0::"))?.trim();
    let dir = Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/'));
    let current: u64 = std::fs::read_to_string(dir.join("memory.current")).ok()?.trim().parse().ok()?;
    let limit = std::fs::read_to_string(dir.join("memory.max")).ok().and_then(|text| text.trim().parse().ok());
    let inactive = std::fs::read_to_string(dir.join("memory.stat"))
        .ok()
        .and_then(|stat| stat.lines().find_map(|line| line.strip_prefix("inactive_file ")?.trim().parse::<u64>().ok()))
        .unwrap_or(0);
    Some((current.saturating_sub(inactive), limit))
}


/// Free and total bytes of the volume that holds `path`: the mounted file system whose mount
/// point is the longest prefix of the path.
fn disk_space(path: &Path) -> (u64, u64) {
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    // Windows reports canonical paths in verbatim form (\\?\C:\...), mount points as C:\.
    let path = match path.to_str().and_then(|text| text.strip_prefix(r"\\?\")) {
        Some(plain) => std::path::PathBuf::from(plain),
        None => path,
    };
    let disks = Disks::new_with_refreshed_list();
    disks
        .list()
        .iter()
        .filter(|disk| path.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
        .map_or((0, 0), |disk| (disk.available_space(), disk.total_space()))
}

/// Reads the current state of the host. Blocking; call from a blocking task.
pub fn measure(data_dir: &Path) -> Sample {
    let mut system = System::new_with_specifics(RefreshKind::nothing().with_memory(MemoryRefreshKind::nothing().with_ram()));
    let pid = Pid::from_u32(std::process::id());
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing().with_memory());
    let (disk_free, disk_total) = disk_space(data_dir);
    let clamp = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
    let (mem_used, mem_total) = match cgroup_memory() {
        // An unlimited container may use the whole host.
        Some((used, limit)) => (used, limit.unwrap_or(u64::MAX).min(system.total_memory())),
        None => (system.used_memory(), system.total_memory()),
    };
    let mut services = std::collections::BTreeMap::<&str, u64>::new();
    for process in system.processes().values() {
        let service = service_of(&process.name().to_string_lossy());
        if service != "other" || process.pid() == pid {
            *services.entry(if process.pid() == pid { "unomail" } else { service }).or_default() += process.memory();
        }
    }
    // Resident sizes count shared pages in every process, so they can add up to more than used.
    let named: u64 = services.values().sum();
    services.insert("other", mem_used.saturating_sub(named));
    let services: serde_json::Map<String, serde_json::Value> = SERVICES.iter().map(|name| (name.to_string(), clamp(services.get(name).copied().unwrap_or(0)).into())).collect();
    Sample {
        ts: now(),
        disk_free: clamp(disk_free),
        disk_total: clamp(disk_total),
        mem_used: clamp(mem_used),
        mem_total: clamp(mem_total),
        process: clamp(system.process(pid).map_or(0, |process| process.memory())),
        services: Some(serde_json::Value::Object(services).to_string()),
    }
}

pub async fn record(app: &App) -> Option<Sample> {
    let data_dir = app.cfg.data_dir.clone();
    let sample = tokio::task::spawn_blocking(move || measure(&data_dir)).await.ok()?;
    let stored = sqlx::query("INSERT OR REPLACE INTO system_samples (ts, disk_free, disk_total, mem_used, mem_total, process, services) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(sample.ts)
        .bind(sample.disk_free)
        .bind(sample.disk_total)
        .bind(sample.mem_used)
        .bind(sample.mem_total)
        .bind(sample.process)
        .bind(&sample.services)
        .execute(&app.db)
        .await;
    if let Err(err) = stored {
        tracing::error!(%err, "could not store a system sample");
    }
    Some(sample)
}

/// Samples of the last `hours`, thinned out evenly to at most `MAX_POINTS`. Each returned
/// point is the last sample of its time slot, so the newest sample is always included.
pub async fn history(app: &App, hours: i64) -> sqlx::Result<Vec<Sample>> {
    let since = now() - hours.clamp(1, RETENTION_SECS / 3600) * 3600;
    let slot = ((now() - since) / MAX_POINTS).max(1);
    sqlx::query_as(
        "SELECT ts, disk_free, disk_total, mem_used, mem_total, process, services FROM system_samples
         WHERE ts IN (SELECT MAX(ts) FROM system_samples WHERE ts >= ?1 GROUP BY (ts - ?1) / ?2) ORDER BY ts",
    )
    .bind(since)
    .bind(slot)
    .fetch_all(&app.db)
    .await
}

/// Sampler: runs until the process exits.
pub async fn run(app: AppState) {
    loop {
        record(&app).await;
        if let Err(err) = sqlx::query("DELETE FROM system_samples WHERE ts < ?").bind(now() - RETENTION_SECS).execute(&app.db).await {
            tracing::error!(%err, "could not prune system samples");
        }
        tokio::time::sleep(INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_can_be_measured() {
        let dir = tempfile::tempdir().unwrap();
        let sample = measure(dir.path());
        assert!(sample.mem_total > 0 && sample.mem_used > 0 && sample.mem_used <= sample.mem_total, "{sample:?}");
        assert!(sample.disk_total > 0 && sample.disk_free <= sample.disk_total, "{sample:?}");
        assert!(sample.process > 0, "{sample:?}");
        let services: serde_json::Value = serde_json::from_str(sample.services.as_deref().unwrap()).unwrap();
        assert!(services["unomail"].as_i64().unwrap() > 0, "{services}");
        assert_eq!(services.as_object().unwrap().len(), SERVICES.len());
    }

    #[test]
    fn processes_belong_to_services() {
        assert_eq!(service_of("rspamd"), "rspamd");
        assert_eq!(service_of("rspamd: normal process"), "rspamd");
        assert_eq!(service_of("clamd"), "clamav");
        assert_eq!(service_of("freshclam"), "clamav");
        assert_eq!(service_of("redis-server"), "redis");
        assert_eq!(service_of("s6-supervise"), "other");
    }
}
