//! Capacity monitoring: free space on the data volume and memory use, sampled once a minute
//! and kept for a week so the dashboard can show where they are heading.

use std::{path::Path, time::Duration};

use serde::Serialize;
use sysinfo::{Disks, MemoryRefreshKind, Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

use crate::{
    app::{App, AppState},
    util::now,
};

const INTERVAL: Duration = Duration::from_secs(60);
const RETENTION_SECS: i64 = 7 * 86400;
/// Charts never need more points than they have pixels.
pub const MAX_POINTS: i64 = 240;

#[derive(Debug, Clone, Copy, Serialize, sqlx::FromRow, PartialEq, Eq)]
pub struct Sample {
    pub ts: i64,
    pub disk_free: i64,
    pub disk_total: i64,
    pub mem_used: i64,
    pub mem_total: i64,
    pub process: i64,
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
    system.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), true, ProcessRefreshKind::nothing().with_memory());
    let (disk_free, disk_total) = disk_space(data_dir);
    let clamp = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
    Sample {
        ts: now(),
        disk_free: clamp(disk_free),
        disk_total: clamp(disk_total),
        mem_used: clamp(system.used_memory()),
        mem_total: clamp(system.total_memory()),
        process: clamp(system.process(pid).map_or(0, |process| process.memory())),
    }
}

pub async fn record(app: &App) -> Option<Sample> {
    let data_dir = app.cfg.data_dir.clone();
    let sample = tokio::task::spawn_blocking(move || measure(&data_dir)).await.ok()?;
    let stored = sqlx::query("INSERT OR REPLACE INTO system_samples (ts, disk_free, disk_total, mem_used, mem_total, process) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(sample.ts)
        .bind(sample.disk_free)
        .bind(sample.disk_total)
        .bind(sample.mem_used)
        .bind(sample.mem_total)
        .bind(sample.process)
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
        "SELECT ts, disk_free, disk_total, mem_used, mem_total, process FROM system_samples
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
    }
}
