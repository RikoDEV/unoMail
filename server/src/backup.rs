//! Scheduled backups: a consistent snapshot of the database plus every message blob, to a
//! directory or an S3 bucket. Blobs are content-addressed, so each run copies only new ones;
//! snapshots past the configured number are removed together with the blobs only they used.
//!
//! Layout at the target:
//! - `snapshots/<id>/unomail.db.gz`: the database (`VACUUM INTO`, gzip)
//! - `snapshots/<id>/blobs.txt.gz`: the blobs it refers to, one hash per line
//! - `snapshots/<id>/manifest.json`: written last; a snapshot without it is incomplete
//! - `blobs/aa/bb/<hash>`: message contents exactly as stored (sealed, with encryption on)
//!
//! The keys in the data directory (`secret.key`, `blob.key`) are deliberately not part of a
//! backup: keep a copy of them somewhere else.

use std::{
    collections::HashSet,
    io::{Read, Write},
    path::PathBuf,
};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::{
    app::App,
    blobstore::{Blobs, relative_path},
    config::{BackupTarget, Config},
    s3::{S3, S3Error},
    util::now,
};

/// Only one backup at a time.
static RUNNING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub enum Target {
    Dir(PathBuf),
    S3(S3),
}

impl Target {
    pub fn from_config(target: &BackupTarget) -> anyhow::Result<Self> {
        Ok(match target {
            BackupTarget::Dir(dir) => Target::Dir(dir.clone()),
            BackupTarget::S3(cfg) => Target::S3(S3::new(cfg.clone())?),
        })
    }

    pub fn describe(&self) -> String {
        match self {
            Target::Dir(dir) => dir.display().to_string(),
            Target::S3(s3) => s3.cfg.describe(),
        }
    }

    async fn put(&self, name: &str, data: Vec<u8>) -> anyhow::Result<()> {
        match self {
            Target::Dir(dir) => {
                let path = dir.join(name);
                let parent = path.parent().context("invalid backup path")?;
                tokio::fs::create_dir_all(parent).await?;
                let tmp = parent.join(format!(".{}.tmp", crate::util::random_token()));
                tokio::fs::write(&tmp, data).await?;
                tokio::fs::rename(&tmp, &path).await?;
                Ok(())
            }
            Target::S3(s3) => Ok(s3.put(name, data).await?),
        }
    }

    async fn get(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        match self {
            Target::Dir(dir) => match tokio::fs::read(dir.join(name)).await {
                Ok(data) => Ok(Some(data)),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(err) => Err(err.into()),
            },
            Target::S3(s3) => match s3.get(name).await {
                Ok(data) => Ok(Some(data)),
                Err(S3Error::NotFound) => Ok(None),
                Err(err) => Err(err.into()),
            },
        }
    }

    async fn delete(&self, name: &str) -> anyhow::Result<()> {
        match self {
            Target::Dir(dir) => match tokio::fs::remove_file(dir.join(name)).await {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err.into()),
            },
            Target::S3(s3) => Ok(s3.delete(name).await?),
        }
    }

    /// Ids of the complete snapshots, oldest first.
    pub async fn snapshots(&self) -> anyhow::Result<Vec<String>> {
        let mut ids: Vec<String> = match self {
            Target::Dir(dir) => {
                let mut ids = Vec::new();
                match tokio::fs::read_dir(dir.join("snapshots")).await {
                    Ok(mut entries) => {
                        while let Some(entry) = entries.next_entry().await? {
                            if tokio::fs::try_exists(entry.path().join("manifest.json")).await.unwrap_or(false) {
                                ids.push(entry.file_name().to_string_lossy().into_owned());
                            }
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => return Err(err.into()),
                }
                ids
            }
            Target::S3(s3) => s3
                .list("snapshots/")
                .await?
                .into_iter()
                .filter_map(|name| name.strip_prefix("snapshots/").and_then(|n| n.strip_suffix("/manifest.json")).map(str::to_owned))
                .collect(),
        };
        ids.retain(|id| valid_id(id));
        ids.sort();
        Ok(ids)
    }

    pub async fn manifest(&self, id: &str) -> anyhow::Result<Option<Manifest>> {
        Ok(match self.get(&format!("snapshots/{id}/manifest.json")).await? {
            Some(data) => Some(serde_json::from_slice(&data)?),
            None => None,
        })
    }

    async fn blob_list(&self, id: &str) -> anyhow::Result<Vec<String>> {
        let Some(data) = self.get(&format!("snapshots/{id}/blobs.txt.gz")).await? else { anyhow::bail!("snapshot {id} has no blob list") };
        let text = String::from_utf8(gunzip(&data)?)?;
        Ok(text.lines().filter(|h| is_hash(h)).map(str::to_owned).collect())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub id: String,
    pub created_at: i64,
    pub version: String,
    pub hostname: String,
    pub blobs: usize,
    pub database_bytes: usize,
    /// Message contents are sealed: restoring needs the same `blob.key`.
    pub encrypted_mail: bool,
}

fn valid_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|b| b.is_ascii_digit() || b == b'T' || b == b'Z')
}

fn is_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn gzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

fn gunzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data).read_to_end(&mut out)?;
    Ok(out)
}

fn snapshot_id(at: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(at)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        .format(time::macros::format_description!("[year][month][day]T[hour][minute][second]Z"))
        .unwrap_or_default()
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Outcome {
    pub snapshot: String,
    pub blobs_copied: usize,
    pub bytes_copied: u64,
    pub blobs_missing: usize,
    pub snapshots_removed: usize,
    pub blobs_removed: usize,
}

/// Runs one backup now. Fails when none is configured or one is already running.
pub async fn run(app: &App) -> anyhow::Result<Outcome> {
    let target = app.cfg.backup_target.as_ref().context("no backup target is configured (UNOMAIL_BACKUP_DIR or UNOMAIL_BACKUP_S3_BUCKET)")?;
    let target = Target::from_config(target)?;
    let Ok(_guard) = RUNNING.try_lock() else { anyhow::bail!("a backup is already running") };
    let started = now();
    let id = snapshot_id(started);
    let name = target.describe();
    let run_id: i64 = sqlx::query_scalar("INSERT INTO backup_runs (snapshot, target, started_at, status) VALUES (?, ?, ?, 'running') RETURNING id")
        .bind(&id)
        .bind(&name)
        .bind(started)
        .fetch_one(&app.db)
        .await?;
    let result = backup(app, &target, &id).await;
    let (status, detail, copied, bytes) = match &result {
        Ok(outcome) => ("ok", if outcome.blobs_missing > 0 { format!("{} message files were missing from the store", outcome.blobs_missing) } else { String::new() }, outcome.blobs_copied, outcome.bytes_copied),
        Err(err) => ("failed", format!("{err:#}"), 0, 0),
    };
    let _ = sqlx::query("UPDATE backup_runs SET finished_at = ?, status = ?, detail = ?, blobs_copied = ?, bytes_copied = ? WHERE id = ?")
        .bind(now())
        .bind(status)
        .bind(&detail)
        .bind(copied as i64)
        .bind(bytes as i64)
        .bind(run_id)
        .execute(&app.db)
        .await;
    let _ = sqlx::query("DELETE FROM backup_runs WHERE id NOT IN (SELECT id FROM backup_runs ORDER BY id DESC LIMIT 100)").execute(&app.db).await;
    match &result {
        Ok(outcome) => tracing::info!(snapshot = id, blobs = outcome.blobs_copied, target = name, "backup finished"),
        Err(err) => tracing::error!(error = %format!("{err:#}"), target = name, "backup failed"),
    }
    crate::db::audit(&app.db, "system", if result.is_ok() { "backup.completed" } else { "backup.failed" }, &id, "", &detail).await;
    result
}

async fn backup(app: &App, target: &Target, id: &str) -> anyhow::Result<Outcome> {
    let mut outcome = Outcome { snapshot: id.to_owned(), ..Outcome::default() };
    let name = target.describe();

    // 1. The database, consistent at one point in time.
    let tmp = app.cfg.data_dir.join(format!("backup-{id}.db.tmp"));
    let _ = tokio::fs::remove_file(&tmp).await;
    sqlx::query("VACUUM INTO ?").bind(tmp.to_string_lossy().into_owned()).execute(&app.db).await.context("database snapshot failed")?;
    let database = tokio::fs::read(&tmp).await;
    let _ = tokio::fs::remove_file(&tmp).await;
    let database = database?;
    let database_bytes = database.len();
    let compressed = tokio::task::spawn_blocking(move || gzip(&database)).await??;

    // 2. The blobs the snapshot refers to, copying only those not there yet.
    let hashes: Vec<String> = sqlx::query_scalar("SELECT hash FROM blobs ORDER BY hash").fetch_all(&app.db).await?;
    let copied: HashSet<String> = sqlx::query_scalar("SELECT hash FROM backup_blobs WHERE target = ?").bind(&name).fetch_all(&app.db).await?.into_iter().collect();
    let mut listed = Vec::with_capacity(hashes.len());
    for hash in hashes.into_iter().filter(|h| is_hash(h)) {
        if !copied.contains(&hash) {
            match app.store.blobs.get_stored(&hash).await {
                Ok(stored) => {
                    outcome.bytes_copied += stored.len() as u64;
                    target.put(&format!("blobs/{}", relative_path(&hash)), stored).await.with_context(|| format!("copying message {hash}"))?;
                    sqlx::query("INSERT OR IGNORE INTO backup_blobs (target, hash) VALUES (?, ?)").bind(&name).bind(&hash).execute(&app.db).await?;
                    outcome.blobs_copied += 1;
                }
                Err(crate::store::StoreError::NotFound) => {
                    outcome.blobs_missing += 1;
                    continue;
                }
                Err(err) => return Err(err.into()),
            }
        }
        listed.push(hash);
    }

    // With encryption at rest the database snapshot is sealed with the same key as the mail:
    // it holds subjects, addresses and the search index.
    let compressed = if app.store.blobs.encrypted() { app.store.blobs.seal(&format!("snapshot:{id}"), &compressed) } else { compressed };
    target.put(&format!("snapshots/{id}/unomail.db.gz"), compressed).await?;
    target.put(&format!("snapshots/{id}/blobs.txt.gz"), gzip(listed.join("\n").as_bytes())?).await?;
    let manifest = Manifest {
        id: id.to_owned(),
        created_at: now(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        hostname: app.cfg.hostname.clone(),
        blobs: listed.len(),
        database_bytes,
        encrypted_mail: app.store.blobs.encrypted(),
    };
    target.put(&format!("snapshots/{id}/manifest.json"), serde_json::to_vec_pretty(&manifest)?).await?;

    // 3. Old snapshots go, and the blobs no remaining snapshot needs.
    let snapshots = target.snapshots().await?;
    let excess = snapshots.len().saturating_sub(app.cfg.backup_keep);
    let (old, kept) = snapshots.split_at(excess);
    if !old.is_empty() {
        let mut needed: HashSet<String> = HashSet::new();
        for id in kept {
            needed.extend(target.blob_list(id).await?);
        }
        for id in old {
            for file in ["manifest.json", "blobs.txt.gz", "unomail.db.gz"] {
                target.delete(&format!("snapshots/{id}/{file}")).await?;
            }
            if let Target::Dir(dir) = target {
                let _ = tokio::fs::remove_dir(dir.join("snapshots").join(id)).await;
            }
            outcome.snapshots_removed += 1;
        }
        let stored: Vec<String> = sqlx::query_scalar("SELECT hash FROM backup_blobs WHERE target = ?").bind(&name).fetch_all(&app.db).await?;
        for hash in stored.into_iter().filter(|h| !needed.contains(h)) {
            target.delete(&format!("blobs/{}", relative_path(&hash))).await?;
            sqlx::query("DELETE FROM backup_blobs WHERE target = ? AND hash = ?").bind(&name).bind(&hash).execute(&app.db).await?;
            outcome.blobs_removed += 1;
        }
    }
    Ok(outcome)
}

/// Runs the daily backup at the configured hour. Checked every ten minutes.
pub async fn schedule(app: crate::app::AppState) {
    if app.cfg.backup_target.is_none() {
        return;
    }
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        let now = now();
        let hour = (now.rem_euclid(86_400) / 3600) as u32;
        if hour != app.cfg.backup_hour {
            continue;
        }
        let today = now - now.rem_euclid(86_400);
        let done: Option<i64> = sqlx::query_scalar("SELECT 1 FROM backup_runs WHERE started_at >= ? AND status IN ('ok', 'running') LIMIT 1").bind(today).fetch_optional(&app.db).await.ok().flatten();
        if done.is_none() {
            let _ = run(&app).await;
        }
    }
}

/// Restores a snapshot into the data directory. Run with the server stopped.
///
/// The database is written to `<data>/unomail.db` (an existing one is kept aside as
/// `unomail.db.before-restore-<time>` with `force`), and every blob it needs that the store
/// lacks is copied back.
pub async fn restore(cfg: &Config, snapshot: Option<&str>, force: bool) -> anyhow::Result<String> {
    let target = Target::from_config(cfg.backup_target.as_ref().context("no backup target is configured (UNOMAIL_BACKUP_DIR or UNOMAIL_BACKUP_S3_BUCKET)")?)?;
    let snapshots = target.snapshots().await?;
    let id = match snapshot {
        None | Some("latest") => snapshots.last().cloned().context("the backup target holds no complete snapshot")?,
        Some(id) if snapshots.iter().any(|s| s == id) => id.to_owned(),
        Some(id) => anyhow::bail!("no complete snapshot {id:?}; available: {}", snapshots.join(", ")),
    };
    let manifest = target.manifest(&id).await?.context("the snapshot has no manifest")?;
    if manifest.encrypted_mail && !cfg.data_dir.join("blob.key").exists() {
        anyhow::bail!("this backup holds encrypted mail: put its blob.key into {} first", cfg.data_dir.display());
    }
    std::fs::create_dir_all(&cfg.data_dir)?;
    let db_path = cfg.data_dir.join("unomail.db");
    if db_path.exists() {
        anyhow::ensure!(force, "{} exists; stop the server and pass --force to replace it", db_path.display());
        let aside = cfg.data_dir.join(format!("unomail.db.before-restore-{}", snapshot_id(now())));
        std::fs::rename(&db_path, &aside)?;
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(cfg.data_dir.join(format!("unomail.db{suffix}")));
        }
    }
    let database = target.get(&format!("snapshots/{id}/unomail.db.gz")).await?.context("the snapshot has no database")?;
    let blobs: Blobs = crate::app::blob_backend(cfg)?;
    let database = blobs.open(&format!("snapshot:{id}"), database).map_err(|e| anyhow::anyhow!("the database snapshot cannot be decrypted: {e}"))?;
    std::fs::write(&db_path, gunzip(&database)?)?;

    let mut restored = 0usize;
    for hash in target.blob_list(&id).await? {
        if blobs.exists(&hash).await? {
            continue;
        }
        let stored = target.get(&format!("blobs/{}", relative_path(&hash))).await?.with_context(|| format!("message {hash} is missing from the backup"))?;
        blobs.put_stored(&hash, stored).await?;
        restored += 1;
    }
    Ok(format!("restored snapshot {id} ({} messages, {restored} copied back)", manifest.blobs))
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Run {
    pub id: i64,
    pub snapshot: String,
    pub target: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub status: String,
    pub detail: String,
    pub blobs_copied: i64,
    pub bytes_copied: i64,
}

pub async fn runs(app: &App, limit: i64) -> sqlx::Result<Vec<Run>> {
    sqlx::query_as("SELECT * FROM backup_runs ORDER BY id DESC LIMIT ?").bind(limit).fetch_all(&app.db).await
}

/// Copies every blob into the configured store in the configured form: from `from` (an old
/// blob directory, when moving to S3) or from the store itself (sealing older plaintext
/// blobs once encryption is on). Returns how many were written.
pub async fn migrate_blobs(app: &App, from: Option<PathBuf>) -> anyhow::Result<usize> {
    let hashes: Vec<String> = sqlx::query_scalar("SELECT hash FROM blobs").fetch_all(&app.db).await?;
    let source = from.map(|dir| Blobs::new(crate::blobstore::Backend::Disk(dir), crate::blobstore::load_key(&app.cfg.data_dir).ok()).read_only_key());
    let store = &app.store.blobs;
    let mut written = 0;
    for hash in hashes.into_iter().filter(|h| is_hash(h)) {
        let current = store.get_stored(&hash).await.ok();
        let sealed = current.as_deref().is_some_and(|c| c.starts_with(b"UNOBLOB1"));
        if current.is_some() && sealed == store.encrypted() {
            continue;
        }
        let plain = match (&source, current) {
            (Some(source), None) => match source.get(&hash).await {
                Ok(plain) => plain,
                Err(crate::store::StoreError::NotFound) => continue,
                Err(err) => return Err(err.into()),
            },
            (_, Some(stored)) => store.open(&hash, stored)?,
            (None, None) => continue,
        };
        anyhow::ensure!(crate::util::sha256_hex(&plain) == hash, "message {hash} does not match its checksum");
        store.put_stored(&hash, store.seal(&hash, &plain)).await?;
        written += 1;
    }
    Ok(written)
}
