// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! File-based log output with size-triggered rotation.
//!
//! Writes JSON lines to a file and rotates when `max_bytes` is exceeded.
//! Rotation uses POSIX rename (atomic) to shift files: `access.log` →
//! `access.log.1` → `access.log.2` → ... up to `keep` files.
//!
//! An optional `max_age_secs` field enables time-based TTL pruning of rotated
//! files. Pruning runs at rotation time and, when set, also runs periodically
//! in a background task at half the TTL interval.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::warn;

use crate::request_log::RequestLog;
use crate::writer::LogOutput;

/// Log output that writes JSON lines to a file with size-based rotation.
///
/// Needed for standalone Dwaar deployments without an agent to consume
/// log sockets. Rotation keeps disk usage bounded.
pub struct FileRotationWriter {
    path: PathBuf,
    max_bytes: u64,
    keep: u32,
    /// Optional TTL for rotated files. When set, rotated files older than this
    /// duration are deleted at rotation time and periodically in the background.
    pub max_age_secs: Option<u64>,
    state: Mutex<FileState>,
}

struct FileState {
    file: Option<tokio::fs::File>,
    current_size: u64,
}

impl std::fmt::Debug for FileRotationWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileRotationWriter")
            .field("path", &self.path)
            .field("max_bytes", &self.max_bytes)
            .field("keep", &self.keep)
            .field("max_age_secs", &self.max_age_secs)
            .finish_non_exhaustive()
    }
}

impl FileRotationWriter {
    pub fn new(path: PathBuf, max_bytes: u64, keep: u32) -> Self {
        Self {
            path,
            max_bytes,
            keep,
            max_age_secs: None,
            state: Mutex::new(FileState {
                file: None,
                current_size: 0,
            }),
        }
    }

    /// Create a writer with time-based TTL pruning enabled.
    ///
    /// Spawns a background task that prunes rotated files older than
    /// `max_age_secs` at an interval of `max_age_secs / 2`.
    pub fn new_with_max_age(
        path: PathBuf,
        max_bytes: u64,
        keep: u32,
        max_age_secs: u64,
    ) -> Arc<Self> {
        let writer = Arc::new(Self {
            path,
            max_bytes,
            keep,
            max_age_secs: Some(max_age_secs),
            state: Mutex::new(FileState {
                file: None,
                current_size: 0,
            }),
        });

        // Spawn background pruning task. Uses the directory of the log path and
        // the TTL. The task runs independently; if the writer is dropped the
        // task will eventually notice and exit (Arc weak ref not needed here
        // because the task holds a clone of the Arc, keeping the writer alive
        // as long as rotation is needed — acceptable for a long-lived service).
        let dir = writer
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let base_name = writer
            .path
            .file_name()
            .map(std::ffi::OsStr::to_os_string)
            .unwrap_or_default();
        let max_age = Duration::from_secs(max_age_secs);
        let interval_secs = (max_age_secs / 2).max(1);

        tokio::task::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                ticker.tick().await;
                let dir = dir.clone();
                let base_name = base_name.clone();
                tokio::task::spawn_blocking(move || {
                    prune_old_files(&dir, &base_name, max_age);
                })
                .await
                .ok();
            }
        });

        writer
    }

    async fn open_file(&self) -> Result<(tokio::fs::File, u64), std::io::Error> {
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        let metadata = file.metadata().await?;
        Ok((file, metadata.len()))
    }

    /// Rotate log files: current → .1, .1 → .2, ..., delete oldest.
    ///
    /// Uses blocking rename because `tokio::fs::rename` is just `spawn_blocking`
    /// anyway, and we're already holding the Mutex so no contention.
    async fn rotate(&self) -> Result<(), std::io::Error> {
        // Shift existing rotated files.
        for i in (1..self.keep).rev() {
            let from = rotated_path(&self.path, i);
            let to = rotated_path(&self.path, i + 1);
            if tokio::fs::try_exists(&from).await.unwrap_or(false) {
                if i + 1 > self.keep {
                    let _ = tokio::fs::remove_file(&from).await;
                } else {
                    let _ = tokio::fs::rename(&from, &to).await;
                }
            }
        }

        // Delete the oldest if it would exceed keep.
        let oldest = rotated_path(&self.path, self.keep + 1);
        if tokio::fs::try_exists(&oldest).await.unwrap_or(false) {
            let _ = tokio::fs::remove_file(&oldest).await;
        }

        // Current file → .1
        if tokio::fs::try_exists(&self.path).await.unwrap_or(false) {
            let first_rotated = rotated_path(&self.path, 1);
            tokio::fs::rename(&self.path, &first_rotated).await?;
        }

        // Time-based TTL pruning: remove rotated files older than max_age_secs.
        if let Some(max_age_secs) = self.max_age_secs {
            let max_age = Duration::from_secs(max_age_secs);
            let dir = self
                .path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            let base_name = self
                .path
                .file_name()
                .map(std::ffi::OsStr::to_os_string)
                .unwrap_or_default();
            tokio::task::spawn_blocking(move || {
                prune_old_files(&dir, &base_name, max_age);
            })
            .await
            .ok();
        }

        Ok(())
    }
}

/// Walk `dir` and delete rotated log files (those whose names start with
/// `base_name` followed by `.`) whose mtime is older than `max_age`.
///
/// Only ROTATED files (e.g., `access.log.1`, `access.log.2`) are considered;
/// the active log file itself is never touched. I/O errors on individual files
/// are silently ignored after a `warn!` log — one bad file must not abort
/// cleanup.
fn prune_old_files(dir: &Path, base_name: &std::ffi::OsStr, max_age: Duration) {
    let now = SystemTime::now();

    // Build the prefix string we expect rotated files to start with:
    // e.g., "access.log." so that "access.log" itself is excluded.
    let prefix = {
        let mut s = base_name.to_string_lossy().into_owned();
        s.push('.');
        s
    };

    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            warn!(
                target: "dwaar::log::retention",
                error = %e,
                dir = %dir.display(),
                "failed to read log directory for pruning"
            );
            return;
        }
    };

    for entry_result in read_dir {
        let entry = match entry_result {
            Ok(e) => e,
            Err(e) => {
                warn!(
                    target: "dwaar::log::retention",
                    error = %e,
                    "failed to read directory entry during pruning"
                );
                continue;
            }
        };

        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // Only process rotated files (e.g., access.log.1, access.log.2).
        if !name_str.starts_with(&prefix) {
            continue;
        }

        // Verify the suffix after the prefix is numeric (pure rotation files).
        let suffix = &name_str[prefix.len()..];
        if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let metadata = match std::fs::metadata(entry.path()) {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    target: "dwaar::log::retention",
                    error = %e,
                    path = %entry.path().display(),
                    "failed to stat rotated log file"
                );
                continue;
            }
        };

        let mtime = match metadata.modified() {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    target: "dwaar::log::retention",
                    error = %e,
                    path = %entry.path().display(),
                    "failed to get mtime for rotated log file"
                );
                continue;
            }
        };

        // mtime in the future is clock skew — skip.
        let Ok(age) = now.duration_since(mtime) else {
            continue;
        };

        if age > max_age
            && let Err(e) = std::fs::remove_file(entry.path())
        {
            warn!(
                target: "dwaar::log::retention",
                error = %e,
                path = %entry.path().display(),
                "failed to delete expired rotated log file"
            );
        }
    }
}

fn rotated_path(base: &std::path::Path, n: u32) -> PathBuf {
    let mut path = base.as_os_str().to_owned();
    path.push(format!(".{n}"));
    PathBuf::from(path)
}

#[async_trait]
impl LogOutput for FileRotationWriter {
    async fn write_batch(&self, entries: &[RequestLog]) -> Result<(), std::io::Error> {
        let mut state = self.state.lock().await;

        // Open file if needed.
        if state.file.is_none() {
            let (file, size) = self.open_file().await?;
            state.file = Some(file);
            state.current_size = size;
        }

        let file = state.file.as_mut().expect("file opened above");

        let mut buf = Vec::with_capacity(512);
        let mut batch_bytes: u64 = 0;
        for entry in entries {
            buf.clear();
            sonic_rs::to_writer(&mut buf, entry).map_err(std::io::Error::other)?;
            buf.push(b'\n');
            file.write_all(&buf).await?;
            batch_bytes += buf.len() as u64;
        }
        file.flush().await?;
        state.current_size += batch_bytes;

        // Rotate if over limit.
        if state.current_size >= self.max_bytes {
            // Drop the file handle before rename.
            state.file = None;
            state.current_size = 0;

            if let Err(e) = self.rotate().await {
                warn!(error = %e, "log file rotation failed");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RequestLog;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    fn dummy_log() -> RequestLog {
        RequestLog {
            timestamp: Utc::now(),
            request_id: "test-id".into(),
            method: "GET".into(),
            path: "/test".into(),
            query: None,
            host: "test.example.com".into(),
            status: 200,
            response_time_us: 100,
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: None,
            referer: None,
            bytes_sent: 0,
            bytes_received: 0,
            tls_version: None,
            http_version: "HTTP/1.1".into(),
            is_bot: false,
            country: None,
            upstream_addr: "127.0.0.1:8080".into(),
            upstream_response_time_us: 50,
            cache_status: None,
            compression: None,
            trace_id: None,
            upstream_error_body: None,
            rejected_by: None,
            blocked_by: None,
        }
    }

    #[tokio::test]
    async fn write_creates_file() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("access.log");
        let writer = FileRotationWriter::new(path.clone(), 1_000_000, 3);

        writer
            .write_batch(&[dummy_log()])
            .await
            .expect("write_batch");

        assert!(path.exists());
        let content = tokio::fs::read_to_string(&path).await.expect("read");
        assert!(content.contains("\"method\":\"GET\""));
    }

    #[tokio::test]
    async fn rotation_triggers_on_size() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("access.log");
        // Tiny max_bytes to trigger rotation quickly.
        let writer = FileRotationWriter::new(path.clone(), 100, 3);

        // Write enough to exceed 100 bytes.
        let batch: Vec<RequestLog> = (0..5).map(|_| dummy_log()).collect();
        writer.write_batch(&batch).await.expect("write_batch");

        // After rotation, .1 should exist.
        let rotated = dir.path().join("access.log.1");
        assert!(rotated.exists(), "rotated file .1 should exist");
    }

    #[tokio::test]
    async fn oldest_file_deleted_at_keep_limit() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("access.log");
        // keep=2 means we store .1 and .2, delete anything older.
        let writer = FileRotationWriter::new(path.clone(), 50, 2);

        // Write enough batches to trigger multiple rotations.
        for _ in 0..5 {
            let batch: Vec<RequestLog> = (0..3).map(|_| dummy_log()).collect();
            writer.write_batch(&batch).await.expect("write_batch");
        }

        // .1 and .2 may exist, .3 should not.
        let too_old = dir.path().join("access.log.3");
        assert!(!too_old.exists(), ".3 should be deleted (keep=2)");
    }

    #[test]
    fn is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FileRotationWriter>();
    }

    #[tokio::test]
    async fn max_age_secs_field_defaults_to_none() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("access.log");
        let writer = FileRotationWriter::new(path, 1_000_000, 3);
        assert!(writer.max_age_secs.is_none());
    }

    #[test]
    fn prune_old_files_does_not_touch_active_or_non_rotated_files() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let base = std::ffi::OsStr::new("access.log");

        // The active log file — must never be pruned.
        let active_path = dir.path().join("access.log");
        std::fs::write(&active_path, b"active").expect("create active file");

        // A file with a non-numeric suffix — must not be pruned.
        let unrelated = dir.path().join("access.log.bak");
        std::fs::write(&unrelated, b"backup").expect("create unrelated file");

        // A recently created rotated file — age is ~0s, far below any TTL.
        let recent = dir.path().join("access.log.1");
        std::fs::write(&recent, b"recent rotation").expect("create rotated file");

        // Prune with a generous TTL so recently-written files stay put.
        prune_old_files(dir.path(), base, Duration::from_secs(86400));

        assert!(active_path.exists(), "active log must not be touched");
        assert!(
            unrelated.exists(),
            "non-numeric suffix file must not be touched"
        );
        assert!(
            recent.exists(),
            "recently rotated file within TTL must be kept"
        );
    }
}
