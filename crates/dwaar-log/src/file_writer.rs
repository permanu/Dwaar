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

use std::path::PathBuf;

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
            .finish_non_exhaustive()
    }
}

impl FileRotationWriter {
    pub fn new(path: PathBuf, max_bytes: u64, keep: u32) -> Self {
        Self {
            path,
            max_bytes,
            keep,
            state: Mutex::new(FileState {
                file: None,
                current_size: 0,
            }),
        }
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

        Ok(())
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
}
