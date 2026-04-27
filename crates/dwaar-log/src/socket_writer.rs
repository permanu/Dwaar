// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Unix domain socket log output.
//!
//! Writes JSON lines to a `SOCK_STREAM` UDS. Buffers up to 1000 lines
//! during socket outages and flushes them on reconnect. Oldest lines are
//! dropped on overflow — proxy latency always wins over log completeness.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tracing::warn;

use crate::request_log::RequestLog;
use crate::writer::LogOutput;

const MAX_BUFFER_LINES: usize = 1000;
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Log output that writes JSON lines to a Unix domain socket.
///
/// The Permanu agent listens on this socket to ingest structured logs.
/// More reliable than parsing stdout and decouples log transport from
/// the proxy process's terminal.
pub struct UnixSocketWriter {
    path: PathBuf,
    // Serialises concurrent writes and owns the live connection.
    // tokio::sync::Mutex is appropriate: it is held across the socket
    // write awaits so we need an async-aware lock here.
    stream: Mutex<Option<UnixStream>>,
    // Only held for brief in-memory queue mutations — never across awaits.
    // parking_lot would work too, but we keep tokio::sync here for
    // consistency and to avoid mixing runtimes.
    buffer: Mutex<VecDeque<Vec<u8>>>,
    last_connect_attempt: Mutex<Option<tokio::time::Instant>>,
}

impl std::fmt::Debug for UnixSocketWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnixSocketWriter")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl UnixSocketWriter {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            stream: Mutex::new(None),
            buffer: Mutex::new(VecDeque::new()),
            last_connect_attempt: Mutex::new(None),
        }
    }

    /// Try to establish a connection, respecting the reconnect backoff.
    async fn try_connect(&self) -> Option<UnixStream> {
        let mut last = self.last_connect_attempt.lock().await;
        if let Some(t) = *last
            && t.elapsed() < RECONNECT_DELAY
        {
            return None;
        }
        *last = Some(tokio::time::Instant::now());
        drop(last);

        match UnixStream::connect(&self.path).await {
            Ok(stream) => Some(stream),
            Err(e) => {
                warn!(path = %self.path.display(), error = %e, "log socket connect failed");
                None
            }
        }
    }

    fn serialize_entry(entry: &RequestLog) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = Vec::with_capacity(512);
        sonic_rs::to_writer(&mut buf, entry).map_err(std::io::Error::other)?;
        buf.push(b'\n');
        Ok(buf)
    }

    /// Write a single line to the stream, returning `false` on error.
    async fn write_line(stream: &mut UnixStream, line: &[u8]) -> bool {
        stream.write_all(line).await.is_ok()
    }

    /// Drain `pending` into the stream. Returns entries that could not be
    /// written (because the connection was lost mid-flush) so the caller
    /// can re-enqueue them.
    async fn flush_pending(stream: &mut UnixStream, pending: &mut VecDeque<Vec<u8>>) -> bool {
        while let Some(line) = pending.front() {
            if Self::write_line(stream, line).await {
                pending.pop_front();
            } else {
                return false;
            }
        }
        true
    }

    /// Buffer a serialized line, dropping the oldest if at capacity.
    fn enqueue(buffer: &mut VecDeque<Vec<u8>>, line: Vec<u8>) {
        if buffer.len() >= MAX_BUFFER_LINES {
            buffer.pop_front();
        }
        buffer.push_back(line);
    }
}

#[async_trait]
impl LogOutput for UnixSocketWriter {
    async fn write_batch(&self, entries: &[RequestLog]) -> Result<(), std::io::Error> {
        // Serialize upfront — pure CPU work, no lock needed yet.
        let mut new_lines: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
        for entry in entries {
            match Self::serialize_entry(entry) {
                Ok(line) => new_lines.push(line),
                Err(e) => warn!(error = %e, "failed to serialize log entry"),
            }
        }

        // Drain the existing buffer under a brief lock, then release it
        // before touching the socket. Holding the buffer lock across network
        // I/O would force concurrent write_batch callers to wait for socket
        // writes to complete before they can even enqueue. (#160)
        let mut pending: VecDeque<Vec<u8>> = {
            let mut buf = self.buffer.lock().await;
            std::mem::take(&mut *buf)
        }; // buffer lock dropped here

        // Acquire the stream lock. This is intentionally held for the full
        // write sequence: it serialises writers and guards connection state.
        let mut stream_guard = self.stream.lock().await;

        // Try to establish connection if we don't have one.
        if stream_guard.is_none()
            && let Some(new_stream) = self.try_connect().await
        {
            *stream_guard = Some(new_stream);
        }

        if let Some(ref mut stream) = *stream_guard {
            // Flush previously buffered lines first so ordering is preserved.
            if !Self::flush_pending(stream, &mut pending).await {
                // Socket write failed mid-flush — re-enqueue the remainder
                // plus new lines, then disconnect.
                let mut buf = self.buffer.lock().await;
                for line in pending {
                    Self::enqueue(&mut buf, line);
                }
                for line in new_lines {
                    Self::enqueue(&mut buf, line);
                }
                *stream_guard = None;
                return Ok(());
            }

            // Write new lines.
            let mut failed_at: Option<usize> = None;
            for (i, line) in new_lines.iter().enumerate() {
                if !Self::write_line(stream, line).await {
                    failed_at = Some(i);
                    break;
                }
            }

            if let Some(i) = failed_at {
                // Connection lost mid-batch — buffer remaining new lines and disconnect.
                let mut buf = self.buffer.lock().await;
                for line in new_lines.into_iter().skip(i) {
                    Self::enqueue(&mut buf, line);
                }
                *stream_guard = None;
            }
        } else {
            // No connection — buffer everything (pending was already drained
            // from the persistent buffer, so merge it back with new lines).
            let mut buf = self.buffer.lock().await;
            for line in pending {
                Self::enqueue(&mut buf, line);
            }
            for line in new_lines {
                Self::enqueue(&mut buf, line);
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
    use tokio::io::AsyncBufReadExt;
    use tokio::net::UnixListener;

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
    async fn write_to_socket_receiver_gets_json() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let sock_path = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind");
        let writer = UnixSocketWriter::new(sock_path);

        let accept_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let reader = tokio::io::BufReader::new(stream);
            let mut lines = reader.lines();
            lines.next_line().await.expect("read").expect("got line")
        });

        // Small delay for listener to be ready.
        tokio::time::sleep(Duration::from_millis(50)).await;

        writer
            .write_batch(&[dummy_log()])
            .await
            .expect("write_batch");

        let line = accept_handle.await.expect("task");
        let parsed: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
        assert_eq!(parsed["method"], "GET");
        assert_eq!(parsed["host"], "test.example.com");
    }

    #[tokio::test]
    async fn socket_down_buffers_lines() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let sock_path = dir.path().join("noexist.sock");
        let writer = UnixSocketWriter::new(sock_path);

        writer
            .write_batch(&[dummy_log(), dummy_log()])
            .await
            .expect("write_batch");

        let buffer = writer.buffer.lock().await;
        assert_eq!(buffer.len(), 2);
    }

    #[tokio::test]
    async fn buffer_overflow_drops_oldest() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let sock_path = dir.path().join("overflow.sock");
        let writer = UnixSocketWriter::new(sock_path);

        // Fill buffer beyond capacity.
        let batch: Vec<RequestLog> = (0..MAX_BUFFER_LINES + 50).map(|_| dummy_log()).collect();
        writer.write_batch(&batch).await.expect("write_batch");

        let buffer = writer.buffer.lock().await;
        assert_eq!(buffer.len(), MAX_BUFFER_LINES);
    }

    /// Verify that the buffer lock is not held across socket I/O.
    ///
    /// Two concurrent `write_batch` calls are issued against a live socket.
    /// If the buffer lock were held across the socket write awaits, the
    /// second call would stall until the first completes its network I/O.
    /// On a loopback UDS this is imperceptible, so instead we assert the
    /// structural property: both tasks complete and all lines reach the
    /// receiver. A contention test that truly exercises the parallelism
    /// would require a slow-write shim; this test documents the invariant
    /// and catches regressions that break serialization. (#160)
    #[tokio::test]
    async fn buffer_lock_released_before_socket_await() {
        use std::sync::Arc;
        use tokio::io::AsyncBufReadExt;

        let dir = tempfile::tempdir().expect("create temp dir");
        let sock_path = dir.path().join("concurrent.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind");

        let writer = Arc::new(UnixSocketWriter::new(sock_path));

        // Collect all lines the receiver sees.
        let recv_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let reader = tokio::io::BufReader::new(stream);
            let mut lines_iter = reader.lines();
            let mut count = 0usize;
            while let Ok(Some(_)) = lines_iter.next_line().await {
                count += 1;
                if count == 2 {
                    break;
                }
            }
            count
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let w1 = Arc::clone(&writer);
        let w2 = Arc::clone(&writer);

        let t1 = tokio::spawn(async move { w1.write_batch(&[dummy_log()]).await });
        let t2 = tokio::spawn(async move { w2.write_batch(&[dummy_log()]).await });

        t1.await.expect("task1").expect("write1");
        t2.await.expect("task2").expect("write2");

        let received = recv_handle.await.expect("recv");
        assert_eq!(received, 2, "both lines must reach the receiver");
    }

    #[test]
    fn is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<UnixSocketWriter>();
    }
}
