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
    stream: Mutex<Option<UnixStream>>,
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

    /// Drain buffered lines into the stream. Stops on first write error.
    async fn flush_buffer(stream: &mut UnixStream, buffer: &mut VecDeque<Vec<u8>>) {
        while let Some(line) = buffer.front() {
            if Self::write_line(stream, line).await {
                buffer.pop_front();
            } else {
                break;
            }
        }
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
        let mut stream_guard = self.stream.lock().await;
        let mut buffer_guard = self.buffer.lock().await;

        // Try to establish connection if we don't have one.
        if stream_guard.is_none()
            && let Some(new_stream) = self.try_connect().await
        {
            *stream_guard = Some(new_stream);
        }

        // Serialize all entries upfront so we can buffer on failure.
        let mut lines: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
        for entry in entries {
            match Self::serialize_entry(entry) {
                Ok(line) => lines.push(line),
                Err(e) => warn!(error = %e, "failed to serialize log entry"),
            }
        }

        if let Some(ref mut stream) = *stream_guard {
            // Flush previously buffered lines first.
            Self::flush_buffer(stream, &mut buffer_guard).await;

            // Write new lines.
            for line in lines {
                if !Self::write_line(stream, &line).await {
                    // Connection lost — buffer remaining lines and disconnect.
                    Self::enqueue(&mut buffer_guard, line);
                    *stream_guard = None;
                    break;
                }
            }
        } else {
            // No connection — buffer everything.
            for line in lines {
                Self::enqueue(&mut buffer_guard, line);
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

    #[test]
    fn is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<UnixSocketWriter>();
    }
}
