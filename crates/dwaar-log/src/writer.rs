// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Batch log writer with bounded async channel.
//!
//! Producers (`logging()` callback) push [`RequestLog`] entries via a
//! non-blocking [`LogSender`]. A background task drains the channel in
//! batches, flushing when the batch hits [`BATCH_SIZE`] or the
//! [`FLUSH_INTERVAL`] timer fires — whichever comes first.
//!
//! The channel is bounded at [`CHANNEL_CAPACITY`] entries. When full,
//! entries are dropped with a warning — proxy latency always wins over
//! logging completeness.

use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::RequestLog;

/// Channel capacity — bounds memory growth under load.
const CHANNEL_CAPACITY: usize = 8192;

/// Flush when this many entries are buffered.
const BATCH_SIZE: usize = 200;

/// Flush after this much time even if batch isn't full.
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);

/// Trait for log output destinations.
#[async_trait]
pub trait LogOutput: Send + Sync {
    async fn write_batch(&self, entries: &[RequestLog]) -> Result<(), std::io::Error>;
}

/// Writes JSON Lines to stdout — one JSON object per line.
#[derive(Debug)]
pub struct StdoutWriter;

#[async_trait]
impl LogOutput for StdoutWriter {
    async fn write_batch(&self, entries: &[RequestLog]) -> Result<(), std::io::Error> {
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        // sonic-rs serializes into a Vec<u8> buffer (SIMD-accelerated, 2.5-3x
        // faster than serde_json). Buffer is allocated once and reused per entry.
        let mut buf = Vec::with_capacity(512);
        for entry in entries {
            buf.clear();
            sonic_rs::to_writer(&mut buf, entry).map_err(std::io::Error::other)?;
            handle.write_all(&buf)?;
            handle.write_all(b"\n")?;
        }
        handle.flush()?;
        Ok(())
    }
}

/// Handle for sending log entries to the batch writer.
///
/// Cheap to clone — multiple proxy threads share the same channel.
#[derive(Debug, Clone)]
pub struct LogSender {
    tx: mpsc::Sender<RequestLog>,
}

impl LogSender {
    /// Send a log entry. Non-blocking — drops the entry if the channel is full.
    pub fn send(&self, entry: RequestLog) {
        if self.tx.try_send(entry).is_err() {
            warn!("log channel full, dropping entry");
        }
    }
}

/// Create a log writer channel pair.
///
/// Returns `(LogSender, LogReceiver)`. Pass the sender to proxy threads
/// and feed the receiver into [`spawn_writer`].
pub fn channel() -> (LogSender, LogReceiver) {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    (LogSender { tx }, LogReceiver { rx })
}

/// Receiving end of the log channel. Consumed by [`spawn_writer`].
#[derive(Debug)]
pub struct LogReceiver {
    rx: mpsc::Receiver<RequestLog>,
}

/// Spawn the batch writer as a background tokio task.
///
/// Requires an active tokio runtime. For use inside Pingora's runtime,
/// use [`run_writer`] directly from a `BackgroundService` instead.
pub fn spawn_writer(
    receiver: LogReceiver,
    output: Box<dyn LogOutput>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_writer(receiver, output).await;
    })
}

/// Run the batch writer loop. Drains the channel in batches of up to
/// [`BATCH_SIZE`] entries, flushing every [`FLUSH_INTERVAL`] or when
/// the batch is full.
///
/// This is the async entry point — call it from a `BackgroundService`
/// or use [`spawn_writer`] if a tokio runtime is already active.
pub async fn run_writer(receiver: LogReceiver, output: Box<dyn LogOutput>) {
    run_writer_inner(receiver.rx, output).await;
}

async fn run_writer_inner(mut rx: mpsc::Receiver<RequestLog>, output: Box<dyn LogOutput>) {
    let mut batch = Vec::with_capacity(BATCH_SIZE);
    let mut flush_timer = tokio::time::interval(FLUSH_INTERVAL);
    // First tick completes immediately — skip it so the timer starts fresh.
    flush_timer.tick().await;

    loop {
        tokio::select! {
            entry = rx.recv() => {
                if let Some(log) = entry {
                    batch.push(log);
                    if batch.len() >= BATCH_SIZE {
                        flush(&*output, &mut batch).await;
                    }
                } else {
                    // Channel closed — flush remaining entries and exit.
                    if !batch.is_empty() {
                        flush(&*output, &mut batch).await;
                    }
                    debug!("log writer shutting down");
                    return;
                }
            }
            _ = flush_timer.tick() => {
                if !batch.is_empty() {
                    flush(&*output, &mut batch).await;
                }
            }
        }
    }
}

async fn flush(output: &dyn LogOutput, batch: &mut Vec<RequestLog>) {
    debug!(count = batch.len(), "flushing log batch");
    if let Err(e) = output.write_batch(batch).await {
        warn!(error = %e, count = batch.len(), "failed to write log batch");
    }
    batch.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

    use chrono::Utc;

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
        }
    }

    /// Test output that collects batches for assertions.
    #[derive(Debug)]
    struct CollectingOutput {
        batches: Arc<Mutex<Vec<Vec<RequestLog>>>>,
    }

    impl CollectingOutput {
        fn new() -> (Self, Arc<Mutex<Vec<Vec<RequestLog>>>>) {
            let batches = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    batches: Arc::clone(&batches),
                },
                batches,
            )
        }
    }

    #[async_trait]
    impl LogOutput for CollectingOutput {
        async fn write_batch(&self, entries: &[RequestLog]) -> Result<(), std::io::Error> {
            self.batches
                .lock()
                .expect("lock poisoned")
                .push(entries.to_vec());
            Ok(())
        }
    }

    #[tokio::test]
    async fn batch_flushes_at_capacity() {
        let (output, batches) = CollectingOutput::new();
        let (sender, receiver) = channel();
        let handle = spawn_writer(receiver, Box::new(output));

        for _ in 0..200 {
            sender.send(dummy_log());
        }

        // Give the writer time to drain.
        tokio::time::sleep(Duration::from_millis(100)).await;

        {
            let b = batches.lock().expect("lock poisoned");
            assert!(!b.is_empty(), "should have flushed at least once");
            assert_eq!(b[0].len(), 200, "first batch should be 200 entries");
        }

        drop(sender);
        handle.await.expect("writer task panicked");
    }

    #[tokio::test]
    async fn timer_flushes_partial_batch() {
        let (output, batches) = CollectingOutput::new();
        let (sender, receiver) = channel();
        let handle = spawn_writer(receiver, Box::new(output));

        for _ in 0..5 {
            sender.send(dummy_log());
        }

        // Wait for the 500ms flush timer to fire.
        tokio::time::sleep(Duration::from_millis(700)).await;

        {
            let b = batches.lock().expect("lock poisoned");
            assert!(!b.is_empty(), "timer should have triggered flush");
            let total: usize = b.iter().map(Vec::len).sum();
            assert_eq!(total, 5, "all 5 entries should be flushed");
        }

        drop(sender);
        handle.await.expect("writer task panicked");
    }

    #[tokio::test]
    async fn channel_close_flushes_remaining() {
        let (output, batches) = CollectingOutput::new();
        let (sender, receiver) = channel();
        let handle = spawn_writer(receiver, Box::new(output));

        sender.send(dummy_log());
        sender.send(dummy_log());

        drop(sender);
        handle.await.expect("writer task panicked");

        let b = batches.lock().expect("lock poisoned");
        let total: usize = b.iter().map(Vec::len).sum();
        assert_eq!(total, 2, "remaining entries should be flushed on close");
    }

    #[tokio::test]
    async fn try_send_drops_when_full() {
        // Tiny channel to test backpressure behavior.
        let (tx, _rx) = mpsc::channel(2);
        let sender = LogSender { tx };

        sender.send(dummy_log()); // ok
        sender.send(dummy_log()); // ok (channel now full)
        sender.send(dummy_log()); // dropped with warning — no panic, no block
    }
}
