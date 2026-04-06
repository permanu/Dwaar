// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Per-host upstream TCP connection pool for the HTTP/3 path.
//!
//! Reuses TCP connections to upstream servers across h3 requests, avoiding
//! the overhead of a fresh TCP connect + handshake per request. Connections
//! are keyed by `SocketAddr`, bounded per-host, and expired after an idle
//! timeout.
//!
//! # Buffer ownership
//!
//! Each pooled connection owns a [`BytesMut`] read buffer that persists
//! across requests. This mirrors Pingora's `BufStream` design — buffers
//! live with the connection, not the request, eliminating per-request
//! allocation in the streaming hot path.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Default maximum pooled connections per upstream host.
const DEFAULT_MAX_PER_HOST: usize = 10;

/// Default idle timeout — connections unused longer than this are discarded.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Initial read buffer capacity — matches nginx's `proxy_buffer_size`.
/// Grows on demand up to [`MAX_READ_BUF`] for large response chunks.
const INIT_READ_BUF: usize = 8 * 1024; // 8 KB

/// Target ceiling for the read buffer. Reservations stop growing beyond
/// this size, but `BytesMut` may exceed it transiently during reads.
/// Matches Pingora's `BUF_READ_SIZE` (64 KB). This is a reservation
/// guide, not a hard security boundary — Guardrail #28's response body
/// limit (100 MB) is the hard cap.
const MAX_READ_BUF: usize = 64 * 1024; // 64 KB

/// Maximum chunked accumulator size — bounds the `raw` Vec used during
/// chunked transfer-encoding decoding. RFC 9112 places no limit on
/// individual chunk sizes, so this must be large enough for realistic
/// chunked responses. 1 MB is generous for any single chunk while still
/// protecting against adversarial unbounded growth.
pub const MAX_CHUNKED_ACCUMULATOR: usize = 1024 * 1024; // 1 MB

/// A pooled upstream connection with its own read buffer.
///
/// The buffer is allocated once when the connection is first created and
/// reused across all requests served by this connection. When returned to
/// the pool, the buffer is cleared (O(1) — just resets the length) but
/// retains its capacity for the next request.
///
/// # Zero-copy path
///
/// [`read_into_buf`] appends directly into the `BytesMut`. [`take_bytes`]
/// calls `split_to().freeze()`, which shares the underlying allocation via
/// atomic reference counting — no memcpy.
pub struct BufferedConn {
    pub stream: TcpStream,
    pub(crate) read_buf: BytesMut,
}

impl BufferedConn {
    /// Wrap a fresh TCP connection with an initial read buffer.
    ///
    /// Enables `TCP_NODELAY` to avoid Nagle-delayed writes on the
    /// upstream connection — small request headers and chunked-encoding
    /// framing must be sent immediately, not coalesced.
    pub fn new(stream: TcpStream) -> Self {
        let _ = stream.set_nodelay(true);
        Self {
            stream,
            read_buf: BytesMut::with_capacity(INIT_READ_BUF),
        }
    }

    /// Read from upstream into the connection's own buffer.
    ///
    /// `BytesMut::read_buf` appends to the end of the buffer without
    /// moving existing data. Returns the number of new bytes (0 = EOF).
    ///
    /// Reserves space in increments of [`INIT_READ_BUF`], stopping once
    /// capacity reaches [`MAX_READ_BUF`]. The buffer may transiently
    /// exceed `MAX_READ_BUF` due to `BytesMut` internals — this is a
    /// reservation guide, not a hard limit.
    pub async fn read_into_buf(&mut self) -> std::io::Result<usize> {
        if self.read_buf.capacity() - self.read_buf.len() < 1024 {
            // Reserve more space, but don't exceed MAX_READ_BUF total capacity
            let additional =
                INIT_READ_BUF.min(MAX_READ_BUF.saturating_sub(self.read_buf.capacity()));
            if additional > 0 {
                self.read_buf.reserve(additional);
            }
        }
        self.stream.read_buf(&mut self.read_buf).await
    }

    /// Take the first `n` bytes from the buffer as frozen [`Bytes`].
    ///
    /// This is zero-copy: `split_to().freeze()` shares the underlying
    /// allocation via atomic reference counting.
    #[inline]
    pub fn take_bytes(&mut self, n: usize) -> Bytes {
        self.read_buf.split_to(n).freeze()
    }

    /// Take all buffered bytes as frozen [`Bytes`].
    #[inline]
    pub fn take_all(&mut self) -> Bytes {
        self.read_buf.split().freeze()
    }

    /// Number of unread bytes currently in the buffer.
    #[inline]
    pub fn buffered(&self) -> usize {
        self.read_buf.len()
    }

    /// Prepare for next request — clear contents, keep capacity.
    ///
    /// The buffer legitimately grows up to [`MAX_READ_BUF`] (64 KB)
    /// during normal streaming. Only shrink if something pushed it
    /// beyond that — e.g. a direct `reserve()` from outside the
    /// normal read path.
    pub fn reset_for_reuse(&mut self) {
        self.read_buf.clear();
        if self.read_buf.capacity() > MAX_READ_BUF {
            self.read_buf = BytesMut::with_capacity(INIT_READ_BUF);
        }
    }
}

impl std::fmt::Debug for BufferedConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferedConn")
            .field("peer", &self.stream.peer_addr().ok())
            .field("buf_len", &self.read_buf.len())
            .field("buf_cap", &self.read_buf.capacity())
            .finish()
    }
}

/// A connection sitting in the pool waiting to be reused.
struct PoolEntry {
    conn: BufferedConn,
    idle_since: Instant,
}

/// Per-host TCP connection pool for the H3 upstream bridge.
///
/// Thread-safe — the inner `Mutex` is held only for the brief push/pop
/// of the `VecDeque`, never during I/O. The lock duration is microseconds
/// at most, so contention is negligible even under high concurrency.
pub struct UpstreamConnPool {
    pools: Mutex<HashMap<SocketAddr, VecDeque<PoolEntry>>>,
    max_per_host: usize,
    idle_timeout: Duration,
}

impl std::fmt::Debug for UpstreamConnPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamConnPool")
            .field("max_per_host", &self.max_per_host)
            .field("idle_timeout", &self.idle_timeout)
            .finish_non_exhaustive()
    }
}

impl Default for UpstreamConnPool {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_PER_HOST, DEFAULT_IDLE_TIMEOUT)
    }
}

impl UpstreamConnPool {
    /// Create a pool with custom bounds.
    pub fn new(max_per_host: usize, idle_timeout: Duration) -> Self {
        Self {
            pools: Mutex::new(HashMap::new()),
            max_per_host,
            idle_timeout,
        }
    }

    /// Take a connection from the pool for `addr`, if one is available.
    ///
    /// Expired connections are silently discarded. Returns `None` when the
    /// pool is empty or all connections have expired.
    pub fn take(&self, addr: SocketAddr) -> Option<BufferedConn> {
        let mut pools = self
            .pools
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let deque = pools.get_mut(&addr)?;
        let now = Instant::now();

        // Pop from the back (most recently returned) and discard expired.
        while let Some(entry) = deque.pop_back() {
            if now.duration_since(entry.idle_since) < self.idle_timeout {
                // Clean up empty deques to prevent unbounded key growth.
                if deque.is_empty() {
                    pools.remove(&addr);
                }
                return Some(entry.conn);
            }
            // Expired — drop and try the next one.
        }

        // All entries expired.
        pools.remove(&addr);
        None
    }

    /// Return a connection to the pool for reuse.
    ///
    /// Calls [`BufferedConn::reset_for_reuse`] to clear the read buffer
    /// (retaining capacity) before storing. If the pool for this host is
    /// already at `max_per_host`, the connection is silently dropped.
    pub fn put(&self, addr: SocketAddr, mut conn: BufferedConn) {
        conn.reset_for_reuse();

        let mut pools = self
            .pools
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let deque = pools.entry(addr).or_default();

        if deque.len() >= self.max_per_host {
            return; // at capacity — let the conn drop
        }

        deque.push_back(PoolEntry {
            conn,
            idle_since: Instant::now(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a connected pair of TcpStreams for testing.
    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(addr).await.expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        (client, server)
    }

    #[tokio::test]
    async fn take_from_empty_returns_none() {
        let pool = UpstreamConnPool::default();
        let addr: SocketAddr = "127.0.0.1:9999".parse().expect("addr");
        assert!(pool.take(addr).is_none());
    }

    #[tokio::test]
    async fn put_then_take_returns_conn_with_buffer() {
        let pool = UpstreamConnPool::default();
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let (client, _server) = connected_pair().await;

        let peer = client.local_addr().expect("local_addr");
        let conn = BufferedConn::new(client);
        pool.put(addr, conn);

        let taken = pool.take(addr).expect("should get a connection back");
        assert_eq!(taken.stream.local_addr().expect("local_addr"), peer);
        // Buffer should be cleared but have capacity from init
        assert_eq!(taken.read_buf.len(), 0);
        assert!(taken.read_buf.capacity() >= INIT_READ_BUF);
    }

    #[tokio::test]
    async fn pool_respects_max_per_host() {
        let pool = UpstreamConnPool::new(2, DEFAULT_IDLE_TIMEOUT);
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");

        // Put 3 connections — only 2 should be kept.
        for _ in 0..3 {
            let (client, _server) = connected_pair().await;
            pool.put(addr, BufferedConn::new(client));
        }

        assert!(pool.take(addr).is_some());
        assert!(pool.take(addr).is_some());
        assert!(pool.take(addr).is_none(), "third should have been dropped");
    }

    #[tokio::test]
    async fn expired_connections_are_discarded() {
        let pool = UpstreamConnPool::new(10, Duration::from_millis(50));
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let (client, _server) = connected_pair().await;

        pool.put(addr, BufferedConn::new(client));
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(pool.take(addr).is_none(), "should be expired");
    }

    #[tokio::test]
    async fn fresh_connections_survive_expiry_check() {
        let pool = UpstreamConnPool::new(10, Duration::from_secs(60));
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let (client, _server) = connected_pair().await;

        pool.put(addr, BufferedConn::new(client));
        assert!(pool.take(addr).is_some(), "should still be fresh");
    }

    #[tokio::test]
    async fn reset_shrinks_inflated_buffer() {
        let (client, _server) = connected_pair().await;
        let mut conn = BufferedConn::new(client);

        // Simulate inflation well beyond MAX_READ_BUF
        conn.read_buf.reserve(MAX_READ_BUF * 4);
        assert!(conn.read_buf.capacity() > MAX_READ_BUF);

        conn.reset_for_reuse();
        // Should have shrunk back to INIT_READ_BUF
        assert!(conn.read_buf.capacity() <= MAX_READ_BUF);
    }

    #[tokio::test]
    async fn reset_preserves_normal_growth() {
        let (client, _server) = connected_pair().await;
        let mut conn = BufferedConn::new(client);

        // Grow to MAX_READ_BUF — this is normal operational growth
        conn.read_buf.reserve(MAX_READ_BUF);
        let cap_before = conn.read_buf.capacity();

        conn.reset_for_reuse();
        // Should NOT shrink — capacity within MAX_READ_BUF is normal
        assert_eq!(
            conn.read_buf.capacity(),
            cap_before,
            "normal-range buffer should not be reallocated on reset"
        );
    }

    #[tokio::test]
    async fn read_into_buf_and_take_bytes() {
        let (client, mut server) = connected_pair().await;
        let mut conn = BufferedConn::new(client);

        // Write some data from the server side
        use tokio::io::AsyncWriteExt;
        server.write_all(b"hello world").await.expect("write");

        // Read into conn's buffer
        let n = conn.read_into_buf().await.expect("read");
        assert_eq!(n, 11);
        assert_eq!(conn.buffered(), 11);

        // Take bytes — zero-copy
        let bytes = conn.take_bytes(5);
        assert_eq!(&bytes[..], b"hello");
        assert_eq!(conn.buffered(), 6); // " world" remains

        let rest = conn.take_all();
        assert_eq!(&rest[..], b" world");
        assert_eq!(conn.buffered(), 0);
    }
}
