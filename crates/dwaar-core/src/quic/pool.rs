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

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

/// Default maximum pooled connections per upstream host.
const DEFAULT_MAX_PER_HOST: usize = 10;

/// Default idle timeout — connections unused longer than this are discarded.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// A connection sitting in the pool waiting to be reused.
struct PooledConn {
    stream: TcpStream,
    idle_since: Instant,
}

/// Per-host TCP connection pool for the H3 upstream bridge.
///
/// Thread-safe — the inner `Mutex` is held only for the brief push/pop
/// of the `VecDeque`, never during I/O. The lock duration is microseconds
/// at most, so contention is negligible even under high concurrency.
pub struct UpstreamConnPool {
    pools: Mutex<HashMap<SocketAddr, VecDeque<PooledConn>>>,
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
    pub fn take(&self, addr: SocketAddr) -> Option<TcpStream> {
        let mut pools = self.pools.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let deque = pools.get_mut(&addr)?;
        let now = Instant::now();

        // Pop from the back (most recently returned) and discard expired.
        while let Some(entry) = deque.pop_back() {
            if now.duration_since(entry.idle_since) < self.idle_timeout {
                // Clean up empty deques to prevent unbounded key growth.
                if deque.is_empty() {
                    pools.remove(&addr);
                }
                return Some(entry.stream);
            }
            // Expired — drop and try the next one.
        }

        // All entries expired.
        pools.remove(&addr);
        None
    }

    /// Return a connection to the pool for reuse.
    ///
    /// If the pool for this host is already at `max_per_host`, the connection
    /// is silently dropped instead of stored.
    pub fn put(&self, addr: SocketAddr, stream: TcpStream) {
        let mut pools = self.pools.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let deque = pools.entry(addr).or_default();

        if deque.len() >= self.max_per_host {
            return; // at capacity — let the stream drop
        }

        deque.push_back(PooledConn {
            stream,
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
    async fn put_then_take_returns_stream() {
        let pool = UpstreamConnPool::default();
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let (client, _server) = connected_pair().await;

        let peer = client.local_addr().expect("local_addr");
        pool.put(addr, client);

        let taken = pool.take(addr).expect("should get a connection back");
        assert_eq!(taken.local_addr().expect("local_addr"), peer);
    }

    #[tokio::test]
    async fn pool_respects_max_per_host() {
        let pool = UpstreamConnPool::new(2, DEFAULT_IDLE_TIMEOUT);
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");

        // Put 3 connections — only 2 should be kept.
        for _ in 0..3 {
            let (client, _server) = connected_pair().await;
            pool.put(addr, client);
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

        pool.put(addr, client);
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(pool.take(addr).is_none(), "should be expired");
    }

    #[tokio::test]
    async fn fresh_connections_survive_expiry_check() {
        let pool = UpstreamConnPool::new(10, Duration::from_secs(60));
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let (client, _server) = connected_pair().await;

        pool.put(addr, client);
        assert!(pool.take(addr).is_some(), "should still be fresh");
    }
}
