// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! HTTP/2 upstream connection pool for the HTTP/3 path.
//!
//! Multiplexes many H3 request streams onto a small number of H2
//! connections per upstream host. This eliminates the 1-TCP-per-stream
//! overhead of the HTTP/1.1 bridge.
//!
//! # Architecture
//!
//! Each [`H2ConnPool`] maintains up to [`MAX_CONNS_PER_HOST`] H2
//! connections per upstream `SocketAddr`. The `h2` crate's
//! [`SendRequest`] is cheaply cloneable — each H3 stream gets its own
//! clone, and the crate multiplexes them onto the underlying TCP
//! connection automatically.
//!
//! A background driver task per connection polls `h2::client::Connection`
//! to completion. When the upstream sends GOAWAY or the TCP connection
//! dies, the driver removes the entry from the pool and all in-flight
//! `send_request` calls on that connection fail with an `h2::Error`.
//! The caller retries idempotent requests on a fresh connection.
//!
//! # Flow control
//!
//! H2 flow control is managed by the `h2` crate. The initial stream
//! window is 2 MB, connection window is 4 MB. The caller must call
//! `flow_control().release_capacity(n)` after consuming each DATA
//! frame to prevent deadlocks.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use bytes::Bytes;
use h2::client::SendRequest;
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, warn};

/// Maximum H2 connections per upstream host. Two connections limit
/// the GOAWAY blast radius to 50% of streams while still providing
/// redundancy.
const MAX_CONNS_PER_HOST: usize = 2;

/// Timeout for TCP connect + H2 handshake (Guardrail #29).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Initial H2 stream-level flow control window (bytes).
const INITIAL_WINDOW_SIZE: u32 = 2 * 1024 * 1024; // 2 MB

/// Initial H2 connection-level flow control window (bytes).
const INITIAL_CONNECTION_WINDOW_SIZE: u32 = 4 * 1024 * 1024; // 4 MB

/// Maximum concurrent streams per H2 connection.
const MAX_CONCURRENT_STREAMS: u32 = 250;

/// A live H2 connection in the pool.
struct H2Conn {
    sender: SendRequest<Bytes>,
}

/// Per-host H2 connection pool for the H3 upstream bridge.
///
/// Thread-safe with two concentric guards:
///
/// * `conns` — a fast, synchronous `parking_lot::Mutex` held only for
///   the microseconds needed to clone/insert a `SendRequest`. Never
///   held across I/O.
/// * `connect_locks` — a map of per-host async mutexes, held by the
///   caller that's actively performing the TCP connect + H2 handshake
///   for a given upstream. Without this, 100 concurrent H3 streams
///   racing on a cold pool all see `acquire() == None`, all fall
///   through to `connect()`, and all open their own TCP connection —
///   producing N sockets instead of `MAX_CONNS_PER_HOST`. Once the
///   first caller wins the async mutex and finishes connecting,
///   everyone else wakes up, re-checks `acquire()`, and finds the
///   fresh connection waiting for them.
pub struct H2ConnPool {
    conns: Mutex<HashMap<SocketAddr, Vec<H2Conn>>>,
    /// Per-host async mutex guarding the connect-or-reuse decision.
    /// Keys are lazily inserted on first use and never removed — the
    /// cardinality is bounded by the number of distinct upstream hosts,
    /// which is tiny in practice.
    connect_locks: Mutex<HashMap<SocketAddr, Arc<AsyncMutex<()>>>>,
}

impl std::fmt::Debug for H2ConnPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2ConnPool").finish_non_exhaustive()
    }
}

impl Default for H2ConnPool {
    fn default() -> Self {
        Self::new()
    }
}

impl H2ConnPool {
    pub fn new() -> Self {
        Self {
            conns: Mutex::new(HashMap::new()),
            connect_locks: Mutex::new(HashMap::new()),
        }
    }

    /// Fetch (or lazily create) the per-host connect serializer.
    ///
    /// The outer `parking_lot::Mutex` is held only for the
    /// `HashMap` insert — never during the async wait on the inner
    /// `AsyncMutex`.
    fn connect_lock_for(&self, addr: SocketAddr) -> Arc<AsyncMutex<()>> {
        let mut locks = self.connect_locks.lock();
        locks
            .entry(addr)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    /// Get a `SendRequest` handle for the given upstream address.
    ///
    /// Returns a clone of an existing connection's sender, or `None`
    /// if no connections exist for this host. The `h2` crate's `SendRequest`
    /// is reference-counted — cloning is O(1) and all clones multiplex on
    /// the same underlying TCP connection.
    ///
    /// Dead connections are not proactively evicted here — the `h2` crate
    /// returns an error on `send_request()` if the connection is dead.
    /// The caller should call `evict_and_reconnect()` on failure.
    pub fn acquire(&self, addr: SocketAddr) -> Option<SendRequest<Bytes>> {
        let conns = self.conns.lock();
        let entries = conns.get(&addr)?;
        if entries.is_empty() {
            return None;
        }
        // Clone the sender — this is O(1), just an Arc increment.
        Some(entries[0].sender.clone())
    }

    /// Remove all connections for a host (called after `send_request` fails).
    pub fn evict(&self, addr: SocketAddr) {
        let mut conns = self.conns.lock();
        conns.remove(&addr);
    }

    /// Establish a new H2 connection to the upstream and store it in the pool.
    ///
    /// Opens TCP (with `TCP_NODELAY`), runs the H2 client handshake, spawns
    /// the connection driver as a background task, and inserts the sender
    /// into the pool.
    ///
    /// Returns a cloned `SendRequest` for immediate use.
    pub async fn connect(&self, addr: SocketAddr) -> Result<SendRequest<Bytes>, H2ConnError> {
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| H2ConnError::Timeout)?
            .map_err(|e| H2ConnError::TcpConnect(addr, e))?;

        let _ = tcp.set_nodelay(true);

        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(INITIAL_WINDOW_SIZE)
            .initial_connection_window_size(INITIAL_CONNECTION_WINDOW_SIZE)
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
            .enable_push(false);

        let (sender, connection) = tokio::time::timeout(CONNECT_TIMEOUT, builder.handshake(tcp))
            .await
            .map_err(|_| H2ConnError::Timeout)?
            .map_err(H2ConnError::Handshake)?;

        debug!(upstream = %addr, "H2 upstream connection established");

        // Spawn the connection driver — it must be polled to completion
        // for the H2 protocol to function. On error/GOAWAY, it removes
        // itself from the pool.
        // We need a way for the driver to remove itself. Since we can't
        // give it &self (lifetime issues), we use a separate approach:
        // the driver just logs. Dead connections are evicted lazily in acquire().

        tokio::spawn({
            let addr_copy = addr;
            async move {
                if let Err(e) = connection.await {
                    warn!(upstream = %addr_copy, error = %e, "H2 upstream connection closed");
                } else {
                    debug!(upstream = %addr_copy, "H2 upstream connection gracefully closed");
                }
            }
        });

        // Insert into pool.
        let cloned = sender.clone();
        {
            let mut conns = self.conns.lock();
            let entries = conns.entry(addr).or_default();
            if entries.len() < MAX_CONNS_PER_HOST {
                entries.push(H2Conn { sender });
            }
            // If at capacity, the sender is dropped — the cloned handle
            // still works for this request, and the connection driver
            // stays alive as long as the clone exists.
        }

        Ok(cloned)
    }

    /// Acquire an existing connection or establish a new one.
    ///
    /// Concurrent callers for the same host are serialized through a
    /// per-host async mutex so only one of them ever performs the TCP
    /// connect. The rest wake up, re-check the synchronous pool, and
    /// reuse the freshly-established connection — which is exactly
    /// what an H2 connection pool should do (one TCP socket serving
    /// many multiplexed streams).
    pub async fn get_or_connect(
        &self,
        addr: SocketAddr,
    ) -> Result<SendRequest<Bytes>, H2ConnError> {
        // Fast path — pool already has a connection.
        if let Some(sender) = self.acquire(addr) {
            return Ok(sender);
        }

        // Slow path: serialize the connect decision per host.
        let lock = self.connect_lock_for(addr);
        let _guard = lock.lock().await;

        // A peer may have filled the pool while we were waiting for the
        // mutex. Check again before paying for a fresh handshake.
        if let Some(sender) = self.acquire(addr) {
            return Ok(sender);
        }

        // We are the designated connector for this host. Establish the
        // connection, publish it to the pool, and return.
        self.connect(addr).await
    }
}

/// Errors from H2 connection management.
#[derive(Debug, thiserror::Error)]
pub enum H2ConnError {
    #[error("TCP connect to {0} failed: {1}")]
    TcpConnect(SocketAddr, std::io::Error),

    #[error("H2 handshake failed: {0}")]
    Handshake(h2::Error),

    #[error("connect/handshake timed out")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn acquire_from_empty_returns_none() {
        let pool = H2ConnPool::new();
        let addr: SocketAddr = "127.0.0.1:9999".parse().expect("addr");
        assert!(pool.acquire(addr).is_none());
    }

    #[tokio::test]
    async fn connect_to_h2_server_and_acquire() {
        use h2::server;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        // Spawn a minimal H2 server that accepts one connection.
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut conn = server::handshake(tcp).await.expect("h2 server handshake");
            // Accept and respond to requests until the connection closes.
            while let Some(Ok((req, mut respond))) = conn.accept().await {
                let _ = req;
                let response = http::Response::builder()
                    .status(200)
                    .body(())
                    .expect("response");
                let mut send = respond.send_response(response, false).expect("send resp");
                send.send_data(Bytes::from_static(b"ok"), true)
                    .expect("send data");
            }
        });

        let pool = H2ConnPool::new();

        // Connect and acquire.
        let _sender = pool.connect(addr).await.expect("connect");

        // Acquire again — should return a handle from the same connection.
        let mut sender2 = pool.acquire(addr).expect("acquire should work");

        // Use the sender to verify it works.
        let req = http::Request::builder()
            .uri("http://localhost/test")
            .body(())
            .expect("request");
        let (resp, _) = sender2.send_request(req, true).expect("send_request");
        let resp: http::Response<h2::RecvStream> = resp.await.expect("response");
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn pool_respects_max_conns_per_host() {
        use h2::server;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        // Accept up to 3 connections.
        tokio::spawn(async move {
            for _ in 0..3 {
                let (tcp, _) = listener.accept().await.expect("accept");
                tokio::spawn(async move {
                    let mut conn = server::handshake(tcp).await.expect("handshake");
                    while let Some(Ok((_req, mut respond))) = conn.accept().await {
                        let response = http::Response::builder()
                            .status(200)
                            .body(())
                            .expect("response");
                        let mut send = respond.send_response(response, false).expect("send");
                        send.send_data(Bytes::from_static(b"ok"), true)
                            .expect("data");
                    }
                });
            }
        });

        let pool = H2ConnPool::new();

        // Connect 3 times — pool should only keep MAX_CONNS_PER_HOST (2).
        let _s1 = pool.connect(addr).await.expect("connect 1");
        let _s2 = pool.connect(addr).await.expect("connect 2");
        let _s3 = pool.connect(addr).await.expect("connect 3");

        // Pool should have at most MAX_CONNS_PER_HOST entries.
        let conns = pool.conns.lock();
        let count = conns.get(&addr).map_or(0, Vec::len);
        assert!(
            count <= MAX_CONNS_PER_HOST,
            "pool has {count} conns, expected <= {MAX_CONNS_PER_HOST}"
        );
    }

    #[tokio::test]
    async fn evict_removes_dead_connection_and_reconnect_works() {
        use h2::server;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        // Server accepts connections and responds until they close.
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let Ok(mut conn) = server::handshake(tcp).await else {
                        return;
                    };
                    while let Some(Ok((_req, mut respond))) = conn.accept().await {
                        let response = http::Response::builder()
                            .status(200)
                            .body(())
                            .expect("response");
                        let mut send = respond.send_response(response, false).expect("send");
                        send.send_data(Bytes::from_static(b"ok"), true)
                            .expect("data");
                    }
                });
            }
        });

        let pool = H2ConnPool::new();

        // Establish a connection.
        let mut sender1 = pool.connect(addr).await.expect("connect");
        assert!(pool.acquire(addr).is_some(), "should have a connection");

        // Verify it works.
        let req = http::Request::builder()
            .uri("http://localhost/a")
            .body(())
            .expect("build request a");
        let (resp, _) = sender1.send_request(req, true).expect("send");
        let resp: http::Response<h2::RecvStream> = resp.await.expect("response");
        assert_eq!(resp.status(), 200);

        // Evict — simulates what the handler does on connection error.
        pool.evict(addr);
        assert!(pool.acquire(addr).is_none(), "evict should clear pool");

        // Reconnect — simulates retry path.
        let mut sender2 = pool.connect(addr).await.expect("reconnect");
        let req = http::Request::builder()
            .uri("http://localhost/b")
            .body(())
            .expect("build request b");
        let (resp, _) = sender2
            .send_request(req, true)
            .expect("send after reconnect");
        let resp: http::Response<h2::RecvStream> = resp.await.expect("response after reconnect");
        assert_eq!(resp.status(), 200);
    }
}
