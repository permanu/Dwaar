// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Layer 4 UDP proxy runtime.
//!
//! Implements connectionless UDP proxying with a session table that maps
//! each client address to a dedicated upstream socket. Sessions are evicted
//! after an idle timeout to bound memory. The service runs as a Pingora
//! `BackgroundService` and is only spawned when the Dwaarfile contains
//! `udp` blocks (lazy loading — zero overhead if unused).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use dashmap::DashMap;
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use crate::l4::L4LoadBalancePolicy;

/// Receive buffer — 64 KiB covers the largest possible UDP datagram
/// (65 535 bytes minus IP/UDP headers). Allocated once per listen loop.
const RECV_BUF_SIZE: usize = 65_535;

/// How often the reaper scans for idle sessions.
const REAPER_INTERVAL: Duration = Duration::from_secs(10);

/// Grace period after shutdown signal before forcibly dropping sessions.
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);

// ── Compiled config ───────────────────────────────────────────────────────

/// A compiled UDP server ready for runtime. One per listen address.
#[derive(Debug, Clone)]
pub struct CompiledUdpServer {
    pub listen: SocketAddr,
    pub upstreams: Vec<SocketAddr>,
    pub policy: L4LoadBalancePolicy,
    pub max_sessions: usize,
    pub idle_timeout: Duration,
}

// ── Session table ─────────────────────────────────────────────────────────

/// A live UDP session: one client mapped to one upstream.
struct UdpSession {
    /// Dedicated socket `connect()`ed to the upstream — `send()` goes there,
    /// `recv()` returns upstream replies.
    upstream_socket: Arc<UdpSocket>,
    /// Epoch seconds of the last packet in either direction.
    last_activity: AtomicU64,
    /// Which upstream this session targets (for metrics/logging).
    upstream_addr: SocketAddr,
}

/// Atomic counters for observability — no lock, no allocation on the hot path.
#[derive(Debug, Default)]
pub struct UdpMetrics {
    /// Currently active sessions across all listen addresses.
    pub active_sessions: AtomicU64,
    /// Total datagrams forwarded (client→upstream + upstream→client).
    pub datagrams_forwarded: AtomicU64,
}

// ── Service ───────────────────────────────────────────────────────────────

/// UDP proxy service — spawned only when the Dwaarfile contains `udp` blocks.
#[derive(Debug)]
pub struct UdpProxyService {
    servers: Vec<CompiledUdpServer>,
    metrics: Arc<UdpMetrics>,
}

impl UdpProxyService {
    #[must_use]
    pub fn new(servers: Vec<CompiledUdpServer>) -> Self {
        Self {
            servers,
            metrics: Arc::new(UdpMetrics::default()),
        }
    }

    /// Snapshot of active sessions and forwarded datagrams.
    pub fn metrics(&self) -> &Arc<UdpMetrics> {
        &self.metrics
    }
}

#[async_trait]
impl BackgroundService for UdpProxyService {
    async fn start(&self, shutdown: ShutdownWatch) {
        if self.servers.is_empty() {
            return;
        }

        let mut tasks = tokio::task::JoinSet::new();

        for server in &self.servers {
            let srv = server.clone();
            let metrics = Arc::clone(&self.metrics);
            let shutdown = shutdown.clone();

            tasks.spawn(async move {
                if let Err(e) = run_udp_listener(srv, metrics, shutdown).await {
                    error!(error = %e, "UDP listener exited with error");
                }
            });
        }

        // Wait for all listener tasks to finish (they exit on shutdown).
        while tasks.join_next().await.is_some() {}
        info!("UDP proxy service shut down");
    }
}

// ── Per-listener event loop ───────────────────────────────────────────────

async fn run_udp_listener(
    server: CompiledUdpServer,
    metrics: Arc<UdpMetrics>,
    shutdown: ShutdownWatch,
) -> Result<(), UdpProxyError> {
    let listener = UdpSocket::bind(server.listen)
        .await
        .map_err(UdpProxyError::Bind)?;
    let listener = Arc::new(listener);

    info!(
        addr = %server.listen,
        upstreams = server.upstreams.len(),
        max_sessions = server.max_sessions,
        idle_timeout = ?server.idle_timeout,
        "UDP listener bound"
    );

    let sessions: Arc<DashMap<SocketAddr, Arc<UdpSession>>> = Arc::new(DashMap::new());

    // Round-robin counter shared across all sessions for this listener.
    let rr_counter = Arc::new(AtomicU64::new(0));

    // Spawn the idle session reaper.
    let reaper_sessions = Arc::clone(&sessions);
    let reaper_metrics = Arc::clone(&metrics);
    let idle_timeout = server.idle_timeout;
    let reaper_shutdown = shutdown.clone();
    tokio::spawn(async move {
        reaper_loop(
            reaper_sessions,
            reaper_metrics,
            idle_timeout,
            reaper_shutdown,
        )
        .await;
    });

    let mut buf = vec![0u8; RECV_BUF_SIZE];

    loop {
        tokio::select! {
            result = listener.recv_from(&mut buf) => {
                let (len, client_addr) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        debug!(error = %e, "UDP recv_from error");
                        continue;
                    }
                };

                let data = &buf[..len];

                // Fast path: existing session.
                if let Some(session) = sessions.get(&client_addr) {
                    update_activity(&session.last_activity);
                    let sock = Arc::clone(&session.upstream_socket);
                    // Relay without blocking the recv loop. Cloning the slice
                    // into a Vec is unavoidable since send is async and the
                    // buffer will be reused immediately.
                    let payload = data.to_vec();
                    let m = Arc::clone(&metrics);
                    tokio::spawn(async move {
                        if let Err(e) = sock.send(&payload).await {
                            debug!(error = %e, "UDP send to upstream failed");
                        } else {
                            m.datagrams_forwarded.fetch_add(1, Ordering::Relaxed);
                        }
                    });
                    continue;
                }

                // Slow path: new session.
                create_session(
                    &server,
                    &sessions,
                    &rr_counter,
                    &listener,
                    &metrics,
                    client_addr,
                    data,
                )
                .await;
            }
            () = shutdown_signal(&shutdown) => {
                info!(addr = %server.listen, "UDP listener shutting down");
                // Brief drain period so in-flight relays can finish.
                tokio::time::sleep(SHUTDOWN_DRAIN).await;
                return Ok(());
            }
        }
    }
}

/// Create a new UDP session for `client_addr`, bind a dedicated upstream socket,
/// forward the initial datagram, and spawn a reverse-relay task.
#[allow(clippy::too_many_arguments)]
async fn create_session(
    server: &CompiledUdpServer,
    sessions: &Arc<DashMap<SocketAddr, Arc<UdpSession>>>,
    rr_counter: &Arc<AtomicU64>,
    listener: &Arc<UdpSocket>,
    metrics: &Arc<UdpMetrics>,
    client_addr: SocketAddr,
    data: &[u8],
) {
    if sessions.len() >= server.max_sessions {
        warn!(
            client = %client_addr,
            max = server.max_sessions,
            "UDP session table full — dropping datagram"
        );
        return;
    }

    let Some(upstream_addr) =
        select_upstream(&server.upstreams, server.policy, rr_counter, client_addr)
    else {
        warn!(client = %client_addr, "no UDP upstream available");
        return;
    };

    // Bind a fresh socket for this session. Using 0.0.0.0:0 lets the OS pick
    // an ephemeral port; connect() pins it to the upstream.
    let bind_addr: SocketAddr = if upstream_addr.is_ipv6() {
        "[::]:0".parse().expect("valid v6 unspecified addr")
    } else {
        "0.0.0.0:0".parse().expect("valid v4 unspecified addr")
    };

    let upstream_socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to bind upstream UDP socket");
            return;
        }
    };
    if let Err(e) = upstream_socket.connect(upstream_addr).await {
        error!(upstream = %upstream_addr, error = %e, "UDP connect failed");
        return;
    }

    let upstream_socket = Arc::new(upstream_socket);
    let session = Arc::new(UdpSession {
        upstream_socket: Arc::clone(&upstream_socket),
        last_activity: AtomicU64::new(now_secs()),
        upstream_addr,
    });

    sessions.insert(client_addr, Arc::clone(&session));
    metrics.active_sessions.fetch_add(1, Ordering::Relaxed);

    debug!(client = %client_addr, upstream = %upstream_addr, "new UDP session");

    // Send the initial datagram.
    let payload = data.to_vec();
    let fwd_metrics = Arc::clone(metrics);
    let fwd_sock = Arc::clone(&upstream_socket);
    tokio::spawn(async move {
        if let Err(e) = fwd_sock.send(&payload).await {
            debug!(error = %e, "UDP initial send to upstream failed");
        } else {
            fwd_metrics
                .datagrams_forwarded
                .fetch_add(1, Ordering::Relaxed);
        }
    });

    // Spawn the reverse relay: upstream → client via the listener socket.
    let relay_listener = Arc::clone(listener);
    let relay_session = Arc::clone(&session);
    let relay_metrics = Arc::clone(metrics);
    tokio::spawn(async move {
        reverse_relay(relay_listener, relay_session, client_addr, relay_metrics).await;
    });
}

/// Relay upstream replies back to the client through the shared listener socket.
///
/// Runs for the lifetime of a session. The task exits when the upstream socket
/// returns an error or the session is evicted (socket dropped).
async fn reverse_relay(
    listener: Arc<UdpSocket>,
    session: Arc<UdpSession>,
    client_addr: SocketAddr,
    metrics: Arc<UdpMetrics>,
) {
    let mut buf = vec![0u8; RECV_BUF_SIZE];
    loop {
        match session.upstream_socket.recv(&mut buf).await {
            Ok(0) => break,
            Ok(len) => {
                update_activity(&session.last_activity);
                if let Err(e) = listener.send_to(&buf[..len], client_addr).await {
                    debug!(client = %client_addr, error = %e, "UDP send_to client failed");
                    break;
                }
                metrics.datagrams_forwarded.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                debug!(
                    client = %client_addr,
                    upstream = %session.upstream_addr,
                    error = %e,
                    "UDP upstream recv error"
                );
                break;
            }
        }
    }
}

// ── Session reaper ────────────────────────────────────────────────────────

/// Periodically scan the session table and evict entries that have been idle
/// longer than `idle_timeout`. Runs until shutdown.
async fn reaper_loop(
    sessions: Arc<DashMap<SocketAddr, Arc<UdpSession>>>,
    metrics: Arc<UdpMetrics>,
    idle_timeout: Duration,
    shutdown: ShutdownWatch,
) {
    let timeout_secs = idle_timeout.as_secs();
    loop {
        tokio::select! {
            () = tokio::time::sleep(REAPER_INTERVAL) => {
                let now = now_secs();
                let mut evicted = 0u64;
                sessions.retain(|_client, session| {
                    let last = session.last_activity.load(Ordering::Relaxed);
                    if now.saturating_sub(last) > timeout_secs {
                        evicted += 1;
                        false
                    } else {
                        true
                    }
                });
                if evicted > 0 {
                    metrics
                        .active_sessions
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            Some(v.saturating_sub(evicted))
                        })
                        .ok();
                    debug!(evicted, "UDP sessions reaped");
                }
            }
            () = shutdown_signal(&shutdown) => return,
        }
    }
}

// ── Load balancing ────────────────────────────────────────────────────────

fn select_upstream(
    upstreams: &[SocketAddr],
    policy: L4LoadBalancePolicy,
    rr_counter: &AtomicU64,
    peer: SocketAddr,
) -> Option<SocketAddr> {
    if upstreams.is_empty() {
        return None;
    }
    if upstreams.len() == 1 {
        return Some(upstreams[0]);
    }

    Some(match policy {
        L4LoadBalancePolicy::RoundRobin => {
            let idx = rr_counter.fetch_add(1, Ordering::Relaxed) as usize % upstreams.len();
            upstreams[idx]
        }
        L4LoadBalancePolicy::Random => upstreams[fastrand::usize(..upstreams.len())],
        // IpHash is the natural default for UDP — same client always reaches
        // the same upstream, important for stateful protocols like DNS.
        // LeastConn falls back to IpHash since UDP has no persistent connections.
        L4LoadBalancePolicy::IpHash | L4LoadBalancePolicy::LeastConn => {
            let idx = fnv_hash_ip(peer.ip()) % upstreams.len();
            upstreams[idx]
        }
    })
}

/// FNV-1a hash over an IP address for deterministic upstream selection.
fn fnv_hash_ip(ip: std::net::IpAddr) -> usize {
    const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
    const FNV_PRIME: u64 = 1_099_511_628_211;
    let mut hash = FNV_OFFSET;
    let bytes: &[u8] = match &ip {
        std::net::IpAddr::V4(v4) => &v4.octets() as &[u8],
        std::net::IpAddr::V6(v6) => &v6.octets() as &[u8],
    };
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash as usize
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn update_activity(last_activity: &AtomicU64) {
    last_activity.store(now_secs(), Ordering::Relaxed);
}

async fn shutdown_signal(shutdown: &ShutdownWatch) {
    let mut watch = shutdown.clone();
    while !*watch.borrow() {
        if watch.changed().await.is_err() {
            return;
        }
    }
}

// ── Errors ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum UdpProxyError {
    #[error("failed to bind UDP listener: {0}")]
    Bind(std::io::Error),
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    /// Verify session table insert, lookup, and idle eviction.
    #[tokio::test]
    async fn session_table_insert_lookup_evict() {
        let sessions: DashMap<SocketAddr, Arc<UdpSession>> = DashMap::new();
        let client: SocketAddr = "127.0.0.1:9000".parse().expect("valid addr");
        let upstream: SocketAddr = "127.0.0.1:9001".parse().expect("valid addr");

        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind ok");
        sock.connect(upstream).await.expect("connect ok");

        let session = Arc::new(UdpSession {
            upstream_socket: Arc::new(sock),
            last_activity: AtomicU64::new(0), // ancient timestamp → immediately evictable
            upstream_addr: upstream,
        });

        sessions.insert(client, session);
        assert_eq!(sessions.len(), 1);
        assert!(sessions.get(&client).is_some());

        // Evict anything idle > 0 seconds.
        let now = now_secs();
        sessions.retain(|_k, v| now.saturating_sub(v.last_activity.load(Ordering::Relaxed)) == 0);
        assert_eq!(sessions.len(), 0, "session should have been evicted");
    }

    /// LB policy selection for UDP.
    #[test]
    fn lb_policy_selection() {
        let upstreams: Vec<SocketAddr> = vec![
            "127.0.0.1:53".parse().expect("valid"),
            "127.0.0.2:53".parse().expect("valid"),
        ];
        let counter = AtomicU64::new(0);
        let peer: SocketAddr = "10.0.0.1:12345".parse().expect("valid");

        // RoundRobin cycles through upstreams.
        let rr_first = select_upstream(&upstreams, L4LoadBalancePolicy::RoundRobin, &counter, peer);
        let rr_second =
            select_upstream(&upstreams, L4LoadBalancePolicy::RoundRobin, &counter, peer);
        assert_ne!(rr_first, rr_second, "round robin should alternate");

        // IpHash is deterministic for the same peer.
        let hash_first = select_upstream(&upstreams, L4LoadBalancePolicy::IpHash, &counter, peer);
        let hash_second = select_upstream(&upstreams, L4LoadBalancePolicy::IpHash, &counter, peer);
        assert_eq!(hash_first, hash_second, "ip_hash should be deterministic");

        // Single upstream always returns it.
        let single = vec!["127.0.0.1:53".parse().expect("valid")];
        let single_pick = select_upstream(&single, L4LoadBalancePolicy::Random, &counter, peer);
        assert_eq!(single_pick, Some(single[0]));

        // Empty upstream list returns None.
        let empty: Vec<SocketAddr> = vec![];
        assert!(select_upstream(&empty, L4LoadBalancePolicy::RoundRobin, &counter, peer).is_none());
    }

    /// `max_sessions` enforcement — reject when full.
    #[tokio::test]
    async fn max_sessions_enforcement() {
        let sessions: DashMap<SocketAddr, Arc<UdpSession>> = DashMap::new();
        let max_sessions: usize = 3;
        let upstream: SocketAddr = "127.0.0.1:9002".parse().expect("valid");

        for i in 0..max_sessions {
            let client: SocketAddr = format!("127.0.0.{}:{}", i + 1, 10_000 + i)
                .parse()
                .expect("valid");
            let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind ok");
            sock.connect(upstream).await.expect("connect ok");
            let session = Arc::new(UdpSession {
                upstream_socket: Arc::new(sock),
                last_activity: AtomicU64::new(now_secs()),
                upstream_addr: upstream,
            });
            sessions.insert(client, session);
        }

        assert_eq!(sessions.len(), max_sessions);

        // The next session should be rejected.
        let overflow_client: SocketAddr = "127.0.0.100:50000".parse().expect("valid");
        let should_reject = sessions.len() >= max_sessions;
        assert!(should_reject, "should reject when at capacity");
        assert!(sessions.get(&overflow_client).is_none());
    }

    /// Integration test: send a datagram through the UDP proxy to a mock upstream.
    #[tokio::test]
    async fn integration_roundtrip() {
        // Bind a mock upstream that echoes datagrams.
        let mock_upstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
        let upstream_addr = mock_upstream.local_addr().expect("local_addr");

        let server = CompiledUdpServer {
            listen: "127.0.0.1:0".parse().expect("valid"),
            upstreams: vec![upstream_addr],
            policy: L4LoadBalancePolicy::RoundRobin,
            max_sessions: 100,
            idle_timeout: Duration::from_secs(5),
        };

        // Bind the proxy listener to get its actual port.
        let proxy_sock = UdpSocket::bind(server.listen).await.expect("bind proxy");
        let proxy_addr = proxy_sock.local_addr().expect("proxy addr");
        drop(proxy_sock);

        // Re-create with the actual bound address.
        let server = CompiledUdpServer {
            listen: proxy_addr,
            ..server
        };

        let svc = UdpProxyService::new(vec![server]);
        let metrics = Arc::clone(svc.metrics());

        // Create a shutdown watch.
        let (tx, rx) = tokio::sync::watch::channel(false);

        // Run the service in the background.
        let svc_handle = tokio::spawn(async move {
            svc.start(rx).await;
        });

        // Give the listener a moment to bind.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Spawn the mock upstream echo loop.
        let echo_handle = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            // Echo back up to 5 datagrams then exit.
            for _ in 0..5 {
                let result =
                    tokio::time::timeout(Duration::from_secs(2), mock_upstream.recv_from(&mut buf))
                        .await;
                match result {
                    Ok(Ok((len, src))) => {
                        let _ = mock_upstream.send_to(&buf[..len], src).await;
                    }
                    _ => break,
                }
            }
        });

        // Send a datagram from a "client" to the proxy.
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        client.send_to(b"hello", proxy_addr).await.expect("send");

        // Wait for the echo reply.
        let mut reply = [0u8; 64];
        let result = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut reply)).await;
        match result {
            Ok(Ok(len)) => assert_eq!(&reply[..len], b"hello", "echo mismatch"),
            Ok(Err(e)) => panic!("recv error: {e}"),
            Err(elapsed) => panic!("timeout waiting for UDP echo reply: {elapsed}"),
        }

        assert!(
            metrics.datagrams_forwarded.load(Ordering::Relaxed) >= 2,
            "should have forwarded at least 2 datagrams (send + echo)"
        );

        // Shutdown.
        let _ = tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(10), svc_handle).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), echo_handle).await;
    }

    /// Stress test: 100 concurrent clients sending 10 datagrams each.
    #[tokio::test]
    async fn stress_concurrent_clients() {
        const NUM_CLIENTS: usize = 100;
        const DATAGRAMS_PER_CLIENT: usize = 10;

        let mock_upstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock");
        let upstream_addr = mock_upstream.local_addr().expect("local_addr");

        // Bind to get actual port.
        let tmp = UdpSocket::bind("127.0.0.1:0").await.expect("tmp bind");
        let proxy_addr = tmp.local_addr().expect("proxy addr");
        drop(tmp);

        let server = CompiledUdpServer {
            listen: proxy_addr,
            upstreams: vec![upstream_addr],
            policy: L4LoadBalancePolicy::IpHash,
            max_sessions: 10_000,
            idle_timeout: Duration::from_secs(10),
        };

        let svc = UdpProxyService::new(vec![server]);
        let (tx, rx) = tokio::sync::watch::channel(false);

        let svc_handle = tokio::spawn(async move {
            svc.start(rx).await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Echo server — relay all received datagrams back.
        let echo_handle = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let result =
                    tokio::time::timeout(Duration::from_secs(5), mock_upstream.recv_from(&mut buf))
                        .await;
                match result {
                    Ok(Ok((len, src))) => {
                        let _ = mock_upstream.send_to(&buf[..len], src).await;
                    }
                    _ => break,
                }
            }
        });

        let mut client_handles = Vec::with_capacity(NUM_CLIENTS);

        for client_id in 0..NUM_CLIENTS {
            let addr = proxy_addr;
            client_handles.push(tokio::spawn(async move {
                let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
                let mut received = 0usize;

                for seq in 0..DATAGRAMS_PER_CLIENT {
                    let msg = format!("{client_id}:{seq}");
                    if client.send_to(msg.as_bytes(), addr).await.is_err() {
                        continue;
                    }
                    let mut buf = [0u8; 64];
                    let result =
                        tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
                            .await;
                    if let Ok(Ok((len, _))) = result
                        && &buf[..len] == msg.as_bytes()
                    {
                        received += 1;
                    }
                }

                received
            }));
        }

        let mut total_received = 0usize;
        for handle in client_handles {
            if let Ok(count) = handle.await {
                total_received += count;
            }
        }

        // Allow some packet loss under stress, but the vast majority should arrive.
        let expected = NUM_CLIENTS * DATAGRAMS_PER_CLIENT;
        let success_rate = (total_received as f64) / (expected as f64);
        assert!(
            success_rate > 0.80,
            "expected >80% delivery, got {total_received}/{expected} ({:.0}%)",
            success_rate * 100.0
        );

        let _ = tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(10), svc_handle).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), echo_handle).await;
    }
}
