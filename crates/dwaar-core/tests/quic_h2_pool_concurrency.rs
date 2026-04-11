// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Concurrency invariant for the H3 → H2 upstream bridge.
//!
//! The streaming bridge multiplexes many H3 request streams onto a
//! bounded number of H2 upstream connections. Without the pool, 100
//! concurrent H3 streams would open 100 upstream TCP connections —
//! defeating the whole point of H3/H2 multiplexing.
//!
//! This test asserts:
//!
//! 1. `H2ConnPool::get_or_connect` never opens more than
//!    `MAX_CONNS_PER_HOST` (2) TCP connections per upstream, even
//!    under N concurrent callers.
//! 2. All callers receive a working `SendRequest` handle; the pool
//!    never hands out a dead sender.
//! 3. The invariant holds whether callers arrive simultaneously or
//!    staggered.
//!
//! The count is measured at the listener side with an `AtomicUsize`
//! counter incremented on every `accept()` — this catches any leak
//! even if the pool thinks it's handed out a pooled connection but
//! secretly punched a new TCP socket.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dwaar_core::quic::h2_pool::H2ConnPool;
use tokio::net::TcpListener;

/// Spawn a minimal H2 server on `127.0.0.1:0` that counts every
/// accepted TCP connection in `counter`. Returns the bound address
/// and an abort handle so the test can tear the server down cleanly.
async fn spawn_counting_h2_server(counter: Arc<AtomicUsize>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };

            counter.fetch_add(1, Ordering::SeqCst);

            tokio::spawn(async move {
                use h2::server;

                let Ok(mut conn) = server::handshake(tcp).await else {
                    return;
                };

                // Answer every request with an empty 200 OK. The
                // concurrency invariant is measured by the accept
                // counter, not by response content.
                while let Some(req_result) = conn.accept().await {
                    let Ok((_req, mut respond)) = req_result else {
                        return;
                    };
                    let Ok(response) = http::Response::builder().status(200).body(()) else {
                        return;
                    };
                    if let Ok(mut send) = respond.send_response(response, false) {
                        let _ = send.send_data(bytes::Bytes::from_static(b"ok"), true);
                    }
                }
            });
        }
    });

    addr
}

/// 100 concurrent `get_or_connect` calls on a fresh pool must open
/// at most `MAX_CONNS_PER_HOST` actual TCP connections.
///
/// This is the core invariant from Phase 27 ISSUE-108 Part 5: H3
/// multiplexing must not translate 1-to-1 into upstream TCP
/// connections.
#[tokio::test]
async fn hundred_streams_share_two_upstream_connections() {
    let counter = Arc::new(AtomicUsize::new(0));
    let addr = spawn_counting_h2_server(Arc::clone(&counter)).await;

    let pool = Arc::new(H2ConnPool::new());

    // Fire 100 concurrent requests — each caller wants a SendRequest
    // handle for `addr`.  The pool should coalesce them onto at most
    // two TCP connections.
    let mut join_set = tokio::task::JoinSet::new();
    for _ in 0..100 {
        let pool = Arc::clone(&pool);
        join_set.spawn(async move {
            let sender = pool
                .get_or_connect(addr)
                .await
                .expect("get_or_connect should succeed");

            // Actually drive a request so the underlying TCP connection
            // gets used — a pool that's handed out a stale sender would
            // fail here even if acquire() looked healthy.
            let mut sender = sender.ready().await.expect("sender ready");
            let req = http::Request::builder()
                .method(http::Method::GET)
                .uri("http://localhost/x")
                .body(())
                .expect("request");
            let (resp_fut, _) = sender.send_request(req, true).expect("send_request");
            let resp = resp_fut.await.expect("response");
            assert_eq!(resp.status(), 200);
        });
    }

    while let Some(res) = join_set.join_next().await {
        res.expect("task should not panic");
    }

    // Give the server a brief moment — TCP accept() may lag a pending
    // connection by a few ms under heavy load. If the pool leaked, the
    // counter will exceed 2 regardless.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let total = counter.load(Ordering::SeqCst);
    assert!(
        total <= 2,
        "pool opened {total} TCP connections; expected <= 2 \
         (MAX_CONNS_PER_HOST). Concurrency invariant violated."
    );
    assert!(
        total >= 1,
        "expected at least one TCP connection to be opened"
    );
}

/// Helper for `staggered_waves_reuse_pooled_connections`: fire `count`
/// concurrent `get_or_connect` calls and drive each through one real
/// request/response.
async fn fire_wave(pool: Arc<H2ConnPool>, addr: std::net::SocketAddr, count: usize) {
    let mut join_set = tokio::task::JoinSet::new();
    for _ in 0..count {
        let pool = Arc::clone(&pool);
        join_set.spawn(async move {
            let sender = pool
                .get_or_connect(addr)
                .await
                .expect("get_or_connect should succeed");
            let mut sender = sender.ready().await.expect("sender ready");
            let req = http::Request::builder()
                .method(http::Method::GET)
                .uri("http://localhost/w")
                .body(())
                .expect("request");
            let (resp_fut, _) = sender.send_request(req, true).expect("send_request");
            let _ = resp_fut.await.expect("response");
        });
    }
    while let Some(res) = join_set.join_next().await {
        res.expect("task should not panic");
    }
}

/// Under staggered load — 50 requests, short pause, 50 more — the pool
/// still honours the connection ceiling. This catches a specific bug
/// class where the first batch is serviced correctly but the second
/// batch opens a fresh pair because the pool forgot about the first.
#[tokio::test]
async fn staggered_waves_reuse_pooled_connections() {
    let counter = Arc::new(AtomicUsize::new(0));
    let addr = spawn_counting_h2_server(Arc::clone(&counter)).await;

    let pool = Arc::new(H2ConnPool::new());

    fire_wave(Arc::clone(&pool), addr, 50).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    fire_wave(Arc::clone(&pool), addr, 50).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let total = counter.load(Ordering::SeqCst);
    assert!(
        total <= 2,
        "staggered waves opened {total} TCP connections; expected <= 2. \
         The pool is not retaining connections across waves."
    );
}
