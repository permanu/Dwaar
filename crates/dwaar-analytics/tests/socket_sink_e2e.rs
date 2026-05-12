// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! End-to-end test for the `SocketSink` + `AggregationService` chain.
//!
//! Spins up an `AggregationService` wired to a real `SocketSink`, listens
//! on the matching unix socket from a tokio task, sends an aggregation
//! event through the channel, and asserts that a `DomainMetricsSnapshot`
//! arrives on the listener with the expected `domain` field.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use dwaar_analytics::aggregation::service::{AggregationService, RouteValidator};
use dwaar_analytics::aggregation::{AggEvent, AggReceiver};
use dwaar_analytics::beacon::BeaconEvent;
use dwaar_analytics::sink::SocketSink;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, watch};

struct TestValidator(HashSet<String>);

impl RouteValidator for TestValidator {
    fn is_known_host(&self, host: &str) -> bool {
        self.0.contains(host)
    }
    fn known_hosts(&self) -> Vec<String> {
        self.0.iter().cloned().collect()
    }
}

fn sample_event(host: &str) -> AggEvent {
    AggEvent {
        host: host.into(),
        path: "/".into(),
        query: None,
        status: 200,
        bytes_sent: 256,
        client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        country: Some("US".into()),
        referer: None,
        user_agent: Some("Mozilla/5.0".into()),
        is_bot: false,
        response_latency_us: 0,
    }
}

fn short_socket_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("dwaar-analytics-")
        .tempdir_in("/tmp")
        .expect("create short socket temp dir")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socket_sink_receives_snapshot_through_aggregation_service() {
    let dir = short_socket_dir();
    let sock_path = dir.path().join("analytics.sock");

    // Listener task: accept one connection, read one JSON line, send it
    // back over a oneshot. SOCK_STREAM matches `SocketSink`'s
    // `UnixStream::connect` and the agent's `UnixListener::bind`.
    let listener = UnixListener::bind(&sock_path).expect("bind unix socket");
    let (line_tx, line_rx) = tokio::sync::oneshot::channel::<String>();
    let listener_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read line");
        let _ = line_tx.send(line);
    });

    // Service wired with the SocketSink pointing at the same path.
    let domain = "e2e.example.com";
    let known: HashSet<String> = [domain.to_string()].into_iter().collect();
    let metrics = Arc::new(DashMap::new());
    let (_beacon_tx, beacon_rx) = mpsc::channel::<BeaconEvent>(8);
    let (log_tx, log_rx) = mpsc::channel::<AggEvent>(8);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let svc = Arc::new(
        AggregationService::new(
            Arc::clone(&metrics),
            TestValidator(known),
            beacon_rx,
            AggReceiver { rx: log_rx },
        )
        .with_sink(Box::new(SocketSink::new(sock_path.clone()))),
    );

    let svc_clone = Arc::clone(&svc);
    let run_task = tokio::spawn(async move {
        svc_clone.run(shutdown_rx).await;
    });

    // Push an event so the domain has non-default metrics for the snapshot.
    log_tx.send(sample_event(domain)).await.expect("send event");

    // Give the run loop a moment to ingest before shutdown. Shutdown
    // triggers a final flush() — which is the path that writes through
    // the SocketSink to our listener — so we don't have to wait the full
    // 60s flush interval.
    tokio::time::sleep(Duration::from_millis(100)).await;
    shutdown_tx.send(true).expect("signal shutdown");

    // Wait for the listener to receive the line.
    let line = tokio::time::timeout(Duration::from_secs(5), line_rx)
        .await
        .expect("listener timed out")
        .expect("listener task dropped sender");

    let _ = run_task.await;
    let _ = listener_task.await;

    let parsed: serde_json::Value =
        serde_json::from_str(line.trim()).expect("snapshot is valid JSON");
    assert_eq!(
        parsed["domain"].as_str(),
        Some(domain),
        "snapshot domain field must round-trip through the unix socket"
    );
    assert!(
        parsed.get("unique_visitors").is_some(),
        "snapshot must carry the DomainMetricsSnapshot shape"
    );

    // Ensure the metrics map saw our event end-to-end.
    assert!(
        metrics.contains_key(domain),
        "domain metrics should be ingested"
    );
}
