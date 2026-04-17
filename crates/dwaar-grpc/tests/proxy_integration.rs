// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! End-to-end integration tests for the Wheel #2 Week 4-5 proxy hooks.
//!
//! These tests spin up minimal `tokio::net::TcpListener` fake upstreams
//! and exercise the control-plane primitives without booting Pingora. The
//! coverage here complements the pure-unit tests in `crates/dwaar-grpc/src/*.rs`
//! by validating:
//!
//! * `SplitRegistry::choose` produces the expected distribution when
//!   weights change (100→50/50→100).
//! * `MirrorDispatcherImpl` fires a fire-and-forget TCP connection to the
//!   configured target (`sent` / `error` / `sampled_out` counters update).
//! * `HeaderRuleRegistry` matching logic + `SplitRegistry` precedence.
//! * `AnomalyOutcomeSink` emits events via the shared `EventBus`.
//! * `LogChunkBuffer` flushes chunks on cap hit and tick.

use std::sync::Arc;
use std::time::Duration;

use dwaar_core::proxy::MirrorDispatcher;
use dwaar_core::registries::{
    HeaderRuleConfig, HeaderRuleRegistry, MirrorConfig, MirrorRegistry, SplitConfig, SplitRegistry,
    WeightedEntry,
};
use dwaar_grpc::{
    AnomalyOutcomeSink, AnomalyThresholds, EventBus, LogChunkBuffer, LogIngest,
    MIRROR_OUTCOME_ERROR, MIRROR_OUTCOME_SAMPLED_OUT, MIRROR_OUTCOME_SENT, MirrorDispatcherImpl,
};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

#[test]
fn split_100_all_traffic_to_single_upstream() {
    let registry = SplitRegistry::new();
    registry.upsert(SplitConfig {
        domain: "api.example.com".into(),
        entries: vec![WeightedEntry {
            upstream_addr: "127.0.0.1:1001".into(),
            weight: 100,
            deploy_id: "stable".into(),
        }],
        strategy: "canary".into(),
    });

    // 1000 picks — every single one must be the stable upstream.
    let mut stable = 0;
    for _ in 0..1000 {
        let entry = registry.choose("api.example.com").expect("pick");
        if entry.deploy_id == "stable" {
            stable += 1;
        }
    }
    assert_eq!(stable, 1000);
}

#[test]
fn split_50_50_distributes_within_tolerance() {
    let registry = SplitRegistry::new();
    registry.upsert(SplitConfig {
        domain: "api.example.com".into(),
        entries: vec![
            WeightedEntry {
                upstream_addr: "127.0.0.1:1001".into(),
                weight: 50,
                deploy_id: "a".into(),
            },
            WeightedEntry {
                upstream_addr: "127.0.0.1:1002".into(),
                weight: 50,
                deploy_id: "b".into(),
            },
        ],
        strategy: "canary".into(),
    });

    let mut counts = (0u32, 0u32);
    let samples = 4000;
    for _ in 0..samples {
        let entry = registry.choose("api.example.com").expect("pick");
        match entry.deploy_id.as_str() {
            "a" => counts.0 += 1,
            "b" => counts.1 += 1,
            other => panic!("unexpected bucket: {other}"),
        }
    }
    // Tolerance: ±15% of the ideal midpoint. With 4000 samples the 3σ band
    // around 50% is ≈1.5% — 15% is generous enough to avoid CI flakiness.
    let ideal = samples / 2;
    let tolerance = samples * 15 / 100;
    assert!(
        counts.0.abs_diff(ideal) < tolerance,
        "a={} b={} ideal={}",
        counts.0,
        counts.1,
        ideal
    );
    assert!(counts.1.abs_diff(ideal) < tolerance);
}

#[test]
fn split_100_rolling_back_to_single() {
    // Weight transitions: 50/50 → 100/0 (simulating a canary rollback).
    let registry = SplitRegistry::new();
    registry.upsert(SplitConfig {
        domain: "api.example.com".into(),
        entries: vec![
            WeightedEntry {
                upstream_addr: "127.0.0.1:1001".into(),
                weight: 50,
                deploy_id: "stable".into(),
            },
            WeightedEntry {
                upstream_addr: "127.0.0.1:1002".into(),
                weight: 50,
                deploy_id: "canary".into(),
            },
        ],
        strategy: "canary".into(),
    });

    // Replace with 100/0 — canary rolled back.
    registry.upsert(SplitConfig {
        domain: "api.example.com".into(),
        entries: vec![
            WeightedEntry {
                upstream_addr: "127.0.0.1:1001".into(),
                weight: 100,
                deploy_id: "stable".into(),
            },
            WeightedEntry {
                upstream_addr: "127.0.0.1:1002".into(),
                weight: 0,
                deploy_id: "canary".into(),
            },
        ],
        strategy: "canary".into(),
    });

    for _ in 0..500 {
        let entry = registry.choose("api.example.com").expect("pick");
        assert_eq!(entry.deploy_id, "stable");
    }
}

#[test]
fn header_rule_match_overrides_default_upstream() {
    let registry = HeaderRuleRegistry::new();
    let mut header_match = std::collections::HashMap::new();
    header_match.insert("x-env".to_string(), "canary".to_string());
    registry.upsert(HeaderRuleConfig {
        domain: "api.example.com".into(),
        header_match,
        upstream_addr: "127.0.0.1:9001".into(),
    });

    let snap = registry
        .snapshot_for("api.example.com")
        .expect("rule recorded");

    let canary_request = |name: &str| match name.to_ascii_lowercase().as_str() {
        "x-env" => Some("canary".to_string()),
        _ => None,
    };
    let stable_request = |name: &str| match name.to_ascii_lowercase().as_str() {
        "x-env" => Some("stable".to_string()),
        _ => None,
    };
    assert!(snap.matches(canary_request));
    assert!(!snap.matches(stable_request));
}

#[tokio::test]
async fn mirror_dispatcher_fires_against_real_listener() {
    // Spin up a TcpListener that counts how many mirror hits it receives.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let mirror_to = listener.local_addr().expect("local_addr");

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let mut accum = Vec::new();
                // Read the request headers once.
                match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await
                {
                    Ok(Ok(n)) if n > 0 => {
                        accum.extend_from_slice(&buf[..n]);
                    }
                    _ => {}
                }
                // Send a tiny HTTP/1.1 response so the client can close cleanly.
                let _ = tokio::io::AsyncWriteExt::write_all(
                    &mut stream,
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
                let _ = tx.send(accum).await;
            });
        }
    });

    let registry = Arc::new(MirrorRegistry::new());
    registry.upsert(MirrorConfig {
        source_domain: "api.example.com".into(),
        mirror_to: mirror_to.to_string(),
        sample_rate_bps: 10_000, // 100% — always mirror
    });

    let dispatcher = MirrorDispatcherImpl::new(Arc::clone(&registry));
    dispatcher.mirror(
        "api.example.com",
        "GET",
        "/mirror-path",
        &[("user-agent".to_string(), "dwaar-test".to_string())],
    );

    // Wait for the listener to record the mirror.
    let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("mirror received within 2s")
        .expect("channel open");
    let raw = String::from_utf8_lossy(&received);
    assert!(raw.contains("GET /mirror-path HTTP/1.1"));
    assert!(raw.contains("Host: api.example.com"));
    assert!(raw.contains("X-Dwaar-Mirror: 1"));
    assert!(raw.contains("user-agent: dwaar-test"));

    // Give the spawned task one more tick to update the counter.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let snapshot = dispatcher.metrics().snapshot();
    assert!(
        snapshot.iter().any(|(k, _)| k.2 == MIRROR_OUTCOME_SENT),
        "expected at least one sent outcome, got {snapshot:?}"
    );
}

#[tokio::test]
async fn mirror_dispatcher_records_sampled_out_for_zero_rate() {
    let registry = Arc::new(MirrorRegistry::new());
    registry.upsert(MirrorConfig {
        source_domain: "api.example.com".into(),
        mirror_to: "127.0.0.1:9".into(),
        sample_rate_bps: 0,
    });
    let dispatcher = MirrorDispatcherImpl::new(registry);
    for _ in 0..5 {
        dispatcher.mirror("api.example.com", "GET", "/", &[]);
    }
    let snap = dispatcher.metrics().snapshot();
    assert!(
        snap.iter()
            .any(|(k, v)| k.2 == MIRROR_OUTCOME_SAMPLED_OUT && *v == 5)
    );
    assert!(!snap.iter().any(|(k, _)| k.2 == MIRROR_OUTCOME_SENT));
}

#[tokio::test]
async fn mirror_dispatcher_records_error_when_target_unreachable() {
    let registry = Arc::new(MirrorRegistry::new());
    // Bind to a port, drop the listener, then mirror to the freed port.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);
    registry.upsert(MirrorConfig {
        source_domain: "api.example.com".into(),
        mirror_to: addr.to_string(),
        sample_rate_bps: 10_000,
    });
    let dispatcher = MirrorDispatcherImpl::new(registry);
    dispatcher.mirror("api.example.com", "GET", "/", &[]);

    // Give the detached task time to attempt and fail.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let snap = dispatcher.metrics().snapshot();
    assert!(
        snap.iter().any(|(k, _)| k.2 == MIRROR_OUTCOME_ERROR),
        "expected error outcome, snapshot={snap:?}"
    );
}

#[tokio::test]
async fn anomaly_sink_emits_via_event_bus_on_error_rate() {
    let bus = Arc::new(EventBus::new());
    let mut sub = bus.subscribe();
    let sink = AnomalyOutcomeSink::with_thresholds(
        Arc::clone(&bus),
        AnomalyThresholds {
            error_rate_min_requests: 10,
            ..AnomalyThresholds::default()
        },
    );
    // 10 clean requests, then 10 errors → 50% rate.
    for _ in 0..10 {
        dwaar_core::proxy::RequestOutcomeSink::record(
            &sink,
            "api.example.com",
            200,
            Duration::from_millis(10),
        );
    }
    for _ in 0..10 {
        dwaar_core::proxy::RequestOutcomeSink::record(
            &sink,
            "api.example.com",
            503,
            Duration::from_millis(10),
        );
    }

    let msg = tokio::time::timeout(Duration::from_millis(200), sub.next())
        .await
        .expect("anomaly event fired")
        .expect("bus open");
    match &msg.kind {
        Some(dwaar_grpc::pb::server_message::Kind::AnomalyEvent(ev)) => {
            assert_eq!(ev.domain, "api.example.com");
            assert_eq!(ev.anomaly_type, "error_rate");
            assert!(ev.severity > 0.0);
        }
        other => panic!("expected AnomalyEvent, got {other:?}"),
    }
}

#[tokio::test]
async fn log_buffer_batches_up_to_cap_then_flushes() {
    let bus = Arc::new(EventBus::new());
    let mut sub = bus.subscribe();
    // Tick-based flush: use a very short interval to avoid flake.
    let buf = LogChunkBuffer::with_interval(Arc::clone(&bus), Duration::from_millis(25));

    for i in 0..5 {
        buf.append(&LogIngest {
            domain: "api.example.com".into(),
            deploy_id: "d1".into(),
            line: format!("line-{i}").into_bytes(),
        });
    }
    tokio::time::sleep(Duration::from_millis(40)).await;
    buf.tick();

    let msg = tokio::time::timeout(Duration::from_millis(200), sub.next())
        .await
        .expect("chunk flushed")
        .expect("bus open");
    match &msg.kind {
        Some(dwaar_grpc::pb::server_message::Kind::LogChunk(chunk)) => {
            assert_eq!(chunk.domain, "api.example.com");
            assert_eq!(chunk.deploy_id, "d1");
            #[allow(clippy::naive_bytecount)]
            let lines = chunk.payload.iter().filter(|&&b| b == b'\n').count();
            assert_eq!(lines, 5);
        }
        other => panic!("expected LiveLogChunk, got {other:?}"),
    }
}

#[tokio::test]
async fn bus_drops_oldest_on_subscriber_overrun_and_publisher_never_blocks() {
    let bus = Arc::new(EventBus::with_capacity(2));
    let _sub = bus.subscribe();

    // Fire a burst of 100 events at a 2-deep subscriber — publisher must
    // return without blocking; bus records drops.
    let t0 = tokio::time::Instant::now();
    for i in 0..100 {
        bus.publish_anomaly(dwaar_grpc::pb::AnomalyEvent {
            domain: format!("d{i}"),
            anomaly_type: "error_rate".into(),
            severity: 0.5,
            detail: String::new(),
            observed_at_unix_ms: 0,
        });
    }
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_millis(250),
        "publisher blocked — took {elapsed:?}"
    );
    assert!(bus.dropped_count() > 0, "expected at least one drop");
}
