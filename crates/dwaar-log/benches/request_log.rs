// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Benchmark for `RequestLog` JSON serialization.
//!
//! Serialization runs in the `logging()` callback on every request,
//! so it sits directly on the hot path. Target: <1µs per entry.
//!
//! Run with: `cargo bench -p dwaar-log`

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use chrono::Utc;
use criterion::{Criterion, criterion_group, criterion_main};
use dwaar_log::RequestLog;

fn sample_log() -> RequestLog {
    RequestLog {
        timestamp: Utc::now(),
        request_id: "01924f5c-7e2a-7d00-b3f4-deadbeef1234".into(),
        method: "GET".into(),
        path: "/api/users".into(),
        query: Some("page=1&limit=20".into()),
        host: "api.example.com".into(),
        status: 200,
        response_time_us: 1234,
        client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        user_agent: Some(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0".into(),
        ),
        referer: Some("https://example.com/dashboard".into()),
        bytes_sent: 4096,
        bytes_received: 256,
        tls_version: Some("TLSv1.3".into()),
        http_version: "HTTP/2".into(),
        is_bot: false,
        country: Some("US".into()),
        upstream_addr: "127.0.0.1:8080".into(),
        upstream_response_time_us: 980,
        cache_status: None,
        compression: Some("gzip".into()),
    }
}

fn bench_request_log(c: &mut Criterion) {
    let log = sample_log();

    // Full serialization — the most common path
    c.bench_function("request_log/serialize_json", |b| {
        b.iter(|| serde_json::to_string(black_box(&log)));
    });

    // Minimal log (all optionals None) — best case
    let mut minimal = sample_log();
    minimal.query = None;
    minimal.user_agent = None;
    minimal.referer = None;
    minimal.tls_version = None;
    minimal.country = None;
    minimal.cache_status = None;
    minimal.compression = None;

    c.bench_function("request_log/serialize_json_minimal", |b| {
        b.iter(|| serde_json::to_string(black_box(&minimal)));
    });

    // Pre-allocated buffer reuse (what a batch writer would do)
    c.bench_function("request_log/serialize_json_to_vec", |b| {
        let mut buf = Vec::with_capacity(512);
        b.iter(|| {
            buf.clear();
            serde_json::to_writer(black_box(&mut buf), black_box(&log))
        });
    });
}

criterion_group!(benches, bench_request_log);
criterion_main!(benches);
