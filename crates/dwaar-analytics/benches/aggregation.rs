// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Analytics aggregation benchmark — `DomainMetrics` ingestion.
//!
//! `DomainMetrics::ingest_log()` is called for every request passing
//! through the proxy. It must stay under 1µs to meet the <50µs
//! total analytics overhead budget (which also includes channel send
//! and batching).
//!
//! Run with: `cargo bench -p dwaar-analytics`

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use chrono::Utc;
use criterion::{Criterion, criterion_group, criterion_main};
use dwaar_analytics::aggregation::DomainMetrics;
use dwaar_log::RequestLog;
use hyperloglog::HyperLogLog;

fn sample_log(i: u32) -> RequestLog {
    RequestLog {
        timestamp: Utc::now(),
        request_id: String::new(),
        method: "GET".to_string(),
        path: format!("/page/{}", i % 500),
        query: None,
        host: "example.com".to_string(),
        status: if i.is_multiple_of(20) { 404 } else { 200 },
        response_time_us: 100 + u64::from(i % 5000),
        client_ip: IpAddr::V4(Ipv4Addr::from(i)),
        user_agent: Some("Mozilla/5.0 Chrome/120.0".to_string()),
        referer: if i.is_multiple_of(3) {
            Some(format!("https://ref-{}.com/page", i % 30))
        } else {
            None
        },
        bytes_sent: 1024 + u64::from(i % 10_000),
        bytes_received: 256,
        tls_version: Some("TLSv1.3".to_string()),
        http_version: "HTTP/2".to_string(),
        is_bot: false,
        country: Some(
            ["US", "IN", "DE", "JP", "BR", "GB", "FR", "AU", "CA", "KR"][i as usize % 10]
                .to_string(),
        ),
        upstream_addr: "127.0.0.1:8080".to_string(),
        upstream_response_time_us: 50,
        cache_status: None,
        compression: None,
    }
}

fn bench_aggregation(c: &mut Criterion) {
    // Single ingest — the per-request cost
    let log = sample_log(42);
    c.bench_function("aggregation/ingest_log_single", |b| {
        let mut metrics = DomainMetrics::new();
        b.iter(|| metrics.ingest_log(black_box(&log)));
    });

    // Batch ingest — simulate 1K requests hitting one domain
    let logs: Vec<RequestLog> = (0..1000).map(sample_log).collect();
    c.bench_function("aggregation/ingest_log_1000", |b| {
        b.iter(|| {
            let mut metrics = DomainMetrics::new();
            for log in &logs {
                metrics.ingest_log(black_box(log));
            }
        });
    });

    // HyperLogLog insert in isolation — the probabilistic unique counter
    c.bench_function("aggregation/hll_insert_10000", |b| {
        b.iter(|| {
            let mut hll: HyperLogLog = HyperLogLog::new(0.02);
            for i in 0..10_000u32 {
                hll.insert(black_box(&IpAddr::V4(Ipv4Addr::from(i))));
            }
            hll.len()
        });
    });

    // HyperLogLog cardinality query (the len() call)
    let mut hll: HyperLogLog = HyperLogLog::new(0.02);
    for i in 0..100_000u32 {
        hll.insert(&IpAddr::V4(Ipv4Addr::from(i)));
    }
    c.bench_function("aggregation/hll_cardinality_100k", |b| {
        b.iter(|| black_box(&hll).len());
    });
}

criterion_group!(benches, bench_aggregation);
criterion_main!(benches);
