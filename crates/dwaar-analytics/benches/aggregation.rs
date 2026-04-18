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

use criterion::{Criterion, criterion_group, criterion_main};
use dwaar_analytics::aggregation::{AggEvent, DomainMetrics};
use hyperloglog::HyperLogLog;

fn sample_event(i: u32) -> AggEvent {
    // Cycle through representative UAs so the device classifier branch
    // is exercised in the hot path benchmark — otherwise the device
    // BoundedCounter insert cost is not measured.
    const UAS: &[&str] = &[
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit Chrome/120 Safari",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148",
        "Mozilla/5.0 (iPad; CPU OS 17_0) AppleWebKit Mobile/15E148",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/122.0",
    ];
    AggEvent {
        host: "example.com".into(),
        path: format!("/page/{}", i % 500).into(),
        // Every 4th event carries a UTM query so the benchmark measures
        // the cost of the UTM extraction path end-to-end, not just the
        // no-query fast exit. Term and content are cycled on a finer
        // spread than source/medium/campaign to stress the tighter
        // bounded-counter caps (25 vs 50) on those dimensions.
        query: if i.is_multiple_of(4) {
            Some(
                format!(
                    "utm_source=src{}&utm_medium=cpc&utm_campaign=campaign{}\
                     &utm_term=term{}&utm_content=ad{}",
                    i % 10,
                    i % 7,
                    i % 12,
                    i % 15
                )
                .into(),
            )
        } else {
            None
        },
        status: if i.is_multiple_of(20) { 404 } else { 200 },
        bytes_sent: 1024 + u64::from(i % 10_000),
        client_ip: IpAddr::V4(Ipv4Addr::from(i)),
        country: Some(
            ["US", "IN", "DE", "JP", "BR", "GB", "FR", "AU", "CA", "KR"][i as usize % 10].into(),
        ),
        referer: if i.is_multiple_of(3) {
            Some(format!("https://ref-{}.com/page", i % 30).into())
        } else {
            None
        },
        user_agent: Some(UAS[i as usize % UAS.len()].into()),
        is_bot: i.is_multiple_of(7),
        // Vary latency across the full bucket range so the benchmark
        // exercises the partition_point lookup across every bucket
        // rather than pinning all observations to one slot.
        response_latency_us: u64::from(i % 20_000) * 1_000,
    }
}

fn bench_aggregation(c: &mut Criterion) {
    // Single ingest — the per-request cost
    let event = sample_event(42);
    c.bench_function("aggregation/ingest_log_single", |b| {
        let mut metrics = DomainMetrics::new();
        b.iter(|| metrics.ingest_log(black_box(&event)));
    });

    // Batch ingest — simulate 1K requests hitting one domain
    let events: Vec<AggEvent> = (0..1000).map(sample_event).collect();
    c.bench_function("aggregation/ingest_log_1000", |b| {
        b.iter(|| {
            let mut metrics = DomainMetrics::new();
            for event in &events {
                metrics.ingest_log(black_box(event));
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
