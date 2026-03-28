// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Dwaarfile parser benchmark — parse configs of varying sizes.
//!
//! Config parsing happens at startup and on hot-reload. While not
//! on the per-request hot path, slow parsing delays config changes
//! and impacts the <10ms reload target.
//!
//! Run with: `cargo bench -p dwaar-config`

use std::fmt::Write;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use dwaar_config::parser;

/// Generate a Dwaarfile with `n` site blocks, each with multiple directives.
fn generate_dwaarfile(n: usize) -> String {
    let mut config = String::with_capacity(n * 200);
    for i in 0..n {
        let _ = write!(
            config,
            r#"app-{i}.example.com {{
    reverse_proxy 10.0.{}.{}:{}
    tls auto
    encode gzip br
    header X-Request-Id "{{{{uuid}}}}"
    rate_limit 100/s
}}

"#,
            (i / 256) % 256,
            i % 256,
            3000 + (i % 10000),
        );
    }
    config
}

fn bench_parser(c: &mut Criterion) {
    // Small config — typical single-app deployment
    let small = generate_dwaarfile(10);
    c.bench_function("parser/parse_10_routes", |b| {
        b.iter(|| parser::parse(black_box(&small)));
    });

    // Medium config — multi-service deployment
    let medium = generate_dwaarfile(100);
    c.bench_function("parser/parse_100_routes", |b| {
        b.iter(|| parser::parse(black_box(&medium)));
    });

    // Large config — hosting platform scale
    let large = generate_dwaarfile(1000);
    c.bench_function("parser/parse_1000_routes", |b| {
        b.iter(|| parser::parse(black_box(&large)));
    });

    // Tokenizer-only cost: measure overhead of parsing a minimal config
    c.bench_function("parser/parse_minimal", |b| {
        b.iter(|| parser::parse(black_box("a.com { reverse_proxy :8080 }")));
    });
}

criterion_group!(benches, bench_parser);
criterion_main!(benches);
