// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Benchmark proving route table lookups are <10ns.
//!
//! Run with: `cargo bench -p dwaar-core`

use std::net::SocketAddr;

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use dwaar_core::route::{Route, RouteTable};

/// Build a route table with `n` exact domains + `n/10` wildcard patterns.
fn build_table(n: usize) -> RouteTable {
    let mut routes = Vec::with_capacity(n + n / 10);

    for i in 0..n {
        let domain = format!("app-{i}.example.com");
        let port = 3000 + (i as u16 % 10000);
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        routes.push(Route::new(&domain, addr, false, None));
    }

    // Add wildcard patterns for 10 different base domains
    for i in 0..n / 10 {
        let domain = format!("*.base-{i}.example.com");
        let addr = SocketAddr::from(([127, 0, 0, 1], 9000));
        routes.push(Route::new(&domain, addr, false, None));
    }

    RouteTable::new(routes)
}

fn bench_route_lookup(c: &mut Criterion) {
    // Test at three scales to prove O(1) amortized lookup holds
    for &n in &[1_000, 10_000, 100_000] {
        let table = build_table(n);
        let mid = n / 2;

        c.bench_function(&format!("resolve/exact_hit_{n}_routes"), |b| {
            let host = format!("app-{mid}.example.com");
            b.iter(|| table.resolve(black_box(&host)));
        });

        c.bench_function(&format!("resolve/wildcard_hit_{n}_routes"), |b| {
            let host = format!("anything.base-{}.example.com", n / 20);
            b.iter(|| table.resolve(black_box(&host)));
        });

        c.bench_function(&format!("resolve/miss_{n}_routes"), |b| {
            b.iter(|| table.resolve(black_box("nonexistent.unknown.dev")));
        });
    }
}

criterion_group!(benches, bench_route_lookup);
criterion_main!(benches);
