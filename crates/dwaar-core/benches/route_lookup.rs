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
        routes.push(Route::new(&domain, addr, false));
    }

    // Add wildcard patterns for 10 different base domains
    for i in 0..n / 10 {
        let domain = format!("*.base-{i}.example.com");
        let addr = SocketAddr::from(([127, 0, 0, 1], 9000));
        routes.push(Route::new(&domain, addr, false));
    }

    RouteTable::new(routes)
}

fn bench_route_lookup(c: &mut Criterion) {
    let table = build_table(1000);

    // Exact match — best case, single HashMap lookup
    c.bench_function("resolve/exact_hit_1000_routes", |b| {
        b.iter(|| table.resolve(black_box("app-500.example.com")));
    });

    // Wildcard match — worst case for a hit: exact miss + wildcard lookup
    c.bench_function("resolve/wildcard_hit_1000_routes", |b| {
        b.iter(|| table.resolve(black_box("anything.base-50.example.com")));
    });

    // Total miss — worst case overall: exact miss + wildcard miss
    c.bench_function("resolve/miss_1000_routes", |b| {
        b.iter(|| table.resolve(black_box("nonexistent.unknown.dev")));
    });
}

criterion_group!(benches, bench_route_lookup);
criterion_main!(benches);
