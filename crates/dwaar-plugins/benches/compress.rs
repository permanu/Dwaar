// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Compression throughput benchmark — gzip, brotli, zstd.
//!
//! Measures streaming compression on realistic HTML payloads.
//! Compression runs in `response_body_filter()` on every compressible
//! response, so throughput directly affects time-to-first-byte.
//!
//! Run with: `cargo bench -p dwaar-plugins -- compress`

use std::hint::black_box;

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};
use dwaar_plugins::compress::{CompressEncoding, ResponseCompressor};

/// Realistic HTML payload (~10KB) — typical server-rendered page.
fn html_payload(size_kb: usize) -> Vec<u8> {
    let fragment = br#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Dashboard - My Application</title>
<link rel="stylesheet" href="/assets/main.css">
<script src="/assets/app.js" defer></script></head><body>
<nav class="navbar"><a href="/">Home</a><a href="/about">About</a></nav>
<main><section class="hero"><h1>Welcome to Dwaar</h1>
<p>A high-performance reverse proxy built on Pingora.</p></section>
<div class="grid"><div class="card"><h3>Routes</h3><p>42 active</p></div>
<div class="card"><h3>Requests</h3><p>1.2M today</p></div>
<div class="card"><h3>P99 Latency</h3><p>0.8ms</p></div></div></main>
<footer><p>Powered by Dwaar v0.1.0</p></footer></body></html>
"#;
    fragment
        .iter()
        .copied()
        .cycle()
        .take(size_kb * 1024)
        .collect()
}

fn bench_compress(c: &mut Criterion) {
    let payload_small = html_payload(10);
    let payload_large = html_payload(100);

    for (name, encoding) in [
        ("gzip", CompressEncoding::Gzip),
        ("brotli", CompressEncoding::Brotli),
        ("zstd", CompressEncoding::Zstd),
    ] {
        // Single-shot: entire payload in one chunk (small responses)
        c.bench_function(&format!("compress/{name}_10kb_single"), |b| {
            b.iter(|| {
                let mut compressor = ResponseCompressor::new(encoding);
                let mut body = Some(Bytes::from(payload_small.clone()));
                compressor.compress(black_box(&mut body), true);
                body
            });
        });

        // Streaming: 8KB chunks (typical chunked transfer)
        c.bench_function(&format!("compress/{name}_100kb_streaming"), |b| {
            b.iter(|| {
                let mut compressor = ResponseCompressor::new(encoding);
                let chunks: Vec<&[u8]> = payload_large.chunks(8192).collect();
                let last_idx = chunks.len() - 1;
                for (i, chunk) in chunks.iter().enumerate() {
                    let mut body = Some(Bytes::from(chunk.to_vec()));
                    compressor.compress(black_box(&mut body), i == last_idx);
                }
            });
        });
    }

    // Encoding negotiation (runs on every response with Accept-Encoding)
    c.bench_function("compress/negotiate_encoding", |b| {
        b.iter(|| {
            dwaar_plugins::compress::negotiate_encoding(black_box(
                "gzip, deflate, br;q=1.0, zstd;q=0.5",
            ))
        });
    });
}

criterion_group!(benches, bench_compress);
criterion_main!(benches);
