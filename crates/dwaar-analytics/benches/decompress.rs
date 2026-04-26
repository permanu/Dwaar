// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Decompression benchmarks. Issues #153 and #155 hinge on pre-allocation
//! of the feed buffer (`Decompressor::new`) and the output buffer used by
//! `read_bounded`. Run: `cargo bench -p dwaar-analytics --bench decompress`.

use std::hint::black_box;
use std::io::Write;

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};
use dwaar_analytics::decompress::{Decompressor, Encoding};
use flate2::Compression;
use flate2::write::GzEncoder;

fn gzip_payload(size_bytes: usize) -> Vec<u8> {
    let html: String = std::iter::repeat_n('a', size_bytes).collect();
    let mut enc = GzEncoder::new(Vec::with_capacity(size_bytes), Compression::fast());
    enc.write_all(html.as_bytes()).expect("encode");
    enc.finish().expect("finish")
}

fn bench_decompress_50k(c: &mut Criterion) {
    let payload = gzip_payload(50_000);
    c.bench_function("decompress_50k_gzip_one_shot", |b| {
        b.iter(|| {
            let mut dec = Decompressor::new(Encoding::Gzip);
            let mut body = Some(Bytes::from(payload.clone()));
            dec.decompress(&mut body, true);
            black_box(body);
        });
    });
}

criterion_group!(benches, bench_decompress_50k);
criterion_main!(benches);
