// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Bot detection benchmark — classify 1K+ User-Agent strings.
//!
//! The `BotDetector` runs on every proxied request, so its per-call
//! cost directly impacts tail latency. The `RegexSet` (Aho-Corasick)
//! should give us O(n) in UA length regardless of pattern count.
//!
//! Run with: `cargo bench -p dwaar-plugins -- bot`

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use dwaar_plugins::bot_detect::BotDetector;

/// Real-world User-Agent strings covering all categories.
const USER_AGENTS: &[&str] = &[
    // Browsers (should return None — human traffic)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91",
    // Search engines
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    // Social crawlers
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Twitterbot/1.0",
    // Malicious
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    // Generic bots
    "curl/8.4.0",
    "python-requests/2.31.0",
    "Go-http-client/2.0",
];

fn bench_bot_detect(c: &mut Criterion) {
    let detector = BotDetector::new();

    // Single classification — typical hot-path cost
    c.bench_function("bot_detect/classify_chrome_ua", |b| {
        let ua = USER_AGENTS[0]; // long Chrome UA — worst case for human traffic
        b.iter(|| detector.classify(black_box(ua)));
    });

    c.bench_function("bot_detect/classify_googlebot", |b| {
        b.iter(|| detector.classify(black_box(USER_AGENTS[5])));
    });

    c.bench_function("bot_detect/classify_empty", |b| {
        b.iter(|| detector.classify(black_box("")));
    });

    // Batch: classify all UAs — simulates a burst of mixed traffic
    c.bench_function("bot_detect/classify_batch_15_uas", |b| {
        b.iter(|| {
            for ua in USER_AGENTS {
                let _ = detector.classify(black_box(ua));
            }
        });
    });

    // Scale test: 1000 UAs (repeat the set ~67 times)
    let thousand_uas: Vec<&str> = USER_AGENTS.iter().copied().cycle().take(1000).collect();
    c.bench_function("bot_detect/classify_1000_uas", |b| {
        b.iter(|| {
            for ua in &thousand_uas {
                let _ = detector.classify(black_box(ua));
            }
        });
    });
}

criterion_group!(benches, bench_bot_detect);
criterion_main!(benches);
