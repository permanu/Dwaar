# Dwaar vs nginx Benchmark

## Setup
- **Machine**: macOS Darwin 25.3.0, Apple Silicon M-series, 10 cores
- **Backend**: Rust TCP server (thread-per-conn, keep-alive, 27-byte JSON)
- **Load generator**: wrk 4.2.0, 4 threads, 10s per level, 3s warmup
- **Dwaar**: v0.1.0 release, `--bare`, 1 worker × 10 tokio threads
- **nginx**: 1.27.1, `worker_processes auto` (10), `keepalive 128`, `access_log off`

## Results

| Conns | Dwaar RPS | nginx RPS | Dwaar P50 | nginx P50 | Dwaar P99 | nginx P99 |
|-------|-----------|-----------|-----------|-----------|-----------|-----------|
| 100 | **65,037** | 63,753 | **1.46ms** | 1.54ms | **5.14ms** | 8.35ms |
| 500 | **68,610** | 65,182 | **6.94ms** | 7.49ms | **16.05ms** | 21.92ms |
| 1000 | **67,325** | 63,087 | **14.44ms** | 15.45ms | **40.26ms** | 40.70ms |

**Memory**: Dwaar 6 MB vs nginx 51 MB (**8.5x less**)

## Summary

Dwaar matches or beats nginx on throughput, P50, and P99 at all concurrency
levels, while using 8.5x less memory. This validates Pingora's claim that
async Rust can compete with hand-tuned C — when the application layer
doesn't add unnecessary overhead.

## Optimizations that closed the gap

| Change | Impact |
|--------|--------|
| `LevelFilter` instead of `EnvFilter` | **32K → 67K RPS** (biggest single win) |
| 1 worker × all cores (was cpu_count workers × 1 thread) | 28K → 32K RPS |
| Non-cumulative histogram buckets | Eliminated P99 exponential growth |
| Bundled DomainRequestMetrics | 1 DashMap lock instead of 4 |
| `get()` before `entry()` on DashMap | No clone under shard lock |
| fastrand UUID v7 | ~3ns instead of ~100ns per request |

**Critical lesson**: `tracing_subscriber::EnvFilter` evaluates a regex-like
filter string on every tracing callsite on every event. With ~57 tracing
macro calls per request (31 in Dwaar + 26 in Pingora), this was 3.8M string
comparisons per second at 67K RPS — consuming 50% of throughput. Switching
to `LevelFilter` (single atomic compare) eliminated this entirely.

## Reproducing

```bash
cargo build --release
cd bench && bash local.sh
```

**Critical**: do NOT set `RUST_LOG` or `DWAAR_LOG_LEVEL` during benchmarks.
These env vars activate EnvFilter which halves throughput. The default
LevelFilter (INFO) is used when no env var is present.
