# Dwaar vs nginx Benchmark (2026-04-06)

## Setup
- **Machine**: macOS Darwin 25.3.0, Apple Silicon M-series, 10 cores
- **Backend**: Rust TCP server (thread-per-conn, keep-alive, 27-byte JSON)
- **Load generator**: wrk 4.2.0, 4 threads, 10s duration, 3s warmup
- **Dwaar**: v0.1.0 release, `--bare` (no logging/analytics/plugins), 1 worker × 10 threads
- **nginx**: 1.27.1, `worker_processes auto` (10 workers), `keepalive 128`, `access_log off`

## Results

| Proxy | Conns | Req/sec | P50 | P99 | RSS |
|-------|-------|---------|-----|-----|-----|
| **Dwaar** | 100 | 32,391 | 3.03ms | 7.09ms | 6 MB |
| **nginx** | 100 | 64,308 | 1.53ms | 3.59ms | 30 MB |
| **Dwaar** | 500 | 31,654 | 7.19ms | 77.94ms | 6 MB |
| **nginx** | 500 | 65,118 | 7.46ms | 33.72ms | 30 MB |
| **Dwaar** | 1000 | 32,118 | 8.01ms | 179.34ms | 6 MB |
| **nginx** | 1000 | 62,720 | 15.54ms | 28.97ms | 30 MB |

## Summary

| Metric | Dwaar | nginx | Ratio |
|--------|-------|-------|-------|
| Throughput | 32K | 63K | nginx 2x |
| P50 @ 500 | 7.19ms | 7.46ms | **Dwaar wins** |
| P99 @ 1000 | 179ms | 29ms | nginx 6x |
| Memory | 6 MB | 30 MB | **Dwaar 5x** |

**Dwaar wins on memory (5x) and P50 at medium concurrency.**
**nginx wins on raw throughput (2x) and tail latency.**

The P99 gap is a consequence of the throughput gap — at 1000 connections sharing
32K capacity, the 99th percentile request waits in queue. Match throughput → match P99.

## Root Cause

The 2x throughput gap is Pingora's async Rust overhead vs nginx's hand-tuned C:
- Tokio task scheduling per request (~microseconds)
- `Box<HttpPeer>` heap allocation (mandatory Pingora API)
- Trait object dispatch through ProxyHttp hooks
- HTTP parsing overhead (Pingora httparse vs nginx custom)

This is the Pingora tradeoff: memory safety + developer velocity at ~2x
throughput cost. Cloudflare runs Pingora at CDN scale where features and safety
matter more than single-machine RPS.

## Optimizations Applied

| Change | Impact |
|--------|--------|
| Non-cumulative histogram buckets | 3 atomics/req instead of 13+ |
| Bundled DomainRequestMetrics | 1 DashMap lock instead of 4 |
| get() before entry() on DashMap | No clone under shard lock |
| 1 worker × all cores | Shared pool, no process overhead |
| fastrand UUID v7 | ~3ns instead of ~100ns per request |
| Upstream pool 512 | Matches nginx effective pool |

## Reproducing

```bash
cargo build --release
cd bench && bash local.sh
```
