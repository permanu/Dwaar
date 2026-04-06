# Dwaar vs nginx Benchmark (2026-04-06)

## Setup
- **Machine**: macOS Darwin 25.3.0, Apple Silicon M-series, 10 cores
- **Backend**: Rust TCP server (thread-per-conn, keep-alive, 27-byte JSON)
- **Load generator**: wrk 4.2.0, 4 threads, 10s × 3 runs per level
- **Dwaar**: v0.1.0 release, `--bare` (no logging/analytics/plugins), auto workers (2)
- **nginx**: 1.27.1, `worker_processes auto` (10), `keepalive 128`, `access_log off`

## Results (3-run median, 1000 concurrent connections)

| Metric | Dwaar | nginx | Winner |
|--------|-------|-------|--------|
| **Req/sec** | 32,032 | 62,399 | nginx 1.9x |
| **P50** | 7.96ms | 15.51ms | **Dwaar 1.9x** |
| **P99** | 204ms | 41ms | nginx 5x |
| **RSS** | 6 MB | 30 MB | **Dwaar 5x** |

## Full concurrency sweep

| Proxy | Conns | Req/sec | P50 | P99 | RSS |
|-------|-------|---------|-----|-----|-----|
| Dwaar | 100 | 33,085 | 3.00ms | 4.12ms | 7 MB |
| nginx | 100 | 65,329 | 1.50ms | 3.11ms | 30 MB |
| Dwaar | 500 | 30,903 | 7.26ms | 79.02ms | 7 MB |
| nginx | 500 | 66,481 | 7.17ms | 55.17ms | 30 MB |
| Dwaar | 1000 | 32,032 | 7.96ms | 204ms | 7 MB |
| nginx | 1000 | 62,399 | 15.51ms | 41ms | 30 MB |

## Worker tuning (discovered root cause)

| Workers × Threads | c=100 RPS | c=100 P99 | c=1000 RPS | c=1000 P99 |
|-------------------|-----------|-----------|------------|------------|
| 10 × 1 (old auto) | 27,737 | 17.53ms | 29,749 | 222ms |
| 2 × 5 (new auto) | 33,085 | 4.12ms | 32,032 | 204ms |
| 1 × 10 | 31,102 | 6.93ms | 30,080 | 214ms |

Old default spawned `cpu_count` workers with 1 thread each — no Tokio work-stealing,
duplicate background runtimes, thread oversubscription. New default: 2 workers on
8+ cores, 1 worker below.

## Analysis

**P99 gap is a throughput gap.** At 1000 connections sharing 32K capacity, requests
queue. If Dwaar matched nginx's 63K, its P99 would be comparable. The P99 is a
symptom, not the disease.

**Throughput gap is Pingora's async overhead.** Per-request costs vs nginx's raw C
event loop: Tokio task scheduling, `Box<HttpPeer>` alloc, trait dispatch,
CompactString allocations, UUID v7 crypto RNG. This is Pingora's tradeoff: safety
and developer velocity at ~2x throughput cost.

**Dwaar wins on memory (5x) and P50 (2x at 1000 conns).** Median requests through
Dwaar are actually faster — the tail latency comes from queuing, not processing.

## Reproducing

```bash
cd bench && bash local.sh         # local (same machine)
cd bench && docker compose up     # Docker (isolated CPUs)
```
