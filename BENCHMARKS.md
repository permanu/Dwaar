# Dwaar vs nginx Benchmark (2026-04-06)

## Setup
- **Machine**: macOS Darwin 25.3.0, Apple Silicon, 10 cores
- **Backend**: Rust TCP server (thread-per-conn), keep-alive, 27-byte JSON
- **Load generator**: wrk 4.2.0, 4 threads, 10s duration, 2s warmup
- **Dwaar**: v0.1.0 release, `--bare --workers 2` (2 processes × 5 tokio threads)
- **nginx**: 1.27.1, `worker_processes auto` (10 workers), `keepalive 128`, `access_log off`

## Results

| Proxy | Conns | Req/sec | P50 | P99 | RSS |
|-------|-------|---------|-----|-----|-----|
| **Dwaar** | 100 | 31,982 | 3.02ms | 8.03ms | 6 MB |
| **nginx** | 100 | 63,059 | 1.50ms | 19.37ms | 30 MB |
| **Dwaar** | 500 | 31,815 | 7.12ms | 78.55ms | 6 MB |
| **nginx** | 500 | 66,660 | 7.37ms | 21.19ms | 30 MB |
| **Dwaar** | 1000 | 32,690 | 7.87ms | 174.98ms | 6 MB |
| **nginx** | 1000 | 63,220 | 15.48ms | 24.46ms | 30 MB |

## Analysis

### What Dwaar wins
- **Memory**: 5x more efficient (6 MB vs 30 MB)
- **Throughput stability**: flat 32K at all concurrency levels (no degradation)

### What nginx wins
- **Raw throughput**: 2x (63K vs 32K)
- **P99 under load**: 7x at 1000 conns (24ms vs 175ms)
- **P99 scaling**: nearly flat (19ms → 24ms); Dwaar grows 22x (8ms → 175ms)

### Root cause: Pingora's async overhead vs nginx's bare event loop

nginx uses a hand-tuned C event loop with zero abstraction overhead. Each
worker is a single-threaded `epoll`/`kqueue` loop handling thousands of
connections with no scheduler, no task queue, no trait objects.

Dwaar/Pingora uses Rust async/await on Tokio. Per-request overhead includes:
- Tokio task scheduling + wake/poll cycles
- `Box<HttpPeer>` heap allocation per request
- Trait object dispatch through `ProxyHttp` hooks
- CompactString allocations for host/method/path/request_id
- UUID v7 generation (crypto RNG) per request

The throughput cap at ~32K RPS is Pingora's ceiling for this workload, not
Dwaar-specific. The P99 growth is queuing: at 1000 conns sharing 32K RPS
capacity, the 99th percentile request waits in the Tokio task queue.

### Worker configuration matters

| Workers × Threads | c=100 RPS | c=100 P99 | c=1000 RPS | c=1000 P99 |
|-------------------|-----------|-----------|------------|------------|
| 10 × 1 (default) | 27,737 | 17.53ms | 29,749 | 222.71ms |
| 2 × 5 (optimal) | 33,343 | 4.09ms | 32,743 | 178.39ms |
| 1 × 10 | 31,102 | 6.93ms | 30,080 | 214.48ms |

Default auto (N workers × 1 thread each) is suboptimal. 2 workers × 5
threads gives 20% better throughput and 4x better P99 at low concurrency.

### Root cause: worker count × thread oversubscription

Each Pingora worker spawns its own Tokio runtime plus background services
(admin API, health checker, config watcher, log writer). With 10 workers
on a 10-core machine, each gets 1 Tokio thread — no work-stealing possible.
The 10 separate admin API runtimes alone create 80+ threads idle on
pthread_cond_wait, consuming scheduler attention and cache.

Fix (committed): default auto now uses `(cores / 4).clamp(1, 4)` workers
instead of `cores`. On a 10-core machine: 2 workers × 5 threads each,
giving proper work-stealing within each runtime.

### Remaining gap: Pingora vs nginx async overhead

The 2x throughput gap is structural — Pingora's async/await model has
irreducible per-request overhead compared to nginx's raw C event loop:
- Tokio task scheduling + wake/poll cycles per request
- `Box<HttpPeer>` heap allocation per upstream_peer() return
- Trait object dispatch through ProxyHttp hooks
- CompactString allocations for host/method/path
- UUID v7 generation (crypto RNG) for request_id

This is Pingora's design tradeoff: developer productivity + safety at the
cost of ~2x raw throughput vs hand-tuned C. Cloudflare accepts this because
Pingora replaces nginx for them at the CDN edge where features matter more
than raw RPS on a single machine.
