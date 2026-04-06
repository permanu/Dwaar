---
title: "Performance Internals"
---

# Performance Internals

Dwaar is built to serve high-concurrency workloads with predictable tail latency. This page explains the implementation choices that make that possible, how to measure them, and how to go further with a PGO build.

---

## Design Principles

Every hot-path decision in Dwaar is justified by at least one of four pillars: Performance, Reliability, Security, or Competitive Parity. The table below covers the choices that directly affect throughput and latency.

| Technique | Crate / Module | Why it matters |
|-----------|---------------|----------------|
| **jemalloc allocator** | `tikv-jemallocator`, `crates/dwaar-cli/src/main.rs` | Eliminates heap fragmentation from per-request string alloc/free churn. Removes allocator lock contention that causes tail-latency spikes under high concurrency. Replaces the system allocator globally via `#[global_allocator]`. |
| **ArcSwap lock-free reads** | `arc-swap`, route table, config | Hot-reload swaps the entire route table atomically. Readers never block — a load takes ~1 ns and never contends with a concurrent reload. |
| **CompactString** | `compact_str`, `RequestLog`, context fields | Strings ≤24 bytes (method, status, short paths) are stored inline on the stack — no heap allocation, no pointer indirection. Reduces allocator pressure on the hot path. |
| **sonic-rs JSON serialization** | `sonic-rs`, `dwaar-log` | SIMD-accelerated JSON serialization. `RequestLog` serialization target is <1 µs per entry (see bench in `crates/dwaar-log/benches/request_log.rs`). |
| **Bytes zero-copy** | `bytes`, response body handling | Response bodies use `Bytes` reference-counted slices. Forwarding a response body from upstream to downstream copies zero bytes — only the reference counter increments. |
| **Connection-owned buffers** | `BufferedConn`, `crates/dwaar-core/src/quic/pool.rs` | Read buffers live with the pooled connection, not the request. Eliminates per-request 64 KB allocations in the H3 streaming path. Buffer starts at 8 KB and grows to 64 KB on demand. Zero-copy via `BytesMut::split_to().freeze()`. |
| **H2 upstream multiplexing** | `H2ConnPool`, `crates/dwaar-core/src/quic/h2_pool.rs` | When `transport h2` is configured, H3 streams multiplex onto 1-2 shared H2 connections per upstream host. Reduces 5,000 TCP connections to ~20-40. GOAWAY-aware with automatic retry for idempotent methods. |
| **Batch log writing** | `dwaar-log`, `BatchWriter` | Log entries are queued in a channel and flushed in batches of up to 200 entries per syscall. Removes one `write()` syscall per request from the hot path. |
| **Pingora work-stealing scheduler** | `pingora-core` | Pingora uses Tokio with a work-stealing thread pool. Idle threads steal tasks from busy threads, keeping all cores saturated without manual thread pinning. |
| **Multi-worker fork** | `crates/dwaar-cli/src/main.rs` | `dwaar run --workers N` forks N worker processes before Pingora initializes. Each worker owns its own Tokio runtime and memory space. CPU-bound work scales linearly with cores. |
| **Single ArcSwap load per request** | `RequestContext`, `crates/dwaar-core/src/context.rs` | `RequestContext` loads the route table once at the start of `request_filter` and caches all derived values. Downstream callbacks read from `RequestContext` — no second ArcSwap load. |

---

## Memory Profile

Dwaar's memory footprint is small and predictable. It does not grow with traffic volume — only with configuration complexity.

| Configuration | Approximate RSS |
|---------------|----------------|
| Single site, analytics off | ~5 MB |
| 100 domains, analytics on | ~25 MB |
| Per active downstream connection (Pingora H1/H2) | ~135 KB |
| Per active upstream connection (H1, pooled) | ~8 KB (connection-owned buffer) |
| Per active upstream connection (H2, multiplexed) | ~150 KB (shared across all streams) |
| Per H3 request stream overhead | ~1 KB (no per-request buffer alloc) |
| HTTP cache (depends on `max_size` setting) | bounded by config |

The dominant allocations at steady state are:

- **Route table** — one `Arc<RouteTable>` per active generation (two during hot-reload). Each compiled route holds pre-compiled regex matchers.
- **Connection buffers** — Pingora allocates read/write buffers per connection. Connections are released back to the OS on close.
- **Log channel** — bounded MPSC channel holds at most ~200 log entries between flushes (~200 KB peak).
- **Analytics aggregations** — HyperLogLog sketches and TDigest accumulators are fixed-size per domain (~4 KB per domain).

If RSS grows continuously over hours, the likely cause is an unbounded HTTP cache. Set an explicit limit:

```
cache {
    max_size 512mb
}
```

---

## Benchmarks

The `benchmarks/docker/` directory contains a fully reproducible Dwaar-vs-nginx benchmark.

### Setup

Three Docker containers run on the same host, each limited to 2 CPU cores and 256 MB RAM:

| Container | Role | Port |
|-----------|------|------|
| `backend` | nginx serving a static 200 OK | 9090 |
| `dwaar` | Dwaar proxying to `backend` | 6188 |
| `nginx-proxy` | nginx proxying to `backend` | 8080 |

The benchmark tool is [wrk](https://github.com/wg/wrk).

### Running

```bash
cd benchmarks/docker
./run-benchmark.sh
```

The script runs three connection levels (100, 500, 1000) against each target for 30 seconds each and prints a comparison table:

```
Proxy        Conns     RPS          p50 lat    p99 lat    Avg lat    Transfer     Mem(MB)
──────────   ──────    ──────────   ────────   ────────   ────────   ──────────   ──────
direct       100       ...          ...        ...        ...        ...          n/a
DWAAR        100       ...          ...        ...        ...        ...          ...
NGINX        100       ...          ...        ...        ...        ...          ...
```

To customize duration, threads, or connection counts:

```bash
BENCH_DURATION=60s BENCH_THREADS=8 BENCH_CONNECTIONS="100 1000 5000" ./run-benchmark.sh
```

### What the numbers mean

- **RPS** — requests per second. Dwaar targets >100K RPS on a single core for simple proxy workloads.
- **p99 latency** — Dwaar's proxy overhead target is <1 ms added to upstream latency at p99.
- **Memory** — Dwaar's base footprint should be lower than nginx under equivalent load because jemalloc eliminates fragmentation and the route table is a single ArcSwap read.

---

## Profiling

### CPU flamegraph (Linux)

```bash
# Record with perf
sudo perf record -F 99 -p $(pgrep dwaar) -g -- sleep 30
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > dwaar.svg
```

On macOS, use `cargo flamegraph`:

```bash
cargo install flamegraph
sudo cargo flamegraph --bin dwaar -- run --config Dwaarfile
```

Open `flamegraph.svg` in a browser. Look for wide frames in:
- `DwaarProxy::request_filter` — route lookup and plugin chain
- `DwaarProxy::logging` — JSON serialization
- `BatchWriter::flush` — log I/O

### Criterion microbenchmarks

```bash
# Run all benchmarks and open the HTML report
cargo bench
open target/criterion/report/index.html

# Run only the log serialization bench
cargo bench -p dwaar-log
```

Criterion benches live in:
- `crates/dwaar-log/benches/request_log.rs` — `RequestLog` JSON serialization (<1 µs target)

### jemalloc allocation stats

To see allocator stats at runtime without restarting:

```bash
MALLOC_CONF=stats_print:true dwaar run --config Dwaarfile 2>&1 | grep -A 40 "jemalloc stats"
```

This prints arena utilization, fragmentation ratio, and per-size-class counts. A fragmentation ratio above 1.3 is worth investigating.

---

## PGO Build

Profile-Guided Optimization feeds real traffic patterns back to LLVM so it can inline hot functions, reorder basic blocks, and eliminate cold-path checks from the fast path. Typical gain is 5–15% throughput improvement.

### Running the PGO pipeline

```bash
./scripts/pgo-build.sh
```

The script runs four steps automatically:

```
Step 1 — Instrumented build    (RUSTFLAGS=-Cprofile-generate=...)
Step 2 — Profile collection    (30s of real or simulated traffic)
Step 3 — Merge profiles        (llvm-profdata merge)
Step 4 — PGO-optimized build   (RUSTFLAGS=-Cprofile-use=...)
```

### Using a custom workload

The default workload is a simple `curl` loop. For a more representative profile, point the script at your stress suite:

```bash
PGO_WORKLOAD=/path/to/my-workload.sh PGO_DURATION=60 ./scripts/pgo-build.sh
```

The workload script receives `STRESS_TARGET=host:port` in its environment.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROFILE_DIR` | `target/pgo-profiles` | Where `.profraw` files are stored |
| `PGO_DURATION` | `30` | Seconds to run the profiling workload |
| `PGO_WORKLOAD` | — | Path to a custom workload script |
| `DWAAR_CONFIG` | auto-generated | Dwaarfile to use during profiling |

### Prerequisites

```bash
rustup component add llvm-tools   # provides llvm-profdata
```

On macOS, `llvm-profdata` can also be found via `xcrun`. The script detects all three locations automatically.

---

## Related

- [Compression](../features/compression.md) — gzip / brotli / zstd reduce bytes transferred, shifting the bottleneck from network to CPU.
- [Caching](../features/caching.md) — `pingora-cache` eliminates upstream round-trips for cacheable responses.
- [HTTP/3](../features/http3.md) — QUIC reduces connection setup latency and eliminates head-of-line blocking.
- [Timeouts](../features/timeouts.md) — Proper timeout configuration prevents slow upstreams from exhausting connection pool slots.
