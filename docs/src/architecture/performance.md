# Performance

> Benchmarks will be published after Phase 13 (ISSUE-042, ISSUE-043).

## Design Targets

| Metric | Target |
|--------|--------|
| Requests/sec (single core) | >100K |
| P99 latency overhead | <1ms |
| Memory (100 domains, analytics on) | ~25 MB |
| TLS handshake (cached cert) | <2ms |
| Config reload | <10ms |
| Zero-downtime upgrade | 0 dropped connections |

## Performance Principles

- **Lock-free reads** — Route table uses ArcSwap (~1ns per lookup)
- **Zero-copy** — Response body uses `bytes::Bytes` (reference counting, no memcpy)
- **Batch I/O** — Logs batch-written (200 entries per syscall)
- **Connection pooling** — Upstream connections reused (skip TCP handshake)
- **Async I/O** — Tokio event loop (one thread handles thousands of connections)
