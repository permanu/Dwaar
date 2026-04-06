# Changelog

The full, version-by-version changelog lives in the repository root:

**[CHANGELOG.md](https://github.com/permanu/dwaar/blob/main/CHANGELOG.md)**

That file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each release entry lists Added, Changed, Fixed, and Removed items.

---

## Major Milestones

The table below summarizes what each phase of Dwaar's development delivered. These correspond to the progressive build plan in the issue tracker.

| Phase | Name | Key Deliverables |
|-------|------|-----------------|
| 0–1 | Foundation | Cargo workspace, CI, BSL-1.1 license, Pingora integration, ProxyHttp engine, graceful shutdown |
| 2 | Route Table & Config | ArcSwap route table, Dwaarfile tokenizer and parser, hot-reload, TLS/header/redirect directives |
| 3 | TLS & HTTPS | SNI cert store, automatic HTTPS redirect, ACME Let's Encrypt (HTTP-01), certificate watcher |
| 4 | Request Logging | Structured JSON logs (22 fields), batch writer, log rotation |
| 5 | Admin API | REST admin service (`/routes`, `/certs`, `/reload`, `/metrics`), Unix domain socket listener, bearer token auth |
| 6 | Analytics | JS beacon injection, HyperLogLog visitor counting, Top-K pages, TDigest Web Vitals, per-domain aggregation |
| 7 | Bot & Rate Limiting | RegexSet bot detection, sliding-window rate limiter, Under Attack mode |
| 8 | Docker Integration | Docker label discovery, deploy agent |
| 9 | GeoIP | MaxMind mmdb lookup, `country` field in request logs |
| 10 | Compression | gzip / brotli / zstd response compression plugin with automatic content negotiation |
| 11 | Plugin System | `DwaarPlugin` trait, `PluginChain` with priority sorting, basicauth, security headers plugins |
| 12 | CLI Polish | `routes` / `certs` / `reload` / `upgrade` subcommands, PID management |
| 13 | Performance | Criterion benchmarks, stress tests, jemalloc allocator, `CompactString`, `sonic-rs` JSON |
| 14 | Caddy Directive Parity | `handle`, `handle_path`, `route`, `respond`, `rewrite`, `uri`, `error`, `abort`, `method`, `request_body`, `try_files`, `forward_auth`, named matchers |
| 15 | Full Caddyfile Runtime | Template engine, `VarRegistry`, 13 typed directives, parser modularization, multi-worker fork, feature toggles, PGO build |
| 16 | Remaining Gaps | Tokenizer fixes, `handle_errors`, per-site log output, block-form `reverse_proxy` with load balancing and health checks, `bind`, `intercept` / `copy_response` |
| 17 | Production Viability | WebSocket proxy, body size limits, IP allowlist/blocklist (CIDR trie), Prometheus metrics, HTTP cache (`pingora-cache`), gRPC transparent proxy |
| 18 | Competitive Parity | Connection draining, slow-loris timeouts, mTLS upstream, QUIC scaffold, `Alt-Svc` header |
| 19 | Differentiation | DNS-01 ACME wildcard certificates (Cloudflare provider), scale-to-zero wake |
| 20–22 | Kubernetes Ingress | `dwaar-ingress` crate, K8s reflector watchers, Ingress-to-route translator, TLS secrets, leader election, annotations, Helm chart, integration tests |
| 23–24 | WASM Runtime | Wasmtime component model, WIT interface, host functions, resource limits (fuel / memory / timeout), module caching, auto-disable on repeated traps |
| 25 | HTTP/3 Full Flow | h3 request parsing, proxy bridge, connection lifecycle, 0-RTT, flow control |
| 26 | Observability Pipeline | W3C `traceparent` propagation, process metrics, rate/cache Prometheus counters, log socket and file rotation, `AnalyticsSink` trait, upstream error body capture |
| 27 | H3 Memory & Performance | Connection-owned `BufferedConn` (zero per-request alloc), H2 upstream multiplexing (`transport h2`), zero-copy body streaming, `TCP_NODELAY`, jemalloc heap profiling feature, chunked/decompressor buffer caps |

| 27 | Hot Reload + H3 Completion | Streaming H3 → upstream bridge, upstream connection pool, hot reload for health-check pools, ACME domain coverage, and cache sizing |

---

## Versioning Policy

Dwaar follows Semantic Versioning:

- **Patch** releases fix bugs without changing configuration semantics.
- **Minor** releases add features in a backward-compatible way.
- **Major** releases may change the Dwaarfile format or remove deprecated directives. Migration guides are published in `docs/src/migration/`.
