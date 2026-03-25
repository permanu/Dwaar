# Dwaar Architecture

## Overview

Dwaar is a reverse proxy built on Cloudflare's Pingora framework. It combines Pingora's raw performance (~5 MB base, 5-10x nginx throughput) with Caddy-like ease of use (automatic HTTPS, simple config DSL) and built-in first-party analytics.

## System Context

```
Internet → Cloudflare Edge → CF Tunnel → Dwaar (:443) → App Containers
                                           │
                                           ├── Analytics collected (same-origin, ad-blocker-proof)
                                           ├── Request logged (34+ fields, batch-written)
                                           ├── Bot detected (UA + behavior)
                                           └── All in ~25 MB RAM
```

## Process Architecture

Dwaar runs as a single OS process with multiple Pingora Services, each on its own Tokio runtime:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Pingora Server                               │
│                   (Process Manager)                              │
│                                                                  │
│  Responsibilities:                                               │
│  • Signal handling (SIGQUIT=graceful upgrade, SIGTERM=shutdown)  │
│  • PID file management                                           │
│  • Listen FD transfer for zero-downtime upgrades                │
│  • Service lifecycle orchestration                               │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │   Proxy      │  │    Admin     │  │  Background Services   │  │
│  │   Service    │  │    Service   │  │                        │  │
│  │              │  │              │  │  • ACME Client          │  │
│  │  :80 (TCP)   │  │  :9876 (TCP) │  │  • Health Checker      │  │
│  │  :443 (TLS)  │  │  or UDS      │  │  • Cert Renewal        │  │
│  │              │  │              │  │  • Log Flusher          │  │
│  │  N threads   │  │  1 thread    │  │  • Docker Watcher      │  │
│  │  (work-steal │  │              │  │  • GeoIP Updater       │  │
│  │   or pinned) │  │              │  │                        │  │
│  └──────┬───────┘  └──────┬───────┘  │  1 thread each         │  │
│         │                 │          └────────────────────────┘  │
│         │                 │                                      │
│  Each service = own Tokio runtime = isolated thread pool         │
│  Services can declare dependencies (ACME must complete before    │
│  proxy accepts TLS)                                              │
└─────────────────────────────────────────────────────────────────┘
```

## Proxy Service: Request Lifecycle

Every HTTP request passes through Pingora's `ProxyHttp` trait hooks. Dwaar implements these hooks:

```
TCP Accept
  │
  ▼
TLS Handshake (if :443)
  │  ┌─────────────────────────────────────────────┐
  │  │ TlsAccept::certificate_callback()           │
  │  │  1. Extract SNI hostname from ClientHello    │
  │  │  2. Check cert cache (in-memory LRU)         │
  │  │  3. Cache miss → load from filesystem        │
  │  │  4. Load cert+key into OpenSSL               │
  │  │                                              │
  │  │ TlsAccept::handshake_complete_callback()     │
  │  │  Store domain info in TLS digest extension   │
  │  │  (available in all later phases)             │
  │  └─────────────────────────────────────────────┘
  │
  ▼
Phase 1: early_request_filter()
  • IP blocklist check
  • Rate limiting (pingora-limits)
  • ACME HTTP-01 challenge response (/.well-known/acme-challenge/)
  │
  ▼
Phase 2: request_filter()
  • Serve /_dwaar/* paths directly (analytics JS, beacon endpoint)
  • Bot detection (User-Agent analysis)
  • Visitor tracking (read/set encrypted first-party cookie)
  • Session management
  • GeoIP lookup (country from IP)
  • UTM parameter extraction
  • Store enrichment data in per-request CTX
  • WASM plugin request hooks
  │
  ▼
Phase 3: upstream_peer()
  • Read Host header
  • Lookup in RouteTable (ArcSwap, lock-free read ~1ns)
  • Return HttpPeer (upstream address + options)
  │
  ▼
Phase 4: upstream_request_filter()
  • Add X-Real-IP, X-Forwarded-For, X-Forwarded-Proto
  • Add X-Request-Id (auto-generated UUID)
  • Strip hop-by-hop headers
  │
  ▼
Phase 5: [PROXY TO UPSTREAM]
  • Connection pool lookup (keyed on addr+scheme+SNI)
  • Reuse existing connection or create new
  • Retry up to 3 times on connection failure
  │
  ▼
Phase 6: response_filter()
  • Add security headers (HSTS, X-Content-Type-Options, X-Frame-Options)
  • Add Server: Dwaar header
  • Detect Content-Type for body filter
  │
  ▼
Phase 7: response_body_filter()  ★ ANALYTICS INJECTION ★
  • If Content-Type is text/html:
    - Find </head>, inject: <script src="/_dwaar/a.js" defer></script>
    - Find </body>, inject: <noscript><img src="/_dwaar/p.gif"/></noscript>
  • Apply compression (gzip/brotli based on Accept-Encoding)
  • WASM plugin response hooks
  │
  ▼
Phase 8: logging()  (ALWAYS called, even on errors)
  • Build RequestLog struct (34+ fields)
  • Push to batch writer channel (async, non-blocking)
  • Update in-memory analytics aggregates
```

## Route Table

The route table maps domains to upstream addresses. It supports multiple config sources:

```
Config Sources (all compile to same internal struct):
  ┌──────────────┐
  │  Dwaarfile   │──parse──┐
  │  (startup)   │         │
  └──────────────┘         │
  ┌──────────────┐         │     ┌──────────────────────┐
  │  Admin API   │──parse──┼────▶│ DwaarConfig (internal)│
  │  (runtime)   │         │     │                      │
  └──────────────┘         │     │  Validated, typed    │
  ┌──────────────┐         │     └──────────┬───────────┘
  │Docker Labels │──parse──┤               │ compile
  │  (watch)     │         │               ▼
  └──────────────┘         │     ┌──────────────────────┐
  ┌──────────────┐         │     │  ArcSwap<RouteTable>  │
  │ Deploy Agent │──parse──┘     │                      │
  │  (UDS push)  │               │  Lock-free reads     │
  └──────────────┘               │  Atomic swap on      │
                                 │  config change       │
                                 │  ~1ns per lookup     │
                                 └──────────────────────┘
```

## TLS Architecture

```
Certificate Lifecycle:

1. Domain added to config
   │
   ▼
2. ACME Background Service
   • Check if cert exists in store
   • If not: request from Let's Encrypt (HTTP-01 or DNS-01)
   • Fallback: try ZeroSSL
   • Store cert+key to filesystem (PEM)
   │
   ▼
3. Cert Cache (in-memory)
   • LRU cache, ~1000 certs
   • Loaded on first TLS handshake for domain
   • TTL-based eviction
   │
   ▼
4. Renewal (background)
   • Check all certs daily
   • Renew 30 days before expiry
   • Atomic file replacement
   • Cache invalidation
   │
   ▼
5. TLS Handshake (per-connection)
   • SNI → cert cache lookup → load into OpenSSL
   • Exact match first, wildcard fallback
   • OCSP stapling (background fetch, cached)
```

## Analytics Architecture

Two complementary data paths:

```
Path 1: Server-Side (zero JavaScript, covers 100% of requests)
─────────────────────────────────────────────────────────────
  Every request → logging() callback → RequestLog struct
  │
  Fields: timestamp, method, path, status, response_time,
          client_ip, country, user_agent, referer, is_bot,
          bytes_sent, tls_version, cache_status
  │
  ▼
  Batch Writer (8192-entry channel, 200-row batches, 500ms flush)
  ▼
  Output: stdout (JSON) / file / SQLite / Unix socket

Path 2: Client-Side (JavaScript beacon, adds Web Vitals + interaction)
─────────────────────────────────────────────────────────────────────
  response_body_filter() injects <script src="/_dwaar/a.js">
  │
  Browser loads /_dwaar/a.js (~2KB gzipped, served from proxy memory)
  │
  Collects: page URL, referrer, screen size, Web Vitals (LCP/FID/CLS),
            scroll depth, time on page
  │
  Sends beacon to /_dwaar/collect (same-origin POST, no CORS)
  │
  request_filter() intercepts /_dwaar/collect → parse → enrich → aggregate
  │
  Never hits upstream. Entirely handled within the proxy.

Aggregation (in-memory, per-domain):
  • Page view counts (1-minute buckets)
  • Unique visitors (HyperLogLog sketch, ~12 KB per domain)
  • Top pages (min-heap, top 100)
  • Referrer breakdown (HashMap, bounded)
  • Country breakdown (HashMap, bounded)
  • Web Vitals percentiles (t-digest, p50/p75/p95/p99)
  • Status code distribution
  │
  Flush every 60s → output destination
```

## Plugin System

Two tiers of extensibility:

```
Native Plugins (Rust, compiled into binary)
────────────────────────────────────────────
  trait DwaarPlugin: Send + Sync {
      fn name(&self) -> &str;
      fn priority(&self) -> u16;  // execution order
      fn on_request(&self, req: &RequestHeader, ctx: &mut PluginCtx) -> PluginAction;
      fn on_response(&self, resp: &mut ResponseHeader, ctx: &mut PluginCtx) -> PluginAction;
      fn on_body(&self, body: &mut Option<Bytes>, eos: bool, ctx: &mut PluginCtx) -> PluginAction;
  }

  Built-in plugins:
  • AnalyticsPlugin     — JS injection + beacon collection
  • RateLimitPlugin     — per-IP/domain limits (pingora-limits)
  • BotDetectPlugin     — UA patterns + behavior heuristics
  • CompressionPlugin   — gzip/brotli/zstd auto-negotiation
  • SecurityPlugin      — HSTS, CSP, X-Frame-Options, etc.
  • CorsPlugin          — Cross-origin configuration
  • RedirectPlugin      — HTTP→HTTPS, www→apex, custom rules

WASM Plugins (any language → WASM, loaded at runtime) [Commercial]
──────────────────────────────────────────────────────────────────
  • wasmtime runtime (~10-15 MB when loaded)
  • Sandboxed: no filesystem, no network, memory-limited
  • Hot-loadable without proxy restart
  • Host functions expose request/response data
  • Use cases: custom auth, A/B testing, header rewriting
```

## Deploy Integration

When Dwaar runs as part of the Deploy platform:

```
User's VPS
┌──────────────────────────────────────────────────────┐
│                                                      │
│  Dwaar (Rust)  ◄──Unix Socket──►  Deploy Agent (Go)  │
│  :80, :443                        Docker management  │
│                                   gRPC to backend    │
│  Communication:                                      │
│  • Agent installs + auto-updates Dwaar binary        │
│  • Agent pushes routes via Admin API (Unix socket)   │
│  • Dwaar pushes analytics to Agent (Unix socket)     │
│  • Agent forwards analytics to Backend (gRPC)        │
│  • All local IPC, no network calls between them      │
│                                                      │
│  Docker Containers                                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │ App :3000│ │ App :8080│ │ PG :5432 │            │
│  └──────────┘ └──────────┘ └──────────┘            │
└──────────────────────────────────────────────────────┘
```

## Memory Budget (Typical Production, 100 Domains)

```
Component                          RAM
──────────────────────────────────────
Pingora core (proxy+TLS+pool)     ~5-8 MB
Route table (1000 domains)        ~2-5 MB
TLS cert cache (100 certs)        ~1-2 MB
ACME client state                 ~1 MB
Analytics buffer (8192 entries)   ~4 MB
Dwaarfile config                  <1 MB
Request logging buffer            ~2-4 MB
GeoIP Country DB                  ~5 MB
──────────────────────────────────────
TOTAL                             ~20-30 MB
──────────────────────────────────────

With WASM plugins loaded:          +10-15 MB
With GeoIP City DB:                +45 MB
```

## Key Data Structures

| Structure | Type | Purpose | Access Pattern |
|-----------|------|---------|----------------|
| RouteTable | `ArcSwap<HashMap<String, Route>>` | Domain→upstream mapping | Lock-free read (~1ns), atomic swap on change |
| CertCache | `LruCache<String, CertKeyPair>` | TLS cert/key pairs | Mutex-guarded, populated on first handshake |
| AnalyticsAgg | `DashMap<String, DomainMetrics>` | Per-domain metrics | Concurrent read/write, flushed every 60s |
| RequestLog | Channel `Sender<RequestLog>` | Access log entries | Bounded async channel, batch-consumed |
| VisitorId | Encrypted cookie value | Visitor tracking | AES-GCM encrypt/decrypt per request |
| BotRules | `Vec<Regex>` | Bot detection patterns | Compiled once, matched per request |

## Performance Targets

| Metric | Target | How |
|--------|--------|-----|
| Requests/sec (single core) | >100K | Pingora's async Rust engine |
| P99 latency overhead | <1ms | Lock-free route lookup, zero-copy where possible |
| Memory per idle connection | <1 KB | Pingora's connection pooling |
| TLS handshake (cached cert) | <2ms | In-memory cert cache, no disk I/O |
| Config reload | <10ms | ArcSwap atomic pointer swap |
| Analytics overhead per request | <50μs | Channel push + in-memory aggregation |
| Zero-downtime upgrade | 0 dropped connections | Pingora's FD transfer mechanism |
