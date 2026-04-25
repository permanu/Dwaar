# Changelog

All notable changes to Dwaar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`auto_update { enabled / drain_timeout_secs / health_check_url / rollback_on_health_fail }` knobs** —
  Four new fields in the `auto_update { }` global-options block:
  - `enabled` (bool, default `true`) — toggle the background check loop without removing the config block.
  - `drain_timeout_secs` (u64, default `60`) — how long the parent process waits for in-flight requests to drain after the new binary is healthy before exiting.
  - `health_check_url` (string, default `http://127.0.0.1:6663/healthz`) — URL polled after spawning the new binary; `200` means ready.
  - `rollback_on_health_fail` (bool, default `true`) — kill the new binary and keep the parent running if the health check never passes within `drain_timeout_secs`.

- **SIGUSR2 graceful-upgrade orchestration** — the running parent now installs a SIGUSR2 handler. On signal receipt:
  1. Spawns `<argv[0]> --upgrade` (or the path in `DWAAR_UPGRADE_BINARY` if set) with `DWAAR_UPGRADE_SOCK` forwarded so parent and child share a single FD-transfer rendezvous socket.
  2. Polls `health_check_url` until `200` or `drain_timeout_secs` elapses.
  3. On success sends itself SIGQUIT → Pingora graceful drain + exit.
  4. On failure kills the child and stays up (rollback).
  - `DWAAR_UPGRADE_SOCK` env overrides the default upgrade socket path (`/run/dwaar/upgrade.sock`).
  - `DWAAR_UPGRADE_FROM=1` env is equivalent to `--upgrade` so the installer can trigger the child-side FD-receive without modifying argv.
  - The parent binary path may be atomically replaced via `rename(2)` while the process is running (Linux inode semantics); re-exec'ing `argv[0]` picks up the new binary from the filesystem.

- **Admin `GET /healthz`** — unauthenticated liveness probe. Returns `200 {"status":"ok"}` while the proxy is up, `503 {"status":"draining"}` once the server enters the graceful-shutdown drain window. Used by the upgrade orchestrator and external health checkers.

- **Admin `GET /version`** — unauthenticated. Returns `{"version":"<semver>","started_at":"<rfc3339>","pid":<int>}`. Lets the installer confirm the new binary is answering and verify the PID changed after a successful upgrade.

### Security
- Release binaries are now signed with cosign (keyless OIDC). `install.sh` verifies the signature when cosign is installed. Verification command: `cosign verify-blob --certificate-identity-regexp "^https://github.com/permanu/Dwaar/\\.github/workflows/release\\.yml@.*" --certificate-oidc-issuer "https://token.actions.githubusercontent.com" --certificate <binary>.cert --signature <binary>.sig <binary>`. Permanu's auto-update agent verifies the same way before swapping any binary.

## [0.3.9] - 2026-04-25

First tagged release covering the v0.3.7 OTLP/sample_ratio work, which
was internally version-bumped in main (#218) but never had a tag or
GitHub release cut for it. v0.3.9 supersedes both (the v0.3.8 tag failed to publish — LICENSE version mismatch in CI). Ships the
following on top of v0.3.6:

### Security

- **rustls-webpki 0.103.13** (was 0.103.11) — fixes
  [GHSA-82j2-j2ch-gfr8](https://github.com/rustls/webpki/security/advisories/GHSA-82j2-j2ch-gfr8)
  (reachable panic when parsing a CRL with negative `thisUpdate` /
  `nextUpdate`) and [GHSA-965h-392x-2mh5](https://github.com/rustls/webpki/security/advisories/GHSA-965h-392x-2mh5)
  follow-on (URI name constraint exclusion logic was inverted, allowing
  excluded URIs to validate). Pulled in via `pingora-core` and the rustls
  TLS stack — every Dwaar build is exposed.
- **openssl 0.10.78 + openssl-sys 0.9.114** — patches a dangling stack
  pointer in custom-extension callbacks, an OID handling panic, an
  AES key-unwrap bounds check, and callback length validation. No CVE
  ID assigned but memory-safety relevant.

### Added (carried forward from internal v0.3.7)

- **OTLP ingress span per request** — Dwaar now emits one OpenTelemetry
  span for every proxied HTTP request when `tracing { otlp_endpoint }` is
  configured. Exported via the existing `dwaar-analytics` OTLP/HTTP path
  and appears as the root node (or child of the client's span) in the
  Permanu trace viewer.
- **W3C Trace Context child-span propagation** — when a request carries
  `traceparent`, Dwaar generates a *child* span (same `trace_id`, fresh
  `span_id`) and injects the new context upstream so downstream services
  nest under the Dwaar ingress span. Fresh root span when no
  `traceparent` is present.
- **`sample_ratio` config knob** — `tracing { sample_ratio 0.1 }` records
  only a fraction of requests (range `[0.0, 1.0]`, default `1.0`) for
  cost-controlled sampling on high-traffic sites.
- **Semantic-convention attributes on the ingress span** —
  `http.request.method`, `http.response.status_code`, `url.path`,
  `url.scheme`, `server.address`, `client.address`, `dwaar.upstream`,
  request/response body sizes, and `dwaar.tls.version` (when TLS).
- **Error-capture script auto-injection for HTML responses** (#217) —
  Dwaar can now inject a small client-side error-capture snippet into
  HTML responses for first-party error tracking.

### Fixed

- **Non-finite `sample_ratio` no longer silently disables tracing.**
  `f64::parse` accepts `"nan"`, `"inf"`, `"-inf"` as valid floats and
  `NaN.clamp()` propagates NaN unchanged, so a typo'd
  `sample_ratio nan` would zero sampling without warning
  (`fastrand::f64() < NaN` is always false). Parser now adds an
  `is_finite()` guard so non-finite values fall back to the default
  `1.0`. Regression test covers `nan`, `inf`, `-inf`, `NaN`, `Inf`.

### Changed

- `TracingConfig` gains a `sample_ratio: f64` field (default `1.0`).
  Existing Dwaarfiles without `sample_ratio` continue to record every
  request unchanged.
- The OTLP exporter `Arc` is now shared between `DwaarProxy` (records
  spans on the hot path) and the background flush loop, eliminating the
  prior double-initialisation.

### CI

- Workflows optimised: macOS dropped from the test matrix (release.yml's
  cross-compile matrix covers it at tag time), build job is dev-profile
  not `--release` (release-profile compilation moves to tag-time only),
  `cargo install cargo-deny / cargo-audit` replaced with
  `taiki-e/install-action` (~5s prebuilt binary vs ~2-3min source
  compile), `concurrency.cancel-in-progress` added to ci.yml + audit.yml
  so rapid pushes don't pile up redundant runs, `Swatinem/rust-cache`
  added to the fmt job. Net wall time per PR drops ~5-10 min.
- `cargo fmt --all` + `cargo clippy --fix` cleanup applied across
  `parser/tests.rs`, `proxy.rs`, and `error_script_injection.rs` (carry-
  over from prior releases that landed without local fmt/clippy).

## [0.3.7] - 2026-04-24

### Added

- **OTLP ingress span per request** — Dwaar now emits one OpenTelemetry
  span for every proxied HTTP request when `tracing { otlp_endpoint }` is
  configured. The span is exported to the OTLP/HTTP collector via the
  existing `dwaar-analytics` exporter and appears as the root node (or
  child of the client's span) in the Permanu trace viewer.
- **W3C Trace Context child-span propagation** — when an inbound request
  carries a `traceparent` header, Dwaar now generates a *child* span
  (same `trace_id`, fresh `span_id`) instead of propagating the client's
  span unchanged. The child context is injected into the upstream request
  so downstream services appear nested under the Dwaar ingress span.
  When no `traceparent` is present, a fresh root span is generated as
  before.
- **`sample_ratio` config knob** — operators can set
  `sample_ratio 0.1` inside the `tracing { }` block to record only a
  fraction of requests (range `[0.0, 1.0]`, default `1.0`). Useful for
  high-traffic sites where full sampling is cost-prohibitive.
- **Semantic convention attributes on ingress span** — the span carries
  `http.request.method`, `http.response.status_code`, `url.path`,
  `url.scheme`, `server.address`, `client.address`, `dwaar.upstream`,
  `http.request.body.size`, `http.response.body.size`, and
  `dwaar.tls.version` (when TLS).

### Changed

- `TracingConfig` gains a `sample_ratio: f64` field (default `1.0`).
  Existing Dwaarfiles without `sample_ratio` continue to record every
  request unchanged.
- The OTLP exporter `Arc` is now shared between `DwaarProxy` (records
  spans on the hot path) and the background flush loop, eliminating the
  double initialisation that existed previously.

## [0.3.6] - 2026-04-18

### Added

- **Response-latency bucket histogram** — on every request,
  `DomainMetrics` now records the server-observed response latency in a
  fixed ten-bucket histogram (`BucketHistogram`). Edges in milliseconds:
  `[10, 50, 100, 250, 500, 1000, 2500, 5000, 10000, +Inf]`. Cardinality
  is bounded at ten labels by construction, so downstream VictoriaMetrics
  fan-out is capped at `10 × domains` regardless of traffic volume.
- **`response_latency_buckets` on every analytics snapshot** — the
  histogram surfaces on `DomainMetricsSnapshot` (socket sink),
  `FlushSnapshot` (stdout-legacy), and `AnalyticsSnapshot` (Admin API)
  in the same `(le_label, count)` shape so consumers can parse any of
  the three paths with one decoder. Always emitted in order with zero
  counts included — downstream heatmaps key on a stable label axis.
- **Window-delta semantics** — the histogram is zeroed by `flush()`
  after serialisation, matching the existing `status_codes` /
  `bytes_sent` / bot-vs-human per-window reset discipline so operators
  reading the flushed stream see deltas across windows rather than a
  perpetually growing lifetime total.

### Changed

- `AggEvent` gains a `response_latency_us: u64` field so the proxy
  hot-path can propagate the already-measured `response_time_us` into
  the analytics aggregator without duplicating the clock read. The
  microsecond unit matches `RequestLog::response_time_us` verbatim.

## [0.3.5] - 2026-04-18

### Added

- **UTM term + content labels** — `extract_utm_params()` now returns all
  five UTM fields. `utm_terms` + `utm_contents` aggregate into
  `BoundedCounter<25>` (tighter cap than source/medium/campaign because
  term/content are more ad-hoc). Surfaced on all three snapshot paths.
  Completes Plausible-level attribution coverage.

### Fixed

- **Release workflow installs `protoc`** — `dwaar-grpc`'s build.rs
  invokes `prost-build` which shells out to `protoc`. Ubuntu-latest and
  macos-latest runners no longer ship it preinstalled, so the release
  build silently failed for `v0.3.4`. Workflow now installs
  `protobuf-compiler` on Linux and homebrew `protobuf` on macOS before
  `cargo build`.

## [0.3.4] - 2026-04-18

### Added

- **UTM source / medium / campaign labels** — when a request carries
  `utm_*` query params, Dwaar aggregates them into per-domain
  `BoundedCounter` (50 / 20 / 50). Case-folded and trimmed before
  counting. Surfaced on `DomainMetricsSnapshot` / `FlushSnapshot` /
  `AnalyticsSnapshot` via `utm_sources` / `utm_mediums` /
  `utm_campaigns`. Powers marketing-attribution dashboards.
- **Status-class counters** — the 1xx / 2xx / 3xx / 4xx / 5xx counters
  already computed in `AggEvent` now surface on every snapshot as
  `status_classes: Vec<(class, count)>`. Fixed cardinality (5 labels)
  → safe for VictoriaMetrics fan-out at any scale.
- **Referrer / device / top-path emission** — previously-bounded
  counters (referrers top-50, top-pages top-100) and new device
  classification (desktop / mobile / tablet / bot / unknown via UA
  heuristic) are now included in every flushed snapshot. Unblocks the
  Plausible-parity referrer and device panels in the Permanu UI.

## [0.3.3] - 2026-04-17

Wheel #2 Weeks 4–5 — proxy hot-path integration and server-initiated event
stream.

### Added

- **Proxy consults the split registry on every request** — a matched
  `SplitTraffic` config for the current domain now steers the upstream pick
  through a weighted choice. When no split is installed the dispatcher
  bypasses the registry entirely, so single-upstream routes pay nothing.
  Registries moved from `dwaar-grpc` into a new `dwaar_core::registries`
  module so the hot path can consult them without the control-plane crate
  taking a circular dependency on `dwaar-core`.
- **Fire-and-forget mirror traffic** via `MirrorDispatcherImpl` —
  `request_filter` spawns a detached tokio task per matching request that
  replays the method + path + headers to `mirror_to`. Sample rate is
  enforced with `sample_rate_bps`; mirror failures never influence the
  primary response. A new Prometheus counter `dwaar_mirror_requests_total`
  (labels: `source_domain`, `mirror_to`, `outcome={sent|sampled_out|error}`)
  is exposed via `MirrorMetrics::render`.
- **`SetHeaderRule` handler** + `HeaderRuleRegistry`. Header rules are
  strictly more specific than traffic splits — when both are installed
  for the same domain the header rule wins and overrides the default
  upstream. The pb `action == "route_to"` repurposes `header_value` as the
  override upstream address (single-pair matches, Week 4 scope).
- **Server-initiated event stream** (Wheel #2 Week 5). New `EventBus`
  multiplexes `AnomalyEvent`, `TrafficSpikeEvent`, and `LiveLogChunk`
  messages to every connected gRPC peer. A per-domain `AnomalyDetector`
  drives thresholds: 5xx rate > 1 % over a 60 s rolling window; P95
  latency > 2× the 10-min baseline; traffic RPS > 2× the 5-min moving
  average sustained ≥ 30 s. `LogChunkBuffer` batches structured log
  chunks every 200 ms (caps: 100 lines / 64 KB / chunk).
- Bounded mpsc subscriber queues (depth 256) with oldest-drop on
  backpressure and a drop counter, so publishers never block primary
  request flow.

### Changed

- `DwaarProxy::new` gains three optional wiring methods —
  `with_control_plane`, `with_mirror_dispatcher`, `with_outcome_sink` —
  that populate the new hot-path hooks. `None` keeps the pre-existing
  single-upstream fast path unchanged.
- `dwaar-cli` builds the `DwaarControlService` up-front and threads its
  registries into `DwaarProxy` before the proxy service is registered,
  so every worker observes the same shared state.

### Tests

- 10 proxy-level integration tests in
  `crates/dwaar-grpc/tests/proxy_integration.rs` covering split
  100→50/50→100 transitions, mirror dispatch against a real `TcpListener`,
  mirror error / sampled-out counters, header-rule match semantics, the
  event-bus drop-on-backpressure behaviour, anomaly emission, and log-chunk
  batching.
- Unit tests for `SplitRegistry`, `MirrorRegistry`, `HeaderRuleRegistry`,
  `AnomalyDetector`, `LogChunkBuffer`, and `MirrorDispatcherImpl`.

## [0.2.11] - 2026-04-13

### Fixed

- **L4 listeners now dual-stack (IPv4 + IPv6)** — bare `:port` in layer4
  config now binds to `[::]` instead of `0.0.0.0`, enabling both IPv4 and
  IPv6 connections on the same listener. Linux dual-stack sockets accept
  both address families by default.

## [0.2.10] - 2026-04-13

Layer 4 TLS termination with explicit cert/key — enables encrypted database
and TCP proxy connections without an HTTP site block.

### Added

- **L4 TLS with explicit cert/key paths** — the `tls { cert ... key ... }`
  config block in layer4 handlers now loads certs directly from disk instead
  of requiring a shared HTTP `CertStore` entry. This enables TLS termination
  for L4-only services like PostgreSQL, MySQL, and Redis proxies where no
  corresponding HTTP site block exists.
- Two-mode TLS resolution: explicit cert/key paths take priority; falls back
  to `CertStore` SNI lookup for domains that share certs with HTTP sites.

### Example

```
layer4 {
    :5432 {
        route {
            tls {
                cert /etc/dwaar/certs/db.crt
                key  /etc/dwaar/certs/db.key
            }
            proxy 172.18.0.2:5432
        }
    }
}
```

External clients connect with `sslmode=require` and Dwaar terminates TLS
before forwarding plaintext to the container on the same host.

## [0.2.9] - 2026-04-13

Hotfix: imported config files now work with hot-reload.

### Fixed

- **Import resolution used CWD instead of config directory** — `parser::parse()`
  resolved `import` paths relative to the working directory, not the Dwaarfile's
  parent. On servers where CWD is `/`, imported files were never found.
- **Imported file changes didn't trigger reload** — the content hash was computed
  from the raw Dwaarfile only. Now hashes the expanded content (after import
  expansion) so changes to any imported file trigger a reload.
- **Config watcher now watches recursively** — `RecursiveMode::Recursive` ensures
  changes to imported files in subdirectories (e.g. `apps/*.dwaar`) are detected.
- Added `parse_expanded()` entry point for pre-expanded config text, avoiding
  double import expansion in the watcher.

## [0.2.8] - 2026-04-13

Layer 4 hot-reload — the last major gap for zero-touch deploy automation.

### Added

- **Layer 4 hot-reload** — `Layer4Service` now uses `ArcSwap` + `Notify` for
  dynamic listener management. On config reload: new L4 ports are bound, removed
  ports are cancelled, and routes on existing ports are swapped — no restart
  needed. Follows the same proven pattern as health pools and ACME domains.
- Added `tokio-util` dependency to `dwaar-core` for `CancellationToken` in
  L4 listener lifecycle management.

## [0.2.7] - 2026-04-13

Deploy agent compatibility patch.

### Fixed

- **Empty config no longer prevents startup** — Dwaar now starts with zero
  routes and logs a warning, allowing the config watcher to pick up routes
  on reload. Previously it would bail with "no valid routes found."
- **`dwaar reload` admin endpoint discovery** — the server now writes the
  active admin endpoint to `/tmp/dwaar-admin.addr` on startup. `dwaar reload`
  reads this file to discover the correct address, eliminating hardcoded UDS
  paths. Works with any `--admin-socket` value.

### Tests

- Added `imported_layer4_block_parsed` test confirming that `layer4 {}`
  blocks imported via `import` directives are correctly parsed.

## [0.2.6] - 2026-04-13

Hardening patch: 5 fixes for audit findings and a deploy-blocking startup bug.

### Security

- **Float-to-int truncation in compress negotiation** — `Accept-Encoding`
  quality values now clamped with `.round().clamp(0.0, 1000.0)` before cast,
  preventing incorrect encoding selection on `NaN`/`Infinity`/negative `q`.
  (fixes #144)
- **Beacon body overflow parsed truncated data** — oversized beacon bodies
  now return 413 Payload Too Large instead of silently parsing the truncated
  prefix. (fixes #151)

### Fixed

- **L4-only configs no longer rejected at startup** — `route_table.is_empty()`
  guard now also checks for layer4 config, allowing Dwaar to start with only
  TCP/UDP proxy routes and no HTTP sites.
- **`.expect()` removed from hot proxy path** — 13 `.expect()` calls in
  `upstream_request_filter` and `upstream_response_filter` replaced with `?`
  propagation, preventing worker crashes on unexpected header values. (fixes #145)
- **Docker watcher dual-map race condition** — `docker_routes` and
  `container_domains` consolidated into a single `DockerState` struct under
  one lock, ensuring atomic map updates. (fixes #148)

## [0.2.5] - 2026-04-13

Critical security fix, parser hardening, and CLI improvements.

### Security

- **Integer overflow in size parsing** — `parse_size` used wrapping multiplication
  for GB/MB/KB suffixes, allowing a malicious config to produce silently incorrect
  size limits (e.g., cache `max_size` wrapping to near-zero). Now uses `checked_mul`,
  returning a parse error on overflow. (fixes #146)

### Fixed

- **Top-level `layer4 {}` blocks now parsed** — caddy-l4 syntax places `layer4`
  at the top level alongside site blocks, not inside global options. The parser
  now handles both placements correctly.
- **`dwaar reload` supports Unix sockets** — the CLI admin client now connects
  via Unix domain sockets (`/var/run/dwaar-admin.sock` or `unix:///path`).
  When the default TCP address is used, the CLI auto-detects the well-known
  UDS path and tries it first.

### Dependencies

- Bump `rustls` 0.23.37 → 0.23.38
- Bump `openssl` 0.10.76 → 0.10.77
- Bump `openssl-sys` 0.9.112 → 0.9.113
- Bump `daachorse` 1.0.1 → 2.0.0
- Bump `softprops/action-gh-release` v2 → v3
- Bump `actions/setup-node` v4 → v6
- Bump `actions/upload-pages-artifact` v3 → v4
- Bump `actions/deploy-pages` v4 → v5

## [0.2.4] - 2026-04-13

### Fixed

- **Layer 4 parser was dead code** — `parse_layer4_config` (490+ lines) was
  fully implemented but never wired into the global options dispatch.
  Configs with `layer4 {}` blocks were silently ignored. Now parsed into
  `GlobalOptions.layer4` and available at runtime.
- Wire `listener_wrappers { layer4 {} }` parsing inside `servers` blocks
  for shared-listener L4 protocol detection.
- Remove `#![allow(dead_code)]` suppression from `parser/layer4.rs`.

## [0.2.3] - 2026-04-12

Security and performance hardening patch. Addresses 51 findings from an
external audit. All dependencies bumped to latest stable.

### Breaking

- **WASM plugin ABI** — `request-info` and `response-info` records no longer
  carry a `headers` field. Guests must use the new host-imported
  `get-request-header` / `get-response-header` functions instead.
- **Analytics counter semantics** — `status_codes`, `bytes_sent`, `bot_views`,
  `human_views` now reset on each flush (per-window deltas, not lifetime totals).

### Security

- Beacon endpoint now authenticates requests with HMAC-SHA256 signed nonces.
- Revoked certificates are evicted from cache on OCSP detection.
- OCSP responder URLs are validated against a private-IP blocklist (SSRF).
- Wildcard SNI enforces RFC 6125 (`*` must be the entire first label).
- ACME private keys and cached cert buffers are zeroized on drop.
- Beacon URL/referrer inputs sanitized and length-capped before aggregation.
- Rate-limit plugin now runs before under-attack in the chain.
- IPv4-mapped IPv6 addresses normalized for rate-limit key generation.
- Admin API responses set `Access-Control-Allow-Origin: null`.
- Prometheus label values escaped per exposition format spec.
- ACME atomic writes use randomized temp files instead of predictable `.tmp`.
- ACME challenge token map bounded at 1024 entries.
- Upstream 5xx error bodies redacted for IPs, emails, PEM, and tokens in logs.
- Referer query strings redacted in access logs.
- Security-headers plugin strips upstream `X-Powered-By` and similar headers.
- L4 Host header matching is now case-insensitive per RFC 7230.
- L4 HTTP detection recognizes TRACE method.

### Privacy

- Analytics JS respects `Sec-GPC` (Global Privacy Control) header.
- `sendBeacon` fallback uses `fetch({ keepalive: true })` instead of sync XHR.
- IPv6 anonymization consistent between client and server paths (/48 mask).

### Performance

- TLS cert-store disk reads moved to `spawn_blocking` (async hot path).
- Bot-detection User-Agent lowercasing uses a stack buffer (no heap alloc).
- Compression encoding negotiation uses a bitmask instead of `HashSet`.
- Compression encoder buffers pre-allocated at 8 KiB.
- Under-attack challenge verification accepts current + previous window.
- WASM headers accessed lazily via host functions (zero-copy on hot path).
- WASM `Linker` built once per plugin, reused per hook call.
- `DwaarPlugin::name()` returns `&str` — eliminates `Box::leak` on reload.
- Cache key allocation uses pre-sized `String` instead of `format!`.
- ACME challenge lookups fast-path when no challenges are pending.
- Per-IP throttle on challenge endpoint during active issuance.

### Reliability

- Supervisor shutdown flag uses `SeqCst` atomic ordering.
- GeoIP database reloadable via `ArcSwap` without restart.
- OCSP responses older than 7 days are no longer stapled.
- Cert-store path construction validates SNI hostnames.
- ACME cert directory permissions set to 0700.
- `VarSlots::set` bounded at 256 to prevent unbounded growth.
- Admin `DELETE /routes` rejects domains > 253 bytes with HTTP 414.
- DNS TXT propagation check uses exact match instead of substring.
- `/admin/reload` uses async file I/O and strips paths from error responses.
- Decompressor emits empty body on overflow instead of raw bytes.

### Dependencies

- wasmtime 30 → 43, kube 0.98 → 3.1, k8s-openapi 0.24 → 0.27
- hmac 0.12 → 0.13, sha2 0.10 → 0.11, bcrypt 0.17 → 0.19
- compact_str 0.8 → 0.9, sonic-rs 0.3 → 0.5, webpki-roots 0.26 → 1.0
- rand 0.10.0 → 0.10.1
- Removed unused `aes-gcm` dependency.

## [0.2.2] - 2026-04-11

### Added

- **Glob imports** — `import apps/*.dwaar` expands glob patterns with
  deterministic sort order and path-traversal hardening. Empty matches are
  not errors.
- **Access log fields** — `rejected_by` and `blocked_by` show which plugin
  denied a request (#128).
- **Health transition logs** — upstream backends log WARN/INFO on state
  changes (#127).
- **Justfile** with common development recipes (#129).
- **`scripts/check-dev-env.sh`** for first-time contributor setup (#130).
- **CONTRIBUTING Quick Start** section (#131).

### Changed

- H3 chunk forwarding is zero-copy via `Bytes::split_to` (ISSUE-108).
- H3 h2 upstream backpressure properly awaits flow-control capacity (ISSUE-108).
- `var_defaults` clone skipped when no `map` directives fire (#126).
- Analytics sink and config watcher mutexes migrated to `parking_lot` (#125).

### Fixed

- H3 pool concurrency race — 100 streams now share ≤ 2 upstream connections (ISSUE-108).
- H3 per-chunk + wall-clock + capacity deadlines prevent slow-loris (ISSUE-108).
- `forward_auth` plaintext targets rejected at parse time (#118).
- HMAC comparison uses `subtle::ConstantTimeEq` (#124).
- ACME challenge redirect bypass restricted to GET (#122).
- Supervisor readiness probe polls admin socket before retiring old worker (#121).
- Leader election re-reads lease on 409 Conflict (#123).
- WASM module cache invalidated on config reload (#120).
- CLI prints actionable hints on connection errors (#134).
- `/admin/reload` returns full parse error in response body (#133).
- Config errors show expected format hints (#132).

## [0.2.1] - 2026-04-11

### Fixed — Security

- FastCGI path traversal — `resolve_script` canonicalizes and validates paths.
- Wake command uses `Command::new` instead of `sh -c` (no shell injection).
- Constant-time HMAC compare for under-attack cookie verification.
- Beacon `Origin` header validated against configured host.
- `forward_auth` refuses non-loopback plaintext without explicit opt-in.
- gRPC body limit capped at 1 GiB (was unlimited).
- QUIC close-delimited response capped at 1 GiB.
- Admin token, DNS API token, and UAM secret wrapped in `Zeroizing`.
- DNS token literal triggers a parser warning recommending `{env.VAR}`.
- Regex NFA budget capped at 1 MiB to block ReDoS patterns.

### Added

- CSP header support in `security_headers` plugin (opt-in).
- Analytics consent gating via `DNT` header and cookies.
- Client IP anonymization in request logs (IPv4 /24, IPv6 /48).
- Query-string redaction for sensitive parameter names.
- Admin audit logs for mutations.
- Log file retention TTL with automatic pruning.
- Cache reload leak counter for Prometheus.

### Changed — Performance

- FastCGI param map uses `ahash` (no key allocation).
- Cert store and QUIC pool mutexes moved to `parking_lot`.
- File server I/O fully async via `spawn_blocking`.
- `AggEvent` fields use `Arc<str>` (pointer bump instead of heap copy).
- `Content-Length` formatted via `itoa` (no allocation).
- Path rewrite loop operates entirely in `CompactString`.

## [0.2.0] - 2026-04-11

### Added

- Layer 4 TCP proxy with protocol-aware matchers (TLS SNI/ALPN, HTTP Host,
  SSH, PostgreSQL, remote_ip CIDR) and bidirectional splice.
- Auto-update background service with maintenance-window scheduling.

## [0.1.1] - 2026-04-10

### Added

- `dwaar self-update` with SHA-256 verification and atomic binary replacement.
- Release binaries published to GitHub Releases.
- Cache backend leak counters for Prometheus.

### Fixed

- Bounded all unbounded reads across 5 crates (Guardrail #28).
- OCSP HTTP fetcher rejects control characters in responder URLs.
- Chunked transfer decoding tracks cumulative body size.
- Cert store panics on poisoned mutex instead of silent recovery.
- H3 request handlers tracked in connection-scoped `JoinSet` with drain.
- SNI cert cache entries invalidated for domains removed from config.

[Unreleased]: https://github.com/permanu/Dwaar/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/permanu/Dwaar/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/permanu/Dwaar/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/permanu/Dwaar/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/permanu/Dwaar/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/permanu/Dwaar/compare/v0.1.0...v0.1.1
