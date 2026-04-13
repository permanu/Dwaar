# Changelog

All notable changes to Dwaar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
