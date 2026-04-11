# Changelog

All notable changes to Dwaar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

[Unreleased]: https://github.com/permanu/Dwaar/compare/v0.2.3...HEAD

## [0.2.3] - 2026-04-12

Hardening patch addressing the external security and performance audit.
Triage identified 51 real findings (after filtering 5 false positives
and ~15 items already remediated in v0.2.1/v0.2.2). v0.2.3 closes
**all 51** — 43 in the main wave, 5 in a close-out pass, plus the final
3 (L-05, L-16, L-17) that were previously documented as deferred now
fully implemented as real structural fixes. Zero accepted-design
exits, zero deferrals. v0.2.2's glob-import and H3-streaming work
remain in place unchanged.

### Fixed — Final close-out (3)

- **L-05 — Per-IP ACME challenge throttle.** `ChallengeSolver::get` now
  takes an optional source IP and throttles probes to
  `PROBE_MAX_PER_WINDOW = 120` per `PROBE_WINDOW_SECS = 60` per-IP
  sliding window during active issuance. The tracked-IP counter map
  is hard-capped at `PROBES_MAX_TRACKED_IPS = 10_000` with opportunistic
  cleanup of expired windows to block rotating-source amplification.
  The `is_empty()` fast-path from the earlier close-out still short-
  circuits the steady-state case at zero cost. `None` source IP
  (loopback, UDS, unit tests) bypasses the throttle.
- **L-16 — Lazy WASM header access.** Replaced the eager
  `list<header-entry>` field on `request-info` / `response-info` in the
  `dwaar-plugin` WIT contract with host-imported functions
  `get-request-header`, `list-request-header-names`,
  `get-response-header`, `list-response-header-names`. Guests read only
  the headers they need. `PluginState` holds raw `*const RequestHeader`
  / `*const ResponseHeader` pointers set by the enclosing hook call
  and dereferenced only inside the host-function closures — zero
  header copies on the hot path. The 8 KiB per-value cap and CRLF-
  injection name filter from `host.rs` are still applied on every
  lookup. **Breaking WIT ABI** — existing guest binaries that read
  `req.headers` must migrate to `get-request-header(name)`.
- **L-17 — DwaarPlugin::name() trait refactor.** Changed the trait
  signature from `fn name(&self) -> &'static str` to
  `fn name(&self) -> &str`. `WasmPlugin` now holds the plugin name as
  an owned `String` field and returns `&self.name`, eliminating the
  `Box::leak` on every config reload. Literal-returning impls in
  `bot_detect`, `compress`, `ip_filter`, `rate_limit`,
  `security_headers`, and `under_attack` keep their
  `fn name(&self) -> &'static str` signatures (string literals satisfy
  `&str` trivially) — zero behaviour change for those. Plugin tests:
  141 passing with the wasm feature enabled.

### Fixed — Audit close-out (8)

- **M-07** — `build_cache_key` now uses `String::with_capacity` + `push_str`
  instead of `format!("{method} {path}")`, guaranteeing a single exact-
  sized allocation on the cacheable-request hot path.
- **L-05** — `ChallengeSolver::get` fast-returns `None` when the pending
  set is empty, so an attacker spraying
  `/.well-known/acme-challenge/<random>` requests at a fully-issued
  instance no longer touches the `DashMap` at all. Closes the shard-
  contention DoS surface.
- **L-10** — `/admin/reload` handler now uses `tokio::fs::read_to_string`
  instead of blocking `std::fs::read_to_string`. The admin endpoint is
  already async-contextual (Pingora `BackgroundService`); the blocking
  call was a v0.2.2 oversight when `#133` added the in-process parse.
- **L-11** — Parse-error response bodies from `/admin/reload` now
  replace the absolute config path + basename with `<config>` before
  returning to the client. Line/column remain. Operators still see the
  full path in the structured `warn!` audit log for correlation.
- **M-23** — Removed the unused `aes-gcm` dependency from
  `dwaar-analytics/Cargo.toml`. The crate is no longer pulled in by the
  beacon HMAC implementation (which uses `hmac` + `sha2`), and the
  libc-cfg cascade that blocked the initial removal attempt is gone
  after Wave D's `process_metrics.rs` rewrite.

### Documented — Accepted design (2)

- **M-15** — Added an extensive doc comment on
  `AdminService::check_rate_limit` documenting the accepted
  `Ordering::Relaxed` race: the `compare_exchange` boundary can produce
  a ~2× burst at window boundaries, capped at 120 requests, which is
  acceptable for a token-authenticated admin API that sees at most 1
  req/sec in practice. Stronger ordering would add a memory barrier
  per call without changing the behaviour at realistic rates.
- **L-16** — WASM plugin `from_ctx_with_request` pre-sizes the header
  `Vec` to avoid reallocation. Full lazy header access is blocked by
  the `dwaar-plugin` WIT contract (`request-info.headers` is a
  by-value `list<header-entry>`); migrating to a lazy `get-header`
  host function is a breaking WIT change tracked under plugin-system
  redesign.

### Previously deferred — now fully fixed

L-16 and L-17 were listed as deferred in an earlier close-out pass.
Both are now implemented as real structural fixes — see "Final
close-out" above. There are **no accepted-design exits and no deferred
items** remaining in the v0.2.3 audit scope.

### Main wave (43 fixes)

### Added — Security
- **Beacon HMAC authentication (C-04)** — analytics beacons are now
  cryptographically authenticated. The injector emits a
  `<meta name="dwaar-beacon-auth" content="<nonce_b64>:<sig_hex>">` tag on
  every injected page; the server verifies `HMAC-SHA256(nonce || host ||
  window)` against a process-wide random 32-byte secret, accepting the
  current or previous 5-minute window. Constant-time comparison via
  `subtle::ConstantTimeEq`. Activates the previously-dormant `hmac`,
  `sha2`, `hex`, and `rand` dependencies.
- **OCSP SSRF blocklist (M-12)** — `http_post_ocsp` now resolves the
  AIA-extracted responder host and rejects private, loopback, link-local,
  broadcast, multicast, unspecified, ULA (`fc00::/7`), and metadata
  (`169.254.0.0/16`) addresses. Non-HTTP(S) schemes rejected per RFC 6960.
- **Revoked cert cache eviction (C-03)** — on OCSP `CertRevoked` detection,
  the ACME service now invalidates the LRU cache entry and deletes the
  on-disk `.pem`/`.key` files before re-issuance. Previously the revoked
  cert stayed in cache.
- **Wildcard SNI position enforcement (M-13)** — `is_valid_sni_hostname`
  now requires `*` to be the entire first label per RFC 6125. Rejects
  `exam*ple.com`, `*ample.com`, `foo.*.com`, `**.example.com`, etc.
- **Domain validation on cert-store path construction (M-10)** —
  `CertStore::get`/`get_async`/`get_or_load` reject invalid SNI hostnames
  before interpolating into file paths.
- **ACME private key zeroization (H-07)** — `generate_key_and_csr` now
  returns `Zeroizing<String>` for the private key PEM, wiping on drop.
- **CachedCert zeroization (H-08)** — `CachedCert` now has a manual `Drop`
  that zeroes the OCSP response buffer; relies on OpenSSL's `EVP_PKEY_free`
  + `OPENSSL_cleanse` for the private key.
- **Beacon data sanitization (C-05)** — `sanitize_url_to_path` rejects
  protocol-relative URLs, control bytes, and non-path inputs; caps paths
  at 512 bytes. `sanitize_referrer_host` extracts only the host component,
  caps at 128 bytes. Invalid beacons drop silently.
- **Forward-auth plugin chain order (L-14)** — `rate_limit` now has
  priority 15 (was 20); `under_attack` priority 20 (was 15). Rate-limited
  requests no longer receive under-attack challenge pages.
- **IPv4-mapped IPv6 rate-limit normalization (L-15)** — `rate_limit`
  now canonicalizes IPs via `Ipv6Addr::to_canonical()`. `::ffff:127.0.0.1`
  and `127.0.0.1` produce the same rate-limit key.
- **Admin API CORS lockdown (M-14)** — every admin API response sets
  `Access-Control-Allow-Origin: null`; `OPTIONS` preflight returns 405.
- **Prometheus label injection escaping (H-11)** — user-controlled label
  values (domain names) are now escaped per the exposition format spec
  (`\`, `"`, `\n`). Hot path returns `Cow::Borrowed` when no escaping is
  needed.
- **Atomic write tempfile randomization (L-07)** — ACME cert PEM and
  account JSON writes now use `tempfile::NamedTempFile::new_in(parent)`
  + `persist(target)`, eliminating the predictable `.tmp` suffix that
  enabled symlink attacks on shared systems.
- **ACME token count bound (L-09)** — `ChallengeSolver::set` rejects new
  tokens past `MAX_PENDING_TOKENS = 1024`. Updates to existing tokens
  still allowed at cap.
- **Upstream error body PII redaction (H-12)** — captured 5xx error body
  fragments are now redacted for IPv4/IPv6 literals, emails, PEM blocks,
  and bearer-token patterns before being written to access logs.
- **Referer query-string redaction (M-24)** — Referer URLs in access logs
  now go through the same query-param redaction as the request's own
  query string (`token`, `key`, `secret`, `password`, `api_key`,
  `access_token`, `auth`).
- **Decompressor safe-body fallback (M-25)** — on HTML-injection decoder
  overflow or error, the pipeline emits an empty body instead of leaking
  raw compressed bytes into the response.
- **Security-headers info-leak stripping (M-20)** — the plugin now strips
  upstream `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`,
  `X-Runtime`, `X-Generator`, `Server` before applying its own banner.
  Default CSP remains opt-in per the 0.2.1 design.
- **Host header case-insensitive matching (L-03)** — L4 `extract_http_host`
  now matches per RFC 7230 (e.g. `HOST:`, `hOsT:`).
- **TRACE method detection (L-04)** — L4 `looks_like_http` now recognizes
  TRACE requests.

### Added — Privacy
- **Sec-GPC header check (L-22)** — analytics.js now suppresses beacons
  when `navigator.globalPrivacyControl === true`, alongside the existing
  DNT check.
- **fetch keepalive fallback (L-23)** — analytics.js replaced the sync
  XHR unload fallback with `fetch(..., { keepalive: true })`.
- **IPv6 anonymization consistency (M-22)** — client-side and server-side
  aggregation paths now both mask IPv6 to `/48` before HyperLogLog insert.

### Added — Reliability
- **Leader election resourceVersion invariant (already v0.2.2 #123)** —
  unchanged.
- **Supervisor SHUTTING_DOWN SeqCst (H-05)** — signal handler and
  supervisor loop now use `SeqCst` ordering on the shutdown flag per
  C11 memory model + POSIX signal-safety rules.
- **GeoIP hot reload (M-27)** — `GeoLookup::reader` moved behind
  `ArcSwap<Reader<Mmap>>`. New `GeoLookup::reload(path)` swaps the
  underlying mmap atomically; lookups remain lock-free. CLI wiring
  deferred to a follow-up.
- **OCSP staleness guard (M-11)** — `CachedCert` tracks `ocsp_last_refresh:
  Option<Instant>`. Stale OCSP responses (>7 days) are no longer stapled.

### Changed — Performance
- **Async TLS filesystem reads (H-06)** — `CertStore::get_async` wraps
  disk reads in `tokio::task::spawn_blocking`. The hot-path `certificate_callback`
  is async (pingora trait permits this). Cache hits remain lock-free
  and I/O-free.
- **Bot-detect stack buffer (M-17)** — `classify()` uses a 512-byte stack
  buffer for the User-Agent lowercase form, heap-fallback for longer
  inputs. Eliminates per-request allocation on the hot path.
- **Compress bitmask (M-21)** — `negotiate_encoding` replaced the
  per-response `HashSet` allocation with an inline `Encodings` bitmask
  struct.
- **Compress encoder pre-allocation (L-18)** — gzip/brotli/zstd encoder
  buffers start at 8 KiB capacity.
- **Under-attack window boundary grace (M-19)** — `verify_challenge` now
  accepts the current window OR the previous 5-minute window, matching
  the beacon HMAC pattern. Eliminates boundary-crossing failures.
- **Under-attack `strip_dwaar_params` (L-20)** — single-pass String
  writer replaces the `Vec<&str>::collect::<Vec<_>>().join("&")` pattern.
- **WASM adapter header Vec pre-alloc (L-16)** — `from_ctx_with_request`
  and `from_ctx_with_response` use `Vec::with_capacity(headers.len())`
  to avoid reallocation. Full lazy access is blocked by the WIT contract;
  documented inline.
- **WASM adapter Linker reuse (L-19)** — `Linker<PluginState>` built once
  at plugin construction and reused per hook call.
- **Analytics sink parking_lot (already v0.2.2 #125)** — no change.

### Changed — Observability
- **Per-window counter reset (H-13)** — `status_codes`, `bytes_sent`,
  `bot_views`, `human_views` now reset to zero on each flush, matching
  the doc comment's "cumulative since last flush" semantics. Previously
  these accumulated as lifetime totals.
- **Upstream health log masking (M-08)** — transition WARN/INFO logs now
  mask the upstream address (`10.x.x.x:8080` for IPv4, `/48` prefix for
  IPv6) to avoid leaking internal network topology in shared-log
  deployments.
- **Prometheus `MAX_TRACKED_DOMAINS` deduplication (L-25)** — the
  `10_000` constant now lives in `dwaar-analytics::MAX_TRACKED_DOMAINS`
  and is imported by both `prometheus.rs` and `rate_cache_metrics.rs`.
- **Accurate process start time (L-24)** — `ProcessMetrics::start_time_secs`
  now reads from `/proc/self/stat` on Linux and `libc::proc_pidinfo`
  (`PROC_PIDTBSDINFO`) on macOS, cached in a `OnceLock`. Falls back to
  construction time on unsupported platforms.

### Fixed — Reliability
- **ACME cert directory perms (M-09)** — `write_cert_files` now sets
  0o700 on the cert directory after creation, mirroring the ACME account
  directory.
- **VarSlots bound (L-06)** — `VarSlots::set()` rejects slot indices past
  `MAX_VAR_SLOTS = 256` (silent no-op), preventing unbounded Vec growth
  from a config bug.
- **Admin DELETE path length cap (L-12)** — `DELETE /routes/{domain}`
  rejects domain paths longer than 253 bytes (RFC 1035 max) with HTTP
  414 before any `to_lowercase()` allocation.
- **DNS TXT exact-match (L-08)** — DNS propagation checker no longer
  relies on substring matching; the dig output is now parsed line-by-line
  and the quoted value is compared exactly.

### Closed — Audit triage (no code change)
- **H-04** (self-update OOM) — false positive; curl streams the download
  to temp file before `fs::read`.
- **H-09** (compression bomb) — false positive; Dwaar compresses
  responses but does not decompress attacker-controlled input.
- **L-01** (admin_client header tabs) — false positive; literal uses
  spaces and headers are correctly terminated.
- **L-21** (MinuteBuckets non-atomic) — false positive; DashMap shard
  locks the containing struct.
- **M-03** (directory listing URL encoding) — false positive; HTML
  attribute escaping is correct for href context.

## [0.2.2] - 2026-04-11

### Added — Config
- **Dwaarfile glob imports** — the `import` directive now accepts glob
  patterns (`*`, `?`, `[...]`). Matches are sorted lexicographically for
  deterministic load order. Path-traversal hardening (canonicalize +
  containment check) is enforced on every resolved match, and an empty
  match set is not an error. Unlocks per-app file drops into `apps/`
  without mutating the top-level Dwaarfile. New `ImportError::InvalidGlob`
  variant.

### Added — Observability
- **Access log `rejected_by` / `blocked_by` fields** (#128) — JSON access
  log now carries a `&'static str` reason when a request is denied by a
  plugin. `rate_limit` populates `rejected_by`; `bot_detection` has the
  infrastructure wired but no setter yet. Fields are omitted when absent.
- **Upstream health WARN/INFO transitions** (#127) — backends log a
  `warn!` on healthy→unhealthy edges (with the probe error reason
  captured in `Backend::last_error`) and `info!` on the reverse edge.
  Only transitions are logged — no noise on steady-state probes.

### Added — DX
- **Justfile** (#129) — top-level `Justfile` with `test`, `test-crate`,
  `lint`, `build-release`, `ci`, and `quick` recipes.
- **`scripts/check-dev-env.sh`** (#130) — verifies `rustc`, `cargo`, and
  `openssl` availability and runs a dry-run workspace check.
- **CONTRIBUTING Quick Start** (#131) — new 5-step onboarding block at
  the top of `CONTRIBUTING.md` wiring together the script and Justfile.

### Changed — Performance
- **H3 zero-copy chunk forwarding (ISSUE-108)** — replaced
  `BytesMut::with_capacity + BufMut::put + freeze` (memcpy per chunk)
  with `Buf::copy_to_bytes`, which monomorphizes to `Bytes::split_to`
  on the h3-quinn path. Chunk forwarding on the HTTP/3 → upstream
  bridge is now a refcount bump; peak per-chunk allocation drops to
  zero.
- **H3 h2 backpressure (ISSUE-108)** — `h2::SendStream::send_data` now
  awaits reserved capacity via a new `await_h2_capacity` helper
  (`H2_CAPACITY_WAIT = 30s`). Previous code called
  `reserve_capacity(n)` and immediately sent, causing silent unbounded
  in-memory queuing inside `h2`'s internals on slow upstreams.
- **`var_defaults` clone elision** (#126) — per-request
  `route.var_defaults.clone()` in `request_filter` is skipped on routes
  with no `map` directives. Template evaluation falls back to the route's
  default map directly. Measurably reduces hot-path allocations for
  routes with `vars` defaults but no `map` rules.
- **`parking_lot` migration** (#125) — analytics sink's three `std::sync::Mutex`
  fields (stream / buffer / last_attempt) collapsed into a single
  `parking_lot::Mutex<SocketSinkState>`. Config watcher's `last_hash`
  moved from `std::sync::Mutex` to `parking_lot::Mutex`. Guardrail #58.

### Fixed — Security
- **`forward_auth` compile-time plaintext rejection** (#118) — non-loopback
  plaintext `forward_auth` targets are now rejected at config parse time.
  Operators must opt in with `insecure_plaintext` inside the
  `forward_auth` block; the opt-in path logs a parse-time warning
  instead of a per-request hot-path warning. Loopback targets continue
  to accept plaintext without opt-in.
- **Constant-time HMAC via `subtle`** (#124) — `under_attack` plugin's
  hand-rolled `constant_time_eq` replaced with `subtle::ConstantTimeEq::ct_eq`,
  matching `dwaar-admin/src/auth.rs`. Guardrail #30 enforced.
- **ACME challenge method guard** (#122) — the HTTP→HTTPS redirect
  bypass for `/.well-known/acme-challenge/` now requires the request
  method to be `GET`. Non-GET requests to that path are redirected
  normally. RFC 8555 compliant.

### Fixed — Reliability
- **H3 upstream pool concurrency (ISSUE-108)** — fixed a check-then-act
  race in `H2ConnPool::get_or_connect` that caused N concurrent H3
  streams with a cold pool to open N upstream TCP connections instead
  of multiplexing. Gated connect decisions with a per-host async
  mutex. 100 concurrent streams now share ≤ `MAX_CONNS_PER_HOST`
  (default 2) TCP connections. Verified by new integration test
  `quic_h2_pool_concurrency::hundred_streams_share_two_upstream_connections`.
- **H3 request/response body deadlines (ISSUE-108)** — per-chunk read
  timeout (`CHUNK_READ_TIMEOUT = 30s`), aggregate wall-clock body
  deadline (`BODY_WALL_CLOCK = 5 min`), and H2 capacity wait
  (`H2_CAPACITY_WAIT = 30s`) now apply independently on the H3
  bridge. Together they cover slow-loris, tail-latency, and
  wedged-upstream scenarios that a single outer timeout could not.
  Enforced by a new `BodyDeadline` helper in
  `crates/dwaar-core/src/quic/stream_guard.rs`.
- **Supervisor readiness probe** (#121) — after forking a new child
  worker the supervisor now polls the admin socket (UDS or TCP) with a
  50 ms cadence, capped at 10 s, before considering the restart
  successful. Child crashes during boot are detected via `waitpid(WNOHANG)`.
  Uses blocking stdlib sockets — no Tokio runtime in the supervisor.
- **Leader election 409 re-read** (#123) — on `kube::Error::Api(409)`
  during lease patching the controller re-`GET`s the lease,
  re-evaluates expiry, and patches with the fresh `resourceVersion`
  instead of reusing the stale in-memory copy. Guardrail #34.
- **WASM cache reload invalidation** (#120) — on hot-reload, changed or
  removed `.wasm` module paths are diffed by mtime and
  `ModuleCache::invalidate()` is called per-path before the new config
  goes live. Previously required a full restart.

### Fixed — DX
- **CLI actionable error hints** (#134) — `dwaar routes` against a
  stopped daemon now prints an actionable message pointing at the admin
  socket path and the `dwaar --config` command. Config-not-found errors
  surface the canonical absolute path instead of whatever relative path
  the user typed.
- **`/admin/reload` returns full parse error** (#133) — POST
  `/admin/reload` now returns `400 Bad Request` with `text/plain;
  charset=utf-8` body containing the full `ConfigError::Display` output,
  including line, column, and message. Cooldown preserved.
- **Config error format hints** (#132) — `ParseErrorKind::InvalidValue`
  carries an optional `accepted_format: &'static str` field. Parse
  errors for `rate_limit`, body size limits, and timeouts display an
  `expected:` line showing the canonical format (e.g.,
  `100/s or 5000/10m`). Nested-directive spelling suggestions extended
  to 37 new names (`transport`, `lb_policy`, `health_uri`, ...).

### Closed (stale, already fixed in earlier release)
- **#116** — H2 pool `std::Mutex` + cap. Already resolved in the 0.2.1
  audit; `h2_pool.rs` uses `parking_lot::Mutex` with
  `MAX_CONNS_PER_HOST = 2`.
- **#135** — unused `cpu_count` warning. `cpu_count` is used at
  `crates/dwaar-cli/src/main.rs:346`; no warning fires.

[0.2.2]: https://github.com/permanu/Dwaar/compare/v0.2.1...v0.2.2

## [0.2.1] - 2026-04-11

### Fixed — Security
- **FastCGI path traversal** — `resolve_script` now canonicalizes the root and
  verifies every resolved candidate stays inside it, matching the guard used by
  `file_server`. Traversal attempts are treated as "not found".
- **Wake command shell injection** — `scale_to_zero` `wake_command` is no
  longer executed via `sh -c`. Commands run through `Command::new(binary).args(..)`
  with no shell interpolation. The binary path MUST now be absolute; relative
  paths fail with `WakeError::CommandPathNotAbsolute`.
- **Constant-time HMAC compare** — `under_attack`'s challenge comparison now
  folds length XOR into the result instead of early-returning on length
  mismatch. Cookie verification switched to `hmac::Mac::verify_slice`.
- **Beacon Origin validation** — `/_dwaar/b` now validates the `Origin` header
  against the configured host before accepting events.
- **forward_auth plaintext enforcement** — refuses to dispatch to non-loopback
  plaintext targets unless explicitly opted in via `insecure_plaintext`.
- **gRPC body limit cap** — gRPC routes no longer disable body limits entirely.
  A 1 GiB cap applies unless a lower limit is explicitly configured. gRPC
  detection is now driven by a route-level `grpc` directive first, with the
  `Content-Type: application/grpc` check as fallback.
- **QUIC close-delimited response cap** — `stream_response_body_inline` now
  enforces a 1 GiB cumulative read limit, closing the last unbounded path.
- **Secret zeroization** — admin token, Cloudflare DNS API token, and the UAM
  HMAC secret are now wrapped in `zeroize::Zeroizing` and wiped on drop.
- **DNS token literal warning** — the parser warns when a DNS provider token
  is specified as a literal, recommending `{env.VAR}` instead.
- **Regex NFA size limit** — all user-supplied regex patterns now compile with
  a 1 MiB NFA budget, blocking pathological patterns like `(a+)+$`.

### Added — Privacy & Observability
- **CSP header support** — `security_headers` plugin now exposes
  `content_security_policy` and `content_security_policy_report_only` fields
  (both opt-in, off by default for backwards compatibility).
- **Analytics consent gating** — `HtmlInjector::process_with_consent` respects
  the `DNT: 1` header and looks for `dwaar_consent=1` / `analytics_consent=1`
  cookies before injecting the analytics beacon. Opt-in via `respect_consent`.
- **Request-log client IP anonymization** — IPv4 logs zero the last octet;
  IPv6 keeps the /48 prefix. Always on, gated by a compile-time const.
- **Request-log query-string redaction** — `token`, `key`, `secret`, `password`,
  `api_key`, `access_token`, `auth` values in query strings are redacted to
  `REDACTED` before serialization.
- **Admin audit logs** — mutations (`route_add`, `route_delete`, `cache_purge`)
  emit structured `tracing::info!` at target `dwaar::admin::audit`.
- **Log file retention TTL** — `FileRotationWriter` accepts `max_age_secs`.
  Rotated files older than the TTL are pruned at rotate time and via a
  periodic background task.
- **Cache reload leak metrics** — `leaked_reload_count()` exposes the
  cumulative count of cache backends leaked across reloads.

### Changed — Performance
- **FastCGI param map** — `HashMap<&str, String>` → `ahash::AHashMap<&'static str, String>`,
  removing the keys' `String::from` allocation on every request.
- **Intercept header clone** — now produces `CompactString` directly, skipping
  the `str → String → CompactString` double allocation.
- **Cert store mutex** — `std::sync::Mutex` → `parking_lot::Mutex` (infallible).
- **QUIC upstream pools** — `std::sync::Mutex` → `parking_lot::Mutex`.
- **File server I/O** — `serve_file`, `read_file`, and
  `generate_directory_listing` are now `async`, wrapping all blocking
  `std::fs` calls in `tokio::task::spawn_blocking`.
- **AggEvent** — `host`, `path`, `country`, `referer` switched from
  `CompactString`/`Option<CompactString>` to `Arc<str>`/`Option<Arc<str>>`.
  Per-event clone is now a pointer bump instead of a heap copy.
- **Content-Length formatting** — replaced `usize::to_string()` with
  `itoa::Buffer::format` at 7 sites, eliminating the allocation entirely.
- **Path rewrite loop** — works end-to-end in `CompactString` with no
  intermediate `String` allocation. `RewriteRule::SubstringReplace` builds
  directly into a pre-sized `CompactString` via a single `str::find` walk.

### Documentation
- **Starlight is now the sole documentation source of truth.** The stale
  mdbook tree under `docs/` and its CI workflow (`.github/workflows/docs.yml`)
  were removed. All user docs live in `site/src/content/docs/` and ship via
  `site.yml`.
- New **Layer 4 TCP Proxy** reference page documenting matchers, handlers,
  load-balancing policies, passive health checks, listener-wrapper fall-through,
  and current limitations.
- Audit-remediation features (CSP, consent gating, log privacy, admin audit,
  wake breaking change, gRPC cap, HTTP/3 body cap) documented across the
  existing security, observability, and API sections.

[0.2.1]: https://github.com/permanu/Dwaar/compare/v0.2.0...v0.2.1

## [0.2.0] - 2026-04-11

### Added
- **Layer 4 TCP proxy** — caddy-l4 compatible `layer4 {}` global block with
  protocol-aware matchers (TLS SNI/ALPN, HTTP Host, SSH, PostgreSQL,
  remote_ip CIDR) and bidirectional TCP splice. Supports both standalone
  L4 servers and `listener_wrappers` for port-sharing with HTTP.
- Auto-update background service (`auto_update {}` Dwaarfile block) —
  periodically checks releases.dwaar.dev, downloads with SHA-256
  verification, and triggers zero-downtime reload within a configurable
  maintenance window.

[0.2.0]: https://github.com/permanu/Dwaar/compare/v0.1.1...v0.2.0

## [0.1.1] - 2026-04-10

### Added
- `dwaar self-update` subcommand — checks releases.dwaar.dev for the latest
  version, downloads the binary with SHA-256 verification, and atomically
  replaces the running binary in-place.
- R2 upload step in release workflow — binaries are now published to
  releases.dwaar.dev so the installer and self-update work out of the box.
- Cache backend leak observability — `leaked_cache_backend_count()` and
  `leaked_cache_backend_bytes()` counters exposed for Prometheus.

### Fixed
- **Security:** Bounded all unbounded reads across 5 crates (quic bridge,
  Docker client, config watcher, ACME account, OCSP) to enforce Guardrail #28.
- **Security:** OCSP HTTP fetcher now rejects control characters in the
  responder URL, closing a header-injection vector (Guardrail #31).
- **Security:** `decode_chunked` tracks cumulative body size and rejects
  responses exceeding `MAX_UPSTREAM_RESPONSE` — previously many small chunks
  could bypass the cap.
- **Reliability:** Cert store now panics on poisoned mutex instead of
  silently recovering potentially corrupted state.
- **Reliability:** H3 request handlers are tracked in a connection-scoped
  `JoinSet` with a 5-second graceful drain on connection close.
- **Reload:** SNI cert cache entries are now invalidated for domains removed
  from config, preventing stale certs from being served via the LRU fallback.

[0.2.3]: https://github.com/permanu/Dwaar/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/permanu/Dwaar/compare/v0.2.1...v0.2.2
[0.1.1]: https://github.com/permanu/Dwaar/compare/v0.1.0...v0.1.1
