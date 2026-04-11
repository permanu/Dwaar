# Changelog

All notable changes to Dwaar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

[Unreleased]: https://github.com/permanu/Dwaar/compare/v0.2.2...HEAD

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

[0.1.1]: https://github.com/permanu/Dwaar/compare/v0.1.0...v0.1.1
