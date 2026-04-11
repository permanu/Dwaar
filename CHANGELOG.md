# Changelog

All notable changes to Dwaar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

[Unreleased]: https://github.com/permanu/Dwaar/compare/v0.2.1...HEAD

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
