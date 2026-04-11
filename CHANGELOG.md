# Changelog

All notable changes to Dwaar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

[Unreleased]: https://github.com/permanu/Dwaar/compare/v0.2.0...HEAD

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
