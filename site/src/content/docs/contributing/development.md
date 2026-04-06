---
title: "Development Setup"
---

# Development Setup

This page covers everything you need to build, test, and iterate on Dwaar locally.

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Rust (stable) | Install via [rustup](https://rustup.rs/). Dwaar tracks the current stable toolchain. |
| OpenSSL headers | `libssl-dev` (Debian/Ubuntu), `openssl-devel` (Fedora), or `brew install openssl` (macOS). |
| Docker | Required only if you want to run integration tests that exercise Docker label discovery. |
| MaxMind GeoLite2 DB | Optional. Needed to build/run with the `geo` feature enabled. Download from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data). |
| Wasmtime | Optional. Needed to build/run with the `wasm-plugins` feature enabled. |

## Building

Build the entire workspace:

```bash
cargo build --workspace
```

Build with optional features:

```bash
# Enable GeoIP support
cargo build --workspace --features geo

# Enable WASM plugin support
cargo build --workspace --features wasm-plugins

# Enable both
cargo build --workspace --features geo,wasm-plugins
```

Build a release binary:

```bash
cargo build --release -p dwaar-ingress
```

The resulting binary is at `target/release/dwaar`.

## Running Tests

Run the full unit test suite:

```bash
cargo test --workspace
```

Run tests for a single crate:

```bash
cargo test -p dwaar-config
```

Run integration tests (requires Docker):

```bash
cargo test --workspace --test '*'
```

Benchmarks (requires nightly for some):

```bash
cargo bench -p dwaar-log
```

## Code Style

All contributions must pass these checks before opening a PR:

```bash
# Formatting
cargo fmt --all -- --check

# Lints (zero warnings policy)
cargo clippy --workspace --all-targets -- -D warnings

# Tests
cargo test --workspace
```

The CI pipeline enforces all three. Run them locally first to avoid round trips.

Additional standards:
- Every public function and type must have a doc comment.
- New async code must not call `tokio::spawn` at request time; use a `BackgroundService` instead.
- Unsafe blocks require a `// SAFETY:` comment explaining the invariant.

## Project Structure

Dwaar is a Cargo workspace. Each crate has a single, focused responsibility:

- **`dwaar-ingress`** — binary entry point and Pingora server bootstrap
- **`dwaar-cli`** — CLI argument parsing
- **`dwaar-core`** — the hot-path `ProxyHttp` implementation
- **`dwaar-config`** — Dwaarfile parsing and hot-reload
- **`dwaar-tls`** — ACME and SNI
- **`dwaar-analytics`** — JS injection, beacon collection, Prometheus
- **`dwaar-plugins`** — plugin trait and built-in middleware
- **`dwaar-admin`** — admin API
- **`dwaar-docker`** — Docker label discovery
- **`dwaar-geo`** — GeoIP lookups
- **`dwaar-log`** — async request logging

See the [Crate Map](../architecture/crate-map.md) for per-crate dependency graphs and interface details.

## Related

- [Architecture Overview](../architecture/overview.md)
- [Architecture for Contributors](architecture.md)
- [CONTRIBUTING.md](https://github.com/permanu/Dwaar/blob/main/CONTRIBUTING.md) — PR process, commit convention, release workflow
