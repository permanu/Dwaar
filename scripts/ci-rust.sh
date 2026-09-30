#!/usr/bin/env sh
# Shared Rust gates for Permanu CI and the manual GitHub Actions fallback.
set -eu

# Bound test concurrency on small runners; permit an explicit runner override.
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"
# Supported by the CI runners (dash/bash); best effort on other shells.
# shellcheck disable=SC3045
ulimit -n 4096 2>/dev/null || true

cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --exclude dwaar-cli
# These integration suites start their own local services. proxy_integration
# still requires an external instance; stress/upgrade remain explicit tests.
cargo test --locked -p dwaar-cli --bins \
  --test cli_integration --test admin_route_state --test multi_upstream \
  --test route_path --test webhook_route
cargo test --locked --workspace --exclude dwaar-cli -- --ignored --nocapture
# Tests already compile/link the dev binaries. Check release-only cfg branches
# without paying for release codegen/LTO (owned by the release workflow).
cargo check --locked --workspace --release
