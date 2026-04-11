#!/usr/bin/env bash
# Dwaar first-time contributor environment check.
# Verifies required toolchain and runs a dry-run workspace check.
set -u
# No set -e — we want to collect all failures and report at the end.

# ------------------------------------------------------------------
# Accumulators
# ------------------------------------------------------------------
# Each summary line looks like "[ok] rustc 1.94.0" or "[fail] cargo missing".
SUMMARY=""
EXIT_CODE=0

record_ok() {
    SUMMARY="${SUMMARY}[ok]   $1"$'\n'
}

record_warn() {
    SUMMARY="${SUMMARY}[warn] $1"$'\n'
}

record_fail() {
    SUMMARY="${SUMMARY}[fail] $1"$'\n'
    EXIT_CODE=1
}

# ------------------------------------------------------------------
# Required toolchain minimum
# ------------------------------------------------------------------
# If rust-toolchain.toml pins a channel, extract the first numeric version
# we see (e.g. "1.94" or "1.75.0"). Otherwise fall back to 1.75, which is
# the historical floor for Dwaar.
REQUIRED_RUST="1.75"
TOOLCHAIN_FILE="$(dirname "$0")/../rust-toolchain.toml"
if [ -f "$TOOLCHAIN_FILE" ]; then
    pinned=$(grep -E '^[[:space:]]*channel[[:space:]]*=' "$TOOLCHAIN_FILE" \
        | head -n 1 \
        | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -n "${pinned:-}" ] && echo "$pinned" | grep -Eq '^[0-9]'; then
        REQUIRED_RUST="$pinned"
    fi
fi

# Compare two dotted versions. Returns 0 if $1 >= $2.
version_ge() {
    # shellcheck disable=SC3043
    local have="$1"
    local want="$2"
    # Normalize to three components.
    have_major=$(echo "$have" | awk -F. '{print $1+0}')
    have_minor=$(echo "$have" | awk -F. '{print $2+0}')
    have_patch=$(echo "$have" | awk -F. '{print $3+0}')
    want_major=$(echo "$want" | awk -F. '{print $1+0}')
    want_minor=$(echo "$want" | awk -F. '{print $2+0}')
    want_patch=$(echo "$want" | awk -F. '{print $3+0}')

    if [ "$have_major" -gt "$want_major" ]; then return 0; fi
    if [ "$have_major" -lt "$want_major" ]; then return 1; fi
    if [ "$have_minor" -gt "$want_minor" ]; then return 0; fi
    if [ "$have_minor" -lt "$want_minor" ]; then return 1; fi
    if [ "$have_patch" -ge "$want_patch" ]; then return 0; fi
    return 1
}

# ------------------------------------------------------------------
# Required tools
# ------------------------------------------------------------------

echo "Checking required tools..."

if command -v rustc >/dev/null 2>&1; then
    RUSTC_VERSION=$(rustc --version 2>/dev/null | awk '{print $2}')
    if [ -n "$RUSTC_VERSION" ] && version_ge "$RUSTC_VERSION" "$REQUIRED_RUST"; then
        record_ok "rustc ${RUSTC_VERSION} (>= ${REQUIRED_RUST})"
    else
        record_fail "rustc ${RUSTC_VERSION:-unknown} is older than required ${REQUIRED_RUST} — run 'rustup update'"
    fi
else
    record_fail "rustc not found — install via https://rustup.rs"
fi

if command -v cargo >/dev/null 2>&1; then
    CARGO_VERSION=$(cargo --version 2>/dev/null | awk '{print $2}')
    record_ok "cargo ${CARGO_VERSION}"
else
    record_fail "cargo not found — install via https://rustup.rs"
fi

# ------------------------------------------------------------------
# Optional tools
# ------------------------------------------------------------------

echo "Checking optional tools..."

if command -v openssl >/dev/null 2>&1; then
    OPENSSL_VERSION=$(openssl version 2>/dev/null | awk '{print $2}')
    record_ok "openssl ${OPENSSL_VERSION}"
else
    record_warn "openssl not found — only needed for some TLS integration tests"
fi

if command -v docker >/dev/null 2>&1; then
    DOCKER_VERSION=$(docker --version 2>/dev/null | awk '{print $3}' | tr -d ',')
    record_ok "docker ${DOCKER_VERSION}"
else
    record_warn "docker not found — deploy-agent integration tests will be skipped"
fi

if command -v just >/dev/null 2>&1; then
    JUST_VERSION=$(just --version 2>/dev/null | awk '{print $2}')
    record_ok "just ${JUST_VERSION}"
else
    record_warn "just not found — install via 'cargo install just' to use the Justfile shortcuts"
fi

# ------------------------------------------------------------------
# Dry-run workspace smoke test
# ------------------------------------------------------------------

echo "Running 'cargo check --workspace --quiet' (dry-run smoke test)..."
if command -v cargo >/dev/null 2>&1; then
    if cargo check --workspace --quiet; then
        record_ok "cargo check --workspace passed"
    else
        record_fail "cargo check --workspace failed — fix compilation errors before contributing"
    fi
else
    record_fail "skipped cargo check — cargo is not installed"
fi

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------

echo
echo "Summary:"
printf "%s" "$SUMMARY"

if [ "$EXIT_CODE" -eq 0 ]; then
    echo
    echo "Environment looks good. You are ready to contribute."
else
    echo
    echo "One or more required checks failed. See [fail] lines above."
fi

exit "$EXIT_CODE"
