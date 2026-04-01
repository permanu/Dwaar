#!/usr/bin/env bash
# pgo-build.sh — Profile-Guided Optimization build pipeline for Dwaar.
#
# Usage:
#   ./scripts/pgo-build.sh
#   PROFILE_DIR=/tmp/pgo PGO_DURATION=60 ./scripts/pgo-build.sh
#   PGO_WORKLOAD=/path/to/my-workload.sh ./scripts/pgo-build.sh
#
# Environment variables:
#   PROFILE_DIR   — where to store profile data (default: target/pgo-profiles)
#   PGO_WORKLOAD  — optional script to run during profiling instead of built-in traffic
#   PGO_DURATION  — seconds to run the workload (default: 30)
#   DWAAR_CONFIG  — Dwaarfile to use; if unset, a temp one is created

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROFILE_DIR="${PROFILE_DIR:-${PROJECT_ROOT}/target/pgo-profiles}"
PGO_DURATION="${PGO_DURATION:-30}"
DWAAR_BIN="${PROJECT_ROOT}/target/release/dwaar"
CLEANUP_PIDS=()
CLEANUP_FILES=()

# ── Color helpers ─────────────────────────────────────────────────────────────

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

info()  { printf "${GREEN}[ok]${RESET}  %s\n"   "$*"; }
warn()  { printf "${YELLOW}[warn]${RESET} %s\n" "$*"; }
error() { printf "${RED}[err]${RESET}  %s\n"    "$*" >&2; exit 1; }
step()  { printf "\n${BOLD}── %s${RESET}\n"     "$*"; }

# ── Cleanup on exit ───────────────────────────────────────────────────────────

cleanup() {
    for pid in "${CLEANUP_PIDS[@]+"${CLEANUP_PIDS[@]}"}"; do
        kill "$pid" 2>/dev/null || true
    done
    for f in "${CLEANUP_FILES[@]+"${CLEANUP_FILES[@]}"}"; do
        rm -f "$f"
    done
}

trap cleanup EXIT INT TERM

# ── Find llvm-profdata ────────────────────────────────────────────────────────

find_llvm_profdata() {
    # Prefer whatever's already on PATH — fastest and most predictable.
    if command -v llvm-profdata &>/dev/null; then
        echo "$(command -v llvm-profdata)"
        return
    fi

    # Fall back to the copy shipped with the active Rust toolchain.
    # Requires: rustup component add llvm-tools
    local sysroot host_triple
    sysroot="$(rustc --print sysroot 2>/dev/null)" || true
    host_triple="$(rustc -vV 2>/dev/null | grep '^host:' | cut -d' ' -f2)" || true

    if [[ -n "${sysroot}" && -n "${host_triple}" ]]; then
        local candidate="${sysroot}/lib/rustlib/${host_triple}/bin/llvm-profdata"
        if [[ -x "${candidate}" ]]; then
            echo "${candidate}"
            return
        fi
    fi

    # macOS fallback via Xcode toolchain.
    if command -v xcrun &>/dev/null; then
        local xc_path
        xc_path="$(xcrun -f llvm-profdata 2>/dev/null)" || true
        if [[ -n "${xc_path}" ]]; then
            echo "${xc_path}"
            return
        fi
    fi

    return 1
}

# ── Prerequisite checks ───────────────────────────────────────────────────────

step "Checking prerequisites"

cd "${PROJECT_ROOT}"

if ! command -v cargo &>/dev/null; then
    error "cargo not found — install Rust via https://rustup.rs"
fi

LLVM_PROFDATA="$(find_llvm_profdata)" || {
    warn "llvm-profdata not found on PATH or in rustc sysroot."
    warn "Install it with: rustup component add llvm-tools"
    warn "Then re-run this script."
    error "Missing llvm-profdata"
}
info "llvm-profdata: ${LLVM_PROFDATA}"

# Confirm the dwaar binary target exists in the workspace.
if ! cargo metadata --no-deps --format-version 1 2>/dev/null \
        | grep -q '"name":"dwaar"'; then
    error "No binary named 'dwaar' found in the workspace"
fi

# ── Step 1: Instrumented build ────────────────────────────────────────────────

step "Step 1 — Instrumented build"

# Wipe stale profiles so old data doesn't contaminate the merge.
rm -rf "${PROFILE_DIR}"
mkdir -p "${PROFILE_DIR}"

info "Building with -Cprofile-generate..."
RUSTFLAGS="-Cprofile-generate=${PROFILE_DIR}" \
    cargo build --release --bin dwaar
info "Instrumented binary ready: ${DWAAR_BIN}"

# ── Step 2: Profile collection ────────────────────────────────────────────────

step "Step 2 — Profile collection (${PGO_DURATION}s)"

BACKEND_PORT=9090
DWAAR_PORT=6188

# Create a minimal Dwaarfile unless the caller supplied one.
if [[ -z "${DWAAR_CONFIG:-}" ]]; then
    TEMP_DWAARFILE="$(mktemp /tmp/dwaarfile.pgo.XXXXXX)"
    CLEANUP_FILES+=("${TEMP_DWAARFILE}")
    cat >"${TEMP_DWAARFILE}" <<EOF
:${DWAAR_PORT} {
    reverse_proxy 127.0.0.1:${BACKEND_PORT}
}
EOF
    DWAAR_CONFIG="${TEMP_DWAARFILE}"
    info "Created temp Dwaarfile: ${DWAAR_CONFIG}"
fi

# Spin up a throwaway HTTP backend that just echoes 200 OK.
python3 -m http.server "${BACKEND_PORT}" --bind 127.0.0.1 \
    >/dev/null 2>&1 &
BACKEND_PID=$!
CLEANUP_PIDS+=("${BACKEND_PID}")
info "Mock backend PID ${BACKEND_PID} on :${BACKEND_PORT}"

# Give the backend a moment before dwaar tries to connect.
sleep 1

# Start the instrumented proxy.
"${DWAAR_BIN}" --config "${DWAAR_CONFIG}" \
    >/dev/null 2>&1 &
DWAAR_PID=$!
CLEANUP_PIDS+=("${DWAAR_PID}")
info "Instrumented dwaar PID ${DWAAR_PID} on :${DWAAR_PORT}"

# Poll until dwaar accepts connections (max 15s).
READY=0
for i in $(seq 1 15); do
    if curl -sf "http://127.0.0.1:${DWAAR_PORT}/" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 1
done

if [[ "${READY}" -eq 0 ]]; then
    warn "dwaar didn't respond within 15s — profiling may be incomplete"
fi

# Run traffic.  Prefer a caller-supplied workload; fall back to the repo's
# stress test if it exists; otherwise just loop with curl.
if [[ -n "${PGO_WORKLOAD:-}" ]]; then
    info "Running custom workload: ${PGO_WORKLOAD}"
    STRESS_TARGET="127.0.0.1:${DWAAR_PORT}" bash "${PGO_WORKLOAD}" &
    WORKLOAD_PID=$!
    CLEANUP_PIDS+=("${WORKLOAD_PID}")
    sleep "${PGO_DURATION}"
    kill "${WORKLOAD_PID}" 2>/dev/null || true
elif cargo test -p dwaar-cli --test stress -- \
        --list 2>/dev/null | grep -q 'stress_test'; then
    info "Using stress test suite for profiling"
    STRESS_TARGET="127.0.0.1:${DWAAR_PORT}" \
        cargo test -p dwaar-cli --test stress \
            -- --ignored --nocapture 2>/dev/null || true
else
    info "Sending curl traffic for ${PGO_DURATION}s (no stress suite found)"
    DEADLINE=$(( $(date +%s) + PGO_DURATION ))
    while [[ $(date +%s) -lt ${DEADLINE} ]]; do
        curl -sf "http://127.0.0.1:${DWAAR_PORT}/" >/dev/null 2>&1 || true
    done
fi

# Graceful shutdown — let dwaar flush any in-flight profile writes.
kill -TERM "${DWAAR_PID}" 2>/dev/null || true
wait "${DWAAR_PID}" 2>/dev/null || true
kill -TERM "${BACKEND_PID}" 2>/dev/null || true

# Remove the PIDs we've already reaped so cleanup() doesn't warn.
CLEANUP_PIDS=()

PROFRAW_COUNT=$(find "${PROFILE_DIR}" -name '*.profraw' | wc -l | tr -d ' ')
info "${PROFRAW_COUNT} .profraw file(s) collected in ${PROFILE_DIR}"

if [[ "${PROFRAW_COUNT}" -eq 0 ]]; then
    error "No profile data collected — check that the instrumented binary ran"
fi

# ── Step 3: Merge profiles ────────────────────────────────────────────────────

step "Step 3 — Merge profiles"

MERGED="${PROFILE_DIR}/merged.profdata"
"${LLVM_PROFDATA}" merge -o "${MERGED}" "${PROFILE_DIR}"
info "Merged profile: ${MERGED}"

# ── Step 4: Optimized build ───────────────────────────────────────────────────

step "Step 4 — PGO-optimized build"

PRE_PGO_SIZE="$(stat -c%s "${DWAAR_BIN}" 2>/dev/null || stat -f%z "${DWAAR_BIN}")"

RUSTFLAGS="-Cprofile-use=${MERGED} -Cllvm-args=-pgo-warn-missing-function" \
    cargo build --release --bin dwaar
info "Optimized binary ready: ${DWAAR_BIN}"

POST_PGO_SIZE="$(stat -c%s "${DWAAR_BIN}" 2>/dev/null || stat -f%z "${DWAAR_BIN}")"

# ── Optional: BOLT ────────────────────────────────────────────────────────────
# BOLT reorders basic blocks and functions based on a separate instrumentation
# pass for an additional 5-15% improvement.  It needs its own profiling run
# with llvm-bolt --instrument, then llvm-bolt -data=bolt.fdata.
# Tracked in ISSUE-061 (future step) — wire it in once llvm-bolt lands in CI.
if command -v llvm-bolt &>/dev/null; then
    warn "llvm-bolt found but BOLT integration requires a dedicated instrumentation"
    warn "pass — skipping for now (see ISSUE-061)."
fi

# ── Summary ───────────────────────────────────────────────────────────────────

step "Summary"

human_size() {
    local bytes=$1
    if (( bytes >= 1048576 )); then
        printf "%.1f MiB" "$(echo "scale=1; ${bytes}/1048576" | bc)"
    else
        printf "%.1f KiB" "$(echo "scale=1; ${bytes}/1024" | bc)"
    fi
}

printf "  Before PGO : %s\n" "$(human_size "${PRE_PGO_SIZE}")"
printf "  After PGO  : %s\n" "$(human_size "${POST_PGO_SIZE}")"
printf "  Binary     : %s\n" "${DWAAR_BIN}"
printf "  Profiles   : %s\n" "${PROFILE_DIR}"
printf "\n"
info "PGO build complete. Run your benchmarks to measure the gain."
