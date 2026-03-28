#!/usr/bin/env bash
# Dwaar vs nginx benchmark — Docker-based, fair comparison.
#
# Usage:
#   cd benchmarks/docker
#   ./run-benchmark.sh
#
# Requires: docker, docker compose, wrk (brew install wrk)

set -euo pipefail

DURATION="${BENCH_DURATION:-30s}"
THREADS="${BENCH_THREADS:-4}"
CONNECTIONS="${BENCH_CONNECTIONS:-100 500 1000}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

header() { echo -e "\n${BOLD}${CYAN}═══ $1 ═══${NC}\n"; }
info()   { echo -e "${GREEN}▸${NC} $1"; }
warn()   { echo -e "${RED}▸${NC} $1"; }

# Check wrk is installed
if ! command -v wrk &>/dev/null; then
    warn "wrk not found. Install with: brew install wrk"
    exit 1
fi

cd "$SCRIPT_DIR"

# ── Build & start containers ─────────────────────────────────────

header "Building Dwaar (release mode) and starting containers"
NO_COLOR=1 /usr/local/bin/docker compose build --quiet
NO_COLOR=1 /usr/local/bin/docker compose up -d

info "Waiting for services to be ready..."
sleep 5

# Verify all services are healthy
for svc in backend dwaar nginx-proxy; do
    if ! NO_COLOR=1 /usr/local/bin/docker compose ps "$svc" 2>/dev/null | grep -q "Up"; then
        warn "Service $svc is not running!"
        NO_COLOR=1 /usr/local/bin/docker compose logs "$svc" | tail -10
        NO_COLOR=1 /usr/local/bin/docker compose down
        exit 1
    fi
done

# Quick health check
for target in "http://127.0.0.1:9090" "http://127.0.0.1:6188" "http://127.0.0.1:8080"; do
    if ! curl -sf -o /dev/null -H "Host: backend" "$target" 2>/dev/null; then
        # Try without host header
        curl -sf -o /dev/null "$target" 2>/dev/null || true
    fi
done
info "All services running"

# Get container IDs for resource monitoring
DWAAR_CID=$(NO_COLOR=1 /usr/local/bin/docker compose ps -q dwaar)
NGINX_CID=$(NO_COLOR=1 /usr/local/bin/docker compose ps -q nginx-proxy)

# ── Helper: run wrk and extract stats ────────────────────────────

run_wrk() {
    local name="$1"
    local url="$2"
    local conns="$3"
    local host_header="${4:-backend}"

    wrk -t"$THREADS" -c"$conns" -d"$DURATION" \
        -H "Host: $host_header" \
        --latency "$url" 2>&1
}

# Extract metrics from wrk output
parse_wrk() {
    local output="$1"
    local rps lat50 lat99 latavg transfer errors

    rps=$(echo "$output" | grep "Requests/sec:" | awk '{print $2}')
    lat50=$(echo "$output" | grep "50%" | awk '{print $2}')
    lat99=$(echo "$output" | grep "99%" | awk '{print $2}')
    latavg=$(echo "$output" | grep "Latency" | head -1 | awk '{print $2}')
    transfer=$(echo "$output" | grep "Transfer/sec:" | awk '{print $2}')
    errors=$(echo "$output" | grep -c "Socket errors" || echo "0")

    echo "$rps|$lat50|$lat99|$latavg|$transfer|$errors"
}

# Get container memory usage
get_memory_mb() {
    local cid="$1"
    NO_COLOR=1 /usr/local/bin/docker stats --no-stream --format '{{.MemUsage}}' "$cid" 2>/dev/null | \
        awk -F'/' '{gsub(/[^0-9.]/, "", $1); print $1}'
}

# ── Run benchmarks ───────────────────────────────────────────────

RESULTS_FILE="/tmp/dwaar-vs-nginx-results.txt"
echo "" > "$RESULTS_FILE"

header "Benchmark Configuration"
info "Duration:    $DURATION per test"
info "Threads:     $THREADS"
info "Connections: $CONNECTIONS"
info "CPU limit:   2 cores per container"
info "Memory:      256 MB per container"

# Print table header
printf "\n${BOLD}%-12s  %-8s  %-12s  %-10s  %-10s  %-10s  %-12s  %-8s${NC}\n" \
    "Proxy" "Conns" "RPS" "p50 lat" "p99 lat" "Avg lat" "Transfer" "Mem(MB)"
printf "%-12s  %-8s  %-12s  %-10s  %-10s  %-10s  %-12s  %-8s\n" \
    "──────────" "──────" "──────────" "────────" "────────" "────────" "──────────" "──────"

for CONNS in $CONNECTIONS; do

    # ── Baseline (direct to backend) ──
    header "Baseline: direct to backend ($CONNS connections)"
    output=$(run_wrk "baseline" "http://127.0.0.1:9090/" "$CONNS" "localhost")
    parsed=$(parse_wrk "$output")
    IFS='|' read -r rps lat50 lat99 latavg transfer errors <<< "$parsed"
    printf "%-12s  %-8s  %-12s  %-10s  %-10s  %-10s  %-12s  %-8s\n" \
        "direct" "$CONNS" "$rps" "$lat50" "$lat99" "$latavg" "$transfer" "n/a"
    echo "direct|$CONNS|$parsed" >> "$RESULTS_FILE"

    # ── Dwaar ──
    header "Dwaar: proxy to backend ($CONNS connections)"
    output=$(run_wrk "dwaar" "http://127.0.0.1:6188/" "$CONNS" "backend")
    parsed=$(parse_wrk "$output")
    IFS='|' read -r rps lat50 lat99 latavg transfer errors <<< "$parsed"
    mem=$(get_memory_mb "$DWAAR_CID")
    printf "%-12s  %-8s  %-12s  %-10s  %-10s  %-10s  %-12s  %-8s\n" \
        "DWAAR" "$CONNS" "$rps" "$lat50" "$lat99" "$latavg" "$transfer" "$mem"
    echo "dwaar|$CONNS|$parsed|$mem" >> "$RESULTS_FILE"

    # ── nginx ──
    header "nginx: proxy to backend ($CONNS connections)"
    output=$(run_wrk "nginx" "http://127.0.0.1:8080/" "$CONNS" "backend")
    parsed=$(parse_wrk "$output")
    IFS='|' read -r rps lat50 lat99 latavg transfer errors <<< "$parsed"
    mem=$(get_memory_mb "$NGINX_CID")
    printf "%-12s  %-8s  %-12s  %-10s  %-10s  %-10s  %-12s  %-8s\n" \
        "NGINX" "$CONNS" "$rps" "$lat50" "$lat99" "$latavg" "$transfer" "$mem"
    echo "nginx|$CONNS|$parsed|$mem" >> "$RESULTS_FILE"

    echo ""
    sleep 2
done

# ── Docker stats snapshot ────────────────────────────────────────

header "Final Container Resource Usage"
NO_COLOR=1 /usr/local/bin/docker stats --no-stream --format \
    'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}' \
    "$DWAAR_CID" "$NGINX_CID" 2>/dev/null

# ── Cleanup ──────────────────────────────────────────────────────

header "Cleaning up"
NO_COLOR=1 /usr/local/bin/docker compose down --remove-orphans --timeout 5

info "Results saved to $RESULTS_FILE"
info "Done!"
