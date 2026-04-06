#!/usr/bin/env bash
set -euo pipefail

# ─── Dwaar vs nginx benchmark ────────────────────────────────────────
# Fair comparison: Rust backend, wrk load generator, same machine.
#
# Usage:
#   ./bench.sh              # Dwaar vs nginx
#   ./bench.sh --dwaar-only # Dwaar only
#
# Prerequisites:
#   cargo build --release
#   brew install wrk nginx

DURATION=10
WARMUP=2
BACKEND_PORT=19876
DWAAR_PORT=6188
NGINX_PORT=8199
CONNS=(100 500 1000)

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

cleanup() {
    kill $BACKEND_PID 2>/dev/null || true
    kill $DWAAR_PID 2>/dev/null || true
    nginx -s stop 2>/dev/null || true
}
trap cleanup EXIT

# ── Compile Rust backend ──
BACKEND_SRC=$(mktemp /tmp/bench-backend-XXXX.rs)
cat > "$BACKEND_SRC" << 'RSEOF'
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 27\r\nContent-Type: application/json\r\nConnection: keep-alive\r\n\r\n{\"status\":\"ok\",\"version\":1}";
fn main() {
    let l = TcpListener::bind("127.0.0.1:BACKEND_PORT").expect("bind");
    for s in l.incoming() {
        let mut s = s.expect("accept");
        thread::spawn(move || {
            let mut b = [0u8; 4096];
            loop { match s.read(&mut b) { Ok(0) | Err(_) => break, Ok(_) => { let _ = s.write_all(RESP); } } }
        });
    }
}
RSEOF
sed -i '' "s/BACKEND_PORT/$BACKEND_PORT/" "$BACKEND_SRC"
BACKEND_BIN=$(mktemp /tmp/bench-backend-XXXX)
rustc -O -o "$BACKEND_BIN" "$BACKEND_SRC" 2>/dev/null || { echo "Failed to compile backend"; exit 1; }

# ── Start backend ──
$BACKEND_BIN &
BACKEND_PID=$!; sleep 1
curl -sf "http://127.0.0.1:$BACKEND_PORT/" >/dev/null || { echo "Backend failed"; exit 1; }

run_bench() {
    local name="$1" port="$2" pid="$3"
    echo -e "\n${BOLD}${CYAN}═══ $name ═══${NC}"
    printf "  %-6s  %8s  %8s  %8s  %6s\n" "Conns" "Req/sec" "P50" "P99" "RSS"
    printf "  %-6s  %8s  %8s  %8s  %6s\n" "-----" "-------" "------" "------" "-----"

    for C in "${CONNS[@]}"; do
        wrk -t4 -c$C -d${WARMUP}s "http://127.0.0.1:$port/" >/dev/null 2>&1
        local result
        result=$(wrk -t4 -c$C -d${DURATION}s --latency "http://127.0.0.1:$port/" 2>&1)
        local rps p50 p99
        rps=$(echo "$result" | grep "Requests/sec" | awk '{printf "%.0f", $2}')
        p50=$(echo "$result" | grep "50%" | awk '{print $2}')
        p99=$(echo "$result" | grep "99%" | awk '{print $2}')

        # RSS — sum all child workers for nginx
        local rss=0
        for wp in $(pgrep -P "$pid" 2>/dev/null); do
            local r; r=$(ps -o rss= -p "$wp" 2>/dev/null | tr -d ' ') || true
            rss=$((rss + ${r:-0}))
        done
        # Add parent
        local pr; pr=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ') || true
        rss=$((rss + ${pr:-0}))
        local rss_mb=$((rss / 1024))

        printf "  %-6s  %8s  %8s  %8s  %4s MB\n" "$C" "$rps" "$p50" "$p99" "$rss_mb"
    done
}

# ── Dwaar ──
echo -e "${GREEN}Starting Dwaar (bare mode)...${NC}"
DWAAR_BIN="$(dirname "$0")/target/release/dwaar"
[ -f "$DWAAR_BIN" ] || { echo "Build first: cargo build --release"; exit 1; }
echo "127.0.0.1 { reverse_proxy 127.0.0.1:$BACKEND_PORT }" > /tmp/dwaar-bench.conf
RUST_LOG=error $DWAAR_BIN --config /tmp/dwaar-bench.conf --bare >/dev/null 2>&1 &
DWAAR_PID=$!; sleep 2
curl -sf "http://127.0.0.1:$DWAAR_PORT/" >/dev/null || { echo "Dwaar failed to start"; exit 1; }
run_bench "Dwaar v0.1.0 (bare)" $DWAAR_PORT $DWAAR_PID
kill $DWAAR_PID 2>/dev/null; wait $DWAAR_PID 2>/dev/null || true; sleep 2

# ── nginx (skip with --dwaar-only) ──
if [[ "${1:-}" != "--dwaar-only" ]]; then
    echo -e "\n${GREEN}Starting nginx...${NC}"
    cat > /tmp/bench-nginx.conf << NEOF
worker_processes auto;
error_log /dev/null;
pid /tmp/bench-nginx.pid;
events { worker_connections 4096; }
http {
    access_log off;
    upstream b { server 127.0.0.1:$BACKEND_PORT; keepalive 128; }
    server { listen $NGINX_PORT; location / { proxy_pass http://b; proxy_http_version 1.1; proxy_set_header Connection ""; } }
}
NEOF
    nginx -c /tmp/bench-nginx.conf; sleep 1
    NGINX_PID=$(cat /tmp/bench-nginx.pid)
    curl -sf "http://127.0.0.1:$NGINX_PORT/" >/dev/null || { echo "nginx failed"; exit 1; }
    run_bench "nginx 1.27.1" $NGINX_PORT $NGINX_PID
    nginx -s stop 2>/dev/null
fi

echo -e "\n${GREEN}Done.${NC}"
