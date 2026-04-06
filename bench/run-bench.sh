#!/usr/bin/env bash
set -euo pipefail

DURATION=10
WARMUP=3
CONNS=(100 500 1000)

echo "Waiting for proxies..."
for target in dwaar:6188 nginx:8199; do
    for i in $(seq 1 30); do
        if curl -sf "http://$target/" >/dev/null 2>&1; then
            echo "  $target ready"
            break
        fi
        sleep 1
    done
done

run_bench() {
    local name="$1" host="$2" port="$3"
    echo ""
    echo "═══ $name ═══"
    printf "  %-6s  %8s  %8s  %8s\n" "Conns" "Req/sec" "P50" "P99"
    printf "  %-6s  %8s  %8s  %8s\n" "-----" "-------" "------" "------"

    for C in "${CONNS[@]}"; do
        wrk -t2 -c$C -d${WARMUP}s "http://$host:$port/" >/dev/null 2>&1
        result=$(wrk -t2 -c$C -d${DURATION}s --latency "http://$host:$port/" 2>&1)
        rps=$(echo "$result" | grep "Requests/sec" | awk '{printf "%.0f", $2}')
        p50=$(echo "$result" | grep "50%" | awk '{print $2}')
        p99=$(echo "$result" | grep "99%" | awk '{print $2}')
        errs=$(echo "$result" | grep "Socket errors" | sed 's/.*Socket errors: //' || echo "0")
        printf "  %-6s  %8s  %8s  %8s" "$C" "$rps" "$p50" "$p99"
        [ "$errs" != "0" ] && printf "  errors: %s" "$errs"
        printf "\n"
    done
}

echo ""
echo "┌─────────────────────────────────────────────────┐"
echo "│  Dwaar vs nginx — Docker isolated benchmark     │"
echo "│  Backend: Rust TCP, 4 proxy CPUs, 2 wrk CPUs    │"
echo "│  Duration: ${DURATION}s per level, ${WARMUP}s warmup           │"
echo "└─────────────────────────────────────────────────┘"

run_bench "Dwaar" "dwaar" "6188"
run_bench "nginx" "nginx" "8199"

echo ""
echo "Done."
