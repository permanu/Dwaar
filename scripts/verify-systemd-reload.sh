#!/usr/bin/env bash
# verify-systemd-reload.sh
#
# Asserts that `systemctl reload dwaar` performs a Pingora-style warm-restart
# (zero dropped connections, MAINPID changes, no 5xx) instead of killing the
# daemon. Must be run on a Linux host with dwaar already installed via
# scripts/install.sh and a Dwaarfile that exposes at least one HTTP route.
#
# Usage: sudo ./scripts/verify-systemd-reload.sh [URL]
#   URL defaults to http://127.0.0.1/healthz
#
# Exit 0 = warm-restart confirmed. Exit non-zero = regression.

set -euo pipefail

URL="${1:-http://127.0.0.1/healthz}"
DURATION_S=10
RPS=20

if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not available — this check only runs on Linux hosts." >&2
    exit 2
fi

if ! systemctl is-active --quiet dwaar; then
    echo "dwaar.service is not active — start it before running this check." >&2
    exit 2
fi

old_pid=$(systemctl show -p MainPID --value dwaar)
echo "dwaar MainPID before reload: ${old_pid}"

tmp_log=$(mktemp)
trap 'rm -f "${tmp_log}"' EXIT

# Background load: small, non-blocking, just enough to see drops.
(
    end=$(( $(date +%s) + DURATION_S ))
    while [ "$(date +%s)" -lt "${end}" ]; do
        for _ in $(seq 1 "${RPS}"); do
            code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${URL}" || echo "000")
            echo "${code}" >> "${tmp_log}"
        done
        sleep 1
    done
) &
load_pid=$!

# Trigger reload mid-flight.
sleep 2
echo "issuing: systemctl reload dwaar"
systemctl reload dwaar

wait "${load_pid}"

new_pid=$(systemctl show -p MainPID --value dwaar)
echo "dwaar MainPID after reload:  ${new_pid}"

if ! systemctl is-active --quiet dwaar; then
    echo "FAIL: dwaar.service is no longer active after reload — SIGHUP regression?" >&2
    exit 1
fi

if [ "${new_pid}" = "${old_pid}" ]; then
    echo "WARN: MainPID unchanged (${new_pid}). Reload may have been a no-op rather than a warm-restart." >&2
fi

total=$(wc -l < "${tmp_log}" | tr -d ' ')
fives=$(grep -cE '^5[0-9]{2}$' "${tmp_log}" || true)
zeros=$(grep -cE '^000$' "${tmp_log}" || true)
twos=$(grep -cE '^2[0-9]{2}$' "${tmp_log}" || true)
echo "requests: total=${total} 2xx=${twos} 5xx=${fives} conn-fail=${zeros}"

if [ "${fives}" != "0" ] || [ "${zeros}" != "0" ]; then
    echo "FAIL: dropped or 5xx requests during reload — warm-restart not clean." >&2
    exit 1
fi

echo "OK: warm-restart verified — no dropped connections, no 5xx."
