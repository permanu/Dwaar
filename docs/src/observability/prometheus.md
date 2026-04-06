# Prometheus Metrics

Dwaar exposes every counter, gauge, and histogram in Prometheus text exposition format on the admin API. Scrape `GET /metrics` on port `6190` to feed your existing Prometheus deployment with per-domain request rates, latencies, byte counts, TLS timing, rate limiter activity, cache efficiency, and standard process resource usage.

All metrics use lock-free atomics — no mutexes, no allocation on the hot path after the first request per domain. Up to 10,000 distinct domains are tracked; new domains beyond that limit are silently dropped to prevent unbounded memory growth.

---

## Quick Start

Metrics are enabled by default. No configuration is required. Verify the endpoint is reachable:

```sh
curl http://127.0.0.1:6190/metrics
```

You should see output beginning with:

```
# HELP dwaar_requests_total Total HTTP requests processed.
# TYPE dwaar_requests_total counter
dwaar_requests_total{domain="example.com",method="GET",status="2xx"} 42
...
```

---

## Metrics Endpoint

| Property | Value |
|----------|-------|
| Method | `GET` |
| Path | `/metrics` |
| Port | `6190` (admin API) |
| Content-Type | `text/plain; version=0.0.4` |
| Auth | Bearer token required on TCP; bypassed on Unix socket |

The endpoint renders a full snapshot on every request. There is no incremental or streaming mode.

---

## Available Metrics

### Request Metrics

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `dwaar_requests_total` | counter | `domain`, `method`, `status` | Total HTTP requests processed. `method` is one of `GET POST PUT DELETE PATCH HEAD OPTIONS OTHER`. `status` is a group: `1xx 2xx 3xx 4xx 5xx`. |
| `dwaar_request_duration_seconds` | histogram | `domain` | End-to-end request duration in seconds. Buckets: 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s. |
| `dwaar_bytes_sent_total` | counter | `domain` | Total response bytes sent to clients. |
| `dwaar_bytes_received_total` | counter | `domain` | Total request bytes received from clients. |
| `dwaar_active_connections` | gauge | `domain` | Currently active connections. Incremented on connection open, decremented on close. |

### Upstream Metrics

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `dwaar_upstream_connect_duration_seconds` | histogram | `upstream` | Time to establish a connection to the upstream backend in seconds. Same bucket boundaries as request duration. |
| `dwaar_upstream_health` | gauge | `upstream` | Upstream health status: `1` = healthy, `0` = unhealthy. |

### TLS Metrics

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `dwaar_tls_handshake_duration_seconds` | histogram | _(none)_ | Global TLS handshake duration in seconds. Only emitted when at least one handshake has completed. |

### Config Metrics

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `dwaar_config_reload_total` | counter | `result` | Config reload attempts. `result` is `success` or `failure`. Only emitted when at least one reload has occurred. |

### Rate Limiter Metrics

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `dwaar_rate_limit_rejected_total` | counter | `domain` | Requests rejected with HTTP 429 by the rate limiter. |
| `dwaar_rate_limit_allowed_total` | counter | `domain` | Requests allowed through by the rate limiter. |

### Cache Metrics

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `dwaar_cache_hits_total` | counter | `domain` | Responses served from cache. |
| `dwaar_cache_misses_total` | counter | `domain` | Requests that required a backend fetch (cache miss). |
| `dwaar_cache_stored_bytes` | gauge | _(none)_ | Total bytes currently held in the HTTP response cache. |

### Process Metrics

These follow the standard Prometheus `process_*` naming convention recognised automatically by Grafana and most dashboards.

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `process_cpu_seconds_total` | counter | _(none)_ | Total user + system CPU time consumed by the proxy process in seconds. |
| `process_resident_memory_bytes` | gauge | _(none)_ | Resident set size (RSS) in bytes. Read from `/proc/self/status` on Linux; `getrusage(RUSAGE_SELF)` on macOS. |
| `process_open_fds` | gauge | _(none)_ | Number of open file descriptors. |
| `process_max_fds` | gauge | _(none)_ | File descriptor limit (`RLIMIT_NOFILE` soft limit). |
| `process_start_time_seconds` | gauge | _(none)_ | Unix timestamp of process start. Used to compute uptime: `time() - process_start_time_seconds`. |
| `process_threads` | gauge | _(none)_ | Number of OS threads. Read from `/proc/self/status` on Linux; reports `0` on other platforms. |

---

## Scrape Configuration

Add the following job to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: dwaar
    static_configs:
      - targets:
          - "127.0.0.1:6190"   # replace with your admin API address
    metrics_path: /metrics
    # If you enabled bearer token auth on the admin API:
    authorization:
      credentials: "your-admin-token-here"
    scrape_interval: 15s
    scrape_timeout: 5s
```

For multi-instance deployments, list every admin API address under `targets` or use service discovery:

```yaml
scrape_configs:
  - job_name: dwaar
    file_sd_configs:
      - files:
          - /etc/prometheus/dwaar_targets.json
    metrics_path: /metrics
    authorization:
      credentials_file: /etc/prometheus/dwaar_token
```

---

## Grafana Dashboard

The queries below cover the most common panels. Adjust the `domain` and `upstream` label matchers to match your environment.

**Request rate (per domain, by status group)**

```promql
sum by (domain, status) (
  rate(dwaar_requests_total[1m])
)
```

**Error rate (5xx / total)**

```promql
sum(rate(dwaar_requests_total{status="5xx"}[5m]))
/
sum(rate(dwaar_requests_total[5m]))
```

**P99 request latency per domain**

```promql
histogram_quantile(
  0.99,
  sum by (domain, le) (
    rate(dwaar_request_duration_seconds_bucket[5m])
  )
)
```

**P50 upstream connect latency**

```promql
histogram_quantile(
  0.50,
  sum by (upstream, le) (
    rate(dwaar_upstream_connect_duration_seconds_bucket[5m])
  )
)
```

**Cache hit ratio per domain**

```promql
rate(dwaar_cache_hits_total[5m])
/
(rate(dwaar_cache_hits_total[5m]) + rate(dwaar_cache_misses_total[5m]))
```

**Rate limit rejection rate**

```promql
sum by (domain) (
  rate(dwaar_rate_limit_rejected_total[1m])
)
```

**Active connections**

```promql
sum by (domain) (dwaar_active_connections)
```

**Process memory (RSS)**

```promql
process_resident_memory_bytes
```

**Process uptime**

```promql
time() - process_start_time_seconds
```

**FD utilisation**

```promql
process_open_fds / process_max_fds
```

---

## Related

- [Admin API](../api/admin.md) — full reference for all `/metrics`, `/routes`, `/health`, and `/analytics` endpoints
- [Logging](logging.md) — structured JSON access logs with per-request fields
- [Analytics](analytics.md) — in-memory analytics aggregation and the `/analytics` JSON endpoint
