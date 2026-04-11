---
title: "Request Logging"
---

# Request Logging

Every completed HTTP request produces a structured `RequestLog` entry with 23 fields covering timing, identity, routing, security, and performance. Entries are serialized to JSON using a SIMD-accelerated serializer and written through a bounded async channel to one or more output destinations.

Optional fields are omitted from the JSON object when absent — no `null` noise in your log aggregator.

---

## Quick Start

Add `log` to any site block to enable access logging to stdout with the default JSON format:

```txt
api.example.com {
    reverse_proxy localhost:8080
    log
}
```

That is all that is required. Every request to `api.example.com` will produce one JSON line on stdout.

---

## How It Works

The logging pipeline is asynchronous and non-blocking. The proxy thread never waits for I/O.

```mermaid
graph LR
    A[Request completes] --> B[Build RequestLog]
    B --> C{try_send to\nbounded channel\n8 192 slots}
    C -- slot available --> D[LogSender enqueues]
    C -- channel full --> E[Entry dropped\nwarn! emitted]
    D --> F[Batch writer loop]
    F -- 200 entries --> G[flush batch]
    F -- 500 ms timer --> G
    F -- channel closed --> G
    G --> H{Output}
    H --> I[stdout / stderr]
    H --> J[File with rotation]
    H --> K[Unix socket]
```

The batch writer runs as a Pingora `BackgroundService`. It drains the channel in batches of up to 200 entries, flushing either when the batch is full or every 500 ms — whichever comes first. On shutdown, any remaining entries in the batch are flushed before the writer exits.

**Backpressure policy:** when the channel is full (8 192 pending entries), new entries are dropped and a `WARN` log is emitted. Proxy latency always wins over logging completeness.

---

## Log Fields

Every request produces the following fields. Fields marked **optional** are omitted from the JSON output when not present.

| JSON key | Type | Required | Description | Example |
|---|---|---|---|---|
| `timestamp` | string (RFC 3339) | yes | When the request arrived, UTC | `"2026-04-05T14:23:01.452Z"` |
| `request_id` | string | yes | UUID v7 unique to this request (time-sortable) | `"01924f5c-7e2a-7d00-b3f4-deadbeef1234"` |
| `method` | string | yes | HTTP method | `"GET"` |
| `path` | string | yes | Request path, without query string | `"/api/users"` |
| `query` | string | optional | Raw query string if present | `"page=1&limit=20"` |
| `host` | string | yes | `Host` header, or `:authority` for HTTP/2 | `"api.example.com"` |
| `status` | integer | yes | HTTP response status code | `200` |
| `response_time_us` | integer | yes | Total time from request received to response sent, microseconds | `1234` |
| `client_ip` | string | yes | Client IP address from the direct TCP connection — not `X-Forwarded-For` | `"192.168.1.100"` |
| `user_agent` | string | optional | `User-Agent` request header | `"Mozilla/5.0 ..."` |
| `referer` | string | optional | `Referer` request header | `"https://example.com"` |
| `bytes_sent` | integer | yes | Response body size in bytes | `4096` |
| `bytes_received` | integer | yes | Request body size in bytes | `256` |
| `tls_version` | string | optional | TLS version negotiated; absent for plaintext | `"TLSv1.3"` |
| `http_version` | string | yes | HTTP protocol version | `"HTTP/2"` |
| `is_bot` | boolean | yes | Whether the request was classified as a bot | `false` |
| `country` | string | optional | Two-letter country code from GeoIP lookup | `"US"` |
| `upstream_addr` | string | yes | Backend address that served this request | `"127.0.0.1:8080"` |
| `upstream_response_time_us` | integer | yes | Time the upstream took to respond, microseconds | `980` |
| `cache_status` | string | optional | Cache result if applicable | `"HIT"` or `"MISS"` |
| `compression` | string | optional | Compression algorithm applied to the response | `"gzip"` or `"br"` |
| `trace_id` | string | optional | W3C trace ID for distributed tracing correlation | `"4bf92f3577b34da6a3ce929d0e0e4736"` |
| `upstream_error_body` | string | optional | First 1 KB of the upstream response body on 5xx errors; absent on successful responses | `"connection refused"` |
| `rejected_by` | string | optional | Plugin name that denied the request with a non-fatal rejection (e.g. rate limited, auth challenge). Set to a static interned string, never user input. | `"rate_limit"` |
| `blocked_by` | string | optional | Plugin name that hard-blocked the request (e.g. IP deny list, bot detection). Mutually exclusive with `rejected_by` in normal flows. | `"bot_detection"` |

All timing fields use **microseconds** for sub-millisecond precision. Both `response_time_us` and `upstream_response_time_us` are always present; their difference accounts for Dwaar's processing overhead.

### Denial reason fields

The `rejected_by` and `blocked_by` fields make plugin-driven denials first-class in log analysis — dashboards and alerts no longer have to infer "why was this a 429?" from the status code alone. Both fields are `&'static str` values set by the plugin at deny time, so the log line is an O(1) tag write with no allocation and no risk of user-controlled content landing in the log.

| Field | Semantic | Populated by |
|---|---|---|
| `rejected_by` | Soft denial — the request was rate-limited or sent back a challenge, and a legitimate client can retry. | `rate_limit` (0.2.2) |
| `blocked_by` | Hard denial — the request was denied outright based on identity, reputation, or policy. | Infrastructure wired for `bot_detection` in 0.2.2; no setter yet. |

Both fields are omitted from the JSON object when `None`, so logs for allowed traffic stay compact. A rate-limited request logs as:

```json
{"timestamp":"2026-04-11T12:00:00Z","method":"GET","path":"/api","status":429,"rejected_by":"rate_limit", ...}
```

The value space is a fixed set of plugin names. Tailing for `rejected_by=rate_limit` in your log aggregator gives an instant count of per-IP rejections without a secondary metric source.

---

## Privacy

### Client IP anonymization

Client IP addresses are anonymized at serialization time. This behaviour is currently compiled in (`ANONYMIZE_CLIENT_IP = true`) and is always active:

- **IPv4** — the last octet is zeroed, retaining the `/24` prefix. `203.0.113.42` logs as `203.0.113.0`.
- **IPv6** — segments 3–7 are zeroed, retaining the `/48` prefix (first 3 segments). `2001:db8:1234:5678::1` logs as `2001:db8:1234::`.

The full client IP is never written to the log. The `client_ip` field always contains the anonymized form.

### Query-string redaction

Sensitive query-parameter values are replaced with `REDACTED` before the `query` field is serialized. The following parameter names are treated as sensitive (matching is case-insensitive):

`token`, `key`, `secret`, `password`, `api_key`, `access_token`, `auth`

For example, a request to `/search?q=hello&token=abc123` logs `query` as `q=hello&token=REDACTED`. Parameters not on the list are logged verbatim. No allocation occurs when the query string contains no sensitive keys.

### Referer redaction (0.2.3)

As of 0.2.3, the `referer` field goes through the **same** query-string redactor as the request's own query. If a visitor lands on your site from `https://partner.example/dashboard?token=abc123&user=42`, the logged `referer` becomes `https://partner.example/dashboard?token=REDACTED&user=42`.

The redaction is applied after host validation, so an invalid or oversized Referer is still dropped before it reaches the redactor. Hosts with no query string pass through unchanged with no allocation.

This closes a leak where credentials embedded in upstream referrer URLs — a surprisingly common pattern with OAuth redirect flows and single-page-app routers — would land verbatim in Dwaar's access log.

### Upstream error body PII redaction (0.2.3)

When an upstream returns a 5xx, Dwaar captures the first 256 bytes of the response body into the `upstream_error_body` field. Before 0.2.3, that capture was a verbatim byte copy — any PII that the upstream dumped into its error page (client IPs, email addresses, stack-trace-embedded secrets) would land in the access log.

0.2.3 runs the captured fragment through a redactor before it is serialized. The following patterns are replaced with `REDACTED`:

| Pattern | Example |
|---|---|
| IPv4 literal | `192.0.2.77` |
| IPv6 literal | `2001:db8::1`, `::1` |
| Email address | `ops@example.com` |
| Bearer token | `Bearer eyJ...` |
| PEM block | `-----BEGIN PRIVATE KEY-----...` |

The redactor operates on the fragment in place, so there is no heap allocation on the no-match hot path. 5xx responses with clean bodies pay nothing.

```json
{
  "timestamp": "2026-04-11T12:00:00Z",
  "status": 500,
  "upstream_error_body": "connection to database REDACTED failed: user REDACTED not found"
}
```

The redactor does **not** try to unpack JSON, YAML, or any other structured format — it operates on the raw bytes. If the upstream is returning structured errors, apply your own redaction upstream and rely on this as defense-in-depth.

---

## Output Destinations

### stdout

The default. Writes one JSON object per line to stdout. Use this when a process supervisor, container runtime, or log shipper (Fluentd, Vector, Loki) consumes stdout.

```txt
log
# equivalent to:
log {
    output stdout
}
```

### stderr

Writes JSON lines to stderr instead of stdout. Useful when stdout carries application output and you want to route logs separately at the shell level.

```txt
log {
    output stderr
}
```

### File with rotation

Writes JSON lines to a file. Rotates when the file exceeds `max_size`. On rotation, the active file is renamed to `access.log.1`, any existing `.1` is shifted to `.2`, and so on up to the `keep` limit. The oldest file beyond `keep` is deleted. Rotation uses atomic POSIX rename — no log lines are lost during the shift.

```txt
log {
    output file /var/log/dwaar/access.log {
        max_size 100mb
        keep     5
    }
}
```

| Option | Default | Description |
|---|---|---|
| `max_size` | none (unbounded) | Rotate when the active file reaches this size. Accepts `kb`, `mb`, `gb` suffixes (case-insensitive) or a plain byte count. |
| `keep` | none | Number of rotated files to retain (`.1` through `.N`). Files beyond this count are deleted. |

After a rotation cycle with `keep 3`, you will see:

```
access.log        ← current, just started
access.log.1      ← previous rotation
access.log.2      ← one before that
access.log.3      ← oldest retained
```

### Unix socket

Writes JSON lines to a `SOCK_STREAM` Unix domain socket. This is the preferred transport when a Permanu agent or any structured-log consumer (Vector, Fluent Bit) runs on the same host.

```txt
log {
    output unix /run/dwaar/log.sock
}
```

**Disconnect resilience:** when the socket is unavailable, incoming log lines are buffered in memory up to 1 000 lines. On the next successful connection, buffered lines are flushed before new entries are written. If the buffer fills before the socket recovers, the oldest lines are evicted — proxy latency still wins. Reconnect attempts are rate-limited to once per second.

---

## Configuration

### Directives

| Directive | Context | Description |
|---|---|---|
| `log` | site block | Enable access logging with defaults (stdout, JSON, INFO) |
| `log { ... }` | site block | Enable logging with explicit options |
| `skip_log` | site block, route block | Suppress the access log entry for matching requests |
| `log_append { ... }` | site block | Inject additional fields into every log entry for this site |
| `log_name <name>` | site block | Assign a named logger for per-site log routing |

### `log` block options

```txt
log {
    output  <destination>   # stdout | stderr | discard | file <path> { ... } | unix <path>
    format  <format>        # json (default) | console
    level   <level>         # INFO (default) | DEBUG | WARN | ERROR
}
```

| Option | Values | Default | Description |
|---|---|---|---|
| `output` | `stdout`, `stderr`, `discard`, `file <path>`, `unix <path>` | `stdout` | Where to send log entries |
| `format` | `json`, `console` | `json` | `json` emits one JSON object per line; `console` emits a human-readable text line |
| `level` | `DEBUG`, `INFO`, `WARN`, `ERROR` | `INFO` | Minimum log level to emit |

### Suppress logging for a route

Use `skip_log` inside a `route` block to silence health-check endpoints or other high-frequency, low-value paths:

```txt
api.example.com {
    reverse_proxy localhost:8080
    log

    route /health {
        skip_log
        respond "ok" 200
    }
}
```

### Append custom fields

Use `log_append` to inject request-scoped fields into every log entry for a site. Values are evaluated as templates at request time.

```txt
app.example.com {
    reverse_proxy localhost:3000
    log

    log_append {
        tenant  {http.request.header.X-Tenant-ID}
        region  eu-west-1
    }
}
```

---

## Per-Site Logging

Each site block configures its own logger independently. Sites with no `log` directive produce no access logs. Sites with different outputs write to their respective destinations simultaneously.

```txt
api.example.com {
    reverse_proxy localhost:8080
    log {
        output unix /run/dwaar/api.sock
        level  DEBUG
    }
}

static.example.com {
    file_server /var/www
    log {
        output file /var/log/dwaar/static.log {
            max_size 50mb
            keep     3
        }
    }
}

internal.example.com {
    reverse_proxy localhost:9000
    # No log directive — no access log for this site.
}
```

---

## Complete Example

A realistic multi-site Dwaarfile with distinct log configurations per domain:

```txt
{
    admin localhost:2019
}

# Public API — structured logs to a Unix socket consumed by Vector
api.example.com {
    reverse_proxy localhost:8080 localhost:8081 {
        lb_policy round_robin
        health_uri /health
    }

    log {
        output unix /run/dwaar/api-logs.sock
        format json
        level  INFO
    }

    log_append {
        service api-gateway
        env     production
    }

    route /health {
        skip_log
        respond "ok" 200
    }
}

# Marketing site — file logs with rotation, human-readable format for tailing
www.example.com {
    file_server /var/www/html

    log {
        output file /var/log/dwaar/www.log {
            max_size 100mb
            keep     7
        }
        format console
        level  INFO
    }
}

# Admin panel — verbose debug logs to stdout, captured by journald
admin.example.com {
    reverse_proxy localhost:4000

    tls {
        client_auth require
    }

    log {
        output stdout
        format json
        level  DEBUG
    }
}

# Metrics scrape endpoint — no logging to avoid noise
metrics.internal {
    metrics /metrics
    skip_log
}
```

---

## Related

- [Analytics](./analytics.md) — aggregated traffic metrics built on top of request logs
- [Prometheus](./prometheus.md) — per-route request counters and latency histograms
- [Tracing](./tracing.md) — distributed trace propagation and `trace_id` correlation
