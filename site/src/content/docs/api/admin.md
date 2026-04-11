---
title: "Admin API Reference"
---

# Admin API Reference

The Admin API is a REST interface for managing Dwaar at runtime — add and remove routes, trigger config reloads, purge cache entries, and inspect metrics without restarting the proxy.

---

## Connection

### Unix socket (default)

The socket path is `/var/run/dwaar-admin.sock` when you pass `--admin-socket` without an argument. UDS connections are trusted by the OS: only processes that have read/write permission on the socket file can connect. No `Authorization` header is required on UDS.

```bash
# Start dwaar with the default UDS path
dwaar --admin-socket

# Start dwaar with a custom UDS path
dwaar --admin-socket /run/dwaar/admin.sock

# Call an endpoint over UDS
curl --unix-socket /var/run/dwaar-admin.sock http://localhost/health
curl --unix-socket /var/run/dwaar-admin.sock http://localhost/routes
```

### TCP (default `127.0.0.1:6190`)

Worker 0 always binds TCP on `127.0.0.1:6190`. This interface requires a bearer token on every authenticated request.

```bash
# Health — no token needed
curl http://127.0.0.1:6190/health

# Authenticated request
curl -H "Authorization: Bearer $DWAAR_ADMIN_TOKEN" \
     http://127.0.0.1:6190/routes
```

---

## Authentication

TCP connections require a bearer token. Set the token via the environment variable `DWAAR_ADMIN_TOKEN` before starting Dwaar:

```bash
export DWAAR_ADMIN_TOKEN="$(openssl rand -hex 32)"
dwaar
```

If `DWAAR_ADMIN_TOKEN` is not set, Dwaar starts but rejects **all** TCP requests with `401`. The warning `admin API will reject all authenticated requests` appears in the log.

Include the token in every TCP request:

```
Authorization: Bearer <token>
```

Unix socket connections bypass token authentication — access is controlled by the socket file's filesystem permissions (mode `0600`, owner = the Dwaar process user).

### Rate limit

Authenticated requests are subject to a global rate limit of **60 requests per 60-second window**. Exceeding the limit returns `429 Too Many Requests`. The `GET /health` endpoint is exempt.

---

## Endpoints

### GET /health

Returns proxy liveness and uptime. No authentication required on either transport.

**Response** `200 OK`

```json
{
  "status": "ok",
  "uptime_secs": 3742
}
```

| Field | Type | Description |
|---|---|---|
| `status` | string | Always `"ok"` when the process is alive |
| `uptime_secs` | integer | Seconds since process start |

---

### GET /routes

List all active routes in the route table.

```bash
curl -H "Authorization: Bearer $TOKEN" \
     http://127.0.0.1:6190/routes
```

**Response** `200 OK`

```json
[
  {
    "domain": "api.example.com",
    "upstream": "10.0.0.5:8080",
    "tls": false,
    "rate_limit_rps": 500,
    "under_attack": false,
    "source": null
  },
  {
    "domain": "www.example.com",
    "upstream": "10.0.0.6:443",
    "tls": true,
    "rate_limit_rps": null,
    "under_attack": false,
    "source": "dwaar-ingress"
  }
]
```

| Field | Type | Description |
|---|---|---|
| `domain` | string | Hostname pattern (lowercase). Wildcard form: `*.example.com` |
| `upstream` | string\|null | Upstream socket address, or `null` for file-server-only routes |
| `tls` | boolean | Whether the proxy connects to the upstream over TLS |
| `rate_limit_rps` | integer\|null | Per-IP request rate limit, or `null` if not set |
| `under_attack` | boolean | Challenge mode active for this route |
| `source` | string\|null | Controller that owns this route (e.g. `"dwaar-ingress"`), or `null` |

**Status codes**

| Code | Meaning |
|---|---|
| `200` | Route list returned |
| `401` | Missing or invalid bearer token (TCP only) |
| `429` | Rate limit exceeded |
| `500` | Internal serialization error |

---

### POST /routes

Add a new route or replace an existing one with the same domain. The domain key is compared case-insensitively.

```bash
curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"domain":"app.example.com","upstream":"10.0.1.10:8080","tls":false}' \
     http://127.0.0.1:6190/routes
```

**Request body**

```json
{
  "domain": "app.example.com",
  "upstream": "10.0.1.10:8080",
  "tls": false,
  "source": "my-controller"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `domain` | string | yes | Hostname to route. Wildcards accepted: `*.example.com` |
| `upstream` | string | yes | Socket address in `host:port` form |
| `tls` | boolean | yes | Connect to upstream with TLS |
| `source` | string | no | Controller identity tag for ownership tracking |

**Response** `201 Created`

```json
{
  "domain": "app.example.com",
  "upstream": "10.0.1.10:8080",
  "tls": false,
  "rate_limit_rps": null,
  "under_attack": false,
  "source": "my-controller"
}
```

**Status codes**

| Code | Meaning |
|---|---|
| `201` | Route created or replaced |
| `400` | Invalid JSON, invalid domain, or invalid upstream address |
| `401` | Missing or invalid bearer token (TCP only) |
| `413` | Request body exceeds 64 KB |
| `429` | Rate limit exceeded |

---

### DELETE /routes/{domain}

Remove a route by domain. The domain is matched case-insensitively.

```bash
curl -X DELETE \
     -H "Authorization: Bearer $TOKEN" \
     http://127.0.0.1:6190/routes/app.example.com
```

**Response** `200 OK`

```json
{
  "deleted": "app.example.com"
}
```

**Status codes**

| Code | Meaning |
|---|---|
| `200` | Route deleted; body contains the deleted domain |
| `400` | Domain segment is empty |
| `401` | Missing or invalid bearer token (TCP only) |
| `404` | No route with that domain exists |
| `429` | Rate limit exceeded |

---

### GET /metrics

Serve Prometheus metrics in text exposition format (`text/plain; version=0.0.4`). Requires Prometheus support to be enabled at startup (enabled by default; disable with `--no-metrics`).

```bash
curl -H "Authorization: Bearer $TOKEN" \
     http://127.0.0.1:6190/metrics
```

**Response** `200 OK` — Prometheus text format

```
# HELP dwaar_requests_total Total requests proxied
# TYPE dwaar_requests_total counter
dwaar_requests_total{domain="api.example.com",status="2xx"} 148203
...
```

**Status codes**

| Code | Meaning |
|---|---|
| `200` | Metrics text returned |
| `401` | Missing or invalid bearer token (TCP only) |
| `404` | Metrics not enabled; start without `--no-metrics=false` |
| `429` | Rate limit exceeded |

---

### GET /analytics

Return analytics snapshots for all tracked domains as a JSON array. Domains with no traffic since startup are not included.

```bash
curl -H "Authorization: Bearer $TOKEN" \
     http://127.0.0.1:6190/analytics
```

**Response** `200 OK`

```json
[
  {
    "domain": "www.example.com",
    "page_views_1m": 84,
    "page_views_60m": 3902,
    ...
  }
]
```

See [Analytics API](analytics.md) for the complete response schema.

**Status codes**

| Code | Meaning |
|---|---|
| `200` | Array of domain snapshots (empty array if no data) |
| `401` | Missing or invalid bearer token (TCP only) |
| `429` | Rate limit exceeded |
| `500` | Internal serialization error |

---

### GET /analytics/{domain}

Return the analytics snapshot for a single domain.

```bash
curl -H "Authorization: Bearer $TOKEN" \
     http://127.0.0.1:6190/analytics/www.example.com
```

**Response** `200 OK` — see [Analytics API](analytics.md) for the full schema.

**Status codes**

| Code | Meaning |
|---|---|
| `200` | Domain snapshot returned |
| `400` | Domain segment is empty or contains invalid characters |
| `401` | Missing or invalid bearer token (TCP only) |
| `404` | No analytics recorded for this domain |
| `429` | Rate limit exceeded |

---

### PURGE /cache/{host}/{path}

Invalidate a single cache entry. The key is derived from the host and path segments of the URL. Requires cache storage to be enabled.

```bash
curl -X PURGE \
     -H "Authorization: Bearer $TOKEN" \
     "http://127.0.0.1:6190/cache/www.example.com/blog/post-slug"
```

The key format matches what the proxy stores: `{host}/{path}` where path begins with `/`. Leading `/` is added automatically if absent.

**Response** `200 OK` — entry was found and invalidated

```json
{ "purged": true }
```

**Response** `404 Not Found` — entry was not in the cache

```json
{ "purged": false, "reason": "not found" }
```

**Status codes**

| Code | Meaning |
|---|---|
| `200` | Cache entry invalidated |
| `400` | Key segment is empty |
| `401` | Missing or invalid bearer token (TCP only) |
| `404` | Entry not found in cache |
| `429` | Rate limit exceeded |
| `501` | Cache not enabled |

---

### POST /reload

Signal Dwaar to re-read the Dwaarfile and atomically swap the route table. Requires the config watcher to be active (default when a Dwaarfile exists). A cooldown of **5 seconds** is enforced between consecutive reloads.

```bash
curl -X POST \
     -H "Authorization: Bearer $TOKEN" \
     http://127.0.0.1:6190/reload

# From the CLI (wraps this endpoint)
dwaar reload --admin 127.0.0.1:6190
```

**Response** `200 OK`

```json
{ "message": "config reload triggered" }
```

**Response** `400 Bad Request` — parse error in the new Dwaarfile

As of 0.2.2, a failed parse returns `400` with the full `ConfigError::Display` output as the response body. `Content-Type` is `text/plain; charset=utf-8` so the error reads cleanly when piped to a terminal. The running config is never touched on parse failure — the cooldown is still consumed so a broken file cannot be hot-reloaded in a tight loop.

```bash
curl -sS -X POST \
     -H "Authorization: Bearer $TOKEN" \
     http://127.0.0.1:6190/reload
```

```
parse error at line 12 col 5: unexpected token 'reverse_proxys'
  expected one of: reverse_proxy, respond, handle, handle_path, route, ...
  did you mean 'reverse_proxy'?
```

**Response** `429 Too Many Requests` — cooldown not elapsed

```json
{ "error": "reload too soon", "retry_after": 3 }
```

The `Retry-After` response header contains the same integer value as `retry_after`.

**Status codes**

| Code | Meaning |
|---|---|
| `200` | Reload signal sent to config watcher |
| `400` | Parse error in the new Dwaarfile. Body is the full error text (plain). Running config is unchanged. |
| `401` | Missing or invalid bearer token (TCP only) |
| `429` | Cooldown period active; see `Retry-After` header |
| `501` | Config watcher not active |

---

## Error Responses

All error responses use a consistent JSON envelope:

```json
{ "error": "<human-readable message>" }
```

The `Content-Type` is always `application/json`. The message is safe to display — special characters are escaped via `serde_json`.

**Common errors**

| Status | `error` value | Cause |
|---|---|---|
| `400` | `"invalid JSON: ..."` | Malformed request body |
| `400` | `"invalid domain: ..."` | Domain fails validation |
| `400` | `"invalid upstream address: ..."` | Not a valid `host:port` |
| `400` | `"missing domain"` | Empty path segment in DELETE |
| `401` | `"unauthorized"` | Bearer token absent or wrong |
| `405` | `"method not allowed"` | Wrong HTTP method for this path; check `Allow` header |
| `413` | `"request body too large"` | Body exceeds 64 KB |
| `429` | `"rate limit exceeded"` | Global 60 req/60 s window |
| `500` | `"serialize error: ..."` | Internal failure serializing the response |
| `501` | `"reload not supported — config watcher not active"` | Reload called without watcher |
| `501` | `"cache not enabled"` | PURGE called without cache backend |

---

## Audit Logging

Mutating operations emit a structured `tracing::info!` event at target `dwaar::admin::audit`. The following operations produce an audit event:

| Operation | `action` value | `resource` value |
|---|---|---|
| `POST /routes` | `route_add` | domain name |
| `DELETE /routes/{domain}` | `route_delete` | domain name |
| `PURGE /cache/{host}/{path}` | `cache_purge` | `{host}/{path}` key |

Every audit event includes the fields `action`, `principal` (always `"admin"` for API-driven mutations), and `resource`.

To capture only audit events, set:

```
RUST_LOG=dwaar::admin::audit=info
```

This lets you route audit entries to a separate log sink without increasing the overall log verbosity. Audit events are `INFO` level and flow through the normal `tracing` subscriber — they appear in whatever output format your subscriber is configured to use.

---

## Related

- [Analytics API](analytics.md) — full response schema for `/analytics` and `/analytics/{domain}`
- [Cache Purge](cache-purge.md) — caching configuration and purge strategies
- [CLI Reference](../reference/cli.md) — `dwaar routes`, `dwaar reload`, and `--admin-socket`
- [Prometheus Metrics](../observability/prometheus.md) — metric names and labels served at `/metrics`
