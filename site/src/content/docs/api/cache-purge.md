---
title: "Cache Purge"
---

# Cache Purge

Invalidate a cached response via the Admin API without restarting the proxy. Dwaar's in-memory cache stores responses keyed by `{method}:{host}:{path}`. The PURGE endpoint accepts a `host/path` pair, reconstructs the GET cache key, and evicts the entry immediately.

Purging is instant — the next request for that URL fetches a fresh response from the upstream.

---

## Quick Start

```bash
curl -X PURGE http://localhost:6190/cache/example.com/assets/style.css \
  -H "Authorization: Bearer $DWAAR_ADMIN_TOKEN"
```

---

## Endpoint

```
PURGE /cache/{host}/{path}
```

The `PURGE` method is non-standard HTTP — it is used by Varnish, Squid, and Nginx for cache invalidation and is understood by most HTTP clients.

| Component | Description |
|-----------|-------------|
| `host` | The virtual host as it appears in the cache key (no port suffix) |
| `path` | The URL path, with or without a leading `/` |

The Admin API listens on port `6190` by default. All endpoints except `GET /health` require authentication.

---

## Request

### Method

`PURGE`

### Path format

```
PURGE /cache/{host}/{path}
```

The `host` segment is the route domain — the canonical domain from the matched route, not the raw `Host` header (which may include a port). The `path` segment is everything after the first `/` separator.

Examples:

```
PURGE /cache/example.com/assets/style.css
PURGE /cache/api.example.com/v1/users
PURGE /cache/example.com/
```

### Authentication

All TCP connections to the Admin API require a bearer token in the `Authorization` header:

```
Authorization: Bearer <token>
```

The token is set via the `DWAAR_ADMIN_TOKEN` environment variable at startup. Connections over a Unix domain socket (UDS) bypass token auth — access is controlled by filesystem permissions on the socket file.

If `DWAAR_ADMIN_TOKEN` is not set, all authenticated endpoints (including PURGE) reject requests with `401 Unauthorized`.

### Rate limiting

The Admin API enforces a global rate limit of 60 authenticated requests per 60-second window. Exceeding this returns `429 Too Many Requests`.

---

## Response

### 200 — Entry purged

The cache entry was found and invalidated.

```json
{"purged": true}
```

### 400 — Missing cache key

The path after `/cache/` was empty.

```json
{"error": "missing cache key — use PURGE /cache/{host}/{path}"}
```

### 401 — Unauthorized

The `Authorization` header is missing, malformed, or carries an incorrect token.

```json
{"error": "unauthorized"}
```

### 404 — Not found in cache

The key was valid but the entry does not exist in the cache (never cached, already expired, or already purged).

```json
{"purged": false, "reason": "not found"}
```

### 429 — Rate limited

The global request counter for the current 60-second window has been exceeded.

```json
{"error": "rate limit exceeded"}
```

### 501 — Cache not enabled

The proxy was started without cache support. The PURGE endpoint is only available when a cache storage backend is attached to the Admin service.

```json
{"error": "cache not enabled"}
```

---

## Examples

### Purge a single asset

```bash
curl -X PURGE http://localhost:6190/cache/example.com/assets/app.js \
  -H "Authorization: Bearer $DWAAR_ADMIN_TOKEN"
```

Expected response:

```json
{"purged": true}
```

### Purge the root path

```bash
curl -X PURGE http://localhost:6190/cache/example.com/ \
  -H "Authorization: Bearer $DWAAR_ADMIN_TOKEN"
```

### Purge over a Unix domain socket

When running Dwaar with a UDS admin socket, skip the bearer token — the OS controls access via socket file permissions:

```bash
curl --unix-socket /run/dwaar/admin.sock \
  -X PURGE http://localhost/cache/example.com/assets/style.css
```

### Check whether an entry exists before purging

The Admin API does not have a HEAD-style lookup endpoint. If you need to verify cache membership, issue the PURGE and check whether the response is `{"purged":true}` or `{"purged":false}`.

### Scripting a multi-path purge

The API does not support wildcard or prefix purges — each URL must be purged individually. To purge a set of paths after a deploy:

```bash
PATHS=(
  "/assets/app.js"
  "/assets/style.css"
  "/index.html"
)

for p in "${PATHS[@]}"; do
  curl -s -X PURGE "http://localhost:6190/cache/example.com${p}" \
    -H "Authorization: Bearer $DWAAR_ADMIN_TOKEN"
  echo
done
```

---

## Related

- [Caching](../caching.md) — how Dwaar caches responses, cache key construction, TTL configuration
- [Admin API](admin.md) — all Admin API endpoints, authentication, rate limiting, and UDS setup
