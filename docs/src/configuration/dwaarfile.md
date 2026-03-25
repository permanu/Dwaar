# Dwaarfile Reference

The Dwaarfile is Dwaar's configuration format. It is designed to be readable, minimal, and production-ready with zero boilerplate.

## Location

Dwaar looks for configuration in this order:

1. `--config` CLI flag: `dwaar --config /path/to/Dwaarfile`
2. `./Dwaarfile` in the current directory
3. `/etc/dwaar/Dwaarfile`

## Syntax

A Dwaarfile consists of **domain blocks**. Each block configures one domain:

```
domain.com {
    directive value
    directive value
}
```

**Rules:**
- One domain per block
- Directives are one per line
- Comments start with `#`
- No semicolons, no quotes around simple values
- Indentation is convention (2 or 4 spaces), not required

## Directives

### `proxy` (required)

Where to forward requests.

```
example.com {
    proxy localhost:8080
}
```

The upstream address. Supports `host:port` format. `localhost` is equivalent to `127.0.0.1`.

### `tls`

TLS mode. Default: `auto`.

```
example.com {
    proxy localhost:8080
    tls auto          # Automatic cert via Let's Encrypt (default)
}

dev.local {
    proxy localhost:8080
    tls off           # No TLS (HTTP only)
}

secure.example.com {
    proxy localhost:8080
    tls manual        # Use manually provided certs
    tls_cert /path/to/cert.pem
    tls_key /path/to/key.pem
}
```

| Value | Behavior |
|-------|----------|
| `auto` | Request cert from Let's Encrypt. Fallback to ZeroSSL. Renew automatically. |
| `off` | Serve HTTP only. No TLS. |
| `manual` | Use certs from `tls_cert` and `tls_key` paths. |

### `analytics`

Enable first-party analytics. Default: `off`.

```
example.com {
    proxy localhost:8080
    analytics on
}
```

When enabled, Dwaar injects a lightweight JavaScript snippet into HTML responses. The script collects page views, referrers, screen size, and Web Vitals — served from the same origin, bypassing ad blockers.

Analytics data is available via the [Admin API](../api/admin.md).

### `rate_limit`

Per-IP rate limiting. Default: none (unlimited).

```
api.example.com {
    proxy localhost:3000
    rate_limit 100/s
}
```

Format: `<number>/<unit>` where unit is `s` (second), `m` (minute), or `h` (hour).

Exceeding the limit returns `429 Too Many Requests` with a `Retry-After` header.

### `compress`

Response compression. Default: `on`.

```
example.com {
    proxy localhost:8080
    compress off    # Disable compression
}
```

When on, Dwaar compresses text responses (HTML, CSS, JS, JSON, XML, SVG) using Brotli or Gzip based on the client's `Accept-Encoding` header. Responses smaller than 1 KB and already-compressed responses are skipped.

### `headers`

Custom response headers. No defaults.

```
example.com {
    proxy localhost:8080
    headers {
        X-Custom-Header "my-value"
        Cache-Control "public, max-age=3600"
    }
}
```

## Defaults

The following are enabled by default for every domain. No configuration required:

| Feature | Default | Override |
|---------|---------|----------|
| TLS | `auto` (Let's Encrypt) | `tls off` or `tls manual` |
| HTTP → HTTPS redirect | On | Disabled when `tls off` |
| Compression | On (Brotli/Gzip) | `compress off` |
| Security headers | On (HSTS, X-Content-Type-Options, etc.) | Not yet configurable |
| HTTP/2 | On | Not yet configurable |
| Access logging | On (JSON to stdout) | Not yet configurable |
| X-Request-Id | On (UUID v7) | Not yet configurable |
| Proxy headers | On (X-Real-IP, X-Forwarded-For) | Not yet configurable |

## Complete Example

```
# Production API with rate limiting
api.example.com {
    proxy localhost:3000
    rate_limit 200/s
    analytics off
    compress on
}

# Marketing site with analytics
www.example.com {
    proxy localhost:4000
    analytics on
}

# Internal admin (no TLS for local access)
admin.internal {
    proxy localhost:5000
    tls off
    analytics off
    compress off
}
```

## Validation

Check your Dwaarfile for errors without starting the server:

```bash
dwaar validate
# Config valid.

dwaar validate --config /path/to/Dwaarfile
# Config valid.
```

## Formatting

Format your Dwaarfile consistently:

```bash
dwaar fmt
# Formatted 3 domain blocks.

dwaar fmt --check
# Exit code 1 if unformatted (useful in CI).
```
