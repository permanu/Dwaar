---
title: "Migrating from Caddy"
---

# Migrating from Caddy

Dwaar uses Caddyfile-compatible syntax. Most Caddyfiles work with minimal changes: rename the file to `Dwaarfile`, swap a few directive names, and you're done. This page documents every point where Dwaar behaves differently from Caddy, and shows the exact config translation for the most common patterns.

---

## Key Differences

| Feature | Caddy | Dwaar |
|---|---|---|
| Config file name | `Caddyfile` | `Dwaarfile` |
| Primary proxy directive | `reverse_proxy` | `reverse_proxy` (identical) |
| Simple proxy shorthand | `proxy` (deprecated in v2) | `proxy` accepted as an alias |
| Compression directive | `encode gzip zstd br` | `encode gzip zstd br` (identical) |
| TLS auto-provision | `tls` with no args, or implicit | Implicit by default; `tls auto` also works |
| TLS manual cert | `tls /cert /key` | `tls manual` + `tls_cert` / `tls_key` |
| Basic auth directive | `basicauth` | `basic_auth` (underscore preferred; `basicauth` is an alias) |
| Security headers | None by default | Applied automatically to every response |
| Built-in analytics | No | `analytics on` |
| Rate limiting | `crowdsec` or third-party module | `rate_limit 100/s` (built in) |
| IP filtering | Third-party module | `ip_filter` (built in) |
| Plugin system | Go modules | WASM plugins |
| `respond` directive | Supported | Supported (identical) |
| `rewrite` directive | Supported | Supported (identical) |
| `redir` directive | `301` default | `308` default (method-preserving) |
| HTTP/3 | Built-in | `servers { h3 on }` in global block |
| Admin API | REST at `:2019` | REST at `:9876` |
| Module ecosystem | Hundreds of Go modules | WASM plugins; native modules compiled in |

---

## Config Translations

### Basic reverse proxy

**Before (Caddy)**
```txt
example.com {
    reverse_proxy localhost:8080
}
```

**After (Dwaar)**
```
example.com {
    reverse_proxy localhost:8080
}
```

Identical. No changes required.

---

### Multi-upstream with load balancing

**Before (Caddy)**
```txt
example.com {
    reverse_proxy backend1:8080 backend2:8080 backend3:8080 {
        lb_policy round_robin
        health_uri /health
        health_interval 10s
    }
}
```

**After (Dwaar)**
```
example.com {
    reverse_proxy {
        to backend1:8080 backend2:8080 backend3:8080
        lb_policy round_robin
        health_uri /health
        health_interval 10
    }
}
```

Two changes:
- Multi-upstream must use block form with a `to` subdirective.
- `health_interval` takes an integer (seconds), not a duration string.

---

### TLS with ACME

**Before (Caddy)**
```txt
{
    email admin@example.com
}

example.com {
    reverse_proxy localhost:3000
}
```

**After (Dwaar)**
```
{
    email admin@example.com
}

example.com {
    reverse_proxy localhost:3000
}
```

Identical. Automatic HTTPS is on by default in both.

**Manual certs — before (Caddy)**
```txt
example.com {
    reverse_proxy localhost:3000
    tls /etc/ssl/cert.pem /etc/ssl/key.pem
}
```

**Manual certs — after (Dwaar)**
```
example.com {
    reverse_proxy localhost:3000
    tls manual
    tls_cert /etc/ssl/cert.pem
    tls_key  /etc/ssl/key.pem
}
```

Dwaar uses explicit `tls manual` with separate `tls_cert` / `tls_key` directives instead of inline paths.

---

### File server with SPA fallback

**Before (Caddy)**
```txt
example.com {
    root * /var/www
    try_files {path} /index.html
    file_server
}
```

**After (Dwaar)**
```
example.com {
    root * /var/www
    try_files {path} /index.html
    file_server
}
```

Identical. `try_files`, `root`, and `file_server` behave the same way.

---

### Rate limiting

**Before (Caddy)**
```txt
example.com {
    reverse_proxy localhost:3000
    # Requires external module, e.g. caddy-ratelimit
    rate_limit {
        zone static {
            key {remote_host}
            events 100
            window 1s
        }
    }
}
```

**After (Dwaar)**
```
example.com {
    reverse_proxy localhost:3000
    rate_limit 100/s
}
```

Rate limiting is built into Dwaar. Use `rate_limit <n>/s` — no module required.

---

### Headers

**Before (Caddy)**
```txt
example.com {
    reverse_proxy localhost:3000
    header {
        X-Custom-Header "my-value"
        Cache-Control "public, max-age=3600"
        -Server
    }
}
```

**After (Dwaar)**
```
example.com {
    reverse_proxy localhost:3000
    header {
        X-Custom-Header "my-value"
        Cache-Control  "public, max-age=3600"
    }
}
```

The `header` block syntax is identical for adding and overriding headers. Header deletion with `-Header-Name` is not yet supported — the upstream `Server` header is replaced automatically with `Dwaar` by the built-in security headers plugin.

---

### Redirects

**Before (Caddy)**
```txt
example.com {
    redir /old-path /new-path 301
    redir /blog/* /articles/{http.request.uri.path.remainder} 301
}
```

**After (Dwaar)**
```
example.com {
    redir /old-path /new-path 301
    redir /blog/* /articles/{http.request.uri.path.remainder} 301
}
```

Identical syntax. Note that Dwaar's default redirect code is `308` (not `301`) when no code is specified — explicitly pass `301` when you need it.

---

### Handle and handle_path blocks

**Before (Caddy)**
```txt
example.com {
    handle /api/* {
        reverse_proxy localhost:8080
    }

    handle_path /static/* {
        root * /var/www/assets
        file_server
    }

    handle {
        file_server /var/www
    }
}
```

**After (Dwaar)**
```
example.com {
    handle /api/* {
        reverse_proxy localhost:8080
    }

    handle_path /static/* {
        root * /var/www/assets
        file_server
    }

    handle {
        root * /var/www
        file_server
    }
}
```

`handle` and `handle_path` are identical in semantics. The only change: `file_server` does not accept a path as a positional argument in Dwaar — set the root with the `root` directive instead.

---

### Encode (compression)

**Before (Caddy)**
```txt
example.com {
    reverse_proxy localhost:3000
    encode gzip zstd br
}
```

**After (Dwaar)**
```
example.com {
    reverse_proxy localhost:3000
    encode gzip zstd br
}
```

Identical. Compression is also on by default in Dwaar without any `encode` directive — add `encode` only when you need to control which algorithms are offered.

---

### Basic auth

**Before (Caddy)**
```txt
example.com {
    basicauth /admin/* {
        alice JDJhJDE0JGV...
    }
    reverse_proxy localhost:3000
}
```

**After (Dwaar)**
```
example.com {
    handle /admin/* {
        basic_auth {
            alice $2b$14$...
        }
        reverse_proxy localhost:3000
    }

    handle {
        reverse_proxy localhost:3000
    }
}
```

Two changes:
- Use `basic_auth` (underscore) or `basicauth` — both are accepted.
- Dwaar does not support a path argument directly on `basic_auth`. Scope it to a path using a `handle` block instead.
- Hashes must start with `$2b$` or `$2y$`. Generate with `htpasswd -nbBC 12 alice password`.

---

### Matchers

**Before (Caddy)**
```txt
example.com {
    @api {
        path /api/*
        method GET POST PUT DELETE
    }

    @static {
        path *.css *.js *.png *.jpg *.svg
    }

    handle @api {
        reverse_proxy localhost:8080
    }

    handle @static {
        root * /var/www
        file_server
    }
}
```

**After (Dwaar)**
```
example.com {
    @api {
        path   /api/*
        method GET POST PUT DELETE
    }

    @static {
        path *.css *.js *.png *.jpg *.svg
    }

    handle @api {
        reverse_proxy localhost:8080
    }

    handle @static {
        root * /var/www
        file_server
    }
}
```

Named matchers are identical in syntax. All Caddy matcher conditions (`path`, `method`, `host`, `header`, `remote_ip`, `not`, etc.) are supported.

---

## Unsupported Caddy Features

The following Caddyfile features are not yet supported in Dwaar. Dwaar parses and ignores unknown directives (it does not error on them), so existing configs will load — but the behaviour will be absent.

| Feature | Caddy directive | Status |
|---|---|---|
| DNS-01 challenge provider config | `tls { dns ... }` | Planned |
| Header deletion | `header -Header-Name` | Planned |
| Request body rewriting | `request_body` | Not planned |
| Logging filter expressions | `log { filter ... }` | Planned |
| `push` (HTTP/2 server push) | `push` | Not planned (deprecated in browsers) |
| `acme_server` (internal CA) | `acme_server` | Not planned |
| Pki app (`pki { ... }`) | Caddyfile pki block | Not planned |
| Syslog output | `log { output net ... }` | Planned |
| `vars` directive | `vars` | Not planned |
| `import` / snippets | `import snippet_name` | Planned |
| Multiple sites on one address with path routing | `example.com/path { ... }` | Not supported |

---

## Migration Steps

1. Copy your `Caddyfile` to `Dwaarfile` in the same directory.

2. Run the validator to see what needs to change:
   ```bash
   dwaar validate --config Dwaarfile
   ```

3. If you use `reverse_proxy` with multiple backends and options, convert to block form with `to`:
   ```
   reverse_proxy {
       to backend1:8080 backend2:8080
       lb_policy least_conn
   }
   ```

4. Replace any `tls /cert /key` lines with:
   ```
   tls manual
   tls_cert /cert
   tls_key  /key
   ```

5. Replace third-party rate-limiting modules with `rate_limit <n>/s`.

6. Replace `file_server /path` (path as positional arg) with `root * /path` + `file_server`.

7. Replace `basicauth /path/* { ... }` with a `handle /path/* { basic_auth { ... } ... }` block.

8. Start Dwaar and watch logs:
   ```bash
   dwaar run --config Dwaarfile
   ```

9. Verify TLS, routing, and response headers with `curl -I https://yourdomain.com`.

---

## Related

- [Dwaarfile Reference](../configuration/dwaarfile.md) — complete directive reference
- [Comparison with Other Proxies](../getting-started/comparison.md) — feature matrix
- [Automatic HTTPS](../tls/automatic-https.md) — how ACME provisioning works
- [Rate Limiting](../security/rate-limiting.md) — built-in sliding-window rate limiter
