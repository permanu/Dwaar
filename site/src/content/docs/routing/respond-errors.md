---
title: "Respond & Error Pages"
---

# Respond & Error Pages

Dwaar provides four directives for generating responses without touching an
upstream: `respond` returns a static body, `error` synthesises an error
status, `abort` drops the connection without sending anything, and
`handle_errors` lets you intercept error responses and replace them with
custom pages. All four are resolved at compile time — no runtime dispatch.

---

## respond

`respond` returns a static HTTP response. Use it for health checks,
maintenance pages, or any endpoint that does not need an upstream.

**Syntax**

```
respond [<body>] [<status>]
respond <status>
```

Dwaar follows Caddy's argument-parsing rules:

- If the only argument is a 3-digit integer, it is treated as the status code (no body).
- If both arguments are present, the first is the body and the second is the status code.
- If only a string is provided, it becomes the body and the status defaults to `200`.
- With no arguments, Dwaar sends an empty `200 OK`.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `body` | quoted string | no | Response body text |
| `status` | integer | no | HTTP status code; defaults to `200` |

**Examples**

```
example.com {
    # Health check endpoint — no body, 200 OK
    handle /health {
        respond 200
    }

    # Plain text body with explicit status
    handle /maintenance {
        respond "Service temporarily unavailable" 503
    }

    # Body only — status defaults to 200
    handle /ping {
        respond "pong"
    }

    # No body, no status — empty 200
    handle /ok {
        respond
    }
}
```

---

## error

`error` triggers an error response with a given status code and optional
message. Unlike `respond`, `error` is designed to deliberately surface
error conditions — the response body is the message string, and
`handle_errors` (see below) can intercept it to render a custom page.

**Syntax**

```
error [<message>] <status>
error <status>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `message` | quoted string | no | Error description sent as the response body |
| `status` | integer | yes | HTTP status code |

**Examples**

```
example.com {
    # Deny a specific path with a clean 403
    handle /internal/* {
        error "Forbidden" 403
    }

    # Return 404 for unknown API routes (message is the body)
    handle /api/* {
        error "Not Found" 404
    }

    # Status-only form — no message body
    handle /gone {
        error 410
    }
}
```

---

## abort

`abort` drops the TCP connection immediately without sending any HTTP
response. Use it to silently discard requests from known-bad actors —
it gives no information to the caller that Dwaar even exists.

**Syntax**

```
abort
```

`abort` takes no arguments.

**Examples**

```
example.com {
    # Drop requests from a known malicious IP without responding
    @bad_ip {
        remote_ip 203.0.113.42/32
    }
    handle @bad_ip {
        abort
    }

    # Drop scanner probes on common vulnerability paths
    @scanners {
        path /wp-admin/* /.env /phpinfo.php
    }
    handle @scanners {
        abort
    }

    reverse_proxy localhost:8080
}
```

> **`abort` vs `error 403`:** Use `abort` when you want to make Dwaar
> invisible. Use `error 403` when you want the client to receive a
> well-formed HTTP response (e.g. so a browser can show an error page).

---

## handle_errors

`handle_errors` runs its inner directives when a request results in an
error status (4xx or 5xx), either from `error`, from an upstream failure,
or from an internal Dwaar error. Use it to replace generic error pages with
branded HTML, or to log or redirect on specific status codes.

**Syntax**

```
handle_errors {
    <directives>
}
```

Inside `handle_errors` you have access to the `{http.error.status_code}`
and `{http.error.message}` placeholders. Use a nested `handle` with a
named matcher to target specific status codes.

**Examples**

```
example.com {
    reverse_proxy localhost:8080

    handle_errors {
        # Custom 404 page
        @not_found {
            expression {http.error.status_code} == 404
        }
        handle @not_found {
            root * /var/www/errors
            rewrite /404.html
            file_server
        }

        # Custom 5xx page for upstream failures
        @server_error {
            expression {http.error.status_code} >= 500
        }
        handle @server_error {
            root * /var/www/errors
            rewrite /500.html
            file_server
        }

        # Fallback for everything else — plain text body
        handle {
            respond "{http.error.status_code} {http.error.message}" {http.error.status_code}
        }
    }
}
```

---

## Complete Example

This configuration serves a maintenance page for most traffic, exposes a
health check endpoint, silently drops scanner probes, and renders a custom
404 for anything that slips through.

```
example.com {

    # ── Security: drop scanner traffic silently ───────────────────────────────
    @scanners {
        path /.env /wp-login.php /phpinfo.php /admin.php
    }
    handle @scanners {
        abort
    }

    # ── Health check (monitoring systems bypass maintenance) ──────────────────
    handle /health {
        respond "ok" 200
    }

    # ── Maintenance mode ──────────────────────────────────────────────────────
    handle /maintenance-check {
        # Internal probe — return 200 when maintenance is over
        respond 200
    }

    handle /* {
        respond "We'll be back shortly. Follow @example for updates." 503
    }

    # ── Error pages ───────────────────────────────────────────────────────────
    handle_errors {
        @is_404 {
            expression {http.error.status_code} == 404
        }
        handle @is_404 {
            root * /var/www/errors
            rewrite /404.html
            file_server
        }

        # Generic fallback
        handle {
            respond "Error {http.error.status_code}: {http.error.message}" {http.error.status_code}
        }
    }
}
```

---

## Related

- [Handle & Route Blocks](./handle.md) — scope error directives to specific paths
- [Reverse Proxy](./reverse-proxy.md) — upstream failure modes that trigger `handle_errors`
