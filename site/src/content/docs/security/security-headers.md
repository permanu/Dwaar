---
title: "Security Headers"
---

# Security Headers

Dwaar automatically adds a baseline set of security response headers to every proxied response. No configuration is required. The headers defend against MIME-sniffing, clickjacking, referer leakage, and server fingerprinting. HSTS is applied only on TLS connections to avoid locking browsers out of intentionally HTTP-only routes.

The `SecurityHeadersPlugin` runs at priority 100 — after all request-phase plugins — and modifies response headers before they reach the client.

---

## Quick Start

Security headers are **built in and always active**. Add a site block and they apply automatically:

```
api.example.com {
    reverse_proxy localhost:8080
}
```

Every response from this site includes:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
Server: Dwaar
```

If the connection is not TLS (e.g. `http://api.example.com`), `Strict-Transport-Security` is omitted. All other headers are always present.

---

## Headers Applied

| Header | Value | What it prevents |
|--------|-------|-----------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Downgrade attacks and cookie hijacking over plain HTTP. Tells browsers to use HTTPS for one year, including all subdomains. **TLS connections only.** |
| `X-Content-Type-Options` | `nosniff` | MIME-sniffing attacks where a browser executes an uploaded `.txt` file as JavaScript. Forces the browser to honour the declared `Content-Type`. |
| `X-Frame-Options` | `SAMEORIGIN` | Clickjacking via invisible iframe overlays. Prevents your pages from being embedded in frames on external origins. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Referer header leakage to third-party sites. Full URL is sent for same-origin navigations; only the origin is sent cross-origin; nothing is sent on HTTP→HTTPS downgrade. |
| `Server` | `Dwaar` | Server fingerprinting. Replaces whatever banner the upstream sends (e.g. `Apache/2.4.57`, `Express`) with a neutral value that reveals nothing about the backend stack. |

### HSTS scope

The HSTS header uses `max-age=31536000` (one year) and `includeSubDomains`. Once a browser has seen this header for a site, it refuses plain-HTTP connections to that site and all its subdomains for one year, even before the first HTTPS request completes. This eliminates the TOFU (trust-on-first-use) window that would otherwise allow a downgrade attack on the very first visit.

If your deployment includes subdomains that intentionally serve only HTTP (e.g. an internal monitoring endpoint), place those on a separate top-level domain rather than a subdomain, so HSTS on your main domain does not affect them.

---

## Content Security Policy

The `SecurityHeadersPlugin` has two optional CSP fields: `content_security_policy` and `content_security_policy_report_only`. Both default to `None` — no `Content-Security-Policy` or `Content-Security-Policy-Report-Only` header is sent unless explicitly configured. Configure them via the `header` directive inside a site block (the plugin picks up overrides at response-header time):

```
api.example.com {
    reverse_proxy localhost:8080

    header {
        Content-Security-Policy "default-src 'self'; script-src 'self' cdn.example.com"
        Content-Security-Policy-Report-Only "default-src 'self'; report-uri /csp-report"
    }
}
```

Use `Content-Security-Policy-Report-Only` during rollout to log violations without blocking requests. Once the policy is stable, switch to `Content-Security-Policy`.

---

## Configuration

### Overriding individual headers

Use the `header` directive inside a site block to override any header the plugin sets, or to add additional security headers:

```
api.example.com {
    reverse_proxy localhost:8080

    header {
        # Extend HSTS to two years and add preload eligibility
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

        # Tighten frame policy to deny all embedding
        X-Frame-Options "DENY"

        # Add a Content Security Policy
        Content-Security-Policy "default-src 'self'; script-src 'self' cdn.example.com"

        # Add Permissions-Policy to disable unused browser features
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
    }
}
```

The `header` directive runs after `SecurityHeadersPlugin`, so your values replace the defaults.

### Removing a header

Prefix the header name with `-` to remove it entirely:

```
www.example.com {
    reverse_proxy localhost:3000

    header {
        # Allow embedding on any origin (e.g. a widget meant to be iframed)
        -X-Frame-Options
    }
}
```

### Suppressing the Server banner on a specific route

```
internal.example.com {
    reverse_proxy localhost:9000

    header {
        # Pass the upstream's own Server header through unchanged
        -Server
    }
}
```

---

## Complete Example

```
# Global config — TLS certificate provisioning
{
    email admin@example.com
}

# Public marketing site — extend HSTS and add CSP
www.example.com {
    reverse_proxy localhost:3000

    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        Content-Security-Policy "default-src 'self'; img-src 'self' data: https://cdn.example.com; font-src 'self' https://fonts.gstatic.com"
        Permissions-Policy "camera=(), microphone=()"
    }
}

# API — defaults are sufficient; add CORS header for browser clients
api.example.com {
    reverse_proxy localhost:8080

    header {
        Access-Control-Allow-Origin "https://www.example.com"
        Access-Control-Allow-Methods "GET, POST, OPTIONS"
    }
}

# Admin panel — deny all framing, strict CSP
admin.example.com {
    basic_auth {
        admin $2y$12$...
    }
    reverse_proxy localhost:8090

    header {
        X-Frame-Options "DENY"
        Content-Security-Policy "default-src 'self'"
        Referrer-Policy "no-referrer"
    }
}

# Widget endpoint — allow cross-origin framing for embed use case
widget.example.com {
    reverse_proxy localhost:8070

    header {
        -X-Frame-Options
        Content-Security-Policy "frame-ancestors https://www.example.com https://partner.com"
    }
}
```

---

## Related

- [Basic Auth](basic-auth.md) — HTTP Basic Authentication for protecting routes with a username and password
- [Forward Auth](forward-auth.md) — delegate authentication decisions to an external service
- [Rate Limiting](rate-limiting.md) — per-IP sliding-window rate limiting to slow bots and brute-force attacks
