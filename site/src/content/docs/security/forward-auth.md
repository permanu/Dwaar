---
title: "Forward Auth"
---

# Forward Auth

Delegate authentication to an external service before proxying a request to the upstream. Dwaar sends a subrequest to your auth service with the original request's method, URI, and client IP. A `2xx` response allows the request through; a `4xx` blocks it with the auth service's status code and body returned directly to the client.

Compatible with Authelia, Authentik, Pomerium, and any service that implements the forward-auth subrequest pattern.

---

## Quick Start

```
api.example.com {
    forward_auth authelia:9091 {
        uri       /api/authz/forward-auth
        copy_headers Remote-User Remote-Groups
    }
    reverse_proxy localhost:8080
}
```

Every request to `api.example.com` is checked against `authelia:9091/api/authz/forward-auth` first. On `2xx`, the `Remote-User` and `Remote-Groups` headers from the auth response are injected into the upstream request. On `4xx`, the auth service's response is forwarded directly to the client.

---

## How It Works

```mermaid
sequenceDiagram
    participant C as Client
    participant D as Dwaar
    participant A as Auth Service
    participant U as Upstream

    C->>D: GET /api/data
    D->>A: GET /api/authz/forward-auth<br/>X-Forwarded-Method: GET<br/>X-Forwarded-Uri: /api/data<br/>X-Forwarded-For: &lt;client-ip&gt;
    alt 2xx — allowed
        A-->>D: 200 OK<br/>Remote-User: alice<br/>Remote-Groups: admin
        D->>U: GET /api/data<br/>Remote-User: alice<br/>Remote-Groups: admin
        U-->>D: 200 OK + body
        D-->>C: 200 OK + body
    else 4xx — denied
        A-->>D: 401 Unauthorized + body
        D-->>C: 401 Unauthorized + body
    end
```

Dwaar opens a direct TCP (or TLS) connection to the auth service for every request. The subrequest carries three headers derived from the original request:

- `X-Forwarded-Method` — original HTTP method (e.g. `GET`, `POST`)
- `X-Forwarded-Uri` — original request URI including query string
- `X-Forwarded-For` — client IP address

After a `2xx`, any headers listed in `copy_headers` are extracted from the auth response and injected into the request that goes to the upstream. Headers that the client sent with the same names are **stripped before copying** — a client cannot pre-inject `Remote-User` to impersonate an authenticated identity when the auth service does not return it.

---

## Configuration

```
forward_auth <upstream> {
    uri          <path>
    copy_headers <Header1> [Header2 ...]
    transport    tls
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `<upstream>` | yes | Auth service address. Accepts `host:port` or a bare hostname. |
| `uri` | no | Path to send the subrequest to. Defaults to the original request's URI if omitted. |
| `copy_headers` | no | Space-separated list of response header names to copy from the auth response into the upstream request. |
| `transport tls` | no | Connect to the auth service over TLS. Required when the auth service is on a remote host or untrusted network. |

### Upstream address formats

```
# Hostname with port (plaintext by default)
forward_auth authelia:9091 { ... }

# Bare IP
forward_auth 127.0.0.1:9000 { ... }
```

### TLS transport

When `transport tls` is set, Dwaar upgrades the connection using `tokio-rustls` with the `webpki-roots` trust store. If the upstream address was a DNS hostname (e.g. `authelia:9091`), the hostname is used as the TLS SNI value so certificate validation works correctly. If the upstream is a literal IP address, SNI is set to the IP.

Without `transport tls`, Dwaar emits a one-time warning at startup:

```
WARN forward_auth uses plaintext TCP — auth responses are not integrity-protected
```

An on-path attacker could forge a `2xx` response and inject arbitrary values for `copy_headers` fields. Use `transport tls` whenever the auth service is not on loopback.

---

## Response Handling

| Auth service response | What Dwaar does |
|-----------------------|----------------|
| `2xx` | Copies `copy_headers` values into the upstream request, then forwards to upstream. |
| `4xx` | Returns the auth service's status code and response body directly to the client. The upstream is never contacted. |
| `5xx` | Treated the same as a connection error — see next row. |
| Connection error or timeout | Returns `502 Bad Gateway` to the client. The error is logged with the upstream address and reason. |
| Malformed response | Returns `502 Bad Gateway`. Dwaar requires a valid HTTP status line to determine allow or deny. |

The subrequest times out after **5 seconds** for each phase: TCP connect, request write, and response read. The auth service response body is capped at **64 KiB** — any body beyond that is truncated before parsing.

---

## Headers Forwarded

### Sent to the auth service

| Header | Value |
|--------|-------|
| `X-Forwarded-Method` | Original request method (`GET`, `POST`, etc.) |
| `X-Forwarded-Uri` | Original request URI including query string |
| `X-Forwarded-For` | Client IP address (omitted if not available) |
| `Host` | Auth service address as configured |
| `Connection` | `close` |

All client-supplied values are sanitized to remove `\r` and `\n` characters before being interpolated into the subrequest, preventing CRLF header injection.

### Copied from the auth response to the upstream request

Only headers explicitly listed in `copy_headers` are copied. Any header in that list that was present in the **original client request** is stripped first, then replaced with the auth service's value. This prevents a client from supplying `Remote-User: admin` before Dwaar has a chance to set the real value from the auth service.

No headers are copied by default — `copy_headers` must be set explicitly.

---

## Complete Example

```
{
    email ops@example.com
}

# API protected by Authelia
api.example.com {
    forward_auth authelia:9091 {
        uri          /api/authz/forward-auth
        copy_headers Remote-User Remote-Groups Remote-Name Remote-Email
        transport    tls
    }

    reverse_proxy localhost:8080
}

# Admin panel — same auth service, extra path restriction
admin.example.com {
    forward_auth authelia:9091 {
        uri          /api/authz/forward-auth
        copy_headers Remote-User Remote-Groups
        transport    tls
    }

    handle /metrics* {
        respond 404
    }

    reverse_proxy localhost:9090
}

# Public site — no auth
www.example.com {
    reverse_proxy localhost:3000
}
```

The upstream receives `Remote-User`, `Remote-Groups`, `Remote-Name`, and `Remote-Email` set by Authelia after a successful check. It never receives these headers from an unauthenticated client — they are stripped on every request before the subrequest result is applied.

---

## Related

- [Basic Auth](basic-auth.md) — HTTP Basic authentication handled directly by Dwaar, no external service required
- [IP Filtering](ip-filtering.md) — allow or deny requests by source IP before auth runs
- [Security Headers](security-headers.md) — add `Strict-Transport-Security`, CSP, and other response headers
