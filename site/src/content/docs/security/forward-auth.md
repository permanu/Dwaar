---
title: "Forward Auth"
---

# Forward Auth

Delegate authentication to an external service before proxying a request to the upstream. Dwaar sends a subrequest to your auth service with the original request's method, URI, and client IP. A `2xx` response allows the request through; a `4xx` blocks it with the auth service's status code and body returned directly to the client.

Compatible with Authelia, Authentik, Pomerium, and any service that implements the forward-auth subrequest pattern.

:::caution[Plaintext targets are rejected at parse time]
Since 0.2.2, a `forward_auth` target that is neither a loopback address nor TLS-wrapped is rejected during config load. The parser refuses the Dwaarfile with:

```
forward_auth target '<host>:<port>' is plaintext and non-loopback;
set tls: true, use a loopback target, or explicitly opt in with
allow_plaintext: true
```

The opt-in directive is `insecure_plaintext` inside the `forward_auth` block. Use it only when you cannot provision TLS — an on-path attacker can forge a `2xx` response and inject arbitrary `copy_headers` values (such as `Remote-User: admin`) on every request. The recommended configuration is `transport tls` with an in-cluster auth service (Authelia, Authentik, Pomerium) fronted by an internal CA. See [Plaintext enforcement](#plaintext-enforcement) below.
:::

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
    uri                 <path>
    copy_headers        <Header1> [Header2 ...]
    transport           tls
    insecure_plaintext
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `<upstream>` | yes | Auth service address. Accepts `host:port` or a bare hostname. |
| `uri` | no | Path to send the subrequest to. Defaults to the original request's URI if omitted. |
| `copy_headers` | no | Space-separated list of response header names to copy from the auth response into the upstream request. |
| `transport tls` | no | Connect to the auth service over TLS. Required when the auth service is on a remote host or untrusted network. |
| `insecure_plaintext` | no | Explicit opt-in to plaintext subrequests against a non-loopback target. Without this, Dwaar rejects the config at parse time. See [Plaintext enforcement](#plaintext-enforcement). |

### Upstream address formats

```
# Hostname with port (plaintext by default)
forward_auth authelia:9091 { ... }

# Bare IP
forward_auth 127.0.0.1:9000 { ... }
```

### TLS transport

When `transport tls` is set, Dwaar upgrades the connection using `tokio-rustls` with the `webpki-roots` trust store. If the upstream address was a DNS hostname (e.g. `authelia:9091`), the hostname is used as the TLS SNI value so certificate validation works correctly. If the upstream is a literal IP address, SNI is set to the IP.

### Plaintext enforcement

As of 0.2.2, a non-loopback `forward_auth` target without `transport tls` is rejected at config parse time rather than logged as a runtime warning. The runtime hot-path check has been removed entirely.

| Target | TLS set? | Result |
|---|---|---|
| `127.0.0.1:*`, `localhost`, `ip6-localhost`, `ip6-loopback` | no | Accepted. Loopback is considered trusted by the host network namespace. |
| Any other host/IP | yes (`transport tls`) | Accepted. |
| Any other host/IP | no | **Parse error.** Must either add `transport tls` or set `insecure_plaintext`. |
| Any other host/IP | no, with `insecure_plaintext` | Accepted. A parse-time `WARN` is logged once at config load. No per-request warning. |

The opt-out is named `insecure_plaintext` to make the cost explicit in grep/review:

```
forward_auth authelia:9091 {
    uri          /api/authz/forward-auth
    copy_headers Remote-User Remote-Groups
    insecure_plaintext
}
```

**Why this matters.** The auth subrequest is the authority that tells Dwaar whether to forward `Remote-User`, `Remote-Groups`, and any other headers in `copy_headers` to the upstream. On a plaintext link an on-path attacker can inject a synthetic `2xx` response with `Remote-User: admin` and take over the upstream session. TLS with the `webpki-roots` trust store (or a pinned internal CA) closes that window. Loopback is exempt because the packets never leave the kernel's network namespace.

**Recommended for production.** Run the auth service as a sidecar or in-cluster service fronted by an internal CA and enable `transport tls`. If the auth service is on `127.0.0.1` or a UNIX-side-by-side container, no opt-in is required.

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
