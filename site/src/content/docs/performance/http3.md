---
title: "HTTP/3 (QUIC)"
---

# HTTP/3 (QUIC)

Dwaar serves HTTP/3 over a QUIC transport alongside its existing HTTP/1.1 and
HTTP/2 listeners. Enabling HTTP/3 gives clients:

- **0-RTT connection resumption** — returning clients begin sending requests
  before the TLS handshake completes (idempotent methods only).
- **Head-of-line blocking elimination** — independent request streams are
  multiplexed over a single UDP connection; a lost packet stalls only the
  stream it belongs to.
- **Built-in TLS 1.3** — QUIC encrypts all transport metadata; there is no
  plaintext HTTP/3.

Enable with a single option in the global options block. No per-site changes
are required.

---

## Quick Start

```caddyfile
{
    servers {
        h3 on
    }
}

example.com {
    tls /etc/ssl/certs/example.com.pem /etc/ssl/private/example.com.key
    reverse_proxy :3000
}
```

Dwaar binds a UDP listener on the same port as the TLS listener (default 443)
and advertises HTTP/3 support via the `Alt-Svc` response header automatically.

---

## How It Works

```mermaid
sequenceDiagram
    participant C as Client (browser)
    participant D as Dwaar
    participant U as Upstream (TCP)

    C->>D: HTTPS/1.1 or HTTP/2 request (TCP)
    D-->>C: Response + Alt-Svc: h3=":443"; ma=86400

    Note over C: Client caches Alt-Svc entry (24 h)

    C->>D: QUIC Initial + ClientHello (UDP :443)
    D-->>C: 0-RTT accepted (session ticket present)

    C->>D: HTTP/3 request (QUIC stream, 0-RTT)
    D->>U: HTTP/1.1 or HTTP/2 request (TCP)
    U-->>D: Response
    D-->>C: HTTP/3 response (QUIC stream)

    Note over C,D: Subsequent requests reuse the QUIC connection
    Note over D,U: With transport h2, streams multiplex on 1-2 H2 connections
```

Each HTTP/3 request is handled by `QuicService`, a Pingora `BackgroundService`
that shares the same `RouteTable` and `PluginChain` as the TCP proxy path.
Config reloads propagate to the QUIC path automatically — no restart required.

---

## Alt-Svc Discovery

When a browser first visits a site over TCP, Dwaar injects the following header
into every response from a route that is reachable over QUIC:

```
Alt-Svc: h3=":443"; ma=86400
```

`ma=86400` tells the client to cache the alternative-service record for 24 hours.
On the next visit (and for 24 hours afterward) the browser races a QUIC
connection against a TCP connection and uses whichever wins — usually QUIC after
the first successful handshake.

The header is injected only when **both** conditions are true:

1. `h3 on` is set in the global `servers` block.
2. The request arrived over a TLS connection (QUIC is always TLS 1.3; the
   Alt-Svc header is suppressed for plain-HTTP virtual hosts).

---

## Configuration

### Global options

```caddyfile
{
    servers {
        h3 on
    }
}
```

| Option            | Values         | Default | Description                                                                    |
|-------------------|----------------|---------|--------------------------------------------------------------------------------|
| `h3`              | `on` / `off`   | `off`   | Enable or disable the QUIC listener. When `off`, no UDP socket is opened and no `Alt-Svc` header is injected. |
| `h3_max_streams`  | integer        | `100`   | Maximum concurrent HTTP/3 request streams per QUIC connection. Enforced at the QUIC transport layer via `max_concurrent_bidi_streams`. |

### Firewall requirements

HTTP/3 uses UDP. If a firewall or security group blocks UDP traffic, clients
will fall back to HTTP/2 transparently — no error is surfaced to users.

| Port | Protocol | Purpose                          |
|------|----------|----------------------------------|
| 443  | UDP      | QUIC / HTTP/3                    |
| 443  | TCP      | TLS / HTTP/1.1 + HTTP/2          |

Open UDP 443 inbound (and the corresponding stateful return path) alongside
the existing TCP 443 rule.

### TLS requirement

`h3 on` has no effect on a site that does not configure TLS. QUIC mandates
TLS 1.3; Dwaar enforces this by injecting `Alt-Svc` only when the downstream
connection is already TLS-encrypted.

---

## Body Size Limits

Close-delimited upstream response bodies (responses with no `Content-Length` and no `Transfer-Encoding: chunked`) are capped at **1 GiB** on the HTTP/3 bridge path (`MAX_CLOSE_DELIMITED_BODY`). Bodies that exceed this limit are truncated. This prevents unbounded memory growth when an upstream omits length framing.

---

## Current Limitations

| Limitation | Impact |
|---|---|
| **Reverse proxy only** | `FileServer`, `StaticResponse`, and `FastCGI` handlers return 502 over H3. Clients fall back to HTTP/2 for those routes. |

Request and response bodies are streamed without full buffering. Upstream connections are pooled per host.

**Non-idempotent 0-RTT requests.** POST, PUT, PATCH, and DELETE requests
arriving during the 0-RTT window are rejected with `425 Too Early`. The client
must wait for the full TLS handshake to complete and then retry. This is
required by RFC 9114 §4.2.5 — 0-RTT data is replayable, so only safe methods
(GET, HEAD, OPTIONS) are permitted in that window.

---

## Complete Example

```caddyfile
{
    servers {
        h3             on
        h3_max_streams 200
    }
}

example.com {
    tls /etc/ssl/certs/example.com.pem /etc/ssl/private/example.com.key

    reverse_proxy :8080

    encode gzip br
}

api.example.com {
    tls /etc/ssl/certs/api.example.com.pem /etc/ssl/private/api.example.com.key

    reverse_proxy :9090
}
```

With this configuration:

- Both `example.com` and `api.example.com` advertise HTTP/3 support.
- Each QUIC connection accepts up to 200 concurrent request streams.
- Clients that cannot use QUIC (UDP blocked, no browser support) connect over
  HTTP/2 or HTTP/1.1 without any configuration change or error.
- Brotli and gzip compression applies to HTTP/3 responses identically to the
  TCP path.

---

## Related

- [Global Options](../configuration/global-options.md) — `servers { }` block reference
- [Timeouts](./timeouts.md) — upstream round-trip timeout (30 s default on the H3 path)
- [Compression](./compression.md) — `encode` directive
- [TLS](../tls/) — certificate configuration required for QUIC
- [Performance](./load-balancing.md) — load balancing across upstream pools
