---
title: "Layer 4 TCP Proxy"
---

# Layer 4 TCP Proxy

Layer 4 proxies raw TCP connections rather than HTTP requests. Use it to terminate TLS and forward to backend services, to multiplex protocols on a single port by inspecting connection content (SNI, HTTP Host header, SSH handshake, Postgres startup message), or to chain matchers and handlers for fall-through listener routing.

The Layer 4 service binds its own TCP listeners independently from the HTTP proxy and runs as a background service alongside the rest of Dwaar.

---

## Syntax

The `layer4` block is a top-level Dwaarfile app block. Each address stanza inside it defines one or more listen addresses that share a set of named matchers and routes.

```caddy
layer4 {
    :443 {
        @tls tls sni example.com
        @ssh ssh

        route @tls {
            tls
            proxy 127.0.0.1:9001
        }
        route @ssh {
            proxy 127.0.0.1:22
        }
    }
}
```

One server stanza may listen on multiple addresses by listing them space-separated before the opening brace:

```caddy
layer4 {
    :443 :8443 {
        @tls tls
        route @tls {
            proxy 10.0.0.1:8443
        }
    }
}
```

**Named matchers** (`@name`) are declared at the server level and referenced by one or more `route` blocks. Multiple matchers on a single `@name` line must ALL match (AND logic). A `route` with no matcher reference is a catch-all.

**Routes** are evaluated in declaration order; the first matching route wins.

---

## Matchers

Matchers are declared as `@name <matcher> [args] [<matcher> [args] ...]` and referenced by `route @name`. All conditions on a single `@name` line are ANDed.

### `tls`

Matches a TLS ClientHello. By itself it matches any TLS connection. Narrow with `sni` and/or `alpn` sub-fields.

```caddy
# Any TLS connection
@any_tls tls

# Specific SNI hostname (wildcards follow RFC 6125 §6.4.3)
@app tls sni app.example.com
@wildcard tls sni *.example.com

# ALPN protocol
@h2 tls alpn h2

# Both SNI and ALPN
@grpc tls sni api.example.com alpn h2
```

Wildcard SNI patterns match a single label only: `*.example.com` matches `foo.example.com` but not `foo.bar.example.com`.

### `http`

Peeks at the first bytes of the connection to detect an HTTP/1.1 request line, then optionally matches the `Host` header.

```caddy
# Any HTTP connection
@http http

# Specific Host header value
@site http host www.example.com
```

### `ssh`

Matches connections that begin with the SSH version string (`SSH-`).

```caddy
@ssh ssh
```

### `postgres`

Matches connections that begin with a PostgreSQL wire-protocol startup message (8-byte header with protocol version 3.0 / `196608`).

```caddy
@pg postgres
```

### `remote_ip`

Matches the client's IP address against one or more CIDR ranges.

```caddy
@internal remote_ip 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12
@single   remote_ip 203.0.113.42/32
```

### `not`

Negates the immediately following matcher.

```caddy
@external not remote_ip 10.0.0.0/8
```

---

## Handlers

Handlers are listed inside a `route` block and execute in order for matching connections.

### `proxy`

Forwards the raw TCP byte stream to one or more upstream addresses. Upstream addresses are `host:port` or `ip:port` strings.

**Inline form** (one or more upstreams on the same line):

```caddy
route @tls {
    proxy 10.0.0.1:9000 10.0.0.2:9000
}
```

**Block form** (with options):

```caddy
route @tls {
    proxy {
        to 10.0.0.1:9000 10.0.0.2:9000
        lb_policy least_conn
        max_fails 5
        fail_duration 30s
        health_timeout 5s
    }
}
```

`to`, `upstream`, and `upstreams` are all accepted as the upstream address keyword in block form.

#### `proxy` options

| Option | Default | Description |
|---|---|---|
| `lb_policy` | `round_robin` | Load balancing algorithm. Accepted values: `round_robin`, `least_conn`, `random`, `ip_hash`. |
| `max_fails` | `3` | Consecutive connect failures before an upstream is quarantined. |
| `fail_duration` | `10s` | How long a quarantined upstream is excluded from selection. |
| `health_timeout` | `10s` | Per-connection dial timeout. Also accepted as `connect_timeout`. |
| `health_interval` | — | Recognized but not yet active. See [Limitations](#limitations). |
| `health_uri` | — | Recognized but not yet active. See [Limitations](#limitations). |

### `tls`

Terminates TLS at the Layer 4 level using Dwaar's shared certificate store. The cert is selected by the SNI hostname already parsed from the peeked `ClientHello`. After decryption the decrypted byte stream is passed to the next handler in the same `route` block.

```caddy
route @tls {
    tls
    proxy 127.0.0.1:8080
}
```

Place `tls` before `proxy` in the handler list. The `proxy` handler then receives plaintext bytes and forwards them to the upstream.

### `subroute`

A nested route set with its own matchers and routes. Used to re-inspect decrypted bytes after `tls` termination, or to group related routes under a common outer matcher.

Accepts an optional `matching_timeout` to override how long to buffer bytes waiting for protocol detection inside the subroute.

```caddy
route @tls {
    tls
    subroute {
        matching_timeout 3s
        @grpc http host grpc.example.com
        @web  http host www.example.com
        route @grpc {
            proxy 127.0.0.1:50051
        }
        route @web {
            proxy 127.0.0.1:8080
        }
    }
}
```

---

## Load Balancing and Passive Health

When a `proxy` handler has multiple upstreams, Dwaar selects one per connection using the configured `lb_policy`:

- **`round_robin`** (default) — distributes connections in turn using a global atomic counter. No lock on the hot path.
- **`least_conn`** — picks the upstream with the fewest active connections at the moment of selection.
- **`random`** — uniform random pick.
- **`ip_hash`** — hashes the client IP so the same client is consistently sent to the same upstream.

**Passive health** is inferred from real connection outcomes; no background prober is involved.

- Each upstream tracks `consecutive_fails` and `active_conns` via atomic counters.
- When a connect attempt times out or is refused, the fail counter increments.
- After `max_fails` consecutive failures the upstream is quarantined: it is excluded from selection until `fail_duration` seconds have elapsed.
- On the next successful connect, the failure counter and quarantine timestamp are both cleared.
- If all upstreams are simultaneously quarantined, the connection is dropped with a log warning.

---

## Listener Wrapper (fall-through)

A single TCP port can be shared between the Layer 4 service and the HTTP proxy using the listener-wrapper pattern. The `Layer4ListenerWrapper` type attaches an L4 route set to an HTTP site block's listen address. The Layer 4 routes are evaluated first; connections that do not match any L4 route fall through to normal HTTP processing.

This is an advanced configuration used when the same port must handle both raw TCP protocols and HTTP traffic. The exact Dwaarfile syntax for the listener-wrapper form is plumbed through `parse_layer4_route_set` and `compile_l4_wrappers` in the config layer; consult those source files for the current state of that wiring.

---

## Examples

### TLS termination with SNI-based routing

Route two different HTTPS services on port 443 based on hostname.

```caddy
layer4 {
    :443 {
        @app tls sni app.example.com
        @api tls sni api.example.com

        route @app {
            tls
            proxy 127.0.0.1:3000
        }
        route @api {
            tls
            proxy 127.0.0.1:4000
        }
    }
}
```

### SSH and HTTPS multiplexing on port 443

Serve SSH and HTTPS on the same port. The TLS ClientHello and the SSH version string are structurally distinct, so no ambiguity exists between the two matchers.

```caddy
layer4 {
    :443 {
        @tls tls
        @ssh ssh

        route @tls {
            tls
            proxy 127.0.0.1:8443
        }
        route @ssh {
            proxy 127.0.0.1:22
        }
    }
}
```

### Postgres proxying with least-connection load balancing

Forward PostgreSQL connections to a pool of database replicas.

```caddy
layer4 {
    :5432 {
        @pg postgres

        route @pg {
            proxy {
                to 10.0.1.10:5432 10.0.1.11:5432 10.0.1.12:5432
                lb_policy least_conn
                max_fails 2
                fail_duration 20s
                health_timeout 3s
            }
        }
    }
}
```

---

## Limitations

- **Active health checks are not implemented.** `health_interval` and `health_uri` are recognized by the parser and accepted without error, but they have no effect at runtime. Upstream reachability is tracked passively only (connect success/failure).
- **UDP is not supported.** The Layer 4 service binds TCP listeners only. There is no UDP proxy path.
- **Matching timeout is fixed at 3 seconds per server.** Per-server override is not yet wired through; `matching_timeout` inside `subroute` blocks is respected, but the top-level server timeout is always 3 seconds.
- **Protocol detection peeks at most 4 KB.** Connections that do not produce a recognizable protocol signature within the first 4 096 bytes within the matching timeout are dropped.

---

## Related

- [Reverse Proxy](reverse-proxy.md) — HTTP/1.1, HTTP/2, and HTTP/3 upstream proxying
- [TLS](../configuration/environment.md) — certificate management and SNI
