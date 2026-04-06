# Reverse Proxy

`reverse_proxy` is Dwaar's primary directive. It forwards every matched request to one or more upstream servers, handles load balancing, health checking, connection limiting, and upstream TLS — all without blocking the event loop.

---

## Quick Start

```caddy
example.com {
    reverse_proxy localhost:8080
}
```

One upstream, no configuration needed. Dwaar connects over plain HTTP and forwards the request as-is.

---

## Inline Syntax

List multiple upstream addresses on the same line to create a load-balanced pool. The default policy is round-robin.

```caddy
example.com {
    reverse_proxy backend1:8080 backend2:8080 backend3:8080
}
```

Dwaar distributes requests evenly across all three backends. A backend that fails a health check is removed from rotation automatically.

---

## Block Syntax

Use the block form to configure load balancing policy, health checks, connection limits, upstream TLS, and HTTP/2 upstream multiplexing.

```caddy
example.com {
    reverse_proxy {
        to backend1:8080 backend2:8080
        lb_policy least_conn
        health_uri /health
        health_interval 10
        fail_duration 30
        max_conns 200
        transport {
            tls
            tls_server_name api.internal
        }
    }
}
```

The `to` subdirective is required in block form. All other subdirectives are optional.

---

## Configuration Options

| Field | Type | Default | Description |
|---|---|---|---|
| `to` | `host:port ...` | — | One or more upstream addresses. Required in block form. |
| `lb_policy` | `round_robin \| least_conn \| random \| ip_hash` | `round_robin` | Load balancing algorithm to use when multiple upstreams are configured. |
| `health_uri` | `string` | `""` (disabled) | HTTP path polled on each backend to determine reachability (e.g. `/health`). Omit to disable health checking. |
| `health_interval` | `u64` (seconds) | `10` | Seconds between health probe polls. Applies to all backends in this pool. |
| `fail_duration` | `u64` (seconds) | `0` | How long (seconds) to keep a backend marked unhealthy after a probe failure. `0` means re-check immediately on the next interval. |
| `max_conns` | `u32` | unlimited | Maximum concurrent connections per backend. New connections are rejected (502) when the cap is reached. Enforced atomically — no mutex on the hot path. |
| `transport_tls` | `bool` (flag) | `false` | Connect to the upstream over TLS. Enabled implicitly by any `transport { tls ... }` subdirective. |
| `transport_h2` | `bool` (flag) | `false` | Use HTTP/2 multiplexing for upstream connections. All H3 streams share 1-2 H2 connections per host instead of opening one TCP connection per stream. Requires upstream H2 support. See [HTTP/2 Upstream](#http2-upstream). |
| `tls_server_name` | `string` | `""` (use IP) | SNI hostname sent during the upstream TLS handshake. Required when the upstream serves multiple virtual hosts over a single IP. |
| `tls_client_auth` | `(cert_path, key_path)` | `None` | Paths to a client certificate and private key for mutual TLS with the upstream. Both files are loaded and validated at config compile time. |
| `tls_trusted_ca_certs` | `string` | `None` | Path to a custom CA bundle for verifying the upstream's server certificate. Use when the backend uses a private CA not in the system trust store. |
| `scale_to_zero` | block | `None` | Wake a sleeping backend on first request instead of returning 502. See [Scale to Zero](#scale-to-zero). |

> `max_request_body_size` is a global option configured via the [handle](handle.md) directive, not on `reverse_proxy` directly.

---

## Health Checks

When `health_uri` is set, Dwaar runs a background `HealthChecker` service that probes every backend on the configured interval.

```caddy
api.example.com {
    reverse_proxy {
        to app1:8080 app2:8080
        health_uri /health
        health_interval 15
        fail_duration 60
    }
}
```

**How it works:**

1. The checker issues an HTTP GET to `http://<backend><health_uri>` every `health_interval` seconds.
2. A `2xx` response marks the backend healthy.
3. Any non-`2xx` response or connection error marks the backend unhealthy immediately.
4. An unhealthy backend is excluded from all load balancing selections.
5. Once a subsequent probe succeeds, the backend is returned to the pool.

When every backend in a pool is unhealthy, Dwaar returns `502 Bad Gateway` to the client.

The `fail_duration` field controls how long a backend stays marked unhealthy regardless of subsequent probe results. Set it to a value longer than `health_interval` to prevent flapping.

---

## Upstream TLS

Use a `transport` block to connect to the upstream over HTTPS.

### Plain TLS

```caddy
api.example.com {
    reverse_proxy {
        to secure-backend:443
        transport {
            tls
        }
    }
}
```

### Custom SNI

Required when the backend serves multiple virtual hosts on one IP.

```caddy
api.example.com {
    reverse_proxy {
        to 10.0.0.5:443
        transport {
            tls_server_name api.internal.corp
        }
    }
}
```

### Custom CA

Use when the upstream presents a certificate signed by a private CA.

```caddy
api.example.com {
    reverse_proxy {
        to secure-backend:443
        transport {
            tls
            tls_trusted_ca_certs /etc/ssl/private-ca.pem
        }
    }
}
```

### Mutual TLS (mTLS)

Provide a client certificate and key for backends that require client authentication.

```caddy
api.example.com {
    reverse_proxy {
        to secure-backend:443
        transport {
            tls_client_auth /etc/ssl/client.crt /etc/ssl/client.key
            tls_trusted_ca_certs /etc/ssl/private-ca.pem
        }
    }
}
```

All three `tls_*` fields inside `transport { }` implicitly enable `transport_tls`. Setting any one of them is enough — you do not need to repeat the bare `tls` flag.

---

## HTTP/2 Upstream

Use `transport h2` to enable HTTP/2 multiplexing for upstream connections. This is especially beneficial when Dwaar serves HTTP/3 (QUIC) traffic — instead of opening one TCP connection per H3 stream, all streams multiplex onto 1-2 shared H2 connections per upstream host.

```caddy
api.example.com {
    reverse_proxy {
        to backend:8080
        transport h2
    }
}
```

**When to use:** Your upstream supports HTTP/2 (Go, Node.js, Java, nginx, or any modern server). The benefit scales with concurrency — at 100 concurrent H3 streams, this reduces upstream TCP connections from 100 to 2.

**Combining with TLS:**

```caddy
api.example.com {
    reverse_proxy {
        to secure-backend:443
        transport {
            tls
            h2
            tls_server_name api.internal
        }
    }
}
```

**How it works:**

- Dwaar maintains 1-2 H2 connections per upstream host (capped to limit GOAWAY blast radius).
- Each H3 request stream gets a cloned `SendRequest` handle — no per-request TCP overhead.
- If the upstream sends GOAWAY or the connection dies, Dwaar evicts the dead connection and retries idempotent requests (GET, HEAD, OPTIONS, PUT, DELETE) on a fresh connection.
- Non-idempotent requests (POST, PATCH) are not retried to prevent duplicate side effects.

**Without `transport h2`:** Dwaar uses HTTP/1.1 upstream connections (one per concurrent stream, pooled for sequential reuse).

---

## Scale to Zero

`scale_to_zero` lets Dwaar wake a sleeping backend instead of returning 502. When the upstream is unreachable, Dwaar holds the incoming request, runs `wake_command` once (coalesced across concurrent requests), polls the backend's health endpoint, and forwards the request as soon as the backend responds.

```caddy
myapp.example.com {
    reverse_proxy {
        to localhost:8080
        health_uri /health
        scale_to_zero {
            wake_timeout 30
            wake_command "docker start myapp"
        }
    }
}
```

| Field | Default | Description |
|---|---|---|
| `wake_timeout` | `30` | Seconds to wait for the backend to become reachable before giving up with 502. |
| `wake_command` | — | Shell command to execute to start the backend. Run once per unreachable event; concurrent requests wait on the same wake attempt. |

`health_uri` is required for scale-to-zero to detect when the backend is ready. Without it, Dwaar cannot know when to forward the held request.

---

## Complete Example

Multi-upstream deployment with health checks, least-connection load balancing, and mTLS to the upstream.

```caddy
api.example.com {
    reverse_proxy {
        to app1.internal:8443 app2.internal:8443 app3.internal:8443

        lb_policy least_conn

        health_uri /healthz
        health_interval 10
        fail_duration 30

        max_conns 500

        transport {
            tls_server_name app.internal
            tls_client_auth /etc/ssl/client.crt /etc/ssl/client.key
            tls_trusted_ca_certs /etc/ssl/internal-ca.pem
        }
    }
}
```

---

## Related

- [Load Balancing](../performance/load-balancing.md) — policy details and connection limits
- [Handle](handle.md) — route matching and request body limits
- [Timeouts](../performance/timeouts.md) — header, body, and keep-alive timeouts
- [mTLS](../security/mtls.md) — upstream and downstream mutual TLS
