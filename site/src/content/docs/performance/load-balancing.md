---
title: "Load Balancing"
---

# Load Balancing

When a `reverse_proxy` block lists more than one upstream, Dwaar selects a backend on every request using a configurable policy. All selection logic is lock-free: health flags and connection counters are atomics, so there is no mutex on the hot path.

When every backend in a pool is either unhealthy or at its connection limit, Dwaar returns `502 Bad Gateway`.

---

## Quick Start

```txt
api.example.com {
    reverse_proxy {
        to backend1:8080 backend2:8080
        lb_policy round_robin
    }
}
```

---

## Policies

```mermaid
graph TD
    R[Incoming Request] --> S{lb_policy}
    S -->|round_robin| RR["Advance counter, pick backend #counter % n#"]
    S -->|least_conn| LC[Scan pool, pick lowest active_conns]
    S -->|random| RD[Pick uniformly random healthy backend]
    S -->|ip_hash| IH["FNV-1a hash of client IP, pick backend #hash % n#"]
    RR --> F["find_available_from: skip unhealthy or at cap"]
    IH --> F
    F --> U[Selected Upstream]
    LC --> U
    RD --> U
```

| Policy | Description | Best For |
|---|---|---|
| `round_robin` | Distributes requests evenly in turn across all healthy backends. Uses a single `AtomicU64` counter; no per-backend state. Default when `lb_policy` is omitted. | General-purpose. Equal-weight stateless backends. |
| `least_conn` | Scans the pool and selects the backend with the fewest in-flight connections (`active_conns`). O(n) scan; fine for pools under ~32 backends. | Long-lived or variable-latency requests (streaming, uploads). |
| `random` | Picks a uniformly random healthy backend using `fastrand`. No shared mutable state at all. | Large pools where counter contention matters. Stateless requests. |
| `ip_hash` | Hashes the client IP (FNV-1a over raw IP bytes) and maps it to a backend deterministically. Falls back to round-robin when no client IP is available. | Session affinity without sticky cookies. Cache-local workloads. |

### Single-Backend Fast Path

When a pool has exactly one backend, Dwaar skips the counter increment and the pool scan entirely. No policy overhead — just a health check and a `max_conns` check.

---

## Health-Aware Routing

All four policies exclude unhealthy backends from selection. When a policy's initial selection lands on an unhealthy or capped backend, Dwaar scans forward through the pool (wrapping around) until it finds one that is available.

```
round_robin / ip_hash selection walk:

  [backend0: unhealthy] → skip
  [backend1: at max_conns] → skip
  [backend2: healthy, under cap] → selected
```

`least_conn` and `random` filter the pool to healthy, under-cap backends before selecting, so they never land on an unavailable backend in the first pass.

### What Marks a Backend Unhealthy

A backend is marked unhealthy when:

- The background `HealthChecker` polls `health_uri` and receives a non-`2xx` response or a connection error.
- A connection attempt in `upstream_peer()` is refused (immediate mark, no waiting for the next health interval).

It is returned to the pool as soon as a subsequent health probe succeeds.

### Transition logs

Health state changes are logged as `tracing` events at the point of transition — not on every probe. Steady-state checks produce no log output at all, so a healthy pool is silent.

| Edge | Level | Example |
|---|---|---|
| Healthy → unhealthy | `WARN` | `upstream transitioned to unhealthy backend=10.x.x.x:8080 reason="connection refused (os error 111)"` |
| Unhealthy → healthy | `INFO` | `upstream transitioned to healthy backend=10.x.x.x:8080` |

The probe error string is captured in `Backend::last_error` (a `parking_lot::Mutex<Option<String>>`) and included in the `WARN` event as the `reason=` field. On the `INFO` transition the error is cleared. This gives operators a precise "when did each backend flip" timeline without needing the full health-check debug log turned on.

**Address masking (0.2.3).** Transition logs mask the upstream address before it reaches the log sink. IPv4 addresses are rendered as `10.x.x.x:8080` (octets 2–4 replaced with `x`); IPv6 addresses are truncated to their `/48` prefix. The port and the backend name are preserved.

This prevents internal network topology from leaking into shared log aggregators in multi-tenant deployments. The full address is still available in debug logs (`RUST_LOG=dwaar=debug`) for on-host troubleshooting, and the unmasked `Backend::addr` value is unchanged in the Admin API — only the `tracing` events on the transition path are redacted.

In a structured-logging pipeline (e.g. Vector, Loki), alert rules can trigger directly on the event name:

```promql
count_over_time({event="upstream transitioned to unhealthy"}[5m]) > 0
```

Configure health checking on the `reverse_proxy` block:

```txt
api.example.com {
    reverse_proxy {
        to app1:8080 app2:8080
        lb_policy round_robin
        health_uri /health
        health_interval 10
        fail_duration 30
    }
}
```

See [Reverse Proxy — Health Checks](../routing/reverse-proxy.md#health-checks) for full field details.

---

## Upstream H2 Pool (H3 → H2 multiplexing)

Dwaar's HTTP/3 bridge shares a **per-host pool** of upstream H2 connections across every concurrent H3 stream targeting that upstream. The pool is capped at `MAX_CONNS_PER_HOST = 2`, and cold-start bursts are serialized through a per-host `tokio::sync::Mutex` inside `H2ConnPool::get_or_connect`. This removes a check-then-act race where N simultaneous H3 streams arriving on a cold pool could each race past the cap and open N separate upstream TCP sockets. With the mutex gating the connect decision, 100 concurrent H3 streams to one upstream share `≤ 2` TCP connections — an invariant enforced in the `quic_h2_pool_concurrency` integration suite.

This is the mechanism that makes H3 → H2 upstream multiplexing deliver real TCP savings under load. It is transparent to operators: no config knob, no directive, no restart.

---

## Connection Limits

`max_conns` caps the number of concurrent in-flight connections to a single backend. The limit is enforced atomically using a compare-and-swap loop on `AtomicU32` — no mutex.

```txt
api.example.com {
    reverse_proxy {
        to app1:8080 app2:8080
        lb_policy least_conn
        max_conns 200
    }
}
```

When `acquire_connection()` is called for a backend already at its cap, it returns `false`. The selection logic then moves to the next available backend. If all backends are at their caps, Dwaar returns `502`.

Connection counters are decremented via `release_connection()` at the end of each request, including on error paths, so the count stays accurate under failure.

| Scenario | Outcome |
|---|---|
| Backend under cap | `acquire_connection` succeeds; request proceeds. |
| Backend at cap, others available | Caller skips to the next backend in the selection walk. |
| All backends at cap | `select()` returns `None`; proxy returns 502. |
| `max_conns` not set | Unlimited connections; `acquire_connection` always succeeds. |

---

## Complete Example

Three-backend pool with IP-hash affinity, health checks, and per-backend connection limits.

```txt
app.example.com {
    reverse_proxy {
        to app1.internal:8080 app2.internal:8080 app3.internal:8080

        lb_policy ip_hash

        health_uri /healthz
        health_interval 10
        fail_duration 60

        max_conns 300
    }
}
```

Each client IP consistently lands on the same backend as long as that backend is healthy. If `app2` fails a health probe, its traffic is redistributed via the `find_available_from` walk — no operator intervention needed.

---

## Related

- [Reverse Proxy](../routing/reverse-proxy.md) — full directive reference including upstream TLS and scale-to-zero
- [Timeouts](timeouts.md) — header, body, and keep-alive timeout configuration
- [Performance](../performance/http3.md) — HTTP/3 and connection efficiency
