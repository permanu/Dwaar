# Dwaar

> The gateway for your applications. Pingora performance. Caddy simplicity.

Dwaar (द्वार — "gateway" in Hindi) is a high-performance reverse proxy built on [Cloudflare Pingora](https://github.com/cloudflare/pingora) with first-party analytics, automatic HTTPS, and a zero-cognitive-load config format.

## Why Dwaar?

| What you get | Without Dwaar | With Dwaar |
|-------------|---------------|------------|
| Reverse proxy + auto TLS | Caddy (~30 MB) | Dwaar (~25 MB) |
| First-party analytics | + Plausible (~200 MB) | Included |
| Request logging | + Custom scripts | Included |
| Bot detection | + fail2ban (~30 MB) | Included |
| **Total** | **~260+ MB, 3-4 services** | **~25 MB, 1 binary** |

## Quick Start

```
# Dwaarfile
example.com {
    proxy localhost:8080
    analytics on
}
```

```bash
dwaar
```

That's it. HTTPS is automatic. Analytics are injected. Requests are logged.

## Features

- **Pingora engine** — 5-10x nginx performance, ~5 MB base memory
- **Automatic HTTPS** — Let's Encrypt + ZeroSSL, zero config
- **First-party analytics** — Ad-blocker-proof, same-origin injection
- **Dwaarfile** — Human-readable config, 3 lines for a working proxy
- **Admin API** — JSON API for runtime config changes, no restarts
- **Docker integration** — Auto-discover containers via labels
- **Plugin system** — Native Rust plugins + WASM runtime
- **Request logging** — 34+ fields per request, batch-written
- **Bot detection** — User-agent + behavior analysis
- **Rate limiting** — Per-IP, per-domain, configurable
- **Zero-downtime upgrades** — Pingora's FD transfer, zero dropped connections

## Architecture

Built on Pingora's `ProxyHttp` trait with 30 lifecycle hooks. Dwaar adds:

```
Pingora (engine)     → TLS, connection pooling, HTTP lifecycle
Dwaar Core (routing) → Dwaarfile parser, route table, admin API
Dwaar Analytics      → JS injection, beacon collection, aggregation
Dwaar Plugins        → Native Rust + WASM extensibility
```

## License

[Business Source License 1.1](LICENSE) — free to use, modify, and redistribute. Cannot be used to offer a competing commercial proxy, CDN, or analytics service. Converts to AGPL-3.0 after 6 years per release.

Commercial licensing available for organizations that need different terms. Contact: [hello@permanu.com](mailto:hello@permanu.com)

## Built by

[Permanu](https://permanu.com) — the team behind Deploy.
