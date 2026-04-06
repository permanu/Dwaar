# Dwaar

> The gateway for your applications. Pingora performance. Caddy simplicity.

**Dwaar** (द्वार — "gateway" in Hindi) is a high-performance reverse proxy built on [Cloudflare Pingora](https://github.com/cloudflare/pingora) with first-party analytics, automatic HTTPS, and a zero-cognitive-load configuration format.

## Why Dwaar?

Most reverse proxies make you choose: **simplicity** (Caddy) or **performance** (Nginx, HAProxy). Dwaar gives you both — Caddy-level ease of use on a Rust engine that uses 5-10x less memory.

And unlike every other proxy, Dwaar includes **built-in analytics** that bypass ad blockers by serving from the same origin as your application.

```
# This is a complete, production-ready HTTPS proxy:
example.com {
    proxy localhost:8080
    analytics on
}
```

Three lines. Automatic HTTPS. First-party analytics. Security headers. Compression. All included.

## What Dwaar Replaces

| Without Dwaar | With Dwaar |
|---------------|------------|
| Caddy or Nginx (~30 MB) | Dwaar (~25 MB) |
| + Plausible or PostHog (~200 MB) | Included |
| + Custom log pipeline | Included |
| + fail2ban for bots (~30 MB) | Included |
| **~260 MB, 3-4 services** | **~25 MB, 1 binary** |

## Key Features

- **Pingora engine** — Rust-based, 5-10x less memory than Go-based proxies
- **Automatic HTTPS** — Let's Encrypt + ZeroSSL, zero configuration
- **First-party analytics** — Ad-blocker-proof, same-origin injection
- **Dwaarfile** — 3 lines for a working proxy, 10 directives total
- **Admin API** — Runtime config changes, no restarts
- **Docker integration** — Auto-discover containers via labels
- **Plugin system** — Native Rust + WASM extensibility
- **Zero-downtime upgrades** — Pingora's FD transfer mechanism

## Quick Example

```bash
# Install
curl -fsSL dwaar.dev/install | sh

# Create config
cat > Dwaarfile <<EOF
api.example.com {
    proxy localhost:3000
    rate_limit 100/s
}

blog.example.com {
    proxy localhost:4000
    analytics on
}
EOF

# Run
dwaar
```

That's it. Both domains get HTTPS certificates automatically. Blog gets analytics. API gets rate limiting. All traffic is logged.

## License

Dwaar is source-available under the [Business Source License 1.1](https://github.com/permanu/Dwaar/blob/main/LICENSE), converting to AGPL-3.0 after 10 years per release. Free to use for any purpose except offering a competing commercial proxy service.

Built by [Permanu](https://permanu.com).
