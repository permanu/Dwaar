---
title: "What is Dwaar?"
---

# What is Dwaar?

Dwaar is a **reverse proxy** — software that sits between the internet and your applications, handling HTTPS, routing, security, and analytics.

## How It Works

```
Internet → Dwaar → Your Applications

User visits https://api.example.com
  → Dwaar terminates TLS (HTTPS encryption)
  → Dwaar reads the Host header
  → Dwaar routes to localhost:3000
  → Your app responds
  → Dwaar adds security headers, compresses, injects analytics
  → Response sent to user
```

Your application doesn't need to know about HTTPS certificates, domain routing, compression, or security headers. It just serves HTTP on a local port. Dwaar handles everything else.

## Who Is Dwaar For?

- **Developers** deploying web applications who want HTTPS without configuration
- **Teams** running multiple services on one server who need domain-based routing
- **Product owners** who want built-in analytics without adding PostHog or Plausible
- **DevOps engineers** who want Caddy's simplicity with better performance
- **Platform builders** who need a proxy component for their deployment platform

## How Dwaar Compares

### vs Caddy

Caddy pioneered automatic HTTPS and simple config. Dwaar follows the same philosophy but adds:

- **5-10x less memory** (Rust vs Go)
- **Built-in analytics** (Caddy has no analytics)
- **WASM plugins** (Caddy uses Go modules, requiring recompilation)

### vs Nginx

Nginx is the most deployed proxy on earth. Dwaar differs in:

- **3-line config** vs 14-line config for a basic proxy
- **Automatic HTTPS** vs manual certificate management
- **Built-in analytics** vs no analytics
- **Runtime config reload** vs SIGHUP-based reload

### vs Traefik

Traefik is the go-to for Docker/Kubernetes environments. Dwaar offers:

- **Half the memory** (~25 MB vs ~50 MB)
- **Simpler config** (Dwaarfile vs YAML/TOML)
- **Built-in analytics** vs no analytics
- **Same Docker label discovery**

See the [full comparison](./comparison.md) for a detailed feature matrix.

## Built on Pingora

Dwaar is built on [Cloudflare Pingora](https://github.com/cloudflare/pingora), the Rust proxy framework that powers a significant portion of Cloudflare's infrastructure. Pingora provides:

- Async Rust on Tokio for maximum efficiency
- Connection pooling with HTTP/1.1 keepalive and HTTP/2 multiplexing
- Zero-downtime upgrades via file descriptor transfer
- Battle-tested at internet scale

Dwaar adds the user-facing experience on top: configuration, ACME, analytics, Docker integration, and the Admin API.

> **Note:** Pingora is a standalone open-source library. Using Dwaar does not require Cloudflare or any cloud provider.
