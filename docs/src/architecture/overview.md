# Architecture Overview

> For a detailed technical architecture, see [ARCHITECTURE.md](https://github.com/permanu/Dwaar/blob/main/ARCHITECTURE.md) in the repository.

Dwaar is a single Rust binary built on Cloudflare Pingora. It runs as one OS process with multiple internal services:

```
┌─────────────────────────────────────────┐
│           Dwaar Process                  │
│                                         │
│  Proxy Service     (ports 80, 443)      │
│  Admin Service     (Unix socket/TCP)    │
│  Background Services:                   │
│    - ACME cert renewal                  │
│    - Health checks                      │
│    - Log flusher                        │
│    - Docker watcher                     │
│                                         │
│  Each service runs on its own           │
│  Tokio runtime (thread pool)            │
└─────────────────────────────────────────┘
```

## Crate Structure

| Crate | Purpose |
|-------|---------|
| `dwaar-core` | ProxyHttp implementation, route table, request context |
| `dwaar-config` | Dwaarfile parser, validation, hot-reload |
| `dwaar-tls` | ACME client, certificate management, SNI routing |
| `dwaar-analytics` | JS injection, beacon collection, in-memory aggregation |
| `dwaar-plugins` | Plugin trait, built-in plugins |
| `dwaar-admin` | Admin API service |
| `dwaar-docker` | Docker label discovery |
| `dwaar-geo` | GeoIP lookup |
| `dwaar-log` | Request logging, batch writer |
| `dwaar-cli` | Binary entry point, CLI |
