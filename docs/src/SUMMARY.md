# Summary

[Introduction](./introduction.md)

# Getting Started

- [What is Dwaar?](./getting-started/what-is-dwaar.md)
- [Installation](./getting-started/installation.md)
- [Quick Start](./getting-started/quickstart.md)
- [Comparison with Other Proxies](./getting-started/comparison.md)

# Configuration

- [Dwaarfile Reference](./configuration/dwaarfile.md)
- [Global Options](./configuration/global-options.md)
- [Named Matchers](./configuration/named-matchers.md)
- [Placeholders & Variables](./configuration/placeholders.md)
- [CLI Reference](./configuration/cli.md)
- [Environment Variables](./configuration/environment.md)

# Routing & Handlers

- [Reverse Proxy](./routing/reverse-proxy.md)
- [File Server](./routing/file-server.md)
- [FastCGI / PHP](./routing/fastcgi.md)
- [Redirects & Rewrites](./routing/redirects-rewrites.md)
- [Handle & Route Blocks](./routing/handle.md)
- [Respond & Error Pages](./routing/respond-errors.md)

# HTTPS & TLS

- [Automatic HTTPS](./tls/automatic-https.md)
- [DNS-01 Challenge (Wildcards)](./tls/dns-challenge.md)
- [Manual Certificates](./tls/manual-certs.md)
- [Self-Signed (Development)](./tls/self-signed.md)
- [Mutual TLS (mTLS)](./tls/mtls.md)
- [OCSP Stapling](./tls/ocsp-stapling.md)

# Security

- [Rate Limiting](./security/rate-limiting.md)
- [IP Filtering (Allow/Blocklist)](./security/ip-filtering.md)
- [Bot Detection](./security/bot-detection.md)
- [Security Headers](./security/security-headers.md)
- [Basic Auth](./security/basic-auth.md)
- [Forward Auth](./security/forward-auth.md)

# Performance

- [Compression](./performance/compression.md)
- [HTTP Caching](./performance/caching.md)
- [HTTP/3 (QUIC)](./performance/http3.md)
- [Timeouts & Connection Draining](./performance/timeouts.md)
- [Load Balancing](./performance/load-balancing.md)

# Observability

- [Request Logging](./observability/logging.md)
- [First-Party Analytics](./observability/analytics.md)
- [Prometheus Metrics](./observability/prometheus.md)
- [Distributed Tracing](./observability/tracing.md)
- [GeoIP](./observability/geoip.md)

# Plugins

- [Plugin System Overview](./plugins/overview.md)
- [WASM Plugins](./plugins/wasm-plugins.md)
- [Native Plugin Development](./plugins/native-plugins.md)

# Admin API

- [API Reference](./api/admin.md)
- [Analytics API](./api/analytics.md)
- [Cache Purge](./api/cache-purge.md)

# Deployment

- [Docker](./deployment/docker.md)
- [Docker Label Discovery](./deployment/docker-labels.md)
- [Kubernetes Ingress Controller](./deployment/kubernetes.md)
- [Helm Chart](./deployment/helm.md)
- [Systemd Service](./deployment/systemd.md)
- [Zero-Downtime Upgrades](./deployment/zero-downtime.md)

# Migration Guides

- [From Caddy](./migration/from-caddy.md)
- [From Nginx](./migration/from-nginx.md)
- [From Traefik](./migration/from-traefik.md)

# Architecture

- [Overview](./architecture/overview.md)
- [Request Lifecycle](./architecture/request-lifecycle.md)
- [Performance Internals](./architecture/performance.md)
- [Crate Map](./architecture/crate-map.md)

# Contributing

- [Development Setup](./contributing/development.md)
- [Architecture for Contributors](./contributing/architecture.md)

# Appendix

- [Troubleshooting & FAQ](./appendix/troubleshooting.md)
- [Changelog](./appendix/changelog.md)
