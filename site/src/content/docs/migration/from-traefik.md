---
title: "Migrating from Traefik"
---

# Migrating from Traefik

Traefik routes traffic by reading labels attached to containers or entries in its dynamic-config files. Dwaar achieves the same routing through two equivalent mechanisms: **Docker labels** (Dwaar watches the Docker socket and reloads routes live) and a **Dwaarfile** (a static config file you write once and reload on change). Both produce the same result; the labels path requires zero static files, while the Dwaarfile path is independent of Docker.

The sections below map every common Traefik pattern to its Dwaar equivalent, then walk through a full migration.

---

## Concept Mapping

| Traefik concept | Dwaar equivalent |
|---|---|
| Router | Site block in Dwaarfile: `example.com { … }` |
| Service / loadbalancer | `reverse_proxy` directive |
| Middleware | Directives (`rate_limit`, `basic_auth`, `redir`, `header`) or plugins |
| Provider (`docker`, `file`) | Docker label watcher or Dwaarfile |
| Entrypoint (`web`, `websecure`) | `http_port` / `https_port` in global options block |
| certificatesResolvers | Automatic HTTPS — no configuration needed; Dwaar provisions certs from Let's Encrypt by default |
| Dashboard | Admin API at `127.0.0.1:6190` |
| Static config (YAML/TOML) | Global options block at top of Dwaarfile |
| Dynamic config (file provider) | Site blocks in Dwaarfile |
| Traefik labels namespace | `dwaar.*` label namespace |

---

## Docker Label Translations

Each example shows the Traefik labels on the left and the Dwaar labels (or equivalent Dwaarfile block) on the right. The Docker Compose service structure is the same in both cases — only the labels change.

### Basic router

**Traefik**

```yaml
services:
  app:
    image: myapp:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`app.example.com`)"
      - "traefik.http.routers.app.entrypoints=websecure"
      - "traefik.http.services.app.loadbalancer.server.port=8080"
```

**Dwaar**

```yaml
services:
  app:
    image: myapp:latest
    labels:
      - "dwaar.domain=app.example.com"
      - "dwaar.port=8080"
```

Dwaar enables HTTPS automatically and redirects HTTP → HTTPS with no extra labels. The `dwaar.enable=true` label is not required — any container with a `dwaar.domain` label is discovered automatically.

---

### TLS with certificate resolver

**Traefik**

```yaml
labels:
  - "traefik.http.routers.app.tls=true"
  - "traefik.http.routers.app.tls.certresolver=letsencrypt"
```

**Dwaar**

```yaml
labels:
  - "dwaar.domain=app.example.com"
  - "dwaar.port=8080"
```

No TLS labels are needed. Dwaar provisions a certificate from Let's Encrypt the first time it sees the domain. To disable automatic HTTPS for a specific container:

```yaml
labels:
  - "dwaar.domain=app.example.com"
  - "dwaar.port=8080"
  - "dwaar.tls=off"
```

---

### Load balancer across multiple containers

**Traefik**

```yaml
services:
  app1:
    image: myapp:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`app.example.com`)"
      - "traefik.http.services.app.loadbalancer.server.port=8080"
  app2:
    image: myapp:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`app.example.com`)"
      - "traefik.http.services.app.loadbalancer.server.port=8080"
```

**Dwaar**

```yaml
services:
  app1:
    image: myapp:latest
    labels:
      - "dwaar.domain=app.example.com"
      - "dwaar.port=8080"
  app2:
    image: myapp:latest
    labels:
      - "dwaar.domain=app.example.com"
      - "dwaar.port=8080"
```

Both containers share the same `dwaar.domain`. Dwaar adds them both to the upstream pool and distributes traffic round-robin. Unhealthy containers are removed from rotation automatically.

---

### Path prefix routing

**Traefik**

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.api.rule=Host(`example.com`) && PathPrefix(`/api`)"
  - "traefik.http.services.api.loadbalancer.server.port=3000"
```

**Dwaar labels** do not support per-path routing directly. Use a Dwaarfile block instead:

```
example.com {
    handle /api/* {
        reverse_proxy api-service:3000
    }
    handle {
        reverse_proxy web-service:8080
    }
}
```

Alternatively, expose the API on a subdomain and use two separate label sets:

```yaml
services:
  api:
    labels:
      - "dwaar.domain=api.example.com"
      - "dwaar.port=3000"
  web:
    labels:
      - "dwaar.domain=example.com"
      - "dwaar.port=8080"
```

---

### Rate limiting middleware

**Traefik**

```yaml
labels:
  - "traefik.http.middlewares.ratelimit.ratelimit.average=100"
  - "traefik.http.middlewares.ratelimit.ratelimit.burst=50"
  - "traefik.http.routers.app.middlewares=ratelimit"
```

**Dwaar**

```yaml
labels:
  - "dwaar.domain=app.example.com"
  - "dwaar.port=8080"
  - "dwaar.rate_limit=100/s"
```

Dwaar uses a sliding-window estimator. The `100/s` limit applies per IP address per domain. Requests over the limit receive `429 Too Many Requests` with a `Retry-After: 1` header.

---

### Basic auth middleware

**Traefik**

```yaml
labels:
  - "traefik.http.middlewares.auth.basicauth.users=alice:$$apr1$$..."
  - "traefik.http.routers.admin.middlewares=auth"
```

**Dwaar**

Docker labels do not support credential configuration for basic auth — credentials would be visible in `docker inspect` output and process lists. Use a Dwaarfile block instead:

```
admin.example.com {
    basic_auth "Admin Panel" {
        alice $2b$12$W9qnDhPDIYYMMsVN5LRVZ.MCFhJJ0lMjx5Uagb0RTMP1bJG2xjhzS
    }
    reverse_proxy admin-service:9000
}
```

Generate bcrypt hashes with `htpasswd -nbBC 12 alice 'yourpassword'`. See [Basic Auth](../security/basic-auth.md) for hash generation and security guidance.

---

### Strip prefix middleware

**Traefik**

```yaml
labels:
  - "traefik.http.middlewares.strip.stripprefix.prefixes=/api"
  - "traefik.http.routers.api.middlewares=strip"
```

**Dwaar** — use `handle_path` in a Dwaarfile block. It matches the prefix and strips it before the upstream sees the request:

```
example.com {
    # GET /api/users → upstream sees GET /users
    handle_path /api/* {
        reverse_proxy api-service:3000
    }
}
```

---

### Headers middleware

**Traefik**

```yaml
labels:
  - "traefik.http.middlewares.headers.headers.customresponseheaders.X-Custom=myvalue"
  - "traefik.http.routers.app.middlewares=headers"
```

**Dwaar**

```yaml
labels:
  - "dwaar.domain=app.example.com"
  - "dwaar.port=8080"
```

Then add custom headers in a Dwaarfile block:

```
app.example.com {
    reverse_proxy app-service:8080
    header {
        X-Custom "myvalue"
        Cache-Control "public, max-age=3600"
    }
}
```

Or use the label for a single header (if your Dwaar deployment supports extended labels):

```yaml
labels:
  - "dwaar.domain=app.example.com"
  - "dwaar.port=8080"
  - "dwaar.header.X-Custom=myvalue"
```

---

### Redirect middleware

**Traefik**

```yaml
labels:
  - "traefik.http.middlewares.redirect-to-https.redirectscheme.scheme=https"
  - "traefik.http.routers.app-http.middlewares=redirect-to-https"
```

**Dwaar** — HTTP → HTTPS redirect is automatic when `tls auto` is active (the default). No labels or directives required.

For custom path redirects, use the Dwaarfile:

```
example.com {
    redir /old-path /new-path 301
    redir /legacy/* /new/{http.request.uri.path.remainder} 308
    reverse_proxy app-service:8080
}
```

---

## Dwaarfile-Based Migration

If you are moving away from Docker label discovery entirely — for example, to manage config in version control or to proxy non-Docker upstreams — translate each Traefik router to a Dwaarfile site block.

**Traefik dynamic config (YAML)**

```yaml
http:
  routers:
    web:
      rule: "Host(`example.com`)"
      service: web-service
      tls:
        certResolver: letsencrypt
      middlewares:
        - rate-limit
        - security-headers

  services:
    web-service:
      loadBalancer:
        servers:
          - url: "http://localhost:3000"
          - url: "http://localhost:3001"

  middlewares:
    rate-limit:
      rateLimit:
        average: 200
    security-headers:
      headers:
        stsSeconds: 63072000
        stsIncludeSubdomains: true
```

**Dwaarfile equivalent**

```
example.com {
    reverse_proxy localhost:3000 localhost:3001

    rate_limit 200/s

    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
    }
}
```

Dwaar adds HSTS, `X-Content-Type-Options`, and `X-Frame-Options` by default as part of its automatic security headers. The `header` block shown above is only needed if you want to customise or override the defaults.

---

## TOML/YAML Static Config to Dwaarfile

Traefik separates static config (entrypoints, certificate resolvers, providers) from dynamic config (routers, services, middlewares). Dwaar merges all of this into a single Dwaarfile.

**Traefik static config (YAML)**

```yaml
entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

certificatesResolvers:
  letsencrypt:
    acme:
      email: ops@example.com
      storage: /acme.json
      httpChallenge:
        entryPoint: web

api:
  dashboard: true

providers:
  docker:
    exposedByDefault: false
```

**Dwaarfile equivalent**

```
{
    http_port  80
    https_port 443
    email      ops@example.com
}

example.com {
    reverse_proxy localhost:3000
}
```

The global options block replaces Traefik's static config. The `email` field is the only required option for automatic HTTPS. Dwaar stores its ACME account and certificates on the filesystem at `/etc/dwaar/certs` — no `acme.json` file is needed.

To change the certificate storage path, set `DWAAR_CERT_DIR` in the environment or pass `--cert-dir` on the command line.

---

## What You Can Remove

After migrating, the following Traefik-specific boilerplate is no longer needed:

| Traefik item | Why it is gone |
|---|---|
| `traefik.enable=true` label | All containers with `dwaar.domain` are discovered automatically |
| `entrypoints` labels | Dwaar listens on 80 and 443 by default; no per-router declaration |
| `tls.certresolver` labels | Certificate provisioning is always on; no resolver to name |
| Dashboard service and router config | Use `curl http://127.0.0.1:6190/routes` instead |
| `api.dashboard: true` in static config | Admin API is always available on loopback |
| `providers.docker.exposedByDefault: false` | Replace with not labelling containers you don't want proxied |
| Middleware chain declarations | Directives are inlined in each site block; no named chain wiring |
| `acme.json` file and its `600` permission fix | Dwaar manages certs in a directory, not a single JSON file |
| `traefik/traefik:latest` image pull | Replace with `ghcr.io/permanu/dwaar:latest` |

---

## Migration Steps

1. **Deploy Dwaar alongside Traefik.** Bind Dwaar to ports 80 and 443 on a test domain before cutting over production. Use `DWAAR_CONFIG` to point at a Dwaarfile that covers only the test domain.

2. **Translate one service at a time.** For each Traefik router, create the equivalent Dwaar labels or Dwaarfile block. Use `dwaar validate` to check the config before applying it.

   ```bash
   dwaar validate --config /etc/dwaar/Dwaarfile
   # Config valid.
   ```

3. **Verify TLS.** After Dwaar starts, check that it obtained a certificate for each domain:

   ```bash
   curl -s http://127.0.0.1:6190/routes | jq '.[] | {domain, tls}'
   ```

4. **Test each route.** Send a request through Dwaar and confirm the upstream receives it correctly. Check that redirects, path stripping, and headers are applied as expected.

5. **Cut over DNS.** Once all routes are validated, point DNS at the Dwaar host. If you were running Traefik on the same host, stop it first to free ports 80 and 443.

6. **Stop Traefik.** Remove Traefik's container and labels. Remove `acme.json` and any Traefik static config files.

7. **Remove Traefik labels from all services.** Clean up `traefik.*` labels from your Docker Compose files. Run `docker compose up -d` to apply.

---

## Related

- [Docker Label Discovery](../deployment/docker-labels.md) — full reference for `dwaar.*` labels
- [Dwaarfile Reference](../configuration/dwaarfile.md) — all Dwaarfile directives
- [Comparison with Other Proxies](../getting-started/comparison.md) — feature matrix including Traefik
- [Basic Auth](../security/basic-auth.md) — bcrypt hash generation and credential configuration
- [Rate Limiting](../security/rate-limiting.md) — sliding-window rate limit internals and per-path overrides
- [Handle & Route Blocks](../routing/handle.md) — path-prefix routing with `handle` and `handle_path`
