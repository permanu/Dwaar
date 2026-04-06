---
title: "Docker"
---

# Docker

Run Dwaar in a container. Mount your Dwaarfile, TLS certificates, and logs as volumes. Expose ports 80, 443, and 443/udp for QUIC. The admin API binds to `127.0.0.1:6190` inside the container; expose it only if your tooling requires it.

## Quick Start

```bash
docker run -d \
  --name dwaar \
  --restart unless-stopped \
  -p 80:80 \
  -p 443:443 \
  -p 443:443/udp \
  -v /etc/dwaar/Dwaarfile:/etc/dwaar/Dwaarfile:ro \
  -v /etc/dwaar/certs:/etc/dwaar/certs:ro \
  -v /var/log/dwaar:/var/log/dwaar \
  -e DWAAR_CONFIG=/etc/dwaar/Dwaarfile \
  -e DWAAR_ADMIN_TOKEN=changeme \
  ghcr.io/permanu/dwaar:latest
```

## Docker Compose

```yaml
services:
  dwaar:
    image: ghcr.io/permanu/dwaar:latest
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - ./Dwaarfile:/etc/dwaar/Dwaarfile:ro
      - ./certs:/etc/dwaar/certs:ro
      - dwaar-logs:/var/log/dwaar
    environment:
      DWAAR_CONFIG: /etc/dwaar/Dwaarfile
      DWAAR_ADMIN_TOKEN: "${DWAAR_ADMIN_TOKEN}"
    healthcheck:
      test: ["CMD", "curl", "-fs", "http://127.0.0.1:6190/health"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 5s

  backend:
    image: nginx:alpine
    expose:
      - "80"

volumes:
  dwaar-logs:
```

Point your Dwaarfile at the backend service by container name:

```
example.com {
  reverse_proxy backend:80
}
```

## Volume Mounts

| Path in container | What to mount | Notes |
|---|---|---|
| `/etc/dwaar/Dwaarfile` | Dwaarfile configuration | Mount read-only (`:ro`) |
| `/etc/dwaar/certs` | TLS certificate directory | Mount read-only; contains `*.crt` and `*.key` files |
| `/var/log/dwaar` | Request log directory | Mount writable; logs rotate daily |
| `/etc/dwaar/geoip` | GeoIP database directory | Mount read-only; expects `GeoLite2-Country.mmdb` |

Dwaar also searches `/usr/share/GeoIP/GeoLite2-Country.mmdb` for the GeoIP database. If neither path has a database, country enrichment is silently disabled — no error, no startup failure.

## Port Mapping

| Host port | Container port | Protocol | Purpose |
|---|---|---|---|
| `80` | `80` | TCP | HTTP (redirected to HTTPS if TLS configured) |
| `443` | `443` | TCP | HTTPS / TLS |
| `443` | `443` | UDP | HTTP/3 over QUIC |
| `6190` | `6190` | TCP | Admin API (bind to loopback inside container) |

Do not expose port `6190` to the internet. If your orchestration tooling needs the admin API from outside the container, proxy it through a secured side channel or use the Unix socket instead (`--admin-socket`).

## Health Check

The admin API exposes a `/health` endpoint at `127.0.0.1:6190`. Use it for Docker health checks:

```dockerfile
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -fs http://127.0.0.1:6190/health || exit 1
```

In Docker Compose, the equivalent is shown in the example above. The `/health` endpoint returns `200 OK` with body `ok` when Dwaar is accepting requests. It does not require authentication.

Query active routes from the host while the container is running:

```bash
docker exec dwaar dwaar routes --admin 127.0.0.1:6190
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DWAAR_CONFIG` | `./Dwaarfile` | Path to the Dwaarfile inside the container |
| `DWAAR_ADMIN_TOKEN` | *(unset)* | Bearer token for authenticated admin API endpoints. When unset, all mutating admin requests are rejected. |
| `DWAAR_LOG_LEVEL` | `info` | Tracing log level: `error`, `warn`, `info`, `debug`, `trace` |
| `DWAAR_UAM_SECRET` | *(unset)* | HMAC secret for Under Attack Mode clearance cookies. Set by the supervisor process; do not set manually. |

Set `DWAAR_ADMIN_TOKEN` to a random 32-byte hex string in production:

```bash
openssl rand -hex 32
```

## Complete Example

Production compose with two backends, TLS, and GeoIP:

```yaml
services:
  dwaar:
    image: ghcr.io/permanu/dwaar:latest
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - ./Dwaarfile:/etc/dwaar/Dwaarfile:ro
      - ./certs:/etc/dwaar/certs:ro
      - ./geoip:/etc/dwaar/geoip:ro
      - dwaar-logs:/var/log/dwaar
    environment:
      DWAAR_CONFIG: /etc/dwaar/Dwaarfile
      DWAAR_ADMIN_TOKEN: "${DWAAR_ADMIN_TOKEN}"
      DWAAR_LOG_LEVEL: info
    healthcheck:
      test: ["CMD", "curl", "-fs", "http://127.0.0.1:6190/health"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 5s
    depends_on:
      - api
      - web

  api:
    image: myapp/api:latest
    expose:
      - "8080"
    restart: unless-stopped

  web:
    image: myapp/web:latest
    expose:
      - "3000"
    restart: unless-stopped

volumes:
  dwaar-logs:
```

Dwaarfile for the above:

```
api.example.com {
  tls /etc/dwaar/certs/api.example.com.crt /etc/dwaar/certs/api.example.com.key
  reverse_proxy api:8080
}

example.com {
  tls /etc/dwaar/certs/example.com.crt /etc/dwaar/certs/example.com.key
  reverse_proxy web:3000
}
```

## Related

- [Docker Label Discovery](docker-labels.md) — auto-discover backends from container labels without editing the Dwaarfile
- [Installation](../getting-started/installation.md) — binary install, build from source
- [systemd](systemd.md) — running Dwaar as a systemd service on bare metal
