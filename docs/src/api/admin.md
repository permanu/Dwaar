# Admin API

> This page will be documented when the Admin API is implemented (ISSUE-022).

The Admin API provides runtime management of Dwaar without restarts.

## Connection

By default, the Admin API listens on a Unix socket:

```bash
curl --unix-socket /var/run/dwaar.sock http://localhost/health
```

Or configure a TCP address via `DWAAR_ADMIN_ADDR=0.0.0.0:9876`.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Proxy health status |
| GET | `/routes` | List all active routes |
| POST | `/routes` | Add or update a route |
| DELETE | `/routes/{domain}` | Remove a route |
| GET | `/config` | Current running config |
| PUT | `/config` | Reload configuration |
| GET | `/certs` | List managed certificates |
| GET | `/metrics` | Prometheus metrics |
| GET | `/analytics/{domain}` | Analytics for a domain |
