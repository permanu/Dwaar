---
title: "Troubleshooting & FAQ"
---

# Troubleshooting & FAQ

Use this page to diagnose the most common failure modes. Each section starts with the symptom, then the cause, then the fix.

---

## Configuration Issues

### Dwaarfile parse error on startup

```
error: unexpected token 'X' at line N
```

Run the formatter first — it surfaces token errors with precise line numbers:

```bash
dwaar fmt --check Dwaarfile
dwaar fmt Dwaarfile        # auto-fix whitespace and ordering
```

Common causes:

| Symptom | Cause | Fix |
|---------|-------|-----|
| `unexpected token '{'` after a directive | Missing space before block | Add a space: `reverse_proxy upstream:port {` |
| `unknown directive 'X'` | Directive not supported or misspelled | Check the [directive reference](../configuration/directives.md) |
| `expected address, got 'X'` | Site address missing port or scheme | Use `example.com`, `:8080`, or `https://example.com` |
| `duplicate site block` | Two blocks with the same address | Merge into one site block |
| Config file not found | Wrong path passed to `--config` | Pass the absolute path: `dwaar run --config /etc/dwaar/Dwaarfile` |

### Validation fails but fmt passes

`dwaar fmt` only checks syntax. Semantic errors (e.g. referencing an upstream that does not resolve) are caught at runtime. Run:

```bash
dwaar validate Dwaarfile
```

This performs full compilation including upstream DNS resolution and TLS config checks without starting the server.

### Hot reload does not take effect

Check the admin API reload endpoint returned `200 OK`:

```bash
curl -s -X POST http://localhost:2019/reload | jq .
```

If it returned an error, the new config failed validation. The previous config remains active. Fix the Dwaarfile and reload again.

---

## TLS / HTTPS

### Certificate not provisioning (ACME / Let's Encrypt)

**Port 80 must be reachable from the internet.** ACME HTTP-01 challenges require Let's Encrypt to reach `http://<your-domain>/.well-known/acme-challenge/<token>`.

Checklist:

1. Confirm port 80 is open in your firewall / security group.
2. Confirm DNS A/AAAA record points to this machine.
3. Confirm no other process holds port 80 (`ss -tlnp | grep :80`).
4. Check Dwaar logs for ACME error lines:
   ```bash
   journalctl -u dwaar --since "5 minutes ago" | grep -i acme
   ```

### ACME rate limit hit

Let's Encrypt enforces [rate limits](https://letsencrypt.org/docs/rate-limits/): 5 duplicate certificates per week, 50 certificates per registered domain per week.

- During development, point `acme_ca` at Let's Encrypt Staging:
  ```
  acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
  ```
- Staging issues untrusted certificates but has relaxed rate limits.
- Switch back to production once the setup is confirmed working.

### TLS handshake fails / "SSL_ERROR_RX_RECORD_TOO_LONG"

The client is connecting with plain HTTP to a TLS port. Confirm the site block uses HTTPS:

```
https://example.com {
    reverse_proxy backend:8080
}
```

Plain `example.com` without a scheme listens on both `:80` and `:443`. If you see this error, the client is sending HTTP to `:443`.

### Self-signed certificate warnings in browser

If you did not configure `tls` or `acme_ca` and Dwaar cannot reach Let's Encrypt, it falls back to a self-signed certificate. Add a valid `tls` directive pointing to your cert files, or ensure port 80 is reachable for ACME.

### Certificate not renewing

Dwaar renews certificates automatically when they have fewer than 30 days remaining. If renewal is failing:

1. Check that port 80 is still reachable (firewall rules change after reboots on some cloud providers).
2. Check logs for `renewal failed` messages.
3. Force a manual renewal via the admin API:
   ```bash
   curl -X POST http://localhost:2019/certs/renew
   ```

---

## Connection Issues

### 502 Bad Gateway

Dwaar reached the upstream but received no valid response. Common causes:

| Cause | Diagnosis | Fix |
|-------|-----------|-----|
| Upstream not running | `curl http://upstream:port/` from Dwaar host | Start the upstream service |
| Wrong upstream address | Check `reverse_proxy` directive | Correct host/port |
| Upstream TLS mismatch | Upstream expects TLS, Dwaar sends plain | Add `transport http { tls }` block |
| Upstream returned non-HTTP data | Check upstream logs | Fix upstream application error |

### Connection refused to upstream

```
error: connect ECONNREFUSED 127.0.0.1:8080
```

The upstream is not listening. Confirm:

```bash
ss -tlnp | grep 8080          # is something listening?
curl -v http://127.0.0.1:8080  # can Dwaar's host reach it?
```

If running in Docker, `127.0.0.1` inside the Dwaar container refers to the container itself, not the host. Use the service name (`backend:8080`) or `host.docker.internal:8080`.

### Request timeout / 504 Gateway Timeout

The upstream accepted the connection but did not respond within the deadline. Check:

1. Upstream is healthy (`curl http://upstream/health`).
2. Upstream is not under load — check its CPU and queue depth.
3. Adjust timeouts in the Dwaarfile if the upstream is legitimately slow:
   ```
   reverse_proxy backend:8080 {
       transport http {
           read_timeout 120s
           dial_timeout 10s
       }
   }
   ```

### WebSocket connections drop after 60 seconds

Pingora's default downstream keepalive is 60 seconds. WebSocket connections need a longer timeout. Set:

```
reverse_proxy ws-backend:8080 {
    transport http {
        keepalive_timeout 300s
    }
}
```

---

## Performance

### High memory usage

Expected memory footprint:

| Configuration | Approximate RSS |
|---------------|----------------|
| Single site, no analytics | ~5 MB |
| 100 sites, analytics on | ~25 MB |
| Per active connection | ~64 KB |
| Per cached response (depends on body size) | variable |

If RSS is significantly higher:

1. Check whether HTTP cache is enabled with no `max_size` bound. Set an explicit limit:
   ```
   cache {
       max_size 512mb
   }
   ```
2. Check for memory growth over time (leak) by watching RSS over hours. If it grows continuously, file a bug with a heap profile from `jemalloc`'s built-in stats:
   ```bash
   MALLOC_CONF=stats_print:true dwaar run --config Dwaarfile 2>&1 | grep -A 20 "jemalloc stats"
   ```

### High P99 latency

Steps to isolate:

1. **Disable plugins one at a time** — bot detection regex and rate limiting add CPU cost per request.
2. **Check upstream latency** — compare `upstream_latency_ms` in request logs against wall time.
3. **Enable Prometheus metrics** and check `dwaar_request_duration_seconds{quantile="0.99"}`.
4. **Profile** — see the [Profiling](../architecture/performance.md#profiling) section.

### Slow config reload

Config reload should complete in under 10 ms. If it is slow, the Dwaarfile is large and regex compilation is the bottleneck. Split large sites into separate files using `import`:

```
import /etc/dwaar/sites/*.dwaar
```

---

## Docker

### Permission denied on Docker socket

```
Error response from daemon: permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

Dwaar's Docker integration reads the socket to discover container labels. Fix:

```bash
# Option 1: add the dwaar user to the docker group
sudo usermod -aG docker dwaar

# Option 2: mount the socket with the correct permissions in compose
services:
  dwaar:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    user: "0"   # run as root only if absolutely necessary
```

### Container not being discovered

Dwaar discovers containers via labels. Confirm the container has the required labels:

```yaml
labels:
  dwaar.enable: "true"
  dwaar.host: "myapp.example.com"
  dwaar.port: "8080"
```

Then check that label discovery is enabled in the Dwaarfile:

```
docker {
    label_prefix dwaar
}
```

Restart Dwaar after adding labels — label discovery runs at startup and on reload, not continuously.

### Container IP changes after restart

Docker reassigns container IPs on restart. Dwaar resolves upstreams by DNS name, not IP. Use the Docker service name as the upstream address:

```
reverse_proxy myapp:8080
```

Docker's embedded DNS resolves service names to the current container IP.

---

## Kubernetes

### Ingress resource not translating to routes

Check that the IngressClass matches:

```yaml
spec:
  ingressClassName: dwaar
```

Confirm the `dwaar-ingress` controller has the correct RBAC permissions:

```bash
kubectl auth can-i list ingresses --as=system:serviceaccount:dwaar:dwaar-ingress -n your-namespace
```

If RBAC is missing, apply the ClusterRole from the Helm chart:

```bash
helm upgrade dwaar dwaar/dwaar-ingress --set rbac.create=true
```

### Leader election not progressing

Dwaar's Kubernetes controller uses a `Lease` resource for leader election. If no pod becomes leader:

```bash
kubectl get lease -n dwaar
kubectl describe lease dwaar-leader -n dwaar
```

Common causes:

| Symptom | Cause | Fix |
|---------|-------|-----|
| Lease not found | RBAC missing `leases` permission | Re-apply Helm chart with `rbac.create=true` |
| Leader not changing after pod death | Lease TTL not expired | Wait for TTL (default 15s) or delete the Lease manually |
| All pods in `CrashLoopBackOff` | API server unreachable | Check network policy and kube-apiserver health |

### Routes not updating after Ingress change

The reflector watches for Ingress events. If updates are not propagating:

```bash
kubectl logs -n dwaar -l app=dwaar-ingress --tail=50 | grep -i reconcil
```

Look for `reconcile error` lines. Common cause: the Ingress references a Service that does not exist. Create the Service or remove the backend reference.

---

## Admin API

### Connection refused to admin endpoint

By default, the admin API listens on a Unix domain socket at `/run/dwaar/admin.sock`. It does not bind a TCP port unless configured.

Connect via the socket:

```bash
curl --unix-socket /run/dwaar/admin.sock http://localhost/routes
```

Or configure a TCP listener in the Dwaarfile:

```
admin :2019 {
    origins localhost
}
```

### Authentication failed (401)

The admin API uses bearer token authentication. Pass the token from your Dwaarfile:

```bash
curl -H "Authorization: Bearer <your-token>" \
     --unix-socket /run/dwaar/admin.sock \
     http://localhost/routes
```

If you lost the token, it is in the `admin` block of your Dwaarfile. Rotate it with a reload.

### Admin API returns 403 on valid token

The request originated from an IP not in the `origins` allowlist. Either connect via the Unix socket (always allowed) or add your IP to the `origins` list:

```
admin :2019 {
    origins 127.0.0.1 10.0.0.0/8
}
```

---

## FAQ

**Is Dwaar production-ready?**

Dwaar has completed 27 build phases covering TLS automation, HTTP/3, WebSocket proxying, gRPC, mTLS, Kubernetes ingress, WASM plugins, an observability pipeline, and 900+ passing tests. The core proxy engine is built on Cloudflare's battle-tested Pingora framework. It is suitable for production use for teams comfortable running early-stage software and willing to track the changelog.

**How does it compare to nginx?**

| Feature | Dwaar | nginx |
|---------|-------|-------|
| Configuration language | Caddyfile-style (Dwaarfile) | nginx.conf |
| Automatic TLS | Yes (ACME, DNS-01) | With certbot / OpenResty |
| Hot reload | Yes, sub-10ms | Yes (graceful reload) |
| HTTP/3 / QUIC | Yes | nginx Plus or community patch |
| Built-in analytics | Yes (JS beacon, Web Vitals) | No |
| WASM plugins | Yes | No |
| Memory footprint | ~5 MB base | ~5–15 MB base |
| Allocator | jemalloc (no fragmentation) | libc malloc |
| Config language features | Matchers, templates, variables | Location blocks, if (limited) |

Dwaar is not a drop-in replacement for nginx — it uses a different configuration model. See the [migration guide](../migration/from-nginx.md) for a directive mapping.

**Can I use Dwaar with Cloudflare?**

Yes. Place Dwaar behind Cloudflare's CDN as the origin server. For end-to-end TLS, set Cloudflare's SSL mode to **Full (strict)** and point the origin to port 443. Dwaar handles ACME certificates independently of Cloudflare.

Dwaar also supports Cloudflare's DNS-01 ACME provider for wildcard certificates:

```
tls {
    dns cloudflare {env.CF_API_TOKEN}
}
```

**What is the license?**

Dwaar is licensed under the [Business Source License 1.1 (BSL-1.1)](https://mariadb.com/bsl11/). The change license is AGPL-3.0, effective ten years after each release. You can use Dwaar freely for any purpose except offering a competing commercial proxy, CDN, or analytics service. See `LICENSE` in the repository root.

**Does Dwaar support HTTP/2?**

Yes. HTTP/2 is enabled automatically for TLS sites. Downstream HTTP/2 multiplexing is handled by Pingora. Upstream connections use HTTP/1.1 by default; configure HTTP/2 upstream with:

```
reverse_proxy backend:8080 {
    transport http {
        versions h2
    }
}
```

**Can I run multiple workers?**

Yes. Pass `--workers N` to fork N worker processes before Pingora initializes. Each worker runs an independent tokio runtime. The supervisor process restarts crashed workers automatically.

```bash
dwaar run --config Dwaarfile --workers 4
```

---

## Getting Help

- **GitHub Issues** — [github.com/permanu/dwaar/issues](https://github.com/permanu/dwaar/issues). Search before opening a new issue. Include your Dwaar version (`dwaar --version`), OS, and a minimal reproducible Dwaarfile.
- **Discussions** — Use GitHub Discussions for questions that are not bugs.
- **Security vulnerabilities** — Do not open a public issue. Email the address in `SECURITY.md`.

When reporting a bug, attach:
1. The output of `dwaar --version`
2. Your Dwaarfile (redact secrets)
3. The relevant log lines (`journalctl -u dwaar --since "10 minutes ago"`)
4. Steps to reproduce
