---
title: "Quick Start"
---

# Quick Start

Get a reverse proxy running in 60 seconds.

## 1. Start Your Application

You need an application running on a local port. For this example, we'll use a simple Python server:

```bash
echo "Hello from my app!" > index.html
python3 -m http.server 8080 &
```

## 2. Create a Dwaarfile

```bash
cat > Dwaarfile <<EOF
example.com {
    proxy localhost:8080
}
EOF
```

Replace `example.com` with your actual domain. The domain's DNS must point to this server's IP.

## 3. Run Dwaar

```bash
sudo dwaar
```

> `sudo` is needed to bind to ports 80 and 443. See [running without root](../guides/rootless.md) for alternatives.

That's it. Dwaar will:

1. Read the Dwaarfile
2. Request a TLS certificate from Let's Encrypt for `example.com`
3. Start listening on ports 80 (redirect to HTTPS) and 443 (HTTPS)
4. Proxy all traffic to `localhost:8080`

Visit `https://example.com` — you'll see your application served over HTTPS.

## Local Development (No Domain)

For local development without a real domain:

```bash
cat > Dwaarfile <<EOF
localhost {
    proxy localhost:8080
    tls off
}
EOF

dwaar
```

Visit `http://localhost` — traffic is proxied without TLS.

## Multiple Domains

```bash
cat > Dwaarfile <<EOF
api.example.com {
    proxy localhost:3000
    rate_limit 100/s
}

blog.example.com {
    proxy localhost:4000
    analytics on
}

admin.example.com {
    proxy localhost:5000
}
EOF
```

Each domain gets its own TLS certificate, routes to a different upstream, and can have independent features enabled.

## Enable Analytics

Add `analytics on` to any domain block:

```
example.com {
    proxy localhost:8080
    analytics on
}
```

Dwaar will inject a lightweight JavaScript snippet into HTML responses. Analytics data is available via the Admin API:

```bash
curl http://localhost:9876/analytics/example.com
```

## What's Next

- [Dwaarfile Reference](../configuration/dwaarfile.md) — all configuration options
- [Automatic HTTPS](../features/automatic-https.md) — how TLS works
- [First-Party Analytics](../features/analytics.md) — analytics in depth
- [Admin API](../api/admin.md) — runtime management
