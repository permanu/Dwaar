---
title: "Migrating from Nginx"
---

# Migrating from Nginx

Nginx configuration is built around a C-style block language with hundreds of directives spread across modules. A Dwaarfile replaces all of that with a domain-centric format where each block contains only the options that matter for that site — no boilerplate, no inherited contexts to untangle.

This page maps every major nginx concept to its Dwaar equivalent and shows side-by-side config translations for the patterns you're most likely to migrate.

---

## Concept Mapping

| Nginx concept | Dwaar equivalent | Notes |
|---|---|---|
| `http { }` block | Implicit | Every site block lives at the top level |
| `server { }` block | `domain.com { }` | One block per domain |
| `location / { }` | `handle / { }` | First-match semantics, same as nginx's `location` |
| `location ~ regex { }` | `@name path_regexp pattern` + `handle @name { }` | Named matcher with regexp condition |
| `upstream { }` block | Inline `reverse_proxy backend1 backend2` | No separate upstream declaration |
| `proxy_pass` | `reverse_proxy` | Directive name only |
| `root` + `index` | `root * /path` + `file_server` | `index.html` is tried automatically |
| `try_files` | `try_files` | Identical semantics |
| `ssl_certificate` / `ssl_certificate_key` | `tls manual` + `tls_cert` / `tls_key` | Or omit entirely for automatic HTTPS |
| `add_header` | `header { Name "value" }` | Block form for multiple headers |
| `return 301` | `redir /from /to 301` | |
| `rewrite ^/old(.*)$ /new$1` | `rewrite /new{http.request.uri.path.remainder}` | |
| `gzip on` | `encode gzip` | Brotli and zstd also available |
| `fastcgi_pass` | `php_fastcgi` | All CGI params constructed automatically |
| `auth_basic` | `basic_auth` | bcrypt hashes only (not MD5/SHA1) |
| `allow` / `deny` | `ip_filter { allow ... deny ... default deny }` | |
| `limit_req` | `rate_limit 100/s` | Built in, no module required |
| `worker_processes` | Not needed | Dwaar manages its own thread pool |
| `events { worker_connections }` | Not needed | Managed internally |
| `error_log` | Structured JSON to stdout | Configure log destination via env or CLI |
| `access_log` | Built-in structured access log | Always on; 34+ fields per request |

---

## Config Translations

### Basic reverse proxy

**Before (nginx)**
```nginx
server {
    listen 80;
    server_name example.com;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

**After (Dwaar)**
```
example.com {
    reverse_proxy localhost:8080
}
```

Dwaar sets `Host`, `X-Real-IP`, and `X-Forwarded-For` automatically on every proxied request. The `listen` directive is replaced by the domain name. HTTPS is provisioned automatically.

---

### TLS

**Before (nginx)**
```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/example.com.crt;
    ssl_certificate_key /etc/ssl/example.com.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://localhost:3000;
    }
}

# HTTP → HTTPS redirect
server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}
```

**After (Dwaar) — automatic certificate**
```
example.com {
    reverse_proxy localhost:3000
}
```

Dwaar provisions a Let's Encrypt certificate automatically and redirects HTTP to HTTPS. No cipher list or protocol version configuration is required — Dwaar defaults to TLS 1.2/1.3 with a secure cipher suite.

**After (Dwaar) — manual certificate**
```
example.com {
    reverse_proxy localhost:3000
    tls manual
    tls_cert /etc/ssl/example.com.crt
    tls_key  /etc/ssl/example.com.key
}
```

---

### Location blocks

**Before (nginx)**
```nginx
server {
    listen 443 ssl;
    server_name example.com;

    location /api/ {
        proxy_pass http://localhost:8080/;
    }

    location /admin/ {
        proxy_pass http://localhost:9000/;
    }

    location / {
        root /var/www/html;
        try_files $uri $uri/ /index.html;
    }
}
```

**After (Dwaar)**
```
example.com {
    handle /api/* {
        reverse_proxy localhost:8080
    }

    handle /admin/* {
        reverse_proxy localhost:9000
    }

    handle {
        root * /var/www/html
        try_files {path} /index.html
        file_server
    }
}
```

`handle` uses first-match semantics identical to nginx's `location` blocks. The catch-all `handle { }` at the end is equivalent to `location / { }`.

---

### Upstream blocks

**Before (nginx)**
```nginx
upstream backend {
    server app1:8080;
    server app2:8080;
    server app3:8080;
    least_conn;
}

server {
    listen 443 ssl;
    server_name example.com;

    location / {
        proxy_pass http://backend;
    }
}
```

**After (Dwaar)**
```
example.com {
    reverse_proxy {
        to app1:8080 app2:8080 app3:8080
        lb_policy least_conn
    }
}
```

There is no separate upstream block. Declare backends inline in the `reverse_proxy` block. Available policies: `round_robin` (default), `least_conn`, `random`, `ip_hash`.

---

### Rate limiting

**Before (nginx)**
```nginx
http {
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;

    server {
        listen 443 ssl;
        server_name api.example.com;

        location / {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://localhost:3000;
        }
    }
}
```

**After (Dwaar)**
```
api.example.com {
    reverse_proxy localhost:3000
    rate_limit 100/s
}
```

No zone declaration, no shared memory configuration. Dwaar's rate limiter uses a Count-Min Sketch that fits in 32 KB of memory regardless of how many distinct IPs it tracks. Requests over the limit receive `429 Too Many Requests` with `Retry-After: 1`.

---

### Headers

**Before (nginx)**
```nginx
server {
    listen 443 ssl;
    server_name example.com;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header Cache-Control "public, max-age=3600";

    location / {
        proxy_pass http://localhost:3000;
    }
}
```

**After (Dwaar)**
```
example.com {
    reverse_proxy localhost:3000
    header {
        Cache-Control "public, max-age=3600"
    }
}
```

`Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` are added by Dwaar automatically on every response — you do not need to configure them. Use the `header` block only for custom or additional headers.

---

### Redirects

**Before (nginx)**
```nginx
server {
    listen 443 ssl;
    server_name example.com;

    # Permanent redirect
    location /old-path {
        return 301 /new-path;
    }

    # Temporary redirect to another domain
    location /docs {
        return 302 https://docs.example.com;
    }
}
```

**After (Dwaar)**
```
example.com {
    redir /old-path /new-path 301
    redir /docs https://docs.example.com 302
    reverse_proxy localhost:3000
}
```

`redir` replaces `return 301/302`. The default when no code is given is `308` (permanent, method-preserving) — always specify the code explicitly to match nginx's `301`/`302` behaviour.

---

### Static files

**Before (nginx)**
```nginx
server {
    listen 443 ssl;
    server_name static.example.com;

    root /var/www/html;
    index index.html index.htm;

    location / {
        try_files $uri $uri/ =404;
    }
}
```

**After (Dwaar)**
```
static.example.com {
    root * /var/www/html
    try_files {path} {path}/ =404
    file_server
}
```

`root` and `try_files` work the same way. `index.html` is tried automatically for directory requests — no `index` directive needed. Dotfiles (`.env`, `.git/`, `.htpasswd`) are blocked by default and cannot be served.

---

### Gzip

**Before (nginx)**
```nginx
http {
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript;
}
```

**After (Dwaar)**
```
example.com {
    reverse_proxy localhost:3000
    encode gzip zstd br
}
```

One directive replaces six. Compressible content types (HTML, CSS, JS, JSON, SVG, XML, WASM, plain text) are compressed automatically — no `gzip_types` list needed. Responses under 1 KB and already-compressed formats are skipped. Add `zstd` and `br` for Brotli and Zstandard alongside gzip.

---

### FastCGI / PHP

**Before (nginx)**
```nginx
server {
    listen 443 ssl;
    server_name example.com;

    root /var/www/html;

    location ~ \.php$ {
        fastcgi_pass   unix:/run/php/php8.2-fpm.sock;
        fastcgi_index  index.php;
        fastcgi_param  SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include        fastcgi_params;
    }

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
}
```

**After (Dwaar)**
```
example.com {
    root * /var/www/html
    php_fastcgi unix//run/php/php8.2-fpm.sock
}
```

`php_fastcgi` constructs all FastCGI parameters automatically (`SCRIPT_FILENAME`, `DOCUMENT_ROOT`, `REQUEST_METHOD`, `QUERY_STRING`, etc.) and implements the same `try_files` front-controller fallback that the nginx + `fastcgi_params` combo provides. The separate `location ~ \.php$` and `location /` blocks collapse into a single directive.

---

### Basic auth

**Before (nginx)**
```nginx
server {
    listen 443 ssl;
    server_name admin.example.com;

    location / {
        auth_basic           "Admin Panel";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass           http://localhost:9000;
    }
}
```

**After (Dwaar)**
```
admin.example.com {
    basic_auth "Admin Panel" {
        alice $2b$12$W9qnDhPDIYYMMsVN5LRVZ.MCFhJJ0lMjx5Uagb0RTMP1bJG2xjhzS
    }
    reverse_proxy localhost:9000
}
```

Credentials are declared inline in the Dwaarfile, not in a separate `.htpasswd` file. Dwaar accepts only bcrypt hashes (`$2b$` or `$2y$`). MD5 and SHA1 hashes from nginx's `.htpasswd` format are not accepted — regenerate with `htpasswd -nbBC 12 username password`.

---

### IP restrictions

**Before (nginx)**
```nginx
server {
    listen 443 ssl;
    server_name internal.example.com;

    location / {
        allow 10.0.0.0/8;
        allow 192.168.0.0/16;
        deny  all;
        proxy_pass http://localhost:8080;
    }
}
```

**After (Dwaar)**
```
internal.example.com {
    ip_filter {
        allow 10.0.0.0/8
        allow 192.168.0.0/16
        default deny
    }
    reverse_proxy localhost:8080
}
```

`ip_filter` with `default deny` is equivalent to nginx's `deny all` at the end. Longest-prefix-match semantics apply: a more specific `deny` overrides a broader `allow`. IPv4 and IPv6 rules can be mixed freely.

---

## What You Can Remove

Nginx requires substantial boilerplate even for a minimal proxy. The following nginx directives have no Dwaarfile equivalent because Dwaar handles the concern automatically.

| Nginx directive | Why you can remove it |
|---|---|
| `worker_processes auto` | Dwaar sets its own thread count based on CPU cores |
| `worker_rlimit_nofile` | Not required; Dwaar manages file descriptors internally |
| `events { worker_connections 1024; }` | Connection limits are managed per-upstream with `max_conns` |
| `events { use epoll; }` | Dwaar uses the OS's best async I/O automatically (epoll, kqueue) |
| `http { ... }` wrapper block | Every Dwaarfile is implicitly an HTTP server config |
| `sendfile on` | Not applicable; Dwaar is not an nginx module |
| `tcp_nopush on` | Not applicable |
| `tcp_nodelay on` | Not applicable |
| `keepalive_timeout 65` | Default keep-alive idle is 60 s; override with `servers { timeouts { idle 65s } }` |
| `gzip_vary on` | Dwaar always sends `Vary: Accept-Encoding` when compressing |
| `gzip_proxied any` | Dwaar compresses all proxied responses of compressible types |
| `include mime.types` | MIME types are built in |
| `default_type application/octet-stream` | Built in |
| `proxy_set_header Host $host` | Set automatically |
| `proxy_set_header X-Real-IP $remote_addr` | Set automatically |
| `proxy_set_header X-Forwarded-For ...` | Set automatically |
| `proxy_http_version 1.1` | Dwaar uses HTTP/1.1 keep-alive to upstreams by default |
| `proxy_set_header Connection ""` | Set correctly by default |
| `ssl_protocols TLSv1.2 TLSv1.3` | Dwaar enforces TLS 1.2+ by default |
| `ssl_ciphers HIGH:!aNULL:!MD5` | Dwaar uses a modern cipher suite by default |
| `ssl_prefer_server_ciphers on` | Handled automatically |
| `ssl_session_cache shared:SSL:10m` | Session caching is managed internally |
| `ssl_session_timeout 10m` | Managed internally |

---

## Migration Steps

1. Identify each `server { }` block in your nginx config. Each becomes one domain block in a Dwaarfile.

2. Create a `Dwaarfile` and add a global block with your ACME email if you want automatic HTTPS:
   ```
   {
       email ops@example.com
   }
   ```

3. For each nginx `server { }` block:
   - Use the `server_name` value as the Dwaarfile domain.
   - Replace `proxy_pass http://upstream` with `reverse_proxy upstream`.
   - Replace `location /path { }` with `handle /path/* { }`.
   - Remove all `proxy_set_header` lines — Dwaar sets these automatically.

4. Translate `upstream { }` blocks to `reverse_proxy { to ... lb_policy ... }` blocks.

5. Replace `ssl_certificate` / `ssl_certificate_key` with `tls manual` + `tls_cert` / `tls_key`, or remove them entirely if you want Dwaar to provision certificates automatically.

6. Replace `limit_req_zone` + `limit_req` with `rate_limit <n>/s`.

7. Replace `allow` / `deny` directives with an `ip_filter { }` block.

8. Regenerate `.htpasswd` credentials as bcrypt hashes for `basic_auth`.

9. Validate the config:
   ```bash
   dwaar validate
   ```

10. Run Dwaar and confirm requests are served correctly:
    ```bash
    dwaar run
    curl -I https://yourdomain.com
    ```

---

## Related

- [Dwaarfile Reference](../configuration/dwaarfile.md) — complete directive reference
- [Comparison with Other Proxies](../getting-started/comparison.md) — feature matrix
- [Automatic HTTPS](../tls/automatic-https.md) — how ACME provisioning works
- [Reverse Proxy](../routing/reverse-proxy.md) — load balancing, health checks, upstream TLS
- [IP Filtering](../security/ip-filtering.md) — CIDR-based allow/deny
