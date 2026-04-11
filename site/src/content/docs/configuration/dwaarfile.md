---
title: "Dwaarfile Reference"
---

# Dwaarfile Reference

The Dwaarfile is Dwaar's configuration format. It is designed to be readable, minimal, and production-ready with zero boilerplate.

## Location

Dwaar looks for configuration in this order:

1. `--config` CLI flag: `dwaar --config /path/to/Dwaarfile`
2. `./Dwaarfile` in the current directory
3. `/etc/dwaar/Dwaarfile`

## Syntax

A Dwaarfile consists of **domain blocks**. Each block configures one domain:

```
domain.com {
    directive value
    directive value
}
```

**Rules:**
- One domain per block
- Directives are one per line
- Comments start with `#`
- No semicolons, no quotes around simple values
- Indentation is convention (2 or 4 spaces), not required

## Directive Index

The table below lists every directive Dwaar recognises. Follow the link in the **Reference** column for full syntax, options, and examples.

| Directive | Description | Reference |
|-----------|-------------|-----------|
| `reverse_proxy` | Forward requests to one or more upstream backends | [Reverse Proxy](../routing/reverse-proxy.md) |
| `file_server` | Serve static files from disk | [File Server](../routing/file-server.md) |
| `php_fastcgi` | Forward requests to a PHP-FPM socket or address | [FastCGI](../routing/fastcgi.md) |
| `redir` | Issue an HTTP redirect to a new URL | [Redirects & Rewrites](../routing/redirects-rewrites.md) |
| `rewrite` | Rewrite the request URI internally before routing | [Redirects & Rewrites](../routing/redirects-rewrites.md) |
| `uri` | Strip a path prefix, append a suffix, or replace path segments | [Redirects & Rewrites](../routing/redirects-rewrites.md) |
| `handle` | Group directives that apply to a specific path prefix | [Handle & Route](../routing/handle.md) |
| `handle_path` | Like `handle`, but strips the matched prefix from the request path | [Handle & Route](../routing/handle.md) |
| `route` | Evaluate a group of directives in strict order | [Handle & Route](../routing/handle.md) |
| `respond` | Write a static response body and status code | [Respond & Errors](../routing/respond-errors.md) |
| `error` | Synthesise an error with a given status code | [Respond & Errors](../routing/respond-errors.md) |
| `abort` | Close the connection immediately with no response | [Respond & Errors](../routing/respond-errors.md) |
| `handle_errors` | Define how Dwaar handles error responses | [Respond & Errors](../routing/respond-errors.md) |
| `tls` | Control TLS mode: `auto`, `off`, or `manual` with explicit cert paths | [Automatic HTTPS](../tls/automatic-https.md) |
| `encode` | Compress responses using Brotli or Gzip | [Compression](../performance/compression.md) |
| `cache` | Cache upstream responses at the edge | [Caching](../performance/caching.md) |
| `rate_limit` | Enforce per-IP request rate limits; returns `429` on breach | [Rate Limiting](../security/rate-limiting.md) |
| `ip_filter` | Allow or deny requests by IP address or CIDR range | [IP Filtering](../security/ip-filtering.md) |
| `basic_auth` | Protect routes with HTTP Basic authentication | [Basic Auth](../security/basic-auth.md) |
| `forward_auth` | Delegate authentication to an external service | [Forward Auth](../security/forward-auth.md) |
| `header` | Set or delete response headers | inline |
| `request_header` | Set or delete request headers before proxying | inline |
| `log` | Configure per-domain access logging | [Logging](../observability/logging.md) |
| `root` | Set the filesystem root used by `file_server` and `try_files` | [File Server](../routing/file-server.md) |
| `try_files` | Attempt a list of paths in order before falling through | [File Server](../routing/file-server.md) |
| `bind` | Bind the server socket to a specific address or interface | inline |
| `request_body` | Set a maximum allowed request body size | inline |
| `wasm_plugin` | Load a WebAssembly plugin for custom request/response logic | [WASM Plugins](../plugins/wasm-plugins.md) |
| `vars` | Define named variables available as placeholders | [Placeholders](../configuration/placeholders.md) |
| `map` | Map an input value to an output variable via a lookup table | [Placeholders](../configuration/placeholders.md) |
| `@name` | Declare a named matcher for reuse across directives | [Named Matchers](../configuration/named-matchers.md) |
| `metrics` | Expose a Prometheus `/metrics` endpoint | [Prometheus](../observability/prometheus.md) |
| `skip_log` | Suppress access log entries for matched requests | [Logging](../observability/logging.md) |
| `import` | Include a snippet, file, or glob pattern at the point of the directive | [Imports & Snippets](#imports--snippets) |

Directives marked **inline** are simple enough to be fully described inline in examples below rather than warranting a dedicated page.

### Inline directive reference

**`header`** — Set or delete response headers:

```
example.com {
    reverse_proxy localhost:8080
    header X-Frame-Options "DENY"
    header -Server     # delete the Server header
}
```

**`request_header`** — Set or delete request headers before the request is forwarded:

```
example.com {
    reverse_proxy localhost:8080
    request_header X-Real-IP {remote_host}
    request_header -Cookie    # strip cookies before proxying
}
```

**`bind`** — Bind to a specific address instead of all interfaces:

```
internal.example.com {
    bind 10.0.0.1
    reverse_proxy localhost:9000
}
```

**`request_body`** — Reject requests whose body exceeds a size limit:

```
upload.example.com {
    reverse_proxy localhost:8080
    request_body 10MB
}
```

## Defaults

The following are active for every domain with no configuration required:

| Feature | Default | Override |
|---------|---------|----------|
| TLS | `auto` (Let's Encrypt) | `tls off` or `tls manual` |
| HTTP → HTTPS redirect | On | Disabled when `tls off` |
| Compression | On (Brotli/Gzip) | `encode off` |
| Security headers | On (HSTS, X-Content-Type-Options, etc.) | Not yet configurable |
| HTTP/2 | On | Not yet configurable |
| Access logging | On (JSON to stdout) | `log` directive or `skip_log` |
| X-Request-Id | On (UUID v7) | Not yet configurable |
| Proxy headers | On (X-Real-IP, X-Forwarded-For) | Not yet configurable |

## Imports & Snippets

The `import` directive runs as a text preprocessor before the parser sees the Dwaarfile. It has three forms:

```
import <snippet-name>           # named snippet defined elsewhere in the file
import <path>                   # single file relative to the Dwaarfile's directory
import <glob-pattern>           # every file matching a glob (`*`, `?`, `[...]`)
```

All three forms support positional arguments (`{args[0]}`, `{args[1]}`, `{args[:]}`) for parameterized reuse. Recursion is bounded at 10 levels of nesting. Circular imports are detected by canonical path and rejected at parse time.

### File imports

Single-file imports are resolved relative to the directory containing the Dwaarfile:

```
# Dwaarfile
import common/headers.conf

example.com {
    reverse_proxy localhost:8080
}
```

```
# common/headers.conf
header -Server
header X-Frame-Options DENY
```

The parser reads `common/headers.conf` at the point of the directive and splices the contents into the source before tokenization. Errors in the imported file surface with the real file name in their location.

### Glob imports

Glob imports enumerate every file matching a shell-style pattern. Matches are sorted lexicographically for deterministic load order across reloads, regardless of filesystem iteration order:

```
# Dwaarfile — one line does everything
import apps/*.dwaar
```

```
# apps/api.dwaar
api.example.com {
    reverse_proxy localhost:3001
    rate_limit 200/s
}
```

```
# apps/www.dwaar
www.example.com {
    reverse_proxy localhost:3002
}
```

On startup, Dwaar expands `apps/*.dwaar` to `apps/api.dwaar` then `apps/www.dwaar`, then runs the parser on the combined text. Adding `apps/admin.dwaar` and issuing `dwaar reload` picks up the new site — no edit to the top-level Dwaarfile is required.

Glob patterns support the standard wildcards:

| Token | Meaning |
|---|---|
| `*` | Match any number of characters (excluding `/`) |
| `?` | Match exactly one character |
| `[abc]` | Match any character in the set |

### Deploy-agent workflow

The glob form is the primary mechanism for zero-mutation deploy-agent workflows. An external agent (Permanu, a CI job, a shell script) writes one `.dwaar` file per application into a managed directory and then calls `dwaar reload`. The top-level Dwaarfile is owned by the operator and never touched by automation:

```
# Operator-owned top-level Dwaarfile
{
    email ops@example.com
}

# Shared snippets
import common/defaults.conf

# Per-app configs dropped in by the deploy agent
import apps/*.dwaar
```

The agent's responsibilities shrink to file writes in `apps/` plus one HTTP call to the admin API. Rollback is `rm apps/<app>.dwaar && dwaar reload`. Concurrent agents can write independent files without coordination.

### Empty matches

A glob pattern that matches zero files is **not an error**. The `import` directive expands to nothing and the rest of the Dwaarfile proceeds normally. This lets you ship a Dwaarfile with `import apps/*.dwaar` before any agent has written a file — the proxy starts clean and picks up apps as they land:

```
# Dropped into an empty tree — still loads.
import apps/*.dwaar
```

A `tracing::debug!` event is emitted when a pattern matches zero files so operators can spot typos without failing startup.

### Security & error handling

Every resolved match is canonicalized and verified to stay inside the Dwaarfile's base directory. A symlink pointing outside the tree causes the **entire import to fail** with `PathTraversal` — no silent skip. The string `..` in a pattern is rejected before any filesystem access.

| Condition | Result |
|---|---|
| Pattern matches one or more files, all inside base dir | Files are imported in lexicographic order. |
| Pattern matches zero files | Empty expansion. Not an error. |
| Pattern contains `..` | `PathTraversal` error. |
| A matched symlink resolves outside the base directory | `PathTraversal` error — the whole import aborts. |
| Pattern is malformed (e.g. unclosed `[`) | `InvalidGlob` error with the pattern text and parser message. |
| A single matched file cannot be read | `IoError` with the canonical path. |
| An imported file imports a file already in the current chain | `CircularImport` error. |
| Recursion exceeds 10 levels | `DepthLimitExceeded` error. |

Non-file matches (directories that happen to satisfy a broad pattern like `apps/*`) are skipped automatically.

### Snippets

Named snippets defined at the top level of a Dwaarfile can be imported the same way. Snippet definitions use the `(name) { ... }` form and are extracted before the parser runs:

```
(common) {
    encode gzip
    header -Server
}

example.com {
    import common
    reverse_proxy localhost:8080
}
```

Snippets accept positional arguments via `{args[0]}`, `{args[1]}`, or `{args[:]}` for all arguments joined by space:

```
(backend) {
    reverse_proxy {args[0]}
    header X-Backend {args[1]}
}

example.com {
    import backend localhost:9000 api
}
```

---

## Complete Example

```
# Production API — rate-limited, no analytics, metrics exposed
api.example.com {
    reverse_proxy localhost:3000
    rate_limit 200/s
    encode on
    metrics /internal/metrics
    log {
        output file /var/log/dwaar/api.log
    }
    skip_log /healthz
}

# Marketing site — static files with a fallback to the SPA index
www.example.com {
    root /var/www/marketing
    try_files {path} /index.html
    file_server
    encode on
}

# PHP application via FastCGI
app.example.com {
    root /var/www/app/public
    php_fastcgi unix//run/php/php8.3-fpm.sock
}

# Admin panel — forward auth, no public TLS
admin.internal {
    bind 10.0.0.0/8
    tls off
    forward_auth http://authd:9001/validate {
        copy_headers X-User X-Role
    }
    reverse_proxy localhost:5000
}

# Redirect bare domain to www
example.com {
    redir https://www.example.com{uri} permanent
}
```

## Validation

Check your Dwaarfile for errors without starting the server:

```bash
dwaar validate
# Config valid.

dwaar validate --config /path/to/Dwaarfile
# Config valid.
```

## Formatting

Format your Dwaarfile consistently:

```bash
dwaar fmt
# Formatted 3 domain blocks.

dwaar fmt --check
# Exit code 1 if unformatted (useful in CI).
```
