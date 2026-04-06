# Redirects & Rewrites

Dwaar provides three URI-manipulation directives that run before any
upstream request is made: `redir` sends an HTTP redirect to the client,
`rewrite` silently changes the URI the upstream sees, and `uri` performs
partial transformations (strip a prefix, strip a suffix, or replace a
substring). All three are processed at compile time into the route table —
there is no per-request lookup overhead.

---

## Redirects

Use `redir` to send the client to a different URL. Dwaar defaults to
`308 Permanent Redirect` (like Caddy), which preserves the HTTP method
across the redirect. Specify a different code to override.

**Syntax**

```
redir <from> <to> [<code>]
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `from` | path pattern | yes | Path (or `*` wildcard) to match |
| `to` | URL or path | yes | Destination — absolute URL or root-relative path |
| `code` | integer | no | HTTP status code; defaults to `308` |

**Supported status codes**

| Code | Name | Method preserved? | When to use |
|------|-----------------------------|-------------------|--------------------------------------|
| 301 | Moved Permanently | No (becomes GET) | Legacy permanent moves |
| 302 | Found (Temporary) | No (becomes GET) | Short-term redirects |
| 307 | Temporary Redirect | Yes | Temporary; method must be preserved |
| 308 | Permanent Redirect (default)| Yes | Permanent; method must be preserved |

**Examples**

```
example.com {
    # Permanent redirect — old path to new path (default 308)
    redir /blog/* /articles/{http.request.uri.path.remainder}

    # Explicit 301 for a renamed page
    redir /about-us /about 301

    # Temporary (302) redirect to a maintenance page
    redir * https://status.example.com 302

    # Redirect HTTP to HTTPS (often handled automatically by auto_https,
    # but can be declared explicitly)
    redir http://example.com{uri} https://example.com{uri} 301
}
```

> **Note on wildcards:** `*` matches any path. Use
> `{http.request.uri.path.remainder}` to forward the suffix of a wildcard
> pattern to the destination.

---

## Rewrites

Use `rewrite` to change the URI before it reaches the upstream. The client
never sees the rewrite — it is entirely internal. The request method and
headers are unchanged.

**Syntax**

```
rewrite <to>
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `to` | path string | yes | New URI path sent to upstream |

**Examples**

```
api.example.com {
    # Rewrite all requests to a single entry point
    rewrite /index.php

    # Rewrite versioned API path to internal path
    handle /v2/* {
        rewrite /v1{http.request.uri.path.remainder}
        reverse_proxy localhost:8080
    }

    # Rewrite a specific legacy path
    handle /old-endpoint {
        rewrite /new-endpoint
        reverse_proxy localhost:8080
    }
}
```

`rewrite` is commonly paired with `handle` or `handle_path` blocks to
scope the rewrite to a specific path prefix. See
[Handle & Route Blocks](./handle.md) for details.

---

## URI Manipulation

Use `uri` for partial URI transformations without replacing the entire
path. Three operations are available.

**Syntax**

```
uri strip_prefix <prefix>
uri strip_suffix <suffix>
uri replace      <find> <replacement>
```

### `strip_prefix`

Removes a fixed string from the beginning of the request path.

```
handle /api/* {
    uri strip_prefix /api
    reverse_proxy localhost:3000
}
# GET /api/users → upstream sees GET /users
```

### `strip_suffix`

Removes a fixed string from the end of the request path.

```
example.com {
    uri strip_suffix .html
    # GET /about.html → upstream sees GET /about
}
```

### `replace`

Replaces all occurrences of `<find>` in the path with `<replacement>`.

```
example.com {
    uri replace /v1 /v2
    # GET /v1/resource → upstream sees GET /v2/resource
}
```

> **`handle_path` vs `uri strip_prefix`:** `handle_path /prefix/* { ... }`
> implicitly strips the prefix and is the preferred form when the prefix
> is static and you also want first-match semantics. Use `uri strip_prefix`
> when you need to strip without entering a new routing scope, or when the
> prefix is determined by a preceding `handle` match.

---

## Complete Example

```
example.com {

    # ── Redirects ─────────────────────────────────────────────────────────────

    # Permanently redirect legacy blog URLs (301 to preserve search ranking)
    redir /blog/posts/* /blog/{http.request.uri.path.remainder} 301

    # Redirect bare /docs to versioned docs
    redir /docs /docs/latest 302

    # ── Rewrites ──────────────────────────────────────────────────────────────

    # Rewrite clean SEO URLs to PHP entry point before proxying
    handle /products/* {
        rewrite /index.php
        reverse_proxy localhost:9000
    }

    # ── URI manipulation ──────────────────────────────────────────────────────

    # Strip /api prefix before forwarding to backend
    handle /api/* {
        uri strip_prefix /api
        reverse_proxy localhost:8080
    }

    # Strip .html extension for clean URLs served from file server
    handle /static/* {
        uri strip_suffix .html
        file_server
    }

    # Fallthrough: proxy everything else
    reverse_proxy localhost:8080
}
```

---

## Related

- [Handle & Route Blocks](./handle.md) — scope rewrites with `handle` and `handle_path`
- [Reverse Proxy](./reverse-proxy.md) — forwarding rewritten requests upstream
