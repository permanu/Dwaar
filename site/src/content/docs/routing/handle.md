---
title: "Handle & Route Blocks"
---

# Handle & Route Blocks

`handle`, `handle_path`, and `route` are the three structural directives
that let you dispatch different requests to different sub-configurations
inside a single site block. They differ in two dimensions: **when they
stop evaluating** (first match vs. all matches) and **whether they modify
the path** before handing off to inner directives.

---

## handle

`handle` evaluates blocks top-to-bottom and stops at the first block whose
matcher passes. Directives inside the winning block run; all subsequent
`handle` blocks are skipped. The request path is **not** modified.

**Syntax**

```
handle [<matcher>] {
    <directives>
}
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `matcher` | no | Inline path pattern (e.g. `/api/*`) or named matcher (`@name`). Omit for a catch-all. |

**Examples**

```
example.com {
    # Match /api/* — only this block runs for API requests
    handle /api/* {
        reverse_proxy localhost:8080
    }

    # Match /admin/* — runs for admin requests that didn't match /api/*
    handle /admin/* {
        basicauth {
            admin $2a$14$...
        }
        reverse_proxy localhost:9000
    }

    # Catch-all — runs only when no earlier handle matched
    handle {
        file_server
    }
}
```

Because `handle` uses first-match semantics, order matters. Place the most
specific matchers first.

---

## handle_path

`handle_path` works exactly like `handle` — first-match, stops on a win —
but it also **strips the matched path prefix** from the URI before the
inner directives see it. This is equivalent to `handle` + `uri
strip_prefix` in a single directive.

**Syntax**

```
handle_path <prefix> {
    <directives>
}
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `prefix` | yes | Path prefix to match and strip (e.g. `/api/*`). The trailing `/*` is required to capture arbitrary sub-paths. |

**Examples**

```
example.com {
    # /api/users → upstream sees /users
    # /api/posts/1 → upstream sees /posts/1
    handle_path /api/* {
        reverse_proxy localhost:3000
    }

    # /static/img/logo.png → file server looks up /img/logo.png
    handle_path /static/* {
        root * /var/www/assets
        file_server
    }
}
```

> **When to use `handle_path` vs `uri strip_prefix`:** Use `handle_path`
> when you want first-match routing and prefix stripping together.
> Use `uri strip_prefix` inside an existing `handle` block when you only
> need the stripping step without opening a new routing scope.

---

## route

`route` differs from `handle` in one critical way: **every `route` block
whose matcher passes will execute**, in source order. There is no early
exit. Use `route` when multiple transformation steps must apply to the same
request (e.g. rewrite, then add a header, then proxy).

**Syntax**

```
route [<matcher>] {
    <directives>
}
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `matcher` | no | Inline path pattern or named matcher. Omit for match-all. |

**Examples**

```
example.com {
    # Step 1: rewrite legacy path (runs for /old/*)
    route /old/* {
        rewrite /new{http.request.uri.path.remainder}
    }

    # Step 2: add tracing header (runs for ALL requests — including rewritten ones)
    route {
        request_header X-Trace-Id "dwaar-{http.request.id}"
    }

    # Step 3: proxy (runs for ALL requests)
    route {
        reverse_proxy localhost:8080
    }
}
```

---

## Comparison

| Directive | Match semantics | Path stripping | Typical use case |
|--------------|-----------------|----------------|----------------------------------------------|
| `handle` | First match wins; remaining blocks skipped | No | Branching: serve API vs. static vs. fallback |
| `handle_path` | First match wins; remaining blocks skipped | Yes — strips matched prefix | Mounting a sub-app at a path prefix |
| `route` | All matching blocks run, in order | No | Ordered pipeline: rewrite → header → proxy |

---

## Nesting

`handle` blocks can be nested. The inner blocks follow the same first-match
rules and are evaluated only when the outer block's matcher passes.

```
example.com {
    handle /api/* {
        # Inner routing within /api
        handle /api/v1/* {
            reverse_proxy localhost:8081
        }
        handle /api/v2/* {
            reverse_proxy localhost:8082
        }
        # Catch-all within /api — unknown API version
        handle {
            respond "Unknown API version" 400
        }
    }

    handle {
        file_server
    }
}
```

The outer `handle /api/*` matches first; only then does Dwaar evaluate the
inner `handle` blocks. Requests not matching `/api/*` fall through to the
outer `file_server` block.

---

## Complete Example

```
example.com {

    # Named matcher for authenticated routes
    @auth {
        path /dashboard/* /settings/*
    }

    # ── Authenticated section ─────────────────────────────────────────────────
    handle @auth {
        forward_auth localhost:9091 {
            uri /auth/verify
            copy_headers X-User X-Roles
        }
        reverse_proxy localhost:8080
    }

    # ── API — prefix stripped before upstream sees the request ────────────────
    handle_path /api/* {
        reverse_proxy localhost:3000
    }

    # ── Ordered pipeline for static assets ───────────────────────────────────
    # Route 1: add cache headers
    route /assets/* {
        header Cache-Control "public, max-age=31536000, immutable"
    }
    # Route 2: strip /assets prefix and serve from disk
    route /assets/* {
        uri strip_prefix /assets
        root * /var/www/static
        file_server
    }

    # ── Fallback ──────────────────────────────────────────────────────────────
    handle {
        reverse_proxy localhost:8080
    }
}
```

---

## Related

- [Reverse Proxy](./reverse-proxy.md) — proxying inside handle blocks
- [Named Matchers](../configuration/named-matchers.md) — `@name` matcher definitions
- [Respond & Error Pages](./respond-errors.md) — returning errors from handle blocks
