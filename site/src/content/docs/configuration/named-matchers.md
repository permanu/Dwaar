---
title: "Named Matchers"
---

# Named Matchers

Named matchers let you define a reusable request-matching condition once and reference it by name anywhere in a site block. Instead of repeating the same `path` or `method` checks across multiple directives, declare the matcher at the top of the site block and reference it with `@name`.

## Quick Start

```
api.example.com {
    @api {
        path   /api/*
        method GET POST
    }

    reverse_proxy @api localhost:3000
    respond        "not found" 404
}
```

Requests that match both `path /api/*` AND `method GET POST` are forwarded to `localhost:3000`. All other requests receive a 404.

## Syntax

**Block form** — declare multiple conditions inside `{ }`:

```
@name {
    condition1 args...
    condition2 args...
}
```

**Inline form** — declare a single condition on one line:

```
@name condition args...
```

Both forms are equivalent when there is only one condition. Use block form as soon as you need two or more conditions.

Matcher names must start with `@`. The `@` is part of the name in the Dwaarfile; when referencing the matcher in a directive you include the `@` prefix:

```
handle @name { ... }
reverse_proxy @name upstream:port
```

## AND Logic

All conditions inside a single matcher block use AND logic. Every condition must match for the matcher to pass. There is no built-in OR at the condition level — create separate matchers and reference them in separate directives to achieve OR semantics.

```
# Both conditions must match: path starts with /admin AND method is GET or POST.
@admin-read {
    path   /admin/*
    method GET POST
}

# This only runs for GET/POST /admin/* requests.
handle @admin-read {
    reverse_proxy localhost:8080
}
```

To match either of two paths, use two matchers or use `path` with multiple patterns (which are themselves OR'd within `path`):

```
# path accepts multiple patterns — any one of them matching is sufficient.
@public {
    path /health /status /ping
}
```

## Matcher Conditions

Every condition available inside a named matcher block is listed below.

| Condition | Syntax | Description | Example |
|---|---|---|---|
| `path` | `path pattern...` | Match URI path against one or more glob patterns. `*` matches within a single path segment; `**` matches across segments. Any pattern matching is sufficient. | `path /api/* /v2/*` |
| `path_regexp` | `path_regexp [name] pattern` | Match URI path against a regular expression. `name` is an optional capture-group label used with placeholders. | `path_regexp legacy \.php$` |
| `host` | `host hostname...` | Match the `Host` header against one or more values. Supports `*` wildcards, e.g. `*.example.com`. | `host api.example.com admin.example.com` |
| `method` | `method METHOD...` | Match the HTTP request method. Accepts one or more uppercase method names. | `method GET HEAD` |
| `header` | `header Name [value]` | Match a request header by name. If `value` is provided, the header value must equal it exactly. If omitted, only header presence is checked. | `header X-Internal-Request` or `header X-Role admin` |
| `header_regexp` | `header_regexp Name pattern` | Match a request header value against a regular expression. | `header_regexp Authorization ^Bearer\s` |
| `protocol` | `protocol http\|https` | Match by protocol. Use `https` to restrict a matcher to TLS connections only. | `protocol https` |
| `remote_ip` | `remote_ip cidr...` | Match the peer IP address (the directly-connected client) against one or more CIDR ranges. Does not inspect `X-Forwarded-For`. | `remote_ip 10.0.0.0/8 192.168.0.0/16` |
| `client_ip` | `client_ip cidr...` | Match the logical client IP against one or more CIDR ranges. Honours `X-Forwarded-For` when set by a trusted upstream. | `client_ip 203.0.113.0/24` |
| `query` | `query key=value...` | Match a query string parameter. Each argument is a `key=value` pair; all listed pairs must be present. | `query version=2 format=json` |
| `not` | `not { conditions }` | Negate a set of conditions. The `not` block matches when none of its inner conditions match. | `not { path /public/* }` |
| `expression` | `expression <cel>` | Match using a CEL expression. The expression is stored as-is and evaluated at request time. | `expression {http.request.host} == 'internal.example.com'` |
| `file` | `file { try_files paths... }` | Match if any of the listed file paths exist on disk. Useful for routing requests to a backend only when a static file is absent. | `file { try_files /public{path} /public{path}/index.html }` |
| Unknown keyword | `keyword args...` | Unrecognised condition keywords are stored verbatim and do not cause a parse error. Dwaar preserves forward-compatible Caddyfile syntax. | *(future extensions)* |

## Using Matchers

Reference a named matcher in any directive that accepts a matcher argument. Dwaar evaluates the matcher before executing the directive; if the matcher does not pass, the directive is skipped.

**`handle`** — execute a block of directives only for matching requests:

```
example.com {
    @api path /api/*

    handle @api {
        reverse_proxy localhost:3000
    }

    handle {
        file_server /var/www/html
    }
}
```

**`reverse_proxy`** — forward only matching requests to an upstream:

```
example.com {
    @authenticated header Authorization

    reverse_proxy @authenticated localhost:3000
    respond "unauthorized" 401
}
```

**`route`** — enforce directive evaluation order for matching requests:

```
example.com {
    @internal remote_ip 10.0.0.0/8

    route @internal {
        header +X-Internal true
        reverse_proxy localhost:9000
    }
}
```

## Negation

Use the `not` condition inside a matcher block to invert a set of conditions. The `not` block matches when none of its inner conditions match.

```
example.com {
    # Match everything that is NOT under /public and NOT a health check.
    @protected {
        not {
            path /public/* /health /favicon.ico
        }
    }

    handle @protected {
        forward_auth localhost:4181 /validate
        reverse_proxy localhost:3000
    }

    handle {
        file_server /var/www/public
    }
}
```

You can nest `not` alongside other conditions — remember all conditions in the outer block still use AND logic:

```
@authenticated-non-bot {
    header Authorization
    not {
        header User-Agent Googlebot
    }
}
```

This matches requests that have an `Authorization` header AND whose `User-Agent` is not `Googlebot`.

## Complete Example

```
api.example.com {
    # ── Named matchers ──────────────────────────────────────────────────────────

    # Internal health and metrics — only reachable from private networks.
    @internal {
        path   /health /metrics
        remote_ip 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
    }

    # Read-only public API — unauthenticated GET requests to /api/v2/*.
    @public-read {
        path     /api/v2/*
        method   GET HEAD
        protocol https
    }

    # Mutating requests — POST/PUT/PATCH/DELETE under /api/v2/*.
    @api-write {
        path   /api/v2/*
        method POST PUT PATCH DELETE
    }

    # Anything not explicitly handled above — catch-all for auth enforcement.
    @unauthenticated {
        not {
            header Authorization
        }
    }

    # ── Routing ─────────────────────────────────────────────────────────────────

    # Internal probes bypass auth entirely.
    handle @internal {
        reverse_proxy localhost:3000
    }

    # Public reads go straight through.
    handle @public-read {
        reverse_proxy localhost:3000
    }

    # Write requests require a valid auth token.
    route @api-write {
        forward_auth localhost:4181 /validate
        reverse_proxy localhost:3000
    }

    # Reject anything else that arrived without a credential.
    handle @unauthenticated {
        respond "unauthorized" 401
    }

    # Default: forward authenticated requests.
    handle {
        reverse_proxy localhost:3000
    }
}
```

## Related

- [Handle](../routing/handle.md) — directive execution blocks that accept matcher arguments
- [Reverse Proxy](../routing/reverse-proxy.md) — per-request upstream routing with matcher support
- [IP Filtering](../security/ip-filtering.md) — `remote_ip` and `client_ip` in depth, including trusted proxy configuration
