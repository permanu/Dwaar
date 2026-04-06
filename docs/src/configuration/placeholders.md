# Placeholders & Variables

Dwaarfile supports dynamic values through three mechanisms: environment variable interpolation at parse time, named variables set with `vars`, and request-time variable mapping with `map`. Placeholders use the `{name}` syntax throughout.

## Environment Variables

Use `{env.VAR_NAME}` anywhere a value is expected in your Dwaarfile. Dwaar expands these at startup — before any request is processed. If the variable is unset at startup, Dwaar exits with a configuration error rather than silently using an empty value.

```
{
    email {env.ACME_EMAIL}
}

api.example.com {
    reverse_proxy {env.UPSTREAM_HOST}:{env.UPSTREAM_PORT}
    tls auto
}
```

Environment variable placeholders work in:
- Global options values (email, ports)
- Upstream addresses in `reverse_proxy`
- Header values in `header` and `request_header`
- Response bodies in `respond`
- Any directive value that accepts a string

## vars Directive

`vars` assigns a named variable within a site block. Other directives in the same block reference it with `{vars.name}`.

```
example.com {
    vars upstream_host 10.0.1.20:8080

    reverse_proxy {vars.upstream_host}
    header X-Backend "{vars.upstream_host}"
}
```

**Syntax:**

```
vars <name> <value>
```

- `name` — the variable name, referenced later as `{vars.name}`
- `value` — a string literal; may itself contain `{env.VAR}` interpolation

`vars` is evaluated at compile time. Use `map` when you need the value to change per-request.

## map Directive

`map` evaluates a source expression per-request, matches it against a list of patterns, and sets a destination variable. It is how you implement conditional variable assignment without scripting.

```
example.com {
    map {query.mode} {vars.cache_ttl} {
        fast    30
        slow    3600
        default 300
    }

    header Cache-Control "max-age={vars.cache_ttl}"
    reverse_proxy localhost:8080
}
```

**Syntax:**

```
map <source> <dest_var> {
    <pattern> <value>
    ...
    default   <value>
}
```

| Field | Description |
|-------|-------------|
| `source` | Template expression evaluated per-request, e.g. `{host}`, `{query.mode}`, `{http.request.header.X-Env}` |
| `dest_var` | Variable name set in the request context; reference it as `{vars.dest_var}` in other directives |
| `pattern` | Exact string match (case-insensitive), `~regex` for regex match, or `default` as fallback |
| `value` | Value to assign; may contain placeholders |

Patterns are tested in source order. The first match wins. If no pattern matches and no `default` entry exists, `dest_var` is set to an empty string.

**Regex patterns** use the `~` prefix:

```
map {path} {vars.section} {
    ~/blog/.*    blog
    ~/api/.*     api
    default      root
}
```

## log_append

`log_append` adds custom fields to structured log entries for the site. Field values are templates evaluated per-request, so you can inject request-scoped data into every log line.

**Inline form** (one field):

```
example.com {
    log_append trace_id "{http.request.header.X-Trace-Id}"
    reverse_proxy localhost:8080
}
```

**Block form** (multiple fields):

```
example.com {
    log_append {
        environment production
        region      {env.REGION}
        path        {path}
    }
    reverse_proxy localhost:8080
}
```

The field names appear as top-level keys in the JSON log output alongside the standard request fields (`host`, `method`, `status`, etc.).

## Template Placeholders

These placeholders are available in directive values that are evaluated per-request, including `map` source and value expressions, `log_append` values, `rewrite` targets, `respond` bodies, and header values.

| Placeholder | Description |
|-------------|-------------|
| `{host}` | Request `Host` header value |
| `{path}` | Request URI path (e.g. `/api/users`) |
| `{query}` | Full query string, without the leading `?` |
| `{query.KEY}` | Value of the named query parameter `KEY` |
| `{method}` | HTTP method (e.g. `GET`, `POST`) |
| `{scheme}` | `http` or `https` |
| `{remote_ip}` | Peer IP address as seen by the socket |
| `{client_ip}` | Client IP, honouring `X-Forwarded-For` |
| `{uri}` | Full request URI including path and query |
| `{http.request.header.NAME}` | Value of request header `NAME` |
| `{vars.NAME}` | Variable set by `vars` or `map` |
| `{env.NAME}` | Environment variable `NAME` (expanded at parse time) |

## Complete Example

```
{
    email {env.ACME_EMAIL}
}

app.example.com {
    # Static variable — set at compile time
    vars region {env.DEPLOY_REGION}

    # Request-time mapping — different TTL per API tier
    map {http.request.header.X-Api-Tier} {vars.ttl} {
        free       60
        pro        300
        enterprise 3600
        default    60
    }

    # Inject enrichment headers before proxying
    request_header X-Region "{vars.region}"
    request_header X-Cache-Ttl "{vars.ttl}"

    # Append custom fields to every access log entry
    log_append {
        region  {vars.region}
        api_tier {http.request.header.X-Api-Tier}
    }

    reverse_proxy {env.APP_UPSTREAM}
    tls auto
}
```

## Related

- [Dwaarfile Reference](dwaarfile.md) — full syntax and directive list
- [Named Matchers](named-matchers.md) — `@name` matcher definitions that can reference placeholders
- [Logging](../observability/logging.md) — structured log format and output configuration
