---
title: "Environment Variables"
---

# Environment Variables

Dwaar reads a small set of environment variables at startup. Most have a direct CLI equivalent — the CLI flag takes precedence when both are set.

## Variables

| Variable | Default | Description | CLI equivalent |
|----------|---------|-------------|----------------|
| `DWAAR_CONFIG` | `./Dwaarfile` | Path to the Dwaarfile to load. | `-c / --config` |
| `DWAAR_LOG_LEVEL` | `info` | Tracing filter for internal Dwaar logs. Accepts `error`, `warn`, `info`, `debug`, `trace`, or a module-scoped filter like `dwaar_core=debug`. | — |
| `DWAAR_ADMIN_TOKEN` | — | Bearer token required on Admin API requests. When unset, the Admin API accepts unauthenticated requests from local processes. | — |
| `DWAAR_UAM_SECRET` | auto-generated | 32-byte hex secret used to sign Under Attack Mode (UAM) challenge cookies. Automatically generated and written to the environment by the supervisor process on startup; set explicitly when running multiple workers that must share the same secret. | — |

### Notes

**`DWAAR_LOG_LEVEL`** controls Dwaar's own structured logs (startup messages, config reload events, worker crashes) — not the HTTP access log. The access log is configured in Dwaarfile via the `log` directive.

**`DWAAR_ADMIN_TOKEN`** protects the Admin API (`/config/reload`, `/routes`, `/metrics`) against unauthorized access. In production, always set this. In development, you can omit it. The token is sent as a `Bearer` header:

```
curl -H "Authorization: Bearer $DWAAR_ADMIN_TOKEN" http://127.0.0.1:6190/routes
```

**`DWAAR_UAM_SECRET`** is inherited by worker processes from the supervisor via `fork()`. You only need to set it manually in container environments where you run workers directly without the supervisor, or when you need cookie signatures to remain valid across a rolling restart.

## Dwaarfile Interpolation

Use `{env.VAR_NAME}` in your Dwaarfile to inject environment variables into configuration values at parse time. Dwaar expands these before compiling the route table. If the variable is unset at startup, Dwaar exits with an error.

```
{
    email {env.ACME_EMAIL}
}

api.example.com {
    reverse_proxy {env.APP_HOST}:{env.APP_PORT}
    tls auto
}
```

This is distinct from `DWAAR_*` variables — those control Dwaar's own behaviour, while `{env.VAR}` lets you inject arbitrary environment values into site configuration.

See [Placeholders & Variables](placeholders.md) for the full list of placeholder syntax.

## Example

Production deployment via systemd with all variables set:

```ini
# /etc/systemd/system/dwaar.service
[Service]
Environment=DWAAR_CONFIG=/etc/dwaar/Dwaarfile
Environment=DWAAR_LOG_LEVEL=warn
Environment=DWAAR_ADMIN_TOKEN=your-secret-token-here
Environment=ACME_EMAIL=ops@example.com
Environment=APP_HOST=10.0.1.5
Environment=APP_PORT=8080
ExecStart=/usr/local/bin/dwaar --daemon --workers auto
```

Or with a `.env` file loaded before the process:

```bash
set -a
source /etc/dwaar/env
set +a
exec dwaar --config /etc/dwaar/Dwaarfile
```

## Related

- [CLI Reference](cli.md) — all flags and subcommands
- [Global Options](global-options.md) — server-wide settings in the Dwaarfile `{ }` block
- [Placeholders & Variables](placeholders.md) — `{env.VAR}` and per-request variable substitution
