---
title: "CLI Reference"
---

# CLI Reference

`dwaar` is the single binary for running, managing, and inspecting the proxy. All subcommands share the global flags below.

```
dwaar [OPTIONS] [COMMAND]
```

## Global Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--config <PATH>` | `-c` | `./Dwaarfile` | Path to Dwaarfile. Also set via `DWAAR_CONFIG`. |
| `--test` | `-t` | — | Validate configuration and exit. Does not start the server. |
| `--daemon` | `-d` | — | Run as a background daemon process. |
| `--upgrade` | `-u` | — | Perform a zero-downtime upgrade from a running instance using Pingora FD transfer. |
| `--docker-socket [PATH]` | — | `/var/run/docker.sock` | Enable Docker container auto-discovery. Pass a custom socket path or omit the value to use the default. |
| `--admin-socket [PATH]` | — | `/var/run/dwaar-admin.sock` | Enable Admin API on a Unix domain socket. Pass a custom socket path or omit the value to use the default. |
| `--bare` | — | — | Disable all optional subsystems: logging, plugins, analytics, GeoIP, metrics, and cache. Implies all `--no-*` flags. Use for maximum throughput on CDN edge nodes. |
| `--no-logging` | — | — | Disable request logging. The log writer is not started and the log channel is not allocated. |
| `--no-plugins` | — | — | Disable the plugin chain (bot detection, rate limiting, compression, security headers). |
| `--no-analytics` | — | — | Disable the analytics subsystem (beacon, aggregation, JS injection). |
| `--no-geoip` | — | — | Disable GeoIP lookups. Skips loading the MaxMind database. |
| `--no-metrics` | — | — | Disable Prometheus metrics collection and the `/metrics` endpoint. |
| `--no-cache` | — | — | Disable HTTP response caching globally. |
| `--workers <N\|auto>` | — | `auto` | Number of worker processes to spawn. `auto` uses all available CPU cores. Each worker binds independently via `SO_REUSEPORT`. Zero is rejected. |

When `--bare` is set, all individual `--no-*` flags are implied. Setting `--bare` together with any `--no-*` flag is redundant but not an error.

## Subcommands

### version

Print the Dwaar version and exit.

```
dwaar version
```

```
dwaar 0.9.0
```

### validate

Parse and validate a Dwaarfile without starting the server. Exits with code 0 on success, non-zero on error.

```
dwaar validate [--config <PATH>]
```

| Flag | Description |
|------|-------------|
| `-c, --config <PATH>` | Path to Dwaarfile. Overrides the global `--config` flag. |

```
$ dwaar validate --config /etc/dwaar/Dwaarfile
Dwaarfile OK (3 sites, 12 routes)
```

```
$ dwaar validate --config /etc/dwaar/Dwaarfile
error: line 14: unknown directive 'proxzy'
```

### fmt

Format a Dwaarfile to canonical style. Rewrites the file in-place unless `--check` is passed.

```
dwaar fmt [--config <PATH>] [--check]
```

| Flag | Description |
|------|-------------|
| `-c, --config <PATH>` | Path to Dwaarfile. Overrides the global `--config` flag. |
| `--check` | Check formatting without modifying the file. Exits 0 if already formatted, 1 if changes would be made. |

Use `--check` in CI to enforce consistent formatting:

```
$ dwaar fmt --check
Dwaarfile is not formatted. Run 'dwaar fmt' to fix.
$ echo $?
1
```

### routes

Display the active route table from a running Dwaar instance by querying the Admin API.

```
dwaar routes [--admin <ADDR>]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--admin <ADDR>` | `127.0.0.1:6190` | Admin API address to query. |

```
$ dwaar routes
DOMAIN                  UPSTREAM             TLS     PLUGINS
api.example.com         10.0.1.5:8080        auto    rate_limit, compress
static.example.com      10.0.1.6:8081        auto    compress
*.example.com           10.0.1.7:8082        auto    —
```

### certs

List managed TLS certificates with subject, expiry, and renewal status.

```
dwaar certs [--cert-dir <PATH>]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--cert-dir <PATH>` | `/etc/dwaar/certs` | Path to the certificate store directory. |

```
$ dwaar certs
DOMAIN                  EXPIRES                 STATUS
api.example.com         2026-07-15 12:00 UTC    valid
*.example.com           2026-07-20 08:30 UTC    valid
dev.internal            2026-05-01 00:00 UTC    renewing
```

### reload

Trigger a configuration reload on a running Dwaar instance without restarting. Dwaar re-parses the Dwaarfile and applies the new route table with zero dropped connections.

```
dwaar reload [--admin <ADDR>]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--admin <ADDR>` | `127.0.0.1:6190` | Admin API address to send the reload signal to. |

```
$ dwaar reload
Config reloaded. 3 sites active.
```

### upgrade

Perform a zero-downtime binary upgrade using Pingora's file descriptor transfer. Starts a new Dwaar process with `--upgrade`, waits for it to finish binding all listeners, then gracefully shuts down the old process. Active connections are not dropped.

```
dwaar upgrade [--binary <PATH>] [--pid-file <PATH>]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--binary <PATH>` | current executable | Path to the new Dwaar binary to exec. Defaults to the running binary's path. |
| `--pid-file <PATH>` | `/tmp/dwaar.pid` | PID file of the running Dwaar instance to upgrade. |

```
$ dwaar upgrade --binary /usr/local/bin/dwaar-new
Sending upgrade signal to PID 12345...
New process started. Waiting for handoff...
Upgrade complete. Old process exited cleanly.
```

## Examples

Start with a custom config and 4 workers:

```
dwaar --config /etc/dwaar/Dwaarfile --workers 4
```

Validate before deploying:

```
dwaar validate --config /etc/dwaar/Dwaarfile && systemctl reload dwaar
```

Run in minimal throughput mode with no optional subsystems:

```
dwaar --bare --config /etc/dwaar/Dwaarfile
```

Run as a daemon and write a PID file for upgrade support:

```
dwaar --daemon --config /etc/dwaar/Dwaarfile
```

Check formatting in CI:

```
dwaar fmt --check --config ./Dwaarfile
```

## Related

- [Dwaarfile Reference](dwaarfile.md) — full configuration syntax
- [Environment Variables](environment.md) — env vars that map to CLI flags
- [Admin API](../admin/api.md) — endpoints used by `routes` and `reload`
