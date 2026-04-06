---
title: "Systemd Service"
---

# Systemd Service

Run Dwaar as a managed systemd service on Linux. Systemd handles process supervision, automatic restarts, journal logging, and capability grants — so Dwaar can bind ports 80 and 443 without running as root.

## Quick Start

```bash
# Copy the unit file
sudo cp /usr/share/dwaar/dwaar.service /etc/systemd/system/dwaar.service

# Reload unit definitions
sudo systemctl daemon-reload

# Enable on boot and start now
sudo systemctl enable --now dwaar

# Confirm it is running
sudo systemctl status dwaar
```

## Unit File

```ini
[Unit]
Description=Dwaar reverse proxy
Documentation=https://dwaar.dev/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dwaar --config /etc/dwaar/Dwaarfile
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStartSec=30s
TimeoutStopSec=60s

# Run as a dedicated non-root user
User=dwaar
Group=dwaar

# Working directory and environment
WorkingDirectory=/etc/dwaar
EnvironmentFile=-/etc/dwaar/dwaar.env

# Grant permission to bind privileged ports without root
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# PID file (written by Pingora when --daemon is used)
PIDFile=/run/dwaar/dwaar.pid
RuntimeDirectory=dwaar
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
```

Save this to `/etc/systemd/system/dwaar.service` then run `systemctl daemon-reload`.

## Capabilities

Dwaar binds ports 80 and 443 by default. On Linux, binding ports below 1024 requires either root or `CAP_NET_BIND_SERVICE`.

| Setting | Value | Effect |
|---|---|---|
| `AmbientCapabilities` | `CAP_NET_BIND_SERVICE` | Grants the capability to the process at exec time |
| `CapabilityBoundingSet` | `CAP_NET_BIND_SERVICE` | Prevents any other capability from being added |
| `User` | `dwaar` | Process runs as a non-root user |

Create the service account before starting the unit:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin dwaar
```

If you bind only to ports above 1024 (e.g. behind a load balancer), remove both `AmbientCapabilities` and `CapabilityBoundingSet` from the unit file.

## Log Integration

Dwaar writes structured JSON logs to stdout. Systemd captures stdout automatically and routes it to the journal.

View live logs:

```bash
journalctl -u dwaar -f
```

View logs since last boot:

```bash
journalctl -u dwaar -b
```

Filter by priority (errors only):

```bash
journalctl -u dwaar -p err
```

Export as JSON for log shippers:

```bash
journalctl -u dwaar -o json | jq .
```

To persist logs across reboots, ensure `/var/log/journal` exists:

```bash
sudo mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
```

## Reload

Send `SIGHUP` to trigger a zero-disruption config reload. The config watcher re-reads the Dwaarfile, recompiles routes, and swaps in new upstream pools without restarting the process or dropping connections.

```bash
# Via systemctl (preferred)
sudo systemctl reload dwaar

# Via the CLI
dwaar reload

# Directly (sends SIGHUP)
sudo kill -HUP $(cat /run/dwaar/dwaar.pid)
```

The `ExecReload` line in the unit file maps `systemctl reload` to `SIGHUP`:

```ini
ExecReload=/bin/kill -HUP $MAINPID
```

## Hardening

Apply these systemd security directives to reduce the attack surface. Add them to the `[Service]` section.

```ini
[Service]
# Filesystem
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/dwaar /var/log/dwaar /run/dwaar /etc/dwaar/certs /etc/dwaar/acme

# Privilege escalation
NoNewPrivileges=true
SecureBits=keep-caps

# Kernel and system calls
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true

# Devices
PrivateDevices=true

# Temporary filesystem
PrivateTmp=true
```

| Directive | What it prevents |
|---|---|
| `ProtectSystem=strict` | Mounts `/`, `/usr`, `/boot` read-only |
| `ProtectHome=true` | Blocks access to all home directories |
| `NoNewPrivileges=true` | Prevents `setuid`/`setgid` escalation |
| `PrivateDevices=true` | Hides all device nodes except pseudo-devices |
| `PrivateTmp=true` | Isolates `/tmp` and `/var/tmp` |
| `MemoryDenyWriteExecute=true` | Blocks JIT and shellcode injection |
| `RestrictAddressFamilies` | Limits sockets to IPv4, IPv6, and Unix |

## Complete Example

Production-ready unit file with all hardening options applied:

```ini
[Unit]
Description=Dwaar reverse proxy
Documentation=https://dwaar.dev/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dwaar --config /etc/dwaar/Dwaarfile
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStartSec=30s
TimeoutStopSec=60s

User=dwaar
Group=dwaar
WorkingDirectory=/etc/dwaar
EnvironmentFile=-/etc/dwaar/dwaar.env

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

PIDFile=/run/dwaar/dwaar.pid
RuntimeDirectory=dwaar
RuntimeDirectoryMode=0750

# Hardening
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/dwaar /var/log/dwaar /run/dwaar /etc/dwaar/certs /etc/dwaar/acme
NoNewPrivileges=true
SecureBits=keep-caps
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
PrivateDevices=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Verify the security score with:

```bash
systemd-analyze security dwaar
```

A well-hardened unit scores below 4.0 (SAFE).

## Related

- [Docker](./docker.md) — running Dwaar in a container
- [Zero-Downtime Upgrades](./zero-downtime.md) — upgrading the binary without dropping connections
- [Installation](../getting-started/installation.md) — binary installation options
