---
title: "Installation"
---

## Quick Install (Linux / macOS)

```bash
curl -fsSL https://dwaar.dev/install.sh | sh
```

This detects your OS and architecture, downloads the latest release, verifies the SHA-256 checksum, and installs to `/usr/local/bin/dwaar`.

**Options:**

```bash
# Install a specific version
DWAAR_VERSION=v0.1.0 curl -fsSL https://dwaar.dev/install.sh | sh

# Install to a custom directory
DWAAR_INSTALL_DIR=~/.local/bin curl -fsSL https://dwaar.dev/install.sh | sh
```

**Supported platforms:**

| Platform | Binary |
|----------|--------|
| Linux x86_64 | `dwaar-linux-amd64` |
| Linux ARM64 | `dwaar-linux-arm64` |
| macOS x86_64 | `dwaar-darwin-amd64` |
| macOS ARM64 (Apple Silicon) | `dwaar-darwin-arm64` |

---

## Docker

```bash
docker run -d \
  --name dwaar \
  -p 80:80 \
  -p 443:443 \
  -p 443:443/udp \
  -v ./Dwaarfile:/etc/dwaar/Dwaarfile \
  -v dwaar-data:/var/lib/dwaar \
  ghcr.io/permanu/dwaar:latest
```

See [Docker Deployment](../deployment/docker/) for volumes, compose, and health checks.

---

## Coming Soon

The following installation methods are planned:

- **Homebrew** -- `brew install permanu/dwaar/dwaar`
- **APT** (Debian/Ubuntu) -- `.deb` packages with systemd integration
- **RPM** (RHEL/Fedora) -- via `dnf`
- **Alpine** (APK) -- for minimal container images

---

## Uninstall

```bash
curl -fsSL https://dwaar.dev/uninstall.sh | sh
```

---

## Verify Installation

```bash
dwaar version
```

```bash
# Validate your config
dwaar validate
```

---

## Next Steps

- [Quick Start](../getting-started/quickstart/) -- get a proxy running in 60 seconds
- [Dwaarfile Reference](../configuration/dwaarfile/) -- learn the config format
- [Systemd Service](../deployment/systemd/) -- production service setup
