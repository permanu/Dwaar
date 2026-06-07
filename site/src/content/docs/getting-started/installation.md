---
title: "Installation"
---

## Quick Install (Linux / macOS)

```bash
curl -fsSL https://dwaar.dev/install.sh | sh
```

That's it — no keys, no extra tooling. The installer:

1. Detects your OS and architecture.
2. Downloads the latest release from GitHub.
3. Verifies the **SHA-256 checksum** (always).
4. Verifies the **cosign signature** if `cosign` is installed. Releases are
   signed keylessly by GitHub Actions (Sigstore/Fulcio), so verification needs
   **no public key**. If `cosign` isn't installed, the installer prints a
   warning and continues — the SHA-256 check is the integrity guarantee.
5. Installs `dwaar` to `/usr/local/bin` (using `sudo` if needed), or falls back
   to `~/.local/bin` when you have no root access.
6. On Linux with systemd, writes a default `/etc/dwaar/Dwaarfile` and installs
   (and enables) a `dwaar` systemd service. On macOS, installs a launchd agent.

**Options:**

```bash
# Install a specific version
DWAAR_VERSION=0.3.23 curl -fsSL https://dwaar.dev/install.sh | sh
```

**Supported platforms:**

| Platform | Binary | Status |
|----------|--------|--------|
| Linux x86_64 | `dwaar-linux-amd64` | ✅ Published |
| Linux ARM64 | `dwaar-linux-arm64` | ✅ Published |
| macOS ARM64 (Apple Silicon) | `dwaar-darwin-arm64` | ✅ Published |
| macOS x86_64 (Intel) | — | Build from source / Rosetta 2 |

> The installer is the same script everywhere: `https://dwaar.dev/install.sh`
> is generated from [`scripts/install.sh`](https://github.com/permanu/Dwaar/blob/main/scripts/install.sh)
> in the repository, so the two can never drift.

---

## Verifying the download yourself (optional)

Every release is signed keylessly with [cosign](https://github.com/sigstore/cosign).
You do **not** need a public key — the `.bundle` is self-contained:

```bash
VERSION=0.3.23   # the release you downloaded
ART=dwaar-linux-amd64
base="https://github.com/permanu/Dwaar/releases/download/v${VERSION}"
curl -fLO "${base}/${ART}"
curl -fLO "${base}/${ART}.bundle"

cosign verify-blob "${ART}" \
  --bundle "${ART}.bundle" \
  --certificate-identity-regexp "^https://github\.com/permanu/Dwaar/\.github/workflows/release\.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

See [Release Signing](../../security/release-signing/) for the full trust model,
including the enterprise key-pinning path (`DWAAR_COSIGN_PUBKEY`).

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
