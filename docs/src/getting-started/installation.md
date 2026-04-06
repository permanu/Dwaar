# Installation

## Quick Install (Linux / macOS)

```bash
curl -fsSL https://dwaar.dev/install.sh | sh
```

This detects your OS and architecture, downloads the latest release, and installs to `/usr/local/bin/dwaar`.

---

## Debian / Ubuntu (APT)

First-class `.deb` packages with systemd integration, automatic updates, and proper file ownership.

**Add the Dwaar repository:**

```bash
# Import the GPG key
curl -fsSL https://pkg.dwaar.dev/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/dwaar-archive-keyring.gpg

# Add the repository
echo "deb [signed-by=/usr/share/keyrings/dwaar-archive-keyring.gpg] https://pkg.dwaar.dev/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/dwaar.list

# Install
sudo apt update
sudo apt install dwaar
```

**What the `.deb` package includes:**

| File | Purpose |
|------|---------|
| `/usr/bin/dwaar` | Main binary |
| `/usr/bin/dwaar-ingress` | Kubernetes ingress controller binary |
| `/etc/dwaar/Dwaarfile` | Default config (editable) |
| `/etc/dwaar/certs/` | TLS certificate storage |
| `/lib/systemd/system/dwaar.service` | Systemd unit file |
| `/usr/share/doc/dwaar/` | Man page and changelog |

**After install:**

```bash
# Edit config
sudo nano /etc/dwaar/Dwaarfile

# Start and enable
sudo systemctl enable --now dwaar

# Check status
sudo systemctl status dwaar
journalctl -u dwaar -f
```

**Upgrade:**

```bash
sudo apt update && sudo apt upgrade dwaar
```

---

## RHEL / Fedora / Rocky (RPM)

```bash
sudo tee /etc/yum.repos.d/dwaar.repo << 'EOF'
[dwaar]
name=Dwaar
baseurl=https://pkg.dwaar.dev/rpm/stable
enabled=1
gpgcheck=1
gpgkey=https://pkg.dwaar.dev/gpg.key
EOF

sudo dnf install dwaar
```

---

## Alpine (APK)

```bash
echo "https://pkg.dwaar.dev/alpine/stable" | sudo tee -a /etc/apk/repositories
wget -qO /etc/apk/keys/dwaar.rsa.pub https://pkg.dwaar.dev/gpg.pub
sudo apk add dwaar
```

---

## macOS (Homebrew)

```bash
brew tap permanu/dwaar
brew install dwaar
```

---

## From GitHub Releases

| Platform | Binary | Checksum |
|----------|--------|----------|
| Linux x86_64 | `dwaar-linux-amd64` | `dwaar-linux-amd64.sha256` |
| Linux ARM64 | `dwaar-linux-arm64` | `dwaar-linux-arm64.sha256` |
| macOS x86_64 | `dwaar-darwin-amd64` | `dwaar-darwin-amd64.sha256` |
| macOS ARM64 (Apple Silicon) | `dwaar-darwin-arm64` | `dwaar-darwin-arm64.sha256` |

```bash
wget https://github.com/permanu/Dwaar/releases/latest/download/dwaar-linux-amd64
wget https://github.com/permanu/Dwaar/releases/latest/download/dwaar-linux-amd64.sha256
sha256sum -c dwaar-linux-amd64.sha256
chmod +x dwaar-linux-amd64
sudo mv dwaar-linux-amd64 /usr/local/bin/dwaar
```

---

## Docker

```bash
docker run -d \
  --name dwaar \
  -p 80:80 -p 443:443 -p 443:443/udp \
  -v ./Dwaarfile:/etc/dwaar/Dwaarfile \
  -v dwaar-data:/var/lib/dwaar \
  ghcr.io/permanu/dwaar:latest
```

See [Docker Deployment](../deployment/docker.md) for volumes, compose, and health checks.

---

## From Source

Requires Rust 1.94+ and OpenSSL development headers:

```bash
sudo apt install build-essential pkg-config libssl-dev
git clone https://github.com/permanu/Dwaar.git
cd Dwaar
cargo build --release
sudo cp target/release/dwaar /usr/local/bin/
```

For a PGO-optimized build (10-15% faster): `./scripts/pgo-build.sh`

---

## Verify

```bash
dwaar version
dwaar validate
```

## Next Steps

- [Quick Start](quickstart.md) -- get a proxy running in 60 seconds
- [Dwaarfile Reference](../configuration/dwaarfile.md) -- learn the config format
- [Systemd Service](../deployment/systemd.md) -- production service setup
