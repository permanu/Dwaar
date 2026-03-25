# Installation

## Quick Install (Linux / macOS)

```bash
curl -fsSL dwaar.dev/install | sh
```

This downloads the latest release binary for your platform and places it in `/usr/local/bin/`.

## From GitHub Releases

Download the binary for your platform from [GitHub Releases](https://github.com/permanu/Dwaar/releases):

| Platform | Binary |
|----------|--------|
| Linux x86_64 | `dwaar-linux-amd64` |
| Linux ARM64 | `dwaar-linux-arm64` |
| macOS x86_64 | `dwaar-darwin-amd64` |
| macOS ARM64 (Apple Silicon) | `dwaar-darwin-arm64` |

```bash
# Example: Linux x86_64
wget https://github.com/permanu/Dwaar/releases/latest/download/dwaar-linux-amd64
chmod +x dwaar-linux-amd64
sudo mv dwaar-linux-amd64 /usr/local/bin/dwaar
```

## Docker

```bash
docker run -d \
  -p 80:80 \
  -p 443:443 \
  -v ./Dwaarfile:/etc/dwaar/Dwaarfile \
  -v dwaar-data:/var/lib/dwaar \
  ghcr.io/permanu/dwaar:latest
```

## From Source

Requires Rust 1.94+:

```bash
git clone https://github.com/permanu/Dwaar.git
cd Dwaar
cargo build --release
./target/release/dwaar
```

## Verify Installation

```bash
dwaar version
# dwaar v0.1.0
```

## Next Steps

- [Quick Start](./quickstart.md) — get a proxy running in 60 seconds
- [Dwaarfile Reference](../configuration/dwaarfile.md) — learn the config format
