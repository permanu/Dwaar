#!/bin/sh
# Dwaar installer — https://dwaar.dev
# Usage: curl -fsSL https://dwaar.dev/install.sh | sh
set -eu

BASE_URL="https://releases.dwaar.dev"
INSTALL_DIR="${DWAAR_INSTALL_DIR:-/usr/local/bin}"

# --- Detect platform ---
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  os="linux" ;;
  Darwin) os="darwin" ;;
  *)      printf "Error: unsupported OS: %s\n" "$OS" >&2; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64)  arch="amd64" ;;
  aarch64|arm64)  arch="arm64" ;;
  *)              printf "Error: unsupported architecture: %s\n" "$ARCH" >&2; exit 1 ;;
esac

ARTIFACT="dwaar-${os}-${arch}"

# --- Resolve version ---
if [ -n "${DWAAR_VERSION:-}" ]; then
  VERSION="$DWAAR_VERSION"
else
  VERSION="$(curl -fsSL "${BASE_URL}/latest")"
fi

if [ -z "$VERSION" ]; then
  printf "Error: could not determine latest version\n" >&2
  exit 1
fi

DOWNLOAD_URL="${BASE_URL}/${VERSION}/${ARTIFACT}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

printf "Installing dwaar %s (%s/%s)\n" "$VERSION" "$os" "$arch"

# --- Download ---
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -fSL --progress-bar -o "${TMP}/${ARTIFACT}" "$DOWNLOAD_URL"
curl -fsSL -o "${TMP}/${ARTIFACT}.sha256" "$CHECKSUM_URL"

# --- Verify checksum ---
cd "$TMP"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c "${ARTIFACT}.sha256"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 -c "${ARTIFACT}.sha256"
else
  printf "Warning: no sha256 tool found, skipping checksum verification\n" >&2
fi

# --- Install ---
chmod +x "$ARTIFACT"

if [ -w "$INSTALL_DIR" ]; then
  mv "$ARTIFACT" "${INSTALL_DIR}/dwaar"
else
  printf "Installing to %s (requires sudo)\n" "$INSTALL_DIR"
  sudo mv "$ARTIFACT" "${INSTALL_DIR}/dwaar"
fi

printf "\ndwaar %s installed to %s/dwaar\n" "$VERSION" "$INSTALL_DIR"
printf "Run 'dwaar --help' to get started\n"
