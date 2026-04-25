#!/bin/sh
# Dwaar installer — https://dwaar.dev
# Usage: curl -fsSL https://dwaar.dev/install.sh | sh
set -eu

GITHUB_REPO="permanu/Dwaar"
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

# x86_64 macOS is not a supported release target (Apple ended Intel Mac
# support). Users on Intel Macs should build from source or use Rosetta 2.
if [ "$os" = "darwin" ] && [ "$arch" = "amd64" ]; then
  printf "Error: Intel Mac (x86_64) binaries are not published.\n" >&2
  printf "Build from source: cargo build --release\n" >&2
  printf "Or run the ARM binary via Rosetta: arch -arm64 dwaar\n" >&2
  exit 1
fi

ARTIFACT="dwaar-${os}-${arch}"

# --- Resolve version ---
if [ -n "${DWAAR_VERSION:-}" ]; then
  VERSION="$DWAAR_VERSION"
else
  # Follow the GitHub Releases /latest redirect to extract the tag.
  VERSION="$(curl -fsSL -o /dev/null -w '%{url_effective}' \
    "https://github.com/${GITHUB_REPO}/releases/latest" | \
    rev | cut -d/ -f1 | rev)"
fi

if [ -z "$VERSION" ]; then
  printf "Error: could not determine latest version\n" >&2
  exit 1
fi

DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${ARTIFACT}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"
SIG_URL="${DOWNLOAD_URL}.sig"
CERT_URL="${DOWNLOAD_URL}.cert"

printf "Installing dwaar %s (%s/%s)\n" "$VERSION" "$os" "$arch"

# --- Download ---
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -fSL --progress-bar -o "${TMP}/${ARTIFACT}" "$DOWNLOAD_URL"
curl -fsSL -o "${TMP}/${ARTIFACT}.sha256" "$CHECKSUM_URL"
curl -fsSL -o "${TMP}/${ARTIFACT}.sig"    "$SIG_URL"
curl -fsSL -o "${TMP}/${ARTIFACT}.cert"   "$CERT_URL"

# --- Verify checksum ---
cd "$TMP"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c "${ARTIFACT}.sha256"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 -c "${ARTIFACT}.sha256"
else
  printf "Warning: no sha256 tool found, skipping checksum verification\n" >&2
fi

# --- Verify cosign signature (keyless OIDC) ---
# The .sig and .cert files are published alongside every release binary.
# Verification pins the GitHub Actions workflow identity — no pre-shared keys.
# If cosign is not installed we fall back to sha256-only and print a loud
# warning. We never silently bypass signature verification.
if command -v cosign >/dev/null 2>&1; then
  printf "Verifying cosign signature...\n"
  cosign verify-blob \
    --certificate "${TMP}/${ARTIFACT}.cert" \
    --signature   "${TMP}/${ARTIFACT}.sig" \
    --certificate-identity-regexp "^https://github\.com/permanu/Dwaar/\.github/workflows/release\.yml@.*" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "${TMP}/${ARTIFACT}"
  printf "Cosign signature verified.\n"
else
  printf "Warning: cosign not installed, skipping signature verification (sha256 still checked).\n" >&2
  printf "         Install cosign: https://github.com/sigstore/cosign/releases\n" >&2
  printf "         Then verify manually:\n" >&2
  printf "           cosign verify-blob \\\\\n" >&2
  printf "             --certificate %s.cert \\\\\n" "$ARTIFACT" >&2
  printf "             --signature %s.sig \\\\\n" "$ARTIFACT" >&2
  printf '             --certificate-identity-regexp "^https://github\\.com/permanu/Dwaar/\\.github/workflows/release\\.yml@.*" \\\\\n' >&2
  printf '             --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \\\\\n' >&2
  printf "             %s\n" "$ARTIFACT" >&2
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
