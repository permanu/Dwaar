---
title: Release Signing
description: How Dwaar release binaries are signed and how to verify them
---

# Release Signing

Every Dwaar release binary is cryptographically signed using [cosign](https://github.com/sigstore/cosign) keyless OIDC signing. No pre-shared keys are required — verification relies on the public Sigstore infrastructure (Fulcio CA + Rekor transparency log).

## Trust chain

```
GitHub Actions OIDC token
        ↓
Fulcio (Sigstore CA) exchanges it for a short-lived signing certificate
        ↓
Certificate encodes the exact workflow identity:
  https://github.com/permanu/Dwaar/.github/workflows/release.yml@refs/tags/<tag>
        ↓
Binary is signed; signature + certificate recorded in Rekor (public transparency log)
        ↓
.sig and .cert artifacts attached to the GitHub Release
```

The certificate's Subject Alternative Name (SAN) is the workflow URI above. Verification checks that the cert chains back to Fulcio **and** that the workflow path matches the expected pattern — so a binary signed by any other workflow or repository will not verify.

## Artifacts published per release

For each platform binary (e.g. `dwaar-linux-amd64`) the following files are attached to the GitHub Release:

| File | Contents |
|------|----------|
| `dwaar-<os>-<arch>` | The binary |
| `dwaar-<os>-<arch>.sha256` | SHA256 checksum |
| `dwaar-<os>-<arch>.sig` | Detached cosign signature |
| `dwaar-<os>-<arch>.cert` | Short-lived signing certificate (PEM) |
| `dwaar-<os>-<arch>.bundle` | Cosign bundle (sig + cert + Rekor metadata) |
| `SHASUMS.txt` | Aggregated SHA256 for all binaries |

## Verifying a binary

### Automatic (via install.sh)

`install.sh` verifies the cosign signature automatically if `cosign` is installed on the system. If cosign is not present it falls back to SHA256 verification and prints a prominent warning.

### Manual verification

Download the binary and its `.sig` / `.cert` siblings, then run:

```sh
cosign verify-blob \
  --certificate dwaar-linux-amd64.cert \
  --signature   dwaar-linux-amd64.sig \
  --certificate-identity-regexp "^https://github\.com/permanu/Dwaar/\.github/workflows/release\.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  dwaar-linux-amd64
```

Replace `dwaar-linux-amd64` with your platform artifact name (`dwaar-linux-arm64`, `dwaar-darwin-arm64`).

A successful verification prints:

```
Verified OK
```

### Installing cosign

```sh
# macOS
brew install cosign

# Linux (direct download)
curl -Lo cosign https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x cosign && sudo mv cosign /usr/local/bin/
```

See the [cosign releases page](https://github.com/sigstore/cosign/releases) for all platforms.

## How to confirm the workflow identity

The `--certificate-identity-regexp` you verify against is:

```
^https://github\.com/permanu/Dwaar/\.github/workflows/release\.yml@.*
```

This anchors to the `permanu/Dwaar` repository and the `release.yml` workflow file. The `@.*` suffix matches any git ref (tag, branch) so the same command works for any release version.

To additionally pin to a specific tag:

```sh
--certificate-identity "https://github.com/permanu/Dwaar/.github/workflows/release.yml@refs/tags/v0.3.8"
```

## Agent-side verification (Permanu auto-update)

The Permanu auto-update agent verifies cosign before swapping any binary:

```sh
cosign verify-blob \
  --certificate <download_dir>/dwaar-<os>-<arch>.cert \
  --signature   <download_dir>/dwaar-<os>-<arch>.sig \
  --certificate-identity-regexp "^https://github\.com/permanu/Dwaar/\.github/workflows/release\.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  <download_dir>/dwaar-<os>-<arch>
```

The agent will refuse to apply an update if cosign verification fails. There is no bypass.
