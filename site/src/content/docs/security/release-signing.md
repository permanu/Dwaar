---
title: Release Signing
description: How Dwaar release binaries are signed and how to verify them
---

# Release Signing

Every Dwaar release binary is cryptographically signed using [cosign](https://github.com/sigstore/cosign). The recommended production path for Permanu BYOS runners is key/KMS-backed signing with verification through a pinned or exported public key. Legacy GitHub Actions keyless verification is retained for older releases during migration.

## Trust chain

```
Enterprise KMS/local/env cosign key
        ↓
cosign sign-blob --key <key> --bundle <artifact>.bundle --yes <artifact>
        ↓
Verifier checks the bundle with the configured public key
```

Legacy token/OIDC releases additionally chain through Fulcio:

```
GitHub Actions or explicit Sigstore OIDC token
        ↓
Fulcio exchanges it for a short-lived signing certificate
        ↓
Binary is signed; bundle, detached signature, and certificate are attached
```

For key/KMS releases, installer and self-update verification is based on the trusted public key rather than a Fulcio certificate identity or provider API access. For token/OIDC releases, the certificate's Subject Alternative Name (SAN) is the workflow URI and verification checks that the cert chains back to Fulcio.

## Artifacts published per release

For each platform binary (e.g. `dwaar-linux-amd64`) the following files are attached to the GitHub Release:

| File | Contents |
|------|----------|
| `dwaar-<os>-<arch>` | The binary |
| `dwaar-<os>-<arch>.sha256` | SHA256 checksum |
| `dwaar-<os>-<arch>.bundle` | Required cosign bundle |
| `dwaar-<os>-<arch>.sig` | Optional detached cosign signature when emitted by the signing command |
| `dwaar-<os>-<arch>.cert` | Token/OIDC releases only: short-lived signing certificate (PEM) |
| `SHASUMS.txt` | Aggregated SHA256 for all binaries |

## Verifying a binary

### Automatic (via install.sh)

`install.sh` verifies the cosign signature automatically if `cosign` is installed on the system.

For key/KMS releases, set one explicit public-key source:

```sh
DWAAR_COSIGN_PUBKEY=/path/to/dwaar-release.pub sh install.sh
```

or:

```sh
DWAAR_COSIGN_PUBKEY_URL=https://example.com/pinned/dwaar-release.pub sh install.sh
```

The installer does not fetch a mutable key URL by default. If a release key is configured, cosign is required and the installer refuses legacy keyless fallback. If a release only has a `.bundle` and no legacy `.sig`/`.cert`, the installer treats it as key-signed and fails closed until `DWAAR_COSIGN_PUBKEY` or `DWAAR_COSIGN_PUBKEY_URL` is configured. Without a configured release key, the installer uses the legacy GitHub Actions keyless policy only for older releases that still publish legacy signature material; if cosign is not present in that legacy mode, it falls back to SHA256 verification with a prominent warning.

### Manual verification

For key/KMS releases, download the binary, `.bundle`, and pinned public key, then run:

```sh
cosign verify-blob dwaar-linux-amd64 \
  --bundle dwaar-linux-amd64.bundle \
  --key dwaar-release.pub
```

For legacy token/OIDC releases, download the binary and either its `.bundle` sibling:

```sh
cosign verify-blob dwaar-linux-amd64 \
  --bundle dwaar-linux-amd64.bundle \
  --certificate-identity-regexp "^https://github\.com/permanu/Dwaar/\.github/workflows/release\.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

or historical `.sig` / `.cert` siblings:

```sh
cosign verify-blob dwaar-linux-amd64 \
  --certificate dwaar-linux-amd64.cert \
  --signature   dwaar-linux-amd64.sig \
  --certificate-identity-regexp "^https://github\.com/permanu/Dwaar/\.github/workflows/release\.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
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

## Self-update verification

`dwaar self-update` uses the same trust policy as the installer. It verifies a configured release-authority public key against the release bundle, otherwise it uses the legacy GitHub Actions keyless bundle or split `.sig` + `.cert` fallback only when legacy signature material exists. Key-signed bundles without a configured public key fail closed. Self-update requires `cosign` and refuses to swap the binary if verification fails.
