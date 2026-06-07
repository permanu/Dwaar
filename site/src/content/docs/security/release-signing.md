---
title: Release Signing
description: How Dwaar release binaries are signed and how to verify them
---

# Release Signing

Every Dwaar release binary is cryptographically signed using [cosign](https://github.com/sigstore/cosign).

**The public releases on GitHub are signed keylessly** by the `release.yml`
GitHub Actions workflow via Sigstore. This is the default path and it requires
**no public key** to verify — the signing certificate and transparency-log proof
are embedded in the `.bundle`. Verification only checks that the bundle was
signed by Dwaar's release workflow identity and chains back to Fulcio.

A separate **enterprise / BYOS** path exists for organizations that run their own
release pipeline with a KMS- or file-backed cosign key. That path verifies the
bundle against a public key you pin via `DWAAR_COSIGN_PUBKEY` /
`DWAAR_COSIGN_PUBKEY_URL`. It is opt-in and does not apply to the binaries
published at `github.com/permanu/Dwaar`.

## Trust chain (default — keyless)

```
GitHub Actions OIDC token (release.yml workflow identity)
        ↓
Fulcio exchanges it for a short-lived signing certificate
        ↓
cosign sign-blob --bundle <artifact>.bundle <artifact>
        ↓
Verifier checks the bundle's cert identity + Fulcio chain (no key needed)
```

The certificate's Subject Alternative Name (SAN) is the workflow URI
`https://github.com/permanu/Dwaar/.github/workflows/release.yml@refs/tags/<tag>`,
and verification confirms it chains back to Fulcio with the expected OIDC issuer.

## Trust chain (enterprise / BYOS — key-pinned)

```
Your KMS/local/env cosign key
        ↓
cosign sign-blob --key <key> --bundle <artifact>.bundle <artifact>
        ↓
Verifier checks the bundle against your configured public key
```

## Artifacts published per release

For each platform binary (e.g. `dwaar-linux-amd64`) the following files are attached to the GitHub Release:

| File | Contents |
|------|----------|
| `dwaar-<os>-<arch>` | The binary |
| `dwaar-<os>-<arch>.sha256` | SHA256 checksum |
| `dwaar-<os>-<arch>.bundle` | Self-contained cosign bundle (cert + signature + log proof) — this is all you need to verify |
| `dwaar-<os>-<arch>.sig` | Optional detached signature (not published by every release; redundant with the bundle) |
| `dwaar-<os>-<arch>.cert` | Optional short-lived signing certificate, PEM (not published by every release; redundant with the bundle) |
| `SHASUMS.txt` | Aggregated SHA256 for all binaries |

## Verifying a binary

### Automatic (via install.sh)

```sh
curl -fsSL https://dwaar.dev/install.sh | sh
```

By default the installer:

1. **Always** verifies the SHA-256 checksum.
2. Verifies the keyless cosign signature **if `cosign` is installed** — no key
   or extra configuration required. A self-contained `.bundle` is all that is
   needed.
3. If `cosign` is **not** installed, prints a prominent warning and continues,
   relying on the SHA-256 check for integrity. (This is best-effort, Caddy-style
   verification — it never blocks a normal install on a missing tool.)

To **require** keyless verification instead of warning, simply install `cosign`
first (`brew install cosign`, or download the binary — see below).

For the **enterprise / BYOS key-pinned** path, set exactly one public-key source.
In this mode cosign is mandatory and keyless fallback is refused:

```sh
DWAAR_COSIGN_PUBKEY=/path/to/dwaar-release.pub        sh install.sh
# or
DWAAR_COSIGN_PUBKEY_URL=https://example.com/dwaar.pub sh install.sh
```

The installer never fetches a mutable key URL unless you explicitly set one.

### Manual verification

**Default (keyless).** Download the binary and its `.bundle` sibling — no key
needed:

```sh
cosign verify-blob dwaar-linux-amd64 \
  --bundle dwaar-linux-amd64.bundle \
  --certificate-identity-regexp "^https://github\.com/permanu/Dwaar/\.github/workflows/release\.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Older releases that published split `.sig` / `.cert` instead of a bundle verify
the same way:

```sh
cosign verify-blob dwaar-linux-amd64 \
  --certificate dwaar-linux-amd64.cert \
  --signature   dwaar-linux-amd64.sig \
  --certificate-identity-regexp "^https://github\.com/permanu/Dwaar/\.github/workflows/release\.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

**Enterprise / BYOS (key-pinned).** Download the binary, `.bundle`, and your
pinned public key, then run:

```sh
cosign verify-blob dwaar-linux-amd64 \
  --bundle dwaar-linux-amd64.bundle \
  --key dwaar-release.pub
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

`dwaar self-update` uses the same trust policy as the installer. By default it
verifies the keyless cosign bundle against the release workflow identity (no key
needed). If you have configured `DWAAR_COSIGN_PUBKEY` / `DWAAR_COSIGN_PUBKEY_URL`,
it verifies against that pinned key instead and refuses keyless fallback. Unlike
the installer, self-update **requires** `cosign` and refuses to swap the binary
if verification fails or cosign is missing.
