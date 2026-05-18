#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
VALIDATOR="${ROOT_DIR}/scripts/validate-release-assets.sh"
BUILDER="${ROOT_DIR}/scripts/build-release-assets.sh"

make_asset_set() {
    dir="$1"
    mode="$2"
    mkdir -p "$dir"
    for artifact in dwaar-linux-amd64 dwaar-linux-arm64 dwaar-darwin-arm64; do
        printf 'binary:%s\n' "$artifact" > "${dir}/${artifact}"
        chmod +x "${dir}/${artifact}"
        printf 'hash  %s\n' "$artifact" > "${dir}/${artifact}.sha256"
        printf 'bundle:%s\n' "$artifact" > "${dir}/${artifact}.bundle"
        printf 'signature:%s\n' "$artifact" > "${dir}/${artifact}.sig"
        if [ "$mode" = "token" ]; then
            printf 'certificate:%s\n' "$artifact" > "${dir}/${artifact}.cert"
        fi
    done
    cat "${dir}"/*.sha256 > "${dir}/SHASUMS.txt"
}

tmp_root=$(mktemp -d)
trap 'rm -rf "$tmp_root"' EXIT

fake_bin="${tmp_root}/bin"
mkdir -p "$fake_bin"
cat > "${fake_bin}/cosign" <<'FAKE'
#!/bin/sh
mode="${1:-}"
shift || true
bundle=""
key=""
identity_token=""
sig=""
cert=""
legacy_identity=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --key)
            key="$2"
            shift 2
            ;;
        --identity-token)
            identity_token="$2"
            shift 2
            ;;
        --bundle)
            bundle="$2"
            shift 2
            ;;
        --output-signature)
            sig="$2"
            shift 2
            ;;
        --output-certificate)
            cert="$2"
            shift 2
            ;;
        --certificate-identity-regexp)
            legacy_identity="$2"
            shift 2
            ;;
        --certificate|--signature|--certificate-oidc-issuer)
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

case "$mode" in
    sign-blob)
        [ -n "$bundle" ] && printf 'bundle\n' > "$bundle"
        if [ -n "$key" ]; then
            [ "$key" = "gcpkms://projects/example/locations/global/keyRings/releases/cryptoKeys/dwaar" ] || {
                echo "missing or unexpected cosign key: $key" >&2
                exit 1
            }
            printf 'signature\n'
        else
            if [ -n "$identity_token" ] && [ "$identity_token" != "test-token" ]; then
                echo "unexpected identity token" >&2
                exit 1
            fi
            [ -n "$sig" ] && printf 'signature\n' > "$sig"
            [ -n "$cert" ] && printf 'certificate\n' > "$cert"
        fi
        ;;
    verify-blob)
        if [ -n "$key" ]; then
            [ "$key" = "gcpkms://projects/example/locations/global/keyRings/releases/cryptoKeys/dwaar" ] || {
                echo "missing or unexpected verify key: $key" >&2
                exit 1
            }
        elif [ -z "$legacy_identity" ]; then
            echo "missing legacy identity verification" >&2
            exit 1
        fi
        ;;
    *)
        echo "unexpected cosign mode: $mode" >&2
        exit 1
        ;;
esac
FAKE
chmod +x "${fake_bin}/cosign"

complete_dir="${tmp_root}/complete-token"
make_asset_set "$complete_dir" token
PATH="${fake_bin}:${PATH}" DWAAR_RELEASE_SIGNING_MODE=token "$VALIDATOR" "$complete_dir"

key_complete_dir="${tmp_root}/complete-key"
make_asset_set "$key_complete_dir" key
PATH="${fake_bin}:${PATH}" \
PERMANU_COSIGN_KEY="gcpkms://projects/example/locations/global/keyRings/releases/cryptoKeys/dwaar" \
DWAAR_RELEASE_SIGNING_MODE=key "$VALIDATOR" "$key_complete_dir"

key_bundle_only_dir="${tmp_root}/complete-key-bundle-only"
make_asset_set "$key_bundle_only_dir" key
rm "${key_bundle_only_dir}"/*.sig
PATH="${fake_bin}:${PATH}" \
PERMANU_COSIGN_KEY="gcpkms://projects/example/locations/global/keyRings/releases/cryptoKeys/dwaar" \
DWAAR_RELEASE_SIGNING_MODE=key "$VALIDATOR" "$key_bundle_only_dir"

missing_dir="${tmp_root}/missing"
make_asset_set "$missing_dir" token
rm "${missing_dir}/dwaar-darwin-arm64.cert"

if PATH="${fake_bin}:${PATH}" DWAAR_RELEASE_SIGNING_MODE=token "$VALIDATOR" "$missing_dir" > "${tmp_root}/missing.out" 2>&1; then
    echo "validator unexpectedly accepted an incomplete asset set" >&2
    exit 1
fi

if ! grep -q "missing required release asset: ${missing_dir}/dwaar-darwin-arm64.cert" "${tmp_root}/missing.out"; then
    echo "validator did not report the missing Darwin certificate" >&2
    cat "${tmp_root}/missing.out" >&2
    exit 1
fi

empty_dir="${tmp_root}/empty"
make_asset_set "$empty_dir" key
: > "${empty_dir}/dwaar-linux-amd64.bundle"

if PATH="${fake_bin}:${PATH}" \
    PERMANU_COSIGN_KEY="gcpkms://projects/example/locations/global/keyRings/releases/cryptoKeys/dwaar" \
    DWAAR_RELEASE_SIGNING_MODE=key "$VALIDATOR" "$empty_dir" > "${tmp_root}/empty.out" 2>&1; then
    echo "validator unexpectedly accepted an empty bundle" >&2
    exit 1
fi

if ! grep -q "missing required release asset: ${empty_dir}/dwaar-linux-amd64.bundle" "${tmp_root}/empty.out"; then
    echo "validator did not report the empty Linux bundle" >&2
    cat "${tmp_root}/empty.out" >&2
    exit 1
fi

missing_mode_dir="${tmp_root}/missing-mode"
make_asset_set "$missing_mode_dir" key

if "$VALIDATOR" "$missing_mode_dir" > "${tmp_root}/missing-mode.out" 2>&1; then
    echo "validator unexpectedly accepted release assets without a signing mode or authority" >&2
    exit 1
fi

if ! grep -q "release signing mode is missing" "${tmp_root}/missing-mode.out"; then
    echo "validator did not report the missing signing mode" >&2
    cat "${tmp_root}/missing-mode.out" >&2
    exit 1
fi

cat > "${fake_bin}/cargo" <<'FAKE'
#!/bin/sh
echo "unexpected cargo invocation" >&2
exit 1
FAKE
cat > "${fake_bin}/rustup" <<'FAKE'
#!/bin/sh
echo "unexpected rustup invocation" >&2
exit 1
FAKE
cat > "${fake_bin}/uname" <<'FAKE'
#!/bin/sh
case "${1:-}" in
    -s) echo "Linux" ;;
    -m) echo "x86_64" ;;
    *) echo "Linux" ;;
esac
FAKE
chmod +x "${fake_bin}/cargo" "${fake_bin}/rustup" "${fake_bin}/uname"

prebuilt_dir="${tmp_root}/prebuilt"
mkdir -p "$prebuilt_dir"
for artifact in dwaar-linux-amd64 dwaar-linux-arm64 dwaar-darwin-arm64; do
    printf 'prebuilt:%s\n' "$artifact" > "${prebuilt_dir}/${artifact}"
done

byos_dir="${tmp_root}/byos-key"
PATH="${fake_bin}:${PATH}" \
GITHUB_REF="refs/tags/v0.0.0" \
PERMANU_COSIGN_KEY="gcpkms://projects/example/locations/global/keyRings/releases/cryptoKeys/dwaar" \
DWAAR_LINUX_AMD64_BINARY="${prebuilt_dir}/dwaar-linux-amd64" \
DWAAR_LINUX_ARM64_BINARY="${prebuilt_dir}/dwaar-linux-arm64" \
DWAAR_DARWIN_ARM64_BINARY="${prebuilt_dir}/dwaar-darwin-arm64" \
    "$BUILDER" "$byos_dir"
PATH="${fake_bin}:${PATH}" \
PERMANU_COSIGN_KEY="gcpkms://projects/example/locations/global/keyRings/releases/cryptoKeys/dwaar" \
DWAAR_RELEASE_SIGNING_MODE=key "$VALIDATOR" "$byos_dir"

if [ -e "${byos_dir}/dwaar-linux-amd64.cert" ]; then
    echo "builder unexpectedly produced a certificate for key-mode signing" >&2
    exit 1
fi

token_dir="${tmp_root}/token"
PATH="${fake_bin}:${PATH}" \
GITHUB_REF="refs/tags/v0.0.0" \
PERMANU_SIGSTORE_ID_TOKEN="test-token" \
DWAAR_LINUX_AMD64_BINARY="${prebuilt_dir}/dwaar-linux-amd64" \
DWAAR_LINUX_ARM64_BINARY="${prebuilt_dir}/dwaar-linux-arm64" \
DWAAR_DARWIN_ARM64_BINARY="${prebuilt_dir}/dwaar-darwin-arm64" \
    "$BUILDER" "$token_dir"
PATH="${fake_bin}:${PATH}" DWAAR_RELEASE_SIGNING_MODE=token "$VALIDATOR" "$token_dir"

missing_darwin_dir="${tmp_root}/missing-darwin"
if PATH="${fake_bin}:${PATH}" \
    GITHUB_REF="refs/tags/v0.0.0" \
    PERMANU_COSIGN_KEY="gcpkms://projects/example/locations/global/keyRings/releases/cryptoKeys/dwaar" \
    DWAAR_LINUX_AMD64_BINARY="${prebuilt_dir}/dwaar-linux-amd64" \
    DWAAR_LINUX_ARM64_BINARY="${prebuilt_dir}/dwaar-linux-arm64" \
    "$BUILDER" "$missing_darwin_dir" > "${tmp_root}/missing-darwin.out" 2>&1; then
    echo "builder unexpectedly accepted a release without darwin-arm64 capability" >&2
    exit 1
fi

if ! grep -q "darwin-arm64 release asset requires a macOS runner or DWAAR_DARWIN_ARM64_BINARY" "${tmp_root}/missing-darwin.out"; then
    echo "builder did not report the missing darwin-arm64 capability" >&2
    cat "${tmp_root}/missing-darwin.out" >&2
    exit 1
fi

missing_identity_dir="${tmp_root}/missing-identity"
if PATH="${fake_bin}:${PATH}" \
    GITHUB_REF="refs/tags/v0.0.0" \
    DWAAR_LINUX_AMD64_BINARY="${prebuilt_dir}/dwaar-linux-amd64" \
    DWAAR_LINUX_ARM64_BINARY="${prebuilt_dir}/dwaar-linux-arm64" \
    DWAAR_DARWIN_ARM64_BINARY="${prebuilt_dir}/dwaar-darwin-arm64" \
    "$BUILDER" "$missing_identity_dir" > "${tmp_root}/missing-identity.out" 2>&1; then
    echo "builder unexpectedly accepted a release without sigstore identity" >&2
    exit 1
fi

if ! grep -q "cosign signing authority is missing" "${tmp_root}/missing-identity.out"; then
    echo "builder did not report the missing signing authority" >&2
    cat "${tmp_root}/missing-identity.out" >&2
    exit 1
fi
