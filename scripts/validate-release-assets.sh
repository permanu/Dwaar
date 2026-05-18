#!/bin/sh
set -eu

dist_dir="${1:-dist}"

artifact_names="dwaar-linux-amd64 dwaar-linux-arm64 dwaar-darwin-arm64"
legacy_identity='^https://github\.com/permanu/Dwaar/\.github/workflows/release\.yml@.*'
legacy_issuer='https://token.actions.githubusercontent.com'

fail() {
    echo "$*" >&2
    exit 1
}

detect_signing_mode() {
    case "${DWAAR_RELEASE_SIGNING_MODE:-}" in
        key|kms|byos)
            printf '%s\n' key
            return 0
            ;;
        token|oidc|keyless)
            printf '%s\n' token
            return 0
            ;;
        "")
            ;;
        *)
            fail "unsupported release signing mode: ${DWAAR_RELEASE_SIGNING_MODE}; expected key or token"
            ;;
    esac

    if [ -n "${COSIGN_KEY:-}" ] || [ -n "${PERMANU_COSIGN_KEY:-}" ]; then
        printf '%s\n' key
        return 0
    fi

    if [ -n "${SIGSTORE_ID_TOKEN:-}" ] || [ -n "${PERMANU_SIGSTORE_ID_TOKEN:-}" ] ||
        { [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; }; then
        printf '%s\n' token
        return 0
    fi

    fail "release signing mode is missing; set DWAAR_RELEASE_SIGNING_MODE=key|token or provide cosign signing authority env"
}

cosign_verify_key() {
    for value in "${DWAAR_COSIGN_PUBKEY:-}" "${PERMANU_COSIGN_VERIFY_KEY:-}" "${COSIGN_VERIFY_KEY:-}" "${PERMANU_COSIGN_KEY:-}" "${COSIGN_KEY:-}"; do
        if [ -n "$value" ]; then
            printf '%s\n' "$value"
            return 0
        fi
    done

    if [ -n "${DWAAR_COSIGN_PUBKEY_URL:-}" ]; then
        case "${DWAAR_COSIGN_PUBKEY_URL}" in
            https://*) ;;
            *) fail "DWAAR_COSIGN_PUBKEY_URL must be an https:// URL" ;;
        esac
        tmp_key=$(mktemp)
        curl -fsSL -o "$tmp_key" "$DWAAR_COSIGN_PUBKEY_URL"
        printf '%s\n' "$tmp_key"
        return 0
    fi

    return 1
}

verify_release_asset() {
    artifact="$1"
    signing_mode="$2"
    binary="${dist_dir}/${artifact}"
    bundle="${binary}.bundle"

    command -v cosign >/dev/null 2>&1 || fail "cosign is required to verify release assets before publishing"

    if [ "$signing_mode" = "key" ]; then
        key=$(cosign_verify_key) || fail "key-mode validation requires DWAAR_COSIGN_PUBKEY, PERMANU_COSIGN_VERIFY_KEY, COSIGN_VERIFY_KEY, PERMANU_COSIGN_KEY, COSIGN_KEY, or DWAAR_COSIGN_PUBKEY_URL"
        cosign verify-blob "$binary" --bundle "$bundle" --key "$key" >/dev/null
        return
    fi

    cosign verify-blob "$binary" \
        --bundle "$bundle" \
        --certificate-identity-regexp "$legacy_identity" \
        --certificate-oidc-issuer "$legacy_issuer" >/dev/null
}

if [ ! -d "$dist_dir" ]; then
    fail "release asset directory does not exist: ${dist_dir}"
fi

signing_mode=$(detect_signing_mode)
missing=0

for artifact in $artifact_names; do
    required_suffixes=".sha256 .bundle"
    if [ "$signing_mode" = "token" ]; then
        required_suffixes="${required_suffixes} .sig .cert"
    fi

    for suffix in "" $required_suffixes; do
        asset="${dist_dir}/${artifact}${suffix}"
        if [ ! -s "$asset" ]; then
            echo "missing required release asset: ${asset}" >&2
            missing=1
        fi
    done

    if [ "$signing_mode" = "key" ] && [ -e "${dist_dir}/${artifact}.sig" ] && [ ! -s "${dist_dir}/${artifact}.sig" ]; then
        echo "empty optional release asset: ${dist_dir}/${artifact}.sig" >&2
        missing=1
    fi

    if [ -s "${dist_dir}/SHASUMS.txt" ] && ! grep -q "[[:space:]]${artifact}$" "${dist_dir}/SHASUMS.txt"; then
        echo "missing SHASUMS.txt entry for required artifact: ${artifact}" >&2
        missing=1
    fi
done

if [ ! -s "${dist_dir}/SHASUMS.txt" ]; then
    echo "missing required release asset: ${dist_dir}/SHASUMS.txt" >&2
    missing=1
fi

if [ "$missing" -ne 0 ]; then
    echo "Refusing to publish an incomplete Dwaar release for ${signing_mode} signing mode." >&2
    exit 1
fi

for artifact in $artifact_names; do
    if ! verify_release_asset "$artifact" "$signing_mode"; then
        echo "Refusing to publish release assets that fail cosign verification: ${artifact}" >&2
        exit 1
    fi
done
