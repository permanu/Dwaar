#!/bin/sh
set -eu

dist_dir="${1:-dist}"

artifact_names="dwaar-linux-amd64 dwaar-linux-arm64 dwaar-darwin-arm64"

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

require_cmd() {
    cmd="$1"
    message="$2"
    command -v "$cmd" >/dev/null 2>&1 || fail "$message"
}

is_tag_release() {
    case "${GITHUB_REF:-}" in
        refs/tags/v*) return 0 ;;
    esac
    case "${GITHUB_REF_NAME:-}" in
        v*) return 0 ;;
    esac
    return 1
}

load_cargo_env() {
    if [ -n "${CARGO_HOME:-}" ] && [ -f "${CARGO_HOME}/env" ]; then
        # shellcheck disable=SC1090,SC1091
        . "${CARGO_HOME}/env"
    elif [ -n "${HOME:-}" ] && [ -f "${HOME}/.cargo/env" ]; then
        # shellcheck disable=SC1091
        . "${HOME}/.cargo/env"
    fi
}

sha256_file() {
    file="$1"
    name=$(basename "$file")
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk -v name="$name" '{print $1 "  " name}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk -v name="$name" '{print $1 "  " name}'
    else
        fail "sha256sum or shasum is required to create release checksums"
    fi
}

copy_supplied_binary() {
    env_name="$1"
    artifact="$2"
    path=$(eval "printf '%s' \"\${${env_name}:-}\"")
    if [ -n "$path" ]; then
        [ -s "$path" ] || fail "${env_name} points to a missing or empty file: ${path}"
        cp "$path" "${dist_dir}/${artifact}"
        chmod +x "${dist_dir}/${artifact}"
        return 0
    fi
    return 1
}

install_linux_arm64_toolchain() {
    if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 && command -v aarch64-linux-gnu-g++ >/dev/null 2>&1; then
        return
    fi

    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            gcc-aarch64-linux-gnu \
            g++-aarch64-linux-gnu \
            libc6-dev-arm64-cross
    fi

    require_cmd aarch64-linux-gnu-gcc "aarch64-linux-gnu-gcc is required for linux-arm64 release builds"
    require_cmd aarch64-linux-gnu-g++ "aarch64-linux-gnu-g++ is required for linux-arm64 release builds"
}

build_linux_amd64() {
    if copy_supplied_binary DWAAR_LINUX_AMD64_BINARY dwaar-linux-amd64; then
        return
    fi

    [ "$(uname -s)" = "Linux" ] || fail "linux-amd64 release asset requires a Linux runner or DWAAR_LINUX_AMD64_BINARY"
    case "$(uname -m)" in
        x86_64|amd64) ;;
        *) fail "linux-amd64 release asset requires an x86_64 Linux runner or DWAAR_LINUX_AMD64_BINARY" ;;
    esac

    rustup target add x86_64-unknown-linux-gnu
    cargo build -p dwaar-cli --bin dwaar --release --target x86_64-unknown-linux-gnu
    cp target/x86_64-unknown-linux-gnu/release/dwaar "${dist_dir}/dwaar-linux-amd64"
    chmod +x "${dist_dir}/dwaar-linux-amd64"
}

build_linux_arm64() {
    if copy_supplied_binary DWAAR_LINUX_ARM64_BINARY dwaar-linux-arm64; then
        return
    fi

    [ "$(uname -s)" = "Linux" ] || fail "linux-arm64 release asset requires a Linux runner or DWAAR_LINUX_ARM64_BINARY"
    rustup target add aarch64-unknown-linux-gnu
    install_linux_arm64_toolchain
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
        cargo build -p dwaar-cli --bin dwaar --release --target aarch64-unknown-linux-gnu
    cp target/aarch64-unknown-linux-gnu/release/dwaar "${dist_dir}/dwaar-linux-arm64"
    chmod +x "${dist_dir}/dwaar-linux-arm64"
}

build_darwin_arm64() {
    if copy_supplied_binary DWAAR_DARWIN_ARM64_BINARY dwaar-darwin-arm64; then
        return
    fi

    if [ "$(uname -s)" != "Darwin" ]; then
        fail "darwin-arm64 release asset requires a macOS runner or DWAAR_DARWIN_ARM64_BINARY; this Linux runner cannot silently skip it"
    fi

    require_cmd xcrun "xcrun/Xcode command line tools are required for darwin-arm64 release builds"
    rustup target add aarch64-apple-darwin
    cargo build -p dwaar-cli --bin dwaar --release --target aarch64-apple-darwin
    cp target/aarch64-apple-darwin/release/dwaar "${dist_dir}/dwaar-darwin-arm64"
    chmod +x "${dist_dir}/dwaar-darwin-arm64"
}

write_checksums() {
    for artifact in $artifact_names; do
        sha256_file "${dist_dir}/${artifact}" > "${dist_dir}/${artifact}.sha256"
    done
    cat "${dist_dir}"/*.sha256 > "${dist_dir}/SHASUMS.txt"
}

resolve_cosign_key() {
    if [ -n "${PERMANU_COSIGN_KEY:-}" ] && [ -z "${COSIGN_KEY:-}" ]; then
        export COSIGN_KEY="${PERMANU_COSIGN_KEY}"
    fi

    [ -n "${COSIGN_KEY:-}" ]
}

has_sigstore_token_authority() {
    if [ -n "${PERMANU_SIGSTORE_ID_TOKEN:-}" ] && [ -z "${SIGSTORE_ID_TOKEN:-}" ]; then
        export SIGSTORE_ID_TOKEN="${PERMANU_SIGSTORE_ID_TOKEN}"
    fi

    if [ -n "${SIGSTORE_ID_TOKEN:-}" ]; then
        return 0
    fi

    [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]
}

sign_release_asset_with_key() {
    artifact="$1"
    binary="${dist_dir}/${artifact}"
    bundle="${dist_dir}/${artifact}.bundle"
    sig="${dist_dir}/${artifact}.sig"

    rm -f "$bundle" "$sig" "${dist_dir}/${artifact}.cert"
    if ! cosign sign-blob \
        --yes \
        --key "${COSIGN_KEY}" \
        --bundle "$bundle" \
        "$binary" > "$sig"; then
        rm -f "$bundle" "$sig"
        fail "cosign key/KMS signing failed for ${artifact}"
    fi

    [ -s "$bundle" ] || fail "cosign key/KMS signing did not produce required bundle: ${bundle}"
    if [ ! -s "$sig" ]; then
        rm -f "$sig"
    fi
}

sign_release_asset_with_token() {
    artifact="$1"
    binary="${dist_dir}/${artifact}"
    bundle="${dist_dir}/${artifact}.bundle"
    sig="${dist_dir}/${artifact}.sig"
    cert="${dist_dir}/${artifact}.cert"

    rm -f "$bundle" "$sig" "$cert"
    if [ -n "${SIGSTORE_ID_TOKEN:-}" ]; then
        cosign sign-blob \
            --yes \
            --identity-token "${SIGSTORE_ID_TOKEN}" \
            --bundle "$bundle" \
            --output-signature "$sig" \
            --output-certificate "$cert" \
            "$binary"
    else
        cosign sign-blob \
            --yes \
            --bundle "$bundle" \
            --output-signature "$sig" \
            --output-certificate "$cert" \
            "$binary"
    fi

    [ -s "$bundle" ] || fail "cosign token/OIDC signing did not produce required bundle: ${bundle}"
    [ -s "$sig" ] || fail "cosign token/OIDC signing did not produce required signature: ${sig}"
    [ -s "$cert" ] || fail "cosign token/OIDC signing did not produce required certificate: ${cert}"
}

sign_release_assets() {
    if ! is_tag_release; then
        echo "Not a tag release; skipping cosign signing."
        return
    fi

    require_cmd cosign "cosign is required for tag release signing"

    signing_mode=""
    if resolve_cosign_key; then
        signing_mode="key"
        echo "Signing release assets with cosign key/KMS authority."
    elif has_sigstore_token_authority; then
        signing_mode="token"
        echo "Signing release assets with cosign token/OIDC authority."
    else
        fail "cosign signing authority is missing; set COSIGN_KEY/PERMANU_COSIGN_KEY for enterprise BYOS KMS/key signing, or SIGSTORE_ID_TOKEN/PERMANU_SIGSTORE_ID_TOKEN/GitHub Actions OIDC for explicit token signing"
    fi

    for artifact in $artifact_names; do
        if [ "$signing_mode" = "key" ]; then
            sign_release_asset_with_key "$artifact"
        else
            sign_release_asset_with_token "$artifact"
        fi
    done
}

load_cargo_env
require_cmd cargo "cargo is required to build Dwaar release assets"
require_cmd rustup "rustup is required to install Dwaar release targets"

mkdir -p "$dist_dir"
rm -f "${dist_dir}"/dwaar-* "${dist_dir}/SHASUMS.txt"

build_linux_amd64
build_linux_arm64
build_darwin_arm64
write_checksums
sign_release_assets
