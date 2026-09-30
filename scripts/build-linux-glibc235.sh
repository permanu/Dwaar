#!/usr/bin/env bash
# Build Dwaar Linux binaries that run on glibc 2.35+ (Ubuntu 22.04+, Debian 12+).
#
# The upstream release builds on ubuntu-latest and needs glibc 2.39. This
# script builds from source inside an ubuntu:22.04 builder (pinned by digest in
# scripts/docker/glibc235.Dockerfile) for linux amd64 and arm64: the builder's
# own architecture natively, the other one with Ubuntu's cross toolchain, so no
# emulation is needed. It refuses a binary that references a glibc symbol
# version newer than 2.35, writes the binaries and their SHA-256 files to the
# output directory and, unless --no-verify, runs `--version` of every binary
# the local Docker can execute in debian:12 and ubuntu:22.04 containers.
#
# Usage: scripts/build-linux-glibc235.sh [--out DIR] [--arch amd64|arm64|all] [--no-verify]
#
# Environment:
#   DOCKER                          docker binary (default: docker)
#   DWAAR_GLIBC_BUILDER_IMAGE       builder image tag (default: dwaar-glibc235-builder:rust-1.94)
#   DWAAR_GLIBC_TARGET_VOLUME       cargo target volume (default: dwaar-glibc235-target)
#   CARGO_REGISTRY_VOLUME           cargo registry volume (default: permanu-cargo-registry)
#   DWAAR_VERIFY_IMAGES             images for the run check (default: "debian:12 ubuntu:22.04")
set -euo pipefail

GLIBC_FLOOR="2.35"

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="${repo_root}/dist/glibc235"
arches="amd64 arm64"
verify=1

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --out)
            [ $# -ge 2 ] || fail "--out needs a directory"
            out_dir="$2"
            shift 2
            ;;
        --arch)
            [ $# -ge 2 ] || fail "--arch needs amd64, arm64 or all"
            case "$2" in
                amd64 | arm64) arches="$2" ;;
                all) arches="amd64 arm64" ;;
                *) fail "unknown --arch: $2" ;;
            esac
            shift 2
            ;;
        --no-verify)
            verify=0
            shift
            ;;
        -h | --help)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) fail "unknown argument: $1" ;;
    esac
done

docker_bin="${DOCKER:-docker}"
image="${DWAAR_GLIBC_BUILDER_IMAGE:-dwaar-glibc235-builder:rust-1.94}"
target_volume="${DWAAR_GLIBC_TARGET_VOLUME:-dwaar-glibc235-target}"
registry_volume="${CARGO_REGISTRY_VOLUME:-permanu-cargo-registry}"
verify_images="${DWAAR_VERIFY_IMAGES:-debian:12 ubuntu:22.04}"

command -v "$docker_bin" >/dev/null 2>&1 || fail "docker not found (set DOCKER)"

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"

echo "==> building builder image ${image}"
"$docker_bin" build \
    --tag "$image" \
    --file "${repo_root}/scripts/docker/glibc235.Dockerfile" \
    "${repo_root}/scripts/docker"

# The build runs as root in the container (the registry volume is root-owned);
# the outputs are handed back to the invoking user at the end.
echo "==> building dwaar for: ${arches}"
# The inner script expands inside the container, not here.
# shellcheck disable=SC2016
"$docker_bin" run --rm \
    --volume "${repo_root}:/src:ro" \
    --volume "${target_volume}:/target" \
    --volume "${registry_volume}:/usr/local/cargo/registry" \
    --volume "${out_dir}:/out" \
    --env CARGO_TARGET_DIR=/target \
    --env CARGO_TERM_COLOR=never \
    --env "ARCHES=${arches}" \
    --env "GLIBC_FLOOR=${GLIBC_FLOOR}" \
    --env "HOST_UID=$(id -u)" \
    --env "HOST_GID=$(id -g)" \
    --workdir /src \
    "$image" \
    bash -euo pipefail -c '
host_arch="$(dpkg --print-architecture)"
for arch in $ARCHES; do
    case "$arch" in
        amd64) triple=x86_64-unknown-linux-gnu; gnu=x86_64-linux-gnu ;;
        arm64) triple=aarch64-unknown-linux-gnu; gnu=aarch64-linux-gnu ;;
    esac
    env_triple="$(echo "$triple" | tr "a-z-" "A-Z_")"
    cc_triple="$(echo "$triple" | tr "-" "_")"
    if [ "$arch" != "$host_arch" ]; then
        export "CARGO_TARGET_${env_triple}_LINKER=${gnu}-gcc"
        export "CC_${cc_triple}=${gnu}-gcc"
        export "CXX_${cc_triple}=${gnu}-g++"
        export "AR_${cc_triple}=${gnu}-ar"
    fi
    echo "--> cargo build ${triple} (builder ${host_arch})"
    cargo build --release --locked -p dwaar-cli --bin dwaar --target "$triple"
    bin="/target/${triple}/release/dwaar"

    # Highest GLIBC_x.y symbol version the binary needs; readelf reads any arch.
    newest="$(readelf --version-info --wide "$bin" \
        | grep -o "GLIBC_[0-9][0-9.]*" | sed "s/GLIBC_//" | sort -Vu | tail -n1)"
    [ -n "$newest" ] || { echo "no GLIBC symbol versions in $bin" >&2; exit 1; }
    highest="$(printf "%s\n%s\n" "$newest" "$GLIBC_FLOOR" | sort -V | tail -n1)"
    if [ "$highest" != "$GLIBC_FLOOR" ]; then
        echo "dwaar-linux-${arch} needs GLIBC_${newest}, above the ${GLIBC_FLOOR} floor" >&2
        exit 1
    fi
    echo "--> dwaar-linux-${arch}: newest glibc symbol GLIBC_${newest} (floor ${GLIBC_FLOOR})"

    install -m 0755 "$bin" "/out/dwaar-linux-${arch}"
    (cd /out && sha256sum "dwaar-linux-${arch}" > "dwaar-linux-${arch}.sha256")
    chown "$HOST_UID:$HOST_GID" "/out/dwaar-linux-${arch}" "/out/dwaar-linux-${arch}.sha256"
done
'

(
    cd "$out_dir"
    cat dwaar-linux-*.sha256 > SHA256SUMS
)
echo "==> outputs in ${out_dir}"
cat "${out_dir}/SHA256SUMS"

[ "$verify" -eq 1 ] || exit 0

# A foreign architecture runs only through a binfmt handler (qemu or Rosetta)
# in the Docker VM/host; probe for one instead of pulling images that could
# never start.
case "$("$docker_bin" info --format '{{.Architecture}}')" in
    aarch64 | arm64) docker_arch=arm64 ;;
    x86_64 | amd64) docker_arch=amd64 ;;
    *) docker_arch=unknown ;;
esac
can_run() {
    [ "$1" = "$docker_arch" ] && return 0
    case "$1" in
        amd64) pattern='x86_64|x86-64|rosetta' ;;
        arm64) pattern='aarch64' ;;
    esac
    "$docker_bin" run --rm --platform "linux/${docker_arch}" ubuntu:22.04 \
        sh -c "grep -lE '${pattern}' /proc/sys/fs/binfmt_misc/* 2>/dev/null | grep -q ." \
        >/dev/null 2>&1
}

echo "==> run check (--version)"
for arch in $arches; do
    if ! can_run "$arch"; then
        echo "SKIP dwaar-linux-${arch}: this Docker (${docker_arch}) has no linux/${arch} emulation"
        continue
    fi
    for img in $verify_images; do
        printf '%s on %s: ' "dwaar-linux-${arch}" "$img"
        "$docker_bin" run --rm --platform "linux/${arch}" \
            --volume "${out_dir}:/dist:ro" "$img" "/dist/dwaar-linux-${arch}" --version
    done
done
