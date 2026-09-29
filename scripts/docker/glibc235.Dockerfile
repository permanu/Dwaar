# Builder for Dwaar Linux binaries that run on glibc 2.35+ (Ubuntu 22.04+,
# Debian 12+). Used by scripts/build-linux-glibc235.sh; not a runtime image.
#
# The base is pinned by digest (the multi-arch index of ubuntu:22.04), so the
# glibc the binaries link against cannot drift. The image carries a native
# toolchain for its own architecture plus a cross toolchain for the other one
# (amd64 <-> arm64), so one builder produces both binaries without emulation.
ARG UBUNTU_IMAGE=ubuntu:22.04@sha256:b8b6ee6aa931ecd9d0d952abc34dc0e5f7c6a30c6bb71b079fe399fde0329c02
FROM ${UBUNTU_IMAGE}

ARG RUST_TOOLCHAIN=1.94
ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      arm64) cross=crossbuild-essential-amd64 ;; \
      amd64) cross=crossbuild-essential-arm64 ;; \
      *) echo "unsupported builder architecture: $arch" >&2; exit 1 ;; \
    esac; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates curl build-essential pkg-config cmake perl make \
      protobuf-compiler binutils "$cross"; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh; \
    sh /tmp/rustup-init.sh -y --no-modify-path --profile minimal \
      --default-toolchain "${RUST_TOOLCHAIN}" \
      --component rustfmt --component clippy; \
    rm /tmp/rustup-init.sh; \
    rustup target add --toolchain "${RUST_TOOLCHAIN}" \
      x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; \
    rustc --version; cargo --version; ldd --version | head -n1
