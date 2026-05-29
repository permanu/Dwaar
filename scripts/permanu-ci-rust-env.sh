#!/usr/bin/env sh
set -eu

mode="${1:-cargo}"

run_bounded() {
  seconds="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$seconds" "$@"
  else
    "$@"
  fi
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required CI runner command: $1" >&2
    exit 1
  fi
}

case "${CARGO_HOME:-}" in
  "") ;;
  *) export PATH="$CARGO_HOME/bin:$PATH" ;;
esac

if ! command -v cargo >/dev/null 2>&1 && [ -n "${HOME:-}" ]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi

require_cmd cargo
require_cmd rustc

cargo_bin_dir="$(dirname "$(command -v cargo)")"
case ":$PATH:" in
  *":$cargo_bin_dir:"*) ;;
  *) export PATH="$cargo_bin_dir:$PATH" ;;
esac

if [ -n "${GITHUB_PATH:-}" ]; then
  printf '%s\n' "$cargo_bin_dir" >> "$GITHUB_PATH"
fi

case "$mode" in
  cargo)
    ;;
  quality)
    require_cmd rustfmt
    require_cmd clippy-driver
    ;;
  audit)
    if ! command -v cargo-audit >/dev/null 2>&1; then
      run_bounded 900 cargo install cargo-audit --locked
    fi
    ;;
  release)
    case "${GITHUB_REF:-}" in
      refs/tags/v*) require_cmd rustup ;;
    esac
    ;;
  *)
    echo "unknown rust CI setup mode: $mode" >&2
    exit 1
    ;;
esac

rustc --version
cargo --version
