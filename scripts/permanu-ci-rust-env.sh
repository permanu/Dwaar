#!/usr/bin/env sh
set -eu

mode="${1:-cargo}"

run_bounded() {
  seconds="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$seconds" "$@"
  else
    "$@" &
    child="$!"
    watcher=""
    (
      sleep "$seconds"
      kill "$child" >/dev/null 2>&1 || true
      sleep 5
      kill -9 "$child" >/dev/null 2>&1 || true
    ) &
    watcher="$!"
    wait "$child"
    status="$?"
    kill "$watcher" >/dev/null 2>&1 || true
    wait "$watcher" 2>/dev/null || true
    if [ "$status" -eq 137 ] || [ "$status" -eq 143 ]; then
      echo "command timed out after ${seconds}s: $*" >&2
      return 124
    fi
    return "$status"
  fi
}

with_rustup_lock() {
  lock_root="${PERMANU_RUSTUP_LOCK_ROOT:-/var/tmp/permanu-ci}"
  mkdir -p "$lock_root"
  lock="$lock_root/permanu-rustup.lock"
  waited=0
  while ! mkdir "$lock" 2>/dev/null; do
    if find "$lock" -maxdepth 0 -mmin +10 >/dev/null 2>&1; then
      rm -rf "$lock"
      continue
    fi
    waited=$((waited + 2))
    if [ "$waited" -gt 900 ]; then
      echo "timed out waiting for rustup lock: $lock" >&2
      exit 1
    fi
    sleep 2
  done

  set +e
  "$@"
  status="$?"
  set -e
  rmdir "$lock" 2>/dev/null || rm -rf "$lock"
  return "$status"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required CI runner command: $1" >&2
    exit 1
  fi
}

rust_channel() {
  if [ -f rust-toolchain.toml ]; then
    sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' rust-toolchain.toml | head -n 1
    return
  fi
  if [ -f rust-toolchain ]; then
    head -n 1 rust-toolchain
    return
  fi
  printf '%s\n' stable
}

ensure_rustup_toolchain() {
  if ! command -v rustup >/dev/null 2>&1; then
    return
  fi

  channel="$(rust_channel)"
  components=""
  case "$mode" in
    quality) components="--component rustfmt --component clippy" ;;
  esac

  echo "ensuring Rust toolchain $channel for $mode"
  # shellcheck disable=SC2086
  with_rustup_lock run_bounded 1200 rustup toolchain install "$channel" --profile minimal $components

  echo "verifying Rust toolchain $channel"
  set +e
  rustup run "$channel" rustc --version >/dev/null 2>&1
  rustc_ok="$?"
  rustup run "$channel" cargo --version >/dev/null 2>&1
  cargo_ok="$?"
  set -e
  if [ "$rustc_ok" -eq 0 ] && [ "$cargo_ok" -eq 0 ]; then
    return
  fi

  echo "rustup toolchain $channel is incomplete; reinstalling" >&2
  with_rustup_lock run_bounded 300 rustup toolchain uninstall "$channel" >/dev/null 2>&1 || true
  echo "reinstalling Rust toolchain $channel"
  # shellcheck disable=SC2086
  with_rustup_lock run_bounded 1200 rustup toolchain install "$channel" --profile minimal $components
}

case "${CARGO_HOME:-}" in
  "") ;;
  *) export PATH="$CARGO_HOME/bin:$PATH" ;;
esac

if ! command -v cargo >/dev/null 2>&1 && [ -n "${HOME:-}" ]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi

ensure_rustup_toolchain

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
    echo "checking rustfmt and clippy-driver"
    with_rustup_lock run_bounded 300 rustfmt --version
    with_rustup_lock run_bounded 300 clippy-driver --version
    ;;
  audit)
    if ! command -v cargo-audit >/dev/null 2>&1; then
      echo "installing cargo-audit"
      with_rustup_lock run_bounded 900 cargo install cargo-audit --locked
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

with_rustup_lock run_bounded 900 rustc --version
with_rustup_lock run_bounded 900 cargo --version
