#!/usr/bin/env sh
set -eu

mode="${PERMANU_RUST_MODE:-${1:-cargo}}"

ensure_writable_tmpdir() {
  tmp="${TMPDIR:-}"
  if [ -z "$tmp" ] || [ ! -d "$tmp" ] || [ ! -w "$tmp" ]; then
    export TMPDIR=/tmp
  fi
  if [ -z "${TMP:-}" ] || [ ! -d "${TMP:-}" ] || [ ! -w "${TMP:-}" ]; then
    export TMP="$TMPDIR"
  fi
  if [ -z "${TEMP:-}" ] || [ ! -d "${TEMP:-}" ] || [ ! -w "${TEMP:-}" ]; then
    export TEMP="$TMPDIR"
  fi
}

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
    command_status="$?"
    kill "$watcher" >/dev/null 2>&1 || true
    wait "$watcher" 2>/dev/null || true
    if [ "$command_status" -eq 137 ] || [ "$command_status" -eq 143 ]; then
      echo "command timed out after ${seconds}s: $*" >&2
      return 124
    fi
    return "$command_status"
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
  command_status="$?"
  set -e
  rmdir "$lock" 2>/dev/null || rm -rf "$lock"
  return "$command_status"
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
  channel="$(rust_channel)"
  components=""
  case "$mode" in
    quality) components="--component rustfmt --component clippy" ;;
  esac

  echo "checking active Rust toolchain for $channel/$mode"
  if active_toolchain_healthy "$channel"; then
    echo "using active Rust toolchain for $channel"
    return
  fi

  if ! command -v rustup >/dev/null 2>&1; then
    return
  fi

  echo "checking Rust toolchain $channel for $mode"
  if rustup_toolchain_healthy "$channel"; then
    echo "using existing Rust toolchain $channel"
    return
  fi

  echo "Rust toolchain $channel is missing or incomplete; reinstalling" >&2
  with_rustup_lock run_bounded 300 rustup toolchain uninstall "$channel" >/dev/null 2>&1 || true
  echo "installing Rust toolchain $channel for $mode"
  # shellcheck disable=SC2086
  with_rustup_lock run_bounded 1200 rustup toolchain install "$channel" --profile minimal $components

  if rustup_toolchain_healthy "$channel"; then
    return
  fi

  echo "Rust toolchain $channel is still incomplete after reinstall" >&2
  exit 1
}

rustup_toolchain_healthy() {
  channel="$1"
  set +e
  rustup run "$channel" rustc --version >/dev/null 2>&1
  rustc_ok="$?"
  rustup run "$channel" cargo --version >/dev/null 2>&1
  cargo_ok="$?"
  rustfmt_ok=0
  clippy_ok=0
  if [ "$mode" = "quality" ]; then
    rustup run "$channel" rustfmt --version >/dev/null 2>&1
    rustfmt_ok="$?"
    rustup run "$channel" clippy-driver --version >/dev/null 2>&1
    clippy_ok="$?"
  fi
  set -e

  if [ "$rustc_ok" -eq 0 ] && [ "$cargo_ok" -eq 0 ] && [ "$rustfmt_ok" -eq 0 ] && [ "$clippy_ok" -eq 0 ]; then
    return
  fi
  return 1
}

active_toolchain_healthy() {
  channel="$1"
  set +e
  rustc_version="$(rustc --version 2>/dev/null)"
  rustc_ok="$?"
  cargo --version >/dev/null 2>&1
  cargo_ok="$?"
  rustfmt_ok=0
  clippy_ok=0
  if [ "$mode" = "quality" ]; then
    rustfmt --version >/dev/null 2>&1
    rustfmt_ok="$?"
    clippy-driver --version >/dev/null 2>&1
    clippy_ok="$?"
  fi
  set -e

  case "$rustc_version" in
    "rustc $channel"|"rustc $channel "*) version_ok=0 ;;
    "rustc $channel."*) version_ok=0 ;;
    *) version_ok=1 ;;
  esac

  if [ "$rustc_ok" -eq 0 ] && [ "$cargo_ok" -eq 0 ] && [ "$rustfmt_ok" -eq 0 ] && [ "$clippy_ok" -eq 0 ] && [ "$version_ok" -eq 0 ]; then
    return
  fi
  return 1
}

case "${CARGO_HOME:-}" in
  "") ;;
  *) export PATH="$CARGO_HOME/bin:$PATH" ;;
esac

case ":${PATH:-}:" in
  *":/usr/local/cargo/bin:"*) ;;
  *) export PATH="/usr/local/cargo/bin:${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}" ;;
esac

if ! command -v cargo >/dev/null 2>&1 && [ -n "${HOME:-}" ]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi

ensure_writable_tmpdir
ensure_rustup_toolchain

if [ -z "${CARGO_BUILD_JOBS:-}" ]; then
  export CARGO_BUILD_JOBS=1
fi
if [ -z "${CARGO_INCREMENTAL:-}" ]; then
  export CARGO_INCREMENTAL=0
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
