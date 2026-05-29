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

with_rustup_lock() {
  lock_root="${RUNNER_TOOL_CACHE:-${TMPDIR:-/tmp}}"
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
    with_rustup_lock run_bounded 300 rustfmt --version
    with_rustup_lock run_bounded 300 clippy-driver --version
    ;;
  audit)
    if ! command -v cargo-audit >/dev/null 2>&1; then
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
