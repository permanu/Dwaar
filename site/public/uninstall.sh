#!/bin/sh
# Dwaar uninstaller — https://dwaar.dev
# Usage: curl -fsSL https://dwaar.dev/uninstall.sh | sh
set -eu

INSTALL_DIR="${DWAAR_INSTALL_DIR:-/usr/local/bin}"
BINARY="${INSTALL_DIR}/dwaar"

if [ ! -f "$BINARY" ]; then
  printf "dwaar not found at %s\n" "$BINARY" >&2
  exit 1
fi

printf "Removing dwaar from %s\n" "$BINARY"

if [ -w "$INSTALL_DIR" ]; then
  rm -f "$BINARY"
else
  sudo rm -f "$BINARY"
fi

printf "dwaar has been uninstalled\n"
