#!/usr/bin/env bash
# Copyright (C) 2026 Permanu
# SPDX-License-Identifier: BSL-1.1
#
# Build the hello-world plugin as a WASM component targeting wasm32-wasip2.
#
# Prerequisites:
#   rustup target add wasm32-wasip2
#
# The output .wasm file is a WASM component (not a core module), which is what
# Dwaar's wasmtime-based plugin runtime expects.

set -euo pipefail

cargo build --target wasm32-wasip2 --release

echo "Built: target/wasm32-wasip2/release/hello_world_plugin.wasm"
