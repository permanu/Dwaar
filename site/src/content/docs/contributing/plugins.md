---
title: "Plugin Development"
---

# Plugin Development

> This guide will be written when the plugin system is implemented (ISSUE-036).

Dwaar supports two types of plugins:

## Native Plugins (Rust)

Implement the `DwaarPlugin` trait and compile into the binary.

## WASM Plugins (Any Language)

Write plugins in any language that compiles to WebAssembly. Load at runtime without recompiling Dwaar. (Commercial license feature.)
