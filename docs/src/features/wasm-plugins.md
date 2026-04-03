# WASM Plugins

Dwaar lets you extend the proxy with plugins written in any language that targets `wasm32-wasip2`. Plugins run inside a sandboxed WebAssembly runtime and hook into three points in the request lifecycle: before the upstream receives the request, after the upstream sends a response, and for each body chunk that flows through.

## What plugins can and cannot do

Plugins receive a snapshot of the request or response and return one of three actions:

| Action | Effect |
|--------|--------|
| `continue` | Pass control to the next plugin, then to the proxy |
| `respond` | Short-circuit with an error response (returns HTTP 503 today; configurable in a future release) |
| `skip` | Stop the plugin chain but let the proxy continue normally |

**Sandboxing guarantees.** Each plugin call runs in an isolated wasmtime store with no access to the filesystem, no network calls, and hard caps on memory and CPU:

- **Memory** — capped at 16 MiB by default. `memory.grow` beyond the cap returns -1 rather than trapping.
- **CPU (fuel)** — capped at 1,000,000 Wasm instructions per hook call. When the budget runs out, the call traps and Dwaar continues without the plugin (fail-open).
- **Wall clock** — capped at 50 ms per call via epoch interruption. Catches slow loops that don't exhaust fuel quickly.

Plugins cannot make outbound connections, read files, or share state between requests. Each hook call gets a fresh store — there are no mutable globals that persist across requests.

## Quick start

**1. Install the WASM target.**

```bash
rustup target add wasm32-wasip2
```

**2. Build the hello-world example.**

```bash
cd examples/wasm-plugins/hello-world
./build.sh
```

The output is at `target/wasm32-wasip2/release/hello_world_plugin.wasm`.

**3. Add the plugin to your Dwaarfile.**

```
example.com {
    wasm_plugin examples/wasm-plugins/hello-world/target/wasm32-wasip2/release/hello_world_plugin.wasm {
        priority 50
    }
    reverse_proxy localhost:8080
}
```

Dwaar loads and JIT-compiles the plugin at startup. Per-request overhead is the cost of a fresh wasmtime store creation plus the plugin's own logic — typically under 100 µs for simple plugins.

## WIT interface reference

The plugin interface is defined in `crates/dwaar-plugins/wit/dwaar-plugin.wit`. Every plugin must implement three exports.

### `on-request`

```wit
export on-request: func(req: request-info) -> plugin-action;
```

Called during `request_filter()`, before Dwaar forwards the request upstream. The `request-info` record contains:

| Field | Type | Description |
|-------|------|-------------|
| `method` | `string` | HTTP method (`GET`, `POST`, …) |
| `path` | `string` | Request path including query string |
| `headers` | `list<header-entry>` | All request headers, names lowercased |
| `is-tls` | `bool` | True when the client connected over HTTPS |
| `client-ip` | `string` | Client IP address, or empty if unavailable |

`header-entry` is a record with two string fields: `name` and `value`.

### `on-response`

```wit
export on-response: func(resp: response-info) -> plugin-action;
```

Called during `response_filter()`, after the upstream sends response headers but before they reach the client. The `response-info` record contains:

| Field | Type | Description |
|-------|------|-------------|
| `status` | `u16` | HTTP status code |
| `headers` | `list<header-entry>` | Response headers, names lowercased |

### `on-body`

```wit
export on-body: func(eos: bool) -> plugin-action;
```

Called for each body chunk in `response_body_filter()`. `eos` is `true` on the final chunk of a response.

### `plugin-action`

```wit
enum plugin-action { continue, respond, skip }
```

- `continue` — move to the next plugin
- `respond` — stop the chain and return an error to the client (HTTP 503 today)
- `skip` — stop the chain, let the proxy continue

## Resource limits

Dwaar enforces three independent limits on every hook call. The first to fire wins.

| Limit | Default | What it catches |
|-------|---------|-----------------|
| Fuel | 1,000,000 instructions | Tight CPU loops |
| Memory | 16 MiB | Unbounded allocations |
| Timeout | 50 ms | Slow code that doesn't burn fuel quickly |

**To tune limits**, add them to the `wasm_plugin` block in your Dwaarfile:

```
wasm_plugin my-plugin.wasm {
    priority    50
    fuel        500000
    memory_mb   4
    timeout_ms  20
}
```

Lower fuel and memory are safer for third-party plugins you don't control. Raise them only if a legitimate plugin needs more (e.g., a plugin doing non-trivial cryptography).

## Language support

Any language that compiles to `wasm32-wasip2` and supports WIT component model bindings works. Here is what's available today:

| Language | Bindings | Notes |
|----------|----------|-------|
| Rust | `wit-bindgen` | Best support; use `crate-type = ["cdylib"]` |
| C / C++ | `wit-bindgen-c` | Generate bindings from WIT, link as a shared lib |
| Go | `wit-bindgen-go` or TinyGo | TinyGo has better WASM size; standard Go via WASI preview 2 |
| Zig | native | Zig's `wasm32-wasi` target works; component model requires a wrapper |
| AssemblyScript | `componentize-js` | Via a Wasm component adapter |

The compiled `.wasm` file must be a WASM component, not a core module. If your toolchain produces a core module, use `wasm-tools component new` to wrap it.

## Error handling

Dwaar is designed to keep serving traffic even when a plugin fails.

**Fail-open.** If a plugin hook traps (fuel exhausted, timeout, memory overflow, or any Wasm trap), Dwaar logs a warning and returns `continue`. The request proceeds as if the plugin wasn't there.

**Auto-disable.** After 10 consecutive traps, Dwaar disables the plugin and logs an error. All future hook calls are skipped immediately — the proxy doesn't waste time trying to instantiate a broken module. The plugin is re-enabled when you fix the `.wasm` binary and reload the config.

```
WARN  plugin=my-plugin hook=on-request consecutive_traps=3 error="fuel exhausted" WASM hook trapped — returning Continue (fail-open)
ERROR plugin=my-plugin hook=on-request traps=10 WASM plugin disabled after too many consecutive traps — fix the module and reload config to re-enable
```

**Config reload.** Sending `SIGHUP` (or running `dwaar reload`) reloads the Dwaarfile and recompiles all `wasm_plugin` entries from scratch. A previously disabled plugin is re-enabled if you supply a new `.wasm` binary at the same path.

## Writing your own plugin

Start from the hello-world example at `examples/wasm-plugins/hello-world/`. The steps are:

1. Create a new Rust crate with `crate-type = ["cdylib"]`.
2. Add `wit-bindgen` as a dependency.
3. Copy `crates/dwaar-plugins/wit/dwaar-plugin.wit` into your crate's `wit/` directory.
4. Call `wit_bindgen::generate!` with `path: "wit/dwaar-plugin.wit"` and `world: "dwaar-plugin"`.
5. Implement the three hook functions on a struct and call `export!(YourStruct)`.
6. Build with `cargo build --target wasm32-wasip2 --release`.
7. Point `wasm_plugin` at the output `.wasm` file in your Dwaarfile.

Keep plugins small and fast. Every millisecond a plugin adds is a millisecond of latency on every request it touches.
