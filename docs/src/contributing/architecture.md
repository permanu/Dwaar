# Architecture for Contributors

A technical orientation for people contributing code to Dwaar. Read this before touching core request-path code.

## Request Pipeline

Every HTTP(S) request passes through a fixed sequence of Pingora hooks implemented in `dwaar-core`:

1. `request_filter` — TLS SNI selection, early rejection (block lists, size limits)
2. Route lookup — `RouteTable::match_request` returns a `RouteHandle` (or 404)
3. Plugin chain — each `DwaarPlugin` on the matched route runs `request_filter` then `upstream_request_filter`
4. `upstream_connect` — connection pooling / upstream selection
5. `upstream_request_filter` — header rewriting, hop-by-hop stripping
6. `upstream_response_filter` — response header rewriting, JS injection
7. `logging` — async hand-off to `dwaar-log`

See [Request Lifecycle](../architecture/request-lifecycle.md) for the full hook sequence with timing notes.

## Config Flow

```
Dwaarfile on disk
    │
    ▼
dwaar-config::tokenize()        — splits raw text into tokens
    │
    ▼
dwaar-config::parse()           — builds DwaarConfig (validated, typed)
    │
    ▼
dwaar-core::compile_routes()    — converts DwaarConfig → RouteTable
    │
    ▼
ArcSwap<RouteTable>             — stored in the shared ServerState
    │
    ▼
hot-reload watcher              — on file change, repeats parse → compile
                                  then calls ArcSwap::store()
```

The `ArcSwap::store()` at the end is the only moment the route table is replaced. All in-flight requests hold a prior `Arc` guard and complete against the old table uninterrupted.

## Key Patterns

### ArcSwap for lock-free config reads

`dwaar-core` wraps the live `RouteTable` in an `ArcSwap<RouteTable>`. Each request calls `load()` once at the start of `request_filter`, giving it a cheap `Arc` snapshot. No mutex is held across the proxy work.

### Channel-based log pipeline

`dwaar-log` uses a bounded `tokio::sync::mpsc` channel. The request handler sends a `RequestRecord` (a plain struct, no I/O) and returns immediately. A `BackgroundService` drains the channel and writes to disk or a socket in batches. Backpressure is handled by dropping log entries (with a counter) rather than blocking requests.

### DwaarPlugin trait

```rust
#[async_trait]
pub trait DwaarPlugin: Send + Sync {
    fn name(&self) -> &'static str;

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut DwaarContext,
    ) -> Result<Option<Response<Vec<u8>>>>;

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut DwaarContext,
    ) -> Result<()>;
}
```

Returning `Some(response)` from `request_filter` short-circuits the pipeline and sends that response directly to the client. Built-in plugins (`RateLimit`, `ForwardAuth`) live in `dwaar-plugins`. The WASM plugin host wraps external `.wasm` modules in the same trait.

### BackgroundService pattern

Any async work that outlives a single request must be a `BackgroundService` registered before `run_forever()`. Never call `tokio::spawn` at request time — it bypasses Pingora's shutdown sequencing and can cause panics on worker thread teardown.

## Where to Start

| Goal | Start here |
|------|-----------|
| Change how routes are matched | `dwaar-core/src/upstream.rs`, `dwaar-core/src/context.rs` |
| Add a new Dwaarfile directive | `dwaar-config/src/parser/directives.rs`, then `dwaar-config/src/model.rs` |
| Write a new built-in plugin | `dwaar-plugins/src/plugin.rs` — implement `DwaarPlugin`, register in `dwaar-ingress` |
| Change request/response header handling | `dwaar-core/src/proxy.rs` |
| Add an admin API endpoint | `dwaar-admin/src/service.rs` |
| Change how logs are written | `dwaar-log/src/writer.rs` and `dwaar-log/src/request_log.rs` |
| Add a new analytics metric | `dwaar-analytics/src/aggregation/service.rs`, `dwaar-analytics/src/prometheus.rs` |

New to the codebase? Start in `dwaar-config` — the parser is self-contained, well-tested, and gives you a feel for Dwaar's data model before touching live request code.

## Related

- [Architecture Overview](../architecture/overview.md)
- [Crate Map](../architecture/crate-map.md)
- [Request Lifecycle](../architecture/request-lifecycle.md)
- [Development Setup](development.md)
