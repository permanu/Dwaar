// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// hello-world-plugin — minimal Dwaar WASM plugin example.
//
// This plugin shows the skeleton every Dwaar plugin must implement: the three
// lifecycle hooks (on-request, on-response, on-body) and how the WIT bindings
// wire them to the host engine.
//
// What it does: inspect the inbound request and pass control to the next
// plugin in the chain. A real plugin would act on req.path, req.headers, etc.
//
// Note: header mutation (e.g. adding X-Hello: World) requires the host to read
// back modified headers from the plugin's return value. That capability is
// tracked in ISSUE-097. For now, plugins return an action and the host acts on
// it; modifying headers from a plugin requires a future WIT extension.

wit_bindgen::generate!({
    // Path to the WIT file is relative to this crate's root directory.
    // The workaround for out-of-crate WIT paths is a symlink or a path
    // that the build system can resolve. When building inside the Dwaar
    // workspace you can point directly at the shared WIT definition; when
    // building standalone, copy dwaar-plugin.wit into this crate's wit/ dir.
    path: "wit/dwaar-plugin.wit",
    world: "dwaar-plugin",
});

// `export!` registers this struct as the implementation of the world's exports.
export!(HelloWorldPlugin);

struct HelloWorldPlugin;

impl Guest for HelloWorldPlugin {
    /// Called once per inbound request, before it reaches the upstream.
    ///
    /// `req` carries the method, path, lowercased headers, TLS flag, and client
    /// IP — everything the plugin needs to make a routing decision.
    fn on_request(req: RequestInfo) -> PluginAction {
        // The request-info record carries method, path, headers, is-tls, and
        // client-ip. In a real plugin you'd inspect req.path, check a header,
        // or act on req.client_ip. Here we ignore everything and pass through.
        let _ = req;

        // Pass control to the next plugin (or the proxy itself if this is last).
        PluginAction::Continue
    }

    /// Called once per upstream response, before headers reach the client.
    fn on_response(_resp: ResponseInfo) -> PluginAction {
        PluginAction::Continue
    }

    /// Called for each body chunk flowing through the proxy.
    ///
    /// `eos` is true on the final chunk. Use it to know when the stream ends.
    fn on_body(_eos: bool) -> PluginAction {
        PluginAction::Continue
    }
}
