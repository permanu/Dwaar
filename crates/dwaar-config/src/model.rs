// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Typed representation of a parsed Dwaarfile.
//!
//! These structs are the output of the parser and the input to the
//! route table compiler (ISSUE-012). They represent the full config —
//! not just routing, but TLS, headers, redirects, compression, etc.

use std::net::SocketAddr;

/// Global options from the bare `{ }` block at the very top of a Dwaarfile.
///
/// Caddyfile's global options block controls server-wide settings that
/// aren't tied to a specific site — port assignments, ACME email, debug
/// logging, etc. We parse these so that a valid Caddyfile is always a
/// valid Dwaarfile, even if not all options are acted on yet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlobalOptions {
    /// HTTP port (default: 80). `http_port 8080`
    pub http_port: Option<u16>,
    /// HTTPS port (default: 443). `https_port 8443`
    pub https_port: Option<u16>,
    /// Email for ACME account registration. `email admin@example.com`
    pub email: Option<String>,
    /// Enable debug logging. `debug` (bare flag, no value)
    pub debug: bool,
    /// Auto HTTPS behavior. `auto_https off` / `auto_https disable_redirects`
    pub auto_https: Option<String>,
    /// How long to wait for in-flight requests before force-closing a
    /// removed route (ISSUE-075). Default: 30 seconds.
    pub drain_timeout_secs: Option<u64>,
    /// Connection-level timeouts for slow loris protection (ISSUE-076).
    pub timeouts: Option<TimeoutsConfig>,
    /// Enable HTTP/3 (QUIC) alongside HTTP/2. Configured via `servers { h3 on }`.
    /// When enabled, Dwaar binds a UDP listener and advertises `Alt-Svc: h3`
    /// on HTTP/2 responses so browsers can upgrade (ISSUE-079).
    pub h3_enabled: bool,
    /// Automatic binary update configuration.
    /// When set, a background service periodically checks GitHub Releases
    /// for newer versions and applies them within the configured window.
    pub auto_update: Option<AutoUpdateConfig>,
    /// Top-level `layer4 { ... }` app block — raw L4 TCP proxy servers.
    /// Compiled into runtime `CompiledL4Server`s by `compile_l4_servers`.
    pub layer4: Option<Layer4Config>,
    /// Listener-wrapper form: sites that share a listener with an L4 matcher
    /// front (caddy-l4 fall-through). Compiled by `compile_l4_wrappers`.
    pub layer4_listener_wrappers: Vec<Layer4ListenerWrapper>,
    /// Options we recognized but don't act on — stored so we never error
    /// on valid Caddyfile syntax we haven't implemented yet.
    pub passthrough: Vec<(String, Vec<String>)>,
}

/// Connection-level timeouts for slow loris protection (ISSUE-076).
///
/// Controls how long Dwaar waits for slow or idle client connections.
/// Values that map to Pingora's session-level APIs are applied per-request;
/// `max_requests` maps to `HttpServerOptions::keepalive_request_limit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutsConfig {
    /// Max seconds to receive complete request headers. Pingora's `read_timeout`
    /// covers this phase on a fresh connection (default: 60s in Pingora).
    pub header_secs: u32,
    /// Max seconds to receive complete request body.
    pub body_secs: u32,
    /// Max idle seconds on a keep-alive connection between requests.
    pub keepalive_secs: u32,
    /// Max requests per keep-alive connection before forcing a reconnect.
    pub max_requests: u32,
}

impl Default for TimeoutsConfig {
    fn default() -> Self {
        Self {
            header_secs: 10,
            body_secs: 30,
            keepalive_secs: 60,
            max_requests: 1000,
        }
    }
}

/// Automatic binary update configuration.
///
/// ```text
/// {
///     auto_update {
///         channel stable
///         check_interval 6h
///         window 03:00-05:00
///         on_new_version reload
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoUpdateConfig {
    /// Release channel to follow. Only `stable` is supported.
    pub channel: String,
    /// How often to check releases.dwaar.dev for a new version (seconds).
    /// Jittered internally to avoid thundering herd.
    pub check_interval_secs: u64,
    /// UTC maintenance window during which the binary replacement is
    /// allowed. Format: `HH:MM-HH:MM`. Outside the window, a discovered
    /// update is deferred until the next window opens.
    /// `None` means updates can be applied at any time.
    pub window: Option<(u16, u16)>,
    /// What to do when a new version is installed.
    ///   - `reload`  — exec `dwaar upgrade` for zero-downtime swap (default)
    ///   - `notify`  — download + replace binary but don't restart
    pub on_new_version: AutoUpdateAction,
}

impl Default for AutoUpdateConfig {
    fn default() -> Self {
        Self {
            channel: "stable".to_string(),
            check_interval_secs: 6 * 3600, // 6 hours
            window: None,
            on_new_version: AutoUpdateAction::Reload,
        }
    }
}

/// Action to take after a new version is installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoUpdateAction {
    /// Zero-downtime upgrade via Pingora FD transfer.
    Reload,
    /// Replace binary on disk but don't restart — operator handles it.
    Notify,
}

/// A fully parsed Dwaarfile — an optional global options block followed
/// by zero or more site blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwaarConfig {
    /// Global options from the bare `{ }` block, if present.
    pub global_options: Option<GlobalOptions>,
    pub sites: Vec<SiteBlock>,
}

/// One site block: a domain (or pattern) with its directives.
///
/// ```text
/// api.example.com {
///     @api {
///         path /api/*
///         method GET POST
///     }
///     reverse_proxy localhost:3000
///     tls auto
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteBlock {
    /// The domain or pattern this block matches.
    /// Examples: `"api.example.com"`, `"*.example.com"`, `":8080"`
    pub address: String,

    /// Named matcher definitions (`@name { ... }`) declared in this site block.
    /// These are resolved at compile time; no per-request dynamic dispatch.
    pub matchers: Vec<MatcherDef>,

    /// Directives inside the block, in source order.
    pub directives: Vec<Directive>,
}

// ── Named matcher types ───────────────────────────────────────────────────────

/// A named matcher definition: `@name { conditions }` or `@name condition`.
///
/// All conditions use AND logic — every condition must match for the matcher
/// to pass. This mirrors Caddy's named matcher semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatcherDef {
    /// Name without the `@` prefix (e.g. `"api"` for `@api`).
    pub name: String,
    /// Matcher conditions — ALL must match (AND logic).
    pub conditions: Vec<MatcherCondition>,
}

/// A single matcher condition inside a named matcher block.
///
/// Conditions correspond to Caddyfile matcher directives as documented at
/// <https://caddyserver.com/docs/caddyfile/matchers>.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatcherCondition {
    /// `path /foo /bar` — match URI paths, supports `*` wildcards.
    Path(Vec<String>),

    /// `path_regexp [name] pattern` — regex path match.
    PathRegexp {
        /// Optional capture group name for the regexp.
        name: Option<String>,
        /// The regular expression pattern.
        pattern: String,
    },

    /// `host example.com other.com` — match the Host header.
    Host(Vec<String>),

    /// `method GET POST` — match HTTP method(s).
    Method(Vec<String>),

    /// `header X-Foo [value]` — match a request header, optionally by value.
    Header {
        /// Header field name.
        name: String,
        /// Required value; if absent, only presence is checked.
        value: Option<String>,
    },

    /// `header_regexp X-Foo pattern` — regex match on a request header value.
    HeaderRegexp {
        /// Header field name.
        name: String,
        /// The regular expression pattern.
        pattern: String,
    },

    /// `protocol https` — match by protocol (`http` or `https`).
    Protocol(String),

    /// `remote_ip 192.168.0.0/16` — match the peer IP/CIDR.
    RemoteIp(Vec<String>),

    /// `client_ip 10.0.0.0/8` — match client IP (honours X-Forwarded-For).
    ClientIp(Vec<String>),

    /// `query key=value` — match a query string parameter.
    Query(Vec<String>),

    /// `not { conditions }` — negate a set of conditions.
    Not(Vec<MatcherCondition>),

    /// `expression <cel>` — CEL expression, stored as-is (not evaluated here).
    Expression(String),

    /// `file { try_files ... }` — match if the listed files exist on disk.
    File { try_files: Vec<String> },

    /// Unknown condition keyword — stored verbatim for forward compatibility.
    /// No parse error is raised; the keyword and its arguments are preserved.
    Unknown {
        /// The unrecognised keyword.
        keyword: String,
        /// The remaining arguments on the same line / in the same block.
        args: Vec<String>,
    },
}

/// How a directive references a matcher.
///
/// This is compile-time resolved (Guardrail #27 — no per-request dynamic
/// dispatch). `Named` references are looked up in the site's `matchers` Vec
/// during compilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatcherRef {
    /// No matcher specified — matches all requests.
    None,
    /// Inline path pattern like `/api/*` or `*`.
    Inline(String),
    /// Named matcher reference like `@api` (without the `@` prefix).
    Named(String),
}

/// A single directive inside a site block.
///
/// Each variant maps to a Caddyfile-compatible directive.
/// Unknown directives are captured as `Unknown` for clear error reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    /// `reverse_proxy localhost:8080` or `reverse_proxy 10.0.0.1:3000 10.0.0.2:3000`
    ReverseProxy(ReverseProxyDirective),

    /// `tls auto` / `tls off` / `tls internal` / `tls /cert.pem /key.pem`
    Tls(TlsDirective),

    /// `header X-Custom "value"` / `header -Server` (delete)
    Header(HeaderDirective),

    /// `redir /old /new 301`
    Redir(RedirDirective),

    /// `encode gzip` / `encode zstd gzip`
    Encode(EncodeDirective),

    /// `rate_limit 100/s`
    RateLimit(RateLimitDirective),

    /// `ip_filter { allow 10.0.0.0/8; deny 203.0.113.0/24; default allow }`
    IpFilter(IpFilterDirective),

    /// `respond "body" 404` / `respond 204` / `respond "ok"`
    Respond(RespondDirective),

    /// `rewrite /new-path`
    Rewrite(RewriteDirective),

    /// `uri strip_prefix /api` / `uri strip_suffix .html` / `uri replace /old /new`
    Uri(UriDirective),

    /// `basicauth { user hash }` or `basic_auth { user hash }`
    BasicAuth(BasicAuthDirective),

    /// `forward_auth localhost:9091 { uri /api/verify; copy_headers Remote-User }`
    ForwardAuth(ForwardAuthDirective),

    /// `root * /var/www` — sets the filesystem root for `file_server`
    Root(RootDirective),

    /// `file_server` or `file_server browse`
    FileServer(FileServerDirective),

    /// `handle [pattern] { directives }` — first match wins, path NOT stripped
    Handle(HandleDirective),

    /// `handle_path <pattern> { directives }` — first match wins, prefix IS stripped
    HandlePath(HandlePathDirective),

    /// `route [pattern] { directives }` — all matching blocks execute in order
    Route(RouteDirective),

    /// `php_fastcgi localhost:9000` — proxy PHP requests to `FastCGI` backend
    PhpFastcgi(PhpFastcgiDirective),

    /// `log { output file /var/log/access.log; format json; level INFO }`
    Log(LogDirective),

    /// `request_header X-Name "value"` / `request_header -X-Remove`
    RequestHeader(RequestHeaderDirective),

    /// `error "message" 500` or `error 404`
    Error(ErrorDirective),

    /// `abort` — drop the connection immediately
    Abort,

    /// `method GET` — override the HTTP method sent to upstream
    Method(MethodDirective),

    /// `request_body { max_size 10MB }`
    RequestBody(RequestBodyDirective),

    /// `response_body_limit 100MB` — max upstream response size before 502.
    ResponseBodyLimit(ResponseBodyLimitDirective),

    /// `try_files {path}.html {path} /index.html`
    TryFiles(TryFilesDirective),

    /// `handle_errors { respond ... }`
    HandleErrors(HandleErrorsDirective),

    /// `bind 0.0.0.0` or `bind 127.0.0.1 ::1`
    Bind(BindDirective),

    /// `skip_log` or `log_skip` — suppress access log for this site
    SkipLog,

    /// `vars key value`
    Vars(VarsDirective),

    // ── ISSUE-056: Typed passthrough replacements ──────────────────────────────
    /// `map {source} {dest_var} { pattern value ... }` — request-time variable mapping.
    Map(MapDirective),

    /// `log_append { field value; ... }` — append dynamic fields to log entries.
    LogAppend(LogAppendDirective),

    /// `log_name <name>` — name the logger for this site.
    LogName(LogNameDirective),

    /// `invoke <name>` — invoke a named route/snippet.
    Invoke(InvokeDirective),

    /// `fs [args] { ... }` — filesystem operations.
    Fs(FsDirective),

    /// `intercept [statuses...] { directives }` — response-phase interception.
    Intercept(InterceptDirective),

    /// `metrics [path]` — expose Prometheus/OpenTelemetry metrics.
    Metrics(MetricsDirective),

    /// `cache { max_size 1g; match_path /static/*; default_ttl 3600 }`
    Cache(CacheDirective),

    /// `tracing [endpoint]` — distributed tracing configuration.
    Tracing(TracingDirective),

    /// `copy_response [statuses...]` — copy upstream response body.
    CopyResponse(CopyResponseDirective),

    /// `copy_response_headers { include/exclude ... }` — copy selected headers.
    CopyResponseHeaders(CopyResponseHeadersDirective),

    /// `templates` — Caddy server-side template rendering (not yet implemented).
    Templates(RecognizedDirective),

    /// `push` — HTTP/2 server push (not yet implemented).
    Push(RecognizedDirective),

    /// `acme_server` — internal ACME CA server (not yet implemented).
    AcmeServer(RecognizedDirective),

    // ── ISSUE-101: WASM plugin directive ─────────────────────────────────────
    /// `wasm_plugin /path/to/plugin.wasm { priority 50; fuel 1000000; ... }`
    WasmPlugin(WasmPluginDirective),

    // ── H2: gRPC route marker ─────────────────────────────────────────────
    /// `grpc` — bare marker that designates this handler block as a gRPC route.
    ///
    /// When present, the runtime applies H2 ALPN enforcement and a 1 GiB body
    /// cap regardless of `Content-Type`. No arguments.
    Grpc,
}

/// `cache { max_size 1g; match_path /static/* /assets/*; default_ttl 3600; stale_while_revalidate 60 }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheDirective {
    /// Max cache size in bytes. `None` = use default (1 GiB).
    pub max_size: Option<u64>,
    /// Path prefixes eligible for caching. Empty = cache everything.
    pub match_paths: Vec<String>,
    /// Default TTL in seconds when upstream has no Cache-Control. `None` = use default (3600).
    pub default_ttl: Option<u32>,
    /// Seconds to serve stale while revalidating. `None` = use default (60).
    pub stale_while_revalidate: Option<u32>,
}

/// `handle` — path-scoped directive block. First match wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleDirective {
    /// Path pattern to match. `None` = catch-all.
    pub matcher: Option<String>,
    /// Directives inside the block.
    pub directives: Vec<Directive>,
}

/// `handle_path` — like handle but strips the matched prefix from the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlePathDirective {
    /// Path prefix to match (required).
    pub path_prefix: String,
    /// Directives inside the block.
    pub directives: Vec<Directive>,
}

/// `route` — ordered execution block. All matching blocks run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDirective {
    /// Path pattern to match. `None` = match all.
    pub matcher: Option<String>,
    /// Directives inside the block.
    pub directives: Vec<Directive>,
}

/// `php_fastcgi` — proxy PHP requests to a `FastCGI` backend (php-fpm).
///
/// Caddy syntax: `php_fastcgi localhost:9000`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhpFastcgiDirective {
    /// `FastCGI` backend address (TCP or Unix socket path).
    pub upstream: UpstreamAddr,
}

/// Load balancing strategy for multi-upstream `reverse_proxy` blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbPolicy {
    /// Distribute requests evenly in turn across backends.
    RoundRobin,
    /// Send each request to the backend with the fewest active connections.
    LeastConn,
    /// Pick a backend at random.
    Random,
    /// Hash the client IP to pick a backend — same client always hits same backend.
    IpHash,
}

/// `reverse_proxy` — route requests to one or more upstream backends.
///
/// Supports both inline form (`reverse_proxy host:port`) and block form with
/// load balancing, health checks, and per-upstream TLS settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseProxyDirective {
    /// One or more upstream addresses. Multiple means load-balanced.
    pub upstreams: Vec<UpstreamAddr>,
    /// Load balancing policy. `None` defaults to `RoundRobin`.
    pub lb_policy: Option<LbPolicy>,
    /// HTTP path to poll on each backend for health checks (e.g. `/health`).
    pub health_uri: Option<String>,
    /// Seconds between health check polls.
    pub health_interval: Option<u64>,
    /// How long (seconds) to keep a backend marked unhealthy after a failure.
    pub fail_duration: Option<u64>,
    /// Maximum concurrent connections per backend (None = unlimited).
    pub max_conns: Option<u32>,
    /// Connect to upstream over TLS (e.g. backend is HTTPS).
    pub transport_tls: bool,
    /// Use HTTP/2 multiplexing for upstream connections.
    /// Enables multiple H3 streams to share 1-2 TCP connections per host
    /// instead of opening one per stream. Requires upstream H2 support.
    pub transport_h2: bool,
    /// SNI hostname to use for upstream TLS connections.
    pub tls_server_name: Option<String>,
    /// Client cert+key paths for mutual TLS with the upstream.
    /// `(cert_path, key_path)` — loaded and validated at compile time.
    pub tls_client_auth: Option<(String, String)>,
    /// Custom CA bundle path for upstream cert verification.
    pub tls_trusted_ca_certs: Option<String>,
    /// Scale-to-zero config — wake a sleeping backend on first request (ISSUE-082).
    pub scale_to_zero: Option<ScaleToZeroDirective>,
}

/// Scale-to-zero config inside a `reverse_proxy` block (ISSUE-082).
///
/// When the upstream is unreachable and this config is present, the proxy
/// holds the request, runs a wake command (once per upstream, coalesced),
/// polls health, and forwards the request once the backend responds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaleToZeroDirective {
    /// Max time to wait for the backend to wake up. Default: 30s.
    pub wake_timeout_secs: u64,
    /// Shell command to wake the backend (e.g. `"docker start myapp"`).
    pub wake_command: String,
}

/// An upstream address — either a socket address or a host:port string
/// that may need DNS resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamAddr {
    /// Fully resolved address like `127.0.0.1:8080`
    SocketAddr(SocketAddr),
    /// Host:port that may need resolution, like `backend:8080`
    HostPort(String),
}

/// `tls` — configure TLS behavior for a site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsDirective {
    /// `tls auto` or just omitting tls (default for HTTPS domains)
    Auto,
    /// `tls off` — no TLS, plain HTTP only
    Off,
    /// `tls internal` — use a self-signed cert (dev/testing)
    Internal,
    /// `tls /path/to/cert.pem /path/to/key.pem` — manual cert files
    Manual { cert_path: String, key_path: String },
    /// `tls { dns cloudflare <token> }` — DNS-01 challenge for wildcard certs
    DnsChallenge {
        /// DNS provider name (e.g. "cloudflare")
        provider: String,
        /// API token for the DNS provider
        api_token: String,
    },
}

/// `header` — add, set, or remove a response header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderDirective {
    /// `header X-Custom "value"` — set header to value
    Set { name: String, value: String },
    /// `header -Server` — remove header from response
    Delete { name: String },
}

/// `redir` — HTTP redirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirDirective {
    /// Source path (what to match)
    pub from: String,
    /// Destination URL or path
    pub to: String,
    /// HTTP status code (301, 302, 307, 308). Defaults to 308 like Caddy.
    pub code: u16,
}

/// `encode` — response compression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeDirective {
    /// Encodings to enable, in preference order.
    /// Valid: "gzip", "zstd", "br" (brotli)
    pub encodings: Vec<String>,
}

/// `rate_limit 100/s` — per-IP rate limiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitDirective {
    /// Maximum requests per second per IP for this route.
    pub requests_per_second: u32,
}

/// `ip_filter` — IP allowlist/blocklist per route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpFilterDirective {
    /// CIDR ranges to allow (e.g., `["10.0.0.0/8", "192.168.1.0/24"]`).
    pub allow: Vec<String>,
    /// CIDR ranges to deny (e.g., `["203.0.113.0/24"]`).
    pub deny: Vec<String>,
    /// Default policy when no rule matches. `true` = allow, `false` = deny.
    pub default_allow: bool,
}

// ── New directive types (Phase 3 + 4) ─────────────────────────────────────────

/// `log` — per-site access logging configuration.
///
/// Without a block, enables default logging. With a block, configures
/// output destination, format, and log level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogDirective {
    pub output: Option<LogOutput>,
    pub format: Option<LogFormat>,
    /// Log level string (e.g. "INFO", "DEBUG", "WARN", "ERROR").
    pub level: Option<String>,
}

/// Where `log` sends access log entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogOutput {
    Stdout,
    Stderr,
    /// Discard all log output for this site.
    Discard,
    /// Write to a file with size-based rotation.
    File {
        path: String,
        /// Rotate when the file exceeds this size in bytes.
        max_bytes: Option<u64>,
        /// Number of rotated files to keep.
        keep: Option<u32>,
    },
    /// Write JSON lines to a Unix domain socket.
    Unix {
        path: String,
    },
}

/// Structured log format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogFormat {
    Console,
    Json,
}

/// `request_header` — modify request headers before proxying to upstream.
///
/// Caddy syntax:
/// - `request_header X-Name "value"` — set
/// - `request_header -X-Remove` — delete
/// - `request_header +X-Append "value"` — append (add without replacing)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestHeaderDirective {
    /// Set the named header to a fixed value, replacing any existing value.
    Set { name: String, value: String },
    /// Remove the header entirely before forwarding.
    Delete { name: String },
    /// Add the header value without removing existing values.
    Add { name: String, value: String },
}

/// `error` — respond with an explicit error status.
///
/// Useful to deny specific paths with a clean error response rather
/// than forwarding to upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorDirective {
    /// Optional human-readable error message body.
    pub message: String,
    /// HTTP status code to send.
    pub status: u16,
}

/// `method` — override the HTTP method forwarded to upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodDirective {
    /// The HTTP method to use (e.g. "GET", "POST").
    pub method: String,
}

/// `request_body` — body size limits and policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBodyDirective {
    /// Maximum allowed request body size in bytes. `None` means no limit.
    pub max_size: Option<u64>,
}

/// `response_body_limit` — max upstream response body size before Dwaar cuts the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseBodyLimitDirective {
    /// Maximum allowed response body size in bytes.
    pub max_size: u64,
}

/// `try_files` — attempt to serve static files before falling through.
///
/// Each entry is a file pattern. The first pattern that exists on disk
/// is served; if none match, the final entry is used as a fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TryFilesDirective {
    /// File patterns to try in order (e.g. `["{path}.html", "{path}", "/index.html"]`).
    pub files: Vec<String>,
}

/// `handle_errors` — error page routing.
///
/// Directives inside this block run when upstream returns an error status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleErrorsDirective {
    pub directives: Vec<Directive>,
}

/// `bind` — listen addresses for this site.
///
/// By default Dwaar listens on all interfaces. `bind` restricts which
/// addresses the listener is attached to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindDirective {
    pub addresses: Vec<String>,
}

/// `vars` — set a named variable for use in other directives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarsDirective {
    pub key: String,
    pub value: String,
}

/// `respond` — return a static response without proxying to upstream.
///
/// Syntax follows Caddy: `respond [body] [status]`
/// - `respond "Not Found" 404` — body + status
/// - `respond 204` — status only (if single arg is a valid 3-digit code)
/// - `respond "ok"` — body only (default status 200)
/// - `respond` — empty body, status 200
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespondDirective {
    /// HTTP status code. Defaults to 200.
    pub status: u16,
    /// Response body. Empty string means no body.
    pub body: String,
}

/// `basicauth` / `basic_auth` — HTTP Basic Authentication.
///
/// Caddy syntax: `basic_auth [<realm>] { username hash }`
/// Dwaar also accepts `basicauth` (no underscore).
///
/// `Debug` is manually implemented to redact password hashes.
#[derive(Clone, PartialEq, Eq)]
pub struct BasicAuthDirective {
    /// Optional realm name for the `WWW-Authenticate` header.
    pub realm: Option<String>,
    /// Credentials: `(username, bcrypt_hash)` pairs.
    pub credentials: Vec<BasicAuthCredential>,
}

impl std::fmt::Debug for BasicAuthDirective {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicAuthDirective")
            .field("realm", &self.realm)
            .field("user_count", &self.credentials.len())
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}

/// A single username + password hash pair.
///
/// `Debug` redacts the hash to prevent accidental credential exposure in logs.
#[derive(Clone, PartialEq, Eq)]
pub struct BasicAuthCredential {
    pub username: String,
    pub password_hash: String,
}

impl std::fmt::Debug for BasicAuthCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicAuthCredential")
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .finish()
    }
}

/// `forward_auth` — subrequest to external auth service before proxying.
///
/// Caddy syntax: `forward_auth <upstream> { uri /path; copy_headers Header1 Header2 }`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardAuthDirective {
    /// Auth service address (e.g., `authelia:9091` or `127.0.0.1:9091`).
    pub upstream: UpstreamAddr,
    /// URI path to send to the auth service. Defaults to the original request URI.
    pub uri: Option<String>,
    /// Headers to copy from auth response to upstream request.
    pub copy_headers: Vec<String>,
    /// Use TLS when connecting to the auth service (`transport tls`).
    pub tls: bool,
    /// Explicit opt-in to plaintext subrequests to non-loopback auth services.
    ///
    /// Defaults to `false`. Set to `true` only for development environments
    /// where TLS to the auth service is not available. The runtime will still
    /// log a warning on first use.
    pub insecure_plaintext: bool,
}

/// `root` — set the filesystem root for `file_server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootDirective {
    /// Filesystem path (e.g., `/var/www/html`).
    pub path: String,
}

/// `file_server` — serve static files from the `root` directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileServerDirective {
    /// Enable directory listing.
    pub browse: bool,
}

/// `rewrite` — replace the request URI sent to upstream.
///
/// `rewrite /new-path` replaces the full URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteDirective {
    /// The new URI to send to upstream.
    pub to: String,
}

/// `uri` — partial URI transformation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriDirective {
    pub operation: UriOperation,
}

/// The specific operation a `uri` directive performs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriOperation {
    /// `uri strip_prefix /api` — remove prefix from path
    StripPrefix(String),
    /// `uri strip_suffix .html` — remove suffix from path
    StripSuffix(String),
    /// `uri replace /old /new` — substring replacement
    Replace { find: String, replace: String },
}

// ── ISSUE-056: Typed passthrough replacement structs ────────────────────────────

/// `map {source} {dest_var} { pattern value; ... }` — request-time variable mapping.
///
/// Evaluates a source expression per-request, matches against pattern entries,
/// and sets the destination variable. This is how Caddy implements conditional
/// variable assignment without scripting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapDirective {
    /// Source expression — a template like `{query.mode}` or `{host}`.
    pub source: String,
    /// Destination variable name (used by other directives via `{dest_var}`).
    pub dest_var: String,
    /// Ordered pattern-value entries. First match wins.
    pub entries: Vec<MapEntry>,
}

/// A single entry inside a `map { ... }` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapEntry {
    /// How to match the evaluated source value.
    pub pattern: MapPattern,
    /// Value to assign when this pattern matches (may contain placeholders).
    pub value: String,
}

/// Matching strategy for a `MapEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapPattern {
    /// Case-insensitive exact string match.
    Exact(String),
    /// Regular expression match (from `~pattern` syntax).
    Regex(String),
    /// Fallback when no other entry matches.
    Default,
}

/// `log_append { field value; ... }` — append dynamic fields to log entries.
///
/// Each field's value is a template evaluated per-request, so you can inject
/// request-scoped data into structured log output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogAppendDirective {
    /// Ordered list of (`field_name`, `template_value`) pairs.
    pub fields: Vec<(String, String)>,
}

/// `log_name <name>` — give the site's logger a name for per-site routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogNameDirective {
    pub name: String,
}

/// `invoke <name>` — invoke a named route or snippet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokeDirective {
    pub name: String,
}

/// `fs [args]` — filesystem operations directive.
///
/// Currently stores raw args for forward compat; runtime not yet implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsDirective {
    pub args: Vec<String>,
}

/// `intercept [status...] { directives }` — response-phase interception.
///
/// Matches specific upstream response status codes and applies directives
/// (rewrite, respond, etc.) before the response reaches the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterceptDirective {
    /// HTTP status codes to intercept. Empty = intercept all.
    pub statuses: Vec<u16>,
    /// Directives to apply when matched.
    pub directives: Vec<Directive>,
}

/// `metrics [path]` — expose a metrics endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsDirective {
    /// Optional URL path for the metrics endpoint (defaults to `/metrics`).
    pub path: Option<String>,
}

/// `tracing [endpoint]` — distributed tracing configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracingDirective {
    /// Optional collector endpoint (e.g., `http://jaeger:4318/v1/traces`).
    pub endpoint: Option<String>,
}

/// `copy_response [status...]` — copy the upstream response body verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyResponseDirective {
    /// Status codes to match. Empty = match all.
    pub statuses: Vec<u16>,
}

/// `copy_response_headers { include Header1; exclude Header2 }` — selective
/// header copying from upstream response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyResponseHeadersDirective {
    /// Header names to include or exclude.
    pub headers: Vec<String>,
}

/// Recognized Caddyfile directive without runtime support.
///
/// Stores raw arguments so the formatter can round-trip the config. Emits
/// a warning at compile time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecognizedDirective {
    /// Positional arguments after the directive name.
    pub args: Vec<String>,
}

/// `wasm_plugin /path/to/plugin.wasm { priority 50; fuel 1000000; memory 16; timeout 50; config k=v }`
///
/// Registers a WASM plugin that participates in the proxy request lifecycle.
/// Plugins are executed in `priority` order (lower = earlier). Resource limits
/// default to safe values when omitted; any combination may be specified.
///
/// # Example
///
/// ```text
/// wasm_plugin /plugins/rate_shape.wasm {
///     priority 50
///     fuel 1000000
///     memory 16
///     timeout 50
///     config key1=value1
///     config key2=value2
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmPluginDirective {
    /// Filesystem path to the `.wasm` binary (absolute or relative to the Dwaarfile).
    pub module_path: String,

    /// Execution priority — lower values run first. Must be 1–65535.
    pub priority: u16,

    /// Instruction budget per hook call. `None` defaults to 1,000,000.
    pub fuel: Option<u64>,

    /// Linear memory cap in MiB. `None` defaults to 16 MiB.
    pub memory_mb: Option<u32>,

    /// Wall-clock deadline per hook call in milliseconds. `None` defaults to 50 ms.
    pub timeout_ms: Option<u64>,

    /// Opaque key=value pairs forwarded to the plugin as startup configuration.
    /// Plugins receive these via the host API during initialisation.
    pub config: Vec<(String, String)>,
}

// ── Layer 4 (TCP proxy) model types ──────────────────────────────────────────
//
// These types represent the output of `parser/layer4.rs` and are consumed by
// `compile.rs` to produce runtime-ready `CompiledL4Server` values.

/// Top-level `layer4 { ... }` app block from a Caddyfile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layer4Config {
    /// All server stanzas inside the `layer4 { }` block.
    pub servers: Vec<Layer4Server>,
}

/// One server entry: one or more listen addresses sharing the same routes.
///
/// ```text
/// :443 :8443 {
///     route { ... }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer4Server {
    /// Raw listen addresses (e.g. `":443"`, `"0.0.0.0:8080"`).
    pub listen: Vec<String>,
    /// Named matcher definitions declared inside the server block.
    pub matchers: Vec<Layer4MatcherDef>,
    /// Routes declared inside the server block.
    pub routes: Vec<Layer4Route>,
}

/// An intermediate parse result for a block that contains matchers + routes.
///
/// Used for both `Layer4Server` bodies and `subroute` bodies. `Default` is
/// required by `parse_subroute_handler` which starts with an empty route set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layer4RouteSet {
    pub matchers: Vec<Layer4MatcherDef>,
    pub routes: Vec<Layer4Route>,
}

/// A named L4 matcher definition: `@name matcher …`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer4MatcherDef {
    /// Name without the `@` prefix.
    pub name: String,
    /// Matcher conditions. All must pass (AND logic).
    pub matchers: Vec<Layer4Matcher>,
}

/// A single L4 matcher condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer4Matcher {
    /// `tls [sni …] [alpn …]` — match TLS `ClientHello` fields.
    Tls {
        sni: Vec<String>,
        alpn: Vec<String>,
        options: Vec<Layer4Option>,
    },
    /// `http [host …]` — match HTTP/1.1 Host header.
    Http {
        host: Vec<String>,
        options: Vec<Layer4Option>,
    },
    /// `ssh` — match SSH protocol handshake.
    Ssh,
    /// `postgres` — match `PostgreSQL` wire-protocol startup.
    Postgres,
    /// `remote_ip 10.0.0.0/8 …` — match peer CIDR.
    RemoteIp(Vec<String>),
    /// `not <matcher>` — invert the inner matcher.
    Not(Box<Layer4Matcher>),
    /// Unknown matcher keyword — stored verbatim for forward compat.
    Unknown { name: String, args: Vec<String> },
}

/// A generic key + args option used inside L4 handlers and matchers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer4Option {
    pub name: String,
    pub args: Vec<String>,
}

/// One `route` block inside an L4 server or subroute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer4Route {
    /// Named matchers that must ALL pass (AND logic). Empty = catch-all.
    pub matcher_names: Vec<String>,
    /// Handlers executed in order for matching connections.
    pub handlers: Vec<Layer4Handler>,
}

/// An L4 route handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer4Handler {
    /// `proxy <upstream> …` — forward raw TCP bytes to upstream.
    Proxy(Layer4ProxyHandler),
    /// `tls { … }` — TLS termination / pass-through.
    Tls(Layer4TlsHandler),
    /// `subroute { … }` — nested route set with optional matching timeout.
    Subroute(Layer4SubrouteHandler),
    /// Unknown handler keyword — stored verbatim for forward compat.
    Unknown { name: String, args: Vec<String> },
}

/// `proxy` handler configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer4ProxyHandler {
    /// Upstream addresses (raw strings, resolved at compile time).
    pub upstreams: Vec<String>,
    /// Generic options (`lb_policy`, `max_fails`, `health_timeout`, …).
    pub options: Vec<Layer4Option>,
}

/// `tls` handler configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer4TlsHandler {
    /// Generic TLS sub-directives (cert, key, ca, …).
    pub options: Vec<Layer4Option>,
}

/// `subroute` handler — a nested L4 route set with an optional detect timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer4SubrouteHandler {
    /// `matching_timeout 3s` — how long to buffer data for protocol detection.
    pub matching_timeout: Option<String>,
    /// Named matcher definitions inside the subroute block.
    pub matchers: Vec<Layer4MatcherDef>,
    /// Routes inside the subroute block.
    pub routes: Vec<Layer4Route>,
}

/// Listener-wrapper fallthrough — a site block address that carries an embedded
/// L4 route set (used when a listener is shared between HTTP and raw TCP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer4ListenerWrapper {
    /// The listen address this wrapper is attached to (e.g. `":443"`).
    pub listen: String,
    /// The L4 route set parsed from the wrapper block.
    pub layer4: Layer4RouteSet,
}

// ─────────────────────────────────────────────────────────────────────────────

impl DwaarConfig {
    /// Create an empty config with no global options and no sites.
    pub fn new() -> Self {
        Self {
            global_options: None,
            sites: Vec::new(),
        }
    }
}

impl Default for DwaarConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config() {
        let config = DwaarConfig::new();
        assert!(config.sites.is_empty());
    }

    #[test]
    fn site_block_with_directives() {
        let site = SiteBlock {
            address: "api.example.com".to_string(),
            matchers: vec![],
            directives: vec![
                Directive::ReverseProxy(ReverseProxyDirective {
                    upstreams: vec![UpstreamAddr::SocketAddr(
                        "127.0.0.1:3000".parse().expect("valid"),
                    )],
                    lb_policy: None,
                    health_uri: None,
                    health_interval: None,
                    fail_duration: None,
                    max_conns: None,
                    transport_tls: false,
                    transport_h2: false,
                    tls_server_name: None,
                    tls_client_auth: None,
                    tls_trusted_ca_certs: None,
                    scale_to_zero: None,
                }),
                Directive::Tls(TlsDirective::Auto),
            ],
        };

        assert_eq!(site.address, "api.example.com");
        assert_eq!(site.directives.len(), 2);
    }

    #[test]
    fn upstream_addr_variants() {
        let resolved = UpstreamAddr::SocketAddr("127.0.0.1:8080".parse().expect("valid"));
        let named = UpstreamAddr::HostPort("backend:8080".to_string());

        // Both should be representable
        assert!(matches!(resolved, UpstreamAddr::SocketAddr(_)));
        assert!(matches!(named, UpstreamAddr::HostPort(_)));
    }

    #[test]
    fn header_directive_variants() {
        let set = HeaderDirective::Set {
            name: "X-Custom".to_string(),
            value: "hello".to_string(),
        };
        let del = HeaderDirective::Delete {
            name: "Server".to_string(),
        };

        assert!(matches!(set, HeaderDirective::Set { .. }));
        assert!(matches!(del, HeaderDirective::Delete { .. }));
    }

    #[test]
    fn redir_defaults_to_308() {
        let redir = RedirDirective {
            from: "/old".to_string(),
            to: "/new".to_string(),
            code: 308,
        };
        assert_eq!(redir.code, 308);
    }

    #[test]
    fn rate_limit_directive() {
        let rl = RateLimitDirective {
            requests_per_second: 100,
        };
        assert_eq!(rl.requests_per_second, 100);
    }

    #[test]
    fn config_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DwaarConfig>();
    }

    // ── Named matcher model types ──────────────────────────────────────────────

    #[test]
    fn matcher_def_basic() {
        let m = MatcherDef {
            name: "api".to_string(),
            conditions: vec![MatcherCondition::Path(vec!["/api/*".to_string()])],
        };
        assert_eq!(m.name, "api");
        assert_eq!(m.conditions.len(), 1);
    }

    #[test]
    fn matcher_ref_variants() {
        let none = MatcherRef::None;
        let inline = MatcherRef::Inline("/api/*".to_string());
        let named = MatcherRef::Named("api".to_string());

        assert!(matches!(none, MatcherRef::None));
        assert!(matches!(inline, MatcherRef::Inline(_)));
        assert!(matches!(named, MatcherRef::Named(_)));
    }

    #[test]
    fn matcher_condition_all_variants_constructable() {
        // Verify every variant can be constructed without compiler error.
        let _ = MatcherCondition::Path(vec!["/foo".to_string()]);
        let _ = MatcherCondition::PathRegexp {
            name: Some("re".to_string()),
            pattern: r"\.php$".to_string(),
        };
        let _ = MatcherCondition::Host(vec!["example.com".to_string()]);
        let _ = MatcherCondition::Method(vec!["GET".to_string()]);
        let _ = MatcherCondition::Header {
            name: "X-Foo".to_string(),
            value: Some("bar".to_string()),
        };
        let _ = MatcherCondition::HeaderRegexp {
            name: "X-Foo".to_string(),
            pattern: "^val".to_string(),
        };
        let _ = MatcherCondition::Protocol("https".to_string());
        let _ = MatcherCondition::RemoteIp(vec!["192.168.0.0/16".to_string()]);
        let _ = MatcherCondition::ClientIp(vec!["10.0.0.0/8".to_string()]);
        let _ = MatcherCondition::Query(vec!["foo=bar".to_string()]);
        let _ = MatcherCondition::Not(vec![MatcherCondition::Path(vec!["/admin/*".to_string()])]);
        let _ = MatcherCondition::Expression("{http.request.host} == 'example.com'".to_string());
        let _ = MatcherCondition::File {
            try_files: vec!["/public{path}".to_string()],
        };
        let _ = MatcherCondition::Unknown {
            keyword: "future_thing".to_string(),
            args: vec!["arg1".to_string()],
        };
    }

    #[test]
    fn site_block_matchers_field_is_separate_from_directives() {
        let site = SiteBlock {
            address: "example.com".to_string(),
            matchers: vec![MatcherDef {
                name: "api".to_string(),
                conditions: vec![MatcherCondition::Path(vec!["/api/*".to_string()])],
            }],
            directives: vec![Directive::Tls(TlsDirective::Auto)],
        };

        assert_eq!(site.matchers.len(), 1);
        assert_eq!(site.directives.len(), 1);
        assert_eq!(site.matchers[0].name, "api");
    }

    // ── New directive model types (Phase 3 + 4) ────────────────────────────────

    #[test]
    fn log_directive_default_no_block() {
        let d = LogDirective {
            output: None,
            format: None,
            level: None,
        };
        assert!(d.output.is_none());
    }

    #[test]
    fn log_directive_file_output() {
        let d = LogDirective {
            output: Some(LogOutput::File {
                path: "/var/log/access.log".to_string(),
                max_bytes: None,
                keep: None,
            }),
            format: Some(LogFormat::Json),
            level: Some("INFO".to_string()),
        };
        assert!(matches!(d.output, Some(LogOutput::File { .. })));
        assert!(matches!(d.format, Some(LogFormat::Json)));
    }

    #[test]
    fn request_header_variants() {
        let set = RequestHeaderDirective::Set {
            name: "X-Custom".to_string(),
            value: "val".to_string(),
        };
        let del = RequestHeaderDirective::Delete {
            name: "X-Remove".to_string(),
        };
        let add = RequestHeaderDirective::Add {
            name: "X-Extra".to_string(),
            value: "extra".to_string(),
        };
        assert!(matches!(set, RequestHeaderDirective::Set { .. }));
        assert!(matches!(del, RequestHeaderDirective::Delete { .. }));
        assert!(matches!(add, RequestHeaderDirective::Add { .. }));
    }

    #[test]
    fn error_directive_fields() {
        let e = ErrorDirective {
            message: "forbidden".to_string(),
            status: 403,
        };
        assert_eq!(e.status, 403);
        assert_eq!(e.message, "forbidden");
    }

    #[test]
    fn request_body_max_size() {
        let rb = RequestBodyDirective {
            max_size: Some(10 * 1024 * 1024),
        };
        assert_eq!(rb.max_size, Some(10 * 1024 * 1024));
    }

    #[test]
    fn bind_directive_multiple_addresses() {
        let b = BindDirective {
            addresses: vec!["0.0.0.0".to_string(), "::1".to_string()],
        };
        assert_eq!(b.addresses.len(), 2);
    }
}
