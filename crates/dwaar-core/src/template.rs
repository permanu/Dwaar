// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Zero-allocation template engine for Caddy-style placeholder evaluation.
//!
//! Compiles strings like `"{host}/api/{path}"` at config load time into a flat
//! segment array. At request time, evaluation is a linear scan (~2-3ns per
//! placeholder) with CRLF injection and open-redirect sanitization built in.
//!
//! ## Usage
//!
//! ```ignore
//! // Config load time (once)
//! let tmpl = CompiledTemplate::compile("/api/{uri}")?;
//!
//! // Request time (every request)
//! let ctx = TemplateContext { host: "example.com", path: "/foo", .. };
//! let result = tmpl.evaluate(&ctx); // "/api/foo"
//! ```
//!
//! ## Design
//!
//! - **Compile time:** parse `{name}` tokens into `Placeholder` enum variants.
//!   Unknown names produce a compile error (fail-fast, Guardrail #27).
//! - **Evaluate time:** linear scan over segments, one `String` allocation.
//!   Literal-only templates skip the scan entirely.
//! - **Security:** `evaluate_sanitized()` strips `\r\n` (CRLF injection) and
//!   `evaluate_redirect()` collapses `//` (open redirect).

use std::fmt;

use compact_str::CompactString;

// ── Placeholder enum ─────────────────────────────────────────

/// All Caddy-compatible placeholders supported by Dwaar.
///
/// Each variant maps to a `{name}` token in config strings. Unknown names
/// produce a compile-time error — no silent ignoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Placeholder {
    // Request basics
    Host,
    Method,
    Path,
    /// Full request URI: path + query string (e.g. `/api?q=1`).
    Uri,
    /// Query string without the `?` (e.g. `q=1`).
    Query,
    /// `"http"` or `"https"`.
    Scheme,
    // Connection
    RemoteHost,
    RemotePort,
    // File path decomposition
    /// File extension (e.g. `html` from `/page.html`).
    FileExt,
    /// Filename without extension (e.g. `page` from `/page.html`).
    FileBase,
    /// Directory portion of the path (e.g. `/subdir` from `/subdir/file.html`).
    Dir,
    // TLS
    TlsServerName,
    TlsCipher,
    // Upstream
    UpstreamHost,
    UpstreamPort,
    // Canonical request headers
    HeaderHost,
    HeaderReferer,
    HeaderUserAgent,
    // Dwaar-specific
    RequestId,
}

impl Placeholder {
    /// Parse a placeholder name (without braces) into a `Placeholder` variant.
    /// Returns `None` for unknown names.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            // Request basics
            "host" => Some(Self::Host),
            "method" => Some(Self::Method),
            "path" => Some(Self::Path),
            "uri" => Some(Self::Uri),
            "query" => Some(Self::Query),
            "scheme" => Some(Self::Scheme),
            // Connection
            "remote_host" => Some(Self::RemoteHost),
            "remote_port" => Some(Self::RemotePort),
            // File path decomposition
            "file.ext" => Some(Self::FileExt),
            "file.base" => Some(Self::FileBase),
            "dir" => Some(Self::Dir),
            // TLS
            "tls_server_name" => Some(Self::TlsServerName),
            "tls_cipher" => Some(Self::TlsCipher),
            // Upstream
            "upstream.host" => Some(Self::UpstreamHost),
            "upstream.port" => Some(Self::UpstreamPort),
            // Request headers (Caddy long form)
            "http.request.host" => Some(Self::HeaderHost),
            "http.request.header.Referer" => Some(Self::HeaderReferer),
            "http.request.header.User-Agent" => Some(Self::HeaderUserAgent),
            // Dwaar-specific
            "request_id" => Some(Self::RequestId),
            _ => None,
        }
    }

    /// The canonical `{name}` for this placeholder.
    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Method => "method",
            Self::Path => "path",
            Self::Uri => "uri",
            Self::Query => "query",
            Self::Scheme => "scheme",
            Self::RemoteHost => "remote_host",
            Self::RemotePort => "remote_port",
            Self::FileExt => "file.ext",
            Self::FileBase => "file.base",
            Self::Dir => "dir",
            Self::TlsServerName => "tls_server_name",
            Self::TlsCipher => "tls_cipher",
            Self::UpstreamHost => "upstream.host",
            Self::UpstreamPort => "upstream.port",
            Self::HeaderHost => "http.request.host",
            Self::HeaderReferer => "http.request.header.Referer",
            Self::HeaderUserAgent => "http.request.header.User-Agent",
            Self::RequestId => "request_id",
        }
    }

    /// All known placeholder names — for error messages suggesting alternatives.
    pub fn all_names() -> &'static [&'static str] {
        &[
            "host",
            "method",
            "path",
            "uri",
            "query",
            "scheme",
            "remote_host",
            "remote_port",
            "file.ext",
            "file.base",
            "dir",
            "tls_server_name",
            "tls_cipher",
            "upstream.host",
            "upstream.port",
            "http.request.host",
            "http.request.header.Referer",
            "http.request.header.User-Agent",
            "request_id",
        ]
    }
}

// ── Variable registry (compile-time) ─────────────────────────

/// Compile-time registry mapping user variable names to `u16` slot indices.
///
/// Variables come from `vars` and `map` directives in the Dwaarfile. During
/// compilation, each unique variable name gets a slot index. Templates that
/// reference `{my_var}` compile to `Segment::UserVar(slot)` — O(1) at runtime.
///
/// The registry is per-site: each `Route` has its own variable namespace.
/// Unknown variable references produce a compile error (fail-fast), unlike
/// Caddy which silently substitutes empty strings.
#[derive(Debug, Clone)]
pub struct VarRegistry {
    /// Variable name → slot index.
    slots: std::collections::HashMap<String, u16>,
    /// Next slot to assign.
    next_slot: u16,
}

impl VarRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            slots: std::collections::HashMap::new(),
            next_slot: 0,
        }
    }

    /// Register a variable, returning its slot index.
    ///
    /// If the variable was already registered, returns its existing slot
    /// without error (idempotent). This allows multiple `vars` directives
    /// to set the same variable — last value wins at runtime.
    pub fn register(&mut self, name: &str) -> u16 {
        if let Some(&slot) = self.slots.get(name) {
            return slot;
        }
        let slot = self.next_slot;
        self.next_slot += 1;
        self.slots.insert(name.to_owned(), slot);
        slot
    }

    /// Look up a variable's slot index by name.
    pub fn get(&self, name: &str) -> Option<u16> {
        self.slots.get(name).copied()
    }

    /// Total number of registered variables — the `VarSlots` capacity needed.
    pub fn len(&self) -> usize {
        self.next_slot as usize
    }

    /// Returns `true` if no variables are registered.
    pub fn is_empty(&self) -> bool {
        self.next_slot == 0
    }
}

impl Default for VarRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Variable slots (runtime) ─────────────────────────────────

/// Hard upper bound on the number of user variable slots per route.
///
/// `VarRegistry` assigns slots densely starting at 0, so in a well-formed
/// config the highest slot index is bounded by the number of `vars`/`map`
/// directives. This constant caps `VarSlots::set` to prevent a mis-wired
/// compiler or a malicious config from triggering unbounded `Vec` growth
/// — an out-of-range `set` becomes a silent no-op rather than allocating.
pub const MAX_VAR_SLOTS: usize = 256;

/// Runtime storage for user variable values, indexed by slot.
///
/// Created from `VarRegistry::len()` and populated at request time.
/// Static values (from `vars` directives) are pre-filled at route
/// compile time. Dynamic values (from `map` evaluation) are filled
/// per-request before template evaluation.
///
/// ## Performance
///
/// - Slot lookup: O(1) index into `Vec`, no hashing
/// - Per-request cost: one `Vec::clone()` from defaults (~100ns for 10 vars)
/// - Memory: ~24 bytes per slot (Option<CompactString>)
#[derive(Debug, Clone, Default)]
pub struct VarSlots {
    values: Vec<Option<CompactString>>,
}

impl VarSlots {
    /// Create a slot store with capacity for `n` variables (all `None`).
    pub fn with_capacity(n: usize) -> Self {
        Self {
            values: vec![None; n],
        }
    }

    /// Set the value for a slot.
    ///
    /// Slot indices at or beyond [`MAX_VAR_SLOTS`] are silently dropped.
    /// The compiler assigns slots densely from 0 and a well-formed config
    /// cannot exceed this bound, so an out-of-range `set` only happens on
    /// a mis-wired compiler or a malicious/bogus call — in which case we
    /// refuse to resize the backing `Vec` unboundedly.
    pub fn set(&mut self, slot: u16, value: CompactString) {
        let idx = slot as usize;
        if idx >= MAX_VAR_SLOTS {
            return;
        }
        if idx >= self.values.len() {
            self.values.resize(idx + 1, None);
        }
        self.values[idx] = Some(value);
    }

    /// Get the value for a slot. Returns `None` if unset or slot out of range.
    pub fn get(&self, slot: u16) -> Option<&str> {
        self.values.get(slot as usize).and_then(|v| v.as_deref())
    }

    /// Number of slots (including unset ones).
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns `true` if no slots exist.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

// ── Segment ──────────────────────────────────────────────────

/// One piece of a compiled template — literal text, built-in placeholder, or user variable.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// Literal text — written as-is during evaluation.
    Literal(String),
    /// A built-in placeholder like `{host}` — resolved from request context.
    Placeholder(Placeholder),
    /// A user variable like `{my_var}` — resolved from `VarSlots` by slot index.
    UserVar(u16),
    /// Regex capture group: `{re.name.N}` — resolved from `path_regexp` match captures.
    RegexCapture {
        matcher_name: CompactString,
        group: usize,
    },
}

/// Parse a `re.name.N` token into a `RegexCapture` segment.
///
/// Caddy format: `{re.matcher_name.group_index}` where group 0 is the full
/// match and 1+ are capture groups. Returns `None` if the token doesn't
/// match the `re.` prefix or has invalid structure.
fn parse_regex_capture(name: &str) -> Option<Segment> {
    let rest = name.strip_prefix("re.")?;
    let dot = rest.rfind('.')?;
    if dot == 0 {
        return None;
    }
    let matcher_name = &rest[..dot];
    let group_str = &rest[dot + 1..];
    let group: usize = group_str.parse().ok()?;
    Some(Segment::RegexCapture {
        matcher_name: CompactString::from(matcher_name),
        group,
    })
}

// ── CompiledTemplate ─────────────────────────────────────────

/// A template compiled at config load time, ready for per-request evaluation.
///
/// Compilation parses `{name}` tokens into `Placeholder` enum variants.
/// Literal-only templates (no placeholders) are a special case — `evaluate()`
/// can return the literal directly without scanning segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledTemplate {
    segments: Vec<Segment>,
    /// Pre-computed: the literal length for sizing the output buffer.
    literal_len: usize,
}

impl CompiledTemplate {
    /// Compile a template string at config load time.
    ///
    /// Parses `{name}` tokens into `Placeholder` variants. Unknown names
    /// produce a [`TemplateError::UnknownPlaceholder`] — fail-fast per
    /// Guardrail #27 (never silently ignore at runtime).
    pub fn compile(input: &str) -> Result<Self, TemplateError> {
        Self::compile_inner(input, None)
    }

    /// Compile with a variable registry for user-declared variables.
    ///
    /// Name resolution order:
    /// 1. Built-in placeholders (`host`, `path`, etc.) — always checked first
    /// 2. User variables from the registry (`my_var`, `dest`, etc.)
    /// 3. Error — unknown name produces `TemplateError::UnknownPlaceholder`
    ///
    /// This is the entry point used by the config compiler when a site has
    /// `vars` or `map` directives.
    pub fn compile_with_registry(
        input: &str,
        registry: &VarRegistry,
    ) -> Result<Self, TemplateError> {
        Self::compile_inner(input, Some(registry))
    }

    /// Compile a template, treating unknown placeholders as errors.
    /// This is the standard entry point for config compilation.
    pub fn compile_strict(input: &str) -> Result<Self, TemplateError> {
        Self::compile(input)
    }

    /// Shared compile logic. `registry` is `Some` when user variables are available.
    fn compile_inner(input: &str, registry: Option<&VarRegistry>) -> Result<Self, TemplateError> {
        let mut segments = Vec::new();
        let mut literal_len = 0;
        let mut chars = input.char_indices().peekable();
        let mut last_literal_end = 0;

        while let Some(&(i, ch)) = chars.peek() {
            if ch == '{' {
                // Flush accumulated literal text
                if i > last_literal_end {
                    let lit = input[last_literal_end..i].to_owned();
                    literal_len += lit.len();
                    segments.push(Segment::Literal(lit));
                }

                // Find the closing `}`
                chars.next(); // consume '{'
                let start = i + 1;
                let mut found_close = false;
                while let Some(&(j, c)) = chars.peek() {
                    if c == '}' {
                        found_close = true;
                        chars.next(); // consume '}'
                        let name = &input[start..j];
                        if name.is_empty() {
                            return Err(TemplateError::EmptyPlaceholder {
                                position: i,
                                input: input.to_owned(),
                            });
                        }
                        // Resolution order: built-in first, regex captures, then user vars
                        if let Some(ph) = Placeholder::from_name(name) {
                            segments.push(Segment::Placeholder(ph));
                        } else if let Some(cap) = parse_regex_capture(name) {
                            segments.push(cap);
                        } else if let Some(reg) = registry {
                            if let Some(slot) = reg.get(name) {
                                segments.push(Segment::UserVar(slot));
                            } else {
                                return Err(TemplateError::UnknownPlaceholder {
                                    name: name.to_owned(),
                                    position: i,
                                    input: input.to_owned(),
                                });
                            }
                        } else {
                            return Err(TemplateError::UnknownPlaceholder {
                                name: name.to_owned(),
                                position: i,
                                input: input.to_owned(),
                            });
                        }
                        last_literal_end = j + 1;
                        break;
                    }
                    // Placeholders can't contain whitespace (that's a block)
                    if c.is_whitespace() {
                        return Err(TemplateError::InvalidPlaceholder {
                            name: input[start..j].to_owned(),
                            position: i,
                            input: input.to_owned(),
                        });
                    }
                    chars.next();
                }
                if !found_close {
                    return Err(TemplateError::UnclosedBrace {
                        position: i,
                        input: input.to_owned(),
                    });
                }
            } else {
                chars.next();
            }
        }

        // Trailing literal
        let end = input.len();
        if end > last_literal_end {
            let lit = input[last_literal_end..end].to_owned();
            literal_len += lit.len();
            segments.push(Segment::Literal(lit));
        }

        Ok(Self {
            segments,
            literal_len,
        })
    }

    /// Whether this template has any placeholders (i.e., needs request context).
    pub fn has_placeholders(&self) -> bool {
        self.segments.iter().any(|s| {
            matches!(
                s,
                Segment::Placeholder(_) | Segment::UserVar(_) | Segment::RegexCapture { .. }
            )
        })
    }

    /// Number of segments in the compiled template.
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Evaluate the template against request context.
    ///
    /// Single allocation for the output `String`. Literal segments are pushed
    /// without intermediate copies. Placeholder segments resolve to borrowed
    /// `&str` values from the context.
    pub fn evaluate(&self, ctx: &TemplateContext<'_>) -> String {
        // Fast path: literal-only — just one segment, return it directly
        if !self.has_placeholders() {
            return self.evaluate_literals();
        }

        let mut out = String::with_capacity(self.literal_len + 64);
        for seg in &self.segments {
            match seg {
                Segment::Literal(s) => out.push_str(s),
                Segment::Placeholder(ph) => out.push_str(resolve_placeholder(*ph, ctx)),
                Segment::UserVar(slot) => {
                    if let Some(slots) = ctx.vars
                        && let Some(val) = slots.get(*slot)
                    {
                        out.push_str(val);
                    }
                }
                Segment::RegexCapture {
                    matcher_name,
                    group,
                } => {
                    if let Some(name) = ctx.regex_matcher_name
                        && name == matcher_name.as_str()
                        && let Some(caps) = ctx.regex_captures
                        && let Some(m) = caps.get(*group)
                    {
                        out.push_str(m.as_str());
                    }
                    // Missing capture or name mismatch → empty string (Caddy behavior)
                }
            }
        }
        out
    }

    /// Evaluate with CRLF sanitization — for header values and redirect targets.
    ///
    /// Strips `\r` and `\n` from the output to prevent header injection
    /// (Guardrail #17: treat all client input as adversarial).
    pub fn evaluate_sanitized(&self, ctx: &TemplateContext<'_>) -> String {
        let mut result = self.evaluate(ctx);
        sanitize_crlf(&mut result);
        result
    }

    /// Evaluate for a redirect target — CRLF sanitization + double-slash collapse.
    ///
    /// Collapses `//` to `/` in the path portion to prevent open redirects
    /// via `https://evil.com` embedded in a `{host}` placeholder.
    pub fn evaluate_redirect(&self, ctx: &TemplateContext<'_>) -> String {
        let mut result = self.evaluate(ctx);
        sanitize_crlf(&mut result);
        collapse_double_slash(&mut result);
        result
    }

    /// Literal-only evaluation — returns the combined literal text.
    /// Visible within the crate for callers that don't have a [`TemplateContext`].
    pub(crate) fn evaluate_literals(&self) -> String {
        match self.segments.as_slice() {
            [] => String::new(),
            [Segment::Literal(s)] => s.clone(),
            _ => {
                let mut out = String::with_capacity(self.literal_len);
                for seg in &self.segments {
                    if let Segment::Literal(s) = seg {
                        out.push_str(s);
                    }
                }
                out
            }
        }
    }
}

impl fmt::Display for CompiledTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for seg in &self.segments {
            match seg {
                Segment::Literal(s) => write!(f, "{s}")?,
                Segment::Placeholder(ph) => write!(f, "{{{}}}", ph.canonical_name())?,
                // User vars display as {var:N} to distinguish from built-ins in debug
                Segment::UserVar(slot) => write!(f, "{{var:{slot}}}")?,
                Segment::RegexCapture {
                    matcher_name,
                    group,
                } => write!(f, "{{re.{matcher_name}.{group}}}")?,
            }
        }
        Ok(())
    }
}

// ── TemplateContext ───────────────────────────────────────────

/// Resolved request values available during template evaluation.
///
/// Created from `RequestContext` per-request. All fields are borrowed —
/// no allocation to build this struct.
#[derive(Debug, Clone)]
pub struct TemplateContext<'a> {
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    /// Path + query string (e.g. `/api?q=1`).
    pub uri: &'a str,
    /// Query string without `?`, or empty string.
    pub query: &'a str,
    /// `"http"` or `"https"`.
    pub scheme: &'a str,
    pub remote_host: &'a str,
    pub remote_port: u16,
    pub request_id: &'a str,
    pub upstream_host: &'a str,
    pub upstream_port: u16,
    pub tls_server_name: &'a str,
    /// User-declared variables from `vars` / `map` directives.
    /// `None` when no variables are declared for this route.
    pub vars: Option<&'a VarSlots>,
    /// Regex captures from a `path_regexp` matcher, if any.
    /// Used by `{re.name.N}` placeholders.
    pub regex_captures: Option<&'a regex::Captures<'a>>,
    /// The matcher name that produced `regex_captures` (e.g., `"api"`).
    pub regex_matcher_name: Option<&'a str>,
}

/// Resolve a single placeholder from the request context.
/// Returns an empty string for placeholders whose context value is not yet
/// computed (file decomposition, cipher, etc. — resolved in `evaluate_owned`).
#[inline]
fn resolve_placeholder<'a>(ph: Placeholder, ctx: &TemplateContext<'a>) -> &'a str {
    match ph {
        Placeholder::Host | Placeholder::HeaderHost => ctx.host,
        Placeholder::Method => ctx.method,
        Placeholder::Path => ctx.path,
        Placeholder::Uri => ctx.uri,
        Placeholder::Query => ctx.query,
        Placeholder::Scheme => ctx.scheme,
        Placeholder::RemoteHost => ctx.remote_host,
        Placeholder::TlsServerName => ctx.tls_server_name,
        Placeholder::UpstreamHost => ctx.upstream_host,
        Placeholder::RequestId => ctx.request_id,
        // Placeholders that need computed values — resolved in evaluate_to_parts
        Placeholder::RemotePort
        | Placeholder::FileExt
        | Placeholder::FileBase
        | Placeholder::Dir
        | Placeholder::TlsCipher
        | Placeholder::UpstreamPort
        | Placeholder::HeaderReferer
        | Placeholder::HeaderUserAgent => "",
    }
}

/// Resolve a placeholder that needs a computed `String` value.
/// Used by `evaluate_to_parts` which can handle both borrowed and owned values.
pub fn resolve_placeholder_owned(ph: Placeholder, ctx: &TemplateContext<'_>) -> Option<String> {
    match ph {
        Placeholder::RemotePort => Some(ctx.remote_port.to_string()),
        Placeholder::UpstreamPort => Some(ctx.upstream_port.to_string()),
        Placeholder::FileExt => {
            let ext = ctx.path.rsplit('.').next();
            if ext.is_some() && ext != Some(ctx.path) && !ctx.path.ends_with('/') {
                ext.map(str::to_owned)
            } else {
                None
            }
        }
        Placeholder::FileBase => {
            let fname = ctx.path.rsplit('/').next().unwrap_or("");
            fname.rfind('.').map(|dot_pos| fname[..dot_pos].to_owned())
        }
        Placeholder::Dir => {
            if let Some(slash) = ctx.path.rfind('/') {
                if slash == 0 {
                    Some("/".to_owned())
                } else {
                    Some(ctx.path[..slash].to_owned())
                }
            } else {
                None
            }
        }
        // Remaining placeholders are either not yet computable or handled by
        // resolve_placeholder (borrowed path).
        _ => None,
    }
}

// ── Sanitization ──────────────────────────────────────────────

/// Strip `\r` and `\n` from a string in-place.
/// Prevents CRLF injection in header values and redirect targets.
fn sanitize_crlf(s: &mut String) {
    if !s.contains(['\r', '\n']) {
        return;
    }
    s.retain(|c| c != '\r' && c != '\n');
}

/// Collapse `//` to `/` in the path portion of a URL.
/// Prevents open redirects via `https://evil.com` in placeholder values.
fn collapse_double_slash(s: &mut String) {
    // Only collapse after the scheme (e.g. don't touch https://)
    if let Some(scheme_end) = s.find("://") {
        let path_start = scheme_end + 3;
        let path_part = s[path_start..].replace("//", "/");
        s.replace_range(path_start.., &path_part);
    } else if s.contains("//") {
        let collapsed = s.replace("//", "/");
        *s = collapsed;
    }
}

// ── Error type ────────────────────────────────────────────────

/// Errors from template compilation — all fail-fast at config load.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TemplateError {
    #[error("unknown placeholder '{{{name}}}' at position {position} in: {input}")]
    UnknownPlaceholder {
        name: String,
        position: usize,
        input: String,
    },
    #[error("empty placeholder '{{}}' at position {position} in: {input}")]
    EmptyPlaceholder { position: usize, input: String },
    #[error("unclosed brace at position {position} in: {input}")]
    UnclosedBrace { position: usize, input: String },
    #[error(
        "invalid placeholder '{{{name}}}' (contains whitespace) at position {position} in: {input}"
    )]
    InvalidPlaceholder {
        name: String,
        position: usize,
        input: String,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_ctx() -> TemplateContext<'static> {
        TemplateContext {
            host: "example.com",
            method: "GET",
            path: "/api/users",
            uri: "/api/users?page=1",
            query: "page=1",
            scheme: "https",
            remote_host: "10.0.0.1",
            remote_port: 54321,
            request_id: "01234567-89ab-cdef-0123-456789abcdef",
            upstream_host: "127.0.0.1",
            upstream_port: 8080,
            tls_server_name: "example.com",
            vars: None,
            regex_captures: None,
            regex_matcher_name: None,
        }
    }

    // ── Compile tests ────────────────────────────────────────

    #[test]
    fn compile_single_placeholder() {
        let t = CompiledTemplate::compile("{host}").unwrap();
        assert_eq!(t.segments.len(), 1);
        assert_eq!(t.evaluate(&test_ctx()), "example.com");
    }

    #[test]
    fn compile_literal_only() {
        let t = CompiledTemplate::compile("/static/path").unwrap();
        assert!(!t.has_placeholders());
        assert_eq!(t.evaluate(&test_ctx()), "/static/path");
    }

    #[test]
    fn compile_prefix_placeholder_suffix() {
        let t = CompiledTemplate::compile("prefix-{host}/api/{path}").unwrap();
        assert_eq!(t.evaluate(&test_ctx()), "prefix-example.com/api//api/users");
    }

    #[test]
    fn compile_adjacent_placeholders() {
        let t = CompiledTemplate::compile("{host}:{path}").unwrap();
        assert_eq!(t.evaluate(&test_ctx()), "example.com:/api/users");
    }

    #[test]
    fn compile_empty_string() {
        let t = CompiledTemplate::compile("").unwrap();
        assert!(!t.has_placeholders());
        assert_eq!(t.evaluate(&test_ctx()), "");
    }

    #[test]
    fn compile_all_placeholders() {
        // Ensure every Placeholder variant compiles
        for name in Placeholder::all_names() {
            let input = format!("{{{name}}}");
            let t = CompiledTemplate::compile(&input);
            assert!(t.is_ok(), "failed to compile placeholder '{name}': {t:?}");
            assert!(t.unwrap().has_placeholders());
        }
    }

    #[test]
    fn compile_unknown_placeholder_is_error() {
        let err = CompiledTemplate::compile("{nonexistent}").unwrap_err();
        match err {
            TemplateError::UnknownPlaceholder { name, .. } => assert_eq!(name, "nonexistent"),
            other => panic!("expected UnknownPlaceholder, got: {other}"),
        }
    }

    #[test]
    fn compile_empty_placeholder_is_error() {
        let err = CompiledTemplate::compile("{}").unwrap_err();
        matches!(err, TemplateError::EmptyPlaceholder { .. });
    }

    #[test]
    fn compile_unclosed_brace_is_error() {
        let err = CompiledTemplate::compile("{host").unwrap_err();
        matches!(err, TemplateError::UnclosedBrace { .. });
    }

    #[test]
    fn compile_whitespace_in_placeholder_is_error() {
        let err = CompiledTemplate::compile("{host name}").unwrap_err();
        matches!(err, TemplateError::InvalidPlaceholder { .. });
    }

    // ── Evaluate tests ────────────────────────────────────────

    #[test]
    fn evaluate_host() {
        let t = CompiledTemplate::compile("{host}").unwrap();
        assert_eq!(t.evaluate(&test_ctx()), "example.com");
    }

    #[test]
    fn evaluate_method() {
        let t = CompiledTemplate::compile("{method}").unwrap();
        assert_eq!(t.evaluate(&test_ctx()), "GET");
    }

    #[test]
    fn evaluate_path() {
        let t = CompiledTemplate::compile("{path}").unwrap();
        assert_eq!(t.evaluate(&test_ctx()), "/api/users");
    }

    #[test]
    fn evaluate_uri() {
        let t = CompiledTemplate::compile("{uri}").unwrap();
        assert_eq!(t.evaluate(&test_ctx()), "/api/users?page=1");
    }

    #[test]
    fn evaluate_query() {
        let t = CompiledTemplate::compile("{query}").unwrap();
        assert_eq!(t.evaluate(&test_ctx()), "page=1");
    }

    #[test]
    fn evaluate_scheme() {
        let t = CompiledTemplate::compile("{scheme}").unwrap();
        assert_eq!(t.evaluate(&test_ctx()), "https");
    }

    #[test]
    fn evaluate_request_id() {
        let t = CompiledTemplate::compile("{request_id}").unwrap();
        assert_eq!(
            t.evaluate(&test_ctx()),
            "01234567-89ab-cdef-0123-456789abcdef"
        );
    }

    #[test]
    fn evaluate_remote_host() {
        let t = CompiledTemplate::compile("{remote_host}").unwrap();
        assert_eq!(t.evaluate(&test_ctx()), "10.0.0.1");
    }

    #[test]
    fn evaluate_complex_url() {
        let t = CompiledTemplate::compile("https://{host}{uri}").unwrap();
        assert_eq!(
            t.evaluate(&test_ctx()),
            "https://example.com/api/users?page=1"
        );
    }

    // ── Sanitization tests ────────────────────────────────────

    #[test]
    fn sanitize_crlf_strips_cr_and_lf() {
        let mut s = "hello\r\nworld".to_owned();
        sanitize_crlf(&mut s);
        assert_eq!(s, "helloworld");
    }

    #[test]
    fn sanitize_crlf_no_op_when_clean() {
        let mut s = "hello world".to_owned();
        sanitize_crlf(&mut s);
        assert_eq!(s, "hello world");
    }

    #[test]
    fn collapse_double_slash_in_path() {
        let mut s = "https://example.com//evil.com/path".to_owned();
        collapse_double_slash(&mut s);
        assert_eq!(s, "https://example.com/evil.com/path");
    }

    #[test]
    fn collapse_preserves_scheme() {
        let mut s = "https://example.com/".to_owned();
        collapse_double_slash(&mut s);
        assert_eq!(s, "https://example.com/");
    }

    #[test]
    fn evaluate_sanitized_strips_crlf() {
        let ctx = TemplateContext {
            host: "evil.com\r\nX-Injected: true",
            ..test_ctx()
        };
        let t = CompiledTemplate::compile("{host}").unwrap();
        let result = t.evaluate_sanitized(&ctx);
        assert_eq!(result, "evil.comX-Injected: true");
        assert!(!result.contains('\r'));
        assert!(!result.contains('\n'));
    }

    #[test]
    fn evaluate_redirect_collapses_double_slash() {
        let ctx = TemplateContext {
            host: "evil.com/",
            ..test_ctx()
        };
        let t = CompiledTemplate::compile("https://{host}{path}").unwrap();
        let result = t.evaluate_redirect(&ctx);
        // {host} = "evil.com/" + {path} = "/api/users" → "evil.com//api/users"
        // redirect evaluation collapses the double slash
        assert_eq!(result, "https://evil.com/api/users");
    }

    // ── Display roundtrip ─────────────────────────────────────

    #[test]
    fn display_roundtrip() {
        let input = "https://{host}{uri}";
        let t = CompiledTemplate::compile(input).unwrap();
        assert_eq!(t.to_string(), input);
    }

    #[test]
    fn display_roundtrip_complex() {
        let input = "prefix-{method}-{host}-{path}-suffix";
        let t = CompiledTemplate::compile(input).unwrap();
        assert_eq!(t.to_string(), input);
    }

    // ── Edge cases ────────────────────────────────────────────

    #[test]
    fn literal_only_fast_path() {
        let t = CompiledTemplate::compile("/health").unwrap();
        assert_eq!(t.segment_count(), 1);
        assert!(!t.has_placeholders());
        // Should return the literal directly without scanning
        assert_eq!(t.evaluate(&test_ctx()), "/health");
    }

    #[test]
    fn multiple_same_placeholder() {
        let t = CompiledTemplate::compile("{host}/{host}").unwrap();
        assert_eq!(t.evaluate(&test_ctx()), "example.com/example.com");
    }

    #[test]
    fn brace_in_literal_after_placeholder() {
        // `}` not part of a placeholder should be literal
        let t = CompiledTemplate::compile("{host}}").unwrap();
        // This compiles as {host} + "}"
        assert_eq!(t.evaluate(&test_ctx()), "example.com}");
    }

    // ── VarRegistry tests (ISSUE-055) ──────────────────────────

    #[test]
    fn registry_assigns_sequential_slots() {
        let mut reg = VarRegistry::new();
        assert_eq!(reg.register("var_a"), 0);
        assert_eq!(reg.register("var_b"), 1);
        assert_eq!(reg.register("var_c"), 2);
        assert_eq!(reg.len(), 3);
    }

    #[test]
    fn registry_idempotent_register() {
        let mut reg = VarRegistry::new();
        assert_eq!(reg.register("x"), 0);
        assert_eq!(reg.register("x"), 0); // same slot, no error
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn registry_get_returns_slot() {
        let mut reg = VarRegistry::new();
        reg.register("alpha");
        reg.register("beta");
        assert_eq!(reg.get("alpha"), Some(0));
        assert_eq!(reg.get("beta"), Some(1));
        assert_eq!(reg.get("unknown"), None);
    }

    #[test]
    fn registry_default_is_empty() {
        let reg = VarRegistry::default();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    // ── VarSlots tests (ISSUE-055) ──────────────────────────────

    #[test]
    fn slots_set_and_get() {
        let mut slots = VarSlots::with_capacity(3);
        slots.set(0, CompactString::from("hello"));
        slots.set(2, CompactString::from("world"));
        assert_eq!(slots.get(0), Some("hello"));
        assert_eq!(slots.get(1), None); // unset
        assert_eq!(slots.get(2), Some("world"));
    }

    #[test]
    fn slots_out_of_range_returns_none() {
        let slots = VarSlots::with_capacity(2);
        assert_eq!(slots.get(99), None);
    }

    #[test]
    fn slots_set_auto_extends() {
        let mut slots = VarSlots::with_capacity(1);
        slots.set(5, CompactString::from("far"));
        assert_eq!(slots.get(5), Some("far"));
        assert_eq!(slots.len(), 6); // extended to fit slot 5
    }

    #[test]
    fn slots_clone() {
        let mut original = VarSlots::with_capacity(2);
        original.set(0, CompactString::from("val"));
        let cloned = original.clone();
        assert_eq!(cloned.get(0), Some("val"));
    }

    #[test]
    fn slots_default_is_empty() {
        let slots = VarSlots::default();
        assert!(slots.is_empty());
    }

    // ── compile_with_registry tests (ISSUE-055) ────────────────

    #[test]
    fn compile_with_registry_user_var() {
        let mut reg = VarRegistry::new();
        reg.register("my_backend");
        let t = CompiledTemplate::compile_with_registry("https://{my_backend}/api", &reg).unwrap();
        assert!(t.has_placeholders());

        let mut slots = VarSlots::with_capacity(reg.len());
        slots.set(0, CompactString::from("app.example.com"));
        let ctx = TemplateContext {
            vars: Some(&slots),
            ..test_ctx()
        };
        assert_eq!(t.evaluate(&ctx), "https://app.example.com/api");
    }

    #[test]
    fn compile_with_registry_mixed_builtin_and_user() {
        let mut reg = VarRegistry::new();
        reg.register("prefix");
        let t = CompiledTemplate::compile_with_registry("/{prefix}{path}", &reg).unwrap();

        let mut slots = VarSlots::with_capacity(reg.len());
        slots.set(0, CompactString::from("api/v2"));
        let ctx = TemplateContext {
            vars: Some(&slots),
            ..test_ctx()
        };
        // {path} = /api/users (built-in), {prefix} = "api/v2" (user var)
        assert_eq!(t.evaluate(&ctx), "/api/v2/api/users");
    }

    #[test]
    fn compile_with_registry_unknown_still_errors() {
        let reg = VarRegistry::new(); // empty registry
        let err = CompiledTemplate::compile_with_registry("{nope}", &reg).unwrap_err();
        match err {
            TemplateError::UnknownPlaceholder { name, .. } => assert_eq!(name, "nope"),
            other => panic!("expected UnknownPlaceholder, got: {other}"),
        }
    }

    #[test]
    fn compile_with_registry_builtin_takes_priority() {
        // "host" is a built-in — even if a user var named "host" exists,
        // the built-in wins
        let mut reg = VarRegistry::new();
        reg.register("host"); // user tries to shadow built-in
        let t = CompiledTemplate::compile_with_registry("{host}", &reg).unwrap();
        // Should resolve as built-in Placeholder::Host, not UserVar(0)
        let mut slots = VarSlots::with_capacity(reg.len());
        slots.set(0, CompactString::from("user-defined-host"));
        let ctx = TemplateContext {
            vars: Some(&slots),
            ..test_ctx()
        };
        // Built-in "host" = "example.com", not the user var
        assert_eq!(t.evaluate(&ctx), "example.com");
    }

    #[test]
    fn compile_with_registry_multiple_user_vars() {
        let mut reg = VarRegistry::new();
        reg.register("env");
        reg.register("version");
        let t = CompiledTemplate::compile_with_registry("/{env}/v{version}/health", &reg).unwrap();

        let mut slots = VarSlots::with_capacity(reg.len());
        slots.set(0, CompactString::from("production"));
        slots.set(1, CompactString::from("3"));
        let ctx = TemplateContext {
            vars: Some(&slots),
            ..test_ctx()
        };
        assert_eq!(t.evaluate(&ctx), "/production/v3/health");
    }

    #[test]
    fn compile_with_registry_unset_var_produces_empty() {
        let mut reg = VarRegistry::new();
        reg.register("missing");
        let t = CompiledTemplate::compile_with_registry("pre-{missing}-post", &reg).unwrap();
        // Slot not set in VarSlots
        let slots = VarSlots::with_capacity(reg.len());
        let ctx = TemplateContext {
            vars: Some(&slots),
            ..test_ctx()
        };
        assert_eq!(t.evaluate(&ctx), "pre--post");
    }

    #[test]
    fn compile_with_no_vars_context_produces_empty() {
        let mut reg = VarRegistry::new();
        reg.register("my_var");
        let t = CompiledTemplate::compile_with_registry("{my_var}", &reg).unwrap();
        let ctx = TemplateContext {
            vars: None, // no vars provided
            ..test_ctx()
        };
        assert_eq!(t.evaluate(&ctx), "");
    }

    #[test]
    fn user_var_in_sanitized_output() {
        let mut reg = VarRegistry::new();
        reg.register("redirect_target");
        let t = CompiledTemplate::compile_with_registry("https://{redirect_target}", &reg).unwrap();

        let mut slots = VarSlots::with_capacity(reg.len());
        slots.set(0, CompactString::from("evil.com\r\nX-Bad: true"));
        let ctx = TemplateContext {
            vars: Some(&slots),
            ..test_ctx()
        };
        let result = t.evaluate_sanitized(&ctx);
        assert!(!result.contains('\r'));
        assert!(!result.contains('\n'));
        assert_eq!(result, "https://evil.comX-Bad: true");
    }

    // ── VarSlots bounds (L-06) ──────────────────────────────

    #[test]
    fn var_slots_set_rejects_out_of_range_index() {
        // A bogus slot index must not grow the backing Vec unboundedly.
        let mut slots = VarSlots::with_capacity(4);
        assert_eq!(slots.len(), 4);

        slots.set(10_000, CompactString::from("boom"));
        assert_eq!(
            slots.len(),
            4,
            "out-of-range slot must not resize the backing Vec"
        );
        assert_eq!(slots.get(10_000), None);
    }

    #[test]
    fn var_slots_set_allows_up_to_max_var_slots() {
        let mut slots = VarSlots::with_capacity(0);
        // Last accepted slot is MAX_VAR_SLOTS - 1.
        let last = (MAX_VAR_SLOTS - 1) as u16;
        slots.set(last, CompactString::from("ok"));
        assert_eq!(slots.get(last), Some("ok"));
        assert_eq!(slots.len(), MAX_VAR_SLOTS);

        // One past the cap is rejected; len stays capped.
        slots.set(MAX_VAR_SLOTS as u16, CompactString::from("reject"));
        assert_eq!(slots.len(), MAX_VAR_SLOTS);
    }

    // ── Regex capture tests ──────────────────────────────────

    #[test]
    fn compile_regex_capture_placeholder() {
        let t = CompiledTemplate::compile("/internal/v{re.api.1}/{re.api.2}").unwrap();
        assert!(t.has_placeholders());
        assert_eq!(t.segment_count(), 4); // "/internal/v", capture 1, "/", capture 2
    }

    #[test]
    fn evaluate_regex_capture_with_captures() {
        let t = CompiledTemplate::compile("/internal/v{re.api.1}/{re.api.2}").unwrap();
        let re = regex::Regex::new(r"/api/v([0-9]+)/(.*)").unwrap();
        let caps = re.captures("/api/v3/users/list").unwrap();
        let ctx = TemplateContext {
            regex_captures: Some(&caps),
            regex_matcher_name: Some("api"),
            ..test_ctx()
        };
        assert_eq!(t.evaluate(&ctx), "/internal/v3/users/list");
    }

    #[test]
    fn regex_capture_missing_captures_returns_empty() {
        let t = CompiledTemplate::compile("/prefix{re.api.1}/suffix").unwrap();
        let ctx = test_ctx();
        assert_eq!(t.evaluate(&ctx), "/prefix/suffix");
    }

    #[test]
    fn regex_capture_name_mismatch_returns_empty() {
        let t = CompiledTemplate::compile("{re.other.1}").unwrap();
        let re = regex::Regex::new(r"(hello)").unwrap();
        let caps = re.captures("hello world").unwrap();
        let ctx = TemplateContext {
            regex_captures: Some(&caps),
            regex_matcher_name: Some("api"),
            ..test_ctx()
        };
        assert_eq!(t.evaluate(&ctx), "");
    }

    #[test]
    fn regex_capture_group_out_of_range_returns_empty() {
        let t = CompiledTemplate::compile("{re.api.99}").unwrap();
        let re = regex::Regex::new(r"(hello)").unwrap();
        let caps = re.captures("hello").unwrap();
        let ctx = TemplateContext {
            regex_captures: Some(&caps),
            regex_matcher_name: Some("api"),
            ..test_ctx()
        };
        assert_eq!(t.evaluate(&ctx), "");
    }

    #[test]
    fn regex_capture_group_zero_is_full_match() {
        let t = CompiledTemplate::compile("{re.m.0}").unwrap();
        let re = regex::Regex::new(r"/api/v([0-9]+)").unwrap();
        let caps = re.captures("/api/v42").unwrap();
        let ctx = TemplateContext {
            regex_captures: Some(&caps),
            regex_matcher_name: Some("m"),
            ..test_ctx()
        };
        assert_eq!(t.evaluate(&ctx), "/api/v42");
    }

    #[test]
    fn regex_capture_display_roundtrip() {
        let input = "/v{re.api.1}/{re.api.2}";
        let t = CompiledTemplate::compile(input).unwrap();
        assert_eq!(t.to_string(), input);
    }

    #[test]
    fn regex_capture_mixed_with_builtins() {
        let t = CompiledTemplate::compile("{scheme}://{host}/v{re.api.1}").unwrap();
        let re = regex::Regex::new(r"/api/v([0-9]+)").unwrap();
        let caps = re.captures("/api/v2").unwrap();
        let ctx = TemplateContext {
            regex_captures: Some(&caps),
            regex_matcher_name: Some("api"),
            ..test_ctx()
        };
        assert_eq!(t.evaluate(&ctx), "https://example.com/v2");
    }

    #[test]
    fn parse_regex_capture_valid_formats() {
        let seg = parse_regex_capture("re.api.1").unwrap();
        assert!(
            matches!(seg, Segment::RegexCapture { ref matcher_name, group } if matcher_name == "api" && group == 1)
        );

        let seg = parse_regex_capture("re.match.0").unwrap();
        assert!(
            matches!(seg, Segment::RegexCapture { ref matcher_name, group } if matcher_name == "match" && group == 0)
        );

        let seg = parse_regex_capture("re.test.12").unwrap();
        assert!(
            matches!(seg, Segment::RegexCapture { ref matcher_name, group } if matcher_name == "test" && group == 12)
        );
    }

    #[test]
    fn parse_regex_capture_invalid_formats() {
        assert!(parse_regex_capture("api.1").is_none());
        assert!(parse_regex_capture("re.api").is_none());
        assert!(parse_regex_capture("re..1").is_none());
        assert!(parse_regex_capture("re.api.abc").is_none());
        assert!(parse_regex_capture("re.").is_none());
    }

    #[test]
    fn regex_capture_sanitized_strips_crlf() {
        let t = CompiledTemplate::compile("{re.m.1}").unwrap();
        let re = regex::Regex::new(r"(.+)").unwrap();
        let input = "evil\r\nheader";
        let caps = re.captures(input).unwrap();
        let ctx = TemplateContext {
            regex_captures: Some(&caps),
            regex_matcher_name: Some("m"),
            ..test_ctx()
        };
        let result = t.evaluate_sanitized(&ctx);
        assert!(!result.contains('\r'));
        assert!(!result.contains('\n'));
    }
}
