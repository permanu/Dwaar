// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Canonical formatter for Dwaarfile syntax.
//!
//! Takes a parsed [`DwaarConfig`] and produces consistently formatted
//! Dwaarfile text — tabs for indentation, one directive per line,
//! blank line between site blocks.

use crate::model::{
    BasicAuthDirective, BindDirective, CacheDirective, CopyResponseHeadersDirective, Directive,
    DwaarConfig, EncodeDirective, ErrorDirective, FileServerDirective, ForwardAuthDirective,
    FsDirective, HandleErrorsDirective, HeaderDirective, InterceptDirective, IpFilterDirective,
    LbPolicy, LogAppendDirective, LogDirective, LogFormat, LogOutput, MapDirective, MapPattern,
    MatcherCondition, MatcherDef, MethodDirective, RateLimitDirective, RecognizedDirective,
    RedirDirective, RequestBodyDirective, RequestHeaderDirective, RespondDirective,
    ResponseBodyLimitDirective, ReverseProxyDirective, RewriteDirective, RootDirective,
    TlsDirective, TryFilesDirective, UpstreamAddr, UriDirective, UriOperation, VarsDirective,
    WasmPluginDirective,
};

/// Format a parsed config into canonical Dwaarfile text.
pub fn format_config(config: &DwaarConfig) -> String {
    let mut out = String::new();

    for (i, site) in config.sites.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&site.address);
        out.push_str(" {\n");

        // Named matcher definitions come before directives.
        for matcher in &site.matchers {
            format_matcher_def(&mut out, matcher);
        }

        for directive in &site.directives {
            format_directive_at_depth(&mut out, directive, 1);
            out.push('\n');
        }

        out.push_str("}\n");
    }

    out
}

fn format_directive_at_depth(out: &mut String, directive: &Directive, depth: usize) {
    let indent = "    ".repeat(depth);
    out.push_str(&indent);
    match directive {
        Directive::ReverseProxy(rp) => format_reverse_proxy(out, rp, depth),
        Directive::Tls(tls) => format_tls(out, tls),
        Directive::Header(h) => format_header(out, h),
        Directive::Redir(r) => format_redir(out, r),
        Directive::Encode(e) => format_encode(out, e),
        Directive::RateLimit(rl) => format_rate_limit(out, rl),
        Directive::Respond(r) => format_respond(out, r),
        Directive::Rewrite(r) => format_rewrite(out, r),
        Directive::Uri(u) => format_uri(out, u),
        Directive::BasicAuth(ba) => format_basicauth(out, ba, depth),
        Directive::ForwardAuth(fa) => format_forward_auth(out, fa, depth),
        Directive::Root(r) => format_root(out, r),
        Directive::FileServer(fs) => format_file_server(out, fs),
        Directive::Handle(h) => {
            format_handle_block(out, "handle", h.matcher.as_deref(), &h.directives, depth);
        }
        Directive::HandlePath(hp) => {
            format_handle_block(
                out,
                "handle_path",
                Some(&hp.path_prefix),
                &hp.directives,
                depth,
            );
        }
        Directive::Route(r) => {
            format_handle_block(out, "route", r.matcher.as_deref(), &r.directives, depth);
        }
        Directive::PhpFastcgi(f) => {
            out.push_str("php_fastcgi ");
            match &f.upstream {
                UpstreamAddr::SocketAddr(addr) => out.push_str(&addr.to_string()),
                UpstreamAddr::HostPort(hp) => out.push_str(hp),
            }
        }
        Directive::Log(ld) => format_log(out, ld, depth),
        Directive::RequestHeader(rh) => format_request_header(out, rh),
        Directive::Error(e) => format_error(out, e),
        Directive::Abort => out.push_str("abort"),
        Directive::Method(m) => format_method(out, m),
        Directive::RequestBody(rb) => format_request_body(out, rb, depth),
        Directive::IpFilter(ipf) => format_ip_filter(out, ipf, depth),
        Directive::ResponseBodyLimit(rbl) => format_response_body_limit(out, rbl),
        Directive::TryFiles(tf) => format_try_files(out, tf),
        Directive::HandleErrors(he) => format_handle_errors(out, he, depth),
        Directive::Bind(b) => format_bind(out, b),
        Directive::SkipLog => out.push_str("skip_log"),
        Directive::Vars(v) => format_vars(out, v),
        // ── ISSUE-056: Typed passthrough replacements ───────────────────
        Directive::Map(m) => format_map(out, m, depth),
        Directive::LogAppend(la) => format_log_append(out, la, depth),
        Directive::LogName(ln) => {
            out.push_str("log_name ");
            out.push_str(&ln.name);
        }
        Directive::Invoke(i) => {
            out.push_str("invoke ");
            out.push_str(&i.name);
        }
        Directive::Fs(f) => format_fs(out, f, depth),
        Directive::Intercept(ic) => format_intercept(out, ic, depth),
        Directive::Metrics(m) => {
            out.push_str("metrics");
            if let Some(path) = &m.path {
                out.push(' ');
                out.push_str(path);
            }
        }
        Directive::Tracing(t) => {
            out.push_str("tracing");
            if let Some(ep) = &t.endpoint {
                out.push(' ');
                out.push_str(ep);
            }
        }
        Directive::CopyResponse(cr) => {
            out.push_str("copy_response");
            for s in &cr.statuses {
                out.push(' ');
                out.push_str(&s.to_string());
            }
        }
        Directive::CopyResponseHeaders(ch) => format_copy_response_headers(out, ch, depth),
        Directive::Templates(r) => format_recognized(out, "templates", r),
        Directive::Push(r) => format_recognized(out, "push", r),
        Directive::AcmeServer(r) => format_recognized(out, "acme_server", r),
        Directive::Cache(c) => format_cache(out, c, depth),
        Directive::WasmPlugin(wp) => format_wasm_plugin(out, wp, depth),
    }
}

fn format_reverse_proxy(out: &mut String, rp: &ReverseProxyDirective, depth: usize) {
    let has_block_options = rp.lb_policy.is_some()
        || rp.health_uri.is_some()
        || rp.health_interval.is_some()
        || rp.fail_duration.is_some()
        || rp.max_conns.is_some()
        || rp.transport_tls
        || rp.transport_h2
        || rp.tls_server_name.is_some()
        || rp.tls_client_auth.is_some()
        || rp.tls_trusted_ca_certs.is_some()
        || rp.upstreams.len() > 1;

    if has_block_options {
        let inner = "    ".repeat(depth + 1);
        let outer = "    ".repeat(depth);

        // Block form — one upstream per line under `to`, then options
        out.push_str("reverse_proxy {\n");
        out.push_str(&inner);
        out.push_str("to");
        for upstream in &rp.upstreams {
            out.push(' ');
            match upstream {
                UpstreamAddr::SocketAddr(addr) => out.push_str(&addr.to_string()),
                UpstreamAddr::HostPort(hp) => out.push_str(hp),
            }
        }
        out.push('\n');

        if let Some(policy) = rp.lb_policy {
            out.push_str(&inner);
            out.push_str("lb_policy ");
            out.push_str(match policy {
                LbPolicy::RoundRobin => "round_robin",
                LbPolicy::LeastConn => "least_conn",
                LbPolicy::Random => "random",
                LbPolicy::IpHash => "ip_hash",
            });
            out.push('\n');
        }
        if let Some(ref uri) = rp.health_uri {
            out.push_str(&inner);
            out.push_str("health_uri ");
            out.push_str(uri);
            out.push('\n');
        }
        if let Some(interval) = rp.health_interval {
            out.push_str(&inner);
            out.push_str("health_interval ");
            out.push_str(&interval.to_string());
            out.push('\n');
        }
        if let Some(dur) = rp.fail_duration {
            out.push_str(&inner);
            out.push_str("fail_duration ");
            out.push_str(&dur.to_string());
            out.push('\n');
        }
        if let Some(max) = rp.max_conns {
            out.push_str(&inner);
            out.push_str("max_conns ");
            out.push_str(&max.to_string());
            out.push('\n');
        }

        format_reverse_proxy_transport(out, rp, depth);

        out.push_str(&outer);
        out.push('}');
    } else {
        // Inline form — space-separated upstreams on one line
        out.push_str("reverse_proxy");
        for upstream in &rp.upstreams {
            out.push(' ');
            match upstream {
                UpstreamAddr::SocketAddr(addr) => out.push_str(&addr.to_string()),
                UpstreamAddr::HostPort(hp) => out.push_str(hp),
            }
        }
    }
}

/// Emit the `transport { tls ... }` block for `reverse_proxy` when TLS options are present.
fn format_reverse_proxy_transport(out: &mut String, rp: &ReverseProxyDirective, depth: usize) {
    let has_transport = rp.transport_tls
        || rp.transport_h2
        || rp.tls_server_name.is_some()
        || rp.tls_client_auth.is_some()
        || rp.tls_trusted_ca_certs.is_some();
    if !has_transport {
        return;
    }
    let inner = "    ".repeat(depth + 1);
    let inner2 = "    ".repeat(depth + 2);
    out.push_str(&inner);
    out.push_str("transport {\n");
    if rp.transport_tls {
        out.push_str(&inner2);
        out.push_str("tls\n");
    }
    if rp.transport_h2 {
        out.push_str(&inner2);
        out.push_str("h2\n");
    }
    if let Some(ref sni) = rp.tls_server_name {
        out.push_str(&inner2);
        out.push_str("tls_server_name ");
        out.push_str(sni);
        out.push('\n');
    }
    if let Some((ref cert, ref key)) = rp.tls_client_auth {
        out.push_str(&inner2);
        out.push_str("tls_client_auth ");
        out.push_str(cert);
        out.push(' ');
        out.push_str(key);
        out.push('\n');
    }
    if let Some(ref ca) = rp.tls_trusted_ca_certs {
        out.push_str(&inner2);
        out.push_str("tls_trusted_ca_certs ");
        out.push_str(ca);
        out.push('\n');
    }
    out.push_str(&inner);
    out.push_str("}\n");
}

fn format_tls(out: &mut String, tls: &TlsDirective) {
    match tls {
        TlsDirective::Auto => out.push_str("tls auto"),
        TlsDirective::Off => out.push_str("tls off"),
        TlsDirective::Internal => out.push_str("tls internal"),
        TlsDirective::Manual {
            cert_path,
            key_path,
        } => {
            out.push_str("tls \"");
            out.push_str(cert_path);
            out.push_str("\" \"");
            out.push_str(key_path);
            out.push('"');
        }
        TlsDirective::DnsChallenge { provider, .. } => {
            // Don't emit the API token in formatted output for security
            out.push_str("tls {\n    dns ");
            out.push_str(provider);
            out.push_str(" <redacted>\n}");
        }
    }
}

fn format_header(out: &mut String, h: &HeaderDirective) {
    match h {
        HeaderDirective::Set { name, value } => {
            out.push_str("header ");
            out.push_str(name);
            out.push_str(" \"");
            out.push_str(value);
            out.push('"');
        }
        HeaderDirective::Delete { name } => {
            out.push_str("header -");
            out.push_str(name);
        }
    }
}

fn format_redir(out: &mut String, r: &RedirDirective) {
    out.push_str("redir ");
    out.push_str(&r.from);
    out.push(' ');
    out.push_str(&r.to);
    if r.code != 308 {
        out.push(' ');
        out.push_str(&r.code.to_string());
    }
}

fn format_encode(out: &mut String, e: &EncodeDirective) {
    out.push_str("encode");
    for encoding in &e.encodings {
        out.push(' ');
        out.push_str(encoding);
    }
}

fn format_rate_limit(out: &mut String, rl: &RateLimitDirective) {
    out.push_str("rate_limit ");
    out.push_str(&rl.requests_per_second.to_string());
    out.push_str("/s");
}

fn format_respond(out: &mut String, r: &RespondDirective) {
    out.push_str("respond");
    if !r.body.is_empty() {
        out.push_str(" \"");
        out.push_str(&r.body);
        out.push('"');
    }
    if r.status != 200 {
        out.push(' ');
        out.push_str(&r.status.to_string());
    }
}

fn format_rewrite(out: &mut String, r: &RewriteDirective) {
    out.push_str("rewrite ");
    out.push_str(&r.to);
}

fn format_uri(out: &mut String, u: &UriDirective) {
    match &u.operation {
        UriOperation::StripPrefix(p) => {
            out.push_str("uri strip_prefix ");
            out.push_str(p);
        }
        UriOperation::StripSuffix(s) => {
            out.push_str("uri strip_suffix ");
            out.push_str(s);
        }
        UriOperation::Replace { find, replace } => {
            out.push_str("uri replace ");
            out.push_str(find);
            out.push(' ');
            out.push_str(replace);
        }
    }
}

fn format_handle_block(
    out: &mut String,
    keyword: &str,
    matcher: Option<&str>,
    directives: &[Directive],
    depth: usize,
) {
    out.push_str(keyword);
    if let Some(pattern) = matcher {
        out.push(' ');
        out.push_str(pattern);
    }
    out.push_str(" {\n");
    for d in directives {
        format_directive_at_depth(out, d, depth + 1);
        out.push('\n');
    }
    let indent = "    ".repeat(depth);
    out.push_str(&indent);
    out.push('}');
}

fn format_basicauth(out: &mut String, ba: &BasicAuthDirective, depth: usize) {
    out.push_str("basicauth");
    if let Some(ref realm) = ba.realm {
        out.push(' ');
        out.push_str(realm);
    }
    out.push_str(" {\n");
    let inner_indent = "    ".repeat(depth + 1);
    for cred in &ba.credentials {
        out.push_str(&inner_indent);
        out.push_str(&cred.username);
        out.push(' ');
        out.push_str(&cred.password_hash);
        out.push('\n');
    }
    let outer_indent = "    ".repeat(depth);
    out.push_str(&outer_indent);
    out.push('}');
}

fn format_root(out: &mut String, r: &RootDirective) {
    out.push_str("root * ");
    out.push_str(&r.path);
}

fn format_file_server(out: &mut String, fs: &FileServerDirective) {
    out.push_str("file_server");
    if fs.browse {
        out.push_str(" browse");
    }
}

fn format_forward_auth(out: &mut String, fa: &ForwardAuthDirective, depth: usize) {
    out.push_str("forward_auth ");
    match &fa.upstream {
        UpstreamAddr::SocketAddr(addr) => out.push_str(&addr.to_string()),
        UpstreamAddr::HostPort(hp) => out.push_str(hp),
    }
    let inner = "    ".repeat(depth + 1);
    let outer = "    ".repeat(depth);
    out.push_str(" {\n");
    if let Some(ref uri) = fa.uri {
        out.push_str(&inner);
        out.push_str("uri ");
        out.push_str(uri);
        out.push('\n');
    }
    if !fa.copy_headers.is_empty() {
        out.push_str(&inner);
        out.push_str("copy_headers");
        for h in &fa.copy_headers {
            out.push(' ');
            out.push_str(h);
        }
        out.push('\n');
    }
    if fa.tls {
        out.push_str(&inner);
        out.push_str("transport tls\n");
    }
    out.push_str(&outer);
    out.push('}');
}

// ── Named matcher formatting ───────────────────────────────────────────────────

/// Format a named matcher definition.
///
/// Single-condition matchers use the compact single-line form:
/// ```text
///     @api path /api/*
/// ```
/// Multi-condition matchers use a block:
/// ```text
///     @api {
///         path /api/*
///         method GET POST
///     }
/// ```
fn format_matcher_def(out: &mut String, m: &MatcherDef) {
    match m.conditions.as_slice() {
        [] => {
            // Empty matcher — single line, no conditions.
            out.push_str("    @");
            out.push_str(&m.name);
            out.push('\n');
        }
        [single] => {
            // Compact single-line form.
            out.push_str("    @");
            out.push_str(&m.name);
            out.push(' ');
            format_matcher_condition_inline(out, single, 1);
            out.push('\n');
        }
        _ => {
            // Block form.
            out.push_str("    @");
            out.push_str(&m.name);
            out.push_str(" {\n");
            for cond in &m.conditions {
                out.push_str("        ");
                format_matcher_condition_inline(out, cond, 2);
                out.push('\n');
            }
            out.push_str("    }\n");
        }
    }
}

/// Format a single matcher condition as a single line (no leading indent).
///
/// `depth` is the current indentation level of the line that will hold this
/// condition — used to indent the bodies of nested blocks (`not`, `file`).
fn format_matcher_condition_inline(out: &mut String, cond: &MatcherCondition, depth: usize) {
    match cond {
        MatcherCondition::Path(paths) => format_word_list(out, "path", paths),
        MatcherCondition::Host(hosts) => format_word_list(out, "host", hosts),
        MatcherCondition::Method(methods) => format_word_list(out, "method", methods),
        MatcherCondition::RemoteIp(cidrs) => format_word_list(out, "remote_ip", cidrs),
        MatcherCondition::ClientIp(cidrs) => format_word_list(out, "client_ip", cidrs),
        MatcherCondition::Query(pairs) => format_word_list(out, "query", pairs),
        MatcherCondition::PathRegexp { name, pattern } => {
            out.push_str("path_regexp");
            if let Some(n) = name {
                out.push(' ');
                out.push_str(n);
            }
            out.push(' ');
            out.push_str(pattern);
        }
        MatcherCondition::Header { name, value } => {
            out.push_str("header ");
            out.push_str(name);
            if let Some(v) = value {
                out.push_str(" \"");
                out.push_str(v);
                out.push('"');
            }
        }
        MatcherCondition::HeaderRegexp { name, pattern } => {
            out.push_str("header_regexp ");
            out.push_str(name);
            out.push(' ');
            out.push_str(pattern);
        }
        MatcherCondition::Protocol(proto) => {
            out.push_str("protocol ");
            out.push_str(proto);
        }
        MatcherCondition::Not(inner) => format_not_condition(out, inner, depth),
        MatcherCondition::Expression(expr) => {
            out.push_str("expression ");
            out.push_str(expr);
        }
        MatcherCondition::File { try_files } => format_file_condition(out, try_files, depth),
        MatcherCondition::Unknown { keyword, args } => {
            out.push_str(keyword);
            for a in args {
                out.push(' ');
                out.push_str(a);
            }
        }
    }
}

/// Format a matcher condition that is a simple keyword followed by a word list.
fn format_word_list(out: &mut String, keyword: &str, words: &[String]) {
    out.push_str(keyword);
    for w in words {
        out.push(' ');
        out.push_str(w);
    }
}

/// Format a `not { ... }` condition block.
///
/// `depth` is the indentation level of the `not` keyword itself.
fn format_not_condition(out: &mut String, inner: &[MatcherCondition], depth: usize) {
    let inner_indent = "    ".repeat(depth + 1);
    let close_indent = "    ".repeat(depth);
    out.push_str("not {\n");
    for cond in inner {
        out.push_str(&inner_indent);
        format_matcher_condition_inline(out, cond, depth + 1);
        out.push('\n');
    }
    out.push_str(&close_indent);
    out.push('}');
}

/// Format a `file { try_files ... }` condition block.
///
/// `depth` is the indentation level of the `file` keyword itself.
fn format_file_condition(out: &mut String, try_files: &[String], depth: usize) {
    let inner_indent = "    ".repeat(depth + 1);
    let close_indent = "    ".repeat(depth);
    out.push_str("file {\n");
    out.push_str(&inner_indent);
    out.push_str("try_files");
    for f in try_files {
        out.push(' ');
        out.push_str(f);
    }
    out.push('\n');
    out.push_str(&close_indent);
    out.push('}');
}

// ── New directive formatters (Phase 3 + 4) ───────────────────────────────────

fn format_log(out: &mut String, ld: &LogDirective, depth: usize) {
    // If no sub-options, emit bare `log`
    if ld.output.is_none() && ld.format.is_none() && ld.level.is_none() {
        out.push_str("log");
        return;
    }

    let inner = "    ".repeat(depth + 1);
    let outer = "    ".repeat(depth);

    out.push_str("log {\n");

    if let Some(output) = &ld.output {
        out.push_str(&inner);
        out.push_str("output ");
        match output {
            LogOutput::Stdout => out.push_str("stdout"),
            LogOutput::Stderr => out.push_str("stderr"),
            LogOutput::Discard => out.push_str("discard"),
            LogOutput::File {
                path,
                max_bytes,
                keep,
            } => {
                out.push_str("file ");
                out.push_str(path);
                if max_bytes.is_some() || keep.is_some() {
                    use std::fmt::Write;
                    out.push_str(" {\n");
                    if let Some(mb) = max_bytes {
                        out.push_str(&inner);
                        let _ = writeln!(out, "    max_size {mb}");
                    }
                    if let Some(k) = keep {
                        out.push_str(&inner);
                        let _ = writeln!(out, "    keep {k}");
                    }
                    out.push_str(&inner);
                    out.push('}');
                }
            }
            LogOutput::Unix { path } => {
                out.push_str("unix ");
                out.push_str(path);
            }
        }
        out.push('\n');
    }

    if let Some(format) = &ld.format {
        out.push_str(&inner);
        out.push_str("format ");
        match format {
            LogFormat::Console => out.push_str("console"),
            LogFormat::Json => out.push_str("json"),
        }
        out.push('\n');
    }

    if let Some(level) = &ld.level {
        out.push_str(&inner);
        out.push_str("level ");
        out.push_str(level);
        out.push('\n');
    }

    out.push_str(&outer);
    out.push('}');
}

fn format_request_header(out: &mut String, rh: &RequestHeaderDirective) {
    match rh {
        RequestHeaderDirective::Set { name, value } => {
            out.push_str("request_header ");
            out.push_str(name);
            out.push_str(" \"");
            out.push_str(value);
            out.push('"');
        }
        RequestHeaderDirective::Delete { name } => {
            out.push_str("request_header -");
            out.push_str(name);
        }
        RequestHeaderDirective::Add { name, value } => {
            out.push_str("request_header +");
            out.push_str(name);
            out.push_str(" \"");
            out.push_str(value);
            out.push('"');
        }
    }
}

fn format_error(out: &mut String, e: &ErrorDirective) {
    out.push_str("error \"");
    out.push_str(&e.message);
    out.push_str("\" ");
    out.push_str(&e.status.to_string());
}

fn format_method(out: &mut String, m: &MethodDirective) {
    out.push_str("method ");
    out.push_str(&m.method);
}

fn format_request_body(out: &mut String, rb: &RequestBodyDirective, depth: usize) {
    let inner = "    ".repeat(depth + 1);
    let outer = "    ".repeat(depth);
    out.push_str("request_body {\n");
    if let Some(max_size) = rb.max_size {
        out.push_str(&inner);
        out.push_str("max_size ");
        out.push_str(&format_size(max_size));
        out.push('\n');
    }
    out.push_str(&outer);
    out.push('}');
}

fn format_ip_filter(out: &mut String, ipf: &IpFilterDirective, depth: usize) {
    let inner = "    ".repeat(depth + 1);
    let outer = "    ".repeat(depth);
    out.push_str("ip_filter {\n");
    if !ipf.allow.is_empty() {
        out.push_str(&inner);
        out.push_str("allow ");
        out.push_str(&ipf.allow.join(" "));
        out.push('\n');
    }
    if !ipf.deny.is_empty() {
        out.push_str(&inner);
        out.push_str("deny ");
        out.push_str(&ipf.deny.join(" "));
        out.push('\n');
    }
    out.push_str(&inner);
    out.push_str(if ipf.default_allow {
        "default allow\n"
    } else {
        "default deny\n"
    });
    out.push_str(&outer);
    out.push('}');
}

fn format_cache(out: &mut String, c: &CacheDirective, depth: usize) {
    let inner = "    ".repeat(depth + 1);
    let outer = "    ".repeat(depth);
    out.push_str("cache {\n");
    if let Some(size) = c.max_size {
        out.push_str(&inner);
        out.push_str("max_size ");
        out.push_str(&format_size(size));
        out.push('\n');
    }
    if !c.match_paths.is_empty() {
        out.push_str(&inner);
        out.push_str("match_path ");
        out.push_str(&c.match_paths.join(" "));
        out.push('\n');
    }
    if let Some(ttl) = c.default_ttl {
        out.push_str(&inner);
        out.push_str("default_ttl ");
        out.push_str(&ttl.to_string());
        out.push('\n');
    }
    if let Some(swr) = c.stale_while_revalidate {
        out.push_str(&inner);
        out.push_str("stale_while_revalidate ");
        out.push_str(&swr.to_string());
        out.push('\n');
    }
    out.push_str(&outer);
    out.push('}');
}

fn format_response_body_limit(out: &mut String, rbl: &ResponseBodyLimitDirective) {
    out.push_str("response_body_limit ");
    out.push_str(&format_size(rbl.max_size));
}

fn format_try_files(out: &mut String, tf: &TryFilesDirective) {
    out.push_str("try_files");
    for file in &tf.files {
        out.push(' ');
        out.push_str(file);
    }
}

fn format_handle_errors(out: &mut String, he: &HandleErrorsDirective, depth: usize) {
    let outer = "    ".repeat(depth);
    out.push_str("handle_errors {\n");
    for directive in &he.directives {
        format_directive_at_depth(out, directive, depth + 1);
        out.push('\n');
    }
    out.push_str(&outer);
    out.push('}');
}

fn format_bind(out: &mut String, b: &BindDirective) {
    out.push_str("bind");
    for addr in &b.addresses {
        out.push(' ');
        out.push_str(addr);
    }
}

fn format_vars(out: &mut String, v: &VarsDirective) {
    out.push_str("vars ");
    out.push_str(&v.key);
    out.push_str(" \"");
    out.push_str(&v.value);
    out.push('"');
}

/// Format a byte count back to a human-readable size string.
///
/// Uses the largest unit that divides evenly, falling back to bytes.
fn format_size(bytes: u64) -> String {
    const GB: u64 = 1024 * 1024 * 1024;
    const MB: u64 = 1024 * 1024;
    const KB: u64 = 1024;

    if bytes.is_multiple_of(GB) {
        format!("{}GB", bytes / GB)
    } else if bytes.is_multiple_of(MB) {
        format!("{}MB", bytes / MB)
    } else if bytes.is_multiple_of(KB) {
        format!("{}KB", bytes / KB)
    } else {
        bytes.to_string()
    }
}

// ── ISSUE-056 formatters ─────────────────────────────────────────────────────

fn format_map(out: &mut String, m: &MapDirective, depth: usize) {
    out.push_str("map ");
    out.push_str(&m.source);
    out.push(' ');
    out.push_str(&m.dest_var);
    out.push_str(" {\n");
    let inner = "    ".repeat(depth + 1);
    for entry in &m.entries {
        out.push_str(&inner);
        match &entry.pattern {
            MapPattern::Exact(e) => {
                out.push_str(e);
            }
            MapPattern::Regex(r) => {
                out.push('~');
                out.push_str(r);
            }
            MapPattern::Default => {
                out.push_str("default");
            }
        }
        out.push(' ');
        out.push_str(&entry.value);
        out.push('\n');
    }
    let outer = "    ".repeat(depth);
    out.push_str(&outer);
    out.push('}');
}

fn format_log_append(out: &mut String, la: &LogAppendDirective, depth: usize) {
    out.push_str("log_append {\n");
    let inner = "    ".repeat(depth + 1);
    for (name, value) in &la.fields {
        out.push_str(&inner);
        out.push_str(name);
        out.push(' ');
        out.push_str(value);
        out.push('\n');
    }
    let outer = "    ".repeat(depth);
    out.push_str(&outer);
    out.push('}');
}

fn format_fs(out: &mut String, f: &FsDirective, _depth: usize) {
    out.push_str("fs");
    for arg in &f.args {
        out.push(' ');
        out.push_str(arg);
    }
    // NOTE: FsDirective currently stores only args (no block). If a block
    // field is added to the model later, block formatting should go here.
}

fn format_intercept(out: &mut String, ic: &InterceptDirective, depth: usize) {
    out.push_str("intercept");
    for s in &ic.statuses {
        out.push(' ');
        out.push_str(&s.to_string());
    }
    out.push_str(" {\n");
    for d in &ic.directives {
        format_directive_at_depth(out, d, depth + 1);
        out.push('\n');
    }
    let outer = "    ".repeat(depth);
    out.push_str(&outer);
    out.push('}');
}

fn format_copy_response_headers(out: &mut String, ch: &CopyResponseHeadersDirective, depth: usize) {
    out.push_str("copy_response_headers {\n");
    let inner = "    ".repeat(depth + 1);
    for h in &ch.headers {
        out.push_str(&inner);
        out.push_str(h);
        out.push('\n');
    }
    let outer = "    ".repeat(depth);
    out.push_str(&outer);
    out.push('}');
}

fn format_recognized(out: &mut String, name: &str, r: &RecognizedDirective) {
    out.push_str(name);
    for arg in &r.args {
        out.push(' ');
        out.push_str(arg);
    }
    // Recognized directives don't have a block field — they just store args.
    // If they had a block, it would need to be formatted, but RecognizedDirective
    // only captures args for forward-compat round-tripping.
}

/// Format a `wasm_plugin` directive as a block form.
///
/// Always emits the block `{ }` form for clarity, even when all fields are
/// at their defaults. This makes diffs readable — you can see exactly what
/// limits apply to every plugin without needing to know the defaults.
fn format_wasm_plugin(out: &mut String, wp: &WasmPluginDirective, depth: usize) {
    use std::fmt::Write as _;
    let outer = "    ".repeat(depth);
    let inner = "    ".repeat(depth + 1);
    let _ = writeln!(out, "wasm_plugin {} {{", wp.module_path);
    let _ = writeln!(out, "{inner}priority {}", wp.priority);
    if let Some(fuel) = wp.fuel {
        let _ = writeln!(out, "{inner}fuel {fuel}");
    }
    if let Some(mb) = wp.memory_mb {
        let _ = writeln!(out, "{inner}memory {mb}");
    }
    if let Some(ms) = wp.timeout_ms {
        let _ = writeln!(out, "{inner}timeout {ms}");
    }
    for (k, v) in &wp.config {
        let _ = writeln!(out, "{inner}config {k}={v}");
    }
    let _ = write!(out, "{outer}}}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    #[test]
    fn roundtrip_simple_config() {
        let input = "example.com {\n    reverse_proxy 127.0.0.1:8080\n}\n";
        let config = parser::parse(input).expect("parse");
        let formatted = format_config(&config);
        assert_eq!(formatted, input);
    }

    #[test]
    fn roundtrip_multiple_sites() {
        let input = "\
api.example.com {
    reverse_proxy 127.0.0.1:3000
    tls auto
}

web.example.com {
    reverse_proxy 127.0.0.1:8080
    encode gzip zstd
}
";
        let config = parser::parse(input).expect("parse");
        let formatted = format_config(&config);
        assert_eq!(formatted, input);
    }

    #[test]
    fn formats_all_directive_types() {
        let input = "\
example.com {
    reverse_proxy 127.0.0.1:8080
    tls \"/cert.pem\" \"/key.pem\"
    header X-Custom \"my value\"
    header -Server
    redir /old /new 301
    encode gzip
}
";
        let config = parser::parse(input).expect("parse");
        let formatted = format_config(&config);
        assert_eq!(formatted, input);
    }

    #[test]
    fn idempotent_formatting() {
        let messy = "   example.com   {  \n  reverse_proxy    127.0.0.1:8080  \n  tls   auto \n } ";
        let config = parser::parse(messy).expect("parse");
        let first = format_config(&config);
        let config2 = parser::parse(&first).expect("reparse");
        let second = format_config(&config2);
        assert_eq!(first, second, "formatting must be idempotent");
    }

    #[test]
    fn redir_omits_default_308_code() {
        let input = "a.com {\n    redir /old /new\n}\n";
        let config = parser::parse(input).expect("parse");
        let formatted = format_config(&config);
        assert_eq!(formatted, input);
    }

    #[test]
    fn empty_config_formats_to_empty_string() {
        let config = DwaarConfig::new();
        assert_eq!(format_config(&config), "");
    }

    #[test]
    fn roundtrip_respond_body_and_status() {
        let input = "a.com {\n    respond \"Not Found\" 404\n}\n";
        let config = parser::parse(input).expect("parse");
        let formatted = format_config(&config);
        assert_eq!(formatted, input);
    }

    #[test]
    fn roundtrip_respond_status_only() {
        let input = "a.com {\n    respond 204\n}\n";
        let config = parser::parse(input).expect("parse");
        let formatted = format_config(&config);
        assert_eq!(formatted, input);
    }

    #[test]
    fn roundtrip_respond_default_200() {
        // respond with no body and status 200 formats as bare "respond"
        let input = "a.com {\n    respond\n}\n";
        let config = parser::parse(input).expect("parse");
        let formatted = format_config(&config);
        assert_eq!(formatted, input);
    }

    #[test]
    fn roundtrip_rewrite() {
        let input = "a.com {\n    reverse_proxy 127.0.0.1:8080\n    rewrite /new\n}\n";
        let config = parser::parse(input).expect("parse");
        assert_eq!(format_config(&config), input);
    }

    #[test]
    fn roundtrip_uri_strip_prefix() {
        let input = "a.com {\n    reverse_proxy 127.0.0.1:8080\n    uri strip_prefix /api\n}\n";
        let config = parser::parse(input).expect("parse");
        assert_eq!(format_config(&config), input);
    }

    #[test]
    fn roundtrip_uri_replace() {
        let input = "a.com {\n    reverse_proxy 127.0.0.1:8080\n    uri replace /old /new\n}\n";
        let config = parser::parse(input).expect("parse");
        assert_eq!(format_config(&config), input);
    }
}
