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
    BasicAuthDirective, Directive, DwaarConfig, EncodeDirective, FileServerDirective,
    ForwardAuthDirective, HeaderDirective, RateLimitDirective, RedirDirective, RespondDirective,
    ReverseProxyDirective, RewriteDirective, RootDirective, TlsDirective, UpstreamAddr,
    UriDirective, UriOperation,
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
        Directive::ReverseProxy(rp) => format_reverse_proxy(out, rp),
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
    }
}

fn format_reverse_proxy(out: &mut String, rp: &ReverseProxyDirective) {
    out.push_str("reverse_proxy");
    for upstream in &rp.upstreams {
        out.push(' ');
        match upstream {
            UpstreamAddr::SocketAddr(addr) => out.push_str(&addr.to_string()),
            UpstreamAddr::HostPort(hp) => out.push_str(hp),
        }
    }
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
    out.push_str(&outer);
    out.push('}');
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
