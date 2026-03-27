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
    Directive, DwaarConfig, EncodeDirective, HeaderDirective, RateLimitDirective, RedirDirective,
    ReverseProxyDirective, TlsDirective, UpstreamAddr,
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
            out.push_str("    ");
            format_directive(&mut out, directive);
            out.push('\n');
        }

        out.push_str("}\n");
    }

    out
}

fn format_directive(out: &mut String, directive: &Directive) {
    match directive {
        Directive::ReverseProxy(rp) => format_reverse_proxy(out, rp),
        Directive::Tls(tls) => format_tls(out, tls),
        Directive::Header(h) => format_header(out, h),
        Directive::Redir(r) => format_redir(out, r),
        Directive::Encode(e) => format_encode(out, e),
        Directive::RateLimit(rl) => format_rate_limit(out, rl),
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
}
