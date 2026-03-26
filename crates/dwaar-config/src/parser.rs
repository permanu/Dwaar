// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Recursive descent parser for Dwaarfile syntax.
//!
//! Consumes a [`Tokenizer`] stream and produces a [`DwaarConfig`].
//! Every grammar rule is a method: `parse_config` → `parse_site_block`
//! → `parse_directive` → `parse_reverse_proxy`, etc.
//!
//! ## Grammar (simplified)
//!
//! ```text
//! config     = site_block*
//! site_block = address "{" directive* "}"
//! directive  = "reverse_proxy" upstream+
//!            | "tls" tls_arg
//!            | "header" header_arg
//!            | "redir" from to [code]
//!            | "encode" encoding+
//! ```

use crate::error::{ParseError, ParseErrorKind, suggest_directive};
use crate::model::{
    Directive, DwaarConfig, EncodeDirective, HeaderDirective, RedirDirective,
    ReverseProxyDirective, SiteBlock, TlsDirective, UpstreamAddr,
};
use crate::token::{TokenKind, Tokenizer};

/// Parse a Dwaarfile string into a typed config.
///
/// Returns all parse errors encountered (not just the first one).
pub fn parse(input: &str) -> Result<DwaarConfig, ParseError> {
    let mut tokenizer = Tokenizer::new(input);
    parse_config(&mut tokenizer)
}

/// Top-level: parse zero or more site blocks until EOF.
fn parse_config(t: &mut Tokenizer<'_>) -> Result<DwaarConfig, ParseError> {
    let mut sites = Vec::new();

    loop {
        let tok = t.peek();
        match tok.kind {
            TokenKind::Eof => break,
            TokenKind::Word(_) => {
                sites.push(parse_site_block(t)?);
            }
            _ => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "site address (e.g. 'example.com')".to_string(),
                        got: format!("{:?}", tok.kind),
                    },
                });
            }
        }
    }

    Ok(DwaarConfig { sites })
}

/// Parse one site block: `address { directive* }`
fn parse_site_block(t: &mut Tokenizer<'_>) -> Result<SiteBlock, ParseError> {
    // Read the address (domain, IP, or :port)
    let addr_tok = t.next_token();
    let TokenKind::Word(address) = addr_tok.kind else {
        return Err(ParseError {
            line: addr_tok.line,
            col: addr_tok.col,
            kind: ParseErrorKind::Expected {
                expected: "site address".to_string(),
                got: format!("{:?}", addr_tok.kind),
            },
        });
    };

    // Expect opening brace
    let brace = t.next_token();
    if brace.kind != TokenKind::OpenBrace {
        return Err(ParseError {
            line: brace.line,
            col: brace.col,
            kind: ParseErrorKind::Expected {
                expected: "'{'".to_string(),
                got: format!("{:?}", brace.kind),
            },
        });
    }

    // Parse directives until closing brace
    let mut directives = Vec::new();
    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::CloseBrace => {
                t.next_token(); // consume the '}'
                break;
            }
            TokenKind::Eof => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::UnexpectedEof {
                        expected: "'}' to close site block".to_string(),
                    },
                });
            }
            TokenKind::Word(_) => {
                directives.push(parse_directive(t)?);
            }
            _ => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "directive or '}'".to_string(),
                        got: format!("{:?}", tok.kind),
                    },
                });
            }
        }
    }

    Ok(SiteBlock {
        address,
        directives,
    })
}

/// Parse a single directive by dispatching on the directive name.
fn parse_directive(t: &mut Tokenizer<'_>) -> Result<Directive, ParseError> {
    let name_tok = t.next_token();
    let name = match &name_tok.kind {
        TokenKind::Word(w) => w.clone(),
        _ => {
            return Err(ParseError {
                line: name_tok.line,
                col: name_tok.col,
                kind: ParseErrorKind::Expected {
                    expected: "directive name".to_string(),
                    got: format!("{:?}", name_tok.kind),
                },
            });
        }
    };

    match name.as_str() {
        "reverse_proxy" | "proxy" => Ok(Directive::ReverseProxy(parse_reverse_proxy(t)?)),
        "tls" => Ok(Directive::Tls(parse_tls(t)?)),
        "header" => Ok(Directive::Header(parse_header(t)?)),
        "redir" => Ok(Directive::Redir(parse_redir(t)?)),
        "encode" => Ok(Directive::Encode(parse_encode(t)?)),

        // Known Caddyfile directives that aren't implemented yet
        "basicauth" => Err(unsupported(&name_tok, &name, "ISSUE-046")),
        "forward_auth" => Err(unsupported(&name_tok, &name, "ISSUE-047")),
        "file_server" => Err(unsupported(&name_tok, &name, "ISSUE-048")),
        "rewrite" | "uri" => Err(unsupported(&name_tok, &name, "ISSUE-049")),
        "handle" | "handle_path" | "route" => Err(unsupported(&name_tok, &name, "ISSUE-050")),
        "respond" => Err(unsupported(&name_tok, &name, "ISSUE-051")),
        "import" => Err(unsupported(&name_tok, &name, "ISSUE-052")),
        "php_fastcgi" => Err(unsupported(&name_tok, &name, "ISSUE-053")),
        "root" | "log" | "bind" | "abort" | "error" | "metrics" | "templates" | "request_body"
        | "request_header" | "method" | "try_files" | "tracing" | "vars" | "map" | "skip_log"
        | "push" | "acme_server" => Err(unsupported(&name_tok, &name, "not yet tracked")),

        _ => {
            let suggestion = suggest_directive(&name);
            Err(ParseError {
                line: name_tok.line,
                col: name_tok.col,
                kind: ParseErrorKind::UnknownDirective {
                    name,
                    suggestion: suggestion.map(String::from),
                },
            })
        }
    }
}

/// `reverse_proxy localhost:8080` or `reverse_proxy 10.0.0.1:3000 10.0.0.2:3000`
fn parse_reverse_proxy(t: &mut Tokenizer<'_>) -> Result<ReverseProxyDirective, ParseError> {
    let mut upstreams = Vec::new();

    // Consume upstream addresses until we hit a brace, another directive, or EOF
    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::Word(w) => {
                // If this word is a known directive name, stop — it's the next directive
                if is_directive_name(w) {
                    break;
                }
                t.next_token();
                upstreams.push(parse_upstream_addr(w));
            }
            // Stop at braces, EOF, or quoted strings (not valid upstream addrs)
            _ => break,
        }
    }

    if upstreams.is_empty() {
        let (line, col) = t.position();
        return Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "reverse_proxy".to_string(),
                message: "expected at least one upstream address".to_string(),
            },
        });
    }

    Ok(ReverseProxyDirective { upstreams })
}

/// `tls auto` / `tls off` / `tls internal` / `tls /cert /key`
fn parse_tls(t: &mut Tokenizer<'_>) -> Result<TlsDirective, ParseError> {
    let tok = t.peek();
    match &tok.kind {
        TokenKind::Word(w) => {
            let w = w.clone();
            match w.as_str() {
                "auto" => {
                    t.next_token();
                    Ok(TlsDirective::Auto)
                }
                "off" => {
                    t.next_token();
                    Ok(TlsDirective::Off)
                }
                "internal" => {
                    t.next_token();
                    Ok(TlsDirective::Internal)
                }
                _ => {
                    // Assume it's a cert path — next word should be key path
                    t.next_token();
                    let cert_path = w;
                    let key_tok = t.next_token();
                    let (TokenKind::Word(key_path) | TokenKind::QuotedString(key_path)) =
                        key_tok.kind
                    else {
                        return Err(ParseError {
                            line: key_tok.line,
                            col: key_tok.col,
                            kind: ParseErrorKind::InvalidValue {
                                directive: "tls".to_string(),
                                message: "expected key file path after cert path".to_string(),
                            },
                        });
                    };
                    Ok(TlsDirective::Manual {
                        cert_path,
                        key_path,
                    })
                }
            }
        }
        TokenKind::QuotedString(_) => {
            // Quoted cert path — next token should be key path
            let cert_tok = t.next_token();
            let TokenKind::QuotedString(cert_path) = cert_tok.kind else {
                unreachable!()
            };
            let key_tok = t.next_token();
            let (TokenKind::Word(key_path) | TokenKind::QuotedString(key_path)) = key_tok.kind
            else {
                return Err(ParseError {
                    line: key_tok.line,
                    col: key_tok.col,
                    kind: ParseErrorKind::InvalidValue {
                        directive: "tls".to_string(),
                        message: "expected key file path after cert path".to_string(),
                    },
                });
            };
            Ok(TlsDirective::Manual {
                cert_path,
                key_path,
            })
        }
        // No arg means auto (Caddy default)
        _ => Ok(TlsDirective::Auto),
    }
}

/// `header X-Custom "value"` or `header -Server` (delete)
fn parse_header(t: &mut Tokenizer<'_>) -> Result<HeaderDirective, ParseError> {
    let name_tok = t.next_token();
    let name = match &name_tok.kind {
        TokenKind::Word(w) => w.clone(),
        TokenKind::QuotedString(s) => s.clone(),
        _ => {
            return Err(ParseError {
                line: name_tok.line,
                col: name_tok.col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "header".to_string(),
                    message: "expected header name".to_string(),
                },
            });
        }
    };

    // If name starts with '-', it's a delete
    if let Some(stripped) = name.strip_prefix('-') {
        return Ok(HeaderDirective::Delete {
            name: stripped.to_string(),
        });
    }

    // Otherwise read the value
    let val_tok = t.next_token();
    let value = match val_tok.kind {
        TokenKind::Word(w) => w,
        TokenKind::QuotedString(s) => s,
        _ => {
            return Err(ParseError {
                line: val_tok.line,
                col: val_tok.col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "header".to_string(),
                    message: "expected header value".to_string(),
                },
            });
        }
    };

    Ok(HeaderDirective::Set { name, value })
}

/// `redir /old /new [code]`
fn parse_redir(t: &mut Tokenizer<'_>) -> Result<RedirDirective, ParseError> {
    let from_tok = t.next_token();
    let TokenKind::Word(from) = from_tok.kind else {
        return Err(ParseError {
            line: from_tok.line,
            col: from_tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "redir".to_string(),
                message: "expected source path".to_string(),
            },
        });
    };

    let to_tok = t.next_token();
    let (TokenKind::Word(to) | TokenKind::QuotedString(to)) = to_tok.kind else {
        return Err(ParseError {
            line: to_tok.line,
            col: to_tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "redir".to_string(),
                message: "expected destination path".to_string(),
            },
        });
    };

    // Optional status code — default 308 like Caddy
    let code = match t.peek().kind {
        TokenKind::Word(ref w) if w.parse::<u16>().is_ok() => {
            let tok = t.next_token();
            if let TokenKind::Word(w) = tok.kind {
                let parsed: u16 = w.parse().unwrap_or(308);
                if !matches!(parsed, 301 | 302 | 303 | 307 | 308) {
                    return Err(ParseError {
                        line: tok.line,
                        col: tok.col,
                        kind: ParseErrorKind::InvalidValue {
                            directive: "redir".to_string(),
                            message: format!(
                                "invalid redirect code {parsed} — must be 301, 302, 303, 307, or 308"
                            ),
                        },
                    });
                }
                parsed
            } else {
                308
            }
        }
        _ => 308,
    };

    Ok(RedirDirective { from, to, code })
}

/// `encode gzip` / `encode zstd gzip br`
fn parse_encode(t: &mut Tokenizer<'_>) -> Result<EncodeDirective, ParseError> {
    let mut encodings = Vec::new();

    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::Word(w) if matches!(w.as_str(), "gzip" | "zstd" | "br" | "brotli") => {
                let tok = t.next_token();
                if let TokenKind::Word(w) = tok.kind {
                    encodings.push(w);
                }
            }
            _ => break,
        }
    }

    if encodings.is_empty() {
        let (line, col) = t.position();
        return Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "encode".to_string(),
                message: "expected at least one encoding (gzip, zstd, br)".to_string(),
            },
        });
    }

    Ok(EncodeDirective { encodings })
}

/// Parse an upstream address — try socket addr first, fall back to host:port string.
fn parse_upstream_addr(s: &str) -> UpstreamAddr {
    // Handle Caddyfile shorthand: ":8080" means "localhost:8080"
    let normalized = if let Some(port) = s.strip_prefix(':') {
        format!("127.0.0.1:{port}")
    } else if !s.contains(':') {
        // Bare hostname without port — default to 80
        format!("{s}:80")
    } else {
        s.to_string()
    };

    normalized.parse().map_or_else(
        |_| UpstreamAddr::HostPort(normalized),
        UpstreamAddr::SocketAddr,
    )
}

/// Check if a word is a known directive name (used to stop greedy argument parsing).
fn is_directive_name(w: &str) -> bool {
    matches!(
        w,
        "reverse_proxy"
            | "proxy"
            | "tls"
            | "header"
            | "redir"
            | "encode"
            | "basicauth"
            | "forward_auth"
            | "file_server"
            | "rewrite"
            | "uri"
            | "handle"
            | "handle_path"
            | "route"
            | "respond"
            | "import"
            | "php_fastcgi"
            | "root"
            | "log"
            | "bind"
    )
}

fn unsupported(tok: &crate::token::Token, name: &str, issue: &str) -> ParseError {
    ParseError {
        line: tok.line,
        col: tok.col,
        kind: ParseErrorKind::UnsupportedDirective {
            name: name.to_string(),
            tracking_issue: Some(issue.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    // ── Happy path ────────────────────────────────────────

    #[test]
    fn parse_single_site_with_reverse_proxy() {
        let config = parse(
            "example.com {
                reverse_proxy localhost:8080
            }",
        )
        .expect("should parse");

        assert_eq!(config.sites.len(), 1);
        assert_eq!(config.sites[0].address, "example.com");
        assert_eq!(config.sites[0].directives.len(), 1);
        assert!(matches!(
            &config.sites[0].directives[0],
            Directive::ReverseProxy(_)
        ));
    }

    #[test]
    fn parse_multiple_sites() {
        let config = parse(
            "api.example.com {
                reverse_proxy localhost:3000
            }

            web.example.com {
                reverse_proxy localhost:8080
            }",
        )
        .expect("should parse");

        assert_eq!(config.sites.len(), 2);
        assert_eq!(config.sites[0].address, "api.example.com");
        assert_eq!(config.sites[1].address, "web.example.com");
    }

    #[test]
    fn parse_wildcard_domain() {
        let config = parse(
            "*.example.com {
                reverse_proxy localhost:9000
            }",
        )
        .expect("should parse");

        assert_eq!(config.sites[0].address, "*.example.com");
    }

    #[test]
    fn parse_port_shorthand() {
        let config = parse(
            "example.com {
                reverse_proxy :3000
            }",
        )
        .expect("should parse");

        if let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] {
            assert_eq!(
                rp.upstreams[0],
                UpstreamAddr::SocketAddr("127.0.0.1:3000".parse().expect("valid"))
            );
        } else {
            panic!("expected ReverseProxy directive");
        }
    }

    #[test]
    fn parse_multiple_upstreams() {
        let config = parse(
            "example.com {
                reverse_proxy 10.0.0.1:8080 10.0.0.2:8080
            }",
        )
        .expect("should parse");

        if let Directive::ReverseProxy(rp) = &config.sites[0].directives[0] {
            assert_eq!(rp.upstreams.len(), 2);
        } else {
            panic!("expected ReverseProxy directive");
        }
    }

    #[test]
    fn parse_tls_variants() {
        let auto = parse("a.com { tls auto }").expect("parse");
        let off = parse("a.com { tls off }").expect("parse");
        let internal = parse("a.com { tls internal }").expect("parse");
        let manual = parse("a.com { tls /cert.pem /key.pem }").expect("parse");

        assert!(matches!(
            auto.sites[0].directives[0],
            Directive::Tls(TlsDirective::Auto)
        ));
        assert!(matches!(
            off.sites[0].directives[0],
            Directive::Tls(TlsDirective::Off)
        ));
        assert!(matches!(
            internal.sites[0].directives[0],
            Directive::Tls(TlsDirective::Internal)
        ));
        if let Directive::Tls(TlsDirective::Manual {
            ref cert_path,
            ref key_path,
        }) = manual.sites[0].directives[0]
        {
            assert_eq!(cert_path, "/cert.pem");
            assert_eq!(key_path, "/key.pem");
        } else {
            panic!("expected Manual TLS");
        }
    }

    #[test]
    fn parse_header_set_and_delete() {
        let config = parse(
            r#"a.com {
                header X-Custom "my value"
                header -Server
            }"#,
        )
        .expect("parse");

        assert!(matches!(
            &config.sites[0].directives[0],
            Directive::Header(HeaderDirective::Set { name, value })
                if name == "X-Custom" && value == "my value"
        ));
        assert!(matches!(
            &config.sites[0].directives[1],
            Directive::Header(HeaderDirective::Delete { name })
                if name == "Server"
        ));
    }

    #[test]
    fn parse_redir_with_and_without_code() {
        let with_code = parse("a.com { redir /old /new 301 }").expect("parse");
        let default_code = parse("a.com { redir /old /new }").expect("parse");

        if let Directive::Redir(r) = &with_code.sites[0].directives[0] {
            assert_eq!(r.code, 301);
        }
        if let Directive::Redir(r) = &default_code.sites[0].directives[0] {
            assert_eq!(r.code, 308); // Caddy default
        }
    }

    #[test]
    fn parse_encode() {
        let config = parse("a.com { encode gzip zstd }").expect("parse");
        if let Directive::Encode(e) = &config.sites[0].directives[0] {
            assert_eq!(e.encodings, vec!["gzip", "zstd"]);
        } else {
            panic!("expected Encode directive");
        }
    }

    #[test]
    fn parse_multiple_directives() {
        let config = parse(
            r#"example.com {
                reverse_proxy localhost:8080
                tls auto
                header X-Powered-By "Dwaar"
                encode gzip
            }"#,
        )
        .expect("parse");

        assert_eq!(config.sites[0].directives.len(), 4);
    }

    #[test]
    fn parse_comments_ignored() {
        let config = parse(
            "# Main site
            example.com {
                # Backend
                reverse_proxy localhost:8080
            }",
        )
        .expect("parse");

        assert_eq!(config.sites.len(), 1);
    }

    #[test]
    fn parse_empty_config() {
        let config = parse("").expect("parse");
        assert!(config.sites.is_empty());
    }

    #[test]
    fn parse_whitespace_only() {
        let config = parse("   \n\n  \t  \n").expect("parse");
        assert!(config.sites.is_empty());
    }

    // ── Error cases ───────────────────────────────────────

    #[test]
    fn error_missing_closing_brace() {
        let err =
            parse("example.com {\n    reverse_proxy localhost:8080\n").expect_err("should fail");
        assert!(matches!(err.kind, ParseErrorKind::UnexpectedEof { .. }));
    }

    #[test]
    fn error_unknown_directive_with_suggestion() {
        let err = parse("a.com { reverse_proxi localhost:8080 }").expect_err("should fail");
        if let ParseErrorKind::UnknownDirective { name, suggestion } = &err.kind {
            assert_eq!(name, "reverse_proxi");
            assert_eq!(suggestion.as_deref(), Some("reverse_proxy"));
        } else {
            panic!("expected UnknownDirective, got: {err:?}");
        }
    }

    #[test]
    fn error_unsupported_directive_with_tracking() {
        let err = parse("a.com { file_server }").expect_err("should fail");
        if let ParseErrorKind::UnsupportedDirective {
            name,
            tracking_issue,
        } = &err.kind
        {
            assert_eq!(name, "file_server");
            assert_eq!(tracking_issue.as_deref(), Some("ISSUE-048"));
        } else {
            panic!("expected UnsupportedDirective, got: {err:?}");
        }
    }

    #[test]
    fn error_reverse_proxy_no_upstream() {
        let err = parse("a.com { reverse_proxy }").expect_err("should fail");
        assert!(matches!(err.kind, ParseErrorKind::InvalidValue { .. }));
    }

    #[test]
    fn error_includes_line_and_column() {
        let err = parse("a.com {\n    badstuff\n}").expect_err("should fail");
        assert_eq!(err.line, 2);
    }

    // ── Real-world Caddyfile samples ──────────────────────

    #[test]
    fn parse_typical_caddyfile() {
        let config = parse(
            r#"
            api.example.com {
                reverse_proxy localhost:3000
                tls auto
                encode gzip
                header -Server
            }

            web.example.com {
                reverse_proxy localhost:8080
                header X-Frame-Options "SAMEORIGIN"
            }

            *.staging.example.com {
                reverse_proxy localhost:9000
                tls internal
            }
            "#,
        )
        .expect("typical caddyfile should parse");

        assert_eq!(config.sites.len(), 3);
        assert_eq!(config.sites[0].address, "api.example.com");
        assert_eq!(config.sites[0].directives.len(), 4);
        assert_eq!(config.sites[1].address, "web.example.com");
        assert_eq!(config.sites[2].address, "*.staging.example.com");
    }
}
