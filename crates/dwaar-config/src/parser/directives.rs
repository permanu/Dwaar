// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Routing directive parsers — determines where a request goes.
//!
//! Covers: `reverse_proxy`, `redir`, `rewrite`, `uri`, `respond`, `handle`, `handle_path`,
//! `handle_errors`, `route`, `root`, `file_server`, `php_fastcgi`, `forward_auth`, `try_files`.

use crate::error::{ParseError, ParseErrorKind};
use crate::model::{
    Directive, FileServerDirective, ForwardAuthDirective, HandleDirective, HandleErrorsDirective,
    HandlePathDirective, LbPolicy, PhpFastcgiDirective, RedirDirective, RespondDirective,
    ReverseProxyDirective, RewriteDirective, RootDirective, RouteDirective, ScaleToZeroDirective,
    TryFilesDirective, UriDirective, UriOperation, WasmPluginDirective,
};
use crate::token::{TokenKind, Tokenizer};

use super::helpers::{
    expect_word_or_quoted, is_directive_name, parse_optional_pattern, parse_upstream_addr,
};

/// `reverse_proxy localhost:8080` or block form:
/// ```text
/// reverse_proxy {
///     to backend1:8080 backend2:8080
///     lb_policy round_robin
///     health_uri /health
///     health_interval 10
///     fail_duration 30
///     max_conns 100
///     transport {
///         tls_server_name backend.internal
///     }
/// }
/// ```
pub(super) fn parse_reverse_proxy(
    t: &mut Tokenizer<'_>,
) -> Result<ReverseProxyDirective, ParseError> {
    // Check whether this is inline form or block form.
    // Inline: address words follow immediately.
    // Block: a `{` follows immediately (possibly after whitespace).
    if let TokenKind::OpenBrace = t.peek().kind {
        parse_reverse_proxy_block(t)
    } else {
        parse_reverse_proxy_inline(t)
    }
}

/// Parse inline form: `reverse_proxy host1:port [host2:port ...]`
fn parse_reverse_proxy_inline(t: &mut Tokenizer<'_>) -> Result<ReverseProxyDirective, ParseError> {
    let mut upstreams = Vec::new();

    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::Word(w) => {
                // Stop at the next directive name — it belongs to the enclosing block
                if is_directive_name(w) {
                    break;
                }
                t.next_token();
                upstreams.push(parse_upstream_addr(w));
            }
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
                accepted_format: None,
            },
        });
    }

    Ok(ReverseProxyDirective {
        upstreams,
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
    })
}

/// Returns true if `w` is a known subdirective keyword inside a `reverse_proxy { }` block.
///
/// Needed so the `to` argument parser stops at the next subdirective instead of
/// treating keywords like `lb_policy` as upstream addresses.
fn is_reverse_proxy_subdirective(w: &str) -> bool {
    matches!(
        w,
        "to" | "lb_policy"
            | "health_uri"
            | "health_interval"
            | "fail_duration"
            | "max_conns"
            | "transport"
            | "scale_to_zero"
    )
}

/// Parse block form: `reverse_proxy { to ...; lb_policy ...; ... }`
#[allow(clippy::too_many_lines)]
fn parse_reverse_proxy_block(t: &mut Tokenizer<'_>) -> Result<ReverseProxyDirective, ParseError> {
    // Consume the opening `{`
    t.next_token();

    let mut upstreams = Vec::new();
    let mut lb_policy: Option<LbPolicy> = None;
    let mut health_uri: Option<String> = None;
    let mut health_interval: Option<u64> = None;
    let mut fail_duration: Option<u64> = None;
    let mut max_conns: Option<u32> = None;
    let mut transport_tls = false;
    let mut transport_h2 = false;
    let mut tls_server_name: Option<String> = None;
    let mut tls_client_auth: Option<(String, String)> = None;
    let mut tls_trusted_ca_certs: Option<String> = None;
    let mut scale_to_zero: Option<ScaleToZeroDirective> = None;

    loop {
        let tok = t.next_token();
        match tok.kind {
            TokenKind::CloseBrace | TokenKind::Eof => break,
            TokenKind::Word(ref sub) => match sub.as_str() {
                "to" => {
                    // Consume upstream addresses until the next subdirective keyword or brace.
                    // We can't use is_directive_name() here because block subdirectives like
                    // `lb_policy` are not top-level directive names.
                    loop {
                        match t.peek().kind {
                            TokenKind::Word(ref w) if !is_reverse_proxy_subdirective(w) => {
                                let addr_tok = t.next_token();
                                if let TokenKind::Word(w) = addr_tok.kind {
                                    upstreams.push(parse_upstream_addr(&w));
                                }
                            }
                            _ => break,
                        }
                    }
                }
                "lb_policy" => {
                    let policy_tok = t.next_token();
                    let (line, col) = (policy_tok.line, policy_tok.col);
                    if let TokenKind::Word(p) = policy_tok.kind {
                        lb_policy = Some(match p.as_str() {
                            "round_robin" => LbPolicy::RoundRobin,
                            "least_conn" => LbPolicy::LeastConn,
                            "random" => LbPolicy::Random,
                            "ip_hash" => LbPolicy::IpHash,
                            other => {
                                return Err(ParseError {
                                    line,
                                    col,
                                    kind: ParseErrorKind::InvalidValue {
                                        directive: "reverse_proxy".to_string(),
                                        message: format!(
                                            "unknown lb_policy '{other}'; \
                                             expected round_robin, least_conn, random, ip_hash"
                                        ),
                                        accepted_format: None,
                                    },
                                });
                            }
                        });
                    }
                }
                "health_uri" => {
                    let uri_tok = t.next_token();
                    if let TokenKind::Word(u) | TokenKind::QuotedString(u) = uri_tok.kind {
                        health_uri = Some(u);
                    }
                }
                "health_interval" => {
                    let val_tok = t.next_token();
                    let (line, col) = (val_tok.line, val_tok.col);
                    if let TokenKind::Word(v) = val_tok.kind {
                        health_interval = Some(v.parse().map_err(|_| ParseError {
                            line,
                            col,
                            kind: ParseErrorKind::InvalidValue {
                                directive: "reverse_proxy".to_string(),
                                message: format!(
                                    "health_interval must be a positive integer, got '{v}'"
                                ),
                                accepted_format: None,
                            },
                        })?);
                    }
                }
                "fail_duration" => {
                    let val_tok = t.next_token();
                    let (line, col) = (val_tok.line, val_tok.col);
                    if let TokenKind::Word(v) = val_tok.kind {
                        fail_duration = Some(v.parse().map_err(|_| ParseError {
                            line,
                            col,
                            kind: ParseErrorKind::InvalidValue {
                                directive: "reverse_proxy".to_string(),
                                message: format!(
                                    "fail_duration must be a positive integer, got '{v}'"
                                ),
                                accepted_format: None,
                            },
                        })?);
                    }
                }
                "max_conns" => {
                    let val_tok = t.next_token();
                    let (line, col) = (val_tok.line, val_tok.col);
                    if let TokenKind::Word(v) = val_tok.kind {
                        max_conns = Some(v.parse().map_err(|_| ParseError {
                            line,
                            col,
                            kind: ParseErrorKind::InvalidValue {
                                directive: "reverse_proxy".to_string(),
                                message: format!("max_conns must be a positive integer, got '{v}'"),
                                accepted_format: None,
                            },
                        })?);
                    }
                }
                "transport" => {
                    // Expect an optional block `{ tls_server_name ... }`
                    if let TokenKind::OpenBrace = t.peek().kind {
                        t.next_token(); // consume `{`
                        loop {
                            let inner = t.next_token();
                            match inner.kind {
                                TokenKind::CloseBrace | TokenKind::Eof => break,
                                TokenKind::Word(ref kw) if kw == "tls" => {
                                    // `transport { tls }` — plain TLS flag
                                    transport_tls = true;
                                }
                                TokenKind::Word(ref kw) if kw == "h2" || kw == "h2c" => {
                                    // `transport { h2 }` — HTTP/2 upstream multiplexing
                                    transport_h2 = true;
                                }
                                TokenKind::Word(ref kw) if kw == "tls_server_name" => {
                                    transport_tls = true;
                                    let sni_tok = t.next_token();
                                    if let TokenKind::Word(sni) | TokenKind::QuotedString(sni) =
                                        sni_tok.kind
                                    {
                                        tls_server_name = Some(sni);
                                    }
                                }
                                TokenKind::Word(ref kw) if kw == "tls_client_auth" => {
                                    transport_tls = true;
                                    let cert_tok = t.next_token();
                                    let key_tok = t.next_token();
                                    if let (
                                        TokenKind::Word(cert) | TokenKind::QuotedString(cert),
                                        TokenKind::Word(key) | TokenKind::QuotedString(key),
                                    ) = (cert_tok.kind, key_tok.kind)
                                    {
                                        tls_client_auth = Some((cert, key));
                                    }
                                }
                                TokenKind::Word(ref kw) if kw == "tls_trusted_ca_certs" => {
                                    transport_tls = true;
                                    let ca_tok = t.next_token();
                                    if let TokenKind::Word(ca) | TokenKind::QuotedString(ca) =
                                        ca_tok.kind
                                    {
                                        tls_trusted_ca_certs = Some(ca);
                                    }
                                }
                                // Skip unknown transport sub-directives gracefully
                                _ => {}
                            }
                        }
                    } else {
                        // `transport tls` or `transport h2` on a single line — no block
                        if let TokenKind::Word(ref kw) = t.peek().kind {
                            match kw.as_str() {
                                "tls" => {
                                    t.next_token();
                                    transport_tls = true;
                                }
                                "h2" | "h2c" => {
                                    t.next_token();
                                    transport_h2 = true;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                "scale_to_zero" => {
                    scale_to_zero = Some(parse_scale_to_zero_block(t)?);
                }
                // Unknown sub-directive — skip tokens until the next known
                // subdirective keyword or the closing brace. This keeps the parser
                // forward-compatible with future `reverse_proxy` block options.
                _ => loop {
                    match t.peek().kind {
                        TokenKind::CloseBrace | TokenKind::Eof => break,
                        TokenKind::Word(ref w) if is_reverse_proxy_subdirective(w) => break,
                        _ => {
                            t.next_token();
                        }
                    }
                },
            },
            _ => {}
        }
    }

    if upstreams.is_empty() {
        let (line, col) = t.position();
        return Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "reverse_proxy".to_string(),
                message: "block form requires at least one upstream via 'to' subdirective"
                    .to_string(),
                accepted_format: None,
            },
        });
    }

    Ok(ReverseProxyDirective {
        upstreams,
        lb_policy,
        health_uri,
        health_interval,
        fail_duration,
        max_conns,
        transport_tls,
        transport_h2,
        tls_server_name,
        tls_client_auth,
        tls_trusted_ca_certs,
        scale_to_zero,
    })
}

/// `redir /old /new [code]`
pub(super) fn parse_redir(t: &mut Tokenizer<'_>) -> Result<RedirDirective, ParseError> {
    let from_tok = t.next_token();
    let TokenKind::Word(from) = from_tok.kind else {
        return Err(ParseError {
            line: from_tok.line,
            col: from_tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "redir".to_string(),
                message: "expected source path".to_string(),
                accepted_format: None,
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
                accepted_format: None,
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
                            accepted_format: None,
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

/// `rewrite /new-path` — replace the request URI.
pub(super) fn parse_rewrite(t: &mut Tokenizer<'_>) -> Result<RewriteDirective, ParseError> {
    let tok = t.next_token();
    let to = match tok.kind {
        TokenKind::Word(w) => w,
        TokenKind::QuotedString(s) => s,
        _ => {
            return Err(ParseError {
                line: tok.line,
                col: tok.col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "rewrite".to_string(),
                    message: "expected target path".to_string(),
                    accepted_format: None,
                },
            });
        }
    };
    Ok(RewriteDirective { to })
}

/// `uri strip_prefix /api` / `uri strip_suffix .html` / `uri replace /old /new`
pub(super) fn parse_uri(t: &mut Tokenizer<'_>) -> Result<UriDirective, ParseError> {
    let op_tok = t.next_token();
    let TokenKind::Word(op) = &op_tok.kind else {
        return Err(ParseError {
            line: op_tok.line,
            col: op_tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "uri".to_string(),
                message: "expected operation: strip_prefix, strip_suffix, or replace".to_string(),
                accepted_format: None,
            },
        });
    };

    match op.as_str() {
        "strip_prefix" => {
            let val = expect_word_or_quoted(t, "uri", "prefix to strip")?;
            Ok(UriDirective {
                operation: UriOperation::StripPrefix(val),
            })
        }
        "strip_suffix" => {
            let val = expect_word_or_quoted(t, "uri", "suffix to strip")?;
            Ok(UriDirective {
                operation: UriOperation::StripSuffix(val),
            })
        }
        "replace" => {
            let find = expect_word_or_quoted(t, "uri replace", "search string")?;
            let replace = expect_word_or_quoted(t, "uri replace", "replacement string")?;
            Ok(UriDirective {
                operation: UriOperation::Replace { find, replace },
            })
        }
        _ => Err(ParseError {
            line: op_tok.line,
            col: op_tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "uri".to_string(),
                message: format!(
                    "unknown operation '{op}' — expected strip_prefix, strip_suffix, or replace"
                ),
                accepted_format: None,
            },
        }),
    }
}

/// `respond "body" 404` / `respond 204` / `respond "body"` / `respond`
///
/// Caddy semantics: if single arg is a valid 3-digit status code, treat as status.
/// Otherwise treat as body. Two args: body then status.
pub(super) fn parse_respond(t: &mut Tokenizer<'_>) -> Result<RespondDirective, ParseError> {
    let tok = t.peek();
    match &tok.kind {
        // No arguments — empty 200
        TokenKind::CloseBrace | TokenKind::Eof => {
            return Ok(RespondDirective {
                status: 200,
                body: String::new(),
            });
        }
        // Next token is a directive name — no arguments, empty 200
        TokenKind::Word(w) if is_directive_name(w) => {
            return Ok(RespondDirective {
                status: 200,
                body: String::new(),
            });
        }
        _ => {}
    }

    // First argument: could be body (quoted or word) or status code
    let first_tok = t.next_token();
    let first = match first_tok.kind {
        TokenKind::Word(w) => w,
        TokenKind::QuotedString(s) => s,
        _ => {
            return Err(ParseError {
                line: first_tok.line,
                col: first_tok.col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "respond".to_string(),
                    message: "expected body string or status code".to_string(),
                    accepted_format: None,
                },
            });
        }
    };

    // Check for optional second argument (status code)
    let second_tok = t.peek();
    match &second_tok.kind {
        TokenKind::Word(w) if w.parse::<u16>().is_ok() && !is_directive_name(w) => {
            let status_tok = t.next_token();
            let status: u16 = if let TokenKind::Word(w) = &status_tok.kind {
                w.parse().unwrap_or(200)
            } else {
                200
            };
            if !(100..=599).contains(&status) {
                return Err(ParseError {
                    line: status_tok.line,
                    col: status_tok.col,
                    kind: ParseErrorKind::InvalidValue {
                        directive: "respond".to_string(),
                        message: format!("invalid HTTP status code {status} — must be 100-599"),
                        accepted_format: None,
                    },
                });
            }
            Ok(RespondDirective {
                status,
                body: first,
            })
        }
        // Single argument, or `respond <status> "body"` form.
        _ => {
            if let Ok(code) = first.parse::<u16>()
                && (100..=599).contains(&code)
            {
                // Check if the next token is a quoted body string.
                // Caddyfile allows: `respond 200 "custom body"`
                let body = if let TokenKind::QuotedString(_) = &t.peek().kind {
                    let body_tok = t.next_token();
                    if let TokenKind::QuotedString(s) = body_tok.kind {
                        s
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                return Ok(RespondDirective { status: code, body });
            }
            // Not a valid status — treat as body
            Ok(RespondDirective {
                status: 200,
                body: first,
            })
        }
    }
}

/// `handle [pattern] { directives }` — first match wins, path NOT stripped.
pub(super) fn parse_handle(t: &mut Tokenizer<'_>) -> Result<HandleDirective, ParseError> {
    let matcher = parse_optional_pattern(t);
    let directives = parse_directive_block(t)?;
    Ok(HandleDirective {
        matcher,
        directives,
    })
}

/// `handle_path <pattern> { directives }` — first match wins, prefix IS stripped.
pub(super) fn parse_handle_path(t: &mut Tokenizer<'_>) -> Result<HandlePathDirective, ParseError> {
    let path_prefix = expect_word_or_quoted(t, "handle_path", "path prefix pattern")?;
    let directives = parse_directive_block(t)?;
    Ok(HandlePathDirective {
        path_prefix,
        directives,
    })
}

/// `handle_errors { directive* }`
pub(super) fn parse_handle_errors(
    t: &mut Tokenizer<'_>,
    dir_tok: &crate::token::Token,
) -> Result<HandleErrorsDirective, ParseError> {
    if t.peek().kind != TokenKind::OpenBrace {
        return Err(ParseError {
            line: dir_tok.line,
            col: dir_tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "handle_errors".to_string(),
                message: "expected '{' block".to_string(),
                accepted_format: None,
            },
        });
    }
    t.next_token(); // consume '{'

    let mut directives = Vec::new();

    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::CloseBrace => {
                t.next_token();
                break;
            }
            TokenKind::Eof => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::UnexpectedEof {
                        expected: "'}' to close handle_errors block".to_string(),
                    },
                });
            }
            TokenKind::Word(_) => {
                directives.push(super::parse_directive(t)?);
            }
            _ => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "directive or '}'".to_string(),
                        got: format!("{}", tok.kind),
                    },
                });
            }
        }
    }

    Ok(HandleErrorsDirective { directives })
}

/// `route [pattern] { directives }` — all matching blocks execute in order.
pub(super) fn parse_route(t: &mut Tokenizer<'_>) -> Result<RouteDirective, ParseError> {
    let matcher = parse_optional_pattern(t);
    let directives = parse_directive_block(t)?;
    Ok(RouteDirective {
        matcher,
        directives,
    })
}

/// `root * /var/www` or `root /var/www` — the `*` matcher is optional and ignored for now.
pub(super) fn parse_root(t: &mut Tokenizer<'_>) -> Result<RootDirective, ParseError> {
    // First token: might be a matcher (`*`) or the path directly
    let first = expect_word_or_quoted(t, "root", "filesystem path")?;
    if first == "*" {
        // Skip the matcher, read the actual path
        let path = expect_word_or_quoted(t, "root", "filesystem path")?;
        Ok(RootDirective { path })
    } else {
        Ok(RootDirective { path: first })
    }
}

/// `file_server` or `file_server browse`
pub(super) fn parse_file_server(t: &mut Tokenizer<'_>) -> FileServerDirective {
    let browse = matches!(t.peek().kind, TokenKind::Word(ref w) if w == "browse");
    if browse {
        t.next_token();
    }
    FileServerDirective { browse }
}

/// `php_fastcgi localhost:9000` — proxy to `FastCGI` backend.
pub(super) fn parse_php_fastcgi(t: &mut Tokenizer<'_>) -> Result<PhpFastcgiDirective, ParseError> {
    let upstream_str = expect_word_or_quoted(t, "php_fastcgi", "FastCGI upstream address")?;
    let upstream = parse_upstream_addr(&upstream_str);
    Ok(PhpFastcgiDirective { upstream })
}

/// `forward_auth authelia:9091 { uri /api/verify; copy_headers Remote-User Remote-Groups }`
pub(super) fn parse_forward_auth(
    t: &mut Tokenizer<'_>,
) -> Result<ForwardAuthDirective, ParseError> {
    // First token: upstream address
    let (upstream_line, upstream_col) = t.position();
    let upstream_str = expect_word_or_quoted(t, "forward_auth", "upstream address")?;
    let upstream = parse_upstream_addr(&upstream_str);

    // Expect opening brace for the block
    let brace_tok = t.next_token();
    if !matches!(brace_tok.kind, TokenKind::OpenBrace) {
        return Err(ParseError {
            line: brace_tok.line,
            col: brace_tok.col,
            kind: ParseErrorKind::Expected {
                expected: "'{' to start forward_auth block".to_string(),
                got: format!("{}", brace_tok.kind),
            },
        });
    }

    let (uri, copy_headers, tls, insecure_plaintext) = parse_forward_auth_body(t)?;

    // Security guard: plaintext subrequests to non-loopback auth services leak
    // credentials to any on-path attacker. Caught here so `dwaar --test
    // Dwaarfile` surfaces the issue loudly at config-load time rather than
    // burying a warning in request logs that operators can easily miss.
    let is_loopback_target = upstream_is_loopback(&upstream);
    if !tls && !is_loopback_target {
        if !insecure_plaintext {
            return Err(ParseError {
                line: upstream_line,
                col: upstream_col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "forward_auth".to_string(),
                    message: format!(
                        "forward_auth target '{upstream_str}' is plaintext and non-loopback; \
                         set tls: true, use a loopback target, or explicitly opt in with insecure_plaintext: true"
                    ),
                    accepted_format: None,
                },
            });
        }
        // Opted-in plaintext: warn ONCE at parse time so it lands in the
        // operator's eyeline when they load the config, not on the first
        // request after a deploy.
        tracing::warn!(
            "forward_auth target '{upstream_str}' is plaintext (insecure_plaintext=true); \
             credentials transit unencrypted — consider tls: true"
        );
    }

    Ok(ForwardAuthDirective {
        upstream,
        uri,
        copy_headers,
        tls,
        insecure_plaintext,
    })
}

/// Best-effort loopback detection for an `UpstreamAddr`.
///
/// `SocketAddr` gives us the real IP check. For `HostPort` we only know the
/// hostname at parse time (DNS resolution happens at compile/runtime), so we
/// recognize the well-known loopback names. Anything else is assumed to be
/// a non-loopback target, which is the safe default for the security guard.
fn upstream_is_loopback(addr: &crate::model::UpstreamAddr) -> bool {
    match addr {
        crate::model::UpstreamAddr::SocketAddr(sa) => sa.ip().is_loopback(),
        crate::model::UpstreamAddr::HostPort(hp) => {
            let host = hp.split(':').next().unwrap_or(hp);
            matches!(host, "localhost" | "ip6-localhost" | "ip6-loopback")
        }
    }
}

/// Parse the body of a `forward_auth { ... }` block.
// Flat directive-dispatch loop — splitting it would scatter related parse arms.
#[allow(clippy::too_many_lines)]
fn parse_forward_auth_body(
    t: &mut Tokenizer<'_>,
) -> Result<(Option<String>, Vec<String>, bool, bool), ParseError> {
    let mut uri = None;
    let mut copy_headers = Vec::new();
    let mut tls = false;
    let mut insecure_plaintext = false;

    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::CloseBrace => {
                t.next_token();
                break;
            }
            TokenKind::Eof => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::UnexpectedEof {
                        expected: "'}' to close forward_auth block".to_string(),
                    },
                });
            }
            TokenKind::Word(w) => match w.as_str() {
                "uri" => {
                    t.next_token();
                    uri = Some(expect_word_or_quoted(
                        t,
                        "forward_auth uri",
                        "auth URI path",
                    )?);
                }
                "copy_headers" => {
                    t.next_token();
                    loop {
                        let next = t.peek();
                        match &next.kind {
                            TokenKind::Word(w)
                                if !matches!(w.as_str(), "uri" | "copy_headers" | "transport")
                                    && !matches!(next.kind, TokenKind::CloseBrace) =>
                            {
                                copy_headers.push(expect_word_or_quoted(
                                    t,
                                    "copy_headers",
                                    "header name",
                                )?);
                            }
                            _ => break,
                        }
                    }
                }
                "transport" => {
                    t.next_token();
                    let proto = expect_word_or_quoted(t, "forward_auth transport", "protocol")?;
                    if proto != "tls" {
                        let (line, col) = t.position();
                        return Err(ParseError {
                            line,
                            col,
                            kind: ParseErrorKind::InvalidValue {
                                directive: "forward_auth transport".to_string(),
                                message: format!("unknown transport '{proto}' — expected 'tls'"),
                                accepted_format: None,
                            },
                        });
                    }
                    tls = true;
                }
                "insecure_plaintext" => {
                    t.next_token();
                    // Accept bare `insecure_plaintext` or `insecure_plaintext true/false`
                    let next = t.peek();
                    match &next.kind {
                        TokenKind::Word(v) if v == "true" => {
                            t.next_token();
                            insecure_plaintext = true;
                        }
                        TokenKind::Word(v) if v == "false" => {
                            t.next_token();
                            insecure_plaintext = false;
                        }
                        // bare word (no value) — treat as true
                        _ => {
                            insecure_plaintext = true;
                        }
                    }
                }
                other => {
                    return Err(ParseError {
                        line: tok.line,
                        col: tok.col,
                        kind: ParseErrorKind::InvalidValue {
                            directive: "forward_auth".to_string(),
                            message: format!("unknown subdirective '{other}'"),
                            accepted_format: None,
                        },
                    });
                }
            },
            _ => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "subdirective or '}'".to_string(),
                        got: format!("{}", tok.kind),
                    },
                });
            }
        }
    }

    Ok((uri, copy_headers, tls, insecure_plaintext))
}

/// `try_files /index.html /fallback.html`
///
/// Collects all whitespace-separated file patterns as arguments.
pub(super) fn parse_try_files(t: &mut Tokenizer<'_>) -> Result<TryFilesDirective, ParseError> {
    let mut files = Vec::new();

    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::Word(w) => {
                if is_directive_name(w) {
                    break;
                }
                let tok = t.next_token();
                if let TokenKind::Word(w) = tok.kind {
                    files.push(w);
                }
            }
            TokenKind::QuotedString(_) => {
                let tok = t.next_token();
                if let TokenKind::QuotedString(s) = tok.kind {
                    files.push(s);
                }
            }
            _ => break,
        }
    }

    if files.is_empty() {
        let (line, col) = t.position();
        return Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "try_files".to_string(),
                message: "expected at least one file pattern".to_string(),
                accepted_format: None,
            },
        });
    }

    Ok(TryFilesDirective { files })
}

/// Parse a `scale_to_zero { ... }` block inside `reverse_proxy`.
///
/// Recognized subdirectives:
/// - `wake_timeout <seconds>` — max time to wait for backend (default 30s)
/// - `wake_command "<shell command>"` — command to run to wake the backend
fn parse_scale_to_zero_block(t: &mut Tokenizer<'_>) -> Result<ScaleToZeroDirective, ParseError> {
    if !matches!(t.peek().kind, TokenKind::OpenBrace) {
        let (line, col) = t.position();
        return Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::Expected {
                expected: "'{' to open scale_to_zero block".to_string(),
                got: format!("{}", t.peek().kind),
            },
        });
    }
    t.next_token(); // consume `{`

    let mut wake_timeout_secs: u64 = 30;
    let mut wake_command: Option<String> = None;

    loop {
        let tok = t.next_token();
        match tok.kind {
            TokenKind::CloseBrace | TokenKind::Eof => break,
            TokenKind::Word(ref kw) => match kw.as_str() {
                "wake_timeout" => {
                    let val = expect_word_or_quoted(t, "scale_to_zero", "timeout value")?;
                    // Accept bare seconds or a duration suffix like "30s"
                    let secs_str = val.strip_suffix('s').unwrap_or(&val);
                    wake_timeout_secs = secs_str.parse().map_err(|_| ParseError {
                        line: tok.line,
                        col: tok.col,
                        kind: ParseErrorKind::InvalidValue {
                            directive: "scale_to_zero".to_string(),
                            message: format!(
                                "wake_timeout must be a positive integer (seconds), got '{val}'"
                            ),
                            accepted_format: None,
                        },
                    })?;
                }
                "wake_command" => {
                    wake_command =
                        Some(expect_word_or_quoted(t, "scale_to_zero", "shell command")?);
                }
                _ => {
                    // Skip unknown subdirectives inside scale_to_zero
                }
            },
            _ => {}
        }
    }

    let wake_command = wake_command.ok_or_else(|| {
        let (line, col) = t.position();
        ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "scale_to_zero".to_string(),
                message: "wake_command is required".to_string(),
                accepted_format: None,
            },
        }
    })?;

    Ok(ScaleToZeroDirective {
        wake_timeout_secs,
        wake_command,
    })
}

/// `wasm_plugin /path/to/plugin.wasm { priority 50; fuel 1000000; ... }`
///
/// The path comes first, then an optional `{ }` block with subdirectives.
/// All block fields are optional; defaults are applied at compile/runtime.
///
/// Validation: `priority` must be 1–65535. `config` may repeat.
///
/// # Example
///
/// ```text
/// wasm_plugin /plugins/shape.wasm {
///     priority 50
///     fuel 500000
///     memory 8
///     timeout 25
///     config region=eu-west
/// }
/// ```
pub(super) fn parse_wasm_plugin(t: &mut Tokenizer<'_>) -> Result<WasmPluginDirective, ParseError> {
    // Read the required module path.
    let path_tok = t.next_token();
    let (TokenKind::Word(module_path) | TokenKind::QuotedString(module_path)) = path_tok.kind
    else {
        return Err(ParseError {
            line: path_tok.line,
            col: path_tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "wasm_plugin".to_string(),
                message: "expected path to .wasm module".to_string(),
                accepted_format: None,
            },
        });
    };

    // All block subdirective fields default to None / unset.
    let mut priority: Option<u16> = None;
    let mut fuel: Option<u64> = None;
    let mut memory_mb: Option<u32> = None;
    let mut timeout_ms: Option<u64> = None;
    let mut config: Vec<(String, String)> = Vec::new();

    // The `{ }` block is optional — bare `wasm_plugin /path.wasm` is valid.
    if matches!(t.peek().kind, TokenKind::OpenBrace) {
        t.next_token(); // consume `{`
        parse_wasm_plugin_block(
            t,
            &mut priority,
            &mut fuel,
            &mut memory_mb,
            &mut timeout_ms,
            &mut config,
        )?;
    }

    Ok(WasmPluginDirective {
        module_path,
        // Default priority 50 when the block is omitted or `priority` is not set.
        priority: priority.unwrap_or(50),
        fuel,
        memory_mb,
        timeout_ms,
        config,
    })
}

/// Returns true if `w` is a known `wasm_plugin` block subdirective.
fn is_wasm_subdirective(w: &str) -> bool {
    matches!(w, "priority" | "fuel" | "memory" | "timeout" | "config")
}

/// Parse the `{ ... }` body of a `wasm_plugin` block, populating the mutable
/// output fields. Extracted to keep the outer function under 100 lines.
fn parse_wasm_plugin_block(
    t: &mut Tokenizer<'_>,
    priority: &mut Option<u16>,
    fuel: &mut Option<u64>,
    memory_mb: &mut Option<u32>,
    timeout_ms: &mut Option<u64>,
    config: &mut Vec<(String, String)>,
) -> Result<(), ParseError> {
    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::CloseBrace => {
                t.next_token();
                break;
            }
            TokenKind::Eof => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::UnexpectedEof {
                        expected: "'}' to close wasm_plugin block".to_string(),
                    },
                });
            }
            TokenKind::Word(w) => match w.as_str() {
                "priority" => {
                    t.next_token();
                    *priority = Some(parse_wasm_priority(t)?);
                }
                "fuel" => {
                    t.next_token();
                    *fuel = Some(parse_wasm_u64(t, "fuel", "a positive integer")?);
                }
                "memory" => {
                    t.next_token();
                    let mb = parse_wasm_u64(t, "memory", "a positive integer (MiB)")?;
                    *memory_mb = Some(mb as u32);
                }
                "timeout" => {
                    t.next_token();
                    *timeout_ms = Some(parse_wasm_u64(t, "timeout", "a positive integer (ms)")?);
                }
                "config" => {
                    t.next_token();
                    config.push(parse_wasm_config_kv(t)?);
                }
                // Unknown subdirective — skip until the next known keyword or `}`.
                _ => {
                    t.next_token();
                    loop {
                        match t.peek().kind {
                            TokenKind::CloseBrace | TokenKind::Eof => break,
                            TokenKind::Word(ref kw) if is_wasm_subdirective(kw) => break,
                            _ => {
                                t.next_token();
                            }
                        }
                    }
                }
            },
            _ => {
                t.next_token();
            }
        }
    }
    Ok(())
}

/// Parse the `priority <n>` value (1–65535).
fn parse_wasm_priority(t: &mut Tokenizer<'_>) -> Result<u16, ParseError> {
    let val_tok = t.next_token();
    let (line, col) = (val_tok.line, val_tok.col);
    let TokenKind::Word(raw) = val_tok.kind else {
        return Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "wasm_plugin".to_string(),
                message: "priority must be an integer (1–65535)".to_string(),
                accepted_format: None,
            },
        });
    };
    let p: u16 = raw.parse().map_err(|_| ParseError {
        line,
        col,
        kind: ParseErrorKind::InvalidValue {
            directive: "wasm_plugin".to_string(),
            message: format!("priority must be an integer 1–65535, got '{raw}'"),
            accepted_format: None,
        },
    })?;
    if p == 0 {
        return Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "wasm_plugin".to_string(),
                message: "priority must be ≥ 1 (0 is reserved)".to_string(),
                accepted_format: None,
            },
        });
    }
    Ok(p)
}

/// Parse a bare `<u64>` word for `fuel`, `memory`, or `timeout` subdirectives.
fn parse_wasm_u64(
    t: &mut Tokenizer<'_>,
    subdirective: &str,
    what: &str,
) -> Result<u64, ParseError> {
    let val_tok = t.next_token();
    let (line, col) = (val_tok.line, val_tok.col);
    let TokenKind::Word(raw) = val_tok.kind else {
        return Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "wasm_plugin".to_string(),
                message: format!("{subdirective} must be {what}"),
                accepted_format: None,
            },
        });
    };
    raw.parse().map_err(|_| ParseError {
        line,
        col,
        kind: ParseErrorKind::InvalidValue {
            directive: "wasm_plugin".to_string(),
            message: format!("{subdirective} must be {what}, got '{raw}'"),
            accepted_format: None,
        },
    })
}

/// Parse a `key=value` pair for the `config` subdirective.
fn parse_wasm_config_kv(t: &mut Tokenizer<'_>) -> Result<(String, String), ParseError> {
    let kv_tok = t.next_token();
    let (line, col) = (kv_tok.line, kv_tok.col);
    let (TokenKind::Word(kv) | TokenKind::QuotedString(kv)) = kv_tok.kind else {
        return Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "wasm_plugin".to_string(),
                message: "config expects 'key=value'".to_string(),
                accepted_format: None,
            },
        });
    };
    // Split on the first `=`.
    let Some((k, v)) = kv.split_once('=') else {
        return Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "wasm_plugin".to_string(),
                message: format!("config value '{kv}' must be in 'key=value' form"),
                accepted_format: None,
            },
        });
    };
    Ok((k.to_string(), v.to_string()))
}

/// Parse a brace-delimited block of directives — the core of `handle`/`handle_path`/`route`.
/// Reuses `parse_directive()` recursively, enabling nested blocks.
pub(super) fn parse_directive_block(t: &mut Tokenizer<'_>) -> Result<Vec<Directive>, ParseError> {
    let brace_tok = t.next_token();
    if !matches!(brace_tok.kind, TokenKind::OpenBrace) {
        return Err(ParseError {
            line: brace_tok.line,
            col: brace_tok.col,
            kind: ParseErrorKind::Expected {
                expected: "'{'".to_string(),
                got: format!("{}", brace_tok.kind),
            },
        });
    }

    let mut directives = Vec::new();
    loop {
        let tok = t.peek();
        match tok.kind {
            TokenKind::CloseBrace => {
                t.next_token();
                break;
            }
            TokenKind::Eof => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::UnexpectedEof {
                        expected: "'}' to close block".to_string(),
                    },
                });
            }
            _ => {
                directives.push(super::parse_directive(t)?);
            }
        }
    }

    Ok(directives)
}
