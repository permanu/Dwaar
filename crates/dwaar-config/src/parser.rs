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
    BasicAuthCredential, BasicAuthDirective, BindDirective, Directive, DwaarConfig,
    EncodeDirective, ErrorDirective, FileServerDirective, ForwardAuthDirective, GlobalOptions,
    HandleDirective, HandleErrorsDirective, HandlePathDirective, HeaderDirective, LogDirective,
    LogFormat, LogOutput, MatcherCondition, MatcherDef, MethodDirective, PhpFastcgiDirective,
    RateLimitDirective, RedirDirective, RequestBodyDirective, RequestHeaderDirective,
    RespondDirective, ReverseProxyDirective, RewriteDirective, RootDirective, RouteDirective,
    SiteBlock, TlsDirective, TryFilesDirective, UpstreamAddr, UriDirective, UriOperation,
    VarsDirective,
};
use crate::token::{TokenKind, Tokenizer};

/// Parse a Dwaarfile string into a typed config.
///
/// Runs the import preprocessor first, then tokenizes and parses.
pub fn parse(input: &str) -> Result<DwaarConfig, ParseError> {
    parse_with_base_dir(input, std::path::Path::new("."))
}

/// Parse with a known base directory for resolving file imports.
pub fn parse_with_base_dir(
    input: &str,
    base_dir: &std::path::Path,
) -> Result<DwaarConfig, ParseError> {
    let expanded = crate::import::expand_imports(input, base_dir)?;
    let mut tokenizer = Tokenizer::new(&expanded);
    parse_config(&mut tokenizer)
}

/// Top-level: parse an optional global options block, then zero or more
/// site blocks until EOF.
///
/// A bare `{` as the very first token means global options (Caddyfile spec).
fn parse_config(t: &mut Tokenizer<'_>) -> Result<DwaarConfig, ParseError> {
    let mut sites = Vec::new();

    // A leading bare `{` is the global options block.
    let global_options = if t.peek().kind == TokenKind::OpenBrace {
        Some(parse_global_options(t)?)
    } else {
        None
    };

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

    Ok(DwaarConfig {
        global_options,
        sites,
    })
}

/// Parse the global options block: `{ key [args]* ... }`.
fn parse_global_options(t: &mut Tokenizer<'_>) -> Result<GlobalOptions, ParseError> {
    t.next_token(); // consume opening `{`

    let mut opts = GlobalOptions::default();

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
                        expected: "'}' to close global options block".to_string(),
                    },
                });
            }
            TokenKind::Word(_) => {
                parse_global_option_line(t, &mut opts)?;
            }
            _ => {
                t.next_token(); // skip unexpected tokens
            }
        }
    }

    Ok(opts)
}

/// Parse one key+args inside the global options block.
/// Dispatches on key name to consume the right number of args.
fn parse_global_option_line(
    t: &mut Tokenizer<'_>,
    opts: &mut GlobalOptions,
) -> Result<(), ParseError> {
    let key_tok = t.next_token();
    let key = match key_tok.kind {
        TokenKind::Word(ref w) => w.clone(),
        _ => return Ok(()),
    };

    match key.as_str() {
        "http_port" => {
            let val = peek_consume_word_or_quoted(t);
            let port: u16 = val.parse().map_err(|_| ParseError {
                line: key_tok.line,
                col: key_tok.col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "http_port".to_string(),
                    message: format!("'{val}' is not a valid port number"),
                },
            })?;
            opts.http_port = Some(port);
        }
        "https_port" => {
            let val = peek_consume_word_or_quoted(t);
            let port: u16 = val.parse().map_err(|_| ParseError {
                line: key_tok.line,
                col: key_tok.col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "https_port".to_string(),
                    message: format!("'{val}' is not a valid port number"),
                },
            })?;
            opts.https_port = Some(port);
        }
        "email" => {
            opts.email = Some(peek_consume_word_or_quoted(t));
        }
        "auto_https" => {
            opts.auto_https = Some(peek_consume_word_or_quoted(t));
        }
        "debug" => {
            opts.debug = true;
        }
        // Unknown option — collect args, consume sub-blocks
        _ => {
            let args = collect_global_passthrough_args(t);
            opts.passthrough.push((key, args));
        }
    }

    Ok(())
}

/// Read the next word/quoted-string if present, else return empty string.
fn peek_consume_word_or_quoted(t: &mut Tokenizer<'_>) -> String {
    match t.peek().kind {
        TokenKind::Word(_) | TokenKind::QuotedString(_) => {
            let tok = t.next_token();
            match tok.kind {
                TokenKind::Word(w) => w,
                TokenKind::QuotedString(s) => s,
                _ => unreachable!(),
            }
        }
        _ => String::new(),
    }
}

/// Collect passthrough args for unknown global options, stopping at known keys.
fn collect_global_passthrough_args(t: &mut Tokenizer<'_>) -> Vec<String> {
    let mut args = Vec::new();
    loop {
        match &t.peek().kind {
            TokenKind::Word(w) if is_global_option_key(w) => break,
            TokenKind::Word(_) | TokenKind::QuotedString(_) => {
                let tok = t.next_token();
                match tok.kind {
                    TokenKind::Word(w) => args.push(w),
                    TokenKind::QuotedString(s) => args.push(s),
                    _ => unreachable!(),
                }
            }
            TokenKind::OpenBrace => {
                t.next_token();
                skip_brace_block(t);
                break;
            }
            _ => break,
        }
    }
    args
}

/// Known global option keywords — used to stop greedy passthrough collection.
fn is_global_option_key(w: &str) -> bool {
    matches!(
        w,
        "http_port"
            | "https_port"
            | "email"
            | "debug"
            | "auto_https"
            | "admin"
            | "grace_period"
            | "shutdown_delay"
            | "log"
            | "order"
            | "storage"
            | "storage_clean_interval"
            | "persist_config"
            | "servers"
            | "default_bind"
            | "metrics"
            | "default_sni"
            | "fallback_sni"
            | "local_certs"
            | "skip_install_trust"
            | "acme_ca"
            | "acme_ca_root"
            | "acme_eab"
            | "acme_dns"
            | "dns"
            | "ech"
            | "on_demand_tls"
            | "key_type"
            | "cert_issuer"
            | "renew_interval"
            | "cert_lifetime"
            | "ocsp_interval"
            | "ocsp_stapling"
            | "pki"
            | "events"
            | "filesystem"
    )
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

    // Parse matchers and directives until closing brace.
    // Named matchers (`@name`) may appear anywhere before directives that
    // reference them, but we collect them separately for compile-time lookup.
    let mut matchers = Vec::new();
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
            TokenKind::Word(w) if w.starts_with('@') => {
                matchers.push(parse_matcher_def(t)?);
            }
            TokenKind::Word(_) => {
                directives.push(parse_directive(t)?);
            }
            _ => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "directive, matcher (@name), or '}'".to_string(),
                        got: format!("{:?}", tok.kind),
                    },
                });
            }
        }
    }

    Ok(SiteBlock {
        address,
        matchers,
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
        "rate_limit" => Ok(Directive::RateLimit(parse_rate_limit(t)?)),

        // Known Caddyfile directives that aren't implemented yet
        "basicauth" | "basic_auth" => Ok(Directive::BasicAuth(parse_basicauth(t)?)),
        "forward_auth" => Ok(Directive::ForwardAuth(parse_forward_auth(t)?)),
        "file_server" => Ok(Directive::FileServer(parse_file_server(t))),
        "root" => Ok(Directive::Root(parse_root(t)?)),
        "rewrite" => Ok(Directive::Rewrite(parse_rewrite(t)?)),
        "uri" => Ok(Directive::Uri(parse_uri(t)?)),
        "handle" => Ok(Directive::Handle(parse_handle(t)?)),
        "handle_path" => Ok(Directive::HandlePath(parse_handle_path(t)?)),
        "route" => Ok(Directive::Route(parse_route(t)?)),
        "respond" => Ok(Directive::Respond(parse_respond(t)?)),
        // import directives are expanded by the preprocessor before parsing.
        // If one reaches here, the preprocessor missed it — that's a bug.
        "import" => Err(ParseError {
            line: name_tok.line,
            col: name_tok.col,
            kind: ParseErrorKind::Other(
                "import directive was not expanded by preprocessor — this is a bug".to_string(),
            ),
        }),
        "php_fastcgi" => Ok(Directive::PhpFastcgi(parse_php_fastcgi(t)?)),
        "log" => Ok(Directive::Log(parse_log(t)?)),
        "request_header" => Ok(Directive::RequestHeader(parse_request_header(t)?)),
        "error" => Ok(Directive::Error(parse_error_directive(t))),
        "abort" => Ok(Directive::Abort),
        "method" => Ok(Directive::Method(parse_method(t, &name_tok)?)),
        "request_body" => Ok(Directive::RequestBody(parse_request_body(t, &name_tok)?)),
        "try_files" => Ok(Directive::TryFiles(parse_try_files(t)?)),
        "handle_errors" => Ok(Directive::HandleErrors(parse_handle_errors(t, &name_tok)?)),
        "bind" => Ok(Directive::Bind(parse_bind(t, &name_tok)?)),
        "skip_log" | "log_skip" => Ok(Directive::SkipLog),
        "vars" => Ok(Directive::Vars(parse_vars(t, &name_tok)?)),

        // Caddy directives we recognize but haven't implemented yet.
        // Parse their full syntax (args + optional block) so the file is valid,
        // then emit a warning at compile time. Guardrail #14: every valid
        // Caddyfile must parse without error.
        "metrics"
        | "templates"
        | "tracing"
        | "map"
        | "push"
        | "acme_server"
        | "invoke"
        | "intercept"
        | "log_append"
        | "log_name"
        | "fs"
        | "copy_response"
        | "copy_response_headers" => {
            let has_block = parse_passthrough(t);
            Ok(Directive::Passthrough { name, has_block })
        }

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

/// `rate_limit 100/s`
fn parse_rate_limit(t: &mut Tokenizer<'_>) -> Result<RateLimitDirective, ParseError> {
    let tok = t.peek();
    let TokenKind::Word(ref value) = tok.kind else {
        let (line, col) = t.position();
        return Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "rate_limit".to_string(),
                message: "expected value like '100/s'".to_string(),
            },
        });
    };

    let value = value.clone();
    let tok = t.next_token();

    let Some(rps_str) = value.strip_suffix("/s") else {
        return Err(ParseError {
            line: tok.line,
            col: tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "rate_limit".to_string(),
                message: format!(
                    "expected '<number>/s' (e.g., '100/s'), got '{value}' — only per-second rates are supported"
                ),
            },
        });
    };

    let rps: u32 = rps_str.parse().map_err(|_| ParseError {
        line: tok.line,
        col: tok.col,
        kind: ParseErrorKind::InvalidValue {
            directive: "rate_limit".to_string(),
            message: format!("'{rps_str}' is not a valid number"),
        },
    })?;

    if rps == 0 {
        return Err(ParseError {
            line: tok.line,
            col: tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "rate_limit".to_string(),
                message: "rate limit must be greater than zero".to_string(),
            },
        });
    }

    Ok(RateLimitDirective {
        requests_per_second: rps,
    })
}

// ── New directive parsers (Phase 3 + 4) ──────────────────────────────────────

/// `log` or `log { output file /path; format json; level INFO }`
fn parse_log(t: &mut Tokenizer<'_>) -> Result<LogDirective, ParseError> {
    // `log` with no block means "enable default logging"
    if t.peek().kind != TokenKind::OpenBrace {
        return Ok(LogDirective {
            output: None,
            format: None,
            level: None,
        });
    }

    t.next_token(); // consume '{'

    let mut output: Option<LogOutput> = None;
    let mut format: Option<LogFormat> = None;
    let mut level: Option<String> = None;

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
                        expected: "'}' to close log block".to_string(),
                    },
                });
            }
            TokenKind::Word(w) => {
                let w = w.clone();
                t.next_token();
                match w.as_str() {
                    "output" => {
                        output = Some(parse_log_output(t)?);
                    }
                    "format" => {
                        format = Some(parse_log_format(t)?);
                    }
                    "level" => {
                        let level_tok = t.next_token();
                        let (TokenKind::Word(level_str) | TokenKind::QuotedString(level_str)) =
                            level_tok.kind
                        else {
                            return Err(ParseError {
                                line: level_tok.line,
                                col: level_tok.col,
                                kind: ParseErrorKind::InvalidValue {
                                    directive: "log".to_string(),
                                    message: "expected log level string (e.g. INFO, DEBUG)"
                                        .to_string(),
                                },
                            });
                        };
                        level = Some(level_str.to_uppercase());
                    }
                    _ => {
                        // Unknown sub-directive inside log block — skip to end of line.
                        // Caddy supports many more log sub-directives; we skip unknown ones
                        // rather than erroring, to preserve forward compatibility.
                        skip_to_next_line(t);
                    }
                }
            }
            _ => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "log sub-directive or '}'".to_string(),
                        got: format!("{:?}", tok.kind),
                    },
                });
            }
        }
    }

    Ok(LogDirective {
        output,
        format,
        level,
    })
}

/// Parse the value after `output` inside a log block.
fn parse_log_output(t: &mut Tokenizer<'_>) -> Result<LogOutput, ParseError> {
    let tok = t.next_token();
    let (line, col) = (tok.line, tok.col);
    let TokenKind::Word(dest) = tok.kind else {
        return Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "log".to_string(),
                message: "expected output destination (stdout, stderr, discard, file)".to_string(),
            },
        });
    };

    match dest.as_str() {
        "stdout" => Ok(LogOutput::Stdout),
        "stderr" => Ok(LogOutput::Stderr),
        "discard" => Ok(LogOutput::Discard),
        "file" => {
            let path_tok = t.next_token();
            let (TokenKind::Word(path) | TokenKind::QuotedString(path)) = path_tok.kind else {
                return Err(ParseError {
                    line: path_tok.line,
                    col: path_tok.col,
                    kind: ParseErrorKind::InvalidValue {
                        directive: "log".to_string(),
                        message: "expected file path after 'output file'".to_string(),
                    },
                });
            };
            Ok(LogOutput::File { path })
        }
        other => Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "log".to_string(),
                message: format!(
                    "unknown log output '{other}' — expected stdout, stderr, discard, or file"
                ),
            },
        }),
    }
}

/// Parse the value after `format` inside a log block.
fn parse_log_format(t: &mut Tokenizer<'_>) -> Result<LogFormat, ParseError> {
    let tok = t.next_token();
    let (line, col) = (tok.line, tok.col);
    match tok.kind {
        TokenKind::Word(w) => match w.as_str() {
            "console" => Ok(LogFormat::Console),
            "json" => Ok(LogFormat::Json),
            other => Err(ParseError {
                line,
                col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "log".to_string(),
                    message: format!("unknown log format '{other}' — expected console or json"),
                },
            }),
        },
        _ => Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "log".to_string(),
                message: "expected log format (console or json)".to_string(),
            },
        }),
    }
}

/// `request_header X-Name "value"` / `request_header -X-Remove` / `request_header +X-Append "value"`
fn parse_request_header(t: &mut Tokenizer<'_>) -> Result<RequestHeaderDirective, ParseError> {
    let name_tok = t.next_token();
    let raw_name = match &name_tok.kind {
        TokenKind::Word(w) => w.clone(),
        TokenKind::QuotedString(s) => s.clone(),
        _ => {
            return Err(ParseError {
                line: name_tok.line,
                col: name_tok.col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "request_header".to_string(),
                    message: "expected header name".to_string(),
                },
            });
        }
    };

    // `-X-Header` means delete
    if let Some(stripped) = raw_name.strip_prefix('-') {
        return Ok(RequestHeaderDirective::Delete {
            name: stripped.to_string(),
        });
    }

    // `+X-Header` means add (append without replacing)
    let (name, is_add) = if let Some(stripped) = raw_name.strip_prefix('+') {
        (stripped.to_string(), true)
    } else {
        (raw_name, false)
    };

    let val_tok = t.next_token();
    let value = match val_tok.kind {
        TokenKind::Word(w) => w,
        TokenKind::QuotedString(s) => s,
        _ => {
            return Err(ParseError {
                line: val_tok.line,
                col: val_tok.col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "request_header".to_string(),
                    message: "expected header value".to_string(),
                },
            });
        }
    };

    if is_add {
        Ok(RequestHeaderDirective::Add { name, value })
    } else {
        Ok(RequestHeaderDirective::Set { name, value })
    }
}

/// `error "message" 500` or `error 404`
///
/// Arguments are order-insensitive: a 3-digit number is the status code,
/// a quoted string or non-numeric word is the message. This matches Caddy's
/// flexible argument ordering.
fn parse_error_directive(t: &mut Tokenizer<'_>) -> ErrorDirective {
    let mut message = String::new();
    let mut status: u16 = 500; // default to 500 when only a message is given
    let mut found_status = false;

    // Read up to two arguments (message and/or status code)
    for _ in 0..2 {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::Word(w) => {
                let w = w.clone();
                // A 3-digit number in [400, 599] is a status code
                if let Ok(n) = w.parse::<u16>()
                    && (400..=599).contains(&n)
                {
                    t.next_token();
                    status = n;
                    found_status = true;
                    continue;
                }
                // Otherwise treat as message text if we haven't got one yet
                if message.is_empty() {
                    t.next_token();
                    message = w;
                } else {
                    break;
                }
            }
            TokenKind::QuotedString(s) => {
                let s = s.clone();
                if message.is_empty() {
                    t.next_token();
                    message = s;
                } else {
                    break;
                }
            }
            _ => break,
        }
    }

    // If only a status code was given with no message, that's fine
    if message.is_empty() {
        message = if found_status {
            status.to_string()
        } else {
            "Internal Server Error".to_string()
        };
    }

    ErrorDirective { message, status }
}

/// `method GET`
fn parse_method(
    t: &mut Tokenizer<'_>,
    dir_tok: &crate::token::Token,
) -> Result<MethodDirective, ParseError> {
    let tok = t.next_token();
    match tok.kind {
        TokenKind::Word(m) => Ok(MethodDirective {
            method: m.to_uppercase(),
        }),
        _ => Err(ParseError {
            line: dir_tok.line,
            col: dir_tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "method".to_string(),
                message: "expected HTTP method name (e.g. GET, POST)".to_string(),
            },
        }),
    }
}

/// `request_body { max_size 10MB }`
fn parse_request_body(
    t: &mut Tokenizer<'_>,
    dir_tok: &crate::token::Token,
) -> Result<RequestBodyDirective, ParseError> {
    if t.peek().kind != TokenKind::OpenBrace {
        return Err(ParseError {
            line: dir_tok.line,
            col: dir_tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "request_body".to_string(),
                message: "expected '{' block".to_string(),
            },
        });
    }
    t.next_token(); // consume '{'

    let mut max_size: Option<u64> = None;

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
                        expected: "'}' to close request_body block".to_string(),
                    },
                });
            }
            TokenKind::Word(w) => {
                let w = w.clone();
                t.next_token();
                match w.as_str() {
                    "max_size" => {
                        let size_tok = t.next_token();
                        let (line, col) = (size_tok.line, size_tok.col);
                        let TokenKind::Word(size_str) = size_tok.kind else {
                            return Err(ParseError {
                                line,
                                col,
                                kind: ParseErrorKind::InvalidValue {
                                    directive: "request_body".to_string(),
                                    message: "expected size value (e.g. 10MB, 512KB)".to_string(),
                                },
                            });
                        };
                        let parsed = parse_size(&size_str).ok_or_else(|| ParseError {
                            line,
                            col,
                            kind: ParseErrorKind::InvalidValue {
                                directive: "request_body".to_string(),
                                message: format!(
                                    "invalid size '{size_str}' — expected a number with optional unit (KB, MB, GB)"
                                ),
                            },
                        })?;
                        max_size = Some(parsed);
                    }
                    _ => {
                        skip_to_next_line(t);
                    }
                }
            }
            _ => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "request_body sub-directive or '}'".to_string(),
                        got: format!("{:?}", tok.kind),
                    },
                });
            }
        }
    }

    Ok(RequestBodyDirective { max_size })
}

/// `try_files /index.html /fallback.html`
///
/// Collects all whitespace-separated file patterns as arguments.
fn parse_try_files(t: &mut Tokenizer<'_>) -> Result<TryFilesDirective, ParseError> {
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
            },
        });
    }

    Ok(TryFilesDirective { files })
}

/// `handle_errors { directive* }`
fn parse_handle_errors(
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

    Ok(HandleErrorsDirective { directives })
}

/// `bind 0.0.0.0` or `bind 127.0.0.1 ::1`
fn parse_bind(
    t: &mut Tokenizer<'_>,
    dir_tok: &crate::token::Token,
) -> Result<BindDirective, ParseError> {
    let mut addresses = Vec::new();

    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::Word(w) => {
                if is_directive_name(w) {
                    break;
                }
                let tok = t.next_token();
                if let TokenKind::Word(addr) = tok.kind {
                    addresses.push(addr);
                }
            }
            _ => break,
        }
    }

    if addresses.is_empty() {
        return Err(ParseError {
            line: dir_tok.line,
            col: dir_tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "bind".to_string(),
                message: "expected at least one bind address".to_string(),
            },
        });
    }

    Ok(BindDirective { addresses })
}

/// `vars key value`
fn parse_vars(
    t: &mut Tokenizer<'_>,
    dir_tok: &crate::token::Token,
) -> Result<VarsDirective, ParseError> {
    let key_tok = t.next_token();
    let key = match key_tok.kind {
        TokenKind::Word(w) => w,
        TokenKind::QuotedString(s) => s,
        _ => {
            return Err(ParseError {
                line: dir_tok.line,
                col: dir_tok.col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "vars".to_string(),
                    message: "expected variable name".to_string(),
                },
            });
        }
    };

    let val_tok = t.next_token();
    let value = match val_tok.kind {
        TokenKind::Word(w) => w,
        TokenKind::QuotedString(s) => s,
        _ => {
            return Err(ParseError {
                line: val_tok.line,
                col: val_tok.col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "vars".to_string(),
                    message: "expected variable value".to_string(),
                },
            });
        }
    };

    Ok(VarsDirective { key, value })
}

/// Parse a human-readable size string like `10MB`, `512KB`, `1GB`, or a bare byte count.
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix("GB").or_else(|| s.strip_suffix("gb")) {
        n.trim().parse::<u64>().ok().map(|n| n * 1024 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("MB").or_else(|| s.strip_suffix("mb")) {
        n.trim().parse::<u64>().ok().map(|n| n * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("KB").or_else(|| s.strip_suffix("kb")) {
        n.trim().parse::<u64>().ok().map(|n| n * 1024)
    } else {
        s.parse().ok()
    }
}

/// Skip tokens until the next line (used to skip unknown sub-directives).
///
/// This reads tokens without consuming the closing brace of the parent block.
fn skip_to_next_line(t: &mut Tokenizer<'_>) {
    loop {
        let tok = t.peek();
        match tok.kind {
            TokenKind::CloseBrace | TokenKind::OpenBrace | TokenKind::Eof => break,
            _ => {
                t.next_token();
            }
        }
    }
}

// ── Named matcher parsing ─────────────────────────────────────────────────────

/// Parse a named matcher definition.
///
/// Two forms are supported:
///
/// Multi-line block:
/// ```text
/// @api {
///     path /api/*
///     method GET POST
/// }
/// ```
///
/// Single-line (exactly one condition):
/// ```text
/// @api path /api/*
/// ```
fn parse_matcher_def(t: &mut Tokenizer<'_>) -> Result<MatcherDef, ParseError> {
    // Consume the `@name` token (the '@' prefix is included in the Word).
    let name_tok = t.next_token();
    let name = match &name_tok.kind {
        TokenKind::Word(w) => {
            // Strip the leading '@' — we validated the prefix in parse_site_block.
            w.trim_start_matches('@').to_string()
        }
        _ => {
            return Err(ParseError {
                line: name_tok.line,
                col: name_tok.col,
                kind: ParseErrorKind::Expected {
                    expected: "matcher name starting with '@'".to_string(),
                    got: format!("{:?}", name_tok.kind),
                },
            });
        }
    };

    let peek = t.peek();
    let conditions = match peek.kind {
        TokenKind::OpenBrace => {
            // Multi-line block: `@name { condition* }`
            t.next_token(); // consume '{'
            let mut conds = Vec::new();
            loop {
                let tok = t.peek();
                match &tok.kind {
                    TokenKind::CloseBrace => {
                        t.next_token(); // consume '}'
                        break;
                    }
                    TokenKind::Eof => {
                        return Err(ParseError {
                            line: tok.line,
                            col: tok.col,
                            kind: ParseErrorKind::UnexpectedEof {
                                expected: format!("'}}' to close matcher '@{name}'"),
                            },
                        });
                    }
                    TokenKind::Word(_) => {
                        conds.push(parse_matcher_condition(t)?);
                    }
                    _ => {
                        return Err(ParseError {
                            line: tok.line,
                            col: tok.col,
                            kind: ParseErrorKind::Expected {
                                expected: "matcher condition or '}'".to_string(),
                                got: format!("{:?}", tok.kind),
                            },
                        });
                    }
                }
            }
            conds
        }
        TokenKind::Word(_) => {
            // Single-line form: `@name condition args...`
            vec![parse_matcher_condition(t)?]
        }
        _ => {
            // `@name` alone with no body — empty matcher (matches everything).
            Vec::new()
        }
    };

    Ok(MatcherDef { name, conditions })
}

/// Parse one matcher condition keyword and its arguments.
fn parse_matcher_condition(t: &mut Tokenizer<'_>) -> Result<MatcherCondition, ParseError> {
    let kw_tok = t.next_token();
    let keyword = match &kw_tok.kind {
        TokenKind::Word(w) => w.clone(),
        _ => {
            return Err(ParseError {
                line: kw_tok.line,
                col: kw_tok.col,
                kind: ParseErrorKind::Expected {
                    expected: "matcher condition keyword".to_string(),
                    got: format!("{:?}", kw_tok.kind),
                },
            });
        }
    };

    match keyword.as_str() {
        "path" => {
            let paths = collect_words_until_brace_or_known(t);
            Ok(MatcherCondition::Path(paths))
        }

        "path_regexp" => {
            // `path_regexp [name] pattern`
            // If two words follow, the first is a capture-group name;
            // if only one word follows, it is the pattern (no capture name).
            let first = next_word_or_quoted(t);
            let second = peek_word(t);
            let (name, pattern) = if second.is_some() {
                // Consume the second word (peek_word doesn't consume).
                t.next_token();
                (first, second.unwrap_or_default())
            } else {
                (None, first.unwrap_or_default())
            };
            Ok(MatcherCondition::PathRegexp { name, pattern })
        }

        "host" => {
            let hosts = collect_words_until_brace_or_known(t);
            Ok(MatcherCondition::Host(hosts))
        }

        "method" => {
            let methods = collect_words_until_brace_or_known(t);
            Ok(MatcherCondition::Method(methods))
        }

        "header" => {
            // `header <name> [value]`
            let name = next_word_or_quoted(t).unwrap_or_default();
            let value = match t.peek().kind {
                TokenKind::Word(ref w)
                    if !is_matcher_condition_keyword(w)
                        && !is_directive_name(w)
                        && !w.starts_with('@') =>
                {
                    let tok = t.next_token();
                    if let TokenKind::Word(w) = tok.kind {
                        Some(w)
                    } else {
                        None
                    }
                }
                TokenKind::QuotedString(_) => {
                    let tok = t.next_token();
                    if let TokenKind::QuotedString(s) = tok.kind {
                        Some(s)
                    } else {
                        None
                    }
                }
                _ => None,
            };
            Ok(MatcherCondition::Header { name, value })
        }

        "header_regexp" => {
            // `header_regexp <name> <pattern>`
            let name = next_word_or_quoted(t).unwrap_or_default();
            let pattern = next_word_or_quoted(t).unwrap_or_default();
            Ok(MatcherCondition::HeaderRegexp { name, pattern })
        }

        "protocol" => {
            let proto = next_word_or_quoted(t).unwrap_or_default();
            Ok(MatcherCondition::Protocol(proto))
        }

        "remote_ip" => {
            let cidrs = collect_words_until_brace_or_known(t);
            Ok(MatcherCondition::RemoteIp(cidrs))
        }

        "client_ip" => {
            let cidrs = collect_words_until_brace_or_known(t);
            Ok(MatcherCondition::ClientIp(cidrs))
        }

        "query" => {
            let pairs = collect_words_until_brace_or_known(t);
            Ok(MatcherCondition::Query(pairs))
        }

        "not" => parse_not_condition(t),

        "expression" => {
            // `expression <cel-expr>` — collect words as a single string.
            let parts = collect_words_until_brace_or_known(t);
            Ok(MatcherCondition::Expression(parts.join(" ")))
        }

        "file" => parse_file_condition(t),

        _ => {
            // Unknown condition — store verbatim for forward compatibility.
            let args = collect_words_until_brace_or_known(t);
            Ok(MatcherCondition::Unknown { keyword, args })
        }
    }
}

// ── Matcher parsing helpers ───────────────────────────────────────────────────

/// Parse a `not { conditions }` block.
fn parse_not_condition(t: &mut Tokenizer<'_>) -> Result<MatcherCondition, ParseError> {
    let brace = t.peek();
    if brace.kind != TokenKind::OpenBrace {
        return Err(ParseError {
            line: brace.line,
            col: brace.col,
            kind: ParseErrorKind::Expected {
                expected: "'{' after 'not'".to_string(),
                got: format!("{:?}", brace.kind),
            },
        });
    }
    t.next_token(); // consume '{'
    let mut inner = Vec::new();
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
                        expected: "'}' to close 'not' block".to_string(),
                    },
                });
            }
            TokenKind::Word(_) => {
                inner.push(parse_matcher_condition(t)?);
            }
            _ => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "matcher condition or '}'".to_string(),
                        got: format!("{:?}", tok.kind),
                    },
                });
            }
        }
    }
    Ok(MatcherCondition::Not(inner))
}

/// Parse a `file { try_files ... }` block.
fn parse_file_condition(t: &mut Tokenizer<'_>) -> Result<MatcherCondition, ParseError> {
    let brace = t.peek();
    if brace.kind != TokenKind::OpenBrace {
        return Err(ParseError {
            line: brace.line,
            col: brace.col,
            kind: ParseErrorKind::Expected {
                expected: "'{' after 'file'".to_string(),
                got: format!("{:?}", brace.kind),
            },
        });
    }
    t.next_token(); // consume '{'
    let mut try_files = Vec::new();
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
                        expected: "'}' to close 'file' block".to_string(),
                    },
                });
            }
            TokenKind::Word(w) if w == "try_files" => {
                t.next_token(); // consume 'try_files'
                let files = collect_words_until_brace_or_known(t);
                try_files.extend(files);
            }
            TokenKind::Word(_) => {
                // Any other word inside file { } — store as a try_files path.
                let tok = t.next_token();
                if let TokenKind::Word(w) = tok.kind {
                    try_files.push(w);
                }
            }
            _ => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "'try_files' or '}'".to_string(),
                        got: format!("{:?}", tok.kind),
                    },
                });
            }
        }
    }
    Ok(MatcherCondition::File { try_files })
}

/// Returns true if `w` is a matcher condition keyword.
fn is_matcher_condition_keyword(w: &str) -> bool {
    matches!(
        w,
        "path"
            | "path_regexp"
            | "host"
            | "method"
            | "header"
            | "header_regexp"
            | "protocol"
            | "remote_ip"
            | "client_ip"
            | "query"
            | "not"
            | "expression"
            | "file"
    )
}

/// Consume words/quoted-strings until we hit a stop token.
///
/// Stops (without consuming) at:
/// - `{`, `}`, EOF
/// - Any word starting with `@` (next named matcher)
/// - Any matcher condition keyword (next condition in the same block)
/// - Any top-level directive name (so single-line matchers don't eat directives)
///
/// Quoted strings are always consumed regardless of their value.
fn collect_words_until_brace_or_known(t: &mut Tokenizer<'_>) -> Vec<String> {
    let mut words = Vec::new();
    loop {
        match t.peek().kind {
            TokenKind::OpenBrace | TokenKind::CloseBrace | TokenKind::Eof => break,
            TokenKind::Word(ref w) if w.starts_with('@') => break,
            TokenKind::Word(ref w) if is_matcher_condition_keyword(w) => break,
            TokenKind::Word(ref w) if is_directive_name(w) => break,
            TokenKind::Word(_) | TokenKind::QuotedString(_) => {
                let tok = t.next_token();
                match tok.kind {
                    TokenKind::Word(w) | TokenKind::QuotedString(w) => words.push(w),
                    _ => {}
                }
            }
        }
    }
    words
}

/// Consume and return the next word or quoted string, or `None`.
fn next_word_or_quoted(t: &mut Tokenizer<'_>) -> Option<String> {
    match t.peek().kind {
        TokenKind::Word(_) | TokenKind::QuotedString(_) => {
            let tok = t.next_token();
            match tok.kind {
                TokenKind::Word(w) | TokenKind::QuotedString(w) => Some(w),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Peek at the next word without consuming it. Returns `None` if the next
/// token is not a plain word.
fn peek_word(t: &mut Tokenizer<'_>) -> Option<String> {
    match t.peek().kind {
        TokenKind::Word(w) => Some(w),
        _ => None,
    }
}

/// `respond "body" 404` / `respond 204` / `respond "body"` / `respond`
///
/// Caddy semantics: if single arg is a valid 3-digit status code, treat as status.
/// Otherwise treat as body. Two args: body then status.
fn parse_respond(t: &mut Tokenizer<'_>) -> Result<RespondDirective, ParseError> {
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
                    },
                });
            }
            Ok(RespondDirective {
                status,
                body: first,
            })
        }
        // Single argument — is it a status code or body?
        _ => {
            if let Ok(code) = first.parse::<u16>()
                && (100..=599).contains(&code)
            {
                return Ok(RespondDirective {
                    status: code,
                    body: String::new(),
                });
            }
            // Not a valid status — treat as body
            Ok(RespondDirective {
                status: 200,
                body: first,
            })
        }
    }
}

/// `basicauth { user hash }` or `basic_auth [realm] { user hash }`
///
/// Parses credential pairs inside a brace-delimited block. The optional realm
/// is a bare word or quoted string before the opening brace.
fn parse_basicauth(t: &mut Tokenizer<'_>) -> Result<BasicAuthDirective, ParseError> {
    let mut realm = None;

    // Check for optional realm before the opening brace
    if matches!(
        t.peek().kind,
        TokenKind::Word(_) | TokenKind::QuotedString(_)
    ) {
        // Peek again — if next after this token is still not a brace, this is a realm
        let next = t.peek();
        if !matches!(next.kind, TokenKind::OpenBrace) {
            let realm_tok = t.next_token();
            realm = Some(match realm_tok.kind {
                TokenKind::Word(w) => w,
                TokenKind::QuotedString(s) => s,
                _ => unreachable!(),
            });
        }
    }

    // Expect opening brace
    let brace_tok = t.next_token();
    if !matches!(brace_tok.kind, TokenKind::OpenBrace) {
        return Err(ParseError {
            line: brace_tok.line,
            col: brace_tok.col,
            kind: ParseErrorKind::Expected {
                expected: "'{' to start basicauth block".to_string(),
                got: format!("{:?}", brace_tok.kind),
            },
        });
    }

    // Parse credential pairs until closing brace
    let mut credentials = Vec::new();
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
                        expected: "'}' to close basicauth block".to_string(),
                    },
                });
            }
            _ => {
                let username = expect_word_or_quoted(t, "basicauth", "username")?;
                let hash = expect_word_or_quoted(t, "basicauth", "password hash")?;
                credentials.push(BasicAuthCredential {
                    username,
                    password_hash: hash,
                });
            }
        }
    }

    if credentials.is_empty() {
        let (line, col) = t.position();
        return Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "basicauth".to_string(),
                message: "at least one username/hash pair required".to_string(),
            },
        });
    }

    Ok(BasicAuthDirective { realm, credentials })
}

/// Parse a brace-delimited block of directives — the core of `handle`/`handle_path`/`route`.
/// Reuses `parse_directive()` recursively, enabling nested blocks.
fn parse_directive_block(t: &mut Tokenizer<'_>) -> Result<Vec<Directive>, ParseError> {
    let brace_tok = t.next_token();
    if !matches!(brace_tok.kind, TokenKind::OpenBrace) {
        return Err(ParseError {
            line: brace_tok.line,
            col: brace_tok.col,
            kind: ParseErrorKind::Expected {
                expected: "'{'".to_string(),
                got: format!("{:?}", brace_tok.kind),
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
                directives.push(parse_directive(t)?);
            }
        }
    }

    Ok(directives)
}

/// `handle [pattern] { directives }` — first match wins, path NOT stripped.
fn parse_handle(t: &mut Tokenizer<'_>) -> Result<HandleDirective, ParseError> {
    let matcher = parse_optional_pattern(t);
    let directives = parse_directive_block(t)?;
    Ok(HandleDirective {
        matcher,
        directives,
    })
}

/// `php_fastcgi localhost:9000` — proxy to `FastCGI` backend.
fn parse_php_fastcgi(t: &mut Tokenizer<'_>) -> Result<PhpFastcgiDirective, ParseError> {
    let upstream_str = expect_word_or_quoted(t, "php_fastcgi", "FastCGI upstream address")?;
    let upstream = parse_upstream_addr(&upstream_str);
    Ok(PhpFastcgiDirective { upstream })
}

fn parse_optional_pattern(t: &mut Tokenizer<'_>) -> Option<String> {
    if let TokenKind::Word(ref w) = t.peek().kind
        && !w.starts_with('{')
    {
        let tok = t.next_token();
        if let TokenKind::Word(w) = tok.kind {
            return Some(w);
        }
    }
    None
}

/// `handle_path <pattern> { directives }` — first match wins, prefix IS stripped.
fn parse_handle_path(t: &mut Tokenizer<'_>) -> Result<HandlePathDirective, ParseError> {
    let path_prefix = expect_word_or_quoted(t, "handle_path", "path prefix pattern")?;
    let directives = parse_directive_block(t)?;
    Ok(HandlePathDirective {
        path_prefix,
        directives,
    })
}

/// `route [pattern] { directives }` — all matching blocks execute in order.
fn parse_route(t: &mut Tokenizer<'_>) -> Result<RouteDirective, ParseError> {
    let matcher = parse_optional_pattern(t);
    let directives = parse_directive_block(t)?;
    Ok(RouteDirective {
        matcher,
        directives,
    })
}

/// `root * /var/www` or `root /var/www` — the `*` matcher is optional and ignored for now.
fn parse_root(t: &mut Tokenizer<'_>) -> Result<RootDirective, ParseError> {
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
fn parse_file_server(t: &mut Tokenizer<'_>) -> FileServerDirective {
    let browse = matches!(t.peek().kind, TokenKind::Word(ref w) if w == "browse");
    if browse {
        t.next_token();
    }
    FileServerDirective { browse }
}

/// `forward_auth authelia:9091 { uri /api/verify; copy_headers Remote-User Remote-Groups }`
fn parse_forward_auth(t: &mut Tokenizer<'_>) -> Result<ForwardAuthDirective, ParseError> {
    // First token: upstream address
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
                got: format!("{:?}", brace_tok.kind),
            },
        });
    }

    let mut uri = None;
    let mut copy_headers = Vec::new();

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
                    // Read header names until next subdirective or closing brace
                    loop {
                        let next = t.peek();
                        match &next.kind {
                            TokenKind::Word(w)
                                if !matches!(w.as_str(), "uri" | "copy_headers")
                                    && !matches!(next.kind, TokenKind::CloseBrace) =>
                            {
                                let header =
                                    expect_word_or_quoted(t, "copy_headers", "header name")?;
                                copy_headers.push(header);
                            }
                            _ => break,
                        }
                    }
                }
                other => {
                    return Err(ParseError {
                        line: tok.line,
                        col: tok.col,
                        kind: ParseErrorKind::InvalidValue {
                            directive: "forward_auth".to_string(),
                            message: format!(
                                "unknown subdirective '{other}' — expected 'uri' or 'copy_headers'"
                            ),
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
                        got: format!("{:?}", tok.kind),
                    },
                });
            }
        }
    }

    Ok(ForwardAuthDirective {
        upstream,
        uri,
        copy_headers,
    })
}

/// `rewrite /new-path` — replace the request URI.
fn parse_rewrite(t: &mut Tokenizer<'_>) -> Result<RewriteDirective, ParseError> {
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
                },
            });
        }
    };
    Ok(RewriteDirective { to })
}

/// `uri strip_prefix /api` / `uri strip_suffix .html` / `uri replace /old /new`
fn parse_uri(t: &mut Tokenizer<'_>) -> Result<UriDirective, ParseError> {
    let op_tok = t.next_token();
    let TokenKind::Word(op) = &op_tok.kind else {
        return Err(ParseError {
            line: op_tok.line,
            col: op_tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "uri".to_string(),
                message: "expected operation: strip_prefix, strip_suffix, or replace".to_string(),
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
            },
        }),
    }
}

/// Helper: expect a word or quoted string token.
fn expect_word_or_quoted(
    t: &mut Tokenizer<'_>,
    directive: &str,
    what: &str,
) -> Result<String, ParseError> {
    let tok = t.next_token();
    match tok.kind {
        TokenKind::Word(w) => Ok(w),
        TokenKind::QuotedString(s) => Ok(s),
        _ => Err(ParseError {
            line: tok.line,
            col: tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: directive.to_string(),
                message: format!("expected {what}"),
            },
        }),
    }
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
        // Implemented directives
        "reverse_proxy"
            | "proxy"
            | "tls"
            | "header"
            | "redir"
            | "encode"
            | "rate_limit"
            | "basicauth"
            | "basic_auth"
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
            // Passthrough directives (recognized Caddyfile, not yet implemented)
            | "log"
            | "bind"
            | "abort"
            | "error"
            | "metrics"
            | "templates"
            | "request_body"
            | "request_header"
            | "method"
            | "try_files"
            | "tracing"
            | "vars"
            | "map"
            | "skip_log"
            | "log_skip"
            | "push"
            | "acme_server"
            | "handle_errors"
            | "invoke"
            | "intercept"
            | "log_append"
            | "log_name"
            | "fs"
            | "copy_response"
            | "copy_response_headers"
    )
}

/// Consume a directive's arguments and optional brace block without
/// interpreting the content. Used for Caddy directives we recognize
/// but haven't implemented — lets the file parse successfully.
///
/// Returns `true` if the directive had a `{ ... }` block.
fn parse_passthrough(t: &mut Tokenizer<'_>) -> bool {
    // Consume tokens on the same "line" until we hit a brace, a known
    // directive name (next directive), the parent's closing brace, or EOF.
    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::OpenBrace => {
                t.next_token(); // consume '{'
                skip_brace_block(t);
                return true;
            }
            TokenKind::CloseBrace | TokenKind::Eof => return false,
            TokenKind::Word(w) if is_directive_name(w) || w.starts_with('@') => return false,
            _ => {
                t.next_token(); // consume arg token
            }
        }
    }
}

/// Skip tokens until the matching `}` is found, handling nested braces.
fn skip_brace_block(t: &mut Tokenizer<'_>) {
    let mut depth: u32 = 1;
    loop {
        let tok = t.next_token();
        match tok.kind {
            TokenKind::OpenBrace => depth += 1,
            TokenKind::CloseBrace => {
                depth -= 1;
                if depth == 0 {
                    return;
                }
            }
            TokenKind::Eof => return, // unterminated block — parser will catch it
            _ => {}
        }
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
    fn passthrough_directive_parses_without_error() {
        // `log` is now a fully implemented directive — must parse as Directive::Log
        let config = parse("a.com { log }").expect("log should parse");
        assert!(matches!(&config.sites[0].directives[0], Directive::Log(_)));
    }

    #[test]
    fn passthrough_directive_with_args() {
        // `bind` is now fully implemented — parses as Directive::Bind
        let config = parse("a.com { bind 0.0.0.0 }").expect("bind should parse");
        assert!(matches!(&config.sites[0].directives[0], Directive::Bind(_)));
    }

    #[test]
    fn passthrough_directive_with_block() {
        // `log` with a block is now fully implemented — parses as Directive::Log
        let config = parse(
            "a.com {\n    log {\n        output file /var/log/access.log\n        format json\n    }\n}\n",
        )
        .expect("log with block should parse");
        assert!(matches!(&config.sites[0].directives[0], Directive::Log(_)));
    }

    #[test]
    fn passthrough_directive_with_nested_blocks() {
        // `templates` remains a passthrough directive
        let config = parse(
            "a.com {\n    templates {\n        mime text/html {\n            charset utf-8\n        }\n    }\n}\n",
        )
        .expect("nested blocks should parse as passthrough");
        assert!(matches!(
            &config.sites[0].directives[0],
            Directive::Passthrough { name, has_block: true } if name == "templates"
        ));
    }

    #[test]
    fn passthrough_does_not_affect_other_directives() {
        // `log` is now implemented — parses as Directive::Log
        let config = parse(
            "a.com {\n    reverse_proxy :8080\n    log {\n        output file /var/log/a.log\n    }\n    tls auto\n}\n",
        )
        .expect("log mixed with real directives");
        assert_eq!(config.sites[0].directives.len(), 3);
        assert!(matches!(
            config.sites[0].directives[0],
            Directive::ReverseProxy(_)
        ));
        assert!(matches!(&config.sites[0].directives[1], Directive::Log(_)));
        assert!(matches!(config.sites[0].directives[2], Directive::Tls(_)));
    }

    #[test]
    fn all_caddy_passthrough_directives_parse() {
        // Every known Caddy directive must parse without error.
        // Note: placeholder syntax like {host} requires tokenizer changes
        // (Phase 2), so we test with simple args here.
        let directives = [
            // Implemented directives
            "log",
            "bind 0.0.0.0",
            "abort",
            "error \"msg\" 500",
            "request_header X-Foo bar",
            "method GET",
            "try_files /index.html",
            "vars key val",
            "skip_log",
            "log_skip",
            "request_body {\n        max_size 10MB\n    }",
            "handle_errors {\n        respond 500\n    }",
            // Passthrough directives
            "metrics",
            "templates",
            "tracing",
            "map",
            "push",
            "acme_server",
            "invoke route_name",
            "intercept",
            "log_append",
            "log_name",
            "fs",
        ];
        for d in directives {
            let input = format!("a.com {{\n    {d}\n}}");
            let result = parse(&input);
            assert!(
                result.is_ok(),
                "directive '{d}' should parse, got: {result:?}"
            );
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

    // ── rate_limit directive (ISSUE-031) ─────────────────

    #[test]
    fn parse_rate_limit() {
        let config = parse("a.com { rate_limit 100/s }").expect("parse");
        if let Directive::RateLimit(rl) = &config.sites[0].directives[0] {
            assert_eq!(rl.requests_per_second, 100);
        } else {
            panic!("expected RateLimit directive");
        }
    }

    #[test]
    fn parse_rate_limit_large_value() {
        let config = parse("a.com { rate_limit 10000/s }").expect("parse");
        if let Directive::RateLimit(rl) = &config.sites[0].directives[0] {
            assert_eq!(rl.requests_per_second, 10000);
        } else {
            panic!("expected RateLimit directive");
        }
    }

    #[test]
    fn error_rate_limit_no_arg() {
        let err = parse("a.com { rate_limit }").expect_err("should fail");
        assert!(matches!(err.kind, ParseErrorKind::InvalidValue { .. }));
    }

    #[test]
    fn error_rate_limit_non_numeric() {
        let err = parse("a.com { rate_limit abc/s }").expect_err("should fail");
        assert!(matches!(err.kind, ParseErrorKind::InvalidValue { .. }));
    }

    #[test]
    fn error_rate_limit_wrong_unit() {
        let err = parse("a.com { rate_limit 100/m }").expect_err("should fail");
        assert!(matches!(err.kind, ParseErrorKind::InvalidValue { .. }));
    }

    #[test]
    fn error_rate_limit_zero() {
        let err = parse("a.com { rate_limit 0/s }").expect_err("should fail");
        assert!(matches!(err.kind, ParseErrorKind::InvalidValue { .. }));
    }

    #[test]
    fn parse_rate_limit_with_other_directives() {
        let config = parse(
            "a.com {
            reverse_proxy 127.0.0.1:8080
            rate_limit 200/s
            tls auto
        }",
        )
        .expect("parse");
        assert_eq!(config.sites[0].directives.len(), 3);
        assert!(matches!(
            &config.sites[0].directives[1],
            Directive::RateLimit(rl) if rl.requests_per_second == 200
        ));
    }

    #[test]
    fn format_roundtrip_rate_limit() {
        let input = "a.com {\n    rate_limit 100/s\n}\n";
        let config = parse(input).expect("parse");
        let formatted = crate::format::format_config(&config);
        assert_eq!(formatted, input);
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

    // ── respond directive (ISSUE-051) ─────────────────────

    #[test]
    fn respond_with_body_and_status() {
        let config = parse(
            r#"
            example.com {
                respond "Not Found" 404
            }
            "#,
        )
        .expect("should parse");
        let d = &config.sites[0].directives[0];
        let Directive::Respond(r) = d else {
            panic!("expected Respond directive");
        };
        assert_eq!(r.status, 404);
        assert_eq!(r.body, "Not Found");
    }

    #[test]
    fn respond_status_only() {
        let config = parse("health.example.com {\n    respond 204\n}\n").expect("should parse");
        let Directive::Respond(r) = &config.sites[0].directives[0] else {
            panic!("expected Respond");
        };
        assert_eq!(r.status, 204);
        assert!(r.body.is_empty());
    }

    #[test]
    fn respond_body_only() {
        let config = parse(
            r#"
            example.com {
                respond "ok"
            }
            "#,
        )
        .expect("should parse");
        let Directive::Respond(r) = &config.sites[0].directives[0] else {
            panic!("expected Respond");
        };
        assert_eq!(r.status, 200);
        assert_eq!(r.body, "ok");
    }

    #[test]
    fn respond_no_args_is_200_empty() {
        let config = parse("a.com {\n    respond\n}\n").expect("should parse");
        let Directive::Respond(r) = &config.sites[0].directives[0] else {
            panic!("expected Respond");
        };
        assert_eq!(r.status, 200);
        assert!(r.body.is_empty());
    }

    #[test]
    fn respond_followed_by_other_directive() {
        let config = parse("a.com {\n    respond 204\n    header X-Custom \"val\"\n}\n")
            .expect("should parse");
        assert_eq!(config.sites[0].directives.len(), 2);
        assert!(matches!(
            config.sites[0].directives[0],
            Directive::Respond(_)
        ));
        assert!(matches!(
            config.sites[0].directives[1],
            Directive::Header(_)
        ));
    }

    #[test]
    fn respond_invalid_status_code_rejected() {
        let result = parse(
            r#"
            example.com {
                respond "err" 999
            }
            "#,
        );
        assert!(result.is_err());
    }

    // ── rewrite and uri directives (ISSUE-049) ───────────

    #[test]
    fn rewrite_replaces_path() {
        let config =
            parse("a.com {\n    reverse_proxy :8080\n    rewrite /new\n}\n").expect("should parse");
        let Directive::Rewrite(r) = &config.sites[0].directives[1] else {
            panic!("expected Rewrite");
        };
        assert_eq!(r.to, "/new");
    }

    #[test]
    fn uri_strip_prefix() {
        let config = parse("a.com {\n    reverse_proxy :8080\n    uri strip_prefix /api\n}\n")
            .expect("should parse");
        let Directive::Uri(u) = &config.sites[0].directives[1] else {
            panic!("expected Uri");
        };
        assert!(matches!(&u.operation, UriOperation::StripPrefix(p) if p == "/api"));
    }

    #[test]
    fn uri_strip_suffix() {
        let config = parse("a.com {\n    reverse_proxy :8080\n    uri strip_suffix .html\n}\n")
            .expect("should parse");
        let Directive::Uri(u) = &config.sites[0].directives[1] else {
            panic!("expected Uri");
        };
        assert!(matches!(&u.operation, UriOperation::StripSuffix(s) if s == ".html"));
    }

    #[test]
    fn uri_replace() {
        let config = parse("a.com {\n    reverse_proxy :8080\n    uri replace /old /new\n}\n")
            .expect("should parse");
        let Directive::Uri(u) = &config.sites[0].directives[1] else {
            panic!("expected Uri");
        };
        assert!(matches!(
            &u.operation,
            UriOperation::Replace { find, replace } if find == "/old" && replace == "/new"
        ));
    }

    #[test]
    fn uri_unknown_operation_rejected() {
        let result = parse("a.com {\n    reverse_proxy :8080\n    uri explode /foo\n}\n");
        assert!(result.is_err());
    }

    #[test]
    fn rewrite_missing_path_rejected() {
        let result = parse("a.com {\n    reverse_proxy :8080\n    rewrite\n}\n");
        assert!(result.is_err());
    }

    // ── basicauth directive (ISSUE-046) ──────────────────

    #[test]
    fn basicauth_parses_credentials() {
        let config = parse(
            r"
            a.com {
                reverse_proxy :8080
                basicauth {
                    admin $2a$14$somehash
                    user $2a$14$otherhash
                }
            }
            ",
        )
        .expect("should parse");
        let Directive::BasicAuth(ba) = &config.sites[0].directives[1] else {
            panic!("expected BasicAuth");
        };
        assert_eq!(ba.credentials.len(), 2);
        assert_eq!(ba.credentials[0].username, "admin");
        assert_eq!(ba.credentials[1].username, "user");
        assert!(ba.realm.is_none());
    }

    #[test]
    fn basic_auth_underscore_form_accepted() {
        let config = parse(
            "a.com {\n    reverse_proxy :8080\n    basic_auth {\n        admin hash\n    }\n}\n",
        )
        .expect("should parse");
        assert!(matches!(
            config.sites[0].directives[1],
            Directive::BasicAuth(_)
        ));
    }

    #[test]
    fn basicauth_empty_block_rejected() {
        let result = parse("a.com {\n    reverse_proxy :8080\n    basicauth {\n    }\n}\n");
        assert!(result.is_err());
    }

    #[test]
    fn basicauth_missing_brace_rejected() {
        let result = parse("a.com {\n    reverse_proxy :8080\n    basicauth admin hash\n}\n");
        assert!(result.is_err());
    }

    // ── forward_auth directive (ISSUE-047) ───────────────

    #[test]
    fn forward_auth_parses_full_block() {
        let config = parse(
            "a.com {\n    reverse_proxy :8080\n    forward_auth 127.0.0.1:9091 {\n        uri /api/verify\n        copy_headers Remote-User Remote-Groups\n    }\n}\n",
        )
        .expect("should parse");
        let Directive::ForwardAuth(fa) = &config.sites[0].directives[1] else {
            panic!("expected ForwardAuth");
        };
        assert_eq!(fa.uri.as_deref(), Some("/api/verify"));
        assert_eq!(fa.copy_headers, vec!["Remote-User", "Remote-Groups"]);
    }

    #[test]
    fn forward_auth_minimal_block() {
        let config = parse(
            "a.com {\n    reverse_proxy :8080\n    forward_auth 127.0.0.1:9091 {\n    }\n}\n",
        )
        .expect("should parse");
        let Directive::ForwardAuth(fa) = &config.sites[0].directives[1] else {
            panic!("expected ForwardAuth");
        };
        assert!(fa.uri.is_none());
        assert!(fa.copy_headers.is_empty());
    }

    #[test]
    fn forward_auth_missing_upstream_rejected() {
        let result = parse("a.com {\n    reverse_proxy :8080\n    forward_auth {\n    }\n}\n");
        assert!(result.is_err());
    }

    #[test]
    fn forward_auth_unknown_subdirective_rejected() {
        let result = parse(
            "a.com {\n    reverse_proxy :8080\n    forward_auth 127.0.0.1:9091 {\n        method POST\n    }\n}\n",
        );
        assert!(result.is_err());
    }

    // ── file_server and root directives (ISSUE-048) ──────

    #[test]
    fn file_server_parses() {
        let config =
            parse("a.com {\n    root * /var/www\n    file_server\n}\n").expect("should parse");
        assert!(matches!(config.sites[0].directives[0], Directive::Root(_)));
        assert!(matches!(
            config.sites[0].directives[1],
            Directive::FileServer(FileServerDirective { browse: false })
        ));
    }

    #[test]
    fn file_server_browse() {
        let config = parse("a.com {\n    root * /var/www\n    file_server browse\n}\n")
            .expect("should parse");
        assert!(matches!(
            config.sites[0].directives[1],
            Directive::FileServer(FileServerDirective { browse: true })
        ));
    }

    #[test]
    fn root_without_matcher() {
        let config =
            parse("a.com {\n    root /var/www\n    file_server\n}\n").expect("should parse");
        let Directive::Root(r) = &config.sites[0].directives[0] else {
            panic!("expected Root");
        };
        assert_eq!(r.path, "/var/www");
    }

    #[test]
    fn root_with_star_matcher() {
        let config =
            parse("a.com {\n    root * /srv/static\n    file_server\n}\n").expect("should parse");
        let Directive::Root(r) = &config.sites[0].directives[0] else {
            panic!("expected Root");
        };
        assert_eq!(r.path, "/srv/static");
    }

    // ── handle/handle_path/route directives (ISSUE-050) ──

    #[test]
    fn handle_with_pattern() {
        let config = parse("a.com {\n    handle /api/* {\n        reverse_proxy :3000\n    }\n}\n")
            .expect("should parse");
        let Directive::Handle(h) = &config.sites[0].directives[0] else {
            panic!("expected Handle");
        };
        assert_eq!(h.matcher.as_deref(), Some("/api/*"));
        assert_eq!(h.directives.len(), 1);
    }

    #[test]
    fn handle_catch_all() {
        let config =
            parse("a.com {\n    handle {\n        respond 404\n    }\n}\n").expect("should parse");
        let Directive::Handle(h) = &config.sites[0].directives[0] else {
            panic!("expected Handle");
        };
        assert!(h.matcher.is_none());
    }

    #[test]
    fn handle_path_strips_prefix() {
        let config =
            parse("a.com {\n    handle_path /api/* {\n        reverse_proxy :3000\n    }\n}\n")
                .expect("should parse");
        let Directive::HandlePath(hp) = &config.sites[0].directives[0] else {
            panic!("expected HandlePath");
        };
        assert_eq!(hp.path_prefix, "/api/*");
    }

    #[test]
    fn route_block() {
        let config = parse("a.com {\n    route {\n        reverse_proxy :3000\n    }\n}\n")
            .expect("should parse");
        assert!(matches!(config.sites[0].directives[0], Directive::Route(_)));
    }

    #[test]
    fn multiple_handle_blocks() {
        let config = parse(
            "a.com {\n    handle /api/* {\n        reverse_proxy :3000\n    }\n    handle /static/* {\n        root * /var/www\n        file_server\n    }\n    handle {\n        respond 404\n    }\n}\n",
        )
        .expect("should parse");
        assert_eq!(config.sites[0].directives.len(), 3);
        assert!(matches!(
            config.sites[0].directives[0],
            Directive::Handle(_)
        ));
        assert!(matches!(
            config.sites[0].directives[1],
            Directive::Handle(_)
        ));
        assert!(matches!(
            config.sites[0].directives[2],
            Directive::Handle(_)
        ));
    }

    #[test]
    fn handle_nested_with_middleware() {
        let config = parse(
            "a.com {\n    handle /admin/* {\n        basicauth {\n            admin hash\n        }\n        reverse_proxy :3000\n    }\n}\n",
        )
        .expect("should parse");
        let Directive::Handle(h) = &config.sites[0].directives[0] else {
            panic!("expected Handle");
        };
        assert_eq!(h.directives.len(), 2);
        assert!(matches!(h.directives[0], Directive::BasicAuth(_)));
        assert!(matches!(h.directives[1], Directive::ReverseProxy(_)));
    }

    // ── Global options block (Phase 1) ─────────────────────

    #[test]
    fn global_options_parses() {
        let config = parse(
            "{\n    http_port 8080\n    https_port 8443\n    email admin@example.com\n    debug\n}\n\na.com {\n    reverse_proxy :3000\n}\n",
        )
        .expect("should parse");
        let opts = config.global_options.as_ref().expect("has global options");
        assert_eq!(opts.http_port, Some(8080));
        assert_eq!(opts.https_port, Some(8443));
        assert_eq!(opts.email.as_deref(), Some("admin@example.com"));
        assert!(opts.debug);
        assert_eq!(config.sites.len(), 1);
    }

    #[test]
    fn global_options_empty_block() {
        let config = parse("{\n}\na.com {\n    reverse_proxy :3000\n}\n").expect("should parse");
        let opts = config.global_options.as_ref().expect("has global options");
        assert_eq!(opts.http_port, None);
        assert!(!opts.debug);
    }

    #[test]
    fn global_options_with_auto_https() {
        let config = parse("{\n    auto_https off\n}\na.com {\n    reverse_proxy :3000\n}\n")
            .expect("should parse");
        let opts = config.global_options.as_ref().expect("has global options");
        assert_eq!(opts.auto_https.as_deref(), Some("off"));
    }

    #[test]
    fn global_options_unknown_stored_as_passthrough() {
        let config = parse(
            "{\n    storage file_system\n    admin off\n}\na.com {\n    reverse_proxy :3000\n}\n",
        )
        .expect("should parse");
        let opts = config.global_options.as_ref().expect("has global options");
        assert!(!opts.passthrough.is_empty());
    }

    #[test]
    fn global_options_with_sub_block() {
        let config = parse(
            "{\n    log {\n        output file /var/log/caddy.log\n        level INFO\n    }\n}\na.com {\n    reverse_proxy :3000\n}\n",
        )
        .expect("sub-block in global options should parse");
        assert!(config.global_options.is_some());
    }

    #[test]
    fn no_global_options_returns_none() {
        let config = parse("a.com {\n    reverse_proxy :3000\n}\n").expect("should parse");
        assert!(config.global_options.is_none());
    }

    #[test]
    fn global_options_only_no_sites() {
        let config = parse("{\n    debug\n}\n").expect("global options without sites");
        assert!(config.global_options.is_some());
        assert!(config.sites.is_empty());
    }
}
