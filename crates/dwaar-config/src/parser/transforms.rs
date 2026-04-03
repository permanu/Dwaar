// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Transformation directive parsers — what changes about the request or response.
//!
//! Covers: `tls`, `header`, `request_header`, `encode`, `basicauth`, `rate_limit`,
//! `method`, `request_body`, `response_body_limit`, `bind`, `vars`, `error`.

use crate::error::{ParseError, ParseErrorKind};
use crate::model::{
    BasicAuthCredential, BasicAuthDirective, BindDirective, CacheDirective, EncodeDirective,
    ErrorDirective, HeaderDirective, IpFilterDirective, MethodDirective, RateLimitDirective,
    RequestBodyDirective, RequestHeaderDirective, ResponseBodyLimitDirective, TlsDirective,
    VarsDirective,
};
use crate::token::{Token, TokenKind, Tokenizer};

use super::helpers::{expect_word_or_quoted, is_directive_name, parse_size, skip_to_next_line};

/// `tls auto` / `tls off` / `tls internal` / `tls /cert /key` /
/// `tls { dns cloudflare <token> }`
pub(super) fn parse_tls(t: &mut Tokenizer<'_>) -> Result<TlsDirective, ParseError> {
    let tok = t.peek();
    match &tok.kind {
        TokenKind::OpenBrace => parse_tls_block(t),
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

/// Parse `tls { dns <provider> <token> }` block form for DNS-01 challenges.
///
/// The `{env.CF_API_TOKEN}` syntax is resolved here: the tokenizer splits it
/// into `OpenBrace Word("env.CF_API_TOKEN") CloseBrace`, so we reassemble
/// and look up the environment variable.
fn parse_tls_block(t: &mut Tokenizer<'_>) -> Result<TlsDirective, ParseError> {
    t.next_token(); // consume opening `{`

    let mut result: Option<TlsDirective> = None;

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
                        expected: "'}' to close tls block".to_string(),
                    },
                });
            }
            TokenKind::Word(w) if w == "dns" => {
                t.next_token(); // consume "dns"
                let (provider, provider_tok) =
                    read_tls_word(t, "dns provider name (e.g. cloudflare)")?;

                // The token might be a literal string or an {env.VAR} placeholder.
                let api_token = read_tls_token_value(t, &provider_tok)?;

                result = Some(TlsDirective::DnsChallenge {
                    provider,
                    api_token,
                });
            }
            _ => {
                // Skip unknown subdirectives inside tls block
                t.next_token();
            }
        }
    }

    result.ok_or_else(|| {
        let (line, col) = t.position();
        ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "tls".to_string(),
                message: "tls block must contain a subdirective (e.g. 'dns cloudflare <token>')"
                    .to_string(),
            },
        }
    })
}

/// Read a word or quoted string from the tokenizer, returning both the string
/// and the token for error positioning.
fn read_tls_word(t: &mut Tokenizer<'_>, what: &str) -> Result<(String, Token), ParseError> {
    let tok = t.next_token();
    match tok.kind {
        TokenKind::Word(ref w) => Ok((w.clone(), tok)),
        TokenKind::QuotedString(ref s) => Ok((s.clone(), tok)),
        _ => Err(ParseError {
            line: tok.line,
            col: tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "tls".to_string(),
                message: format!("expected {what}"),
            },
        }),
    }
}

/// Read a token value that might be a literal or an `{env.VAR}` placeholder.
///
/// The tokenizer splits `{env.CF_API_TOKEN}` into three tokens:
/// `OpenBrace`, `Word("env.CF_API_TOKEN")`, `CloseBrace`. When we see
/// an open brace after the provider name, we reassemble and resolve
/// the environment variable.
fn read_tls_token_value(t: &mut Tokenizer<'_>, _context_tok: &Token) -> Result<String, ParseError> {
    let tok = t.peek();
    match &tok.kind {
        // `{env.VAR_NAME}` syntax — resolve environment variable
        TokenKind::OpenBrace => {
            t.next_token(); // consume `{`
            let var_tok = t.next_token();
            let TokenKind::Word(var_name) = &var_tok.kind else {
                return Err(ParseError {
                    line: var_tok.line,
                    col: var_tok.col,
                    kind: ParseErrorKind::InvalidValue {
                        directive: "tls".to_string(),
                        message: "expected env.VAR_NAME inside braces".to_string(),
                    },
                });
            };

            let env_key = var_name.strip_prefix("env.").ok_or_else(|| ParseError {
                line: var_tok.line,
                col: var_tok.col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "tls".to_string(),
                    message: format!("expected {{env.VAR_NAME}} syntax, got {{{var_name}}}"),
                },
            })?;

            // Consume the closing `}` — but this is the inner brace of
            // `{env.VAR}`, not the tls block's closing brace.
            let close = t.next_token();
            if !matches!(close.kind, TokenKind::CloseBrace) {
                return Err(ParseError {
                    line: close.line,
                    col: close.col,
                    kind: ParseErrorKind::Expected {
                        expected: "'}' to close env variable".to_string(),
                        got: format!("{:?}", close.kind),
                    },
                });
            }

            std::env::var(env_key).map_err(|_| ParseError {
                line: var_tok.line,
                col: var_tok.col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "tls".to_string(),
                    message: format!("environment variable '{env_key}' is not set"),
                },
            })
        }
        // Literal token string or quoted string
        TokenKind::Word(_) | TokenKind::QuotedString(_) => {
            let tok = t.next_token();
            match tok.kind {
                TokenKind::Word(w) | TokenKind::QuotedString(w) => Ok(w),
                _ => unreachable!(),
            }
        }
        _ => Err(ParseError {
            line: tok.line,
            col: tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "tls".to_string(),
                message: "expected API token value or {env.VAR_NAME}".to_string(),
            },
        }),
    }
}

/// `header X-Custom "value"` or `header -Server` (delete)
pub(super) fn parse_header(t: &mut Tokenizer<'_>) -> Result<HeaderDirective, ParseError> {
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

/// `request_header X-Name "value"` / `request_header -X-Remove` / `request_header +X-Append "value"`
pub(super) fn parse_request_header(
    t: &mut Tokenizer<'_>,
) -> Result<RequestHeaderDirective, ParseError> {
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

/// `encode gzip` / `encode zstd gzip br`
pub(super) fn parse_encode(t: &mut Tokenizer<'_>) -> Result<EncodeDirective, ParseError> {
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

/// `basicauth { user hash }` or `basic_auth [realm] { user hash }`
///
/// Parses credential pairs inside a brace-delimited block. The optional realm
/// is a bare word or quoted string before the opening brace.
pub(super) fn parse_basicauth(t: &mut Tokenizer<'_>) -> Result<BasicAuthDirective, ParseError> {
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

/// `rate_limit 100/s`
pub(super) fn parse_rate_limit(t: &mut Tokenizer<'_>) -> Result<RateLimitDirective, ParseError> {
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

/// `ip_filter { allow 10.0.0.0/8; deny 203.0.113.0/24; default allow }`
pub(super) fn parse_ip_filter(
    t: &mut Tokenizer<'_>,
    dir_tok: &Token,
) -> Result<IpFilterDirective, ParseError> {
    if t.peek().kind != TokenKind::OpenBrace {
        return Err(ParseError {
            line: dir_tok.line,
            col: dir_tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "ip_filter".to_string(),
                message: "expected '{' block".to_string(),
            },
        });
    }
    t.next_token(); // consume '{'

    let mut allow = Vec::new();
    let mut deny = Vec::new();
    let mut default_allow = true; // blocklist mode by default

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
                        expected: "'}' to close ip_filter block".to_string(),
                    },
                });
            }
            TokenKind::Word(w) => {
                let keyword = w.clone();
                t.next_token();
                match keyword.as_str() {
                    "allow" => {
                        while matches!(t.peek().kind, TokenKind::Word(_)) {
                            if let TokenKind::Word(cidr) = t.next_token().kind {
                                allow.push(cidr);
                            }
                        }
                    }
                    "deny" => {
                        while matches!(t.peek().kind, TokenKind::Word(_)) {
                            if let TokenKind::Word(cidr) = t.next_token().kind {
                                deny.push(cidr);
                            }
                        }
                    }
                    "default" => {
                        if let TokenKind::Word(policy) = &t.peek().kind {
                            default_allow = policy.eq_ignore_ascii_case("allow");
                            t.next_token();
                        }
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
                        expected: "ip_filter sub-directive (allow/deny/default) or '}'".to_string(),
                        got: format!("{:?}", tok.kind),
                    },
                });
            }
        }
    }

    Ok(IpFilterDirective {
        allow,
        deny,
        default_allow,
    })
}

/// `method GET`
pub(super) fn parse_method(
    t: &mut Tokenizer<'_>,
    dir_tok: &Token,
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
pub(super) fn parse_request_body(
    t: &mut Tokenizer<'_>,
    dir_tok: &Token,
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

/// `response_body_limit 100MB`
pub(super) fn parse_response_body_limit(
    t: &mut Tokenizer<'_>,
    _dir_tok: &Token,
) -> Result<ResponseBodyLimitDirective, ParseError> {
    let size_tok = t.next_token();
    let (line, col) = (size_tok.line, size_tok.col);
    let TokenKind::Word(size_str) = size_tok.kind else {
        return Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "response_body_limit".to_string(),
                message: "expected size value (e.g. 100MB, 1GB)".to_string(),
            },
        });
    };
    let max_size = parse_size(&size_str).ok_or_else(|| ParseError {
        line,
        col,
        kind: ParseErrorKind::InvalidValue {
            directive: "response_body_limit".to_string(),
            message: format!(
                "invalid size '{size_str}' — expected a number with optional unit (KB, MB, GB)"
            ),
        },
    })?;
    Ok(ResponseBodyLimitDirective { max_size })
}

/// `bind 0.0.0.0` or `bind 127.0.0.1 ::1`
pub(super) fn parse_bind(
    t: &mut Tokenizer<'_>,
    dir_tok: &Token,
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
pub(super) fn parse_vars(
    t: &mut Tokenizer<'_>,
    dir_tok: &Token,
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

/// Returns true if `w` is a known `cache` sub-directive keyword.
fn is_cache_sub_directive(w: &str) -> bool {
    matches!(
        w,
        "max_size" | "match_path" | "default_ttl" | "stale_while_revalidate"
    )
}

/// Parse a `max_size` value inside a `cache` block (e.g. `1g`, `500MB`).
fn parse_cache_max_size(t: &mut Tokenizer<'_>) -> Result<u64, ParseError> {
    let size_tok = t.next_token();
    let (line, col) = (size_tok.line, size_tok.col);
    let TokenKind::Word(size_str) = size_tok.kind else {
        return Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "cache".to_string(),
                message: "expected size value (e.g. 1g, 500MB)".to_string(),
            },
        });
    };
    parse_size(&size_str).ok_or_else(|| ParseError {
        line,
        col,
        kind: ParseErrorKind::InvalidValue {
            directive: "cache".to_string(),
            message: format!(
                "invalid size '{size_str}' — expected a number with optional unit (K, M, G, KB, MB, GB)"
            ),
        },
    })
}

/// Parse a u32 seconds value for a named `cache` sub-directive (e.g. `default_ttl 3600`).
fn parse_cache_seconds(t: &mut Tokenizer<'_>, field: &str) -> Result<u32, ParseError> {
    let val_tok = t.next_token();
    let (line, col) = (val_tok.line, val_tok.col);
    let TokenKind::Word(val_str) = val_tok.kind else {
        return Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "cache".to_string(),
                message: format!("expected integer seconds for {field}"),
            },
        });
    };
    val_str.parse().map_err(|_| ParseError {
        line,
        col,
        kind: ParseErrorKind::InvalidValue {
            directive: "cache".to_string(),
            message: format!("'{val_str}' is not a valid u32 for {field}"),
        },
    })
}

/// Collect path patterns for `match_path`, stopping at known sub-directives or block end.
fn collect_cache_match_paths(t: &mut Tokenizer<'_>, paths: &mut Vec<String>) {
    loop {
        match &t.peek().kind {
            TokenKind::Word(w) if is_cache_sub_directive(w) => break,
            TokenKind::Word(_) | TokenKind::QuotedString(_) => {
                let tok = t.next_token();
                match tok.kind {
                    TokenKind::Word(p) | TokenKind::QuotedString(p) => paths.push(p),
                    _ => {}
                }
            }
            _ => break,
        }
    }
}

/// `cache { max_size 1g; match_path /static/* /assets/*; default_ttl 3600; stale_while_revalidate 60 }`
///
/// All sub-directives are optional. An empty block enables caching with defaults.
pub(super) fn parse_cache(
    t: &mut Tokenizer<'_>,
    dir_tok: &Token,
) -> Result<CacheDirective, ParseError> {
    if t.peek().kind != TokenKind::OpenBrace {
        return Err(ParseError {
            line: dir_tok.line,
            col: dir_tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "cache".to_string(),
                message: "expected '{' block".to_string(),
            },
        });
    }
    t.next_token(); // consume '{'

    let mut max_size: Option<u64> = None;
    let mut match_paths: Vec<String> = Vec::new();
    let mut default_ttl: Option<u32> = None;
    let mut stale_while_revalidate: Option<u32> = None;

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
                        expected: "'}' to close cache block".to_string(),
                    },
                });
            }
            TokenKind::Word(w) => {
                let keyword = w.clone();
                let kw_tok = t.next_token();
                match keyword.as_str() {
                    "max_size" => max_size = Some(parse_cache_max_size(t)?),
                    "match_path" => collect_cache_match_paths(t, &mut match_paths),
                    "default_ttl" => default_ttl = Some(parse_cache_seconds(t, "default_ttl")?),
                    "stale_while_revalidate" => {
                        stale_while_revalidate =
                            Some(parse_cache_seconds(t, "stale_while_revalidate")?);
                    }
                    other => {
                        return Err(ParseError {
                            line: kw_tok.line,
                            col: kw_tok.col,
                            kind: ParseErrorKind::InvalidValue {
                                directive: "cache".to_string(),
                                message: format!(
                                    "unknown sub-directive '{other}' — expected max_size, match_path, default_ttl, or stale_while_revalidate"
                                ),
                            },
                        });
                    }
                }
            }
            _ => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "cache sub-directive or '}'".to_string(),
                        got: format!("{:?}", tok.kind),
                    },
                });
            }
        }
    }

    Ok(CacheDirective {
        max_size,
        match_paths,
        default_ttl,
        stale_while_revalidate,
    })
}

/// `error "message" 500` or `error 404`
///
/// Arguments are order-insensitive: a 3-digit number is the status code,
/// a quoted string or non-numeric word is the message. This matches Caddy's
/// flexible argument ordering.
pub(super) fn parse_error_directive(t: &mut Tokenizer<'_>) -> ErrorDirective {
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
