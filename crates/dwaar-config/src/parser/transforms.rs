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
    BasicAuthCredential, BasicAuthDirective, BindDirective, EncodeDirective, ErrorDirective,
    HeaderDirective, MethodDirective, RateLimitDirective, RequestBodyDirective,
    RequestHeaderDirective, ResponseBodyLimitDirective, TlsDirective, VarsDirective,
};
use crate::token::{Token, TokenKind, Tokenizer};

use super::helpers::{expect_word_or_quoted, is_directive_name, parse_size, skip_to_next_line};

/// `tls auto` / `tls off` / `tls internal` / `tls /cert /key`
pub(super) fn parse_tls(t: &mut Tokenizer<'_>) -> Result<TlsDirective, ParseError> {
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
