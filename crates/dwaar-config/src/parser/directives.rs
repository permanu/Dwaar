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
    HandlePathDirective, PhpFastcgiDirective, RedirDirective, RespondDirective,
    ReverseProxyDirective, RewriteDirective, RootDirective, RouteDirective, TryFilesDirective,
    UriDirective, UriOperation,
};
use crate::token::{TokenKind, Tokenizer};

use super::helpers::{
    expect_word_or_quoted, is_directive_name, parse_optional_pattern, parse_upstream_addr,
};

/// `reverse_proxy localhost:8080` or `reverse_proxy 10.0.0.1:3000 10.0.0.2:3000`
pub(super) fn parse_reverse_proxy(
    t: &mut Tokenizer<'_>,
) -> Result<ReverseProxyDirective, ParseError> {
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
                        got: format!("{:?}", tok.kind),
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
            },
        });
    }

    Ok(TryFilesDirective { files })
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
                directives.push(super::parse_directive(t)?);
            }
        }
    }

    Ok(directives)
}
