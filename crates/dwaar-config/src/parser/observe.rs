// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Observability and data directive parsers — what we record, compute, or transform.
//!
//! Covers: `log`, `log_output`, `log_format`, `log_append`, `log_name`, `metrics`, `tracing`,
//! `map`, `invoke`, `fs`, `intercept`, `copy_response`, `copy_response_headers`, recognized.

use crate::error::{ParseError, ParseErrorKind};
use crate::model::{
    CopyResponseDirective, CopyResponseHeadersDirective, FsDirective, InterceptDirective,
    InvokeDirective, LogAppendDirective, LogDirective, LogFormat, LogNameDirective, LogOutput,
    MapDirective, MapEntry, MapPattern, MetricsDirective, RecognizedDirective, TracingDirective,
};
use crate::token::{Token, TokenKind, Tokenizer};

use super::helpers::{consume_arg, is_directive_name, skip_brace_block, skip_to_next_line};

/// `log` or `log { output file /path; format json; level INFO }`
pub(super) fn parse_log(t: &mut Tokenizer<'_>) -> Result<LogDirective, ParseError> {
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
                        got: format!("{}", tok.kind),
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
#[allow(clippy::too_many_lines)]
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
        "unix" => {
            let path_tok = t.next_token();
            let (TokenKind::Word(path) | TokenKind::QuotedString(path)) = path_tok.kind else {
                return Err(ParseError {
                    line: path_tok.line,
                    col: path_tok.col,
                    kind: ParseErrorKind::InvalidValue {
                        directive: "log".to_string(),
                        message: "expected socket path after 'output unix'".to_string(),
                    },
                });
            };
            Ok(LogOutput::Unix { path })
        }
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

            // Optional block: `{ max_size 50mb  keep 3 }`
            let mut max_bytes = None;
            let mut keep = None;
            if t.peek().kind == TokenKind::OpenBrace {
                t.next_token(); // consume '{'
                loop {
                    let tok = t.peek();
                    match &tok.kind {
                        TokenKind::CloseBrace => {
                            t.next_token();
                            break;
                        }
                        TokenKind::Word(w) => {
                            let w = w.clone();
                            t.next_token();
                            match w.as_str() {
                                "max_size" => {
                                    max_bytes = Some(parse_size_value(t, line, col)?);
                                }
                                "keep" => {
                                    let val_tok = t.next_token();
                                    let TokenKind::Word(val) = val_tok.kind else {
                                        return Err(ParseError {
                                            line: val_tok.line,
                                            col: val_tok.col,
                                            kind: ParseErrorKind::InvalidValue {
                                                directive: "log".to_string(),
                                                message: "expected keep count".to_string(),
                                            },
                                        });
                                    };
                                    keep = Some(val.parse::<u32>().map_err(|_| ParseError {
                                        line,
                                        col,
                                        kind: ParseErrorKind::InvalidValue {
                                            directive: "log".to_string(),
                                            message: format!("invalid keep count: '{val}'"),
                                        },
                                    })?);
                                }
                                _ => skip_to_next_line(t),
                            }
                        }
                        _ => skip_to_next_line(t),
                    }
                }
            }

            Ok(LogOutput::File {
                path,
                max_bytes,
                keep,
            })
        }
        other => Err(ParseError {
            line,
            col,
            kind: ParseErrorKind::InvalidValue {
                directive: "log".to_string(),
                message: format!(
                    "unknown log output '{other}' — expected stdout, stderr, discard, unix, or file"
                ),
            },
        }),
    }
}

/// Parse a human-readable size value like `50mb`, `1gb`, `1024`.
fn parse_size_value(t: &mut Tokenizer<'_>, line: usize, col: usize) -> Result<u64, ParseError> {
    let val_tok = t.next_token();
    let raw = match val_tok.kind {
        TokenKind::Word(w) => w,
        TokenKind::QuotedString(s) => s,
        _ => {
            return Err(ParseError {
                line: val_tok.line,
                col: val_tok.col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "log".to_string(),
                    message: "expected size value after 'max_size'".to_string(),
                },
            });
        }
    };
    let lower = raw.to_lowercase();
    let (num_str, multiplier) = if let Some(n) = lower.strip_suffix("gb") {
        (n, 1_073_741_824u64)
    } else if let Some(n) = lower.strip_suffix("mb") {
        (n, 1_048_576u64)
    } else if let Some(n) = lower.strip_suffix("kb") {
        (n, 1024u64)
    } else {
        (lower.as_str(), 1u64)
    };
    let base = num_str.parse::<u64>().map_err(|_| ParseError {
        line,
        col,
        kind: ParseErrorKind::InvalidValue {
            directive: "log".to_string(),
            message: format!("invalid size value: '{raw}'"),
        },
    })?;
    Ok(base.saturating_mul(multiplier))
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

/// Parse `log_append { field value; ... }` or `log_append field value`
pub(super) fn parse_log_append(
    t: &mut Tokenizer<'_>,
    dir_tok: &Token,
) -> Result<LogAppendDirective, ParseError> {
    let tok = t.peek();
    if tok.kind != TokenKind::OpenBrace {
        // Inline form: log_append field value
        let name = consume_arg(t, dir_tok, "log_append", "field name")?;
        let value = consume_arg(t, dir_tok, "log_append", "field value")?;
        return Ok(LogAppendDirective {
            fields: vec![(name, value)],
        });
    }

    t.next_token(); // consume {
    let mut fields = Vec::new();
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
                        expected: "'}' to close log_append block".to_string(),
                    },
                });
            }
            TokenKind::Word(w) | TokenKind::QuotedString(w) => {
                let name = w.clone();
                t.next_token();
                let value = consume_arg(t, dir_tok, "log_append", "field value")?;
                fields.push((name, value));
            }
            TokenKind::OpenBrace => {
                t.next_token();
            }
        }
    }
    Ok(LogAppendDirective { fields })
}

/// Parse `log_name <name>`
pub(super) fn parse_log_name(t: &mut Tokenizer<'_>) -> Result<LogNameDirective, ParseError> {
    let tok = t.next_token();
    let name = match tok.kind {
        TokenKind::Word(w) => w,
        TokenKind::QuotedString(s) => s,
        _ => {
            return Err(ParseError {
                line: tok.line,
                col: tok.col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "log_name".to_string(),
                    message: "expected logger name".to_string(),
                },
            });
        }
    };
    Ok(LogNameDirective { name })
}

/// Parse `metrics [path]`
pub(super) fn parse_metrics(t: &mut Tokenizer<'_>) -> MetricsDirective {
    let tok = t.peek();
    let path = match &tok.kind {
        TokenKind::Word(w) if !is_directive_name(w) && !w.starts_with('@') => {
            t.next_token();
            Some(w.clone())
        }
        _ => None,
    };
    MetricsDirective { path }
}

/// Parse `tracing [endpoint]`
pub(super) fn parse_tracing(t: &mut Tokenizer<'_>) -> TracingDirective {
    let tok = t.peek();
    let endpoint = match &tok.kind {
        TokenKind::Word(w) if !is_directive_name(w) && !w.starts_with('@') => {
            t.next_token();
            Some(w.clone())
        }
        _ => None,
    };
    TracingDirective { endpoint }
}

/// Parse `map {source} {dest_var} { pattern value; ... }`
pub(super) fn parse_map(
    t: &mut Tokenizer<'_>,
    dir_tok: &Token,
) -> Result<MapDirective, ParseError> {
    let source = consume_arg(t, dir_tok, "map", "source expression")?;
    let dest_var = consume_arg(t, dir_tok, "map", "destination variable name")?;

    let entries = parse_map_block(t, dir_tok)?;

    Ok(MapDirective {
        source,
        dest_var,
        entries,
    })
}

fn parse_map_block(t: &mut Tokenizer<'_>, dir_tok: &Token) -> Result<Vec<MapEntry>, ParseError> {
    let tok = t.peek();
    if tok.kind != TokenKind::OpenBrace {
        return Ok(Vec::new());
    }
    t.next_token(); // consume {

    let mut entries = Vec::new();
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
                        expected: "'}' to close map block".to_string(),
                    },
                });
            }
            TokenKind::Word(w) | TokenKind::QuotedString(w) => {
                let w = w.clone();
                t.next_token();
                let pattern = if w == "default" {
                    MapPattern::Default
                } else if let Some(regex) = w.strip_prefix('~') {
                    MapPattern::Regex(regex.to_string())
                } else {
                    MapPattern::Exact(w.clone())
                };
                let value = consume_arg(t, dir_tok, "map", "value for pattern")?;
                entries.push(MapEntry { pattern, value });
            }
            TokenKind::OpenBrace => {
                t.next_token();
            }
        }
    }
    Ok(entries)
}

/// Parse `invoke <name>`
pub(super) fn parse_invoke(t: &mut Tokenizer<'_>) -> Result<InvokeDirective, ParseError> {
    let tok = t.next_token();
    let name = match tok.kind {
        TokenKind::Word(w) => w,
        TokenKind::QuotedString(s) => s,
        _ => {
            return Err(ParseError {
                line: tok.line,
                col: tok.col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "invoke".to_string(),
                    message: "expected route name".to_string(),
                },
            });
        }
    };
    Ok(InvokeDirective { name })
}

/// Parse `fs [args] [{ block }]`
pub(super) fn parse_fs(t: &mut Tokenizer<'_>, _dir_tok: &Token) -> FsDirective {
    let mut args = Vec::new();
    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::OpenBrace => {
                // Consume the block without storing — runtime not yet implemented
                t.next_token();
                skip_brace_block(t);
                break;
            }
            TokenKind::CloseBrace | TokenKind::Eof => break,
            TokenKind::Word(w) if is_directive_name(w) || w.starts_with('@') => break,
            TokenKind::Word(w) | TokenKind::QuotedString(w) => {
                t.next_token();
                args.push(w.clone());
            }
        }
    }
    FsDirective { args }
}

/// Parse a recognized Caddyfile directive that Dwaar doesn't implement
/// (templates, push, `acme_server`). Captures args for config round-tripping.
pub(super) fn parse_recognized(t: &mut Tokenizer<'_>) -> RecognizedDirective {
    let mut args = Vec::new();
    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::OpenBrace => {
                // Consume the block without interpreting — these are
                // Caddy-specific features Dwaar won't implement
                t.next_token();
                let mut depth: u32 = 1;
                loop {
                    let tok = t.next_token();
                    match tok.kind {
                        TokenKind::OpenBrace => depth += 1,
                        TokenKind::CloseBrace => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        TokenKind::Eof => break,
                        _ => {}
                    }
                }
                break;
            }
            TokenKind::CloseBrace | TokenKind::Eof => break,
            TokenKind::Word(w) if is_directive_name(w) || w.starts_with('@') => break,
            TokenKind::Word(w) | TokenKind::QuotedString(w) => {
                t.next_token();
                args.push(w.clone());
            }
        }
    }
    RecognizedDirective { args }
}

/// Parse `intercept [status...] { directives }`
pub(super) fn parse_intercept(
    t: &mut Tokenizer<'_>,
    dir_tok: &Token,
) -> Result<InterceptDirective, ParseError> {
    let mut statuses = Vec::new();
    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::OpenBrace => break,
            TokenKind::CloseBrace | TokenKind::Eof => {
                return Err(ParseError {
                    line: dir_tok.line,
                    col: dir_tok.col,
                    kind: ParseErrorKind::InvalidValue {
                        directive: "intercept".to_string(),
                        message: "expected { block".to_string(),
                    },
                });
            }
            TokenKind::Word(w) => {
                t.next_token();
                if let Ok(code) = w.parse::<u16>() {
                    statuses.push(code);
                } else {
                    break;
                }
            }
            TokenKind::QuotedString(_) => {
                t.next_token();
            }
        }
    }
    let directives = super::directives::parse_directive_block(t)?;
    Ok(InterceptDirective {
        statuses,
        directives,
    })
}

/// Parse `copy_response [status...]`
pub(super) fn parse_copy_response(t: &mut Tokenizer<'_>) -> CopyResponseDirective {
    let mut statuses = Vec::new();
    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::CloseBrace | TokenKind::Eof => break,
            TokenKind::Word(w) if is_directive_name(w) || w.starts_with('@') => break,
            TokenKind::Word(w) => {
                t.next_token();
                if let Ok(code) = w.parse::<u16>() {
                    statuses.push(code);
                }
            }
            _ => {
                t.next_token();
            }
        }
    }
    CopyResponseDirective { statuses }
}

/// Parse `copy_response_headers { headers... }`
pub(super) fn parse_copy_response_headers(
    t: &mut Tokenizer<'_>,
    _dir_tok: &Token,
) -> Result<CopyResponseHeadersDirective, ParseError> {
    let tok = t.peek();
    if tok.kind != TokenKind::OpenBrace {
        return Ok(CopyResponseHeadersDirective {
            headers: Vec::new(),
        });
    }
    t.next_token(); // consume {

    let mut headers = Vec::new();
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
                        expected: "'}' to close copy_response_headers block".to_string(),
                    },
                });
            }
            TokenKind::Word(w) | TokenKind::QuotedString(w) => {
                headers.push(w.clone());
                t.next_token();
            }
            TokenKind::OpenBrace => {
                t.next_token();
            }
        }
    }
    Ok(CopyResponseHeadersDirective { headers })
}
