// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Named matcher parsing — `@name { condition* }` blocks.
//!
//! Matchers define reusable conditions that directives reference by name.
//! Each condition matches on request properties (path, host, method, headers, etc.).

use crate::error::{ParseError, ParseErrorKind};
use crate::model::{MatcherCondition, MatcherDef};
use crate::token::{TokenKind, Tokenizer};

use super::helpers::{
    collect_words_until_brace_or_known, is_directive_name, is_matcher_condition_keyword,
    next_word_or_quoted, peek_word,
};

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
pub(super) fn parse_matcher_def(t: &mut Tokenizer<'_>) -> Result<MatcherDef, ParseError> {
    // Consume the `@name` token (the '@' prefix is included in the Word).
    let name_tok = t.next_token();
    let name = match &name_tok.kind {
        TokenKind::Word(w) => {
            // Strip exactly one leading '@' — we validated the prefix in parse_site_block.
            w.strip_prefix('@').unwrap_or(w).to_string()
        }
        _ => {
            return Err(ParseError {
                line: name_tok.line,
                col: name_tok.col,
                kind: ParseErrorKind::Expected {
                    expected: "matcher name starting with '@'".to_string(),
                    got: format!("{}", name_tok.kind),
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
                                got: format!("{}", tok.kind),
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
                    got: format!("{}", kw_tok.kind),
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

/// Parse a `not { conditions }` block.
fn parse_not_condition(t: &mut Tokenizer<'_>) -> Result<MatcherCondition, ParseError> {
    let brace = t.peek();
    if brace.kind != TokenKind::OpenBrace {
        return Err(ParseError {
            line: brace.line,
            col: brace.col,
            kind: ParseErrorKind::Expected {
                expected: "'{' after 'not'".to_string(),
                got: format!("{}", brace.kind),
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
                        got: format!("{}", tok.kind),
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
                got: format!("{}", brace.kind),
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
                        got: format!("{}", tok.kind),
                    },
                });
            }
        }
    }
    Ok(MatcherCondition::File { try_files })
}
