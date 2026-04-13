// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Shared parsing utilities used across directive, matcher, and grammar modules.

use crate::error::{ParseError, ParseErrorKind};
use crate::model::UpstreamAddr;
use crate::token::{Token, TokenKind, Tokenizer};

/// Parse a human-readable size string like `10MB`, `512KB`, `1GB`, or a bare byte count.
pub(super) fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(n) = s
        .strip_suffix("GB")
        .or_else(|| s.strip_suffix("gb"))
        .or_else(|| s.strip_suffix("G"))
        .or_else(|| s.strip_suffix("g"))
    {
        n.trim()
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(1024 * 1024 * 1024))
    } else if let Some(n) = s
        .strip_suffix("MB")
        .or_else(|| s.strip_suffix("mb"))
        .or_else(|| s.strip_suffix("M"))
        .or_else(|| s.strip_suffix("m"))
    {
        n.trim()
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(1024 * 1024))
    } else if let Some(n) = s
        .strip_suffix("KB")
        .or_else(|| s.strip_suffix("kb"))
        .or_else(|| s.strip_suffix("K"))
        .or_else(|| s.strip_suffix("k"))
    {
        n.trim()
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(1024))
    } else {
        s.parse().ok()
    }
}

/// Skip tokens until the next line (used to skip unknown sub-directives).
///
/// This reads tokens without consuming the closing brace of the parent block.
pub(super) fn skip_to_next_line(t: &mut Tokenizer<'_>) {
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

/// Consume words/quoted-strings until we hit a stop token.
///
/// Stops (without consuming) at:
/// - `{`, `}`, EOF
/// - Any word starting with `@` (next named matcher)
/// - Any matcher condition keyword (next condition in the same block)
/// - Any top-level directive name (so single-line matchers don't eat directives)
///
/// Quoted strings are always consumed regardless of their value.
pub(super) fn collect_words_until_brace_or_known(t: &mut Tokenizer<'_>) -> Vec<String> {
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
pub(super) fn next_word_or_quoted(t: &mut Tokenizer<'_>) -> Option<String> {
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
pub(super) fn peek_word(t: &mut Tokenizer<'_>) -> Option<String> {
    match t.peek().kind {
        TokenKind::Word(w) => Some(w),
        _ => None,
    }
}

/// Helper: expect a word or quoted string token.
pub(super) fn expect_word_or_quoted(
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
                accepted_format: None,
            },
        }),
    }
}

/// Parse an upstream address — try socket addr first, fall back to host:port string.
pub(super) fn parse_upstream_addr(s: &str) -> UpstreamAddr {
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
pub(super) fn is_directive_name(w: &str) -> bool {
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
            // Recognized Caddyfile directives — typed but runtime pending (ISSUE-056)
            | "log"
            | "bind"
            | "abort"
            | "error"
            | "metrics"
            | "templates"
            | "request_body"
            | "response_body_limit"
            | "ip_filter"
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
            | "cache"
            | "wasm_plugin"
    )
}

/// Returns true if `w` is a matcher condition keyword.
pub(super) fn is_matcher_condition_keyword(w: &str) -> bool {
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

/// Skip tokens until the matching `}` is found, handling nested braces.
pub(super) fn skip_brace_block(t: &mut Tokenizer<'_>) {
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

/// Check for an optional path/matcher pattern before a block.
pub(super) fn parse_optional_pattern(t: &mut Tokenizer<'_>) -> Option<String> {
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

/// Consume a required argument (word or quoted string), using the directive token for error location.
pub(super) fn consume_arg(
    t: &mut Tokenizer<'_>,
    dir_tok: &Token,
    directive: &str,
    what: &str,
) -> Result<String, ParseError> {
    let tok = t.next_token();
    match tok.kind {
        TokenKind::Word(w) => Ok(w),
        TokenKind::QuotedString(s) => Ok(s),
        _ => Err(ParseError {
            line: dir_tok.line,
            col: dir_tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: directive.to_string(),
                message: format!("expected {what}"),
                accepted_format: None,
            },
        }),
    }
}
