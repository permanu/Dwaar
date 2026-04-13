// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Parser for the caddy-l4 Caddyfile app syntax.
//!
//! This is deliberately separate from the HTTP directive parser because words
//! like `route`, `tls`, and `proxy` have different meanings in layer4 blocks.
//!
//! Wired from `parse_global_option_line` (top-level `layer4 { }` block)
//! and from `parse_listener_wrappers_block` (server-level `listener_wrappers { layer4 { } }`).

use crate::error::{ParseError, ParseErrorKind};
use crate::model::{
    Layer4Config, Layer4Handler, Layer4Matcher, Layer4MatcherDef, Layer4Option, Layer4ProxyHandler,
    Layer4Route, Layer4RouteSet, Layer4Server, Layer4SubrouteHandler, Layer4TlsHandler,
};
use crate::token::{Token, TokenKind, Tokenizer};

use super::helpers::next_word_or_quoted;

pub(super) fn parse_layer4_config(
    t: &mut Tokenizer<'_>,
    key_tok: &Token,
) -> Result<Layer4Config, ParseError> {
    expect_open_brace(t, key_tok, "layer4")?;

    let mut servers = Vec::new();
    loop {
        let tok = t.peek();
        match tok.kind {
            TokenKind::CloseBrace => {
                t.next_token();
                break;
            }
            TokenKind::Eof => return unexpected_eof(&tok, "'}' to close layer4 block"),
            TokenKind::Word(_) | TokenKind::QuotedString(_) => {
                servers.push(parse_layer4_server(t, &tok)?);
            }
            TokenKind::OpenBrace => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "layer4 listen address or '}'".to_string(),
                        got: format!("{}", tok.kind),
                    },
                });
            }
        }
    }

    Ok(Layer4Config { servers })
}

pub(super) fn parse_layer4_route_set(
    t: &mut Tokenizer<'_>,
    key_tok: &Token,
) -> Result<Layer4RouteSet, ParseError> {
    expect_open_brace(t, key_tok, "layer4")?;
    parse_route_set_body(t, "'}' to close layer4 listener wrapper")
}

fn parse_layer4_server(
    t: &mut Tokenizer<'_>,
    first_tok: &Token,
) -> Result<Layer4Server, ParseError> {
    let mut listen = Vec::new();
    loop {
        match t.peek().kind {
            TokenKind::OpenBrace => {
                t.next_token();
                break;
            }
            TokenKind::Word(_) | TokenKind::QuotedString(_) => {
                let Some(addr) = next_word_or_quoted(t) else {
                    unreachable!("peek ensured word or quoted string")
                };
                listen.push(addr);
            }
            TokenKind::Eof => return unexpected_eof(&t.peek(), "'{' to open layer4 server block"),
            TokenKind::CloseBrace => {
                let tok = t.peek();
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "'{' after layer4 listen address".to_string(),
                        got: format!("{}", tok.kind),
                    },
                });
            }
        }
    }

    if listen.is_empty() {
        return Err(ParseError {
            line: first_tok.line,
            col: first_tok.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "layer4".to_string(),
                message: "expected at least one listen address".to_string(),
                accepted_format: None,
            },
        });
    }

    let route_set = parse_route_set_body(t, "'}' to close layer4 server block")?;
    Ok(Layer4Server {
        listen,
        matchers: route_set.matchers,
        routes: route_set.routes,
    })
}

fn parse_route_set_body(
    t: &mut Tokenizer<'_>,
    eof_expected: &'static str,
) -> Result<Layer4RouteSet, ParseError> {
    let mut matchers = Vec::new();
    let mut routes = Vec::new();

    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::CloseBrace => {
                t.next_token();
                break;
            }
            TokenKind::Eof => return unexpected_eof(&tok, eof_expected),
            TokenKind::Word(w) if w.starts_with('@') => {
                matchers.push(parse_matcher_def(t)?);
            }
            TokenKind::Word(w) if w == "route" => {
                t.next_token();
                routes.push(parse_route(t, &tok)?);
            }
            TokenKind::Word(_) => {
                skip_unknown_layer4_item(t);
            }
            _ => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "layer4 matcher, route, or '}'".to_string(),
                        got: format!("{}", tok.kind),
                    },
                });
            }
        }
    }

    Ok(Layer4RouteSet { matchers, routes })
}

fn parse_matcher_def(t: &mut Tokenizer<'_>) -> Result<Layer4MatcherDef, ParseError> {
    let name_tok = t.next_token();
    let name = match name_tok.kind {
        TokenKind::Word(w) => w.strip_prefix('@').unwrap_or(&w).to_string(),
        _ => unreachable!("caller only dispatches on @word"),
    };

    let mut matchers = Vec::new();
    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::Word(w) if is_matcher_boundary(w) => break,
            TokenKind::Word(_) => matchers.push(parse_matcher(t)?),
            TokenKind::CloseBrace
            | TokenKind::OpenBrace
            | TokenKind::Eof
            | TokenKind::QuotedString(_) => break,
        }
    }

    Ok(Layer4MatcherDef { name, matchers })
}

fn parse_matcher(t: &mut Tokenizer<'_>) -> Result<Layer4Matcher, ParseError> {
    let tok = t.next_token();
    let TokenKind::Word(name) = tok.kind else {
        unreachable!("caller only dispatches on word")
    };

    Ok(match name.as_str() {
        "tls" => parse_tls_matcher(t),
        "http" => parse_http_matcher(t),
        "ssh" => Layer4Matcher::Ssh,
        "postgres" => Layer4Matcher::Postgres,
        "remote_ip" => {
            let ranges = collect_words_until(t, is_matcher_boundary);
            Layer4Matcher::RemoteIp(ranges)
        }
        "not" => Layer4Matcher::Not(Box::new(parse_matcher(t)?)),
        _ => {
            let args = collect_words_until(t, is_matcher_boundary);
            Layer4Matcher::Unknown { name, args }
        }
    })
}

fn parse_tls_matcher(t: &mut Tokenizer<'_>) -> Layer4Matcher {
    let mut sni = Vec::new();
    let mut alpn = Vec::new();
    let mut options = Vec::new();
    loop {
        let tok = t.peek();
        let TokenKind::Word(ref sub) = tok.kind else {
            break;
        };
        if is_matcher_boundary(sub) || is_matcher_keyword(sub) {
            break;
        }
        let name = next_word_or_quoted(t).unwrap_or_default();
        let args = collect_words_until(t, |w| {
            is_matcher_boundary(w) || is_matcher_keyword(w) || matches!(w, "sni" | "alpn")
        });
        match name.as_str() {
            "sni" => sni.extend(args),
            "alpn" => alpn.extend(args),
            _ => options.push(Layer4Option { name, args }),
        }
    }
    Layer4Matcher::Tls { sni, alpn, options }
}

fn parse_http_matcher(t: &mut Tokenizer<'_>) -> Layer4Matcher {
    let mut host = Vec::new();
    let mut options = Vec::new();
    loop {
        let tok = t.peek();
        let TokenKind::Word(ref sub) = tok.kind else {
            break;
        };
        if is_matcher_boundary(sub) || is_matcher_keyword(sub) {
            break;
        }
        let name = next_word_or_quoted(t).unwrap_or_default();
        let args = collect_words_until(t, |w| {
            is_matcher_boundary(w) || is_matcher_keyword(w) || w == "host"
        });
        if name == "host" {
            host.extend(args);
        } else {
            options.push(Layer4Option { name, args });
        }
    }
    Layer4Matcher::Http { host, options }
}

fn parse_route(t: &mut Tokenizer<'_>, route_tok: &Token) -> Result<Layer4Route, ParseError> {
    let mut matcher_names = Vec::new();
    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::OpenBrace => {
                t.next_token();
                break;
            }
            TokenKind::Word(w) if w.starts_with('@') => {
                matcher_names.push(w.trim_start_matches('@').to_string());
                t.next_token();
            }
            TokenKind::Eof => return unexpected_eof(&tok, "'{' to open layer4 route block"),
            _ => {
                return Err(ParseError {
                    line: route_tok.line,
                    col: route_tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "matcher reference or '{' after layer4 route".to_string(),
                        got: format!("{}", tok.kind),
                    },
                });
            }
        }
    }

    let mut handlers = Vec::new();
    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::CloseBrace => {
                t.next_token();
                break;
            }
            TokenKind::Eof => return unexpected_eof(&tok, "'}' to close layer4 route block"),
            TokenKind::Word(w) => {
                let name = w.clone();
                t.next_token();
                handlers.push(parse_handler(t, name, &tok)?);
            }
            _ => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "layer4 handler or '}'".to_string(),
                        got: format!("{}", tok.kind),
                    },
                });
            }
        }
    }

    Ok(Layer4Route {
        matcher_names,
        handlers,
    })
}

fn parse_handler(
    t: &mut Tokenizer<'_>,
    name: String,
    tok: &Token,
) -> Result<Layer4Handler, ParseError> {
    Ok(match name.as_str() {
        "proxy" => Layer4Handler::Proxy(parse_proxy_handler(t)?),
        "tls" => Layer4Handler::Tls(parse_tls_handler(t)?),
        "subroute" => Layer4Handler::Subroute(parse_subroute_handler(t, tok)?),
        _ => Layer4Handler::Unknown {
            name,
            args: collect_handler_args(t),
        },
    })
}

fn parse_proxy_handler(t: &mut Tokenizer<'_>) -> Result<Layer4ProxyHandler, ParseError> {
    if !matches!(t.peek().kind, TokenKind::OpenBrace) {
        return Ok(Layer4ProxyHandler {
            upstreams: collect_handler_args(t),
            options: Vec::new(),
        });
    }

    t.next_token();
    let mut upstreams = Vec::new();
    let mut options = Vec::new();
    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::CloseBrace => {
                t.next_token();
                break;
            }
            TokenKind::Eof => return unexpected_eof(&tok, "'}' to close layer4 proxy block"),
            TokenKind::Word(_) => {
                let name = next_word_or_quoted(t).unwrap_or_default();
                let args =
                    collect_words_until(t, |w| is_proxy_subdirective(w) || is_handler_boundary(w));
                if matches!(name.as_str(), "to" | "upstream" | "upstreams") {
                    upstreams.extend(args);
                } else {
                    options.push(Layer4Option { name, args });
                }
            }
            _ => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "layer4 proxy subdirective or '}'".to_string(),
                        got: format!("{}", tok.kind),
                    },
                });
            }
        }
    }

    Ok(Layer4ProxyHandler { upstreams, options })
}

fn parse_tls_handler(t: &mut Tokenizer<'_>) -> Result<Layer4TlsHandler, ParseError> {
    if !matches!(t.peek().kind, TokenKind::OpenBrace) {
        let args = collect_handler_args(t);
        return Ok(Layer4TlsHandler {
            options: vec![Layer4Option {
                name: "args".to_string(),
                args,
            }],
        });
    }

    t.next_token();
    let mut options = Vec::new();
    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::CloseBrace => {
                t.next_token();
                break;
            }
            TokenKind::Eof => return unexpected_eof(&tok, "'}' to close layer4 tls block"),
            TokenKind::Word(_) => {
                let name = next_word_or_quoted(t).unwrap_or_default();
                let args = collect_words_until(t, is_handler_boundary);
                options.push(Layer4Option { name, args });
            }
            _ => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "layer4 tls subdirective or '}'".to_string(),
                        got: format!("{}", tok.kind),
                    },
                });
            }
        }
    }

    Ok(Layer4TlsHandler { options })
}

fn parse_subroute_handler(
    t: &mut Tokenizer<'_>,
    tok: &Token,
) -> Result<Layer4SubrouteHandler, ParseError> {
    expect_open_brace(t, tok, "subroute")?;

    let mut matching_timeout = None;
    let mut route_set = Layer4RouteSet::default();

    loop {
        let peek = t.peek();
        match &peek.kind {
            TokenKind::CloseBrace => {
                t.next_token();
                break;
            }
            TokenKind::Eof => return unexpected_eof(&peek, "'}' to close layer4 subroute block"),
            TokenKind::Word(w) if w == "matching_timeout" => {
                t.next_token();
                matching_timeout = next_word_or_quoted(t);
            }
            TokenKind::Word(w) if w.starts_with('@') => {
                route_set.matchers.push(parse_matcher_def(t)?);
            }
            TokenKind::Word(w) if w == "route" => {
                t.next_token();
                route_set.routes.push(parse_route(t, &peek)?);
            }
            TokenKind::Word(_) => skip_unknown_layer4_item(t),
            _ => {
                return Err(ParseError {
                    line: peek.line,
                    col: peek.col,
                    kind: ParseErrorKind::Expected {
                        expected: "subroute option, matcher, route, or '}'".to_string(),
                        got: format!("{}", peek.kind),
                    },
                });
            }
        }
    }

    Ok(Layer4SubrouteHandler {
        matching_timeout,
        matchers: route_set.matchers,
        routes: route_set.routes,
    })
}

fn collect_handler_args(t: &mut Tokenizer<'_>) -> Vec<String> {
    collect_words_until(t, is_handler_boundary)
}

fn collect_words_until(t: &mut Tokenizer<'_>, stop: impl Fn(&str) -> bool) -> Vec<String> {
    let mut args = Vec::new();
    loop {
        match &t.peek().kind {
            TokenKind::Word(w) if stop(w) => break,
            TokenKind::Word(_) | TokenKind::QuotedString(_) => {
                if let Some(arg) = next_word_or_quoted(t) {
                    args.push(arg);
                }
            }
            _ => break,
        }
    }
    args
}

fn skip_unknown_layer4_item(t: &mut Tokenizer<'_>) {
    t.next_token();
    if matches!(t.peek().kind, TokenKind::OpenBrace) {
        t.next_token();
        super::helpers::skip_brace_block(t);
    } else {
        let _ = collect_words_until(t, is_route_set_boundary);
    }
}

fn expect_open_brace(
    t: &mut Tokenizer<'_>,
    key_tok: &Token,
    directive: &str,
) -> Result<(), ParseError> {
    let brace = t.peek();
    if !matches!(brace.kind, TokenKind::OpenBrace) {
        return Err(ParseError {
            line: key_tok.line,
            col: key_tok.col,
            kind: ParseErrorKind::Expected {
                expected: format!("'{{' to open {directive} block"),
                got: format!("{}", brace.kind),
            },
        });
    }
    t.next_token();
    Ok(())
}

fn unexpected_eof<T>(tok: &Token, expected: &str) -> Result<T, ParseError> {
    Err(ParseError {
        line: tok.line,
        col: tok.col,
        kind: ParseErrorKind::UnexpectedEof {
            expected: expected.to_string(),
        },
    })
}

fn is_route_set_boundary(w: &str) -> bool {
    w.starts_with('@') || w == "route"
}

fn is_matcher_boundary(w: &str) -> bool {
    is_route_set_boundary(w)
}

fn is_handler_boundary(w: &str) -> bool {
    matches!(w, "proxy" | "tls" | "subroute") || w.starts_with('@')
}

fn is_matcher_keyword(w: &str) -> bool {
    matches!(w, "tls" | "http" | "ssh" | "postgres" | "remote_ip" | "not")
}

fn is_proxy_subdirective(w: &str) -> bool {
    matches!(
        w,
        "to" | "upstream"
            | "upstreams"
            | "lb_policy"
            | "health_uri"
            | "health_interval"
            | "health_timeout"
            | "health_port"
            | "proxy_protocol"
            | "dial_timeout"
            | "dial_fallback_delay"
            | "max_fails"
            | "fail_duration"
            | "max_conns"
            | "transport"
    )
}
