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
//! ## Module layout (SRP)
//!
//! - `mod.rs` — grammar orchestration: public API, config/site/global, directive dispatch
//! - `directives` — routing: where does the request go?
//! - `transforms` — modification: what changes about the request/response?
//! - `observe` — observability: what do we record or compute?
//! - `matchers` — named matcher definitions (`@name { condition* }`)
//! - `helpers` — shared token utilities used by all modules
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

mod directives;
mod helpers;
pub(super) mod layer4;
mod matchers;
mod observe;
mod transforms;

#[cfg(test)]
mod tests;

use crate::error::{ParseError, ParseErrorKind, suggest_directive};
use crate::model::{
    Directive, DwaarConfig, GlobalOptions, Layer4ListenerWrapper, SiteBlock, TimeoutsConfig,
};
use crate::token::{Token, TokenKind, Tokenizer};

use helpers::skip_brace_block;

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
    let mut global_options = if t.peek().kind == TokenKind::OpenBrace {
        Some(parse_global_options(t)?)
    } else {
        None
    };

    // Top-level `layer4 { ... }` block (caddy-l4 app syntax).
    // Can appear alongside site blocks and is stored in global options.
    let mut top_level_layer4 = None;

    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::Eof => break,
            TokenKind::Word(w) if w == "layer4" => {
                let l4_tok = t.next_token();
                top_level_layer4 = Some(layer4::parse_layer4_config(t, &l4_tok)?);
            }
            TokenKind::Word(_) => {
                sites.push(parse_site_block(t)?);
            }
            _ => {
                return Err(ParseError {
                    line: tok.line,
                    col: tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "site address (e.g. 'example.com')".to_string(),
                        got: format!("{}", tok.kind),
                    },
                });
            }
        }
    }

    // Merge top-level layer4 into global options (creating the struct if needed).
    if let Some(l4) = top_level_layer4 {
        global_options
            .get_or_insert_with(GlobalOptions::default)
            .layer4 = Some(l4);
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
                    accepted_format: None,
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
                    accepted_format: None,
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
        "drain_timeout" => {
            let val = peek_consume_word_or_quoted(t);
            let secs = parse_duration_secs(&val).ok_or(ParseError {
                line: key_tok.line,
                col: key_tok.col,
                kind: ParseErrorKind::InvalidValue {
                    directive: "drain_timeout".to_string(),
                    message: format!("'{val}' is not a valid duration (e.g. '30s', '1m', '60')"),
                    accepted_format: Some("duration, e.g., 30s or 2m"),
                },
            })?;
            opts.drain_timeout_secs = Some(secs);
        }
        "timeouts" => {
            opts.timeouts = Some(parse_timeouts_block(t, &key_tok)?);
        }
        "servers" => {
            parse_servers_block(t, opts, &key_tok)?;
        }
        "auto_update" => {
            opts.auto_update = Some(parse_auto_update_block(t, &key_tok)?);
        }
        "layer4" => {
            opts.layer4 = Some(layer4::parse_layer4_config(t, &key_tok)?);
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
                // peek() and next_token() are always consistent; this arm
                // can only fire if the tokenizer has a bug.
                other => {
                    debug_assert!(
                        false,
                        "tokenizer returned unexpected variant after peek: {other:?}"
                    );
                    String::new()
                }
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
            | "drain_timeout"
            | "timeouts"
            | "auto_update"
            | "layer4"
    )
}

/// Parse a duration string like "30s", "1m", "6h", "60" into seconds.
/// Supports bare numbers (seconds), `Ns` (seconds), `Nm` (minutes), `Nh` (hours).
fn parse_duration_secs(s: &str) -> Option<u64> {
    if let Some(rest) = s.strip_suffix('s') {
        rest.parse().ok()
    } else if let Some(rest) = s.strip_suffix('m') {
        rest.parse::<u64>().ok().map(|m| m * 60)
    } else if let Some(rest) = s.strip_suffix('h') {
        rest.parse::<u64>().ok().map(|h| h * 3600)
    } else {
        s.parse().ok()
    }
}

/// Parse a duration value for a `timeouts` sub-key like `header 10s`.
fn parse_timeout_duration(val: &str, directive: &str, tok: &Token) -> Result<u32, ParseError> {
    let secs = parse_duration_secs(val).ok_or(ParseError {
        line: tok.line,
        col: tok.col,
        kind: ParseErrorKind::InvalidValue {
            directive: directive.to_string(),
            message: format!("'{val}' is not a valid duration (e.g. '10s', '1m')"),
            accepted_format: Some("duration, e.g., 30s or 2m"),
        },
    })?;
    Ok(u32::try_from(secs).unwrap_or(u32::MAX))
}

/// Parse the `auto_update { ... }` global block.
#[allow(clippy::too_many_lines)] // Structurally flat: each directive is one match arm; splitting harms readability
fn parse_auto_update_block(
    t: &mut Tokenizer<'_>,
    key_tok: &Token,
) -> Result<super::model::AutoUpdateConfig, ParseError> {
    use super::model::{AutoUpdateAction, AutoUpdateConfig};

    let brace = t.peek();
    if !matches!(brace.kind, TokenKind::OpenBrace) {
        return Err(ParseError {
            line: key_tok.line,
            col: key_tok.col,
            kind: ParseErrorKind::Expected {
                expected: "'{' to open auto_update block".to_string(),
                got: format!("{}", brace.kind),
            },
        });
    }
    t.next_token(); // consume `{`

    let mut cfg = AutoUpdateConfig::default();

    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::CloseBrace => {
                t.next_token();
                break;
            }
            TokenKind::Eof => {
                return Err(ParseError {
                    line: key_tok.line,
                    col: key_tok.col,
                    kind: ParseErrorKind::Expected {
                        expected: "'}' to close auto_update block".to_string(),
                        got: "end of file".to_string(),
                    },
                });
            }
            TokenKind::Word(_) => {
                let sub_tok = t.next_token();
                let sub_key = match &sub_tok.kind {
                    TokenKind::Word(w) => w.clone(),
                    _ => unreachable!(),
                };
                let val = peek_consume_word_or_quoted(t);

                match sub_key.as_str() {
                    "channel" => {
                        if val != "stable" && val != "beta" {
                            return Err(ParseError {
                                line: sub_tok.line,
                                col: sub_tok.col,
                                kind: ParseErrorKind::InvalidValue {
                                    directive: "auto_update.channel".to_string(),
                                    message: format!(
                                        "unknown channel '{val}', expected 'stable' or 'beta'"
                                    ),
                                    accepted_format: None,
                                },
                            });
                        }
                        cfg.channel = val;
                    }
                    "check_interval" => {
                        let secs = parse_duration_secs(&val).ok_or(ParseError {
                            line: sub_tok.line,
                            col: sub_tok.col,
                            kind: ParseErrorKind::InvalidValue {
                                directive: "auto_update.check_interval".to_string(),
                                message: format!(
                                    "'{val}' is not a valid duration (e.g. '6h', '30m', '3600')"
                                ),
                                accepted_format: Some("duration, e.g., 30s or 2m"),
                            },
                        })?;
                        cfg.check_interval_secs = secs;
                    }
                    "window" => {
                        // Format: "HH:MM-HH:MM" (UTC)
                        cfg.window = Some(parse_time_window(&val).ok_or(ParseError {
                            line: sub_tok.line,
                            col: sub_tok.col,
                            kind: ParseErrorKind::InvalidValue {
                                directive: "auto_update.window".to_string(),
                                message: format!(
                                    "'{val}' is not a valid time window (expected HH:MM-HH:MM)"
                                ),
                                accepted_format: None,
                            },
                        })?);
                    }
                    "on_new_version" => match val.as_str() {
                        "reload" => cfg.on_new_version = AutoUpdateAction::Reload,
                        "notify" => cfg.on_new_version = AutoUpdateAction::Notify,
                        _ => {
                            return Err(ParseError {
                                line: sub_tok.line,
                                col: sub_tok.col,
                                kind: ParseErrorKind::InvalidValue {
                                    directive: "auto_update.on_new_version".to_string(),
                                    message: format!(
                                        "unknown action '{val}', expected 'reload' or 'notify'"
                                    ),
                                    accepted_format: None,
                                },
                            });
                        }
                    },
                    other => {
                        return Err(ParseError {
                            line: sub_tok.line,
                            col: sub_tok.col,
                            kind: ParseErrorKind::UnknownDirective {
                                name: format!("auto_update.{other}"),
                                suggestion: None,
                            },
                        });
                    }
                }
            }
            _ => {
                t.next_token();
            }
        }
    }

    Ok(cfg)
}

/// Parse "HH:MM-HH:MM" into (`start_minutes_from_midnight`, `end_minutes_from_midnight`).
fn parse_time_window(s: &str) -> Option<(u16, u16)> {
    let (start, end) = s.split_once('-')?;
    let parse_hm = |hm: &str| -> Option<u16> {
        let (h, m) = hm.split_once(':')?;
        let h: u16 = h.parse().ok()?;
        let m: u16 = m.parse().ok()?;
        if h > 23 || m > 59 {
            return None;
        }
        Some(h * 60 + m)
    };
    Some((parse_hm(start)?, parse_hm(end)?))
}

/// Parse the `timeouts { header 10s; body 30s; keepalive 60s; max_requests 1000 }` block.
/// Starts with defaults matching nginx, then overrides with whatever the user specifies.
fn parse_timeouts_block(
    t: &mut Tokenizer<'_>,
    _key_tok: &Token,
) -> Result<TimeoutsConfig, ParseError> {
    let brace = t.peek();
    if brace.kind != TokenKind::OpenBrace {
        return Err(ParseError {
            line: brace.line,
            col: brace.col,
            kind: ParseErrorKind::InvalidValue {
                directive: "timeouts".to_string(),
                message: "expected '{' after 'timeouts'".to_string(),
                accepted_format: None,
            },
        });
    }
    t.next_token();

    let mut cfg = TimeoutsConfig::default();

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
                        expected: "'}' to close timeouts block".to_string(),
                    },
                });
            }
            TokenKind::Word(_) => {
                let sub_tok = t.next_token();
                let sub_key = match &sub_tok.kind {
                    TokenKind::Word(w) => w.clone(),
                    _ => unreachable!(),
                };
                let val = peek_consume_word_or_quoted(t);
                match sub_key.as_str() {
                    "header" => {
                        cfg.header_secs =
                            parse_timeout_duration(&val, "timeouts.header", &sub_tok)?;
                    }
                    "body" => {
                        cfg.body_secs = parse_timeout_duration(&val, "timeouts.body", &sub_tok)?;
                    }
                    "keepalive" => {
                        cfg.keepalive_secs =
                            parse_timeout_duration(&val, "timeouts.keepalive", &sub_tok)?;
                    }
                    "max_requests" => {
                        cfg.max_requests = val.parse::<u32>().map_err(|_| ParseError {
                            line: sub_tok.line,
                            col: sub_tok.col,
                            kind: ParseErrorKind::InvalidValue {
                                directive: "timeouts.max_requests".to_string(),
                                message: format!("'{val}' is not a valid integer"),
                                accepted_format: None,
                            },
                        })?;
                    }
                    other => {
                        return Err(ParseError {
                            line: sub_tok.line,
                            col: sub_tok.col,
                            kind: ParseErrorKind::InvalidValue {
                                directive: "timeouts".to_string(),
                                message: format!(
                                    "unknown timeout key '{other}' — expected header, body, keepalive, or max_requests"
                                ),
                                accepted_format: None,
                            },
                        });
                    }
                }
            }
            _ => {
                t.next_token();
            }
        }
    }

    Ok(cfg)
}

/// Parse the `servers { h3 on }` block inside the global options.
/// Caddy's `servers` block configures listener-level options.
/// Currently we only extract `h3 on` to enable QUIC (ISSUE-079).
fn parse_servers_block(
    t: &mut Tokenizer<'_>,
    opts: &mut GlobalOptions,
    _key_tok: &Token,
) -> Result<(), ParseError> {
    let brace = t.peek();
    if brace.kind != TokenKind::OpenBrace {
        // `servers` without a sub-block — store as passthrough
        let args = collect_global_passthrough_args(t);
        opts.passthrough.push(("servers".to_string(), args));
        return Ok(());
    }
    t.next_token(); // consume `{`

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
                        expected: "'}' to close servers block".to_string(),
                    },
                });
            }
            TokenKind::Word(_) => {
                let sub_tok = t.next_token();
                let sub_key = match &sub_tok.kind {
                    TokenKind::Word(w) => w.clone(),
                    _ => unreachable!(),
                };
                match sub_key.as_str() {
                    "h3" => {
                        let val = peek_consume_word_or_quoted(t);
                        opts.h3_enabled = val.eq_ignore_ascii_case("on");
                    }
                    "listener_wrappers" => {
                        parse_listener_wrappers_block(t, opts, &sub_tok)?;
                    }
                    _ => {
                        // Skip unknown keys inside servers block
                        let _ = collect_global_passthrough_args(t);
                    }
                }
            }
            _ => {
                t.next_token();
            }
        }
    }

    Ok(())
}

/// Parse `listener_wrappers { layer4 { ... } tls }` inside a `servers` block.
///
/// Each `layer4 { ... }` sub-block is parsed as an L4 route set and attached
/// to a synthetic `"*"` listen address (the real address is resolved at compile
/// time from the site block that owns this server).
fn parse_listener_wrappers_block(
    t: &mut Tokenizer<'_>,
    opts: &mut GlobalOptions,
    key_tok: &Token,
) -> Result<(), ParseError> {
    let brace = t.peek();
    if brace.kind != TokenKind::OpenBrace {
        return Err(ParseError {
            line: key_tok.line,
            col: key_tok.col,
            kind: ParseErrorKind::Expected {
                expected: "'{' to open listener_wrappers block".to_string(),
                got: format!("{}", brace.kind),
            },
        });
    }
    t.next_token(); // consume `{`

    loop {
        let tok = t.peek();
        match &tok.kind {
            TokenKind::CloseBrace => {
                t.next_token();
                break;
            }
            TokenKind::Eof => {
                return Err(ParseError {
                    line: key_tok.line,
                    col: key_tok.col,
                    kind: ParseErrorKind::UnexpectedEof {
                        expected: "'}' to close listener_wrappers block".to_string(),
                    },
                });
            }
            TokenKind::Word(w) if w == "layer4" => {
                let l4_tok = t.next_token();
                let route_set = layer4::parse_layer4_route_set(t, &l4_tok)?;
                opts.layer4_listener_wrappers.push(Layer4ListenerWrapper {
                    listen: "*".to_string(),
                    layer4: route_set,
                });
            }
            TokenKind::Word(_) => {
                // Other wrappers (e.g. `tls`) — consume and skip
                t.next_token();
            }
            _ => {
                t.next_token();
            }
        }
    }

    Ok(())
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
                got: format!("{}", addr_tok.kind),
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
                got: format!("{}", brace.kind),
            },
        });
    }

    // Parse matchers and directives until closing brace.
    // Named matchers (`@name`) may appear anywhere before directives that
    // reference them, but we collect them separately for compile-time lookup.
    let mut matchers_vec = Vec::new();
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
                matchers_vec.push(matchers::parse_matcher_def(t)?);
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
                        got: format!("{}", tok.kind),
                    },
                });
            }
        }
    }

    Ok(SiteBlock {
        address,
        matchers: matchers_vec,
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
                    got: format!("{}", name_tok.kind),
                },
            });
        }
    };

    match name.as_str() {
        // ── Routing directives ──────────────────────────────────────────────
        "reverse_proxy" | "proxy" => {
            Ok(Directive::ReverseProxy(directives::parse_reverse_proxy(t)?))
        }
        "redir" => Ok(Directive::Redir(directives::parse_redir(t)?)),
        "rewrite" => Ok(Directive::Rewrite(directives::parse_rewrite(t)?)),
        "uri" => Ok(Directive::Uri(directives::parse_uri(t)?)),
        "respond" => Ok(Directive::Respond(directives::parse_respond(t)?)),
        "handle" => Ok(Directive::Handle(directives::parse_handle(t)?)),
        "handle_path" => Ok(Directive::HandlePath(directives::parse_handle_path(t)?)),
        "handle_errors" => Ok(Directive::HandleErrors(directives::parse_handle_errors(
            t, &name_tok,
        )?)),
        "route" => Ok(Directive::Route(directives::parse_route(t)?)),
        "root" => Ok(Directive::Root(directives::parse_root(t)?)),
        "file_server" => Ok(Directive::FileServer(directives::parse_file_server(t))),
        "php_fastcgi" => Ok(Directive::PhpFastcgi(directives::parse_php_fastcgi(t)?)),
        "forward_auth" => Ok(Directive::ForwardAuth(directives::parse_forward_auth(t)?)),
        "try_files" => Ok(Directive::TryFiles(directives::parse_try_files(t)?)),

        // ── Transformation directives ───────────────────────────────────────
        "error" => Ok(Directive::Error(transforms::parse_error_directive(t))),
        "tls" => Ok(Directive::Tls(transforms::parse_tls(t)?)),
        "header" => Ok(Directive::Header(transforms::parse_header(t)?)),
        "request_header" => Ok(Directive::RequestHeader(transforms::parse_request_header(
            t,
        )?)),
        "encode" => Ok(Directive::Encode(transforms::parse_encode(t)?)),
        "basicauth" | "basic_auth" => Ok(Directive::BasicAuth(transforms::parse_basicauth(t)?)),
        "rate_limit" => Ok(Directive::RateLimit(transforms::parse_rate_limit(t)?)),
        "ip_filter" => Ok(Directive::IpFilter(transforms::parse_ip_filter(
            t, &name_tok,
        )?)),
        "method" => Ok(Directive::Method(transforms::parse_method(t, &name_tok)?)),
        "request_body" => Ok(Directive::RequestBody(transforms::parse_request_body(
            t, &name_tok,
        )?)),
        "response_body_limit" => Ok(Directive::ResponseBodyLimit(
            transforms::parse_response_body_limit(t, &name_tok)?,
        )),
        "bind" => Ok(Directive::Bind(transforms::parse_bind(t, &name_tok)?)),
        "vars" => Ok(Directive::Vars(transforms::parse_vars(t, &name_tok)?)),

        // ── Observability & data directives ─────────────────────────────────
        "log" => Ok(Directive::Log(observe::parse_log(t)?)),
        "log_append" => Ok(Directive::LogAppend(observe::parse_log_append(
            t, &name_tok,
        )?)),
        "log_name" => Ok(Directive::LogName(observe::parse_log_name(t)?)),
        "metrics" => Ok(Directive::Metrics(observe::parse_metrics(t))),
        "cache" => Ok(Directive::Cache(transforms::parse_cache(t, &name_tok)?)),
        "tracing" => Ok(Directive::Tracing(observe::parse_tracing(t))),
        "map" => Ok(Directive::Map(observe::parse_map(t, &name_tok)?)),
        "invoke" => Ok(Directive::Invoke(observe::parse_invoke(t)?)),
        "fs" => Ok(Directive::Fs(observe::parse_fs(t, &name_tok))),
        "templates" => Ok(Directive::Templates(observe::parse_recognized(t))),
        "push" => Ok(Directive::Push(observe::parse_recognized(t))),
        "acme_server" => Ok(Directive::AcmeServer(observe::parse_recognized(t))),
        "intercept" => Ok(Directive::Intercept(observe::parse_intercept(
            t, &name_tok,
        )?)),
        "copy_response" => Ok(Directive::CopyResponse(observe::parse_copy_response(t))),
        "copy_response_headers" => Ok(Directive::CopyResponseHeaders(
            observe::parse_copy_response_headers(t, &name_tok)?,
        )),

        // ── WASM plugins ────────────────────────────────────────────────────
        "wasm_plugin" => Ok(Directive::WasmPlugin(directives::parse_wasm_plugin(t)?)),

        // ── Simple flags ────────────────────────────────────────────────────
        "abort" => Ok(Directive::Abort),
        "skip_log" | "log_skip" => Ok(Directive::SkipLog),
        "grpc" => Ok(Directive::Grpc),

        // import directives are expanded by the preprocessor before parsing.
        // If one reaches here, the preprocessor missed it — that's a bug.
        "import" => Err(ParseError {
            line: name_tok.line,
            col: name_tok.col,
            kind: ParseErrorKind::Other(
                "import directive was not expanded by preprocessor — this is a bug".to_string(),
            ),
        }),

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
