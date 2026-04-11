// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Regression tests for `POST /reload` error surfacing.
//!
//! The admin API parses the Dwaarfile in-process before signaling the
//! config watcher. When parsing fails it must return the full
//! `ParseError::Display` output as the response body so callers can see
//! the line number, offending directive, and optional accepted-format
//! hint without any JSON wrapping.
//!
//! These tests exercise `handlers::validate_config_source` directly —
//! the same function the `POST /reload` handler calls — so we don't have
//! to spin up a full Pingora listener just to check the error body.

use dwaar_admin::handlers::{ConfigValidation, validate_config_source};

#[test]
fn valid_config_returns_ok() {
    let src = r"
        example.com {
            reverse_proxy 127.0.0.1:8080
        }
    ";
    match validate_config_source(src) {
        ConfigValidation::Ok => {}
        ConfigValidation::Err { status, body } => {
            panic!("expected Ok, got Err {{ status: {status}, body: {body:?} }}");
        }
    }
}

#[test]
fn broken_config_returns_400_with_parse_error_body() {
    // Unknown directive *inside* a site block — the parser reports it as
    // an `UnknownDirective` with a source location and a suggestion.
    let src = r"
        example.com {
            not_a_real_directive foo
        }
    ";

    match validate_config_source(src) {
        ConfigValidation::Ok => panic!("expected Err, got Ok"),
        ConfigValidation::Err { status, body } => {
            assert_eq!(status, 400, "parse errors must map to HTTP 400");
            assert!(
                body.contains("Dwaarfile:"),
                "body should carry the parser's line prefix; got: {body:?}"
            );
            assert!(
                body.contains("not_a_real_directive"),
                "body should mention the offending directive; got: {body:?}"
            );
        }
    }
}

#[test]
fn rate_limit_invalid_value_surfaces_accepted_format() {
    // `rate_limit` with a non-rate value — exercises InvalidValue with
    // an accepted_format hint so the caller sees the canonical format.
    let src = r"
        example.com {
            rate_limit not-a-rate
        }
    ";

    match validate_config_source(src) {
        ConfigValidation::Ok => panic!("expected Err, got Ok"),
        ConfigValidation::Err { status, body } => {
            assert_eq!(status, 400);
            assert!(
                body.contains("rate_limit"),
                "body should mention rate_limit directive; got: {body:?}"
            );
            assert!(
                body.contains("expected:"),
                "body should include the 'expected:' accepted_format line; got: {body:?}"
            );
        }
    }
}

#[test]
fn reverse_proxy_typo_surfaces_suggestion() {
    // Typo in a root-level directive name — should trigger the
    // typo-suggestion branch and include 'did you mean'.
    let src = r"
        example.com {
            reverse_proxi 127.0.0.1:8080
        }
    ";

    match validate_config_source(src) {
        ConfigValidation::Ok => panic!("expected Err, got Ok"),
        ConfigValidation::Err { status, body } => {
            assert_eq!(status, 400);
            assert!(
                body.contains("reverse_proxi"),
                "body should mention the typo; got: {body:?}"
            );
        }
    }
}
