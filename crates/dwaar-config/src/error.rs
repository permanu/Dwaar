// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Parse errors with line numbers and suggestions.
//!
//! Every error includes the exact location in the Dwaarfile and a
//! human-readable message. Suggestions help users fix typos.

use std::fmt;

/// A parse error with source location and helpful context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// 1-based line number where the error occurred.
    pub line: usize,
    /// 1-based column number.
    pub col: usize,
    /// What went wrong.
    pub kind: ParseErrorKind,
}

/// The specific type of parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// Expected a specific token but got something else.
    Expected { expected: String, got: String },
    /// Directive name not recognized.
    UnknownDirective {
        name: String,
        suggestion: Option<String>,
    },
    /// A directive that's valid Caddyfile but not yet implemented.
    UnsupportedDirective {
        name: String,
        tracking_issue: Option<String>,
    },
    /// Invalid value for a directive argument.
    InvalidValue { directive: String, message: String },
    /// Unexpected end of input.
    UnexpectedEof { expected: String },
    /// Generic error for anything else.
    Other(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Dwaarfile:{}:{}: ", self.line, self.col)?;
        match &self.kind {
            ParseErrorKind::Expected { expected, got } => {
                write!(f, "expected {expected}, got {got}")
            }
            ParseErrorKind::UnknownDirective { name, suggestion } => {
                write!(f, "unknown directive '{name}'")?;
                if let Some(s) = suggestion {
                    write!(f, " — did you mean '{s}'?")?;
                }
                Ok(())
            }
            ParseErrorKind::UnsupportedDirective {
                name,
                tracking_issue,
            } => {
                write!(f, "directive '{name}' is not yet supported")?;
                if let Some(issue) = tracking_issue {
                    write!(f, " — tracking issue: {issue}")?;
                }
                Ok(())
            }
            ParseErrorKind::InvalidValue { directive, message } => {
                write!(f, "invalid value for '{directive}': {message}")
            }
            ParseErrorKind::UnexpectedEof { expected } => {
                write!(f, "unexpected end of file, expected {expected}")
            }
            ParseErrorKind::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<crate::import::ImportError> for ParseError {
    fn from(err: crate::import::ImportError) -> Self {
        Self {
            line: 0,
            col: 0,
            kind: ParseErrorKind::Other(format!("import error: {err}")),
        }
    }
}

/// Suggest a known directive name for a typo.
///
/// Uses simple edit distance — if a known directive is within 2
/// edits of the input, suggest it.
pub fn suggest_directive(input: &str) -> Option<&'static str> {
    const KNOWN: &[&str] = &[
        // Implemented
        "reverse_proxy",
        "tls",
        "header",
        "redir",
        "encode",
        "rate_limit",
        "basicauth",
        "basic_auth",
        "forward_auth",
        "file_server",
        "rewrite",
        "uri",
        "handle",
        "handle_path",
        "route",
        "respond",
        "import",
        "php_fastcgi",
        "root",
        // Passthrough (valid Caddyfile directives)
        "log",
        "bind",
        "abort",
        "error",
        "metrics",
        "templates",
        "request_body",
        "response_body_limit",
        "request_header",
        "method",
        "try_files",
        "tracing",
        "vars",
        "map",
        "skip_log",
        "log_skip",
        "push",
        "acme_server",
        "handle_errors",
        "invoke",
        "intercept",
        "log_append",
        "log_name",
        "fs",
        "copy_response",
        "copy_response_headers",
    ];

    KNOWN
        .iter()
        .filter(|&&known| edit_distance(input, known) <= 2)
        .min_by_key(|&&known| edit_distance(input, known))
        .copied()
}

/// Levenshtein edit distance between two strings.
fn edit_distance(a: &str, b: &str) -> usize {
    // Short-circuit for inputs longer than any known directive name
    if a.len() > 64 || b.len() > 64 {
        return usize::MAX;
    }

    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());

    let mut prev = (0..=n).collect::<Vec<_>>();
    let mut curr = vec![0; n + 1];

    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[n]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_with_line_numbers() {
        let err = ParseError {
            line: 5,
            col: 3,
            kind: ParseErrorKind::UnknownDirective {
                name: "prxy".to_string(),
                suggestion: Some("reverse_proxy".to_string()),
            },
        };
        assert_eq!(
            err.to_string(),
            "Dwaarfile:5:3: unknown directive 'prxy' — did you mean 'reverse_proxy'?"
        );
    }

    #[test]
    fn error_display_expected() {
        let err = ParseError {
            line: 3,
            col: 1,
            kind: ParseErrorKind::Expected {
                expected: "'{'".to_string(),
                got: "'proxy'".to_string(),
            },
        };
        assert_eq!(err.to_string(), "Dwaarfile:3:1: expected '{', got 'proxy'");
    }

    #[test]
    fn error_display_unsupported_directive() {
        let err = ParseError {
            line: 7,
            col: 5,
            kind: ParseErrorKind::UnsupportedDirective {
                name: "php_fastcgi".to_string(),
                tracking_issue: Some("ISSUE-053".to_string()),
            },
        };
        assert_eq!(
            err.to_string(),
            "Dwaarfile:7:5: directive 'php_fastcgi' is not yet supported — tracking issue: ISSUE-053"
        );
    }

    #[test]
    fn suggest_typo_correction() {
        assert_eq!(suggest_directive("reverse_proxi"), Some("reverse_proxy"));
        assert_eq!(suggest_directive("reerse_proxy"), Some("reverse_proxy"));
        assert_eq!(suggest_directive("tsl"), Some("tls"));
        assert_eq!(suggest_directive("headr"), Some("header"));
        assert_eq!(suggest_directive("encod"), Some("encode"));
    }

    #[test]
    fn suggest_rate_limit_typo() {
        assert_eq!(suggest_directive("rate_limt"), Some("rate_limit"));
    }

    #[test]
    fn no_suggestion_for_garbage() {
        assert_eq!(suggest_directive("xyzzy_foobar"), None);
    }

    #[test]
    fn edit_distance_basic() {
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("abc", "abc"), 0);
        assert_eq!(edit_distance("tls", "tsl"), 2);
    }
}
