// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Text preprocessor for `import` directives and snippet expansion.
//!
//! Runs **before** tokenization — the parser never sees `import` or
//! snippet definitions. This keeps the parser grammar simple while
//! supporting Caddy-compatible snippet and file import syntax.
//!
//! ## Security
//!
//! File imports are path-traversal hardened: paths are canonicalized
//! and must remain within `base_dir`. Any `..` component is rejected
//! outright before we even touch the filesystem.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::Path;

/// Hard ceiling on recursive expansion to prevent infinite loops.
const MAX_DEPTH: usize = 10;

/// Errors that can occur during import/snippet expansion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// A snippet or file imports itself (directly or transitively).
    CircularImport(String),
    /// Recursive expansion exceeded `MAX_DEPTH` levels.
    DepthLimitExceeded,
    /// File import target does not exist.
    FileNotFound(String),
    /// File import attempted to escape `base_dir` (Guardrail #17).
    PathTraversal(String),
    /// Malformed snippet definition.
    InvalidSnippet { line: usize, message: String },
    /// An IO error while reading an imported file.
    IoError(String),
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CircularImport(name) => write!(f, "circular import detected: '{name}'"),
            Self::DepthLimitExceeded => write!(
                f,
                "import depth limit exceeded (max {MAX_DEPTH} levels of nesting)"
            ),
            Self::FileNotFound(path) => write!(f, "imported file not found: '{path}'"),
            Self::PathTraversal(path) => {
                write!(f, "path traversal blocked: '{path}' escapes base directory")
            }
            Self::InvalidSnippet { line, message } => {
                write!(f, "invalid snippet at line {line}: {message}")
            }
            Self::IoError(msg) => write!(f, "import IO error: {msg}"),
        }
    }
}

impl std::error::Error for ImportError {}

/// A named snippet extracted from the input.
struct Snippet {
    name: String,
    body: String,
}

/// Expand all `import` directives and snippet definitions in `input`.
///
/// Snippet definitions `(name) { ... }` are extracted first, then
/// `import <name> [args...]` lines are substituted with snippet bodies
/// or file contents. Recursion is bounded by `MAX_DEPTH`.
pub fn expand_imports(input: &str, base_dir: &Path) -> Result<String, ImportError> {
    // Extract snippets once from the top-level input; they're available
    // to all nested expansions (matching Caddy's behavior).
    let (snippets, remaining) = extract_snippets(input)?;
    let mut visited = HashSet::new();
    expand_recursive(&remaining, base_dir, &snippets, 0, &mut visited)
}

fn expand_recursive(
    input: &str,
    base_dir: &Path,
    snippets: &[Snippet],
    depth: usize,
    visited: &mut HashSet<String>,
) -> Result<String, ImportError> {
    if depth > MAX_DEPTH {
        return Err(ImportError::DepthLimitExceeded);
    }

    // Any additional snippet definitions in nested content are also extracted
    let (local_snippets, remaining) = extract_snippets(input)?;

    let mut output = String::with_capacity(remaining.len());
    for line in remaining.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("import ") {
            let rest = rest.trim();
            if rest.is_empty() {
                output.push_str(line);
                output.push('\n');
                continue;
            }

            let parts = split_import_args(rest);
            let name = &parts[0];
            let args: Vec<&str> = parts[1..].iter().map(String::as_str).collect();

            // Check local snippets first, then top-level snippets
            let snippet = local_snippets
                .iter()
                .chain(snippets.iter())
                .find(|s| s.name == *name);

            if let Some(snippet) = snippet {
                let key = format!("snippet:{name}");
                if !visited.insert(key.clone()) {
                    return Err(ImportError::CircularImport(name.clone()));
                }

                let body = substitute_args(&snippet.body, &args);
                let expanded = expand_recursive(&body, base_dir, snippets, depth + 1, visited)?;
                output.push_str(&expanded);
                if !expanded.ends_with('\n') {
                    output.push('\n');
                }

                visited.remove(&key);
            } else if looks_like_file_path(name) {
                let key = format!("file:{name}");
                if !visited.insert(key.clone()) {
                    return Err(ImportError::CircularImport(name.clone()));
                }

                let content = read_import_file(name, base_dir)?;
                let body = substitute_args(&content, &args);
                let expanded = expand_recursive(&body, base_dir, snippets, depth + 1, visited)?;
                output.push_str(&expanded);
                if !expanded.ends_with('\n') {
                    output.push('\n');
                }

                visited.remove(&key);
            } else {
                // Unknown name — not a snippet, not a file path
                return Err(ImportError::FileNotFound(name.clone()));
            }
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }

    Ok(output)
}

/// Extract top-level `(name) { ... }` snippet definitions.
///
/// Returns the snippets and the input with snippet blocks removed.
/// Only matches snippets at the top level (not nested inside site blocks).
fn extract_snippets(input: &str) -> Result<(Vec<Snippet>, String), ImportError> {
    let mut snippets = Vec::new();
    let mut remaining = String::with_capacity(input.len());
    let lines: Vec<&str> = input.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();

        // Check for `(name) {` pattern
        if let Some(name) = parse_snippet_header(trimmed) {
            let start_line = i + 1; // 1-based for error messages

            // Collect the body until we find the matching `}`
            let mut body = String::new();
            let mut brace_depth: usize = 1;
            i += 1;

            while i < lines.len() {
                let line_trimmed = lines[i].trim();

                // Track nested braces inside snippets
                for ch in line_trimmed.chars() {
                    match ch {
                        '{' => brace_depth += 1,
                        '}' => brace_depth -= 1,
                        _ => {}
                    }
                }

                if brace_depth == 0 {
                    // This line has the closing `}` — don't include it
                    i += 1;
                    break;
                }

                body.push_str(lines[i]);
                body.push('\n');
                i += 1;
            }

            if brace_depth != 0 {
                return Err(ImportError::InvalidSnippet {
                    line: start_line,
                    message: format!("unclosed snippet '({name})'"),
                });
            }

            snippets.push(Snippet { name, body });
        } else {
            remaining.push_str(lines[i]);
            remaining.push('\n');
            i += 1;
        }
    }

    Ok((snippets, remaining))
}

/// Try to parse a line as `(name) {` — returns the name if it matches.
fn parse_snippet_header(line: &str) -> Option<String> {
    let line = line.trim();
    if !line.starts_with('(') {
        return None;
    }

    let close_paren = line.find(')')?;
    let name = line[1..close_paren].trim();
    if name.is_empty() {
        return None;
    }

    // After `)` we expect optional whitespace then `{`
    let after = line[close_paren + 1..].trim();
    if after == "{" {
        Some(name.to_string())
    } else {
        None
    }
}

/// Split import arguments respecting quoted strings.
fn split_import_args(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    for ch in chars.by_ref() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        parts.push(current);
    }

    parts
}

/// Replace `{args[N]}` and `{args[:]}` placeholders with actual values.
fn substitute_args(body: &str, args: &[&str]) -> String {
    let mut result = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '{' {
            // Try to parse an args placeholder
            let mut placeholder = String::new();
            let mut found_close = false;

            for ch in chars.by_ref() {
                if ch == '}' {
                    found_close = true;
                    break;
                }
                placeholder.push(ch);
            }

            if found_close {
                if let Some(replacement) = resolve_placeholder(&placeholder, args) {
                    result.push_str(&replacement);
                } else {
                    // Not a recognized placeholder — preserve literally
                    result.push('{');
                    result.push_str(&placeholder);
                    result.push('}');
                }
            } else {
                // Unclosed brace — preserve literally
                result.push('{');
                result.push_str(&placeholder);
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Resolve a single placeholder like `args[0]`, `args[1]`, or `args[:]`.
fn resolve_placeholder(placeholder: &str, args: &[&str]) -> Option<String> {
    let inner = placeholder.strip_prefix("args[")?;
    let inner = inner.strip_suffix(']')?;

    if inner == ":" {
        // All args joined by space
        return Some(args.join(" "));
    }

    let idx: usize = inner.parse().ok()?;
    args.get(idx).map(|s| (*s).to_string())
}

/// Heuristic: does this name look like a file path?
fn looks_like_file_path(name: &str) -> bool {
    name.contains('/') || name.contains('.')
}

/// Read a file for import, enforcing path-traversal security.
fn read_import_file(name: &str, base_dir: &Path) -> Result<String, ImportError> {
    // Reject `..` before any filesystem access (belt-and-suspenders with canonicalize)
    if name.contains("..") {
        return Err(ImportError::PathTraversal(name.to_string()));
    }

    let target = base_dir.join(name);

    // Canonicalize both paths to resolve symlinks and check containment
    let canon_base = base_dir
        .canonicalize()
        .map_err(|e| ImportError::IoError(format!("cannot resolve base dir: {e}")))?;

    let canon_target = target
        .canonicalize()
        .map_err(|_| ImportError::FileNotFound(name.to_string()))?;

    if !canon_target.starts_with(&canon_base) {
        return Err(ImportError::PathTraversal(name.to_string()));
    }

    fs::read_to_string(&canon_target).map_err(|_| ImportError::FileNotFound(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;
    use std::fs;
    use tempfile::TempDir;

    // ── Snippet expansion ────────────────────────────────

    #[test]
    fn snippet_expansion_works() {
        let input = "\
(common) {
    encode gzip
    header -Server
}

example.com {
    import common
    reverse_proxy localhost:8080
}
";
        let result = expand_imports(input, Path::new(".")).expect("should expand");
        assert!(result.contains("encode gzip"));
        assert!(result.contains("header -Server"));
        // Snippet definition should be removed
        assert!(!result.contains("(common)"));
    }

    #[test]
    fn file_import_works() {
        let dir = TempDir::new().expect("tempdir");
        let snippet_path = dir.path().join("headers.conf");
        fs::write(&snippet_path, "header -Server\nheader X-Powered-By Dwaar\n")
            .expect("write file");

        let input = "\
example.com {
    import headers.conf
    reverse_proxy localhost:8080
}
";
        let result = expand_imports(input, dir.path()).expect("should expand");
        assert!(result.contains("header -Server"));
        assert!(result.contains("header X-Powered-By Dwaar"));
    }

    #[test]
    fn positional_args_substituted() {
        let input = "\
(backend) {
    reverse_proxy {args[0]}
    header X-Backend {args[1]}
}

example.com {
    import backend localhost:8080 api
}
";
        let result = expand_imports(input, Path::new(".")).expect("should expand");
        assert!(result.contains("reverse_proxy localhost:8080"));
        assert!(result.contains("header X-Backend api"));
    }

    #[test]
    fn args_splat_substitution() {
        let input = "\
(multi) {
    reverse_proxy {args[:]}
}

example.com {
    import multi localhost:3000 localhost:3001
}
";
        let result = expand_imports(input, Path::new(".")).expect("should expand");
        assert!(result.contains("reverse_proxy localhost:3000 localhost:3001"));
    }

    #[test]
    fn circular_import_detected() {
        let input = "\
(a) {
    import a
}

example.com {
    import a
}
";
        let err = expand_imports(input, Path::new(".")).expect_err("should fail");
        assert!(matches!(err, ImportError::CircularImport(_)));
    }

    #[test]
    fn depth_limit_enforced() {
        // Each snippet imports the next, creating a chain deeper than MAX_DEPTH
        let mut input = String::new();
        for i in 0..=MAX_DEPTH + 1 {
            let _ = write!(input, "(s{i}) {{\n    import s{}\n}}\n\n", i + 1);
        }
        // Terminal snippet
        let _ = write!(input, "(s{}) {{\n    encode gzip\n}}\n\n", MAX_DEPTH + 3);
        input.push_str("example.com {\n    import s0\n}\n");

        let err = expand_imports(&input, Path::new(".")).expect_err("should fail");
        assert!(matches!(err, ImportError::DepthLimitExceeded));
    }

    #[test]
    fn path_traversal_rejected() {
        let dir = TempDir::new().expect("tempdir");
        let input = "\
example.com {
    import ../../../etc/passwd
}
";
        let err = expand_imports(input, dir.path()).expect_err("should fail");
        assert!(matches!(err, ImportError::PathTraversal(_)));
    }

    #[test]
    fn unknown_snippet_returns_error() {
        let input = "\
example.com {
    import nonexistent_snippet
}
";
        // "nonexistent_snippet" has no `/` or `.`, so it falls through to FileNotFound
        let err = expand_imports(input, Path::new(".")).expect_err("should fail");
        assert!(matches!(err, ImportError::FileNotFound(_)));
    }

    #[test]
    fn empty_snippet_works() {
        let input = "\
(empty) {
}

example.com {
    import empty
    reverse_proxy localhost:8080
}
";
        let result = expand_imports(input, Path::new(".")).expect("should expand");
        assert!(result.contains("reverse_proxy localhost:8080"));
        assert!(!result.contains("(empty)"));
    }

    #[test]
    fn multiple_snippets_in_one_file() {
        let input = "\
(headers) {
    header -Server
}

(encoding) {
    encode gzip
}

example.com {
    import headers
    import encoding
    reverse_proxy localhost:8080
}
";
        let result = expand_imports(input, Path::new(".")).expect("should expand");
        assert!(result.contains("header -Server"));
        assert!(result.contains("encode gzip"));
        assert!(result.contains("reverse_proxy localhost:8080"));
    }

    #[test]
    fn nested_snippet_braces_handled() {
        // Snippets can contain nested braces (e.g., sub-blocks)
        let input = "\
(logging) {
    log {
        output file /var/log/access.log
    }
}

example.com {
    import logging
    reverse_proxy localhost:8080
}
";
        let result = expand_imports(input, Path::new(".")).expect("should expand");
        assert!(result.contains("output file /var/log/access.log"));
    }

    #[test]
    fn file_import_with_args() {
        let dir = TempDir::new().expect("tempdir");
        let snippet_path = dir.path().join("backend.conf");
        fs::write(&snippet_path, "reverse_proxy {args[0]}\n").expect("write file");

        let input = "\
example.com {
    import backend.conf localhost:9000
}
";
        let result = expand_imports(input, dir.path()).expect("should expand");
        assert!(result.contains("reverse_proxy localhost:9000"));
    }

    #[test]
    fn path_traversal_symlink_rejected() {
        let dir = TempDir::new().expect("tempdir");
        // Even without `..`, a symlink escaping base_dir should be caught
        // by the canonicalize + starts_with check. We test the `..` path
        // since creating cross-boundary symlinks reliably is platform-specific.
        let input = "example.com {\n    import sub/../../../etc/passwd\n}\n";
        let err = expand_imports(input, dir.path()).expect_err("should fail");
        assert!(matches!(err, ImportError::PathTraversal(_)));
    }
}
