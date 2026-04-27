// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Static file server — serves files from disk for the `file_server` directive.
//!
//! ## Security (Guardrail #17 — all client input is adversarial)
//!
//! - Path traversal: canonicalize + `starts_with` check rejects `../`, symlinks outside root
//! - Null bytes: rejected before filesystem access
//! - Dotfiles: hidden by default (`.env`, `.htpasswd`, etc.)
//! - MIME type: derived from extension only, never from client input

use std::path::{Component, Path};
use std::time::SystemTime;

use bytes::Bytes;

/// Cheap lexical check: does `candidate` stay within `root` after resolving
/// `.` and `..`? Catches obvious traversal without a syscall.
/// Symlink-based escapes still need `canonicalize()`.
fn lexically_within(candidate: &Path, root: &Path) -> bool {
    // Walk components after the root prefix. If `..` ever takes us
    // above the root level, it's a traversal attempt.
    let Ok(suffix) = candidate.strip_prefix(root) else {
        return false;
    };
    let mut depth: i32 = 0;
    for component in suffix.components() {
        match component {
            Component::ParentDir => depth -= 1,
            Component::Normal(_) => depth += 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
    }
    true
}

/// Result of resolving a file request.
#[derive(Debug)]
pub enum FileResponse {
    /// File found — ready to serve.
    Found {
        body: Bytes,
        content_type: &'static str,
        content_length: usize,
        last_modified: Option<SystemTime>,
        etag: Option<String>,
    },
    /// Directory listing HTML.
    DirectoryListing { body: Bytes },
    /// File not found — let the next handler try.
    NotFound,
    /// Path traversal or other security rejection.
    Forbidden,
}

/// File extensions that are obviously assets, not client-side routes.
/// Requests with these extensions never trigger SPA fallback — otherwise a
/// missing JS chunk would silently return `index.html`, which browsers and
/// build tools would then try to execute as JavaScript and produce confusing
/// MIME-type or syntax errors. Keep this list conservative: better to skip
/// fallback for a few odd routes than to corrupt asset resolution.
const ASSET_EXTENSIONS: &[&str] = &[
    "js", "mjs", "cjs", "css", "map", "wasm", "woff", "woff2", "ttf", "otf", "eot", "svg", "png",
    "jpg", "jpeg", "gif", "webp", "avif", "ico", "json", "txt", "xml", "pdf", "zip", "gz", "br",
    "mp3", "mp4", "webm", "ogg", "wav",
];

/// Returns true when `request_path` ends with an extension we consider a
/// static asset (and therefore should NOT fall back to `index.html` on 404).
fn is_asset_extension(request_path: &str) -> bool {
    // Strip query string and fragment if present (defensive — proxy normally
    // hands us a path-only string, but be safe).
    let no_query = request_path
        .split_once('?')
        .map_or(request_path, |(p, _)| p);
    let path = no_query.split_once('#').map_or(no_query, |(p, _)| p);

    let last_segment = path.rsplit('/').next().unwrap_or("");
    let Some((_, ext)) = last_segment.rsplit_once('.') else {
        return false;
    };
    let ext_lower = ext.to_ascii_lowercase();
    ASSET_EXTENSIONS.iter().any(|e| *e == ext_lower)
}

/// Resolve a request path to a file response.
///
/// `root`: the configured filesystem root (already canonicalized at compile time).
/// `request_path`: the URL path from the client (e.g., `/css/style.css`).
/// `browse`: whether directory listing is enabled.
/// `fallback`: optional SPA fallback path (already canonicalized inside `root`
///   at compile time). When set, a request that would otherwise return
///   `NotFound` and is not an asset-shaped path will be retried with this
///   file. Used for client-routed apps (`SvelteKit`, React Router, Vue Router).
/// `method`: HTTP method (only `GET`/`HEAD` trigger fallback).
pub async fn serve_file(
    root: &Path,
    request_path: &str,
    browse: bool,
    fallback: Option<&Path>,
    method: &str,
) -> FileResponse {
    let primary = serve_file_inner(root, request_path, browse).await;

    // Fast path: anything other than NotFound (or NotFound without a configured
    // fallback) returns immediately. Preserves backwards compat exactly.
    let FileResponse::NotFound = primary else {
        return primary;
    };
    let Some(fallback_path) = fallback else {
        return FileResponse::NotFound;
    };

    // Method gating: fallback is a GET-shaped recovery, not a generic retry.
    if !matches!(method, "GET" | "HEAD") {
        return FileResponse::NotFound;
    }

    // Don't rewrite missing assets to index.html — see ASSET_EXTENSIONS rationale.
    if is_asset_extension(request_path) {
        return FileResponse::NotFound;
    }

    // Dotfile gate is enforced inside serve_file_inner already; if the original
    // request was a dotfile we've returned Forbidden above (not NotFound) and
    // never reach this branch.

    // Defense-in-depth: re-verify the fallback path is contained in root.
    // compile.rs guarantees this, but a runtime check is cheap.
    if !fallback_path.starts_with(root) {
        return FileResponse::NotFound;
    }

    let fallback_owned = fallback_path.to_path_buf();
    let is_file = tokio::task::spawn_blocking(move || fallback_owned.is_file())
        .await
        .unwrap_or(false);
    if !is_file {
        return FileResponse::NotFound;
    }

    tracing::debug!(
        from = %request_path,
        to = %fallback_path.display(),
        "serve_file: SPA fallback engaged"
    );
    read_file(fallback_path).await
}

/// Inner resolver — original `serve_file` logic without the fallback layer.
/// Kept as a separate function so the fallback wrapper can call it twice
/// without re-implementing path validation.
async fn serve_file_inner(root: &Path, request_path: &str, browse: bool) -> FileResponse {
    // Reject null bytes before any filesystem access
    if request_path.contains('\0') {
        return FileResponse::Forbidden;
    }

    // Strip leading slash and decode percent-encoding basics
    let clean_path = request_path.trim_start_matches('/');

    // Reject dotfiles (hidden files like .env, .htpasswd)
    if clean_path
        .split('/')
        .any(|segment| segment.starts_with('.') && segment != ".")
    {
        return FileResponse::Forbidden;
    }

    // Root is pre-canonicalized at config compile time (see compile.rs).
    let canonical_root = root;

    // Build the candidate path. First do a cheap lexical traversal check —
    // if the normalized components escape the root, reject without a syscall.
    let candidate = canonical_root.join(clean_path);
    if !lexically_within(&candidate, canonical_root) {
        return FileResponse::Forbidden;
    }

    // Canonicalize to resolve symlinks that could escape the root.
    // This is the only per-request syscall and can't be skipped — a
    // symlink inside the root could point anywhere.
    let candidate_owned = candidate.clone();
    let Ok(resolved) = tokio::task::spawn_blocking(move || candidate_owned.canonicalize())
        .await
        .unwrap_or_else(|_| Err(std::io::Error::other("spawn_blocking panicked")))
    else {
        return FileResponse::NotFound;
    };

    // Final security check after symlink resolution.
    if !resolved.starts_with(canonical_root) {
        return FileResponse::Forbidden;
    }

    let resolved_for_is_dir = resolved.clone();
    let is_dir = tokio::task::spawn_blocking(move || resolved_for_is_dir.is_dir())
        .await
        .unwrap_or(false);

    if is_dir {
        // Try index files
        for index in &["index.html", "index.txt"] {
            let index_path = resolved.join(index);
            let index_path_owned = index_path.clone();
            let is_file = tokio::task::spawn_blocking(move || index_path_owned.is_file())
                .await
                .unwrap_or(false);
            if is_file {
                return read_file(&index_path).await;
            }
        }
        if browse {
            return generate_directory_listing(&resolved, request_path).await;
        }
        return FileResponse::NotFound;
    }

    let resolved_for_is_file = resolved.clone();
    let is_file = tokio::task::spawn_blocking(move || resolved_for_is_file.is_file())
        .await
        .unwrap_or(false);

    if is_file {
        // Check for precompressed variants
        // (caller would need Accept-Encoding — for now serve the original)
        return read_file(&resolved).await;
    }

    FileResponse::NotFound
}

async fn read_file(path: &Path) -> FileResponse {
    let content_type = mime_type_for_path(path);

    let path_owned = path.to_path_buf();
    let result = tokio::task::spawn_blocking(move || {
        let metadata = std::fs::metadata(&path_owned)?;
        let data = std::fs::read(&path_owned)?;
        Ok::<_, std::io::Error>((metadata, data))
    })
    .await
    .unwrap_or_else(|_| Err(std::io::Error::other("spawn_blocking panicked")));

    let Ok((metadata, data)) = result else {
        return FileResponse::NotFound;
    };

    let body = Bytes::from(data);
    let last_modified = metadata.modified().ok();
    let etag = last_modified.map(|lm| {
        let duration = lm
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        format!("\"{}{}\"", duration.as_secs(), metadata.len())
    });

    FileResponse::Found {
        content_length: body.len(),
        body,
        content_type,
        last_modified,
        etag,
    }
}

async fn generate_directory_listing(dir: &Path, request_path: &str) -> FileResponse {
    use std::fmt::Write;

    let dir_owned = dir.to_path_buf();
    let items_result = tokio::task::spawn_blocking(move || {
        let mut items: Vec<(String, bool)> = Vec::new();
        let entries = std::fs::read_dir(&dir_owned)?;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            let is_dir = entry.file_type().is_ok_and(|ft| ft.is_dir());
            items.push((name, is_dir));
        }
        items.sort_by(|a, b| a.0.cmp(&b.0));
        Ok::<_, std::io::Error>(items)
    })
    .await
    .unwrap_or_else(|_| Err(std::io::Error::other("spawn_blocking panicked")));

    let items = items_result.unwrap_or_default();

    let mut html = String::with_capacity(4096);
    html.push_str("<!DOCTYPE html><html><head><meta charset=\"utf-8\">");
    html.push_str("<title>Index of ");
    html.push_str(&html_escape(request_path));
    html.push_str(
        "</title><style>body{font-family:monospace;margin:2em}a{text-decoration:none}</style>",
    );
    html.push_str("</head><body><h1>Index of ");
    html.push_str(&html_escape(request_path));
    html.push_str("</h1><hr><pre>\n");

    // Parent directory link
    if request_path != "/" {
        html.push_str("<a href=\"../\">../</a>\n");
    }

    for (name, is_dir) in &items {
        let escaped = html_escape(name);
        let display = if *is_dir {
            format!("{escaped}/")
        } else {
            escaped.clone()
        };
        let href = if *is_dir {
            format!("{escaped}/")
        } else {
            escaped
        };
        let _ = writeln!(html, "<a href=\"{href}\">{display}</a>");
    }

    html.push_str("</pre><hr></body></html>");
    FileResponse::DirectoryListing {
        body: Bytes::from(html),
    }
}

/// Map file extension to MIME type. Uses a small built-in table for common
/// web types, falls back to `application/octet-stream`.
fn mime_type_for_path(path: &Path) -> &'static str {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "br" => "application/x-brotli",
        "wasm" => "application/wasm",
        "map" => "application/json",
        "webmanifest" => "application/manifest+json",
        _ => "application/octet-stream",
    }
}

/// Escape HTML special characters to prevent XSS in directory listings.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_test_dir() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("index.html"), "<html>hello</html>").expect("write index");
        fs::write(dir.path().join("style.css"), "body{}").expect("write css");
        fs::create_dir(dir.path().join("sub")).expect("create subdir");
        fs::write(dir.path().join("sub/page.html"), "<html>sub</html>").expect("write sub");
        fs::write(dir.path().join(".env"), "SECRET=123").expect("write dotfile");
        // Pre-canonicalize like compile.rs does — resolves macOS /tmp -> /private/tmp
        let canonical = dir.path().canonicalize().expect("canonicalize test dir");
        (dir, canonical)
    }

    /// Convenience wrapper that calls `serve_file` with the legacy
    /// no-fallback contract — keeps existing tests focused on their
    /// original behavior.
    async fn serve(root: &Path, path: &str, browse: bool) -> FileResponse {
        serve_file(root, path, browse, None, "GET").await
    }

    #[tokio::test]
    async fn serves_existing_file() {
        let (_dir, root) = setup_test_dir();
        let resp = serve(&root, "/style.css", false).await;
        match resp {
            FileResponse::Found {
                content_type, body, ..
            } => {
                assert_eq!(content_type, "text/css; charset=utf-8");
                assert_eq!(body.as_ref(), b"body{}");
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn serves_index_html_for_directory() {
        let (_dir, root) = setup_test_dir();
        let resp = serve(&root, "/", false).await;
        assert!(matches!(resp, FileResponse::Found { .. }));
    }

    #[tokio::test]
    async fn not_found_for_missing_file() {
        let (_dir, root) = setup_test_dir();
        let resp = serve(&root, "/nonexistent.txt", false).await;
        assert!(matches!(resp, FileResponse::NotFound));
    }

    #[tokio::test]
    async fn rejects_path_traversal() {
        let (_dir, root) = setup_test_dir();
        let resp = serve(&root, "/../../../etc/passwd", false).await;
        assert!(matches!(
            resp,
            FileResponse::Forbidden | FileResponse::NotFound
        ));
    }

    #[tokio::test]
    async fn rejects_null_bytes() {
        let (_dir, root) = setup_test_dir();
        let resp = serve(&root, "/style.css\0.txt", false).await;
        assert!(matches!(resp, FileResponse::Forbidden));
    }

    #[tokio::test]
    async fn rejects_dotfiles() {
        let (_dir, root) = setup_test_dir();
        let resp = serve(&root, "/.env", false).await;
        assert!(matches!(resp, FileResponse::Forbidden));
    }

    #[tokio::test]
    async fn directory_listing_when_browse_enabled() {
        let (_dir, root) = setup_test_dir();
        let resp = serve(&root, "/sub/", true).await;
        match resp {
            FileResponse::DirectoryListing { body } => {
                let html = std::str::from_utf8(&body).expect("valid utf8");
                assert!(html.contains("page.html"));
                assert!(html.contains("../"));
            }
            other => panic!("expected DirectoryListing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn no_listing_when_browse_disabled() {
        let (_dir, root) = setup_test_dir();
        // /sub/ has page.html but no index.html — without browse, returns NotFound
        let resp = serve(&root, "/sub/", false).await;
        assert!(matches!(resp, FileResponse::NotFound));
    }

    #[tokio::test]
    async fn serves_subdirectory_file() {
        let (_dir, root) = setup_test_dir();
        let resp = serve(&root, "/sub/page.html", false).await;
        assert!(matches!(resp, FileResponse::Found { .. }));
    }

    #[tokio::test]
    async fn etag_is_set() {
        let (_dir, root) = setup_test_dir();
        if let FileResponse::Found { etag, .. } = serve(&root, "/style.css", false).await {
            assert!(etag.is_some());
            let tag = etag.expect("etag");
            assert!(tag.starts_with('"'));
            assert!(tag.ends_with('"'));
        } else {
            panic!("expected Found");
        }
    }

    // ── SPA fallback tests ─────────────────────────────────────

    #[tokio::test]
    async fn fallback_engages_for_missing_route() {
        let (_dir, root) = setup_test_dir();
        let fallback = root.join("index.html");
        let resp = serve_file(&root, "/blog/post-slug", false, Some(&fallback), "GET").await;
        match resp {
            FileResponse::Found {
                content_type, body, ..
            } => {
                assert_eq!(content_type, "text/html; charset=utf-8");
                assert_eq!(body.as_ref(), b"<html>hello</html>");
            }
            other => panic!("expected fallback Found, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fallback_skipped_for_asset_extensions() {
        let (_dir, root) = setup_test_dir();
        let fallback = root.join("index.html");
        // A missing .js must NOT serve index.html — that would corrupt the page.
        let resp = serve_file(&root, "/missing.js", false, Some(&fallback), "GET").await;
        assert!(matches!(resp, FileResponse::NotFound));
    }

    #[tokio::test]
    async fn fallback_serves_existing_file_unchanged() {
        let (_dir, root) = setup_test_dir();
        let fallback = root.join("index.html");
        // Existing files are never rerouted to fallback.
        let resp = serve_file(&root, "/style.css", false, Some(&fallback), "GET").await;
        match resp {
            FileResponse::Found {
                content_type, body, ..
            } => {
                assert_eq!(content_type, "text/css; charset=utf-8");
                assert_eq!(body.as_ref(), b"body{}");
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fallback_returns_404_when_fallback_file_missing() {
        let (_dir, root) = setup_test_dir();
        let fallback = root.join("does-not-exist.html");
        let resp = serve_file(&root, "/blog/post", false, Some(&fallback), "GET").await;
        assert!(matches!(resp, FileResponse::NotFound));
    }

    #[tokio::test]
    async fn fallback_engages_for_head_method() {
        let (_dir, root) = setup_test_dir();
        let fallback = root.join("index.html");
        let resp = serve_file(&root, "/blog/post", false, Some(&fallback), "HEAD").await;
        assert!(matches!(resp, FileResponse::Found { .. }));
    }

    #[tokio::test]
    async fn fallback_does_not_engage_for_post() {
        let (_dir, root) = setup_test_dir();
        let fallback = root.join("index.html");
        let resp = serve_file(&root, "/blog/post", false, Some(&fallback), "POST").await;
        assert!(matches!(resp, FileResponse::NotFound));
    }

    #[tokio::test]
    async fn fallback_does_not_override_dotfile_forbidden() {
        let (_dir, root) = setup_test_dir();
        let fallback = root.join("index.html");
        // Dotfile requests are 403 before fallback can be considered.
        let resp = serve_file(&root, "/.env", false, Some(&fallback), "GET").await;
        assert!(matches!(resp, FileResponse::Forbidden));
    }

    #[tokio::test]
    async fn fallback_rejected_when_outside_root() {
        let (_dir, root) = setup_test_dir();
        // Fabricate a fallback that points outside the root.
        let outside = std::env::temp_dir().join("totally-elsewhere.html");
        let resp = serve_file(&root, "/blog/post", false, Some(&outside), "GET").await;
        assert!(matches!(resp, FileResponse::NotFound));
    }

    #[tokio::test]
    async fn no_fallback_preserves_legacy_404() {
        let (_dir, root) = setup_test_dir();
        // Regression guard: missing file with no fallback configured.
        let resp = serve_file(&root, "/blog/post", false, None, "GET").await;
        assert!(matches!(resp, FileResponse::NotFound));
    }

    #[test]
    fn asset_extension_detection() {
        assert!(is_asset_extension("/app.js"));
        assert!(is_asset_extension("/styles/main.CSS"));
        assert!(is_asset_extension("/_app/immutable/chunks/abc.js"));
        assert!(is_asset_extension("/img/logo.png"));
        assert!(!is_asset_extension("/blog/post"));
        assert!(!is_asset_extension("/about"));
        assert!(!is_asset_extension("/"));
        // Query string shouldn't fool us
        assert!(is_asset_extension("/app.js?v=1"));
    }

    #[test]
    fn html_escape_prevents_xss() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }

    #[test]
    fn mime_types_correct() {
        assert_eq!(
            mime_type_for_path(Path::new("style.css")),
            "text/css; charset=utf-8"
        );
        assert_eq!(
            mime_type_for_path(Path::new("app.js")),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(mime_type_for_path(Path::new("image.png")), "image/png");
        assert_eq!(
            mime_type_for_path(Path::new("unknown.xyz")),
            "application/octet-stream"
        );
    }
}
