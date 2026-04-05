// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! TLS Secret integration — materialise K8s TLS Secrets as PEM files on disk.
//!
//! When an Ingress has `spec.tls[].secretName`, the referenced Secret holds the
//! certificate chain and private key as base64-encoded data under `tls.crt` and
//! `tls.key`. kube-rs decodes that base64 automatically into `BinaryData`, so
//! here we only need to write the raw bytes out to the cert directory.
//!
//! ## File naming
//!
//! To avoid collisions across namespaces, files are named:
//!   `{namespace}_{secret_name}.crt` / `{namespace}_{secret_name}.key`
//!
//! ## Permissions
//!
//! Private key files are written with mode `0o600` (owner read/write only).
//! Certificate files receive `0o644` so the proxy process can read them
//! without root even when dropped to a non-privileged UID.
//!
//! ## Security
//!
//! Secret names and namespaces come from the Kubernetes API and are used
//! to construct filesystem paths. We validate them as DNS label segments
//! before joining into a path so that a malicious Ingress cannot escape
//! the cert directory via path traversal (Guardrail #17).

use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use k8s_openapi::api::core::v1::Secret;
use kube::runtime::reflector::Store;
use tracing::{debug, info, warn};

use crate::error::TlsError;

/// Write PEM files for every TLS block on a newly applied Ingress.
///
/// `cert_dir` is the directory where `.crt` / `.key` files are stored. It must
/// already exist. For each `(namespace, secret_name)` pair we look up the Secret
/// in the reflector store and materialise both files.
///
/// Returns the list of base names written (e.g. `["default_my-tls"]`). Callers
/// can store this to know which files to clean up on deletion.
pub fn sync_tls_secrets(
    tls_blocks: &[(String, String)], // (namespace, secret_name)
    secret_store: &Store<Secret>,
    cert_dir: &Path,
) -> Vec<String> {
    let mut written = Vec::new();

    for (namespace, secret_name) in tls_blocks {
        // Validate both segments before touching the filesystem.
        if let Err(e) = validate_path_segment(namespace) {
            warn!(namespace, secret_name, error = %e, "invalid namespace in TLS block — skipping");
            continue;
        }
        if let Err(e) = validate_path_segment(secret_name) {
            warn!(namespace, secret_name, error = %e, "invalid secret name in TLS block — skipping");
            continue;
        }

        let base = format!("{namespace}_{secret_name}");

        match write_secret_pem(namespace, secret_name, &base, secret_store, cert_dir) {
            Ok(()) => {
                info!(namespace, secret_name, "TLS PEM files written");
                written.push(base);
            }
            Err(e) => {
                warn!(namespace, secret_name, error = %e, "failed to write TLS PEM files");
            }
        }
    }

    written
}

/// Remove PEM files for a set of base names.
///
/// Called when an Ingress is deleted. Missing files are not an error — they
/// may have already been cleaned up by a prior controller run.
pub fn remove_tls_pem_files(base_names: &[String], cert_dir: &Path) {
    for base in base_names {
        for ext in ["crt", "key"] {
            let path = cert_dir.join(format!("{base}.{ext}"));
            match std::fs::remove_file(&path) {
                Ok(()) => debug!(path = %path.display(), "removed TLS PEM file"),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    debug!(path = %path.display(), "TLS PEM file already gone — nothing to remove");
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "failed to remove TLS PEM file");
                }
            }
        }
    }
}

/// Look up `secret_name` in `namespace` from the store and write both PEM files.
fn write_secret_pem(
    namespace: &str,
    secret_name: &str,
    base: &str,
    secret_store: &Store<Secret>,
    cert_dir: &Path,
) -> Result<(), TlsError> {
    let obj_ref = kube::runtime::reflector::ObjectRef::<Secret>::new(secret_name).within(namespace);

    let secret = secret_store
        .get(&obj_ref)
        .ok_or_else(|| TlsError::SecretNotFound {
            name: secret_name.to_string(),
            namespace: namespace.to_string(),
        })?;

    // kube-rs decodes the base64 in `data` into raw bytes under `BinaryData`.
    // The Kubernetes TLS Secret type stores the cert under "tls.crt" and the
    // key under "tls.key".
    let data = secret.data.as_ref().ok_or_else(|| TlsError::MissingField {
        secret: secret_name.to_string(),
        field: "data".to_string(),
    })?;

    let crt_bytes = data.get("tls.crt").ok_or_else(|| TlsError::MissingField {
        secret: secret_name.to_string(),
        field: "tls.crt".to_string(),
    })?;

    let key_bytes = data.get("tls.key").ok_or_else(|| TlsError::MissingField {
        secret: secret_name.to_string(),
        field: "tls.key".to_string(),
    })?;

    write_pem_file(cert_dir, &format!("{base}.crt"), &crt_bytes.0, 0o644)?;
    write_pem_file(cert_dir, &format!("{base}.key"), &key_bytes.0, 0o600)?;

    Ok(())
}

/// Write `bytes` to `cert_dir/filename` with the given Unix mode.
///
/// We use `OpenOptions::mode()` from `std::os::unix::fs::OpenOptionsExt` so the
/// file is created with the correct permissions from the start rather than
/// setting them in a separate `chmod` call (which would leave a race window).
fn write_pem_file(
    cert_dir: &Path,
    filename: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<(), TlsError> {
    use std::io::Write;

    let path: PathBuf = cert_dir.join(filename);

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&path)
        .map_err(|e| TlsError::Io {
            path: path.clone(),
            source: e,
        })?;

    f.write_all(bytes).map_err(|e| TlsError::Io {
        path: path.clone(),
        source: e,
    })?;

    Ok(())
}

/// Reject any path segment that could be used to escape the cert directory.
///
/// Kubernetes names are required to be DNS subdomain or label names, which
/// means they can only contain alphanumerics, hyphens, and dots. We reject
/// anything with `/`, `\`, `..`, or null bytes — all classic path traversal
/// characters (Guardrail #17).
fn validate_path_segment(segment: &str) -> Result<(), TlsError> {
    if segment.is_empty() {
        return Err(TlsError::InvalidSegment {
            segment: segment.to_string(),
            reason: "empty".to_string(),
        });
    }
    if segment.contains('/') || segment.contains('\\') || segment.contains('\0') {
        return Err(TlsError::InvalidSegment {
            segment: segment.to_string(),
            reason: "contains path separator or null byte".to_string(),
        });
    }
    if segment == ".." || segment == "." {
        return Err(TlsError::InvalidSegment {
            segment: segment.to_string(),
            reason: "dot segment".to_string(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::runtime::reflector::{self, Store};

    use super::*;

    // Build a populated reflector Store from a list of Secrets.
    fn make_store(secrets: Vec<Secret>) -> Store<Secret> {
        let (reader, mut writer) = reflector::store::<Secret>();
        for s in secrets {
            writer.apply_watcher_event(&kube::runtime::watcher::Event::Apply(s));
        }
        reader
    }

    fn make_secret(namespace: &str, name: &str, crt: &[u8], key: &[u8]) -> Secret {
        let mut data = BTreeMap::new();
        data.insert("tls.crt".to_string(), ByteString(crt.to_vec()));
        data.insert("tls.key".to_string(), ByteString(key.to_vec()));

        Secret {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        }
    }

    #[test]
    fn writes_crt_and_key_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_dir = dir.path();

        let crt = b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n";
        let key = b"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n";
        let store = make_store(vec![make_secret("default", "my-tls", crt, key)]);

        let written = sync_tls_secrets(
            &[("default".to_string(), "my-tls".to_string())],
            &store,
            cert_dir,
        );

        assert_eq!(written, vec!["default_my-tls"]);
        assert_eq!(
            std::fs::read(cert_dir.join("default_my-tls.crt")).expect("crt"),
            crt
        );
        assert_eq!(
            std::fs::read(cert_dir.join("default_my-tls.key")).expect("key"),
            key
        );
    }

    #[test]
    fn key_file_has_mode_0600() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_dir = dir.path();

        let store = make_store(vec![make_secret("default", "my-tls", b"cert", b"key")]);

        sync_tls_secrets(
            &[("default".to_string(), "my-tls".to_string())],
            &store,
            cert_dir,
        );

        let meta = std::fs::metadata(cert_dir.join("default_my-tls.key")).expect("stat key");
        // Only the permission bits — mask off file type bits.
        let perm = meta.permissions().mode() & 0o777;
        assert_eq!(perm, 0o600, "key file must be 0600, got {perm:o}");
    }

    #[test]
    fn crt_file_has_mode_0644() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_dir = dir.path();

        let store = make_store(vec![make_secret("default", "my-tls", b"cert", b"key")]);

        sync_tls_secrets(
            &[("default".to_string(), "my-tls".to_string())],
            &store,
            cert_dir,
        );

        let meta = std::fs::metadata(cert_dir.join("default_my-tls.crt")).expect("stat crt");
        let perm = meta.permissions().mode() & 0o777;
        assert_eq!(perm, 0o644, "crt file must be 0644, got {perm:o}");
    }

    #[test]
    fn missing_key_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_dir = dir.path();

        // Secret has tls.crt but not tls.key
        let mut data = BTreeMap::new();
        data.insert("tls.crt".to_string(), ByteString(b"cert".to_vec()));
        let secret = Secret {
            metadata: ObjectMeta {
                name: Some("bad-secret".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        };
        let store = make_store(vec![secret]);

        // sync_tls_secrets returns an empty list when the write fails.
        let written = sync_tls_secrets(
            &[("default".to_string(), "bad-secret".to_string())],
            &store,
            cert_dir,
        );
        assert!(
            written.is_empty(),
            "should fail silently and return no names"
        );
    }

    #[test]
    fn secret_not_in_store_is_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_dir = dir.path();
        let store = make_store(vec![]);

        let written = sync_tls_secrets(
            &[("default".to_string(), "nonexistent".to_string())],
            &store,
            cert_dir,
        );
        assert!(written.is_empty());
    }

    #[test]
    fn overwrite_replaces_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_dir = dir.path();

        let store1 = make_store(vec![make_secret("default", "s", b"old-cert", b"old-key")]);
        sync_tls_secrets(
            &[("default".to_string(), "s".to_string())],
            &store1,
            cert_dir,
        );

        // Now write updated content via a second store.
        let store2 = make_store(vec![make_secret("default", "s", b"new-cert", b"new-key")]);
        sync_tls_secrets(
            &[("default".to_string(), "s".to_string())],
            &store2,
            cert_dir,
        );

        assert_eq!(
            std::fs::read(cert_dir.join("default_s.crt")).expect("crt"),
            b"new-cert"
        );
        assert_eq!(
            std::fs::read(cert_dir.join("default_s.key")).expect("key"),
            b"new-key"
        );
    }

    #[test]
    fn delete_removes_pem_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_dir = dir.path();

        let store = make_store(vec![make_secret("prod", "app-tls", b"cert", b"key")]);
        let written = sync_tls_secrets(
            &[("prod".to_string(), "app-tls".to_string())],
            &store,
            cert_dir,
        );
        assert_eq!(written, vec!["prod_app-tls"]);

        remove_tls_pem_files(&written, cert_dir);

        assert!(
            !cert_dir.join("prod_app-tls.crt").exists(),
            "crt should be removed"
        );
        assert!(
            !cert_dir.join("prod_app-tls.key").exists(),
            "key should be removed"
        );
    }

    #[test]
    fn delete_missing_files_is_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Call remove on names that never existed — should not panic.
        remove_tls_pem_files(&["nonexistent_secret".to_string()], dir.path());
    }

    #[test]
    fn path_traversal_in_namespace_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = make_store(vec![]);

        // A malicious namespace containing "../" should be rejected before
        // touching the filesystem.
        let written = sync_tls_secrets(
            &[("../evil".to_string(), "secret".to_string())],
            &store,
            dir.path(),
        );
        assert!(written.is_empty(), "path traversal must be rejected");
    }

    #[test]
    fn path_traversal_in_secret_name_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = make_store(vec![]);

        let written = sync_tls_secrets(
            &[("default".to_string(), "../../etc/shadow".to_string())],
            &store,
            dir.path(),
        );
        assert!(written.is_empty(), "path traversal must be rejected");
    }

    #[test]
    fn validate_path_segment_rejects_dot_dot() {
        assert!(validate_path_segment("..").is_err());
        assert!(validate_path_segment(".").is_err());
    }

    #[test]
    fn validate_path_segment_rejects_empty() {
        assert!(validate_path_segment("").is_err());
    }

    #[test]
    fn validate_path_segment_accepts_dns_labels() {
        assert!(validate_path_segment("default").is_ok());
        assert!(validate_path_segment("my-namespace").is_ok());
        assert!(validate_path_segment("tls-secret.v2").is_ok());
    }
}
