// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! ACME account credential management.
//!
//! Handles saving and loading `instant-acme` `AccountCredentials` as JSON
//! files in `/etc/dwaar/acme/`. Each CA gets its own credentials file.

use std::path::{Path, PathBuf};

use tokio::fs;
use tokio::io::AsyncReadExt;
use tracing::{debug, info};

use super::AcmeError;

/// Max size of an ACME account credentials file. Real files are <2 KB
/// (account ID + URLs + base64 PKCS8 key); 64 KB is a generous defensive
/// cap (Guardrail #28).
const MAX_ACCOUNT_FILE_BYTES: u64 = 64 * 1024;

/// Build the credentials file path for a given CA identifier.
/// e.g., `("le")` → `/etc/dwaar/acme/le_account.json`
pub fn credentials_path(acme_dir: &Path, ca_id: &str) -> PathBuf {
    acme_dir.join(format!("{ca_id}_account.json"))
}

/// Ensure the ACME directory exists with `0700` permissions.
pub async fn ensure_acme_dir(dir: &Path) -> Result<(), AcmeError> {
    fs::create_dir_all(dir)
        .await
        .map_err(AcmeError::AccountIo)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        fs::set_permissions(dir, perms)
            .await
            .map_err(AcmeError::AccountIo)?;
    }

    debug!(dir = %dir.display(), "ACME directory ready");
    Ok(())
}

/// Save serialized credentials JSON to disk with `0600` permissions,
/// atomically, using an unpredictable temp file name in the target directory.
///
/// Uses [`tempfile::NamedTempFile::new_in`] (random suffix) instead of a
/// predictable `.tmp` pattern so that a local attacker cannot pre-create a
/// symlink at the temp path pointing to a privileged file and trick dwaar
/// into overwriting it. Mirrors the same pattern used for cert PEM writes.
///
/// The `tempfile` crate's API is blocking, so this runs on `spawn_blocking`
/// to keep the async runtime free during `fsync`.
pub async fn save_credentials(path: &Path, json: &str) -> Result<(), AcmeError> {
    let path = path.to_path_buf();
    let json = json.to_string();

    tokio::task::spawn_blocking(move || -> Result<(), std::io::Error> {
        use std::io::Write;

        let parent = path.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "account credentials path has no parent directory",
            )
        })?;

        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        tmp.write_all(json.as_bytes())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(tmp.path(), perms)?;
        }

        // fsync before rename so a crash cannot leave a zero-length creds file.
        tmp.as_file_mut().sync_all()?;

        tmp.persist(&path).map_err(|e| e.error)?;
        info!(path = %path.display(), "ACME account credentials saved");
        Ok(())
    })
    .await
    .map_err(|e| {
        AcmeError::AccountIo(std::io::Error::other(format!(
            "save_credentials join error: {e}"
        )))
    })?
    .map_err(AcmeError::AccountIo)?;

    Ok(())
}

/// Load credentials JSON from disk, bounded to [`MAX_ACCOUNT_FILE_BYTES`].
pub async fn load_credentials(path: &Path) -> Result<String, AcmeError> {
    let file = fs::File::open(path).await.map_err(AcmeError::AccountIo)?;
    let mut json = String::new();
    let n = file
        .take(MAX_ACCOUNT_FILE_BYTES + 1)
        .read_to_string(&mut json)
        .await
        .map_err(AcmeError::AccountIo)?;
    if n as u64 > MAX_ACCOUNT_FILE_BYTES {
        return Err(AcmeError::AccountIo(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ACME account file exceeds size limit",
        )));
    }
    debug!(path = %path.display(), "ACME account credentials loaded");
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn credentials_path_construction() {
        let acme_dir = std::path::Path::new("/etc/dwaar/acme");
        let path = credentials_path(acme_dir, "le");
        assert_eq!(
            path,
            std::path::PathBuf::from("/etc/dwaar/acme/le_account.json")
        );
    }

    #[tokio::test]
    async fn save_and_load_roundtrip() {
        let dir = TempDir::new().expect("tempdir");
        let dummy_json = r#"{"id":"test","key_pkcs8":"AAAA","urls":{"newNonce":"https://a","newAccount":"https://b","newOrder":"https://c"}}"#;

        let path = dir.path().join("test_account.json");
        save_credentials(&path, dummy_json).await.expect("save");

        let loaded = load_credentials(&path).await.expect("load");
        assert_eq!(loaded, dummy_json);

        // Verify file permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path).expect("metadata").permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }
    }

    #[tokio::test]
    async fn load_missing_returns_error() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("nonexistent.json");
        let result = load_credentials(&path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn ensure_dir_creates_with_permissions() {
        let dir = TempDir::new().expect("tempdir");
        let acme_dir = dir.path().join("acme");
        ensure_acme_dir(&acme_dir).await.expect("create dir");

        assert!(acme_dir.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&acme_dir)
                .expect("metadata")
                .permissions();
            assert_eq!(perms.mode() & 0o777, 0o700);
        }
    }
}
