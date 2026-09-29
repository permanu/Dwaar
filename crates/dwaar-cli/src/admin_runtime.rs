//! Instance-scoped admin endpoint discovery; no shared files under /tmp.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub(crate) fn write(state_dir: &Path, address: &str) -> io::Result<()> {
    let directory = state_dir.join("runtime");
    match fs::create_dir(&directory) {
        Ok(()) => fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(&directory)?;
            if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "admin runtime directory must be private",
                ));
            }
        }
        Err(error) => return Err(error),
    }
    let path = directory.join("admin.addr");
    if fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.is_file()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "admin endpoint must be a regular file",
        ));
    }
    let mut file = tempfile::NamedTempFile::new_in(&directory)?;
    file.write_all(address.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist(&path).map_err(|error| error.error)?;
    Ok(())
}

pub(crate) fn read(state_dir: &Path) -> Option<String> {
    let path = state_dir.join("runtime/admin.addr");
    let metadata = fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > 4096 || metadata.permissions().mode() & 0o077 != 0 {
        return None;
    }
    let mut value = String::new();
    fs::File::open(&path)
        .ok()?
        .take(4097)
        .read_to_string(&mut value)
        .ok()?;
    if value.len() > 4096 || value.is_empty() || value.contains(['\r', '\n']) {
        return None;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_are_private_and_instance_scoped() {
        let first = tempfile::tempdir().expect("create test directory");
        let second = tempfile::tempdir().expect("create test directory");
        write(first.path(), "127.0.0.1:12345").expect("test filesystem operation");
        write(second.path(), "127.0.0.1:23456").expect("test filesystem operation");
        assert_eq!(read(first.path()).as_deref(), Some("127.0.0.1:12345"));
        assert_eq!(read(second.path()).as_deref(), Some("127.0.0.1:23456"));
        assert_eq!(
            fs::metadata(first.path().join("runtime/admin.addr"))
                .expect("test filesystem operation")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn symlink_cannot_redirect_endpoint_writes() {
        let directory = tempfile::tempdir().expect("create test directory");
        write(directory.path(), "127.0.0.1:12345").expect("test filesystem operation");
        let target = directory.path().join("unrelated");
        fs::write(&target, "preserve").expect("test filesystem operation");
        let endpoint = directory.path().join("runtime/admin.addr");
        fs::remove_file(&endpoint).expect("test filesystem operation");
        std::os::unix::fs::symlink(&target, &endpoint).expect("test filesystem operation");
        assert!(write(directory.path(), "127.0.0.1:23456").is_err());
        assert!(read(directory.path()).is_none());
        assert_eq!(
            fs::read_to_string(target).expect("test filesystem operation"),
            "preserve"
        );
    }
}
