//! Symbolic link management with immutable and read-only filesystem resilience.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};

/// Default system socket compatibility path expected by external tools like `crictl`.
pub const DEFAULT_SYSTEM_CONTAINERD_SOCK: &str = "/run/containerd/containerd.sock";

#[derive(Debug)]
pub enum SymlinkError {
    ReadlinkFailed {
        target: PathBuf,
        source: io::Error,
    },
    RemoveFailed {
        target: PathBuf,
        source: io::Error,
    },
    CreateFailed {
        target: PathBuf,
        destination: PathBuf,
        source: io::Error,
    },
    ParentMissing {
        target: PathBuf,
    },
}

impl fmt::Display for SymlinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadlinkFailed { target, source } => {
                write!(
                    f,
                    "failed to read symlink at '{}': {source}",
                    target.display()
                )
            },
            Self::RemoveFailed { target, source } => {
                write!(
                    f,
                    "failed to remove existing target at '{}': {source}",
                    target.display()
                )
            },
            Self::CreateFailed {
                target,
                destination,
                source,
            } => {
                write!(
                    f,
                    "failed to install symlink '{}' -> '{}': {source}",
                    target.display(),
                    destination.display()
                )
            },
            Self::ParentMissing { target } => {
                write!(
                    f,
                    "parent directory for symlink target '{}' does not exist",
                    target.display()
                )
            },
        }
    }
}

impl std::error::Error for SymlinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadlinkFailed { source, .. }
            | Self::RemoveFailed { source, .. }
            | Self::CreateFailed { source, .. } => Some(source),
            Self::ParentMissing { .. } => None,
        }
    }
}

/// Ensure a symbolic link points to the given source, preserving existing correct links.
///
/// If `target` already exists and is a symlink pointing directly to `source`,
/// this function returns `Ok(())` without modifying the filesystem. This is essential
/// for immutable root filesystems or read-only host mounts where an existing link
/// cannot be replaced without error.
///
/// If `target` points elsewhere or is broken, it is removed and recreated.
pub fn ensure_symbolic_link(source: &Path, target: &Path) -> Result<(), SymlinkError> {
    let source_abs = if source.is_absolute() {
        source.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| source.to_path_buf(), |cwd| cwd.join(source))
    };

    if let Ok(existing_dest) = fs::read_link(target)
        && existing_dest == source_abs
    {
        return Ok(());
    }

    if (target.exists() || fs::symlink_metadata(target).is_ok())
        && let Err(err) = fs::remove_file(target)
        && err.kind() != io::ErrorKind::NotFound
    {
        return Err(SymlinkError::RemoveFailed {
            target: target.to_path_buf(),
            source: err,
        });
    }

    if let Some(parent) = target.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent).map_err(|_| SymlinkError::ParentMissing {
            target: target.to_path_buf(),
        })?;
    }

    unix_fs::symlink(&source_abs, target).map_err(|err| SymlinkError::CreateFailed {
        target: target.to_path_buf(),
        destination: source_abs,
        source: err,
    })
}

/// Ensure the standard `/run/containerd/containerd.sock` compatibility symlink
/// points to the managed containerd socket.
pub fn ensure_system_socket_link(
    managed_socket: &Path,
    system_socket: Option<&Path>,
) -> Result<(), SymlinkError> {
    let target = system_socket.unwrap_or_else(|| Path::new(DEFAULT_SYSTEM_CONTAINERD_SOCK));
    ensure_symbolic_link(managed_socket, target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn creates_new_symlink() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("source.sock");
        let target = temp.path().join("target.sock");

        fs::write(&source, b"test").unwrap();
        ensure_symbolic_link(&source, &target).unwrap();

        assert_eq!(fs::read_link(&target).unwrap(), source);
    }

    #[test]
    fn preserves_existing_correct_symlink() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("source.sock");
        let target = temp.path().join("target.sock");

        fs::write(&source, b"test").unwrap();
        unix_fs::symlink(&source, &target).unwrap();

        // Second call should succeed and leave the link intact
        ensure_symbolic_link(&source, &target).unwrap();
        assert_eq!(fs::read_link(&target).unwrap(), source);
    }

    #[test]
    fn replaces_incorrect_symlink() {
        let temp = TempDir::new().unwrap();
        let source_a = temp.path().join("source_a.sock");
        let source_b = temp.path().join("source_b.sock");
        let target = temp.path().join("target.sock");

        fs::write(&source_a, b"a").unwrap();
        fs::write(&source_b, b"b").unwrap();

        unix_fs::symlink(&source_a, &target).unwrap();
        assert_eq!(fs::read_link(&target).unwrap(), source_a);

        // Update to point to source_b
        ensure_symbolic_link(&source_b, &target).unwrap();
        assert_eq!(fs::read_link(&target).unwrap(), source_b);
    }
}
