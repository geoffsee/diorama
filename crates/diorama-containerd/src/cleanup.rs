//! Managed runtime restart cleanup boundaries.
//!
//! Enforces clean and crash restart recovery by removing disposable containerd
//! runtime state (`root/` with stale `meta.db` and task metadata, `state/` with dead
//! sockets and FIFOs, and stale system socket symlinks) while strictly preserving
//! source image archives, binaries, and registry configurations (`hosts.toml`).
//!
//! Stale container state in disposable directories causes pod synchronization failures
//! across restarts if not purged before containerd re-initializes. External or
//! host-managed runtime sockets and unrelated data are never modified.

use crate::service::ContainerdPaths;
use crate::symlink::DEFAULT_SYSTEM_CONTAINERD_SOCK;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Summary report of paths cleaned and preserved during restart preparation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// Paths that were cleaned/removed
    pub removed_paths: Vec<PathBuf>,
    /// Paths that were checked and preserved
    pub preserved_paths: Vec<PathBuf>,
    /// Whether the system compatibility socket was removed
    pub system_socket_cleaned: bool,
}

#[derive(Debug)]
pub enum CleanupError {
    UnsafePath { path: PathBuf, reason: &'static str },
    Io { path: PathBuf, source: io::Error },
}

impl fmt::Display for CleanupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafePath { path, reason } => {
                write!(
                    f,
                    "refusing to clean unsafe path '{}': {reason}",
                    path.display()
                )
            },
            Self::Io { path, source } => {
                write!(
                    f,
                    "io error while cleaning path '{}': {source}",
                    path.display()
                )
            },
        }
    }
}

impl std::error::Error for CleanupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnsafePath { .. } => None,
            Self::Io { source, .. } => Some(source),
        }
    }
}

/// Validates that a path is safe to remove during cleanup, preventing catastrophic
/// deletion of system directories or the filesystem root.
pub fn validate_cleanup_path(path: &Path) -> Result<(), CleanupError> {
    if path.as_os_str().is_empty() {
        return Err(CleanupError::UnsafePath {
            path: path.to_path_buf(),
            reason: "path cannot be empty",
        });
    }

    if path == Path::new("/") {
        return Err(CleanupError::UnsafePath {
            path: path.to_path_buf(),
            reason: "cannot clean filesystem root '/'",
        });
    }

    let forbidden_roots = [
        "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/proc", "/root", "/sbin",
        "/sys", "/usr", "/var",
    ];
    for forbidden in forbidden_roots {
        if path == Path::new(forbidden) {
            return Err(CleanupError::UnsafePath {
                path: path.to_path_buf(),
                reason: "cannot clean top-level system directory",
            });
        }
    }

    Ok(())
}

fn clean_system_socket(
    paths: &ContainerdPaths,
    system_socket: Option<&Path>,
    report: &mut CleanupReport,
) -> Result<(), CleanupError> {
    let system_socket_path =
        system_socket.unwrap_or_else(|| Path::new(DEFAULT_SYSTEM_CONTAINERD_SOCK));
    let Ok(meta) = fs::symlink_metadata(system_socket_path) else {
        return Ok(());
    };

    if !meta.file_type().is_symlink() {
        report
            .preserved_paths
            .push(system_socket_path.to_path_buf());
        return Ok(());
    }

    let Ok(target) = fs::read_link(system_socket_path) else {
        return Ok(());
    };

    let points_to_managed = target == paths.socket_path
        || paths
            .socket_path
            .file_name()
            .is_some_and(|f| target.ends_with(f) && target == paths.socket_path);

    if points_to_managed {
        fs::remove_file(system_socket_path).map_err(|e| CleanupError::Io {
            path: system_socket_path.to_path_buf(),
            source: e,
        })?;
        report.removed_paths.push(system_socket_path.to_path_buf());
        report.system_socket_cleaned = true;
    } else {
        report
            .preserved_paths
            .push(system_socket_path.to_path_buf());
    }

    Ok(())
}

fn clean_disposable_directories(
    paths: &ContainerdPaths,
    report: &mut CleanupReport,
) -> Result<(), CleanupError> {
    if paths.root_dir.exists() {
        validate_cleanup_path(&paths.root_dir)?;
        fs::remove_dir_all(&paths.root_dir).map_err(|e| CleanupError::Io {
            path: paths.root_dir.clone(),
            source: e,
        })?;
        report.removed_paths.push(paths.root_dir.clone());
    }

    if paths.state_dir.exists() {
        validate_cleanup_path(&paths.state_dir)?;
        fs::remove_dir_all(&paths.state_dir).map_err(|e| CleanupError::Io {
            path: paths.state_dir.clone(),
            source: e,
        })?;
        report.removed_paths.push(paths.state_dir.clone());
    }

    if paths.socket_path.exists() || fs::symlink_metadata(&paths.socket_path).is_ok() {
        validate_cleanup_path(&paths.socket_path)?;
        let _ = fs::remove_file(&paths.socket_path);
        if !report.removed_paths.contains(&paths.socket_path) {
            report.removed_paths.push(paths.socket_path.clone());
        }
    }

    Ok(())
}

fn sweep_containerd_entry(
    entry_path: PathBuf,
    paths: &ContainerdPaths,
    report: &mut CleanupReport,
) -> Result<(), CleanupError> {
    let name_str = entry_path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    let is_preserved_name = matches!(
        name_str.as_str(),
        "images"
            | "registry"
            | "config.d"
            | "cni"
            | "containerd"
            | "containerd-shim-runc-v2"
            | "crun"
            | "config.toml"
    );

    if is_preserved_name {
        if !report.preserved_paths.contains(&entry_path) {
            report.preserved_paths.push(entry_path);
        }
        return Ok(());
    }

    if entry_path == paths.root_dir || entry_path == paths.state_dir {
        return Ok(());
    }

    validate_cleanup_path(&entry_path)?;
    if entry_path.is_dir() {
        let _ = fs::remove_dir_all(&entry_path);
    } else {
        let _ = fs::remove_file(&entry_path);
    }
    report.removed_paths.push(entry_path);
    Ok(())
}

fn sweep_containerd_directory(
    paths: &ContainerdPaths,
    report: &mut CleanupReport,
) -> Result<(), CleanupError> {
    let Some(containerd_dir) = paths.root_dir.parent() else {
        return Ok(());
    };
    if !containerd_dir.is_dir() {
        return Ok(());
    }

    let entries = fs::read_dir(containerd_dir).map_err(|e| CleanupError::Io {
        path: containerd_dir.to_path_buf(),
        source: e,
    })?;

    for entry in entries.flatten() {
        sweep_containerd_entry(entry.path(), paths, report)?;
    }

    Ok(())
}

fn record_preserved_assets(paths: &ContainerdPaths, report: &mut CleanupReport) {
    let preserved_candidates = [
        &paths.images_dir,
        &paths.registry_hosts_dir,
        &paths.binary_path,
        &paths.shim_binary_path,
        &paths.crun_binary_path,
    ];

    for candidate in preserved_candidates {
        if candidate.exists() && !report.preserved_paths.contains(candidate) {
            report.preserved_paths.push((*candidate).clone());
        }
    }
}

/// Cleans stale containerd runtime state to allow clean/crash restarts and restore
/// pod synchronization.
///
/// Removes disposable `root/` and `state/` directories containing dead tasks, sockets,
/// and `meta.db` while preserving source image archives, binaries, and registry configurations.
/// Checks the system compatibility socket (`/run/containerd/containerd.sock` by default)
/// and removes it only if it is a symlink pointing to the managed socket; external or
/// host sockets are strictly preserved.
pub fn clean_stale_runtime_state(
    paths: &ContainerdPaths,
    system_socket: Option<&Path>,
) -> Result<CleanupReport, CleanupError> {
    let mut report = CleanupReport::default();

    clean_system_socket(paths, system_socket, &mut report)?;
    clean_disposable_directories(paths, &mut report)?;
    sweep_containerd_directory(paths, &mut report)?;
    record_preserved_assets(paths, &mut report);

    Ok(report)
}
