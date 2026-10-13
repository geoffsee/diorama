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
use std::process::Command;
use std::time::{Duration, Instant};

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

/// Mount points at or inside `roots`, deepest path first.
///
/// `mountinfo` is the text of `/proc/self/mountinfo`. Mount points use the
/// kernel's octal escapes (`\040` for a space). Paths outside `roots` are omitted.
pub fn mounts_under(mountinfo: &str, roots: &[&Path]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for line in mountinfo.lines() {
        let Some(point) = mountinfo_mount_point(line) else {
            continue;
        };
        if roots.iter().any(|root| path_is_within(&point, root)) {
            found.push(point);
        }
    }
    found.sort_by(|left, right| {
        right
            .components()
            .count()
            .cmp(&left.components().count())
            .then_with(|| left.cmp(right))
    });
    found
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn mountinfo_mount_point(line: &str) -> Option<PathBuf> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let separator = fields.iter().position(|field| *field == "-")?;
    if separator < 5 {
        return None;
    }
    Some(PathBuf::from(unescape_mount_field(fields[4])))
}

fn unescape_mount_field(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = String::with_capacity(field.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let octal = &field[index + 1..index + 4];
            if octal.bytes().all(|byte| byte.is_ascii_digit())
                && let Ok(value) = u8::from_str_radix(octal, 8)
            {
                out.push(char::from(value));
                index += 4;
                continue;
            }
        }
        out.push(char::from(bytes[index]));
        index += 1;
    }
    out
}

fn managed_pid_file(paths: &ContainerdPaths) -> Option<PathBuf> {
    paths
        .root_dir
        .parent()
        .map(|dir| dir.join("containerd.pid"))
}

fn process_comm(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let comm = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        let comm = comm.trim();
        if comm.is_empty() {
            None
        } else {
            Some(comm.to_string())
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let output = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8(output.stdout).ok()?;
        let line = text.lines().next()?.trim();
        if line.is_empty() {
            return None;
        }
        Path::new(line)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    }
}

fn process_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .is_ok_and(|status| status.success())
}

fn signal_pid(pid: u32, signal: &str) {
    let _ = Command::new("kill")
        .args([signal, &pid.to_string()])
        .status();
}

fn wait_until_dead(pid: u32, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if !process_alive(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Stops a leftover managed containerd recorded in `{containerd_dir}/containerd.pid`
/// when that pid's command is `containerd`, then detaches mounts under the
/// disposable root and state directories on Linux.
pub fn reclaim_managed_runtime(paths: &ContainerdPaths) {
    stop_recorded_containerd(paths);
    detach_managed_mounts(paths);
}

fn stop_recorded_containerd(paths: &ContainerdPaths) {
    let Some(pid_file) = managed_pid_file(paths) else {
        return;
    };
    let Ok(text) = fs::read_to_string(&pid_file) else {
        return;
    };
    let Ok(pid) = text.trim().parse::<u32>() else {
        return;
    };
    if pid <= 1 || process_comm(pid).as_deref() != Some("containerd") {
        return;
    }
    signal_pid(pid, "-TERM");
    if wait_until_dead(pid, Duration::from_secs(2)) {
        return;
    }
    signal_pid(pid, "-KILL");
    let _ = wait_until_dead(pid, Duration::from_secs(1));
}

fn managed_mounts(mountinfo: &str, paths: &ContainerdPaths) -> Vec<PathBuf> {
    let roots: [&Path; 2] = [paths.root_dir.as_path(), paths.state_dir.as_path()];
    mounts_under(mountinfo, &roots)
}

fn detach_managed_mounts(paths: &ContainerdPaths) {
    #[cfg(target_os = "linux")]
    {
        let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        for mount in managed_mounts(&mountinfo, paths) {
            let _ = Command::new("umount").arg("-l").arg(&mount).status();
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = managed_mounts("", paths);
    }
}

pub(crate) fn cleanup_is_busy(err: &CleanupError) -> bool {
    let CleanupError::Io { source, .. } = err else {
        return false;
    };
    matches!(
        source.kind(),
        io::ErrorKind::ResourceBusy | io::ErrorKind::DirectoryNotEmpty
    )
}
