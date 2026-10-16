use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use crate::error::NetworkError;

pub const IP_FORWARD_SYSCTL_REL_PATH: &str = "net/ipv4/ip_forward";
pub const IPV6_FORWARD_SYSCTL_REL_PATH: &str = "net/ipv6/conf/all/forwarding";

/// Returns true if an IO error on sysctl read/write can be safely ignored.
#[must_use]
pub fn is_ignorable_sysctl_error(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::NotFound | ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
    )
}

/// Reads the sysctl value at `rel_path` relative to `root`.
/// Returns `Ok(Some(trimmed_value))` if readable, `Ok(None)` if file not found, or `Err(NetworkError)`.
pub fn read_sysctl(root: &Path, rel_path: &str) -> Result<Option<String>, NetworkError> {
    let path = root.join(rel_path);
    match fs::read(&path) {
        Ok(bytes) => {
            let s = String::from_utf8_lossy(&bytes);
            Ok(Some(s.trim().to_string()))
        },
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) if is_ignorable_sysctl_error(e.kind()) => {
            tracing::debug!(
                component = "network",
                path = %path.display(),
                error = %e,
                "sysctl path inaccessible, treating as absent"
            );
            Ok(None)
        },
        Err(e) => Err(NetworkError::SysctlError {
            path: path.display().to_string(),
            reason: format!("failed to read sysctl: {e}"),
        }),
    }
}

/// Ensures a sysctl path contains the expected value.
///
/// If the sysctl already contains the expected value, this function succeeds immediately
/// without attempting to write, ensuring success on systems where `/proc/sys` is mounted read-only.
/// If the value is incorrect and the sysctl cannot be written (e.g. read-only or permission denied),
/// an actionable `NetworkError::SysctlError` is returned.
pub fn ensure_sysctl_value(
    root: &Path,
    rel_path: &str,
    expected: &str,
) -> Result<(), NetworkError> {
    let path = root.join(rel_path);

    // 1. Read existing value first to avoid unnecessary writes on read-only filesystems
    match fs::read(&path) {
        Ok(bytes) => {
            let current = String::from_utf8_lossy(&bytes);
            if current.trim() == expected.trim() {
                tracing::debug!(
                    component = "network",
                    path = %path.display(),
                    expected = %expected,
                    "sysctl value already set correctly"
                );
                return Ok(());
            }
        },
        Err(e) if e.kind() == ErrorKind::NotFound => {
            // File does not exist yet (e.g. mock root in testing); proceed to create/write
        },
        Err(e) if is_ignorable_sysctl_error(e.kind()) => {
            tracing::debug!(
                component = "network",
                path = %path.display(),
                error = %e,
                "sysctl read failed with ignorable error"
            );
        },
        Err(e) => {
            tracing::warn!(
                component = "network",
                path = %path.display(),
                error = %e,
                "failed to read sysctl before writing"
            );
        },
    }

    // 2. Attempt to write expected value
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    if let Err(e) = fs::write(&path, expected.as_bytes()) {
        if e.kind() == ErrorKind::ReadOnlyFilesystem || e.kind() == ErrorKind::PermissionDenied {
            return Err(NetworkError::SysctlError {
                path: path.display().to_string(),
                reason: format!(
                    "sysctl requires value '{expected}' but current value differs and filesystem is read-only or access is denied ({e})"
                ),
            });
        }
        return Err(NetworkError::SysctlError {
            path: path.display().to_string(),
            reason: format!("failed to write sysctl: {e}"),
        });
    }

    tracing::info!(
        component = "network",
        path = %path.display(),
        value = %expected,
        "updated sysctl value"
    );

    Ok(())
}

/// Ensures `net.ipv4.ip_forward` is enabled (`1`) on the host system.
///
/// Idempotent and read-only tolerant: succeeds if `/proc/sys/net/ipv4/ip_forward`
/// is already set to `1`, even if `/proc/sys` is mounted read-only.
pub fn ensure_ip_forward() -> Result<(), NetworkError> {
    ensure_ip_forward_in_root(Path::new("/proc/sys"))
}

/// Ensures `net.ipv4.ip_forward` is enabled (`1`) relative to `root`.
pub fn ensure_ip_forward_in_root(root: &Path) -> Result<(), NetworkError> {
    ensure_sysctl_value(root, IP_FORWARD_SYSCTL_REL_PATH, "1")
}

/// Ensures `net.ipv6.conf.all.forwarding` is enabled (`1`) on the host system.
pub fn ensure_ipv6_forward() -> Result<(), NetworkError> {
    ensure_ipv6_forward_in_root(Path::new("/proc/sys"))
}

/// Ensures `net.ipv6.conf.all.forwarding` is enabled (`1`) relative to `root`.
pub fn ensure_ipv6_forward_in_root(root: &Path) -> Result<(), NetworkError> {
    ensure_sysctl_value(root, IPV6_FORWARD_SYSCTL_REL_PATH, "1")
}

/// Allows DNAT toward `127.0.0.0/8` on the host.
///
/// The apiserver listens on loopback. Pod traffic to the `kubernetes` Service is
/// rewritten to that address, and the kernel drops those packets unless
/// `route_localnet` is set on the arriving interface.
pub fn ensure_route_localnet() -> Result<(), NetworkError> {
    ensure_route_localnet_in_root(Path::new("/proc/sys"))
}

/// Sets `route_localnet=1` for `all` and every interface present under `root`.
pub fn ensure_route_localnet_in_root(root: &Path) -> Result<(), NetworkError> {
    let conf = root.join("net/ipv4/conf");
    if let Ok(entries) = fs::read_dir(&conf) {
        for entry in entries.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if !entry.path().join("route_localnet").exists() && name != "all" {
                continue;
            }
            let rel = format!("net/ipv4/conf/{name}/route_localnet");
            ensure_sysctl_value(root, &rel, "1")?;
        }
    }
    ensure_sysctl_value(root, "net/ipv4/conf/all/route_localnet", "1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_ensure_ip_forward_when_already_correct() {
        let dir = tempdir().expect("tempdir");
        let sysctl_path = dir.path().join("net/ipv4/ip_forward");
        fs::create_dir_all(sysctl_path.parent().unwrap()).unwrap();
        fs::write(&sysctl_path, b"1\n").unwrap();

        // Even if read-only permissions are simulated:
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&sysctl_path, fs::Permissions::from_mode(0o444)).unwrap();
        }

        // Should succeed without writing!
        assert!(ensure_ip_forward_in_root(dir.path()).is_ok());
    }

    #[test]
    fn route_localnet_is_enabled_for_all_and_existing_interfaces() {
        let dir = tempdir().expect("tempdir");
        let all = dir.path().join("net/ipv4/conf/all/route_localnet");
        let cni0 = dir.path().join("net/ipv4/conf/cni0/route_localnet");
        fs::create_dir_all(all.parent().unwrap()).unwrap();
        fs::create_dir_all(cni0.parent().unwrap()).unwrap();
        fs::write(&all, b"0\n").unwrap();
        fs::write(&cni0, b"0\n").unwrap();

        ensure_route_localnet_in_root(dir.path()).unwrap();

        assert_eq!(fs::read_to_string(&all).unwrap().trim(), "1");
        assert_eq!(fs::read_to_string(&cni0).unwrap().trim(), "1");
    }

    #[test]
    fn test_ensure_ip_forward_updates_when_zero() {
        let dir = tempdir().expect("tempdir");
        let sysctl_path = dir.path().join("net/ipv4/ip_forward");
        fs::create_dir_all(sysctl_path.parent().unwrap()).unwrap();
        fs::write(&sysctl_path, b"0\n").unwrap();

        assert!(ensure_ip_forward_in_root(dir.path()).is_ok());
        let val = fs::read_to_string(&sysctl_path).unwrap();
        assert_eq!(val.trim(), "1");
    }

    #[test]
    fn test_read_sysctl() {
        let dir = tempdir().expect("tempdir");
        let sysctl_path = dir.path().join("net/ipv4/ip_forward");
        fs::create_dir_all(sysctl_path.parent().unwrap()).unwrap();
        fs::write(&sysctl_path, b"1\n").unwrap();

        let val = read_sysctl(dir.path(), "net/ipv4/ip_forward").unwrap();
        assert_eq!(val.as_deref(), Some("1"));

        let absent = read_sysctl(dir.path(), "nonexistent/sysctl").unwrap();
        assert_eq!(absent, None);
    }

    #[test]
    fn test_ensure_ipv6_forward() {
        let dir = tempdir().expect("tempdir");
        let sysctl_path = dir.path().join(IPV6_FORWARD_SYSCTL_REL_PATH);
        fs::create_dir_all(sysctl_path.parent().unwrap()).unwrap();
        fs::write(&sysctl_path, b"0\n").unwrap();

        assert!(ensure_ipv6_forward_in_root(dir.path()).is_ok());
        let val = fs::read_to_string(&sysctl_path).unwrap();
        assert_eq!(val.trim(), "1");
    }
}
