use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use crate::error::NetworkError;

const IPV6_SYSCTL_REL_PATHS: [&str; 3] = [
    "net/ipv6/conf/all/disable_ipv6",
    "net/ipv6/conf/default/disable_ipv6",
    "net/ipv6/conf/lo/disable_ipv6",
];

/// Returns true if an IO error on sysctl read/write can be safely ignored (e.g. read-only container root or missing path).
#[must_use]
pub fn is_ignorable_sysctl_error(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::NotFound | ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
    )
}

/// Writes `1` to kernel sysctl paths to disable IPv6 on all interfaces.
///
/// Idempotent: paths already set to `1` are skipped.
/// Missing paths or permission errors (e.g. read-only `/proc/sys`) are skipped gracefully.
pub fn disable_ipv6_sysctls() -> Result<(), NetworkError> {
    disable_ipv6_sysctls_in_root(Path::new("/proc/sys"))
}

/// Disables IPv6 sysctls relative to the specified sysctl root directory.
pub fn disable_ipv6_sysctls_in_root(sysctl_root: &Path) -> Result<(), NetworkError> {
    let mut errors = Vec::new();

    for rel in IPV6_SYSCTL_REL_PATHS {
        let path = sysctl_root.join(rel);
        match fs::read(&path) {
            Ok(bytes) => {
                if let Some(&first) = bytes.first()
                    && first == b'1'
                {
                    tracing::debug!(
                        component = "network",
                        path = %path.display(),
                        "ipv6 already disabled"
                    );
                    continue;
                }
            },
            Err(e) if is_ignorable_sysctl_error(e.kind()) => {
                tracing::debug!(
                    component = "network",
                    path = %path.display(),
                    error = %e,
                    "ipv6 sysctl not available, skipping"
                );
                continue;
            },
            Err(e) => {
                tracing::warn!(
                    component = "network",
                    path = %path.display(),
                    error = %e,
                    "failed to read ipv6 sysctl"
                );
            },
        }

        if let Err(e) = fs::write(&path, b"1") {
            if is_ignorable_sysctl_error(e.kind()) {
                tracing::debug!(
                    component = "network",
                    path = %path.display(),
                    error = %e,
                    "ipv6 sysctl write not permitted or path missing, skipping"
                );
            } else {
                errors.push(NetworkError::SysctlError {
                    path: path.display().to_string(),
                    reason: format!("{e}"),
                });
            }
        } else {
            tracing::info!(
                component = "network",
                path = %path.display(),
                "disabled ipv6"
            );
        }
    }

    if let Some(first_err) = errors.into_iter().next() {
        return Err(first_err);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    #[test]
    fn test_is_ignorable_sysctl_error() {
        assert!(is_ignorable_sysctl_error(ErrorKind::NotFound));
        assert!(is_ignorable_sysctl_error(ErrorKind::PermissionDenied));
        assert!(is_ignorable_sysctl_error(ErrorKind::ReadOnlyFilesystem));
        assert!(!is_ignorable_sysctl_error(ErrorKind::Other));
        assert!(!is_ignorable_sysctl_error(ErrorKind::AlreadyExists));
    }
}
