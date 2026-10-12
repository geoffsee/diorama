//! Cgroup driver and init system detection for containerd runtime options.

use std::path::Path;

/// Check if cgroup v2 unified hierarchy is available on the host.
///
/// Looks for `/sys/fs/cgroup/cgroup.controllers`.
#[must_use]
pub fn is_cgroup_v2() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

/// Check if systemd is the active init system.
///
/// Looks for `/run/systemd/private`.
#[must_use]
pub fn is_systemd_running() -> bool {
    Path::new("/run/systemd/private").exists()
}

/// Determines whether containerd/crun should use `SystemdCgroup = true`.
///
/// Systemd cgroup driver requires BOTH cgroup v2 AND systemd as active init.
/// On non-systemd hosts (e.g. Alpine with `OpenRC`), even if cgroup v2 is present,
/// systemd cgroup driver must not be used.
#[must_use]
pub fn use_systemd_cgroup() -> bool {
    is_cgroup_v2() && is_systemd_running()
}

/// Pure helper for evaluating cgroup driver given boolean host conditions.
#[must_use]
pub const fn evaluate_systemd_cgroup(cgroup_v2: bool, systemd_running: bool) -> bool {
    cgroup_v2 && systemd_running
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_evaluation_matrix() {
        // Only both cgroup v2 and systemd yields true
        assert!(evaluate_systemd_cgroup(true, true));
        assert!(!evaluate_systemd_cgroup(true, false));
        assert!(!evaluate_systemd_cgroup(false, true));
        assert!(!evaluate_systemd_cgroup(false, false));
    }
}
