use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::KubeletError;

/// Supported Cgroup versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KubeletCgroupVersion {
    V1,
    V2,
}

impl KubeletCgroupVersion {
    /// Detects cgroup version from the given cgroup root mount path.
    #[must_use]
    pub fn detect(cgroup_root: &Path) -> Self {
        if cgroup_root.join("cgroup.controllers").exists() {
            Self::V2
        } else {
            Self::V1
        }
    }
}

/// Status of mount propagation preparation for container mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MountPropagationStatus {
    Shared,
    SkippedPermissionDenied,
    SkippedNonLinux,
    SimulatedRshared,
}

/// Status of cgroup preparation for container mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CgroupSetupStatus {
    Configured { controllers: Vec<String>, pid: u32 },
    SkippedNotV2,
    SkippedPermissionDenied,
    Simulated { controllers: Vec<String>, pid: u32 },
}

/// Status of IPv6 sysctl disablement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ipv6DisableStatus {
    Disabled { modified_paths: Vec<PathBuf> },
    AlreadyDisabled,
    SkippedPermissionDenied,
    SkippedNotFound,
    SkippedHostMutationsDisallowed,
}

/// Manages host environment checks, mounts, cgroups, and network adjustments for container mode.
#[derive(Clone, Debug)]
pub struct ContainerEnvironment {
    root_path: PathBuf,
    cgroup_root: PathBuf,
    proc_sys_net_ipv6: PathBuf,
    allow_host_mutations: bool,
    simulated: bool,
    pod_cidr: Option<String>,
    snat_ready: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Default for ContainerEnvironment {
    fn default() -> Self {
        Self {
            root_path: PathBuf::from("/"),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            proc_sys_net_ipv6: PathBuf::from("/proc/sys/net/ipv6/conf"),
            allow_host_mutations: true,
            simulated: false,
            pod_cidr: Some(diorama_network::DEFAULT_POD_CIDR.to_string()),
            snat_ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

impl ContainerEnvironment {
    /// Creates a simulated container environment bounded to custom directories for disposable test fixtures.
    #[must_use]
    pub fn new_simulated(
        root_path: PathBuf,
        cgroup_root: PathBuf,
        proc_sys_net_ipv6: PathBuf,
    ) -> Self {
        Self {
            root_path,
            cgroup_root,
            proc_sys_net_ipv6,
            allow_host_mutations: true,
            simulated: true,
            pod_cidr: Some(diorama_network::DEFAULT_POD_CIDR.to_string()),
            snat_ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    #[must_use]
    pub fn with_pod_cidr(mut self, cidr: impl Into<String>) -> Self {
        self.pod_cidr = Some(cidr.into());
        self
    }

    #[must_use]
    pub fn pod_cidr(&self) -> Option<&str> {
        self.pod_cidr.as_deref()
    }

    #[must_use]
    pub fn is_snat_ready(&self) -> bool {
        self.snat_ready.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn prepare_pod_egress(
        &self,
        pod_cidr: &str,
    ) -> Result<Option<diorama_network::MasqueradeBackend>, KubeletError> {
        if !self.allow_host_mutations {
            return Ok(None);
        }
        if self.simulated {
            self.snat_ready
                .store(true, std::sync::atomic::Ordering::SeqCst);
            return Ok(Some(diorama_network::MasqueradeBackend::IpTables));
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = pod_cidr;
            Ok(None)
        }

        #[cfg(target_os = "linux")]
        {
            if let Err(e) = diorama_network::ensure_ip_forward() {
                match e {
                    diorama_network::NetworkError::SysctlError { ref reason, .. }
                        if reason.contains("Permission denied")
                            || reason.contains("Read-only file system") =>
                    {
                        return Ok(None);
                    },
                    _ => return Err(KubeletError::Network(e)),
                }
            }

            match diorama_network::ensure_pod_masquerade(pod_cidr) {
                Ok(backend) => {
                    self.snat_ready
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(Some(backend))
                },
                Err(diorama_network::NetworkError::MasqueradeError { reason })
                    if reason.contains("Permission denied")
                        || reason.contains("you must be root") =>
                {
                    Ok(None)
                },
                Err(e) => Err(KubeletError::Network(e)),
            }
        }
    }

    #[must_use]
    pub fn with_allow_host_mutations(mut self, allow: bool) -> Self {
        self.allow_host_mutations = allow;
        self
    }

    #[must_use]
    pub fn cgroup_root(&self) -> &Path {
        &self.cgroup_root
    }

    #[must_use]
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    #[must_use]
    pub fn proc_sys_net_ipv6(&self) -> &Path {
        &self.proc_sys_net_ipv6
    }

    #[must_use]
    pub fn is_simulated(&self) -> bool {
        self.simulated
    }

    #[must_use]
    pub fn allow_host_mutations(&self) -> bool {
        self.allow_host_mutations
    }

    /// Detects if the current process is running inside a container.
    #[must_use]
    pub fn is_container_detected() -> bool {
        Path::new("/.dockerenv").exists()
            || Path::new("/run/.containerenv").exists()
            || std::env::var_os("container").is_some_and(|val| !val.is_empty())
    }

    /// Prepares mount propagation on the root filesystem for container mode (`rshared`).
    ///
    /// In container mode, Kubernetes requires `/` to have `rshared` propagation so that volume
    /// mounts (projected service-account tokens, configmaps, secrets) can propagate into pods.
    /// In an unprivileged or nested-runtime fixture where mount operations are not permitted,
    /// this gracefully detects and logs the restriction without halting the node.
    pub fn prepare_mounts(&self) -> Result<MountPropagationStatus, KubeletError> {
        if self.simulated {
            return Ok(MountPropagationStatus::SimulatedRshared);
        }

        #[cfg(target_os = "linux")]
        {
            if !self.allow_host_mutations {
                return Ok(MountPropagationStatus::SimulatedRshared);
            }

            // On Linux, invoke remount with MS_REC | MS_SHARED
            // If running unprivileged or permission denied, handle gracefully
            let status = std::process::Command::new("mount")
                .arg("--make-rshared")
                .arg(&self.root_path)
                .status();

            match status {
                Ok(exit) if exit.success() => Ok(MountPropagationStatus::Shared),
                Ok(_) | Err(_) => Ok(MountPropagationStatus::SkippedPermissionDenied),
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(MountPropagationStatus::SkippedNonLinux)
        }
    }

    /// Prepares cgroup v2 hierarchy for nested container workloads.
    ///
    /// In cgroup v2, a cgroup cannot simultaneously host processes and delegate controllers
    /// to child cgroups (the "no internal processes" constraint). To avoid this conflict:
    /// - If not cgroup v2 (e.g. cgroup v1), skips setup cleanly.
    /// - If cgroup v2, creates `<cgroup_root>/init`, moves **every** process listed in
    ///   `<cgroup_root>/cgroup.procs` (plus `pid`) into it, and enables available
    ///   controllers on `<cgroup_root>/cgroup.subtree_control`.
    ///
    /// Moving only the caller leaves siblings behind (entrypoint shell, supervisor
    /// children), so the subtree write fails with `EBUSY` and pods can never start.
    pub fn prepare_cgroups(&self, pid: u32) -> Result<CgroupSetupStatus, KubeletError> {
        if !self.allow_host_mutations {
            return Ok(CgroupSetupStatus::Simulated {
                controllers: Vec::new(),
                pid,
            });
        }

        let controllers_file = self.cgroup_root.join("cgroup.controllers");
        if !controllers_file.exists() {
            return Ok(CgroupSetupStatus::SkippedNotV2);
        }

        let raw_controllers = match fs::read_to_string(&controllers_file) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Ok(CgroupSetupStatus::SkippedPermissionDenied);
            },
            Err(e) => return Err(KubeletError::Io(e)),
        };

        let controllers: Vec<String> = raw_controllers
            .split_whitespace()
            .map(str::to_string)
            .collect();

        let init_cgroup = self.cgroup_root.join("init");
        if let Err(e) = fs::create_dir_all(&init_cgroup) {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                return Ok(CgroupSetupStatus::SkippedPermissionDenied);
            }
            return Err(KubeletError::Io(e));
        }

        // Drain the root cgroup so subtree delegation is legal. Processes that
        // exit mid-migration (ESRCH / InvalidInput) are skipped; a permission
        // failure degrades to SkippedPermissionDenied.
        if let Err(e) = migrate_all_procs(&self.cgroup_root, &init_cgroup, pid) {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                return Ok(CgroupSetupStatus::SkippedPermissionDenied);
            }
            return Err(KubeletError::Io(e));
        }

        let subtree_control = self.cgroup_root.join("cgroup.subtree_control");
        let mut enabled_controllers =
            match enable_subtree_controllers(&subtree_control, &controllers) {
                Ok(c) => c,
                Err(status) => return Ok(status),
            };
        if enabled_controllers.len() != controllers.len() {
            // A process may have forked into the root between migration and the
            // write; drain once more and retry the missing controllers.
            let _ = migrate_all_procs(&self.cgroup_root, &init_cgroup, pid);
            let missing: Vec<String> = controllers
                .iter()
                .filter(|c| !enabled_controllers.contains(c))
                .cloned()
                .collect();
            if let Ok(retried) = enable_subtree_controllers(&subtree_control, &missing) {
                enabled_controllers.extend(retried);
            }
        }

        if self.simulated {
            Ok(CgroupSetupStatus::Simulated {
                controllers: enabled_controllers,
                pid,
            })
        } else {
            Ok(CgroupSetupStatus::Configured {
                controllers: enabled_controllers,
                pid,
            })
        }
    }

    /// Disables IPv6 via kernel sysctls for IPv4-only cluster operation.
    ///
    /// Applies to `all`, `default`, and `lo` sub-interfaces under `/proc/sys/net/ipv6/conf`.
    /// Missing paths or permission errors in constrained/unprivileged containers are ignored gracefully.
    pub fn disable_ipv6(&self) -> Result<Ipv6DisableStatus, KubeletError> {
        if !self.allow_host_mutations {
            return Ok(Ipv6DisableStatus::SkippedHostMutationsDisallowed);
        }

        let targets = ["all", "default", "lo"];
        let mut modified = Vec::new();
        let mut all_already_disabled = true;
        let mut permission_denied = false;
        let mut found_any = false;

        for target in targets {
            let path = self.proc_sys_net_ipv6.join(target).join("disable_ipv6");
            if !path.exists() {
                continue;
            }
            found_any = true;

            match fs::read_to_string(&path) {
                Ok(content) => {
                    if content.trim() == "1" {
                        continue;
                    }
                    all_already_disabled = false;
                    match fs::write(&path, "1\n") {
                        Ok(()) => modified.push(path),
                        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                            permission_denied = true;
                        },
                        Err(e) => return Err(KubeletError::Io(e)),
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    permission_denied = true;
                },
                Err(e) => return Err(KubeletError::Io(e)),
            }
        }

        if !found_any {
            Ok(Ipv6DisableStatus::SkippedNotFound)
        } else if !modified.is_empty() {
            Ok(Ipv6DisableStatus::Disabled {
                modified_paths: modified,
            })
        } else if permission_denied {
            Ok(Ipv6DisableStatus::SkippedPermissionDenied)
        } else if all_already_disabled {
            Ok(Ipv6DisableStatus::AlreadyDisabled)
        } else {
            Ok(Ipv6DisableStatus::SkippedNotFound)
        }
    }
}

/// Moves every process in `root/cgroup.procs` plus `pid` into `init/cgroup.procs`.
fn migrate_all_procs(root: &Path, init: &Path, pid: u32) -> Result<(), std::io::Error> {
    use std::collections::BTreeSet;

    let mut pids: BTreeSet<String> = BTreeSet::new();
    pids.insert(pid.to_string());
    if let Ok(listing) = fs::read_to_string(root.join("cgroup.procs")) {
        for token in listing.split_whitespace() {
            pids.insert(token.to_string());
        }
    }
    let target = init.join("cgroup.procs");
    for entry in pids {
        match fs::write(&target, format!("{entry}\n")) {
            Ok(()) => {},
            // The process exited between listing and migration.
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::InvalidInput => {},
            Err(e) if e.raw_os_error() == Some(3) => {},
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn enable_subtree_controllers(
    subtree_control: &Path,
    controllers: &[String],
) -> Result<Vec<String>, CgroupSetupStatus> {
    if controllers.is_empty() {
        return Ok(Vec::new());
    }

    let enable_str = controllers
        .iter()
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>()
        .join(" ");

    match fs::write(subtree_control, &enable_str) {
        Ok(()) => Ok(controllers.to_vec()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(CgroupSetupStatus::SkippedPermissionDenied)
        },
        Err(_) => {
            let mut enabled = Vec::new();
            for c in controllers {
                let single = format!("+{c}\n");
                if fs::write(subtree_control, single).is_ok() {
                    enabled.push(c.clone());
                }
            }
            Ok(enabled)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prepare_pod_egress_when_host_mutations_disallowed() {
        let env = ContainerEnvironment::default().with_allow_host_mutations(false);
        assert!(!env.is_snat_ready());
        let result = env.prepare_pod_egress("10.42.0.0/16").unwrap();
        assert_eq!(result, None);
        assert!(!env.is_snat_ready());
    }

    #[test]
    fn test_prepare_pod_egress_simulated() {
        let env = ContainerEnvironment::new_simulated(
            PathBuf::from("/tmp/root"),
            PathBuf::from("/tmp/cgroup"),
            PathBuf::from("/tmp/ipv6"),
        );
        assert!(!env.is_snat_ready());
        let result = env.prepare_pod_egress("10.42.0.0/16").unwrap();
        assert_eq!(result, Some(diorama_network::MasqueradeBackend::IpTables));
        assert!(env.is_snat_ready());
    }
}
