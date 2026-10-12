//! Lifecycle ownership boundaries, non-ownership enforcement, and build/runtime validation.
//!
//! Enforces strict non-interference with host-managed CRI runtimes (containerd, CRI-O):
//! - Host runtime process is never killed or signalled on start, stop, restart, or uninstall.
//! - Host sockets, state directories, and registry configs are never deleted or modified.
//! - Unrelated host workloads (containers and sandboxes) remain untouched.
//! - Only owned CNI configuration is managed (deferred to E15); host CNI is untouched.
//! - External-dependency builds (`external_deps`) and external runtime modes are validated as distinct choices.

use std::fmt;
use std::path::{Path, PathBuf};

/// Error returned when a lifecycle or cleanup operation violates external runtime ownership.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnershipViolation {
    /// Attempted to mutate or delete a host-managed runtime path or socket.
    ProtectedPath { path: PathBuf, reason: &'static str },
    /// Attempted to terminate a host-managed runtime process.
    ProtectedProcess { pid: u32 },
    /// Attempted to delete or stop an unrelated host workload.
    UnrelatedWorkload { id: String },
    /// Attempted to mutate a non-owned host CNI configuration path.
    NonOwnedCniPath { path: PathBuf },
    /// Attempted an invalid combination of build profile and runtime mode.
    InvalidCombination {
        build_profile: BuildProfile,
        runtime_mode: RuntimeMode,
        reason: &'static str,
    },
}

impl fmt::Display for OwnershipViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtectedPath { path, reason } => {
                write!(
                    f,
                    "external runtime ownership violation: protected path '{}' cannot be mutated or removed ({reason})",
                    path.display()
                )
            },
            Self::ProtectedProcess { pid } => {
                write!(
                    f,
                    "external runtime ownership violation: host runtime process (PID {pid}) cannot be signalled or terminated"
                )
            },
            Self::UnrelatedWorkload { id } => {
                write!(
                    f,
                    "external runtime ownership violation: unrelated host workload '{id}' cannot be modified or purged"
                )
            },
            Self::NonOwnedCniPath { path } => {
                write!(
                    f,
                    "external runtime ownership violation: non-owned CNI path '{}' cannot be modified (external mode allows only owned CNI configuration)",
                    path.display()
                )
            },
            Self::InvalidCombination {
                build_profile,
                runtime_mode,
                reason,
            } => {
                write!(
                    f,
                    "invalid build profile ({build_profile:?}) and runtime mode ({runtime_mode:?}) combination: {reason}"
                )
            },
        }
    }
}

impl std::error::Error for OwnershipViolation {}

/// Build profile distinguishing standalone binaries with bundled assets from external-dependency builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BuildProfile {
    /// Standard distribution binary containing embedded payloads (bundled containerd, crun, etc.).
    Bundled,
    /// Lean binary built without embedded payloads; relies strictly on host-installed dependencies.
    ExternalDeps,
}

impl BuildProfile {
    /// Returns true if this build profile embeds runtime binaries.
    #[must_use]
    pub const fn has_embedded_binaries(self) -> bool {
        matches!(self, Self::Bundled)
    }
}

/// Runtime attachment mode requested at launch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeMode {
    /// diorama manages its own bundled containerd instance.
    Managed,
    /// diorama attaches to a host-managed external CRI runtime endpoint.
    External,
}

impl RuntimeMode {
    /// Returns true if external runtime attachment is requested.
    #[must_use]
    pub const fn is_external(self) -> bool {
        matches!(self, Self::External)
    }
}

/// Validates the cross-product matrix of build profile and runtime mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildAndRuntimeMatrix {
    pub build_profile: BuildProfile,
    pub runtime_mode: RuntimeMode,
}

impl BuildAndRuntimeMatrix {
    /// Evaluates whether the given build profile and runtime mode are a valid combination.
    ///
    /// # Errors
    /// Returns `OwnershipViolation::InvalidCombination` if `ExternalDeps` is paired with
    /// `Managed`, because an external-dependencies build contains no embedded runtime binaries
    /// to spawn or manage.
    pub fn validate(
        build_profile: BuildProfile,
        runtime_mode: RuntimeMode,
    ) -> Result<Self, OwnershipViolation> {
        match (build_profile, runtime_mode) {
            (BuildProfile::Bundled, _) | (BuildProfile::ExternalDeps, RuntimeMode::External) => {
                Ok(Self {
                    build_profile,
                    runtime_mode,
                })
            },
            (BuildProfile::ExternalDeps, RuntimeMode::Managed) => {
                Err(OwnershipViolation::InvalidCombination {
                    build_profile,
                    runtime_mode,
                    reason: "external-dependency builds omit embedded runtime binaries and require an external CRI runtime endpoint (--container-runtime-endpoint)",
                })
            },
        }
    }
}

/// Policy governing lifecycle operations for a runtime mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeOwnershipPolicy {
    /// External host-managed runtime: zero lifecycle management.
    External {
        runtime_socket: PathBuf,
        image_socket: PathBuf,
    },
    /// Managed bundled containerd runtime: full lifecycle management.
    Managed {
        data_dir: PathBuf,
        socket_path: PathBuf,
    },
}

impl RuntimeOwnershipPolicy {
    /// Creates an external runtime ownership policy.
    pub fn external(runtime_socket: impl Into<PathBuf>, image_socket: impl Into<PathBuf>) -> Self {
        Self::External {
            runtime_socket: runtime_socket.into(),
            image_socket: image_socket.into(),
        }
    }

    /// Creates a managed runtime ownership policy.
    pub fn managed(data_dir: impl Into<PathBuf>, socket_path: impl Into<PathBuf>) -> Self {
        Self::Managed {
            data_dir: data_dir.into(),
            socket_path: socket_path.into(),
        }
    }

    /// Whether diorama is authorized to manage the daemon's operating process (spawn, kill, wait).
    #[must_use]
    pub const fn allows_process_management(&self) -> bool {
        match self {
            Self::External { .. } => false,
            Self::Managed { .. } => true,
        }
    }

    /// Whether diorama is authorized to execute runtime state cleanup (e.g. purging root/state).
    #[must_use]
    pub const fn allows_runtime_cleanup(&self) -> bool {
        match self {
            Self::External { .. } => false,
            Self::Managed { .. } => true,
        }
    }

    /// Whether diorama is authorized to generate or overwrite daemon configuration files.
    #[must_use]
    pub const fn allows_runtime_reconfiguration(&self) -> bool {
        match self {
            Self::External { .. } => false,
            Self::Managed { .. } => true,
        }
    }

    /// Whether diorama is authorized to unpack local embedded image archives into the runtime.
    #[must_use]
    pub const fn allows_embedded_image_unpacking(&self) -> bool {
        match self {
            Self::External { .. } => false,
            Self::Managed { .. } => true,
        }
    }

    /// Validates that a path targeted for cleanup or removal does not touch external runtime resources.
    ///
    /// # Errors
    /// Returns `OwnershipViolation::ProtectedPath` if in external mode and the target path
    /// matches or resides within host runtime sockets, registry paths, or known system directories.
    pub fn validate_cleanup_path(&self, target: &Path) -> Result<(), OwnershipViolation> {
        match self {
            Self::Managed { .. } => Ok(()),
            Self::External {
                runtime_socket,
                image_socket,
            } => {
                if target
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
                {
                    return Err(OwnershipViolation::ProtectedPath {
                        path: target.to_path_buf(),
                        reason: "path contains parent-directory components",
                    });
                }

                if target == runtime_socket
                    || target.starts_with(runtime_socket)
                    || runtime_socket.starts_with(target)
                {
                    return Err(OwnershipViolation::ProtectedPath {
                        path: target.to_path_buf(),
                        reason: "matches or contains external CRI runtime socket",
                    });
                }
                if target == image_socket
                    || target.starts_with(image_socket)
                    || image_socket.starts_with(target)
                {
                    return Err(OwnershipViolation::ProtectedPath {
                        path: target.to_path_buf(),
                        reason: "matches or contains external CRI image socket",
                    });
                }

                // Check against common host runtime paths
                let protected_prefixes = [
                    Path::new("/run/containerd"),
                    Path::new("/var/run/containerd"),
                    Path::new("/var/lib/containerd"),
                    Path::new("/etc/containerd"),
                    Path::new("/run/crio"),
                    Path::new("/var/run/crio"),
                    Path::new("/var/lib/crio"),
                    Path::new("/etc/crio"),
                    Path::new("/etc/containers"),
                ];

                for prefix in protected_prefixes {
                    if target == prefix || target.starts_with(prefix) || prefix.starts_with(target)
                    {
                        return Err(OwnershipViolation::ProtectedPath {
                            path: target.to_path_buf(),
                            reason: "path belongs to or contains host-managed runtime installation",
                        });
                    }
                }

                Ok(())
            },
        }
    }

    /// Validates that a process signal/kill target does not target the host runtime process.
    ///
    /// # Errors
    /// Returns `OwnershipViolation::ProtectedProcess` if in external mode and the target PID
    /// matches any known host runtime process PID.
    pub fn validate_process_signal(
        &self,
        target_pid: u32,
        host_runtime_pids: &[u32],
    ) -> Result<(), OwnershipViolation> {
        if matches!(self, Self::External { .. }) && host_runtime_pids.contains(&target_pid) {
            return Err(OwnershipViolation::ProtectedProcess { pid: target_pid });
        }
        Ok(())
    }

    /// Validates that a CNI configuration path targeted for modification or deletion is diorama-owned.
    ///
    /// External mode allows only owned CNI configuration (managed under diorama data directories);
    /// system CNI locations (e.g. `/etc/cni/net.d`, `/opt/cni/bin`) must never be modified.
    ///
    /// # Errors
    /// Returns `OwnershipViolation::NonOwnedCniPath` if in external mode and the target path
    /// resides outside the specified `owned_cni_dir`.
    pub fn validate_cni_configuration(
        &self,
        cni_path: &Path,
        owned_cni_dir: &Path,
    ) -> Result<(), OwnershipViolation> {
        if matches!(self, Self::External { .. }) {
            if cni_path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            {
                return Err(OwnershipViolation::NonOwnedCniPath {
                    path: cni_path.to_path_buf(),
                });
            }
            if !cni_path.starts_with(owned_cni_dir) {
                return Err(OwnershipViolation::NonOwnedCniPath {
                    path: cni_path.to_path_buf(),
                });
            }
        }
        Ok(())
    }
}

/// Workload scoping helper ensuring diorama only interacts with its own workloads on external runtimes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadScoping {
    /// Namespace or prefix identifying diorama-owned workloads.
    owned_namespace: String,
}

impl WorkloadScoping {
    pub fn new(owned_namespace: impl Into<String>) -> Self {
        Self {
            owned_namespace: owned_namespace.into(),
        }
    }

    /// Checks if a pod sandbox is owned by diorama based on namespace or label markers.
    #[must_use]
    pub fn is_sandbox_owned(
        &self,
        namespace: &str,
        labels: &std::collections::BTreeMap<String, String>,
    ) -> bool {
        if namespace == self.owned_namespace {
            return true;
        }
        labels
            .get("io.kubernetes.pod.namespace")
            .map(String::as_str)
            == Some(&self.owned_namespace)
            || labels.contains_key("io.diorama.managed")
    }

    /// Asserts that a workload target is owned before a destructive operation (stop/remove).
    ///
    /// # Errors
    /// Returns `OwnershipViolation::UnrelatedWorkload` if the workload is not owned by diorama.
    pub fn assert_can_modify_sandbox(
        &self,
        sandbox_id: &str,
        namespace: &str,
        labels: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), OwnershipViolation> {
        if self.is_sandbox_owned(namespace, labels) {
            Ok(())
        } else {
            Err(OwnershipViolation::UnrelatedWorkload {
                id: sandbox_id.to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_combinations() {
        assert!(
            BuildAndRuntimeMatrix::validate(BuildProfile::Bundled, RuntimeMode::Managed).is_ok()
        );
        assert!(
            BuildAndRuntimeMatrix::validate(BuildProfile::Bundled, RuntimeMode::External).is_ok()
        );
        assert!(
            BuildAndRuntimeMatrix::validate(BuildProfile::ExternalDeps, RuntimeMode::External)
                .is_ok()
        );

        let err = BuildAndRuntimeMatrix::validate(BuildProfile::ExternalDeps, RuntimeMode::Managed)
            .unwrap_err();
        assert!(matches!(err, OwnershipViolation::InvalidCombination { .. }));
    }

    #[test]
    fn external_ownership_policy_blocks_cleanup_and_processes() {
        let policy = RuntimeOwnershipPolicy::external(
            "/run/containerd/containerd.sock",
            "/run/containerd/containerd.sock",
        );

        assert!(!policy.allows_process_management());
        assert!(!policy.allows_runtime_cleanup());
        assert!(!policy.allows_runtime_reconfiguration());
        assert!(!policy.allows_embedded_image_unpacking());

        // Validate protected cleanup paths
        assert!(
            policy
                .validate_cleanup_path(Path::new("/run/containerd/containerd.sock"))
                .is_err()
        );
        assert!(
            policy
                .validate_cleanup_path(Path::new(
                    "/var/lib/containerd/io.containerd.content.v1.content"
                ))
                .is_err()
        );
        assert!(
            policy
                .validate_cleanup_path(Path::new("/etc/containerd/config.toml"))
                .is_err()
        );
        assert!(
            policy
                .validate_cleanup_path(Path::new("/etc/crio/crio.conf"))
                .is_err()
        );
        assert!(
            policy
                .validate_cleanup_path(Path::new("/var/lib/diorama/disposable"))
                .is_ok()
        );

        // Validate protected process signal
        assert!(policy.validate_process_signal(1234, &[1234, 5678]).is_err());
        assert!(policy.validate_process_signal(9999, &[1234, 5678]).is_ok());

        // Validate CNI configuration
        let owned_cni = Path::new("/var/lib/diorama/cni/conf");
        assert!(
            policy
                .validate_cni_configuration(
                    Path::new("/var/lib/diorama/cni/conf/10-diorama.conflist"),
                    owned_cni
                )
                .is_ok()
        );
        assert!(
            policy
                .validate_cni_configuration(
                    Path::new("/etc/cni/net.d/10-flannel.conflist"),
                    owned_cni
                )
                .is_err()
        );
    }

    #[test]
    fn managed_policy_permits_lifecycle() {
        let policy = RuntimeOwnershipPolicy::managed(
            "/var/lib/diorama/containerd",
            "/var/lib/diorama/containerd/containerd.sock",
        );

        assert!(policy.allows_process_management());
        assert!(policy.allows_runtime_cleanup());
        assert!(policy.allows_runtime_reconfiguration());
        assert!(policy.allows_embedded_image_unpacking());

        assert!(
            policy
                .validate_cleanup_path(Path::new("/run/containerd/containerd.sock"))
                .is_ok()
        );
        assert!(policy.validate_process_signal(1234, &[1234]).is_ok());
    }

    #[test]
    fn workload_scoping_preserves_unrelated() {
        let scoping = WorkloadScoping::new("kube-system");
        let mut labels = std::collections::BTreeMap::new();

        // Owned sandbox in namespace
        assert!(scoping.is_sandbox_owned("kube-system", &labels));
        assert!(
            scoping
                .assert_can_modify_sandbox("sb-1", "kube-system", &labels)
                .is_ok()
        );

        // Owned sandbox via marker label
        labels.insert("io.diorama.managed".into(), "true".into());
        assert!(scoping.is_sandbox_owned("default", &labels));
        assert!(
            scoping
                .assert_can_modify_sandbox("sb-2", "default", &labels)
                .is_ok()
        );

        // Unrelated host container/sandbox
        labels.clear();
        assert!(!scoping.is_sandbox_owned("default", &labels));
        let err = scoping
            .assert_can_modify_sandbox("host-sb", "default", &labels)
            .unwrap_err();
        assert!(matches!(err, OwnershipViolation::UnrelatedWorkload { .. }));
    }
}
