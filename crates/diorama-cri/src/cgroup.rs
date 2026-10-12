//! CRI runtime cgroup driver query, negotiation, and host fallback detection.
//!
//! Validates `RuntimeConfig` responses and negotiates the cgroup driver
//! (`systemd` vs `cgroupfs`). If the runtime has absent Linux configuration,
//! returns unimplemented, or fails, falls back to host detection rather than
//! fabricating protobuf-zero `systemd`.

use crate::runtime::v1::runtime_service_client::RuntimeServiceClient;
use crate::runtime::v1::{CgroupDriver, RuntimeConfigRequest};
use std::fmt;
use std::path::Path;
use tonic::transport::Channel;

/// Resolved cgroup driver for Kubernetes container execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResolvedCgroupDriver {
    /// systemd cgroup driver.
    Systemd,
    /// cgroupfs cgroup driver.
    Cgroupfs,
}

impl ResolvedCgroupDriver {
    /// Returns the lowercase canonical identifier used by Kubernetes and Kubelet.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::Cgroupfs => "cgroupfs",
        }
    }

    /// Returns `true` if this is the systemd cgroup driver.
    #[must_use]
    pub const fn is_systemd(&self) -> bool {
        matches!(self, Self::Systemd)
    }

    /// Returns the formatted CLI flag for Kubelet configuration.
    #[must_use]
    pub fn as_kubelet_arg(&self) -> String {
        format!("--cgroup-driver={}", self.as_str())
    }
}

impl fmt::Display for ResolvedCgroupDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<ResolvedCgroupDriver> for CgroupDriver {
    fn from(driver: ResolvedCgroupDriver) -> Self {
        match driver {
            ResolvedCgroupDriver::Systemd => Self::Systemd,
            ResolvedCgroupDriver::Cgroupfs => Self::Cgroupfs,
        }
    }
}

/// Provenance of the resolved cgroup driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CgroupDriverSource {
    /// Explicitly reported by the external CRI runtime via `RuntimeService::RuntimeConfig`.
    CriRuntimeConfig,
    /// Fallback to host detection because `RuntimeConfig` had absent Linux configuration,
    /// returned an unimplemented status, or failed.
    HostFallback,
    /// Evaluated from host environment characteristics directly.
    HostDetected,
}

/// Checks if cgroup v2 unified hierarchy is available on the host.
#[must_use]
pub fn is_cgroup_v2() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

/// Checks if systemd is the active init system.
#[must_use]
pub fn is_systemd_running() -> bool {
    Path::new("/run/systemd/private").exists()
}

/// Pure evaluation of host cgroup driver based on cgroup v2 presence and systemd init status.
///
/// Systemd driver requires BOTH cgroup v2 AND active systemd init.
/// Non-systemd hosts (e.g. Alpine/OpenRC) or cgroup v1 hosts resolve to `cgroupfs`.
#[must_use]
pub const fn evaluate_host_cgroup_driver(
    cgroup_v2: bool,
    systemd_running: bool,
) -> ResolvedCgroupDriver {
    if cgroup_v2 && systemd_running {
        ResolvedCgroupDriver::Systemd
    } else {
        ResolvedCgroupDriver::Cgroupfs
    }
}

/// Detects the host's default cgroup driver by inspecting host filesystems.
#[must_use]
pub fn detect_host_cgroup_driver() -> ResolvedCgroupDriver {
    evaluate_host_cgroup_driver(is_cgroup_v2(), is_systemd_running())
}

/// Query the external CRI runtime for its configured cgroup driver via `RuntimeConfig`.
///
/// Returns:
/// - `Ok(Some(driver))` if the runtime explicitly reports a recognized Linux cgroup driver.
/// - `Ok(None)` if the Linux configuration is absent on the wire, the driver number is unknown,
///   or the runtime returns `Unimplemented` (e.g. CRI-O).
/// - `Err(status)` on unexpected gRPC errors.
pub async fn query_cgroup_driver(
    channel: Channel,
) -> Result<Option<ResolvedCgroupDriver>, tonic::Status> {
    let mut client = RuntimeServiceClient::new(channel);
    let request = tonic::Request::new(RuntimeConfigRequest {});
    match client.runtime_config(request).await {
        Ok(response) => {
            let resp = response.into_inner();
            let Some(linux) = resp.linux else {
                return Ok(None);
            };
            match CgroupDriver::try_from(linux.cgroup_driver) {
                Ok(CgroupDriver::Systemd) => Ok(Some(ResolvedCgroupDriver::Systemd)),
                Ok(CgroupDriver::Cgroupfs) => Ok(Some(ResolvedCgroupDriver::Cgroupfs)),
                Err(_) => Ok(None),
            }
        },
        Err(status) if status.code() == tonic::Code::Unimplemented => Ok(None),
        Err(status) => Err(status),
    }
}

/// Negotiate the effective cgroup driver against the external CRI runtime.
///
/// If `RuntimeConfig` returns a recognized cgroup driver, it is used with source
/// `CgroupDriverSource::CriRuntimeConfig`. Otherwise (unimplemented, absent configuration,
/// unknown driver number, or RPC failure), falls back to `host_fallback` with
/// `CgroupDriverSource::HostFallback`.
pub async fn negotiate_cgroup_driver(
    channel: Channel,
    host_fallback: ResolvedCgroupDriver,
) -> (ResolvedCgroupDriver, CgroupDriverSource) {
    match query_cgroup_driver(channel).await {
        Ok(Some(driver)) => (driver, CgroupDriverSource::CriRuntimeConfig),
        Ok(None) | Err(_) => (host_fallback, CgroupDriverSource::HostFallback),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_cgroup_evaluation_matrix() {
        assert_eq!(
            evaluate_host_cgroup_driver(true, true),
            ResolvedCgroupDriver::Systemd
        );
        assert_eq!(
            evaluate_host_cgroup_driver(true, false),
            ResolvedCgroupDriver::Cgroupfs
        );
        assert_eq!(
            evaluate_host_cgroup_driver(false, true),
            ResolvedCgroupDriver::Cgroupfs
        );
        assert_eq!(
            evaluate_host_cgroup_driver(false, false),
            ResolvedCgroupDriver::Cgroupfs
        );
    }

    #[test]
    fn resolved_driver_helpers() {
        assert_eq!(ResolvedCgroupDriver::Systemd.as_str(), "systemd");
        assert_eq!(ResolvedCgroupDriver::Cgroupfs.as_str(), "cgroupfs");
        assert!(ResolvedCgroupDriver::Systemd.is_systemd());
        assert!(!ResolvedCgroupDriver::Cgroupfs.is_systemd());
        assert_eq!(
            ResolvedCgroupDriver::Systemd.as_kubelet_arg(),
            "--cgroup-driver=systemd"
        );
        assert_eq!(
            ResolvedCgroupDriver::Cgroupfs.as_kubelet_arg(),
            "--cgroup-driver=cgroupfs"
        );
    }
}
