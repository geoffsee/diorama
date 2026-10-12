use std::fmt;
use std::fs::OpenOptions;
use std::path::Path;
use std::str::FromStr;

use diorama_network::CommandExecutor;
use serde::{Deserialize, Serialize};

use crate::error::ProxyError;

/// Supported kube-proxy backend modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyMode {
    /// iptables proxy mode using legacy iptables or iptables-nft translation.
    IpTables,
    /// Native nftables proxy mode (stable since Kubernetes 1.31).
    Nftables,
}

impl ProxyMode {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::IpTables => "iptables",
            Self::Nftables => "nftables",
        }
    }
}

impl fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProxyMode {
    type Err = ProxyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "iptables" => Ok(Self::IpTables),
            "nftables" => Ok(Self::Nftables),
            other => Err(ProxyError::InvalidConfiguration {
                field: "proxy-mode".to_string(),
                reason: format!(
                    "unsupported proxy mode '{other}', expected 'iptables' or 'nftables'"
                ),
            }),
        }
    }
}

/// Detects whether the host supports iptables or nftables for kube-proxy.
///
/// Matches upstream `KubeSolo` logic:
/// 1. If `/proc/net/ip_tables_names` exists and `iptables` CLI is usable, select `IpTables`.
/// 2. If `/proc/net/ip_tables_names` exists but `iptables` binary is unavailable, report an actionable error.
/// 3. Otherwise, check if `nft` CLI is available. If so, select `Nftables`.
/// 4. If neither backend is available, report an actionable unsupported capability error.
pub fn detect_proxy_backend(
    sys_root: Option<&Path>,
    executor: &dyn CommandExecutor,
) -> Result<ProxyMode, ProxyError> {
    let proc_root = sys_root.unwrap_or_else(|| Path::new("/"));
    let ip_tables_names = proc_root.join("proc/net/ip_tables_names");

    if ip_tables_names.exists() {
        if let Ok(out) = executor.run("iptables", &["--version"])
            && out.success
        {
            return Ok(ProxyMode::IpTables);
        }

        return Err(ProxyError::UnsupportedCapability {
            reason: "/proc/net/ip_tables_names is present but iptables binary is unavailable or non-functional"
                .to_string(),
            recommendation: "install the iptables package or ensure iptables binary is in PATH"
                .to_string(),
        });
    }

    if let Ok(out) = executor.run("nft", &["--version"])
        && out.success
    {
        tracing::info!(
            component = "kubeproxy",
            "iptables kernel modules not available, using nftables proxy mode"
        );
        return Ok(ProxyMode::Nftables);
    }

    Err(ProxyError::UnsupportedCapability {
        reason: "neither iptables (/proc/net/ip_tables_names) nor nftables (nft) is available on the host"
            .to_string(),
        recommendation: "install iptables or nftables kernel modules and utilities (nftables proxy mode is stable since Kubernetes 1.31)"
            .to_string(),
    })
}

/// Flushes the nftables nat table before kube-proxy starts when running in nftables mode.
///
/// This matches upstream `KubeSolo` behavior (`flushNftablesNat`) to prevent conflicts
/// between native nftables rules (e.g. from container runtimes or rootless netavark)
/// and kube-proxy.
pub fn flush_nftables_nat(executor: &dyn CommandExecutor) -> Result<(), ProxyError> {
    let out = executor
        .run("nft", &["flush", "table", "ip", "nat"])
        .map_err(|e| ProxyError::CommandExecutionFailed {
            command: "nft flush table ip nat".to_string(),
            reason: e.to_string(),
        })?;

    if out.success {
        tracing::info!(
            component = "kubeproxy",
            "flushed nftables ip nat table to avoid nftables conflicts"
        );
    } else {
        let err_lower = out.stderr.to_ascii_lowercase();
        // If the table does not exist, that's completely normal and benign.
        if err_lower.contains("no such file")
            || err_lower.contains("does not exist")
            || err_lower.contains("not found")
        {
            tracing::debug!(
                component = "kubeproxy",
                stderr = %out.stderr.trim(),
                "nft flush table ip nat skipped: table does not exist"
            );
            return Ok(());
        }

        return Err(ProxyError::CommandExecutionFailed {
            command: "nft flush table ip nat".to_string(),
            reason: out.stderr.trim().to_string(),
        });
    }

    Ok(())
}

/// Verifies whether the kernel conntrack sysctl path is writable when required.
///
/// In container mode, kube-proxy zeroes all six conntrack settings and skips writing to
/// `/proc/sys/net/netfilter/nf_conntrack_*`, so read-only `/proc/sys` is fully supported.
/// In host mode, kube-proxy attempts to tune conntrack, which fails if `/proc/sys` is read-only.
/// This probe provides actionable diagnostic feedback instead of opaque startup crash loops.
pub fn check_sysctl_conntrack_writable(
    sys_root: Option<&Path>,
    container_mode: bool,
) -> Result<(), ProxyError> {
    // In container mode, conntrack tuning is explicitly disabled (zeroed), so read-only /proc/sys is allowed.
    if container_mode {
        return Ok(());
    }

    let proc_root = sys_root.unwrap_or_else(|| Path::new("/"));
    let conntrack_dir = proc_root.join("proc/sys/net/netfilter");

    if !conntrack_dir.exists() {
        return Ok(());
    }

    let probe_file = conntrack_dir.join("nf_conntrack_max");
    if probe_file.exists() {
        match OpenOptions::new().write(true).open(&probe_file) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::ReadOnlyFilesystem => {
                Err(ProxyError::ReadOnlySysctl {
                    path: probe_file,
                    reason: "read-only file system (EROFS)".to_string(),
                })
            },
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(ProxyError::ReadOnlySysctl {
                    path: probe_file,
                    reason: format!("write permission denied: {e}"),
                })
            },
            Err(e) if e.raw_os_error() == Some(30) => {
                // EROFS = 30
                Err(ProxyError::ReadOnlySysctl {
                    path: probe_file,
                    reason: "read-only file system (EROFS)".to_string(),
                })
            },
            Err(e) => Err(ProxyError::ReadOnlySysctl {
                path: probe_file,
                reason: format!("sysctl writability check failed: {e}"),
            }),
        }
    } else {
        Ok(())
    }
}
