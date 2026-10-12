use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::ControllerError;

/// List of critical controllers that single-node Kubernetes workloads require.
/// These controllers must never be silently omitted by historical allowlists
/// (per upstream PR #40, #68, #111).
pub const REQUIRED_CONTROLLERS: &[&str] = &[
    "deployment",
    "replicaset",
    "statefulset",
    "daemonset",
    "job",
    "cronjob",
    "garbagecollector",
    "endpointslice",
    "endpoints",
    "namespace",
    "serviceaccount",
    "serviceaccount-token",
    "resourcequota",
    "ttl-after-finished",
    "podgc",
];

pub const DEFAULT_SECURE_PORT: u16 = 10257;
pub const DEFAULT_CONCURRENT_ENDPOINT_SYNCS: usize = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControllerManagerConfig {
    /// Path to kubeconfig used to authenticate with kube-apiserver as system:kube-controller-manager.
    pub kubeconfig: PathBuf,
    /// Path to root CA certificate used for cluster trust verification.
    pub root_ca_file: PathBuf,
    /// Path to service-account RSA private key used for signing/verifying service-account tokens.
    pub service_account_private_key_file: PathBuf,
    /// List of enabled controllers (defaults to `["*"]` for full upstream Kubernetes set).
    pub controllers: Vec<String>,
    /// Delay between `EndpointSlice` batch updates (0s per PR #111 / KS-29).
    pub endpointslice_updates_batch_period: Duration,
    /// Delay between Endpoints batch updates (0s per PR #111 / KS-29).
    pub endpoint_updates_batch_period: Duration,
    /// Number of concurrent Endpoint/EndpointSlice sync workers (5 per PR #111).
    pub concurrent_endpoint_syncs: usize,
    /// Secure HTTPS port for controller healthz and metrics endpoints.
    pub secure_port: u16,
    /// Bind address for secure HTTPS endpoint.
    pub bind_address: IpAddr,
    /// Whether leader election is enabled (false for dedicated single-node diorama).
    pub leader_elect: bool,
    /// Optional node IP.
    pub node_ip: Option<IpAddr>,
}

impl Default for ControllerManagerConfig {
    fn default() -> Self {
        Self {
            kubeconfig: PathBuf::from("/etc/kubernetes/kube-controller-manager.kubeconfig"),
            root_ca_file: PathBuf::from("/etc/kubernetes/pki/ca.crt"),
            service_account_private_key_file: PathBuf::from(
                "/etc/kubernetes/pki/service-account.key",
            ),
            controllers: vec!["*".to_string()],
            endpointslice_updates_batch_period: Duration::ZERO,
            endpoint_updates_batch_period: Duration::ZERO,
            concurrent_endpoint_syncs: DEFAULT_CONCURRENT_ENDPOINT_SYNCS,
            secure_port: DEFAULT_SECURE_PORT,
            bind_address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            leader_elect: false,
            node_ip: None,
        }
    }
}

impl ControllerManagerConfig {
    /// Creates a default configuration rooted in the specified PKI directory.
    pub fn default_for_pki(pki_dir: impl AsRef<Path>, node_ip: IpAddr) -> Self {
        let pki = pki_dir.as_ref();
        Self {
            kubeconfig: pki.join("kube-controller-manager.kubeconfig"),
            root_ca_file: pki.join("ca.crt"),
            service_account_private_key_file: pki.join("service-account.key"),
            controllers: vec!["*".to_string()],
            endpointslice_updates_batch_period: Duration::ZERO,
            endpoint_updates_batch_period: Duration::ZERO,
            concurrent_endpoint_syncs: DEFAULT_CONCURRENT_ENDPOINT_SYNCS,
            secure_port: DEFAULT_SECURE_PORT,
            bind_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            leader_elect: false,
            node_ip: Some(node_ip),
        }
    }

    /// Validates that no required single-node controllers are omitted or explicitly disabled.
    /// Returns `Ok(())` if controllers is `["*"]` or contains all required controllers.
    pub fn validate_controllers(&self) -> Result<(), ControllerError> {
        if self.controllers.is_empty() {
            return Err(ControllerError::InvalidConfiguration {
                field: "controllers".to_string(),
                reason: "controller list cannot be empty".to_string(),
            });
        }

        // Reject any required controller explicitly disabled with '-' prefix
        for &req in REQUIRED_CONTROLLERS {
            if self
                .controllers
                .iter()
                .any(|c| c.strip_prefix('-') == Some(req))
            {
                return Err(ControllerError::OmittedRequiredController {
                    controller: req.to_string(),
                    reason: format!("required controller '{req}' is explicitly disabled"),
                });
            }
        }

        // "*" enables all upstream controllers
        if self.controllers.iter().any(|c| c == "*") {
            return Ok(());
        }

        // Check if any required controller is missing from an explicit allowlist
        for &req in REQUIRED_CONTROLLERS {
            let present = self
                .controllers
                .iter()
                .any(|c| c.trim_start_matches('+') == req);
            if !present {
                return Err(ControllerError::OmittedRequiredController {
                    controller: req.to_string(),
                    reason: format!(
                        "historical allowlist omitted required controller '{req}', dropping required single-node reconciliation"
                    ),
                });
            }
        }

        Ok(())
    }

    /// Validates `EndpointSlice` and `Endpoints` update batch periods match upstream standard defaults (0s).
    pub fn validate_batch_periods(&self) -> Result<(), ControllerError> {
        for (field, value) in [
            (
                "endpointslice_updates_batch_period",
                self.endpointslice_updates_batch_period,
            ),
            (
                "endpoint_updates_batch_period",
                self.endpoint_updates_batch_period,
            ),
        ] {
            if !value.is_zero() {
                return Err(ControllerError::InvalidConfiguration {
                    field: field.to_string(),
                    reason: format!("batch period {value:?} must be 0s per KS-29 / PR #111"),
                });
            }
        }
        Ok(())
    }

    /// Generates command line flags for official kube-controller-manager v1.35.7.
    #[must_use]
    pub fn to_cli_args(&self) -> Vec<String> {
        vec![
            format!("--kubeconfig={}", self.kubeconfig.display()),
            format!("--authentication-kubeconfig={}", self.kubeconfig.display()),
            format!("--authorization-kubeconfig={}", self.kubeconfig.display()),
            format!("--root-ca-file={}", self.root_ca_file.display()),
            format!(
                "--service-account-private-key-file={}",
                self.service_account_private_key_file.display()
            ),
            "--use-service-account-credentials=true".to_string(),
            format!("--controllers={}", self.controllers.join(",")),
            format!(
                "--endpoint-updates-batch-period={}s",
                self.endpoint_updates_batch_period.as_secs()
            ),
            format!(
                "--endpointslice-updates-batch-period={}s",
                self.endpointslice_updates_batch_period.as_secs()
            ),
            format!(
                "--concurrent-endpoint-syncs={}",
                self.concurrent_endpoint_syncs
            ),
            format!("--secure-port={}", self.secure_port),
            format!("--bind-address={}", self.bind_address),
            format!("--leader-elect={}", self.leader_elect),
        ]
    }
}
