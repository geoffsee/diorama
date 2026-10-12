use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("missing required credential '{path:?}' for component '{component}'")]
    MissingCredential {
        path: PathBuf,
        component: &'static str,
    },

    #[error("invalid proxy configuration for field '{field}': {reason}")]
    InvalidConfiguration { field: String, reason: String },

    #[error("unsupported system networking capability: {reason}. Recommendation: {recommendation}")]
    UnsupportedCapability {
        reason: String,
        recommendation: String,
    },

    #[error(
        "kernel sysctl path '{path}' is read-only: {reason}. Recommendation: enable container mode (--container-mode) so kube-proxy sets all conntrack settings to zero and skips sysctl writes"
    )]
    ReadOnlySysctl { path: PathBuf, reason: String },

    #[error("proxy backend detection failed: {reason}")]
    BackendDetectionFailed { reason: String },

    #[error("proxy health check failed: {reason}")]
    HealthCheckFailed { reason: String },

    #[error("failed to ensure pod masquerade rules: {reason}")]
    MasqueradeFailed { reason: String },

    #[error("kube-proxy service failed to start: {reason}")]
    ServiceStartFailed { reason: String },

    #[error("command execution failed for '{command}': {reason}")]
    CommandExecutionFailed { command: String, reason: String },

    #[error(
        "dataplane probe failed for service '{service}': {reason}. Startup succeeded but dataplane routing is non-functional"
    )]
    DataplaneProbeFailed { service: String, reason: String },

    #[error("no ready endpoints available for service '{service}'")]
    NoReadyEndpoints { service: String },

    #[error("routing rule verification failed for '{rule}': {reason}")]
    RoutingVerificationFailed { rule: String, reason: String },

    #[error("foreign firewall state corrupted or blanket flush detected: {reason}")]
    ForeignFirewallCorrupted { reason: String },

    #[error("internal proxy error: {reason}")]
    Internal { reason: String },
}

impl ProxyError {
    #[must_use]
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::MissingCredential { .. } => "proxy-missing-credential",
            Self::InvalidConfiguration { .. } => "proxy-invalid-config",
            Self::UnsupportedCapability { .. } => "proxy-unsupported-capability",
            Self::ReadOnlySysctl { .. } => "proxy-readonly-sysctl",
            Self::BackendDetectionFailed { .. } => "proxy-backend-detection-failed",
            Self::HealthCheckFailed { .. } => "proxy-health-check-failed",
            Self::MasqueradeFailed { .. } => "proxy-masquerade-failed",
            Self::ServiceStartFailed { .. } => "proxy-start-failed",
            Self::CommandExecutionFailed { .. } => "proxy-command-failed",
            Self::DataplaneProbeFailed { .. } => "proxy-dataplane-probe-failed",
            Self::NoReadyEndpoints { .. } => "proxy-no-ready-endpoints",
            Self::RoutingVerificationFailed { .. } => "proxy-routing-verification-failed",
            Self::ForeignFirewallCorrupted { .. } => "proxy-foreign-firewall-corrupted",
            Self::Internal { .. } => "proxy-internal-error",
        }
    }
}
