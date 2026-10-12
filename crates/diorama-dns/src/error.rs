use std::time::Duration;
use thiserror::Error;

/// Errors produced during `CoreDNS` manifest generation, reconciliation, and lifecycle.
#[derive(Debug, Error)]
pub enum DnsError {
    #[error("failed to serialize resource to JSON: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid DNS configuration: {0}")]
    InvalidConfig(String),

    #[error("manifest validation error: {0}")]
    Validation(String),

    #[error("kubernetes API error: {0}")]
    Api(String),

    #[error("API server error: {0}")]
    Apiserver(#[from] diorama_apiserver::ApiserverError),

    #[error("CoreDNS readiness check timed out after {elapsed:?} ({attempts} attempts)")]
    ReadinessTimeout { elapsed: Duration, attempts: u32 },

    #[error("CoreDNS readiness failed: {reason}")]
    ReadinessFailed { reason: String },

    #[error("reconciliation failed for {resource}: {reason}")]
    ReconciliationFailed { resource: String, reason: String },

    #[error("DNS wire format encoding/decoding error: {0}")]
    Wire(String),

    #[error("DNS probe failed: {0}")]
    ProbeFailed(String),

    #[error("DNS I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl DnsError {
    #[must_use]
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::Serialization(_) => "dns-serialization-error",
            Self::InvalidConfig(_) => "dns-invalid-config",
            Self::Validation(_) => "dns-validation-error",
            Self::Api(_) | Self::Apiserver(_) => "dns-api-error",
            Self::ReadinessTimeout { .. } => "dns-readiness-timeout",
            Self::ReadinessFailed { .. } => "dns-readiness-failed",
            Self::ReconciliationFailed { .. } => "dns-reconciliation-failed",
            Self::Wire(_) => "dns-wire-error",
            Self::ProbeFailed(_) => "dns-probe-failed",
            Self::Io(_) => "dns-io-error",
        }
    }
}

pub type Result<T> = std::result::Result<T, DnsError>;
