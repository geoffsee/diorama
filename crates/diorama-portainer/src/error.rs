use std::time::Duration;

use diorama_platform::Architecture;
use thiserror::Error;

/// Errors that can occur during Portainer Edge agent configuration, manifest generation, and lifecycle supervision.
#[derive(Debug, Error)]
pub enum PortainerError {
    /// Portainer Edge agent is explicitly disabled.
    #[error("Portainer edge agent is disabled")]
    Disabled,

    /// Target architecture does not support the Portainer agent image (e.g. RISC-V 64).
    #[error("Portainer edge agent is not supported on architecture {0:?}")]
    UnsupportedArchitecture(Architecture),

    /// Missing both edge ID and edge key credentials.
    #[error("Missing Portainer edge credentials")]
    MissingCredentials,

    /// Only partial credentials provided (either `edge_id` or `edge_key` is missing).
    #[error(
        "Incomplete Portainer edge credentials: edge_id present={has_id}, edge_key present={has_key}"
    )]
    IncompleteCredentials {
        /// Whether `edge_id` was provided.
        has_id: bool,
        /// Whether `edge_key` was provided.
        has_key: bool,
    },

    /// The provided container image reference is invalid.
    #[error("Invalid image reference: {0}")]
    InvalidImage(String),

    /// Resource serialization failed.
    #[error("Resource serialization error: {0}")]
    Serialization(String),

    /// Kubernetes API error occurred.
    #[error("Kubernetes API error: {0}")]
    Api(String),

    /// Kubernetes API server error.
    #[error("API server error: {0}")]
    Apiserver(#[from] diorama_apiserver::ApiserverError),

    /// Portainer agent readiness timed out.
    #[error("Portainer agent readiness timed out after {elapsed:?} ({attempts} attempts)")]
    ReadinessTimeout {
        /// Elapsed time during polling.
        elapsed: Duration,
        /// Number of poll attempts performed.
        attempts: u32,
    },

    /// Reconciliation failed for a specific resource.
    #[error("Reconciliation failed for {resource}: {reason}")]
    ReconciliationFailed {
        /// Name or kind of resource.
        resource: String,
        /// Failure details.
        reason: String,
    },
}

impl From<serde_json::Error> for PortainerError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

impl PortainerError {
    /// Diagnostic code suitable for structured lifecycle logs and supervisor diagnostics.
    #[must_use]
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::Disabled => "portainer_disabled",
            Self::UnsupportedArchitecture(_) => "portainer_unsupported_architecture",
            Self::MissingCredentials => "portainer_missing_credentials",
            Self::IncompleteCredentials { .. } => "portainer_incomplete_credentials",
            Self::InvalidImage(_) => "portainer_invalid_image",
            Self::Serialization(_) => "portainer_serialization_error",
            Self::Api(_) | Self::Apiserver(_) => "portainer_api_error",
            Self::ReadinessTimeout { .. } => "portainer_readiness_timeout",
            Self::ReconciliationFailed { .. } => "portainer_reconciliation_failed",
        }
    }
}

impl PartialEq for PortainerError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Disabled, Self::Disabled)
            | (Self::MissingCredentials, Self::MissingCredentials) => true,
            (Self::UnsupportedArchitecture(a), Self::UnsupportedArchitecture(b)) => a == b,
            (
                Self::IncompleteCredentials {
                    has_id: id_a,
                    has_key: key_a,
                },
                Self::IncompleteCredentials {
                    has_id: id_b,
                    has_key: key_b,
                },
            ) => id_a == id_b && key_a == key_b,
            (Self::InvalidImage(a), Self::InvalidImage(b))
            | (Self::Serialization(a), Self::Serialization(b))
            | (Self::Api(a), Self::Api(b)) => a == b,
            (Self::Apiserver(a), Self::Apiserver(b)) => a.to_string() == b.to_string(),
            (
                Self::ReadinessTimeout {
                    elapsed: el_a,
                    attempts: at_a,
                },
                Self::ReadinessTimeout {
                    elapsed: el_b,
                    attempts: at_b,
                },
            ) => el_a == el_b && at_a == at_b,
            (
                Self::ReconciliationFailed {
                    resource: res_a,
                    reason: why_a,
                },
                Self::ReconciliationFailed {
                    resource: res_b,
                    reason: why_b,
                },
            ) => res_a == res_b && why_a == why_b,
            _ => false,
        }
    }
}

impl Eq for PortainerError {}

/// Result alias for Portainer operations.
pub type Result<T> = std::result::Result<T, PortainerError>;
