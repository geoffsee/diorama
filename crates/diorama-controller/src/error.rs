use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("missing required credential '{path:?}' for component '{component}'")]
    MissingCredential {
        path: PathBuf,
        component: &'static str,
    },

    #[error("controller authentication to API server failed: {reason}")]
    AuthenticationFailed { reason: String },

    #[error("API server is unavailable: {reason}")]
    ApiserverUnavailable { reason: String },

    #[error("invalid controller configuration for field '{field}': {reason}")]
    InvalidConfiguration { field: String, reason: String },

    #[error("required controller '{controller}' cannot be omitted: {reason}")]
    OmittedRequiredController { controller: String, reason: String },

    #[error("failed to reconcile resource '{resource}': {reason}")]
    ReconciliationFailed { resource: String, reason: String },

    #[error("controller manager service failed to start: {reason}")]
    ServiceStartFailed { reason: String },

    #[error("internal controller error: {reason}")]
    Internal { reason: String },
}

impl ControllerError {
    #[must_use]
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::MissingCredential { .. } => "controller-missing-credential",
            Self::AuthenticationFailed { .. } => "controller-auth-failed",
            Self::ApiserverUnavailable { .. } => "controller-apiserver-unavailable",
            Self::InvalidConfiguration { .. } => "controller-invalid-config",
            Self::OmittedRequiredController { .. } => "controller-omitted-required",
            Self::ReconciliationFailed { .. } => "controller-reconciliation-failed",
            Self::ServiceStartFailed { .. } => "controller-start-failed",
            Self::Internal { .. } => "controller-internal-error",
        }
    }
}
