use diorama_apiserver::ApiserverError;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WebhookError {
    #[error("missing credential '{component}' at {}", path.display())]
    MissingCredential {
        path: PathBuf,
        component: &'static str,
    },

    #[error("invalid webhook configuration for '{field}': {reason}")]
    InvalidConfiguration { field: String, reason: String },

    #[error("TLS authentication or verification failed: {reason}")]
    AuthenticationFailed { reason: String },

    #[error("admission review decoding error: {reason}")]
    DecodeError { reason: String },

    #[error("webhook request not allowed: {reason}")]
    NotAllowed { reason: String },

    #[error("LoadBalancer status update error: {reason}")]
    StatusUpdateFailed { reason: String },

    #[error("apiserver communication error: {0}")]
    Apiserver(#[from] ApiserverError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

impl WebhookError {
    #[must_use]
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::MissingCredential { .. } => "webhook-missing-credential",
            Self::InvalidConfiguration { .. } => "webhook-invalid-configuration",
            Self::AuthenticationFailed { .. } => "webhook-auth-failed",
            Self::DecodeError { .. } => "webhook-decode-error",
            Self::NotAllowed { .. } => "webhook-not-allowed",
            Self::StatusUpdateFailed { .. } => "webhook-status-update-failed",
            Self::Apiserver(_) => "webhook-apiserver-error",
            Self::Io(_) => "webhook-io-error",
            Self::Json(_) => "webhook-json-error",
        }
    }
}
