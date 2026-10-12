use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KubeletError {
    #[error("missing required credential for {component} at {path:?}")]
    MissingCredential {
        path: PathBuf,
        component: &'static str,
    },

    #[error("kubelet authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    #[error("Kubernetes API server unavailable: {reason}")]
    ApiserverUnavailable { reason: String },

    #[error("CRI runtime endpoint '{endpoint}' unavailable: {reason}")]
    RuntimeUnavailable { endpoint: String, reason: String },

    #[error("invalid kubelet configuration field '{field}': {reason}")]
    InvalidConfiguration { field: String, reason: String },

    #[error("node registration failed: {reason}")]
    NodeRegistrationFailed { reason: String },

    #[error("pod reconciliation failed for '{pod}': {reason}")]
    PodReconciliationFailed { pod: String, reason: String },

    #[error("container operation failed for '{container}': {reason}")]
    ContainerOperationFailed { container: String, reason: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("API server error: {0}")]
    Apiserver(#[from] diorama_apiserver::ApiserverError),

    #[error("Network error: {0}")]
    Network(#[from] diorama_network::NetworkError),
}

impl KubeletError {
    #[must_use]
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::MissingCredential { .. } => "kubelet-credential-missing",
            Self::AuthenticationFailed { .. } => "kubelet-auth-failed",
            Self::ApiserverUnavailable { .. } => "kubelet-apiserver-unavailable",
            Self::RuntimeUnavailable { .. } => "kubelet-runtime-unavailable",
            Self::InvalidConfiguration { .. } => "kubelet-config-invalid",
            Self::NodeRegistrationFailed { .. } => "kubelet-node-registration-failed",
            Self::PodReconciliationFailed { .. } => "kubelet-pod-reconciliation-failed",
            Self::ContainerOperationFailed { .. } => "kubelet-container-operation-failed",
            Self::Io(_) => "kubelet-io-error",
            Self::Serialization(_) => "kubelet-serialization-error",
            Self::Apiserver(_) => "kubelet-apiserver-error",
            Self::Network(_) => "kubelet-network-error",
        }
    }
}
