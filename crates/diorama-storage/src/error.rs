use std::time::Duration;
use thiserror::Error;

/// Storage-related errors during manifest generation, reconciliation, and lifecycle supervision.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Failed to serialize or deserialize JSON manifest payload.
    #[error("failed to serialize manifest: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Invalid storage configuration parameter.
    #[error("invalid storage configuration: {0}")]
    InvalidConfiguration(String),

    /// Manifest generation error.
    #[error("manifest error: {0}")]
    Manifest(String),

    /// Kubernetes API client error.
    #[error("kubernetes API error: {0}")]
    Api(String),

    /// Kubernetes API server error.
    #[error("API server error: {0}")]
    Apiserver(#[from] diorama_apiserver::ApiserverError),

    /// Local-path provisioner readiness timed out.
    #[error("local-path provisioner readiness timed out after {elapsed:?} ({attempts} attempts)")]
    ReadinessTimeout { elapsed: Duration, attempts: u32 },

    /// Local-path provisioner readiness check failed.
    #[error("local-path provisioner readiness failed: {reason}")]
    ReadinessFailed { reason: String },

    /// Reconciliation failed for a specific resource.
    #[error("reconciliation failed for {resource}: {reason}")]
    ReconciliationFailed { resource: String, reason: String },

    /// Storage provisioner is disabled.
    #[error("local-path storage provisioner is disabled")]
    Disabled,

    /// Injected failure for testing failure degradation.
    #[error("injected storage deployment failure: {0}")]
    InjectedFailure(String),

    /// Volume binding failed.
    #[error("volume binding failed: {0}")]
    VolumeBindingFailed(String),

    /// Persistent volume or claim not found.
    #[error("volume not found: {0}")]
    VolumeNotFound(String),

    /// Path security violation (attempt to escape volume root or mutate unrelated host data).
    #[error("path security violation: {0}")]
    PathSecurityViolation(String),

    /// Persistent volume reclaim or teardown failed.
    #[error("volume reclaim failed: {0}")]
    ReclaimFailed(String),

    /// I/O error.
    #[error("storage I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl StorageError {
    #[must_use]
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::Serialization(_) => "storage-serialization-error",
            Self::InvalidConfiguration(_) => "storage-invalid-config",
            Self::Manifest(_) => "storage-manifest-error",
            Self::Api(_) | Self::Apiserver(_) => "storage-api-error",
            Self::ReadinessTimeout { .. } => "storage-readiness-timeout",
            Self::ReadinessFailed { .. } => "storage-readiness-failed",
            Self::ReconciliationFailed { .. } => "storage-reconciliation-failed",
            Self::Disabled => "storage-provisioner-disabled",
            Self::InjectedFailure(_) => "storage-injected-failure",
            Self::VolumeBindingFailed(_) => "storage-volume-binding-failed",
            Self::VolumeNotFound(_) => "storage-volume-not-found",
            Self::PathSecurityViolation(_) => "storage-path-security-violation",
            Self::ReclaimFailed(_) => "storage-reclaim-failed",
            Self::Io(_) => "storage-io-error",
        }
    }
}

pub type Result<T> = std::result::Result<T, StorageError>;
