use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiserverError {
    #[error("invalid PKI credentials: {reason}")]
    InvalidCredentials { reason: String },

    #[error("persistent storage unusable: {reason}")]
    StorageUnusable { reason: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("datastore error: {0}")]
    Datastore(#[from] diorama_datastore::DatastoreError),

    #[error("PKI error: {0}")]
    Pki(#[from] diorama_pki::PkiError),

    #[error("configuration error: {reason}")]
    Config { reason: String },

    #[error("readiness check failed on {endpoint}: {reason}")]
    ReadinessFailed { endpoint: String, reason: String },

    #[error("unauthenticated: {reason}")]
    Unauthenticated { reason: String },

    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },

    #[error("resource not found: {resource}/{name}")]
    NotFound { resource: String, name: String },

    #[error("resource conflict: {resource}/{name}")]
    Conflict { resource: String, name: String },

    #[error("bad request: {message}")]
    BadRequest { message: String },

    /// A list `continue` token is older than the server keeps. `continue_token`
    /// is the inconsistent token the client should retry with.
    #[error("continue token expired")]
    Expired { continue_token: String },

    #[error("invalid input for {field}: {reason}")]
    InvalidInput { field: String, reason: String },

    #[error("admission denied: {reason}")]
    AdmissionDenied { reason: String },

    #[error("webhook call failed for {webhook}: {reason}")]
    WebhookFailure { webhook: String, reason: String },

    #[error("aggregated API error for {service}: {reason}")]
    AggregatedApiError { service: String, reason: String },

    #[error("internal server error: {reason}")]
    Internal { reason: String },
}

impl ApiserverError {
    #[must_use]
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::InvalidCredentials { .. } | Self::Pki(_) => "apiserver-credentials-invalid",
            Self::StorageUnusable { .. } | Self::Datastore(_) => "apiserver-storage-unusable",
            Self::Config { .. } => "apiserver-config-error",
            Self::ReadinessFailed { .. } => "apiserver-readiness-failed",
            Self::Unauthenticated { .. } => "apiserver-unauthenticated",
            Self::Unauthorized { .. } => "apiserver-unauthorized",
            Self::AdmissionDenied { .. } => "apiserver-admission-denied",
            Self::WebhookFailure { .. } => "apiserver-webhook-failure",
            Self::AggregatedApiError { .. } => "apiserver-aggregated-api-error",
            Self::NotFound { .. } => "apiserver-not-found",
            Self::Conflict { .. } => "apiserver-conflict",
            Self::BadRequest { .. } | Self::InvalidInput { .. } | Self::Expired { .. } => {
                "apiserver-bad-request"
            },
            Self::Internal { .. } => "apiserver-internal-error",
            Self::Io(_) => "apiserver-io-error",
            Self::Serialization(_) => "apiserver-serialization-error",
        }
    }
}
