use thiserror::Error;

/// Error types for network operations and resolution.
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("no usable network interface: {reason}")]
    NoUsableInterface { reason: String },

    #[error("invalid node IP '{ip}': {reason}")]
    InvalidNodeIP { ip: String, reason: String },

    #[error("invalid MTU {mtu}: {reason}")]
    InvalidMTU { mtu: i64, reason: String },

    #[error("resolv.conf error: {reason}")]
    ResolvConfError { reason: String },

    #[error("sysctl error on '{path}': {reason}")]
    SysctlError { path: String, reason: String },

    #[error("cni configuration error: {reason}")]
    CniError { reason: String },

    #[error("serialization error: {reason}")]
    SerializationError { reason: String },

    #[error("masquerade error: {reason}")]
    MasqueradeError { reason: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl NetworkError {
    /// Returns the diagnostic code for this error.
    #[must_use]
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::NoUsableInterface { .. } => "network-no-usable-interface",
            Self::InvalidNodeIP { .. } => "network-invalid-node-ip",
            Self::InvalidMTU { .. } => "network-invalid-mtu",
            Self::ResolvConfError { .. } => "network-resolv-conf-error",
            Self::SysctlError { .. } => "network-sysctl-error",
            Self::CniError { .. } => "network-cni-error",
            Self::SerializationError { .. } => "network-serialization-error",
            Self::MasqueradeError { .. } => "network-masquerade-error",
            Self::Io(_) => "network-io-error",
        }
    }
}
