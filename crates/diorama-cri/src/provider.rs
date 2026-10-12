//! External CRI runtime provider selection and metadata.
//!
//! Recognizes official Kubernetes container runtime providers (containerd and CRI-O)
//! and classifies unrecognized engines with informative error reporting.

use std::fmt;

/// Recognized CRI runtime providers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CriProvider {
    /// containerd CRI plugin runtime.
    Containerd,
    /// CRI-O container runtime.
    Crio,
    /// Unrecognized or unsupported runtime engine (e.g. dockershim, frakti).
    Unsupported(String),
}

impl CriProvider {
    /// Returns true if this provider is supported for diorama Kube execution.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Containerd | Self::Crio)
    }

    /// Canonical identifier for the provider.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Containerd => "containerd",
            Self::Crio => "cri-o",
            Self::Unsupported(name) => name.as_str(),
        }
    }
}

impl fmt::Display for CriProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Detects the CRI provider from the `runtime_name` reported in a CRI `VersionResponse`.
#[must_use]
pub fn detect_provider(runtime_name: &str) -> CriProvider {
    let lower = runtime_name.trim().to_lowercase();
    if lower.contains("containerd") {
        CriProvider::Containerd
    } else if lower.contains("cri-o") || lower.contains("crio") {
        CriProvider::Crio
    } else {
        CriProvider::Unsupported(runtime_name.trim().to_string())
    }
}

/// Provider details reported by the CRI runtime service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderInfo {
    pub provider: CriProvider,
    pub runtime_name: String,
    pub runtime_version: String,
    pub runtime_api_version: String,
}

impl ProviderInfo {
    pub fn new(
        runtime_name: impl Into<String>,
        runtime_version: impl Into<String>,
        runtime_api_version: impl Into<String>,
    ) -> Self {
        let runtime_name = runtime_name.into();
        let provider = detect_provider(&runtime_name);
        Self {
            provider,
            runtime_name,
            runtime_version: runtime_version.into(),
            runtime_api_version: runtime_api_version.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_supported_providers() {
        assert_eq!(detect_provider("containerd"), CriProvider::Containerd);
        assert_eq!(
            detect_provider("io.containerd.runc.v2"),
            CriProvider::Containerd
        );
        assert_eq!(
            detect_provider("containerd v2.0.0"),
            CriProvider::Containerd
        );
        assert_eq!(detect_provider("cri-o"), CriProvider::Crio);
        assert_eq!(detect_provider("crio"), CriProvider::Crio);
        assert_eq!(detect_provider("CRI-O v1.31.0"), CriProvider::Crio);
    }

    #[test]
    fn detect_unsupported_providers() {
        let dockershim = detect_provider("docker");
        assert_eq!(dockershim, CriProvider::Unsupported("docker".into()));
        assert!(!dockershim.is_supported());

        let frakti = detect_provider("frakti");
        assert_eq!(frakti, CriProvider::Unsupported("frakti".into()));
        assert!(!frakti.is_supported());

        let custom = detect_provider("custom-engine");
        assert_eq!(custom, CriProvider::Unsupported("custom-engine".into()));
        assert!(!custom.is_supported());
    }
}
