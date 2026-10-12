//! CRI endpoint parsing and validation.
//!
//! Supports `unix:///path/to/socket.sock` and absolute filesystem paths.
//! Rejects unsupported schemes (`tcp://`, `http://`, etc.), relative paths,
//! and empty inputs with descriptive errors.

use std::fmt;
use std::path::{Path, PathBuf};

/// A validated CRI socket endpoint.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CriEndpoint {
    path: PathBuf,
}

impl CriEndpoint {
    /// Parse and validate a CRI socket endpoint string.
    ///
    /// Accepts:
    /// - `unix:///path/to/socket.sock`
    /// - `/path/to/socket.sock`
    ///
    /// Rejects non-unix schemes, relative paths, and empty inputs.
    pub fn parse(input: &str) -> Result<Self, EndpointError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(EndpointError::Empty);
        }

        let raw_path = if let Some(stripped) = trimmed.strip_prefix("unix://") {
            stripped
        } else {
            if let Some(idx) = trimmed.find("://") {
                let scheme = &trimmed[..idx];
                return Err(EndpointError::UnsupportedScheme {
                    scheme: scheme.to_string(),
                    input: trimmed.to_string(),
                });
            }
            trimmed
        };

        if !raw_path.starts_with('/') {
            return Err(EndpointError::RelativePath(trimmed.to_string()));
        }

        let path = PathBuf::from(raw_path);
        if path == Path::new("/") {
            return Err(EndpointError::InvalidPath {
                input: trimmed.to_string(),
                reason: "endpoint cannot be the filesystem root '/'",
            });
        }

        Ok(Self { path })
    }

    /// Construct a `CriEndpoint` directly from a validated path.
    pub fn from_path(path: impl Into<PathBuf>) -> Result<Self, EndpointError> {
        let path = path.into();
        Self::parse(&path.to_string_lossy())
    }

    /// Returns the filesystem path to the socket.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the canonical `unix://` formatted URI string.
    #[must_use]
    pub fn uri(&self) -> String {
        format!("unix://{}", self.path.display())
    }
}

impl fmt::Display for CriEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unix://{}", self.path.display())
    }
}

impl std::str::FromStr for CriEndpoint {
    type Err = EndpointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Runtime and Image service endpoint pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeEndpoints {
    /// Socket for CRI `RuntimeService` (container and sandbox management).
    pub runtime: CriEndpoint,
    /// Socket for CRI `ImageService` (image management). Defaults to `runtime` if not specified.
    pub image: CriEndpoint,
}

impl RuntimeEndpoints {
    /// Create a new pair of runtime endpoints. If `image` is `None`, defaults to `runtime`.
    pub fn new(runtime: CriEndpoint, image: Option<CriEndpoint>) -> Self {
        let image = image.unwrap_or_else(|| runtime.clone());
        Self { runtime, image }
    }

    /// Create endpoints pointing to the same socket for runtime and image services.
    pub fn single(endpoint: CriEndpoint) -> Self {
        Self::new(endpoint, None)
    }

    /// Parse runtime and optional image endpoint strings.
    pub fn parse(runtime_str: &str, image_str: Option<&str>) -> Result<Self, EndpointError> {
        let runtime = CriEndpoint::parse(runtime_str)?;
        let image = match image_str {
            Some(s) if !s.trim().is_empty() => Some(CriEndpoint::parse(s)?),
            _ => None,
        };
        Ok(Self::new(runtime, image))
    }
}

/// Errors occurring during CRI endpoint parsing and validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointError {
    Empty,
    UnsupportedScheme { scheme: String, input: String },
    RelativePath(String),
    InvalidPath { input: String, reason: &'static str },
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "CRI endpoint cannot be empty"),
            Self::UnsupportedScheme { scheme, input } => {
                write!(
                    f,
                    "unsupported CRI endpoint scheme '{scheme}' in '{input}'; only 'unix://' sockets are supported"
                )
            },
            Self::RelativePath(input) => {
                write!(
                    f,
                    "CRI socket path must be absolute; received relative path '{input}'"
                )
            },
            Self::InvalidPath { input, reason } => {
                write!(f, "invalid CRI endpoint '{input}': {reason}")
            },
        }
    }
}

impl std::error::Error for EndpointError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_endpoints() {
        let ep1 = CriEndpoint::parse("unix:///run/containerd/containerd.sock").unwrap();
        assert_eq!(ep1.path(), Path::new("/run/containerd/containerd.sock"));
        assert_eq!(ep1.uri(), "unix:///run/containerd/containerd.sock");

        let ep2 = CriEndpoint::parse("/var/run/crio/crio.sock").unwrap();
        assert_eq!(ep2.path(), Path::new("/var/run/crio/crio.sock"));
        assert_eq!(ep2.uri(), "unix:///var/run/crio/crio.sock");

        let pair = RuntimeEndpoints::parse(
            "unix:///run/containerd/containerd.sock",
            Some("unix:///run/containerd/image.sock"),
        )
        .unwrap();
        assert_eq!(
            pair.runtime.path(),
            Path::new("/run/containerd/containerd.sock")
        );
        assert_eq!(pair.image.path(), Path::new("/run/containerd/image.sock"));

        let default_pair =
            RuntimeEndpoints::parse("unix:///run/containerd/containerd.sock", None).unwrap();
        assert_eq!(default_pair.runtime, default_pair.image);
    }

    #[test]
    fn parse_invalid_endpoints() {
        assert_eq!(CriEndpoint::parse(""), Err(EndpointError::Empty));
        assert_eq!(CriEndpoint::parse("   "), Err(EndpointError::Empty));

        assert!(matches!(
            CriEndpoint::parse("tcp://127.0.0.1:2375"),
            Err(EndpointError::UnsupportedScheme { scheme, .. }) if scheme == "tcp"
        ));

        assert!(matches!(
            CriEndpoint::parse("http://localhost/socket.sock"),
            Err(EndpointError::UnsupportedScheme { scheme, .. }) if scheme == "http"
        ));

        assert!(matches!(
            CriEndpoint::parse("relative/socket.sock"),
            Err(EndpointError::RelativePath(_))
        ));

        assert!(matches!(
            CriEndpoint::parse("unix://"),
            Err(EndpointError::RelativePath(_))
        ));

        assert!(matches!(
            CriEndpoint::parse("/"),
            Err(EndpointError::InvalidPath { .. })
        ));
    }
}
