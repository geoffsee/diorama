//! Supported Go-to-Rust starting versions and version classification.
//!
//! `KubeSolo` historical versions are compared numerically.
//! Supported starting versions for migration to Diorama:
//! - `v1.1.8`: Legacy CLI flags in service file, pre-config file support.
//! - `v1.2.0`: Legacy CLI flags in service file, seamless upgrades introduced.
//! - `v1.3.0`: Introduced YAML configuration (`/etc/diorama-kube/config.yaml`), `MinConfigFileVersion` gate.
//! - `v1.3.1`, `v1.3.2`, `v1.3.3`: Post-config file releases, `KubeSolo` baseline `2ef1c47`.
//!
//! Versions `< v1.1.0` or invalid/unparseable versions are explicitly rejected.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Supported historical Go `KubeSolo` starting versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SupportedStartingVersion {
    V1_1_8,
    V1_2_0,
    V1_3_0,
    V1_3_1,
    V1_3_2,
    V1_3_3,
}

impl SupportedStartingVersion {
    /// All supported starting versions in chronological order.
    pub const ALL: [Self; 6] = [
        Self::V1_1_8,
        Self::V1_2_0,
        Self::V1_3_0,
        Self::V1_3_1,
        Self::V1_3_2,
        Self::V1_3_3,
    ];

    /// Returns the canonical version tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1_1_8 => "v1.1.8",
            Self::V1_2_0 => "v1.2.0",
            Self::V1_3_0 => "v1.3.0",
            Self::V1_3_1 => "v1.3.1",
            Self::V1_3_2 => "v1.3.2",
            Self::V1_3_3 => "v1.3.3",
        }
    }

    /// Whether this starting version natively supports `--config=/etc/diorama-kube/config.yaml`.
    /// Versions `>= v1.3.0` support config files.
    #[must_use]
    pub const fn supports_config_file(self) -> bool {
        matches!(
            self,
            Self::V1_3_0 | Self::V1_3_1 | Self::V1_3_2 | Self::V1_3_3
        )
    }

    /// Whether this version requires migrating CLI flags from the init service definition into YAML.
    #[must_use]
    pub const fn requires_flag_migration(self) -> bool {
        !self.supports_config_file()
    }

    /// Description of the state layout in this version.
    #[must_use]
    pub const fn layout_description(self) -> &'static str {
        match self {
            Self::V1_1_8 => "Legacy flags in service unit, persistent PKI, Kine SQLite datastore",
            Self::V1_2_0 => {
                "Legacy flags in service unit, persistent CA/PKI, external runtime support"
            },
            Self::V1_3_0 => {
                "YAML config file, persistent PKI with IP auto-regeneration, Kine SQLite"
            },
            Self::V1_3_1 | Self::V1_3_2 | Self::V1_3_3 => {
                "YAML config file, persistent PKI, external runtime & CRI support, Kine SQLite"
            },
        }
    }
}

impl fmt::Display for SupportedStartingVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Error returned when an unsupported or malformed version is encountered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnsupportedVersionError {
    Empty,
    Malformed(String),
    BelowMinimumSupported {
        version: String,
        minimum: &'static str,
    },
    Unrecognized(String),
}

impl fmt::Display for UnsupportedVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "version string cannot be empty"),
            Self::Malformed(v) => write!(f, "malformed version string '{v}': expected vX.Y.Z"),
            Self::BelowMinimumSupported { version, minimum } => {
                write!(
                    f,
                    "version '{version}' is below minimum supported migration version ({minimum})"
                )
            },
            Self::Unrecognized(v) => {
                write!(f, "unrecognized or unsupported starting version '{v}'")
            },
        }
    }
}

impl std::error::Error for UnsupportedVersionError {}

/// Minimum supported migration baseline version.
pub const MINIMUM_SUPPORTED_VERSION: &str = "v1.1.8";

/// Classifies a starting version string into a supported starting version.
///
/// Strips leading `v` or `V` for comparison.
/// Returns an error if the version is unparseable, below `v1.1.8`, or not a recognized Go release.
pub fn classify_starting_version(
    raw: &str,
) -> Result<SupportedStartingVersion, UnsupportedVersionError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(UnsupportedVersionError::Empty);
    }

    let parsed = diorama_config::semver::parse_version(trimmed)
        .ok_or_else(|| UnsupportedVersionError::Malformed(trimmed.to_string()))?;

    // Check minimum supported version: major >= 1, and if major == 1: minor > 1 or (minor == 1 && patch >= 8)
    if parsed.major < 1
        || (parsed.major == 1 && (parsed.minor < 1 || (parsed.minor == 1 && parsed.patch < 8)))
    {
        return Err(UnsupportedVersionError::BelowMinimumSupported {
            version: trimmed.to_string(),
            minimum: MINIMUM_SUPPORTED_VERSION,
        });
    }

    match (parsed.major, parsed.minor, parsed.patch) {
        (1, 1, 8) => Ok(SupportedStartingVersion::V1_1_8),
        (1, 2, 0) => Ok(SupportedStartingVersion::V1_2_0),
        (1, 3, 0) => Ok(SupportedStartingVersion::V1_3_0),
        (1, 3, 1) => Ok(SupportedStartingVersion::V1_3_1),
        (1, 3, 2) => Ok(SupportedStartingVersion::V1_3_2),
        (1, 3, 3) => Ok(SupportedStartingVersion::V1_3_3),
        _ => Err(UnsupportedVersionError::Unrecognized(trimmed.to_string())),
    }
}
