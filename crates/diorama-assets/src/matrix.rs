use crate::{
    AssetId, DeclaredInventory, Delivery, FeatureSupport, OptionalFeature, Variant, feature_support,
};
use diorama_platform::{Architecture, Libc, NodeTarget};
use std::fmt;

/// Operating system for management release targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ManagementOs {
    Linux,
    Darwin,
}

impl fmt::Display for ManagementOs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linux => write!(f, "linux"),
            Self::Darwin => write!(f, "darwin"),
        }
    }
}

/// Architecture for management release targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ManagementArch {
    Amd64,
    Arm64,
}

impl fmt::Display for ManagementArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Amd64 => write!(f, "amd64"),
            Self::Arm64 => write!(f, "arm64"),
        }
    }
}

/// Supported management CLI target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManagementTarget {
    pub os: ManagementOs,
    pub architecture: ManagementArch,
}

impl ManagementTarget {
    pub const fn new(os: ManagementOs, architecture: ManagementArch) -> Self {
        Self { os, architecture }
    }

    /// Generate reproducible management binary filename: `<prefix>-<os>-<arch>`.
    pub fn binary_filename(&self, prefix: &str) -> String {
        format!("{prefix}-{}-{}", self.os, self.architecture)
    }
}

/// Errors relating to management target evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManagementTargetError {
    WindowsExcluded,
    UnsupportedOs(String),
    UnsupportedArchitecture(String),
}

impl fmt::Display for ManagementTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WindowsExcluded => write!(
                f,
                "Windows management binaries are excluded by E01; WSL2 uses Linux userspace"
            ),
            Self::UnsupportedOs(os) => write!(f, "unsupported management OS: {os}"),
            Self::UnsupportedArchitecture(arch) => {
                write!(f, "unsupported management architecture: {arch}")
            },
        }
    }
}

impl std::error::Error for ManagementTargetError {}

/// One of the 16 exhaustive node archive combinations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeVariant {
    pub cell: u8,
    pub architecture: Architecture,
    pub libc: Libc,
    pub variant: Variant,
}

impl NodeVariant {
    pub const fn new(cell: u8, architecture: Architecture, libc: Libc, variant: Variant) -> Self {
        Self {
            cell,
            architecture,
            libc,
            variant,
        }
    }

    pub const fn node_target(&self) -> NodeTarget {
        NodeTarget {
            architecture: self.architecture,
            libc: self.libc,
        }
    }

    /// OCI image platform string for container images on this architecture.
    pub const fn oci_platform(&self) -> &'static str {
        match self.architecture {
            Architecture::Amd64 => "linux/amd64",
            Architecture::Arm64 => "linux/arm64",
            Architecture::ArmV7 => "linux/arm/v7",
            Architecture::Riscv64 => "linux/riscv64",
        }
    }

    /// Policy support for optional features on this target architecture.
    pub fn optional_feature_support(&self, feature: OptionalFeature) -> FeatureSupport {
        feature_support(self.architecture, feature)
    }

    /// Whether an optional feature image payload is bundled in this cell's archive.
    ///
    /// Online archives bundle `CoreDNS` and pause only; optional images require registry pull.
    /// Offline archives bundle all supported optional images for the target architecture.
    pub fn is_image_bundled(&self, feature: OptionalFeature) -> bool {
        match self.variant {
            Variant::Online => false,
            Variant::Offline => {
                self.optional_feature_support(feature) == FeatureSupport::SupportedTarget
            },
        }
    }

    /// Standard archive filename: `<prefix>-<version>-linux-<arch>[-musl][-offline].tar.gz`.
    pub fn archive_filename(&self, prefix: &str, version: &str) -> String {
        let arch_str = match self.architecture {
            Architecture::Amd64 => "amd64",
            Architecture::Arm64 => "arm64",
            Architecture::ArmV7 => "arm",
            Architecture::Riscv64 => "riscv64",
        };
        let libc_suffix = match self.libc {
            Libc::Glibc => "",
            Libc::Musl => "-musl",
        };
        let variant_suffix = match self.variant {
            Variant::Online => "",
            Variant::Offline => "-offline",
        };
        format!("{prefix}-{version}-linux-{arch_str}{libc_suffix}{variant_suffix}.tar.gz")
    }
}

/// Static matrices for node distribution and management targets.
#[derive(Debug)]
pub struct Matrix;

impl Matrix {
    /// Exhaustive 16 node archive cells (Catalog cells 01 to 16).
    pub const NODE_VARIANTS: [NodeVariant; 16] = [
        // amd64
        NodeVariant::new(1, Architecture::Amd64, Libc::Glibc, Variant::Online),
        NodeVariant::new(2, Architecture::Amd64, Libc::Glibc, Variant::Offline),
        NodeVariant::new(3, Architecture::Amd64, Libc::Musl, Variant::Online),
        NodeVariant::new(4, Architecture::Amd64, Libc::Musl, Variant::Offline),
        // arm64
        NodeVariant::new(5, Architecture::Arm64, Libc::Glibc, Variant::Online),
        NodeVariant::new(6, Architecture::Arm64, Libc::Glibc, Variant::Offline),
        NodeVariant::new(7, Architecture::Arm64, Libc::Musl, Variant::Online),
        NodeVariant::new(8, Architecture::Arm64, Libc::Musl, Variant::Offline),
        // armv7
        NodeVariant::new(9, Architecture::ArmV7, Libc::Glibc, Variant::Online),
        NodeVariant::new(10, Architecture::ArmV7, Libc::Glibc, Variant::Offline),
        NodeVariant::new(11, Architecture::ArmV7, Libc::Musl, Variant::Online),
        NodeVariant::new(12, Architecture::ArmV7, Libc::Musl, Variant::Offline),
        // riscv64
        NodeVariant::new(13, Architecture::Riscv64, Libc::Glibc, Variant::Online),
        NodeVariant::new(14, Architecture::Riscv64, Libc::Glibc, Variant::Offline),
        NodeVariant::new(15, Architecture::Riscv64, Libc::Musl, Variant::Online),
        NodeVariant::new(16, Architecture::Riscv64, Libc::Musl, Variant::Offline),
    ];

    /// Four supported management CLI release targets.
    pub const MANAGEMENT_TARGETS: [ManagementTarget; 4] = [
        ManagementTarget::new(ManagementOs::Linux, ManagementArch::Amd64),
        ManagementTarget::new(ManagementOs::Linux, ManagementArch::Arm64),
        ManagementTarget::new(ManagementOs::Darwin, ManagementArch::Amd64),
        ManagementTarget::new(ManagementOs::Darwin, ManagementArch::Arm64),
    ];

    /// Four required OCI image platform architectures.
    pub const OCI_PLATFORMS: [&'static str; 4] = [
        "linux/amd64",
        "linux/arm64",
        "linux/arm/v7",
        "linux/riscv64",
    ];

    pub const fn all_node_variants() -> &'static [NodeVariant; 16] {
        &Self::NODE_VARIANTS
    }

    pub const fn all_management_targets() -> &'static [ManagementTarget; 4] {
        &Self::MANAGEMENT_TARGETS
    }

    pub const fn all_oci_platforms() -> &'static [&'static str; 4] {
        &Self::OCI_PLATFORMS
    }

    pub fn from_cell(cell: u8) -> Result<NodeVariant, MatrixError> {
        if (1..=16).contains(&cell) {
            Ok(Self::NODE_VARIANTS[(cell - 1) as usize])
        } else {
            Err(MatrixError::InvalidCell(cell))
        }
    }

    pub fn find_node_variant(
        architecture: Architecture,
        libc: Libc,
        variant: Variant,
    ) -> Option<NodeVariant> {
        Self::NODE_VARIANTS
            .iter()
            .copied()
            .find(|v| v.architecture == architecture && v.libc == libc && v.variant == variant)
    }

    pub fn find_management_target(
        os: ManagementOs,
        architecture: ManagementArch,
    ) -> Option<ManagementTarget> {
        Self::MANAGEMENT_TARGETS
            .iter()
            .copied()
            .find(|t| t.os == os && t.architecture == architecture)
    }
}

/// Errors relating to matrix lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatrixError {
    InvalidCell(u8),
    NotFound,
}

impl fmt::Display for MatrixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCell(cell) => write!(
                f,
                "invalid node variant cell index: {cell} (expected 1..=16)"
            ),
            Self::NotFound => write!(f, "node variant not found in matrix"),
        }
    }
}

impl std::error::Error for MatrixError {}

/// Parsed node archive metadata from a filename.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedNodeArchive {
    pub bundle_suffix: Option<String>,
    pub prefix: String,
    pub version: String,
    pub variant: NodeVariant,
}

/// Parsed management binary metadata from a filename.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedManagementBinary {
    pub prefix: String,
    pub target: ManagementTarget,
}

/// Errors during artifact filename parsing or clean-checkout validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArtifactNamingError {
    InvalidExtension {
        filename: String,
        expected: &'static str,
    },
    WindowsExcluded(String),
    InvalidFormat(String),
    UnsupportedArchitecture(String),
    UnsupportedLibc(String),
    UnsupportedOs(String),
    PrefixMismatch {
        expected: String,
        actual: String,
    },
    VersionMismatch {
        expected: String,
        actual: String,
    },
    VariantMismatch {
        expected_cell: u8,
        actual_cell: u8,
    },
    TargetMismatch,
    EmptyVersion,
    InvalidVersion(String),
    NonCanonical {
        filename: String,
        canonical: String,
    },
    OptionalImageRejected {
        cell: u8,
        feature: String,
    },
    DigestMismatch {
        asset: String,
    },
    MissingPackagedAsset {
        asset: String,
    },
}

impl fmt::Display for ArtifactNamingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidExtension { filename, expected } => {
                write!(
                    f,
                    "invalid file extension for '{filename}', expected '{expected}'"
                )
            },
            Self::WindowsExcluded(name) => {
                write!(
                    f,
                    "Windows target '{name}' is excluded by E01; WSL2 uses Linux userspace"
                )
            },
            Self::InvalidFormat(name) => write!(f, "invalid artifact naming format: '{name}'"),
            Self::UnsupportedArchitecture(arch) => write!(f, "unsupported architecture: '{arch}'"),
            Self::UnsupportedLibc(libc) => write!(f, "unsupported libc: '{libc}'"),
            Self::UnsupportedOs(os) => write!(f, "unsupported operating system: '{os}'"),
            Self::PrefixMismatch { expected, actual } => {
                write!(f, "prefix mismatch: expected '{expected}', got '{actual}'")
            },
            Self::VersionMismatch { expected, actual } => {
                write!(f, "version mismatch: expected '{expected}', got '{actual}'")
            },
            Self::VariantMismatch {
                expected_cell,
                actual_cell,
            } => {
                write!(
                    f,
                    "variant mismatch: expected cell {expected_cell}, got cell {actual_cell}"
                )
            },
            Self::TargetMismatch => write!(f, "target mismatch"),
            Self::EmptyVersion => write!(f, "version string must not be empty"),
            Self::InvalidVersion(ver) => write!(f, "invalid version string format: '{ver}'"),
            Self::NonCanonical {
                filename,
                canonical,
            } => {
                write!(
                    f,
                    "non-canonical archive '{filename}', expected '{canonical}'"
                )
            },
            Self::OptionalImageRejected { cell, feature } => {
                write!(f, "optional image {feature} is not bundled for cell {cell}")
            },
            Self::DigestMismatch { asset } => {
                write!(f, "packaged digest mismatch for {asset}")
            },
            Self::MissingPackagedAsset { asset } => {
                write!(f, "bundled asset {asset} has no expected digest")
            },
        }
    }
}

impl std::error::Error for ArtifactNamingError {}

/// Artifact naming parsing and validation rules.
#[derive(Debug)]
pub struct ArtifactNaming;

impl ArtifactNaming {
    /// Parse a node archive filename: `<prefix>-<version>-linux-<arch>[-musl][-offline].tar.gz`.
    pub fn parse_node_archive(filename: &str) -> Result<ParsedNodeArchive, ArtifactNamingError> {
        let base = filename.rsplit(['/', '\\']).next().unwrap_or(filename);
        if !base.ends_with(".tar.gz") {
            return Err(ArtifactNamingError::InvalidExtension {
                filename: base.to_string(),
                expected: ".tar.gz",
            });
        }
        let stem = &base[..base.len() - 7];

        if !stem.contains("-linux-")
            && ["-windows-", "-win32-", "-win64-"]
                .iter()
                .any(|os| stem.contains(os))
        {
            return Err(ArtifactNamingError::WindowsExcluded(base.to_string()));
        }

        // Must contain "-linux-"
        let linux_pos = stem
            .find("-linux-")
            .ok_or_else(|| ArtifactNamingError::InvalidFormat(base.to_string()))?;

        let prefix_and_version = &stem[..linux_pos];
        let target_part = &stem[linux_pos + 7..];
        let mut bundle_suffix = None;
        let mut legacy_target = target_part.to_owned();
        for suffix in ["host", "container", "addon-portainer-agent", "addon-d2k"] {
            if let Some(target) = target_part.strip_suffix(&format!("-{suffix}-offline")) {
                bundle_suffix = Some(suffix.to_owned());
                legacy_target = format!("{target}-offline");
                break;
            }
        }
        let target_part = legacy_target.as_str();

        // Split prefix and version: prefix is diorama
        let (prefix, version) = if let Some(stripped) = prefix_and_version.strip_prefix("diorama-")
        {
            ("diorama".to_string(), stripped.to_string())
        } else if let Some(last_dash) = prefix_and_version.rfind('-') {
            (
                prefix_and_version[..last_dash].to_string(),
                prefix_and_version[last_dash + 1..].to_string(),
            )
        } else {
            return Err(ArtifactNamingError::InvalidFormat(base.to_string()));
        };

        if version.is_empty() {
            return Err(ArtifactNamingError::EmptyVersion);
        }

        // Parse target_part: <arch>[-musl][-offline]
        let tokens: Vec<&str> = target_part.split('-').collect();
        if tokens.is_empty() {
            return Err(ArtifactNamingError::InvalidFormat(base.to_string()));
        }

        let arch = match tokens[0] {
            "amd64" => Architecture::Amd64,
            "arm64" => Architecture::Arm64,
            "arm" | "armv7" => Architecture::ArmV7,
            "riscv64" => Architecture::Riscv64,
            other => {
                return Err(ArtifactNamingError::UnsupportedArchitecture(
                    other.to_string(),
                ));
            },
        };

        let (libc, variant) = match &tokens[1..] {
            [] => (Libc::Glibc, Variant::Online),
            ["musl"] => (Libc::Musl, Variant::Online),
            ["offline"] => (Libc::Glibc, Variant::Offline),
            ["musl", "offline"] => (Libc::Musl, Variant::Offline),
            _ => {
                return Err(ArtifactNamingError::InvalidFormat(format!(
                    "suffix order must be arch[-musl][-offline] in '{base}'"
                )));
            },
        };

        let node_variant = Matrix::find_node_variant(arch, libc, variant)
            .ok_or_else(|| ArtifactNamingError::InvalidFormat(base.to_string()))?;

        Ok(ParsedNodeArchive {
            bundle_suffix,
            prefix,
            version,
            variant: node_variant,
        })
    }

    /// Parse a management binary filename: `<prefix>-<os>-<arch>`.
    pub fn parse_management_binary(
        filename: &str,
    ) -> Result<ParsedManagementBinary, ArtifactNamingError> {
        let base = filename.rsplit(['/', '\\']).next().unwrap_or(filename);
        if std::path::Path::new(base)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
            || base.to_ascii_lowercase().contains("windows")
        {
            return Err(ArtifactNamingError::WindowsExcluded(base.to_string()));
        }

        let tokens: Vec<&str> = base.split('-').collect();
        if tokens.len() < 3 {
            return Err(ArtifactNamingError::InvalidFormat(base.to_string()));
        }

        // Last two tokens are os and arch
        let arch_str = tokens[tokens.len() - 1];
        let os_str = tokens[tokens.len() - 2];
        let prefix = tokens[..tokens.len() - 2].join("-");

        let os = match os_str {
            "linux" => ManagementOs::Linux,
            "darwin" | "macos" => ManagementOs::Darwin,
            "windows" => return Err(ArtifactNamingError::WindowsExcluded(base.to_string())),
            other => return Err(ArtifactNamingError::UnsupportedOs(other.to_string())),
        };

        let arch = match arch_str {
            "amd64" => ManagementArch::Amd64,
            "arm64" => ManagementArch::Arm64,
            other => {
                return Err(ArtifactNamingError::UnsupportedArchitecture(
                    other.to_string(),
                ));
            },
        };

        let target = ManagementTarget::new(os, arch);
        Ok(ParsedManagementBinary { prefix, target })
    }

    /// Accepts only the filename `archive_filename` emits for the parsed cell.
    pub fn canonical_node_archive(
        filename: &str,
    ) -> Result<ParsedNodeArchive, ArtifactNamingError> {
        let parsed = Self::parse_node_archive(filename)?;
        let base = filename.rsplit(['/', '\\']).next().unwrap_or(filename);
        let canonical = parsed
            .variant
            .archive_filename(&parsed.prefix, &parsed.version);
        let canonical = if let Some(suffix) = &parsed.bundle_suffix {
            canonical.replace("-offline.tar.gz", &format!("-{suffix}-offline.tar.gz"))
        } else {
            canonical
        };
        if base != canonical {
            return Err(ArtifactNamingError::NonCanonical {
                filename: base.to_string(),
                canonical,
            });
        }
        Ok(parsed)
    }

    /// Rejects an optional image that this cell does not bundle.
    pub fn validate_bundled_optional_images(
        node_variant: NodeVariant,
        bundled: &[OptionalFeature],
    ) -> Result<(), ArtifactNamingError> {
        for feature in bundled {
            if !node_variant.is_image_bundled(*feature) {
                return Err(ArtifactNamingError::OptionalImageRejected {
                    cell: node_variant.cell,
                    feature: format!("{feature:?}"),
                });
            }
        }
        Ok(())
    }

    /// Compares every bundled delivery digest with the caller-supplied pin.
    pub fn validate_packaged_digests(
        inventory: &DeclaredInventory,
        expected: &[(AssetId, &str)],
    ) -> Result<(), ArtifactNamingError> {
        for (id, delivery) in inventory.assets() {
            let Delivery::Bundled { sha256, .. } = delivery else {
                continue;
            };
            let Some((_, expected_digest)) = expected.iter().find(|(asset, _)| *asset == id) else {
                return Err(ArtifactNamingError::MissingPackagedAsset {
                    asset: format!("{id:?}"),
                });
            };
            if sha256 != expected_digest {
                return Err(ArtifactNamingError::DigestMismatch {
                    asset: format!("{id:?}"),
                });
            }
        }
        Ok(())
    }

    /// Validate clean-checkout build inputs and naming reproducibility.
    pub fn validate_clean_checkout_inputs(
        prefix: &str,
        version: &str,
        node_variant: NodeVariant,
        bundled_optional_images: &[OptionalFeature],
    ) -> Result<String, ArtifactNamingError> {
        if prefix.is_empty() {
            return Err(ArtifactNamingError::InvalidFormat(
                "prefix must not be empty".to_string(),
            ));
        }
        if version.is_empty() {
            return Err(ArtifactNamingError::EmptyVersion);
        }
        // Basic semantic check: version must not contain slashes, spaces, or dashes that confuse parsing
        let trimmed_version = version.strip_prefix('v').unwrap_or(version);
        if trimmed_version.is_empty()
            || !trimmed_version
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.')
        {
            return Err(ArtifactNamingError::InvalidVersion(version.to_string()));
        }

        Self::validate_bundled_optional_images(node_variant, bundled_optional_images)?;
        let generated_name = node_variant.archive_filename(prefix, version);
        let parsed = Self::canonical_node_archive(&generated_name)?;

        if parsed.prefix != prefix {
            return Err(ArtifactNamingError::PrefixMismatch {
                expected: prefix.to_string(),
                actual: parsed.prefix,
            });
        }
        if parsed.version != version {
            return Err(ArtifactNamingError::VersionMismatch {
                expected: version.to_string(),
                actual: parsed.version,
            });
        }
        if parsed.variant.cell != node_variant.cell {
            return Err(ArtifactNamingError::VariantMismatch {
                expected_cell: node_variant.cell,
                actual_cell: parsed.variant.cell,
            });
        }

        Ok(generated_name)
    }
}
