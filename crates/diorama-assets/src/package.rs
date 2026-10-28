//! Packaging of node archives, management CLI binaries, and OCI image manifests across the matrix.
//!
//! Provides verifiable release package metadata, layout smoke checks,
//! management binary cross-target verification, and OCI multi-arch manifest index binding.

use crate::{
    ArtifactNaming, ArtifactNamingError, AssetId, AssetLayout, DeclaredInventory, ManagementArch,
    ManagementOs, ManagementTarget, MaterializationError, MaterializationLimits,
    MaterializationOutcome, Materializer, Matrix, MatrixError, NodeVariant, catalog,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::Read,
    path::Path,
};

/// Release package metadata for a single node distribution archive cell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeArchiveArtifact {
    pub cell: u8,
    pub filename: String,
    pub architecture: String,
    pub libc: String,
    pub variant: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub bundled_assets: Vec<String>,
}

/// Release package metadata for a management CLI executable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementArtifact {
    pub os: String,
    pub architecture: String,
    pub filename: String,
    pub size_bytes: u64,
    pub sha256: String,
}

/// OCI platform descriptor inside a multi-arch image index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciPlatformDescriptor {
    pub platform: String,
    pub architecture: String,
    pub os: String,
    pub media_type: String,
    pub digest: String,
    pub size_bytes: u64,
}

/// Release package metadata for a multi-arch OCI container image index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciImageIndexArtifact {
    pub asset_id: String,
    pub image_reference: String,
    pub index_media_type: String,
    pub index_digest: String,
    pub index_size_bytes: u64,
    pub platforms: Vec<OciPlatformDescriptor>,
    pub unsupported_platforms: Vec<String>,
}

/// Complete verifiable release package manifest covering all 16 cells, 4 management targets,
/// and container image multi-arch OCI manifest indices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasePackageManifest {
    pub schema_version: u32,
    pub product_name: String,
    pub version: String,
    pub node_archives: Vec<NodeArchiveArtifact>,
    pub management_binaries: Vec<ManagementArtifact>,
    pub oci_images: Vec<OciImageIndexArtifact>,
    pub excluded_targets: Vec<String>,
}

/// Errors during release package verification or generation.
#[derive(Debug)]
pub enum PackageError {
    InvalidCellCount {
        expected: usize,
        observed: usize,
    },
    MissingCell(u8),
    DuplicateCell(u8),
    DuplicateManagementTarget(String),
    InvalidMetadata(String),
    InvalidManagementCount {
        expected: usize,
        observed: usize,
    },
    MissingManagementTarget(String),
    WindowsTargetIncluded(String),
    DigestMismatch {
        target: String,
        expected: String,
        observed: String,
    },
    SizeMismatch {
        target: String,
        expected: u64,
        observed: u64,
    },
    Naming(ArtifactNamingError),
    Matrix(MatrixError),
    Materialization(MaterializationError),
    InvalidOciPlatform {
        image: String,
        platform: String,
    },
    UnsupportedOciPlatformBundled {
        image: String,
        platform: String,
    },
    MissingRequiredPlatform {
        image: String,
        platform: String,
    },
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for PackageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateManagementTarget(target) => {
                write!(f, "duplicate management target: {target}")
            },
            Self::InvalidMetadata(message) => write!(f, "invalid release metadata: {message}"),
            Self::InvalidCellCount { expected, observed } => write!(
                f,
                "invalid node archive cell count: expected {expected}, observed {observed}"
            ),
            Self::MissingCell(cell) => write!(f, "missing node archive cell: {cell}"),
            Self::DuplicateCell(cell) => write!(f, "duplicate node archive cell: {cell}"),
            Self::InvalidManagementCount { expected, observed } => write!(
                f,
                "invalid management targets count: expected {expected}, observed {observed}"
            ),
            Self::MissingManagementTarget(target) => {
                write!(f, "missing management target: {target}")
            },
            Self::WindowsTargetIncluded(name) => write!(
                f,
                "Windows target '{name}' must not be included; excluded by E01"
            ),
            Self::DigestMismatch {
                target,
                expected,
                observed,
            } => write!(
                f,
                "digest mismatch for '{target}': expected {expected}, observed {observed}"
            ),
            Self::SizeMismatch {
                target,
                expected,
                observed,
            } => write!(
                f,
                "size mismatch for '{target}': expected {expected}, observed {observed}"
            ),
            Self::Naming(e) => write!(f, "artifact naming error: {e}"),
            Self::Matrix(e) => write!(f, "matrix error: {e}"),
            Self::Materialization(e) => write!(f, "materialization smoke error: {e}"),
            Self::InvalidOciPlatform { image, platform } => {
                write!(f, "invalid OCI platform '{platform}' for image '{image}'")
            },
            Self::UnsupportedOciPlatformBundled { image, platform } => write!(
                f,
                "unsupported OCI platform '{platform}' was bundled for image '{image}'"
            ),
            Self::MissingRequiredPlatform { image, platform } => write!(
                f,
                "missing required OCI platform '{platform}' for image '{image}'"
            ),
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::Json(e) => write!(f, "JSON serialization error: {e}"),
        }
    }
}

impl std::error::Error for PackageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Naming(e) => Some(e),
            Self::Matrix(e) => Some(e),
            Self::Materialization(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ArtifactNamingError> for PackageError {
    fn from(e: ArtifactNamingError) -> Self {
        Self::Naming(e)
    }
}

impl From<MatrixError> for PackageError {
    fn from(e: MatrixError) -> Self {
        Self::Matrix(e)
    }
}

impl From<MaterializationError> for PackageError {
    fn from(e: MaterializationError) -> Self {
        Self::Materialization(e)
    }
}

impl From<std::io::Error> for PackageError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for PackageError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// Release packager and verification suite.
#[derive(Debug)]
pub struct ReleasePackager;

impl ReleasePackager {
    /// Format a byte slice into lowercase hexadecimal string.
    pub fn hex_digest(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Compute SHA-256 hex digest of a byte slice.
    pub fn sha256_hex(data: &[u8]) -> String {
        let hash = Sha256::digest(data);
        Self::hex_digest(&hash)
    }

    /// Validate the naming, cell, and checksum of a node archive artifact descriptor.
    pub fn verify_node_archive_descriptor(
        artifact: &NodeArchiveArtifact,
        expected_prefix: &str,
        expected_version: &str,
    ) -> Result<NodeVariant, PackageError> {
        let variant = Matrix::from_cell(artifact.cell)?;
        if artifact.filename.contains(['/', '\\']) {
            return Err(PackageError::InvalidMetadata(
                "node archive filename must be a bare canonical name".into(),
            ));
        }
        let parsed = ArtifactNaming::canonical_node_archive(&artifact.filename)?;

        if parsed.prefix != expected_prefix {
            return Err(ArtifactNamingError::PrefixMismatch {
                expected: expected_prefix.to_string(),
                actual: parsed.prefix,
            }
            .into());
        }
        if parsed.version != expected_version {
            return Err(ArtifactNamingError::VersionMismatch {
                expected: expected_version.to_string(),
                actual: parsed.version,
            }
            .into());
        }
        if parsed.variant.cell != artifact.cell {
            return Err(ArtifactNamingError::VariantMismatch {
                expected_cell: artifact.cell,
                actual_cell: parsed.variant.cell,
            }
            .into());
        }

        // Verify SHA-256 hex string validity
        let architecture = match variant.architecture {
            diorama_platform::Architecture::Amd64 => "amd64",
            diorama_platform::Architecture::Arm64 => "arm64",
            diorama_platform::Architecture::ArmV7 => "arm",
            diorama_platform::Architecture::Riscv64 => "riscv64",
        };
        let libc = match variant.libc {
            diorama_platform::Libc::Glibc => "glibc",
            diorama_platform::Libc::Musl => "musl",
        };
        let delivery = match variant.variant {
            crate::Variant::Online => "online",
            crate::Variant::Offline => "offline",
        };
        if artifact.architecture != architecture
            || artifact.libc != libc
            || artifact.variant != delivery
            || artifact.size_bytes == 0
        {
            return Err(PackageError::InvalidMetadata(format!(
                "node cell {} selectors or size",
                artifact.cell
            )));
        }
        let mut observed_assets = BTreeSet::new();
        for name in &artifact.bundled_assets {
            let id: AssetId = serde_json::from_value(serde_json::Value::String(name.clone()))?;
            if !observed_assets.insert(id) {
                return Err(PackageError::InvalidMetadata(format!(
                    "duplicate bundled asset {name}"
                )));
            }
        }
        let required_assets: BTreeSet<_> = catalog()
            .iter()
            .filter(|entry| match entry.id {
                AssetId::ImagePortainerAgent => {
                    variant.variant == crate::Variant::Offline
                        && variant.architecture != diorama_platform::Architecture::Riscv64
                },
                AssetId::ImageD2k => {
                    variant.variant == crate::Variant::Offline
                        && matches!(
                            variant.architecture,
                            diorama_platform::Architecture::Amd64
                                | diorama_platform::Architecture::Arm64
                        )
                },
                AssetId::ImageLocalPath | AssetId::ImageLocalPathHelper | AssetId::ImageDiorama => {
                    variant.variant == crate::Variant::Offline
                },
                _ => true,
            })
            .map(|entry| entry.id)
            .collect();
        if observed_assets != required_assets {
            return Err(PackageError::InvalidMetadata(format!(
                "bundled inventory for node cell {}",
                artifact.cell
            )));
        }
        if !valid_sha256_hex(&artifact.sha256) {
            return Err(PackageError::DigestMismatch {
                target: artifact.filename.clone(),
                expected: "64 hex chars".to_string(),
                observed: artifact.sha256.clone(),
            });
        }

        Ok(variant)
    }

    /// Check dependency materialization only; this does not qualify a node installation.
    ///
    /// Verifies:
    /// 1. The archive can be unpacked into the given root path by `Materializer`.
    /// 2. All bundled assets required by `inventory` exist in the expected destination paths.
    /// 3. Executable permissions (0o755) and payload permissions (0o644) are set properly.
    /// 4. Extraction is idempotent (second extraction reproduces identical layout).
    pub fn smoke_check_node_archive_layout<R: Read + Clone>(
        inventory: DeclaredInventory,
        root: &Path,
        archive_reader: R,
    ) -> Result<MaterializationOutcome, PackageError> {
        let layout = AssetLayout::canonical();
        let limits = MaterializationLimits::default();
        let materializer = Materializer::new(inventory, root)
            .with_layout(layout)
            .with_limits(limits);

        // Perform primary materialization
        let outcome = materializer.materialize_from_archive(archive_reader.clone())?;

        // Verify on-disk layout
        for asset in &outcome.assets {
            if !asset.path.exists() {
                return Err(MaterializationError::Io {
                    path: asset.path.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "materialized file missing",
                    ),
                }
                .into());
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let metadata = std::fs::metadata(&asset.path)?;
                let mode = metadata.permissions().mode() & 0o777;
                if mode != asset.mode {
                    return Err(MaterializationError::Io {
                        path: asset.path.clone(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!(
                                "file permission mode mismatch: expected {:o}, got {:o}",
                                asset.mode, mode
                            ),
                        ),
                    }
                    .into());
                }
            }
        }

        // Idempotency check: verify re-extraction succeeds without conflict
        let second_outcome = materializer.materialize_from_archive(archive_reader)?;
        if second_outcome.assets != outcome.assets {
            return Err(MaterializationError::CorruptArchive(
                "idempotency check produced different asset paths, modes, sizes or digests"
                    .to_string(),
            )
            .into());
        }

        Ok(outcome)
    }

    /// Verify a management binary release artifact.
    ///
    /// Rejects Windows binaries (`.exe` or `windows`), verifies naming format,
    /// checks that target matches supported 4 targets.
    pub fn verify_management_artifact(
        artifact: &ManagementArtifact,
        expected_prefix: &str,
    ) -> Result<ManagementTarget, PackageError> {
        if artifact.os.eq_ignore_ascii_case("windows")
            || artifact.filename.to_ascii_lowercase().contains("windows")
            || std::path::Path::new(&artifact.filename)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
        {
            return Err(PackageError::WindowsTargetIncluded(
                artifact.filename.clone(),
            ));
        }

        if artifact.filename.contains(['/', '\\']) {
            return Err(PackageError::InvalidMetadata(
                "management filename must be a bare canonical name".into(),
            ));
        }
        let parsed = ArtifactNaming::parse_management_binary(&artifact.filename)?;
        if artifact.filename != parsed.target.binary_filename(expected_prefix) {
            return Err(PackageError::InvalidMetadata(
                "management filename is not canonical".into(),
            ));
        }
        if parsed.prefix != expected_prefix {
            return Err(ArtifactNamingError::PrefixMismatch {
                expected: expected_prefix.to_string(),
                actual: parsed.prefix,
            }
            .into());
        }

        let expected_os = match artifact.os.as_str() {
            "linux" => ManagementOs::Linux,
            "darwin" => ManagementOs::Darwin,
            other => return Err(ArtifactNamingError::UnsupportedOs(other.to_string()).into()),
        };

        let expected_arch = match artifact.architecture.as_str() {
            "amd64" => ManagementArch::Amd64,
            "arm64" => ManagementArch::Arm64,
            other => {
                return Err(ArtifactNamingError::UnsupportedArchitecture(other.to_string()).into());
            },
        };

        if parsed.target.os != expected_os || parsed.target.architecture != expected_arch {
            return Err(ArtifactNamingError::TargetMismatch.into());
        }

        if !valid_sha256_hex(&artifact.sha256) {
            return Err(PackageError::DigestMismatch {
                target: artifact.filename.clone(),
                expected: "64 hex chars".to_string(),
                observed: artifact.sha256.clone(),
            });
        }

        if artifact.size_bytes == 0 {
            return Err(PackageError::InvalidMetadata(
                "empty management artifact".into(),
            ));
        }

        Ok(parsed.target)
    }

    /// Verify OCI multi-arch image index descriptors.
    ///
    /// Checks:
    /// - Index mediaType is valid OCI or Docker manifest list.
    /// - Platforms belong to the 4 canonical OCI architectures (`linux/amd64`, `linux/arm64`, `linux/arm/v7`, `linux/riscv64`).
    /// - Unsupported platforms are strictly partitioned (e.g. Portainer unsupported on `linux/riscv64`, D2K unsupported on `linux/arm/v7` and `linux/riscv64`).
    /// - All supported platforms have valid SHA-256 digests.
    pub fn verify_oci_image_index(artifact: &OciImageIndexArtifact) -> Result<(), PackageError> {
        let valid_oci_platforms = Matrix::all_oci_platforms();

        // Check asset identity in catalog
        let catalog_entry = catalog().iter().find(|e| match artifact.asset_id.as_str() {
            "image-coredns" => e.id == AssetId::ImageCoredns,
            "image-pause" => e.id == AssetId::ImagePause,
            "image-local-path" => e.id == AssetId::ImageLocalPath,
            "image-local-path-helper" => e.id == AssetId::ImageLocalPathHelper,
            "image-portainer-agent" => e.id == AssetId::ImagePortainerAgent,
            "image-d2k" => e.id == AssetId::ImageD2k,
            _ => false,
        });
        if catalog_entry.is_none() && artifact.asset_id != "image-diorama" {
            return Err(PackageError::InvalidOciPlatform {
                image: artifact.asset_id.clone(),
                platform: "unknown asset id".to_string(),
            });
        }
        if artifact.image_reference.is_empty()
            || catalog_entry.is_some_and(|entry| entry.reference != artifact.image_reference)
        {
            return Err(PackageError::InvalidMetadata(format!(
                "image reference for {}",
                artifact.asset_id
            )));
        }
        if !matches!(
            artifact.index_media_type.as_str(),
            "application/vnd.oci.image.index.v1+json"
                | "application/vnd.docker.distribution.manifest.list.v2+json"
        ) || !valid_oci_digest(&artifact.index_digest)
            || artifact.index_size_bytes == 0
        {
            return Err(PackageError::InvalidMetadata(format!(
                "index metadata for {}",
                artifact.asset_id
            )));
        }

        // Determine expected unsupported platforms based on policy
        let expected_unsupported: &[&'static str] = match catalog_entry.map(|e| e.id) {
            Some(AssetId::ImagePortainerAgent) => &["linux/riscv64"],
            Some(AssetId::ImageD2k) => &["linux/arm/v7", "linux/riscv64"],
            _ => &[],
        };

        let mut seen_platforms = BTreeSet::new();
        for p in &artifact.platforms {
            if !seen_platforms.insert(p.platform.as_str()) {
                return Err(PackageError::InvalidMetadata(format!(
                    "duplicate OCI platform {}",
                    p.platform
                )));
            }
            if !valid_oci_platforms.contains(&p.platform.as_str()) {
                return Err(PackageError::InvalidOciPlatform {
                    image: artifact.asset_id.clone(),
                    platform: p.platform.clone(),
                });
            }

            // Check if an unsupported platform was mistakenly bundled
            if expected_unsupported.contains(&p.platform.as_str()) {
                return Err(PackageError::UnsupportedOciPlatformBundled {
                    image: artifact.asset_id.clone(),
                    platform: p.platform.clone(),
                });
            }

            verify_platform_metadata(&artifact.asset_id, p)?;
        }

        let unsupported: BTreeSet<_> = artifact
            .unsupported_platforms
            .iter()
            .map(String::as_str)
            .collect();
        if unsupported.len() != artifact.unsupported_platforms.len()
            || unsupported
                .iter()
                .any(|p| !expected_unsupported.contains(p))
        {
            return Err(PackageError::InvalidMetadata(
                "OCI unsupported platform partition".into(),
            ));
        }

        // Verify that all expected unsupported platforms are listed in `unsupported_platforms`
        for &unsup in expected_unsupported {
            if !artifact.unsupported_platforms.iter().any(|u| u == unsup) {
                return Err(PackageError::MissingRequiredPlatform {
                    image: artifact.asset_id.clone(),
                    platform: format!("unsupported declaration for {unsup}"),
                });
            }
        }

        // Check required supported platforms are all present
        for &expected_p in valid_oci_platforms {
            if !expected_unsupported.contains(&expected_p)
                && !artifact.platforms.iter().any(|p| p.platform == expected_p)
            {
                return Err(PackageError::MissingRequiredPlatform {
                    image: artifact.asset_id.clone(),
                    platform: expected_p.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Full verification of a complete release package manifest across all 16 cells and 4 management targets.
    pub fn verify_release_manifest(
        manifest: &ReleasePackageManifest,
        expected_node_prefix: &str,
        expected_management_prefix: &str,
        expected_version: &str,
    ) -> Result<(), PackageError> {
        if manifest.schema_version != 1
            || manifest.product_name != expected_node_prefix
            || manifest.version != expected_version
        {
            return Err(PackageError::InvalidMetadata(
                "schema, product or release version".into(),
            ));
        }
        // 1. Verify 16 cells are exhaustive and uniquely present (1..=16)
        if manifest.node_archives.len() != 16 {
            return Err(PackageError::InvalidCellCount {
                expected: 16,
                observed: manifest.node_archives.len(),
            });
        }

        let mut seen_cells = [false; 17];
        for archive in &manifest.node_archives {
            if archive.cell == 0 || archive.cell > 16 {
                return Err(MatrixError::InvalidCell(archive.cell).into());
            }
            if seen_cells[archive.cell as usize] {
                return Err(PackageError::DuplicateCell(archive.cell));
            }
            seen_cells[archive.cell as usize] = true;
            Self::verify_node_archive_descriptor(archive, expected_node_prefix, expected_version)?;
        }

        for cell in 1..=16 {
            if !seen_cells[cell as usize] {
                return Err(PackageError::MissingCell(cell));
            }
        }

        // 2. Verify 4 management targets are exhaustive and uniquely present
        if manifest.management_binaries.len() != 4 {
            return Err(PackageError::InvalidManagementCount {
                expected: 4,
                observed: manifest.management_binaries.len(),
            });
        }

        let mut target_set = BTreeMap::new();
        for binary in &manifest.management_binaries {
            let target = Self::verify_management_artifact(binary, expected_management_prefix)?;
            let key = (target.os, target.architecture);
            if target_set.insert(key, binary.filename.clone()).is_some() {
                return Err(PackageError::DuplicateManagementTarget(
                    binary.filename.clone(),
                ));
            }
        }

        for target in Matrix::all_management_targets() {
            let key = (target.os, target.architecture);
            if !target_set.contains_key(&key) {
                return Err(PackageError::MissingManagementTarget(format!(
                    "{}-{}",
                    target.os, target.architecture
                )));
            }
        }

        // 3. Verify Windows exclusion in excluded_targets
        let has_windows_exclusion = manifest
            .excluded_targets
            .iter()
            .any(|t| t.to_ascii_lowercase().contains("windows"));
        if !has_windows_exclusion {
            return Err(PackageError::WindowsTargetIncluded(
                "manifest must explicitly declare Windows excluded".to_string(),
            ));
        }

        // 4. Verify OCI container image index manifests
        let mut images = BTreeSet::new();
        for oci in &manifest.oci_images {
            if !images.insert(oci.asset_id.as_str()) {
                return Err(PackageError::InvalidMetadata(format!(
                    "duplicate image {}",
                    oci.asset_id
                )));
            }
            Self::verify_oci_image_index(oci)?;
        }
        for required in [
            "image-diorama",
            "image-coredns",
            "image-pause",
            "image-local-path",
            "image-local-path-helper",
            "image-portainer-agent",
            "image-d2k",
        ] {
            if !images.contains(required) {
                return Err(PackageError::InvalidMetadata(format!(
                    "missing required OCI image {required}"
                )));
            }
        }

        Ok(())
    }
}

fn valid_oci_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(valid_sha256_hex)
}

fn valid_sha256_hex(hex: &str) -> bool {
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn verify_platform_metadata(image: &str, p: &OciPlatformDescriptor) -> Result<(), PackageError> {
    let expected_arch = match p.platform.as_str() {
        "linux/amd64" => "amd64",
        "linux/arm64" => "arm64",
        "linux/arm/v7" => "arm",
        "linux/riscv64" => "riscv64",
        _ => "",
    };
    if p.os != "linux"
        || p.architecture != expected_arch
        || p.size_bytes == 0
        || !matches!(
            p.media_type.as_str(),
            "application/vnd.oci.image.manifest.v1+json"
                | "application/vnd.docker.distribution.manifest.v2+json"
        )
    {
        return Err(PackageError::InvalidMetadata(format!(
            "platform descriptor {}",
            p.platform
        )));
    }
    if !valid_oci_digest(&p.digest) {
        return Err(PackageError::DigestMismatch {
            target: format!("{} ({})", image, p.platform),
            expected: "sha256:<64 hex>".to_string(),
            observed: p.digest.clone(),
        });
    }
    Ok(())
}
