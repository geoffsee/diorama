use crate::{AssetId, Encoding, Kind, catalog};
use diorama_platform::{Architecture, Libc, NodeTarget};
use serde::Deserialize;
use std::{collections::BTreeSet, fmt};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Variant {
    Online,
    Offline,
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    SupervisedBundle,
    /// Only the baseline's empty embedded payload set; not a supervised-node contract.
    LegacyExternalDeps,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OptionalFeature {
    LocalPathStorage,
    PortainerAgent,
    D2k,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureSupport {
    SupportedTarget,
    UnsupportedTarget,
}
/// Target architecture policy for optional features.
pub fn feature_support(architecture: Architecture, feature: OptionalFeature) -> FeatureSupport {
    match feature {
        OptionalFeature::LocalPathStorage => FeatureSupport::SupportedTarget,
        OptionalFeature::PortainerAgent => {
            if architecture == Architecture::Riscv64 {
                FeatureSupport::UnsupportedTarget
            } else {
                FeatureSupport::SupportedTarget
            }
        },
        OptionalFeature::D2k => {
            if matches!(architecture, Architecture::Amd64 | Architecture::Arm64) {
                FeatureSupport::SupportedTarget
            } else {
                FeatureSupport::UnsupportedTarget
            }
        },
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryRequest {
    pub target: NodeTarget,
    pub variant: Variant,
    pub scope: Scope,
}
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub manifest_bytes: usize,
    pub records: usize,
    pub path_bytes: usize,
    pub encoded_asset_bytes: u64,
    /// Includes up to one EOF/trailing-byte probe per bundled record.
    pub encoded_total_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            manifest_bytes: 1_048_576,
            records: 256,
            path_bytes: 4096,
            encoded_asset_bytes: 8 * 1024 * 1024 * 1024,
            encoded_total_bytes: 32 * 1024 * 1024 * 1024,
        }
    }
}
impl Limits {
    fn valid(self) -> bool {
        self.manifest_bytes > 0
            && self.records > 0
            && self.path_bytes > 0
            && self.encoded_asset_bytes > 0
            && self.encoded_asset_bytes < u64::MAX
            && self.encoded_total_bytes > 0
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InventoryError {
    InvalidLimits,
    LimitExceeded,
    InvalidJson { line: usize, column: usize },
    SchemaVersion,
    TargetMismatch,
    RequestMismatch,
    LegacyScopeHasPayloads,
    DuplicateAsset(AssetId),
    MissingAsset(AssetId),
    WrongDelivery(AssetId),
    WrongEncoding(AssetId),
    UnsafePath(AssetId),
    ConflictingPath(AssetId),
    InvalidDigest(AssetId),
    InvalidSize(AssetId),
}
impl fmt::Display for InventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "asset inventory: {self:?}")
    }
}
impl std::error::Error for InventoryError {}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    os: String,
    architecture: String,
    libc: String,
}
impl Target {
    fn agrees(&self, target: NodeTarget) -> bool {
        let arch = match target.architecture {
            Architecture::Amd64 => "amd64",
            Architecture::Arm64 => "arm64",
            Architecture::ArmV7 => "armv7",
            Architecture::Riscv64 => "riscv64",
        };
        let libc = match target.libc {
            Libc::Glibc => "glibc",
            Libc::Musl => "musl",
        };
        self.os == "linux" && self.architecture == arch && self.libc == libc
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Delivery {
    Bundled {
        path: String,
        encoding: Encoding,
        encoded_bytes: u64,
        sha256: String,
    },
    RegistryRequired {},
    Unavailable {},
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    id: AssetId,
    delivery: Delivery,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    schema_version: u32,
    target: Target,
    variant: Variant,
    scope: Scope,
    assets: Vec<Record>,
}
/// Opaque parsed input, constructed only by the bounded strict byte decoder.
///
/// Generic serde decoding cannot bypass that ingress:
/// ```compile_fail,E0277
/// fn requires_deserialize<T: serde::de::DeserializeOwned>() {}
/// requires_deserialize::<diorama_assets::Manifest>();
/// ```
#[derive(Debug)]
pub struct Manifest {
    raw: RawManifest,
    raw_bytes: usize,
}
#[derive(Clone, Debug)]
pub(crate) struct Blob {
    pub id: AssetId,
    pub path: String,
    pub encoding: Encoding,
    pub bytes: u64,
    pub digest: [u8; 32],
}
/// Complete declared role/target/variant metadata. No content target or installation claim.
#[derive(Debug)]
pub struct DeclaredInventory {
    pub(crate) request: InventoryRequest,
    pub(crate) blobs: Vec<Blob>,
    records: Vec<(AssetId, Delivery)>,
    pub(crate) limits: Limits,
}
impl Manifest {
    pub fn decode(bytes: &[u8], limits: Limits) -> Result<Self, InventoryError> {
        if !limits.valid() {
            return Err(InventoryError::InvalidLimits);
        }
        if bytes.len() > limits.manifest_bytes {
            return Err(InventoryError::LimitExceeded);
        }
        let value: RawManifest =
            serde_json::from_slice(bytes).map_err(|e| InventoryError::InvalidJson {
                line: e.line(),
                column: e.column(),
            })?;
        if value.assets.len() > limits.records {
            return Err(InventoryError::LimitExceeded);
        }
        Ok(Self {
            raw: value,
            raw_bytes: bytes.len(),
        })
    }
    fn validate_header(
        &self,
        request: InventoryRequest,
        limits: Limits,
    ) -> Result<(), InventoryError> {
        if !limits.valid() {
            return Err(InventoryError::InvalidLimits);
        }
        if self.raw_bytes > limits.manifest_bytes || self.raw.assets.len() > limits.records {
            return Err(InventoryError::LimitExceeded);
        }
        if self.raw.schema_version != 1 {
            return Err(InventoryError::SchemaVersion);
        }
        if !self.raw.target.agrees(request.target) {
            return Err(InventoryError::TargetMismatch);
        }
        if self.raw.variant != request.variant || self.raw.scope != request.scope {
            return Err(InventoryError::RequestMismatch);
        }
        Ok(())
    }
    pub fn validate_inventory(
        self,
        request: InventoryRequest,
        limits: Limits,
    ) -> Result<DeclaredInventory, InventoryError> {
        self.validate_header(request, limits)?;
        if request.scope == Scope::LegacyExternalDeps {
            if !self.raw.assets.is_empty() {
                return Err(InventoryError::LegacyScopeHasPayloads);
            }
            return Ok(DeclaredInventory {
                request,
                blobs: Vec::new(),
                records: Vec::new(),
                limits,
            });
        }
        let mut ids = BTreeSet::new();
        let mut paths = BTreeSet::<String>::new();
        let mut blobs = Vec::new();
        let mut records = Vec::new();
        let mut total = 0u64;
        for record in self.raw.assets {
            if !ids.insert(record.id) {
                return Err(InventoryError::DuplicateAsset(record.id));
            }
            let entry = catalog()
                .iter()
                .find(|entry| entry.id == record.id)
                .ok_or(InventoryError::WrongDelivery(record.id))?;
            let unavailable = match record.id {
                AssetId::ImagePortainerAgent => {
                    feature_support(request.target.architecture, OptionalFeature::PortainerAgent)
                        == FeatureSupport::UnsupportedTarget
                },
                AssetId::ImageD2k => {
                    feature_support(request.target.architecture, OptionalFeature::D2k)
                        == FeatureSupport::UnsupportedTarget
                },
                _ => false,
            };
            let bundled = entry.kind == Kind::Executable
                || matches!(record.id, AssetId::ImageCoredns | AssetId::ImagePause)
                || request.variant == Variant::Offline;
            records.push((record.id, record.delivery.clone()));
            match record.delivery {
                Delivery::Unavailable {} if unavailable => {},
                Delivery::RegistryRequired {} if !unavailable && !bundled => {},
                Delivery::Bundled {
                    path,
                    encoding,
                    encoded_bytes,
                    sha256,
                } if !unavailable && bundled => {
                    if encoding != entry.encoding {
                        return Err(InventoryError::WrongEncoding(record.id));
                    }
                    if !safe_path(&path, limits.path_bytes) {
                        return Err(InventoryError::UnsafePath(record.id));
                    }
                    if paths.iter().any(|p| {
                        p == &path
                            || path.starts_with(&format!("{p}/"))
                            || p.starts_with(&format!("{path}/"))
                    }) {
                        return Err(InventoryError::ConflictingPath(record.id));
                    }
                    paths.insert(path.clone());
                    if encoded_bytes == 0 || encoded_bytes > limits.encoded_asset_bytes {
                        return Err(InventoryError::InvalidSize(record.id));
                    }
                    total = total
                        .checked_add(encoded_bytes)
                        .and_then(|n| n.checked_add(1))
                        .ok_or(InventoryError::LimitExceeded)?;
                    if total > limits.encoded_total_bytes {
                        return Err(InventoryError::LimitExceeded);
                    }
                    let digest =
                        parse_digest(&sha256).ok_or(InventoryError::InvalidDigest(record.id))?;
                    blobs.push(Blob {
                        id: record.id,
                        path,
                        encoding,
                        bytes: encoded_bytes,
                        digest,
                    });
                },
                _ => return Err(InventoryError::WrongDelivery(record.id)),
            }
        }
        for entry in catalog() {
            if !ids.contains(&entry.id) {
                return Err(InventoryError::MissingAsset(entry.id));
            }
        }
        blobs.sort_by_key(|blob| blob.id);
        records.sort_by_key(|r| r.0);
        Ok(DeclaredInventory {
            request,
            blobs,
            records,
            limits,
        })
    }
}
fn safe_path(path: &str, limit: usize) -> bool {
    path.len() <= limit
        && !path.is_empty()
        && path.is_ascii()
        && path.split('/').count() <= 32
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
}
fn parse_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0; 32];
    for (slot, text) in out.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let digit = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        *slot = digit(text[0]) * 16 + digit(text[1]);
    }
    Some(out)
}
impl DeclaredInventory {
    pub fn assets(&self) -> impl ExactSizeIterator<Item = (AssetId, &Delivery)> {
        self.records.iter().map(|(id, delivery)| (*id, delivery))
    }
    /// Target policy only; this does not mean the feature is enabled or its payload is pinned.
    pub fn optional_feature_support(
        &self,
    ) -> impl ExactSizeIterator<Item = (OptionalFeature, FeatureSupport)> {
        let architecture = self.request.target.architecture;
        [
            (
                OptionalFeature::LocalPathStorage,
                feature_support(architecture, OptionalFeature::LocalPathStorage),
            ),
            (
                OptionalFeature::PortainerAgent,
                feature_support(architecture, OptionalFeature::PortainerAgent),
            ),
            (
                OptionalFeature::D2k,
                feature_support(architecture, OptionalFeature::D2k),
            ),
        ]
        .into_iter()
    }
    pub fn request(&self) -> InventoryRequest {
        self.request
    }
    pub fn bundled_assets(&self) -> impl ExactSizeIterator<Item = (AssetId, &str, Encoding, u64)> {
        self.blobs
            .iter()
            .map(|b| (b.id, b.path.as_str(), b.encoding, b.bytes))
    }
}
