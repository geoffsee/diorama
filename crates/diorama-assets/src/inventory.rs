use crate::{AssetId, Encoding, Kind, catalog};
use diorama_platform::{Architecture, Libc, NodeTarget};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};

/// Version two bundles declare exactly which installation they support.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BundleKind {
    Host,
    Container,
    Addon,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    Core,
    LocalStorage,
    PortainerAgent,
    D2k,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BundleMetadata {
    pub kind: BundleKind,
    pub version: String,
    pub capabilities: Vec<Capability>,
}

impl BundleMetadata {
    pub fn validate(&self) -> Result<(), InventoryError> {
        let caps: BTreeSet<_> = self.capabilities.iter().copied().collect();
        let valid = match self.kind {
            BundleKind::Host | BundleKind::Container => {
                caps == BTreeSet::from([Capability::Core, Capability::LocalStorage])
            },
            BundleKind::Addon => {
                caps == BTreeSet::from([Capability::PortainerAgent])
                    || caps == BTreeSet::from([Capability::D2k])
            },
        };
        if !valid
            || caps.len() != self.capabilities.len()
            || self.version.is_empty()
            || !self
                .version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_+".contains(&b))
        {
            return Err(InventoryError::InvalidBundleMetadata);
        }
        Ok(())
    }

    pub fn includes(&self, id: AssetId) -> bool {
        match self.kind {
            BundleKind::Container => id == AssetId::ImageDiorama,
            BundleKind::Host => !matches!(
                id,
                AssetId::ImageDiorama | AssetId::ImagePortainerAgent | AssetId::ImageD2k
            ),
            BundleKind::Addon => match id {
                AssetId::ImagePortainerAgent => {
                    self.capabilities.contains(&Capability::PortainerAgent)
                },
                AssetId::ImageD2k => self.capabilities.contains(&Capability::D2k),
                _ => false,
            },
        }
    }

    pub fn suffix(&self) -> &'static str {
        match self.kind {
            BundleKind::Host => "host",
            BundleKind::Container => "container",
            BundleKind::Addon if self.capabilities.contains(&Capability::PortainerAgent) => {
                "addon-portainer-agent"
            },
            BundleKind::Addon => "addon-d2k",
        }
    }

    pub fn image_reference(&self, id: AssetId) -> Option<String> {
        match id {
            AssetId::ImageDiorama => Some(format!("ghcr.io/geoffsee/diorama:{}", self.version)),
            AssetId::ImagePortainerAgent if self.kind == BundleKind::Addon => Some(format!(
                "ghcr.io/geoffsee/diorama-addon-portainer-agent:{}",
                self.version
            )),
            AssetId::ImageD2k if self.kind == BundleKind::Addon => Some(format!(
                "ghcr.io/geoffsee/diorama-addon-d2k:{}",
                self.version
            )),
            _ => catalog()
                .iter()
                .find(|entry| entry.id == id && entry.kind == Kind::Image)
                .map(|entry| entry.reference.to_owned()),
        }
    }
}

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
    InvalidBundleMetadata,
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
    #[serde(default)]
    bundle: Option<BundleMetadata>,
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
    bundle: Option<BundleMetadata>,
    pub(crate) blobs: Vec<Blob>,
    records: Vec<(AssetId, Delivery)>,
    pub(crate) limits: Limits,
}
impl Manifest {
    pub fn bundle(&self) -> Option<&BundleMetadata> {
        self.raw.bundle.as_ref()
    }
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
        match (self.raw.schema_version, &self.raw.bundle) {
            (1, None) => {},
            (2, Some(bundle))
                if request.scope == Scope::SupervisedBundle
                    && request.variant == Variant::Offline =>
            {
                bundle.validate()?;
            },
            _ => return Err(InventoryError::SchemaVersion),
        }
        if !self.raw.target.agrees(request.target) {
            return Err(InventoryError::TargetMismatch);
        }
        if self.raw.variant != request.variant || self.raw.scope != request.scope {
            return Err(InventoryError::RequestMismatch);
        }
        Ok(())
    }
    #[allow(clippy::too_many_lines)] // Validate the inventory once, retaining shared byte and path budgets.
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
                bundle: None,
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
            if self
                .raw
                .bundle
                .as_ref()
                .is_some_and(|b| !b.includes(record.id))
            {
                return Err(InventoryError::WrongDelivery(record.id));
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
                    // Host archives can hash the installed executable directly. Keep
                    // historical encodings valid without relaxing legacy or image rules.
                    let host_executable = entry.kind == Kind::Executable
                        && encoding == Encoding::Identity
                        && self
                            .raw
                            .bundle
                            .as_ref()
                            .is_some_and(|b| b.kind == BundleKind::Host);
                    if encoding != entry.encoding && !host_executable {
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
            if self
                .raw
                .bundle
                .as_ref()
                .is_none_or(|b| b.includes(entry.id))
                && !ids.contains(&entry.id)
            {
                return Err(InventoryError::MissingAsset(entry.id));
            }
        }
        blobs.sort_by_key(|blob| blob.id);
        records.sort_by_key(|r| r.0);
        Ok(DeclaredInventory {
            request,
            bundle: self.raw.bundle,
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
    pub fn bundle(&self) -> Option<&BundleMetadata> {
        self.bundle.as_ref()
    }
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

#[cfg(test)]
mod bundle_tests {
    use super::*;
    use serde_json::{Value, json};

    fn fixture(kind: BundleKind, capabilities: Vec<Capability>) -> Value {
        let mut value: Value =
            serde_json::from_str(include_str!("../tests/fixtures/offline-arm64.json")).unwrap();
        let bundle = BundleMetadata {
            kind,
            version: "v1.2.3".into(),
            capabilities,
        };
        value["schema_version"] = json!(2);
        value["assets"]
            .as_array_mut()
            .unwrap()
            .retain(|entry| bundle.includes(serde_json::from_value(entry["id"].clone()).unwrap()));
        value["bundle"] = serde_json::to_value(bundle).unwrap();
        value
    }
    fn validate(value: &Value) -> Result<DeclaredInventory, InventoryError> {
        Manifest::decode(&serde_json::to_vec(value).unwrap(), Limits::default())?
            .validate_inventory(
                InventoryRequest {
                    target: NodeTarget {
                        architecture: Architecture::Arm64,
                        libc: Libc::Glibc,
                    },
                    variant: Variant::Offline,
                    scope: Scope::SupervisedBundle,
                },
                Limits::default(),
            )
    }
    #[test]
    fn exact_capabilities_determine_required_assets() {
        for (kind, caps, count) in [
            (
                BundleKind::Host,
                vec![Capability::Core, Capability::LocalStorage],
                13,
            ),
            (
                BundleKind::Container,
                vec![Capability::Core, Capability::LocalStorage],
                1,
            ),
            (BundleKind::Addon, vec![Capability::PortainerAgent], 1),
            (BundleKind::Addon, vec![Capability::D2k], 1),
        ] {
            let mut fixture = fixture(kind, caps);
            assert_eq!(validate(&fixture).unwrap().bundled_assets().len(), count);
            fixture["assets"].as_array_mut().unwrap().pop();
            assert!(matches!(
                validate(&fixture),
                Err(InventoryError::MissingAsset(_))
            ));
        }
    }
    #[test]
    fn identity_executables_are_supported_only_by_new_host_inventories() {
        let mut host = fixture(
            BundleKind::Host,
            vec![Capability::Core, Capability::LocalStorage],
        );
        // Previously emitted host packs still use the catalog's zstd encodings.
        validate(&host).unwrap();
        for entry in catalog().iter().filter(|e| e.kind == Kind::Executable) {
            let record = host["assets"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|r| r["id"] == json!(entry.id))
                .unwrap();
            record["delivery"]["encoding"] = json!("identity");
        }
        validate(&host).unwrap();

        let legacy: Value =
            serde_json::from_str(include_str!("../tests/fixtures/offline-arm64.json")).unwrap();
        validate(&legacy).unwrap();
        for entry in catalog().iter().filter(|e| e.encoding == Encoding::Zstd) {
            let mut changed = legacy.clone();
            let record = changed["assets"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|r| r["id"] == json!(entry.id))
                .unwrap();
            record["delivery"]["encoding"] = json!("identity");
            assert!(
                matches!(validate(&changed), Err(InventoryError::WrongEncoding(id)) if id == entry.id)
            );
        }
        for entry in catalog().iter().filter(|e| {
            !matches!(
                e.id,
                AssetId::ImageDiorama | AssetId::ImagePortainerAgent | AssetId::ImageD2k
            )
        }) {
            let mut changed = host.clone();
            let record = changed["assets"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|r| r["id"] == json!(entry.id))
                .unwrap();
            record["delivery"]["encoding"] = json!(if entry.kind == Kind::Executable {
                "gzip"
            } else {
                "identity"
            });
            assert!(
                matches!(validate(&changed), Err(InventoryError::WrongEncoding(id)) if id == entry.id)
            );
        }
    }

    #[test]
    fn malformed_new_headers_cannot_downgrade_to_legacy() {
        let fixture = fixture(
            BundleKind::Host,
            vec![Capability::Core, Capability::LocalStorage],
        );
        for (field, replacement) in [
            ("capabilities", json!(["core"])),
            ("capabilities", json!(["core", "local-storage", "core"])),
            ("version", json!("")),
            ("version", json!("../escape")),
            ("kind", json!("addon")),
        ] {
            let mut changed = fixture.clone();
            changed["bundle"][field] = replacement;
            assert!(validate(&changed).is_err());
        }
        let mut changed = fixture.clone();
        changed["schema_version"] = json!(1);
        assert!(matches!(
            validate(&changed),
            Err(InventoryError::SchemaVersion)
        ));
        let mut changed = fixture.clone();
        changed.as_object_mut().unwrap().remove("bundle");
        assert!(matches!(
            validate(&changed),
            Err(InventoryError::SchemaVersion)
        ));
        let mut changed = fixture.clone();
        changed["target"]["architecture"] = json!("amd64");
        assert!(matches!(
            validate(&changed),
            Err(InventoryError::TargetMismatch)
        ));
        let mut changed = fixture;
        let duplicate = changed["assets"][0].clone();
        changed["assets"].as_array_mut().unwrap().push(duplicate);
        assert!(matches!(
            validate(&changed),
            Err(InventoryError::DuplicateAsset(_))
        ));
    }
}
