//! Exact declared platform-manifest binding, not publisher or registry authentication.
use crate::{
    AssetId, ImagePlatformStatus, Kind, LayerCodec, LayerDigestArchiveObservation, catalog,
};
use diorama_platform::Architecture;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

/// Narrow supported manifest profiles; required mediaType and string annotations only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageManifestFormat {
    OciV1,
    DockerV2,
}
impl ImageManifestFormat {
    fn manifest(self) -> &'static str {
        match self {
            Self::OciV1 => "application/vnd.oci.image.manifest.v1+json",
            Self::DockerV2 => "application/vnd.docker.distribution.manifest.v2+json",
        }
    }
    fn config(self) -> &'static str {
        match self {
            Self::OciV1 => "application/vnd.oci.image.config.v1+json",
            Self::DockerV2 => "application/vnd.docker.container.image.v1+json",
        }
    }
    fn layer(self, codec: LayerCodec) -> Option<&'static str> {
        match (self, codec) {
            (Self::OciV1, LayerCodec::Gzip) => Some("application/vnd.oci.image.layer.v1.tar+gzip"),
            (Self::OciV1, LayerCodec::Zstd) => Some("application/vnd.oci.image.layer.v1.tar+zstd"),
            (Self::DockerV2, LayerCodec::Gzip) => {
                Some("application/vnd.docker.image.rootfs.diff.tar.gzip")
            },
            (Self::DockerV2, LayerCodec::Zstd) => None,
        }
    }
}
/// Caller-declared expected identities. Construction does not approve or authenticate a pin.
/// Platform is Linux with the selected architecture, independent of host libc.
///
/// `archive_sha256` and `archive_bytes` describe the exact encoded Docker-save archive
/// previously verified by the decoding session. `manifest_sha256` and `manifest_bytes`
/// describe the separate raw platform-manifest document, including its whitespace.
/// Neither identity selects a registry index entry or authenticates a tag or publisher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclaredImageManifestPin {
    pub asset: AssetId,
    pub architecture: Architecture,
    pub archive_sha256: [u8; 32],
    pub archive_bytes: u64,
    pub manifest_sha256: [u8; 32],
    pub manifest_bytes: u64,
    pub format: ImageManifestFormat,
}
/// Caller policy for raw manifest bytes, ordered layer references, and JSON depth.
///
/// The byte bound applies before hashing or parsing. The reference bound applies
/// after bounded JSON parsing; repeated references count separately. These are
/// admission limits, not hard CPU/RSS bounds or recoverable-allocation guarantees.
#[derive(Clone, Copy, Debug)]
pub struct ManifestBindingLimits {
    pub manifest_bytes: usize,
    pub layer_references: usize,
    pub json_depth: usize,
}
impl Default for ManifestBindingLimits {
    fn default() -> Self {
        Self {
            manifest_bytes: 1 << 20,
            layer_references: 1024,
            json_depth: 32,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestBindingError {
    InvalidLimits,
    InvalidPin,
    Limit,
    Asset,
    ArchiveIdentity,
    Platform,
    ManifestIdentity,
    Json,
    Profile,
    Descriptor,
    Config,
    Layers,
    Codec,
}
impl fmt::Display for ManifestBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "image manifest binding: {self:?}")
    }
}
impl std::error::Error for ManifestBindingError {}
/// Complete byte identities match caller declarations, not a trusted publisher or index.
///
/// Retains the completed archive/layer observation and its matched declaration.
/// It does not prove inner-tar safety, ABI compatibility, import permission, or
/// installation eligibility. No production payload pin is approved by this type.
/// ```compile_fail
/// use diorama_assets::{ImageManifestBinding, DeclaredImageManifestPin, LayerDigestArchiveObservation};
/// fn forge(pin: DeclaredImageManifestPin, observation: LayerDigestArchiveObservation) -> ImageManifestBinding {
///     ImageManifestBinding { pin, observation }
/// }
/// ```
#[derive(Debug)]
pub struct ImageManifestBinding {
    pin: DeclaredImageManifestPin,
    observation: LayerDigestArchiveObservation,
}
impl ImageManifestBinding {
    pub fn declared_pin(&self) -> &DeclaredImageManifestPin {
        &self.pin
    }
    pub fn observation(&self) -> &LayerDigestArchiveObservation {
        &self.observation
    }
}
impl LayerDigestArchiveObservation {
    /// Bind this exact completed archive to a separately supplied declared platform-manifest pin.
    /// This performs no further decoding, IO, callbacks, session creation, or budget refunds.
    /// On failure no binding escapes; the consumed completed observation is discarded.
    ///
    /// Requires Linux config platform status `DeclaredMatch`, an exact config
    /// descriptor, and every ordered stored-layer digest, size, and codec media type.
    /// OCI supports gzip/zstd; Docker schema 2 supports gzip. Only the documented
    /// image-manifest fields and string annotations are admitted. Indexes, external
    /// descriptor URLs/data, artifact manifests, and unsupported layer media fail.
    pub fn bind_manifest(
        self,
        pin: &DeclaredImageManifestPin,
        raw: &[u8],
        limits: ManifestBindingLimits,
    ) -> Result<ImageManifestBinding, ManifestBindingError> {
        validate_limits_pin(pin, raw, limits)?;
        let archive = self.archive();
        let encoded = archive.decoded_observation().encoded();
        if encoded.id() != pin.asset {
            return Err(ManifestBindingError::Asset);
        }
        if encoded.sha256() != &pin.archive_sha256 || encoded.encoded_bytes() != pin.archive_bytes {
            return Err(ManifestBindingError::ArchiveIdentity);
        }
        let config = archive.config();
        let arch = match pin.architecture {
            Architecture::Amd64 => "amd64",
            Architecture::Arm64 => "arm64",
            Architecture::ArmV7 => "arm",
            Architecture::Riscv64 => "riscv64",
        };
        if config.os() != "linux"
            || config.architecture() != arch
            || config.platform_status() != ImagePlatformStatus::DeclaredMatch
        {
            return Err(ManifestBindingError::Platform);
        }
        let length = u64::try_from(raw.len()).map_err(|_| ManifestBindingError::Limit)?;
        if length != pin.manifest_bytes
            || <[u8; 32]>::from(Sha256::digest(raw)) != pin.manifest_sha256
        {
            return Err(ManifestBindingError::ManifestIdentity);
        }
        let value = crate::archive::strict_json(raw, limits.json_depth)
            .map_err(|_| ManifestBindingError::Json)?;
        let object = profile(
            &value,
            &[
                "schemaVersion",
                "mediaType",
                "config",
                "layers",
                "annotations",
            ],
        )?;
        if object.get("schemaVersion").and_then(Value::as_u64) != Some(2)
            || object.get("mediaType").and_then(Value::as_str) != Some(pin.format.manifest())
        {
            return Err(ManifestBindingError::Profile);
        }
        let config_descriptor =
            descriptor(object.get("config").ok_or(ManifestBindingError::Profile)?)?;
        if config_descriptor.media != pin.format.config() {
            return Err(ManifestBindingError::Codec);
        }
        if config_descriptor.digest != *config.sha256() || config_descriptor.size != config.bytes()
        {
            return Err(ManifestBindingError::Config);
        }
        let layers = object
            .get("layers")
            .and_then(Value::as_array)
            .ok_or(ManifestBindingError::Profile)?;
        if layers.len() > limits.layer_references {
            return Err(ManifestBindingError::Limit);
        }
        if layers.len() != self.layers().len() {
            return Err(ManifestBindingError::Layers);
        }
        for (value, observed) in layers.iter().zip(self.layers()) {
            let row = descriptor(value)?;
            if Some(row.media) != pin.format.layer(observed.codec()) {
                return Err(ManifestBindingError::Codec);
            }
            if row.digest != *observed.stored_sha256() || row.size != observed.stored_bytes() {
                return Err(ManifestBindingError::Layers);
            }
        }
        Ok(ImageManifestBinding {
            pin: *pin,
            observation: self,
        })
    }
}
fn validate_limits_pin(
    pin: &DeclaredImageManifestPin,
    raw: &[u8],
    limits: ManifestBindingLimits,
) -> Result<(), ManifestBindingError> {
    if limits.manifest_bytes == 0
        || limits.layer_references == 0
        || !(1..=64).contains(&limits.json_depth)
    {
        return Err(ManifestBindingError::InvalidLimits);
    }
    if pin.manifest_bytes == 0
        || pin.archive_bytes == 0
        || pin.archive_bytes == u64::MAX
        || !catalog()
            .iter()
            .any(|entry| entry.id == pin.asset && entry.kind == Kind::Image)
    {
        return Err(ManifestBindingError::InvalidPin);
    }
    if raw.len() > limits.manifest_bytes
        || usize::try_from(pin.manifest_bytes).map_or(true, |n| n > limits.manifest_bytes)
    {
        return Err(ManifestBindingError::Limit);
    }
    Ok(())
}
fn profile<'a>(
    value: &'a Value,
    allowed: &[&str],
) -> Result<&'a Map<String, Value>, ManifestBindingError> {
    let object = value.as_object().ok_or(ManifestBindingError::Profile)?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(ManifestBindingError::Profile);
    }
    if let Some(annotations) = object.get("annotations") {
        let annotations = annotations
            .as_object()
            .ok_or(ManifestBindingError::Profile)?;
        if annotations.values().any(|value| !value.is_string()) {
            return Err(ManifestBindingError::Profile);
        }
    }
    Ok(object)
}
struct Descriptor<'a> {
    media: &'a str,
    digest: [u8; 32],
    size: u64,
}
fn descriptor(value: &Value) -> Result<Descriptor<'_>, ManifestBindingError> {
    let o = profile(value, &["mediaType", "digest", "size", "annotations"])?;
    let media = o
        .get("mediaType")
        .and_then(Value::as_str)
        .ok_or(ManifestBindingError::Descriptor)?;
    let size = o
        .get("size")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0 && i64::try_from(*n).is_ok())
        .ok_or(ManifestBindingError::Descriptor)?;
    let text = o
        .get("digest")
        .and_then(Value::as_str)
        .and_then(|s| s.strip_prefix("sha256:"))
        .ok_or(ManifestBindingError::Descriptor)?;
    if text.len() != 64 {
        return Err(ManifestBindingError::Descriptor);
    }
    let mut digest = [0; 32];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let nibble = |b| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(ManifestBindingError::Descriptor),
        };
        digest[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(Descriptor {
        media,
        digest,
        size,
    })
}
