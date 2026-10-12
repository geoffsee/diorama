//! Streaming observations of the narrow single-image crane Docker-save profile.
use crate::{DecodeError, DecodeSession, DecodedObservation};
use diorama_platform::Architecture;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt};

#[derive(Clone, Copy, Debug)]
pub struct ArchiveLimits {
    pub archive_bytes: u64,
    pub members: usize,
    pub layer_references: usize,
    pub config_bytes: usize,
    pub manifest_bytes: usize,
    /// Includes scalar values, maximum 64 to bound recursive JSON processing.
    pub json_depth: usize,
    pub tags: usize,
    pub tag_bytes: usize,
}
impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            archive_bytes: 8 * 1024 * 1024 * 1024,
            members: 256,
            layer_references: 128,
            config_bytes: 1024 * 1024,
            manifest_bytes: 1024 * 1024,
            json_depth: 32,
            tags: 16,
            tag_bytes: 512,
        }
    }
}
impl ArchiveLimits {
    pub(crate) fn validate(self) -> Result<(), ArchivePolicyError> {
        if self.archive_bytes == 0
            || self.archive_bytes == u64::MAX
            || [
                self.members,
                self.layer_references,
                self.config_bytes,
                self.manifest_bytes,
                self.json_depth,
                self.tags,
                self.tag_bytes,
            ]
            .contains(&0)
            || self.json_depth > 64
        {
            return Err(ArchivePolicyError::InvalidLimits);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchivePolicyError {
    InvalidLimits,
    NotGzipImage,
    Limit,
    Allocation,
    Header,
    UnsupportedEntry,
    Name,
    DuplicateMember,
    Padding,
    Truncated,
    Trailing,
    MemberDigest,
    Json,
    Manifest,
    Config,
    References,
    ForeignLayers,
    PlatformMismatch,
    Layer(crate::LayerPolicyError),
}
impl fmt::Display for ArchivePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "image archive policy: {self:?}")
    }
}
impl std::error::Error for ArchivePolicyError {}
#[derive(Debug)]
pub enum ArchiveError {
    Policy(ArchivePolicyError),
    Decode(DecodeError<ArchivePolicyError>),
}
impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Policy(_) => "image archive inspection failed",
            Self::Decode(_) => "image archive decoding or provisional inspection failed",
        })
    }
}
impl std::error::Error for ArchiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(error) => Some(error),
            Self::Decode(error) => Some(error),
        }
    }
}
/// Agreement of declared configuration fields only, never execution/CPU compatibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImagePlatformStatus {
    DeclaredMatch,
    VariantUnresolved,
}
#[derive(Debug)]
pub struct ImageConfigObservation {
    sha256: [u8; 32],
    bytes: u64,
    os: String,
    architecture: String,
    variant: Option<String>,
    platform_status: ImagePlatformStatus,
}
impl ImageConfigObservation {
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn os(&self) -> &str {
        &self.os
    }
    pub fn architecture(&self) -> &str {
        &self.architecture
    }
    pub fn variant(&self) -> Option<&str> {
        self.variant.as_deref()
    }
    pub fn platform_status(&self) -> ImagePlatformStatus {
        self.platform_status
    }
}
/// Exact stored member bytes. Codec, layer tar safety and the declared `DiffID` are unverified.
#[derive(Debug)]
pub struct ArchiveLayerObservation {
    sha256: [u8; 32],
    bytes: u64,
    declared_diff_id: [u8; 32],
}
impl ArchiveLayerObservation {
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn declared_diff_id(&self) -> &[u8; 32] {
        &self.declared_diff_id
    }
}
/// Complete outer gzip/tar and member/reference observations. No registry manifest identity,
/// nested layer integrity, publisher authenticity, import or materialization permission.
///
/// ```compile_fail
/// use diorama_assets::{DockerArchiveObservation, DecodedObservation, ImageConfigObservation};
/// fn fabricate(decoded: DecodedObservation, config: ImageConfigObservation) -> DockerArchiveObservation {
///     DockerArchiveObservation { decoded, config, manifest_sha256: [0; 32], layers: vec![], repo_tags: vec![] }
/// }
/// ```
#[derive(Debug)]
pub struct DockerArchiveObservation {
    decoded: DecodedObservation,
    config: ImageConfigObservation,
    manifest_sha256: [u8; 32],
    layers: Vec<ArchiveLayerObservation>,
    repo_tags: Vec<String>,
}
impl DockerArchiveObservation {
    pub fn decoded_observation(&self) -> &DecodedObservation {
        &self.decoded
    }
    pub fn config(&self) -> &ImageConfigObservation {
        &self.config
    }
    /// Hash of Docker archive manifest.json, NOT the registry image manifest.
    pub fn archive_manifest_sha256(&self) -> &[u8; 32] {
        &self.manifest_sha256
    }
    /// Manifest order is retained, including repeated references to one stored blob.
    pub fn layers(&self) -> &[ArchiveLayerObservation] {
        &self.layers
    }
    /// Untrusted tag metadata; no registry resolution or catalog role authentication.
    pub fn repo_tags(&self) -> &[String] {
        &self.repo_tags
    }
}
impl DecodeSession<'_> {
    /// Inspect a single-image crane gzip tarball without retaining layer payloads or writing paths.
    /// All provisional state stays private until complete gzip and archive closure succeed.
    pub fn inspect_crane_image_archive(
        &mut self,
        id: crate::AssetId,
        bytes: &[u8],
        limits: ArchiveLimits,
    ) -> Result<DockerArchiveObservation, ArchiveError> {
        limits.validate().map_err(ArchiveError::Policy)?;
        let architecture = self.archive_target(id).map_err(ArchiveError::Policy)?;
        let mut parser = ArchiveParser::new(limits);
        let decoded = self
            .inspect_compressed_blob_capped(id, bytes, limits.archive_bytes, |chunk| {
                parser.push(chunk)
            })
            .map_err(ArchiveError::Decode)?;
        parser
            .finish(decoded, architecture)
            .map_err(ArchiveError::Policy)
    }
}
pub(crate) trait LayerObserver {
    fn start(&mut self, _size: u64, _budget: &mut u64) -> Result<(), ArchivePolicyError> {
        Ok(())
    }
    fn push(&mut self, _bytes: &[u8], _budget: &mut u64) -> Result<(), ArchivePolicyError> {
        Ok(())
    }
    fn end(&mut self, _digest: [u8; 32]) -> Result<(), ArchivePolicyError> {
        Ok(())
    }
}
impl LayerObserver for () {}
#[derive(Clone, Copy, PartialEq, Eq)]
enum MemberKind {
    Config,
    Layer,
    Manifest,
}
struct Member {
    kind: MemberKind,
    size: u64,
    digest: [u8; 32],
    data: Vec<u8>,
}
struct Current {
    name: String,
    kind: MemberKind,
    size: u64,
    remaining: u64,
    expected: Option<[u8; 32]>,
    hash: Sha256,
    data: Vec<u8>,
}
pub(crate) struct ArchiveParser {
    limits: ArchiveLimits,
    header: [u8; 512],
    header_used: usize,
    current: Option<Current>,
    padding: usize,
    zeros: u8,
    members: BTreeMap<String, Member>,
    config_seen: bool,
}
impl ArchiveParser {
    pub(crate) fn new(limits: ArchiveLimits) -> Self {
        Self {
            limits,
            header: [0; 512],
            header_used: 0,
            current: None,
            padding: 0,
            zeros: 0,
            members: BTreeMap::new(),
            config_seen: false,
        }
    }
    fn push(&mut self, bytes: &[u8]) -> Result<(), ArchivePolicyError> {
        self.push_observing(bytes, &mut (), &mut 0)
    }
    pub(crate) fn push_observing(
        &mut self,
        mut bytes: &[u8],
        layers: &mut impl LayerObserver,
        budget: &mut u64,
    ) -> Result<(), ArchivePolicyError> {
        while !bytes.is_empty() {
            if let Some(current) = self.current.as_mut() {
                let take = usize::try_from(
                    current
                        .remaining
                        .min(u64::try_from(bytes.len()).map_err(|_| ArchivePolicyError::Limit)?),
                )
                .map_err(|_| ArchivePolicyError::Limit)?;
                let chunk = &bytes[..take];
                current.hash.update(chunk);
                if current.kind == MemberKind::Layer {
                    layers.push(chunk, budget)?;
                } else {
                    current
                        .data
                        .try_reserve_exact(take)
                        .map_err(|_| ArchivePolicyError::Allocation)?;
                    current.data.extend_from_slice(chunk);
                }
                current.remaining -= u64::try_from(take).map_err(|_| ArchivePolicyError::Limit)?;
                bytes = &bytes[take..];
                if current.remaining == 0 {
                    self.complete_member(layers)?;
                }
            } else if self.padding != 0 {
                let take = self.padding.min(bytes.len());
                if bytes[..take].iter().any(|byte| *byte != 0) {
                    return Err(ArchivePolicyError::Padding);
                }
                self.padding -= take;
                bytes = &bytes[take..];
            } else {
                if self.zeros == 2 {
                    return Err(ArchivePolicyError::Trailing);
                }
                let take = (512 - self.header_used).min(bytes.len());
                self.header[self.header_used..self.header_used + take]
                    .copy_from_slice(&bytes[..take]);
                self.header_used += take;
                bytes = &bytes[take..];
                if self.header_used == 512 {
                    self.complete_header(layers, budget)?;
                }
            }
        }
        Ok(())
    }
    fn complete_header(
        &mut self,
        layers: &mut impl LayerObserver,
        budget: &mut u64,
    ) -> Result<(), ArchivePolicyError> {
        self.header_used = 0;
        if self.header.iter().all(|byte| *byte == 0) {
            self.zeros += 1;
            return Ok(());
        }
        if self.zeros != 0 {
            return Err(ArchivePolicyError::Header);
        }
        self.start_member(layers, budget)
    }
    fn start_member(
        &mut self,
        layers: &mut impl LayerObserver,
        budget: &mut u64,
    ) -> Result<(), ArchivePolicyError> {
        let header = &self.header;
        if &header[257..265] != b"ustar\x0000" {
            return Err(ArchivePolicyError::Header);
        }
        let checksum = octal(&header[148..156])?;
        let actual: u64 = header
            .iter()
            .enumerate()
            .map(|(i, byte)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    u64::from(*byte)
                }
            })
            .sum();
        if checksum != actual {
            return Err(ArchivePolicyError::Header);
        }
        if header[156] != b'0'
            || header[157..257].iter().any(|b| *b != 0)
            || header[345..].iter().any(|b| *b != 0)
        {
            return Err(ArchivePolicyError::UnsupportedEntry);
        }
        // Reject numeric encodings/extensions the narrow writer profile never needs.
        for range in [100..108, 108..116, 116..124, 136..148, 329..337, 337..345] {
            octal(&header[range])?;
        }
        let name = terminated(&header[..100])?;
        let (kind, expected) = member_name(name)?;
        let name = std::str::from_utf8(name)
            .map_err(|_| ArchivePolicyError::Name)?
            .to_owned();
        if self.members.contains_key(&name) {
            return Err(ArchivePolicyError::DuplicateMember);
        }
        if self.members.len() >= self.limits.members {
            return Err(ArchivePolicyError::Limit);
        }
        if kind == MemberKind::Config && self.config_seen {
            return Err(ArchivePolicyError::References);
        }
        let size = octal(&header[124..136])?;
        let metadata_limit = match kind {
            MemberKind::Config => self.limits.config_bytes,
            MemberKind::Manifest => self.limits.manifest_bytes,
            MemberKind::Layer => 0,
        };
        if size > self.limits.archive_bytes
            || (kind != MemberKind::Layer
                && size > u64::try_from(metadata_limit).map_err(|_| ArchivePolicyError::Limit)?)
        {
            return Err(ArchivePolicyError::Limit);
        }
        if kind == MemberKind::Layer {
            layers.start(size, budget)?;
        }
        self.config_seen |= kind == MemberKind::Config;
        self.current = Some(Current {
            name,
            kind,
            size,
            remaining: size,
            expected,
            hash: Sha256::new(),
            data: Vec::new(),
        });
        if size == 0 {
            self.complete_member(layers)?;
        }
        Ok(())
    }
    fn complete_member(
        &mut self,
        layers: &mut impl LayerObserver,
    ) -> Result<(), ArchivePolicyError> {
        let current = self.current.take().ok_or(ArchivePolicyError::Header)?;
        let digest: [u8; 32] = current.hash.finalize().into();
        if current.expected.is_some_and(|expected| expected != digest) {
            return Err(ArchivePolicyError::MemberDigest);
        }
        if current.kind == MemberKind::Layer {
            layers.end(digest)?;
        }
        self.padding = usize::try_from((512 - current.size % 512) % 512)
            .map_err(|_| ArchivePolicyError::Limit)?;
        self.members.insert(
            current.name,
            Member {
                kind: current.kind,
                size: current.size,
                digest,
                data: current.data,
            },
        );
        Ok(())
    }
    pub(crate) fn finish(
        self,
        decoded: DecodedObservation,
        architecture: Architecture,
    ) -> Result<DockerArchiveObservation, ArchivePolicyError> {
        if self.current.is_some() || self.padding != 0 || self.header_used != 0 || self.zeros != 2 {
            return Err(ArchivePolicyError::Truncated);
        }
        let manifest = self
            .members
            .get("manifest.json")
            .ok_or(ArchivePolicyError::Manifest)?;
        let value = strict_json(&manifest.data, self.limits.json_depth)?;
        let rows = value.as_array().ok_or(ArchivePolicyError::Manifest)?;
        if rows.len() != 1 {
            return Err(ArchivePolicyError::Manifest);
        }
        let row = rows[0].as_object().ok_or(ArchivePolicyError::Manifest)?;
        if row
            .keys()
            .any(|key| !["Config", "RepoTags", "Layers", "LayerSources"].contains(&key.as_str()))
        {
            return Err(ArchivePolicyError::Manifest);
        }
        if let Some(sources) = row.get("LayerSources")
            && !sources.is_null()
            && !sources.as_object().is_some_and(Map::is_empty)
        {
            return Err(ArchivePolicyError::ForeignLayers);
        }
        let config_name = row
            .get("Config")
            .and_then(Value::as_str)
            .ok_or(ArchivePolicyError::Manifest)?;
        let config = self
            .members
            .get(config_name)
            .filter(|m| m.kind == MemberKind::Config)
            .ok_or(ArchivePolicyError::References)?;
        let raw_config = strict_json(&config.data, self.limits.json_depth)?;
        let object = raw_config.as_object().ok_or(ArchivePolicyError::Config)?;
        let config_observation = observe_config(config, object, architecture)?;
        let rootfs = object
            .get("rootfs")
            .and_then(Value::as_object)
            .ok_or(ArchivePolicyError::Config)?;
        if rootfs.get("type").and_then(Value::as_str) != Some("layers") {
            return Err(ArchivePolicyError::Config);
        }
        let diffids = rootfs
            .get("diff_ids")
            .and_then(Value::as_array)
            .ok_or(ArchivePolicyError::Config)?;
        let layer_names = row
            .get("Layers")
            .and_then(Value::as_array)
            .ok_or(ArchivePolicyError::Manifest)?;
        if layer_names.len() > self.limits.layer_references || layer_names.len() != diffids.len() {
            return Err(ArchivePolicyError::References);
        }
        let mut used = BTreeMap::new();
        let mut layers = Vec::new();
        layers
            .try_reserve_exact(layer_names.len())
            .map_err(|_| ArchivePolicyError::Allocation)?;
        for (name, diffid) in layer_names.iter().zip(diffids) {
            let name = name.as_str().ok_or(ArchivePolicyError::Manifest)?;
            let member = self
                .members
                .get(name)
                .filter(|m| m.kind == MemberKind::Layer)
                .ok_or(ArchivePolicyError::References)?;
            let diffid = diffid
                .as_str()
                .and_then(|s| s.strip_prefix("sha256:"))
                .ok_or(ArchivePolicyError::Config)?;
            let diffid = digest_hex(diffid.as_bytes()).map_err(|_| ArchivePolicyError::Config)?;
            if used
                .insert(name, diffid)
                .is_some_and(|previous| previous != diffid)
            {
                return Err(ArchivePolicyError::References);
            }
            layers.push(ArchiveLayerObservation {
                sha256: member.digest,
                bytes: member.size,
                declared_diff_id: diffid,
            });
        }
        if self.members.len() != used.len().checked_add(2).ok_or(ArchivePolicyError::Limit)? {
            return Err(ArchivePolicyError::References);
        }
        let repo_tags = observe_tags(row.get("RepoTags"), self.limits)?;
        Ok(DockerArchiveObservation {
            decoded,
            manifest_sha256: manifest.digest,
            config: config_observation,
            layers,
            repo_tags,
        })
    }
}
fn observe_config(
    config: &Member,
    object: &Map<String, Value>,
    architecture: Architecture,
) -> Result<ImageConfigObservation, ArchivePolicyError> {
    let os = config_string(object, "os")?;
    let arch = config_string(object, "architecture")?;
    let variant = match object.get("variant") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.len() <= 64 => {
            if s.is_empty() {
                None
            } else {
                Some(s.clone())
            }
        },
        _ => return Err(ArchivePolicyError::Config),
    };
    let expected_arch = match architecture {
        Architecture::Amd64 => "amd64",
        Architecture::Arm64 => "arm64",
        Architecture::ArmV7 => "arm",
        Architecture::Riscv64 => "riscv64",
    };
    if os != "linux" || arch != expected_arch {
        return Err(ArchivePolicyError::PlatformMismatch);
    }
    let platform_status = if architecture == Architecture::ArmV7 {
        match variant.as_deref() {
            Some("v7") => ImagePlatformStatus::DeclaredMatch,
            None => ImagePlatformStatus::VariantUnresolved,
            _ => return Err(ArchivePolicyError::PlatformMismatch),
        }
    } else if variant.is_some() {
        ImagePlatformStatus::VariantUnresolved
    } else {
        ImagePlatformStatus::DeclaredMatch
    };
    Ok(ImageConfigObservation {
        sha256: config.digest,
        bytes: config.size,
        os,
        architecture: arch,
        variant,
        platform_status,
    })
}
fn observe_tags(
    value: Option<&Value>,
    limits: ArchiveLimits,
) -> Result<Vec<String>, ArchivePolicyError> {
    let tags: &[Value] = match value {
        Some(Value::Null) => &[],
        Some(Value::Array(tags)) => tags,
        _ => return Err(ArchivePolicyError::Manifest),
    };
    if tags.len() > limits.tags {
        return Err(ArchivePolicyError::Limit);
    }
    let mut repo_tags = Vec::new();
    repo_tags
        .try_reserve_exact(tags.len())
        .map_err(|_| ArchivePolicyError::Allocation)?;
    for tag in tags {
        let tag = tag.as_str().ok_or(ArchivePolicyError::Manifest)?;
        if tag.is_empty()
            || tag.len() > limits.tag_bytes
            || !tag.is_ascii()
            || tag.bytes().any(|b| b.is_ascii_control())
        {
            return Err(ArchivePolicyError::Manifest);
        }
        repo_tags.push(tag.to_owned());
    }
    Ok(repo_tags)
}
fn config_string(object: &Map<String, Value>, key: &str) -> Result<String, ArchivePolicyError> {
    let s = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(ArchivePolicyError::Config)?;
    if s.is_empty() || s.len() > 64 || !s.is_ascii() || s.bytes().any(|b| b.is_ascii_control()) {
        return Err(ArchivePolicyError::Config);
    }
    Ok(s.to_owned())
}
fn terminated(field: &[u8]) -> Result<&[u8], ArchivePolicyError> {
    let end = field
        .iter()
        .position(|b| *b == 0)
        .ok_or(ArchivePolicyError::Name)?;
    if field[end..].iter().any(|b| *b != 0) {
        return Err(ArchivePolicyError::Name);
    }
    Ok(&field[..end])
}
fn digest_hex(bytes: &[u8]) -> Result<[u8; 32], ArchivePolicyError> {
    if bytes.len() != 64 {
        return Err(ArchivePolicyError::Name);
    }
    let mut result = [0; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let nibble = |b| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(ArchivePolicyError::Name),
        };
        result[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(result)
}
fn member_name(name: &[u8]) -> Result<(MemberKind, Option<[u8; 32]>), ArchivePolicyError> {
    if name == b"manifest.json" {
        return Ok((MemberKind::Manifest, None));
    }
    if let Some(hex) = name.strip_prefix(b"sha256:") {
        return Ok((MemberKind::Config, Some(digest_hex(hex)?)));
    }
    if let Some(hex) = name.strip_suffix(b".tar.gz") {
        return Ok((MemberKind::Layer, Some(digest_hex(hex)?)));
    }
    Err(ArchivePolicyError::Name)
}
fn octal(field: &[u8]) -> Result<u64, ArchivePolicyError> {
    // Go's USTAR writer uses octal followed by NUL/space. Empty zero device fields allowed.
    let mut value = 0u64;
    let mut ended = false;
    for byte in field {
        match *byte {
            0 | b' ' => ended = true,
            b'0'..=b'7' if !ended => {
                value = value
                    .checked_mul(8)
                    .and_then(|v| v.checked_add(u64::from(*byte - b'0')))
                    .ok_or(ArchivePolicyError::Header)?;
            },
            _ => return Err(ArchivePolicyError::Header),
        }
    }
    Ok(value)
}
struct JsonSeed {
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for JsonSeed {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        if self.depth == 0 {
            return Err(de::Error::custom("JSON depth limit"));
        }
        de.deserialize_any(JsonVisitor {
            depth: self.depth - 1,
        })
    }
}
struct JsonVisitor {
    depth: usize,
}
impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON with unique object keys")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("nonfinite number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(value) = seq.next_element_seed(JsonSeed { depth: self.depth })? {
            out.push(value);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(de::Error::custom("duplicate object key"));
            }
            let value = map.next_value_seed(JsonSeed { depth: self.depth })?;
            out.insert(key, value);
        }
        Ok(Value::Object(out))
    }
}
pub(crate) fn strict_json(bytes: &[u8], depth: usize) -> Result<Value, ArchivePolicyError> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = JsonSeed { depth }
        .deserialize(&mut de)
        .map_err(|_| ArchivePolicyError::Json)?;
    de.end().map_err(|_| ArchivePolicyError::Json)?;
    Ok(value)
}

#[cfg(test)]
#[path = "../tests/common/archive.rs"]
pub(crate) mod vectors;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chunk_boundaries_preserve_headers_padding_and_member_digests() {
        let config = vectors::config("amd64", None, 1);
        let layer = vec![0x5a; 20001];
        let layers = [layer.as_slice()];
        let tar = vectors::archive(&config, &layers, &vectors::manifest(&config, &layers));
        for chunk_size in [1, 2, 7, 511, 512, 513, 8192] {
            let mut parser = ArchiveParser::new(ArchiveLimits::default());
            for chunk in tar.chunks(chunk_size) {
                parser.push(chunk).unwrap();
            }
            assert_eq!(parser.zeros, 2);
            assert_eq!(parser.header_used, 0);
            assert!(parser.current.is_none());
            assert_eq!(parser.members.len(), 3);
            let member = parser
                .members
                .get(&format!("{}.tar.gz", vectors::hex(&layer)))
                .unwrap();
            assert!(member.data.is_empty());
            assert_eq!(member.size, 20001);
            assert_eq!(member.digest.as_slice(), Sha256::digest(&layer).as_slice());
        }
    }
    #[test]
    fn every_partial_header_and_body_stays_provisional() {
        let tar = vectors::standard();
        for length in [1, 511, 512, 513, 1023, 1024, tar.len() - 513, tar.len() - 1] {
            let mut parser = ArchiveParser::new(ArchiveLimits::default());
            parser.push(&tar[..length]).unwrap();
            assert!(
                parser.current.is_some()
                    || parser.padding != 0
                    || parser.header_used != 0
                    || parser.zeros != 2
            );
        }
    }
}
