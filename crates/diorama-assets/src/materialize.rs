//! Safe materialization of verified dependency assets into configured writable roots.
use crate::{
    AssetId, DeclaredInventory, Delivery, Encoding, InventoryError, Kind, VerificationError,
    catalog,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File},
    io::{self, Read, Seek, Write},
    path::{Path, PathBuf},
};

/// Default Unix file mode for executable binaries: `rwxr-xr-x`.
pub const EXECUTABLE_PERMISSIONS: u32 = 0o755;

/// Default Unix file mode for image archives and data payloads: `rw-r--r--`.
pub const PAYLOAD_PERMISSIONS: u32 = 0o644;

/// Resource bounds for asset materialization.
#[derive(Clone, Copy, Debug)]
pub struct MaterializationLimits {
    pub max_asset_bytes: u64,
    pub max_total_bytes: u64,
    pub max_archive_members: usize,
    pub path_bytes: usize,
}

impl Default for MaterializationLimits {
    fn default() -> Self {
        Self {
            max_asset_bytes: 8 * 1024 * 1024 * 1024,
            max_total_bytes: 32 * 1024 * 1024 * 1024,
            max_archive_members: 1024,
            path_bytes: 4096,
        }
    }
}

impl MaterializationLimits {
    pub fn valid(self) -> bool {
        self.max_asset_bytes > 0
            && self.max_asset_bytes < u64::MAX
            && self.max_total_bytes > 0
            && self.max_archive_members > 0
            && self.path_bytes > 0
    }
}

/// Errors occurring during asset materialization.
#[derive(Debug)]
pub enum MaterializationError {
    InvalidLimits,
    SelectorMismatch,
    BudgetExceeded {
        limit: u64,
        requested: u64,
    },
    PathEscapesRoot(PathBuf),
    InvalidRelativePath(String),
    ReadOnlyDestination {
        path: PathBuf,
        source: io::Error,
    },
    CorruptArchive(String),
    MissingAssetPayload(AssetId),
    /// The attached selector does not permit bundled materialization of this asset.
    NotSelected(AssetId),
    SizeMismatch {
        asset: AssetId,
        expected: u64,
        observed: u64,
    },
    DigestMismatch {
        asset: AssetId,
        expected: [u8; 32],
        observed: [u8; 32],
    },
    DecompressionFailed {
        asset: AssetId,
        encoding: Encoding,
        message: String,
    },
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Inventory(InventoryError),
    Verification(VerificationError),
    UnsupportedPlatform,
    RollbackFailed {
        path: PathBuf,
        source: io::Error,
    },
}

impl fmt::Display for MaterializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => write!(f, "invalid materialization limits"),
            Self::SelectorMismatch => write!(
                f,
                "selector target, variant or scope does not match the declared inventory"
            ),
            Self::BudgetExceeded { limit, requested } => write!(
                f,
                "materialization budget exceeded: requested {requested}, limit {limit}"
            ),
            Self::PathEscapesRoot(path) => {
                write!(
                    f,
                    "path escapes configured writable root: {}",
                    path.display()
                )
            },
            Self::InvalidRelativePath(path) => {
                write!(f, "invalid relative asset path: {path}")
            },
            Self::ReadOnlyDestination { path, source } => write!(
                f,
                "destination path is read-only at '{}': {source}",
                path.display()
            ),
            Self::CorruptArchive(msg) => write!(f, "corrupt asset archive: {msg}"),
            Self::MissingAssetPayload(id) => {
                write!(f, "missing payload for bundled asset {id:?}")
            },
            Self::NotSelected(id) => write!(
                f,
                "asset {id:?} is not selected for bundled materialization"
            ),
            Self::SizeMismatch {
                asset,
                expected,
                observed,
            } => write!(
                f,
                "asset {asset:?} size mismatch: expected {expected}, observed {observed}"
            ),
            Self::DigestMismatch { asset, .. } => {
                write!(f, "asset {asset:?} digest mismatch")
            },
            Self::DecompressionFailed {
                asset,
                encoding,
                message,
            } => write!(
                f,
                "asset {asset:?} decompression failed for {encoding:?}: {message}"
            ),
            Self::Io { path, source } => {
                write!(f, "I/O error at '{}': {source}", path.display())
            },
            Self::Inventory(err) => write!(f, "inventory error: {err}"),
            Self::Verification(err) => write!(f, "verification error: {err}"),
            Self::UnsupportedPlatform => write!(f, "safe asset materialization requires Unix"),
            Self::RollbackFailed { path, source } => write!(
                f,
                "asset rollback failed; recovery files retained at '{}': {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for MaterializationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadOnlyDestination { source, .. }
            | Self::Io { source, .. }
            | Self::RollbackFailed { source, .. } => Some(source),
            Self::Inventory(err) => Some(err),
            Self::Verification(err) => Some(err),
            _ => None,
        }
    }
}

impl From<InventoryError> for MaterializationError {
    fn from(err: InventoryError) -> Self {
        Self::Inventory(err)
    }
}

impl From<VerificationError> for MaterializationError {
    fn from(err: VerificationError) -> Self {
        Self::Verification(err)
    }
}

/// Destination layout for placing assets inside a configured writable root.
#[derive(Clone, Debug)]
pub struct AssetLayout {
    overrides: BTreeMap<AssetId, String>,
}

impl Default for AssetLayout {
    fn default() -> Self {
        Self::canonical()
    }
}

impl AssetLayout {
    /// Canonical diorama placement within the writable root.
    pub fn canonical() -> Self {
        Self {
            overrides: BTreeMap::new(),
        }
    }

    /// Default relative path for an asset within the root.
    pub fn default_relative_path(id: AssetId) -> &'static str {
        match id {
            AssetId::Containerd => "bin/containerd",
            AssetId::ContainerdShim => "bin/containerd-shim-runc-v2",
            AssetId::Crun => "bin/crun",
            AssetId::CniBridge => "cni/bin/bridge",
            AssetId::CniHostLocal => "cni/bin/host-local",
            AssetId::CniPortmap => "cni/bin/portmap",
            AssetId::CniLoopback => "cni/bin/loopback",
            AssetId::FuseOverlayfsSnapshotter => "bin/containerd-fuse-overlayfs-grpc",
            AssetId::ImageCoredns => "images/coredns.tar.gz",
            AssetId::ImagePause => "images/pause.tar.gz",
            AssetId::ImageLocalPath => "images/local-path-provisioner.tar.gz",
            AssetId::ImageLocalPathHelper => "images/busybox.tar.gz",
            AssetId::ImagePortainerAgent => "images/portainer-agent.tar.gz",
            AssetId::ImageD2k => "images/d2k.tar.gz",
            AssetId::ImageDiorama => "images/diorama.tar.gz",
        }
    }

    /// Construct a layout matching the paths declared in the manifest.
    pub fn from_manifest(inventory: &DeclaredInventory) -> Self {
        let mut overrides = BTreeMap::new();
        for (id, delivery) in inventory.assets() {
            if let Delivery::Bundled { path, .. } = delivery {
                overrides.insert(id, path.clone());
            }
        }
        Self { overrides }
    }

    /// Override the relative path for a specific asset.
    #[must_use]
    pub fn with_path(mut self, id: AssetId, relative: impl Into<String>) -> Self {
        self.overrides.insert(id, relative.into());
        self
    }

    /// Get relative path for an asset in this layout.
    pub fn relative_path(&self, id: AssetId) -> &str {
        self.overrides
            .get(&id)
            .map_or_else(|| Self::default_relative_path(id), String::as_str)
    }

    /// Resolve and validate the target destination path within `root`.
    pub fn resolve_destination(
        &self,
        root: &Path,
        id: AssetId,
    ) -> Result<PathBuf, MaterializationError> {
        let rel = self.relative_path(id);
        validate_and_join_path(root, rel)
    }
}

/// Metadata recorded for an extracted asset on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedAsset {
    pub id: AssetId,
    pub path: PathBuf,
    pub kind: Kind,
    pub mode: u32,
    pub bytes_written: u64,
    pub sha256: [u8; 32],
}

/// Result of materializing a batch or complete inventory of assets.
#[derive(Clone, Debug)]
pub struct MaterializationOutcome {
    pub root: PathBuf,
    pub assets: Vec<MaterializedAsset>,
}

impl MaterializationOutcome {
    pub fn get(&self, id: AssetId) -> Option<&MaterializedAsset> {
        self.assets.iter().find(|a| a.id == id)
    }

    pub fn paths(&self) -> impl Iterator<Item = (AssetId, &Path)> {
        self.assets.iter().map(|a| (a.id, a.path.as_path()))
    }
}

/// Orchestrates safe, atomic, and idempotent extraction of dependency assets.
#[derive(Debug)]
pub struct Materializer {
    inventory: DeclaredInventory,
    root: PathBuf,
    layout: AssetLayout,
    limits: MaterializationLimits,
    selector: Option<crate::AssetSelector>,
}

impl Materializer {
    /// Construct a materializer for the given inventory and configured writable root.
    pub fn new(inventory: DeclaredInventory, root: impl Into<PathBuf>) -> Self {
        Self {
            inventory,
            root: root.into(),
            layout: AssetLayout::canonical(),
            limits: MaterializationLimits::default(),
            selector: None,
        }
    }

    #[must_use]
    pub fn with_layout(mut self, layout: AssetLayout) -> Self {
        self.layout = layout;
        self
    }

    #[must_use]
    pub fn with_limits(mut self, limits: MaterializationLimits) -> Self {
        self.limits = limits;
        self
    }

    #[must_use]
    /// Attach selection policy. Every entry point rejects a target, variant or scope
    /// mismatch before opening payloads or creating the writable root.
    pub fn with_selector(mut self, selector: crate::AssetSelector) -> Self {
        self.selector = Some(selector);
        self
    }

    pub fn selector(&self) -> Option<&crate::AssetSelector> {
        self.selector.as_ref()
    }

    pub fn inventory(&self) -> &DeclaredInventory {
        &self.inventory
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn layout(&self) -> &AssetLayout {
        &self.layout
    }

    pub fn limits(&self) -> MaterializationLimits {
        self.limits
    }

    fn validate_selector(&self) -> Result<(), MaterializationError> {
        let request = self.inventory.request();
        if let Some(selector) = &self.selector
            && (selector.target() != request.target
                || selector.variant() != request.variant
                || selector.scope() != request.scope)
        {
            return Err(MaterializationError::SelectorMismatch);
        }
        Ok(())
    }

    /// Materialize all bundled assets by streaming them from an archive reader (tar or tar.gz).
    pub fn materialize_from_archive<R: Read>(
        &self,
        reader: R,
    ) -> Result<MaterializationOutcome, MaterializationError> {
        self.validate_selector()?;
        if !self.limits.valid() {
            return Err(MaterializationError::InvalidLimits);
        }

        let guard = StagingGuard::create(&self.root)?;
        let temp_dir = &guard.path;

        let mut entries = TarReader::new(reader, self.limits)?;
        let mut remaining: BTreeMap<_, _> = self
            .inventory
            .bundled_assets()
            .filter(|(id, _, _, _)| {
                self.selector
                    .as_ref()
                    .is_none_or(|selector| selector.is_bundled(*id))
            })
            .map(|(id, path, encoding, _)| (path.to_string(), (id, encoding)))
            .collect();
        let expected = remaining.clone();
        let mut materialized = Vec::new();
        while let Some(mut member) = entries.next_entry()? {
            let Some((id, encoding)) = remaining.remove(&member.name) else {
                if expected.contains_key(&member.name) {
                    return Err(MaterializationError::CorruptArchive(
                        "duplicate selected asset member".to_string(),
                    ));
                }
                io::copy(&mut member, &mut io::sink())
                    .map_err(|e| MaterializationError::CorruptArchive(e.to_string()))?;
                continue;
            };

            let entry = catalog()
                .iter()
                .find(|e| e.id == id)
                .ok_or(MaterializationError::MissingAssetPayload(id))?;

            let final_dest = self.layout.resolve_destination(&self.root, id)?;
            let staged_dest = temp_dir.join(format!("staged-{}", id_tag(id)));

            let asset = materialize_blob_to_path(
                &self.inventory,
                id,
                entry.kind,
                encoding,
                &mut member,
                &guard.file,
                &staged_dest,
                &final_dest,
                self.limits,
            )?;
            materialized.push((staged_dest, final_dest, asset));
        }
        if let Some((id, _)) = remaining.into_values().next() {
            return Err(MaterializationError::MissingAssetPayload(id));
        }

        let outcomes = guard.commit(&self.root, materialized)?;

        Ok(MaterializationOutcome {
            root: self.root.clone(),
            assets: outcomes,
        })
    }

    /// Materialize all bundled assets from a directory on disk.
    pub fn materialize_from_dir(
        &self,
        source_dir: &Path,
    ) -> Result<MaterializationOutcome, MaterializationError> {
        self.materialize_from_payloads(|id, rel_path| {
            let file_path = source_dir.join(rel_path);
            let file = File::open(&file_path).map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    MaterializationError::MissingAssetPayload(id)
                } else {
                    map_io_error(&file_path, e)
                }
            })?;
            Ok(Box::new(file))
        })
    }

    /// Materialize bundled assets using a payload reader provider closure.
    pub fn materialize_from_payloads<F>(
        &self,
        mut get_payload: F,
    ) -> Result<MaterializationOutcome, MaterializationError>
    where
        F: FnMut(AssetId, &str) -> Result<Box<dyn Read>, MaterializationError>,
    {
        self.validate_selector()?;
        if !self.limits.valid() {
            return Err(MaterializationError::InvalidLimits);
        }

        let guard = StagingGuard::create(&self.root)?;
        let temp_dir = &guard.path;

        let mut staged_assets = Vec::new();
        for (id, rel_path, encoding, _expected_bytes) in self.inventory.bundled_assets() {
            if let Some(ref selector) = self.selector
                && !selector.is_bundled(id)
            {
                continue;
            }

            let mut reader = get_payload(id, rel_path)?;
            let entry = catalog()
                .iter()
                .find(|e| e.id == id)
                .ok_or(MaterializationError::MissingAssetPayload(id))?;

            let final_dest = self.layout.resolve_destination(&self.root, id)?;
            let staged_dest = temp_dir.join(format!("staged-{}", id_tag(id)));

            let asset = materialize_blob_to_path(
                &self.inventory,
                id,
                entry.kind,
                encoding,
                &mut reader,
                &guard.file,
                &staged_dest,
                &final_dest,
                self.limits,
            )?;
            staged_assets.push((staged_dest, final_dest, asset));
        }

        let outcomes = guard.commit(&self.root, staged_assets)?;

        Ok(MaterializationOutcome {
            root: self.root.clone(),
            assets: outcomes,
        })
    }

    /// Materialize a single asset from a reader into its destination path.
    pub fn materialize_single_asset<R: Read>(
        &self,
        id: AssetId,
        mut reader: R,
    ) -> Result<MaterializedAsset, MaterializationError> {
        self.validate_selector()?;
        if !self.limits.valid() {
            return Err(MaterializationError::InvalidLimits);
        }

        if self
            .selector
            .as_ref()
            .is_some_and(|selector| !selector.is_bundled(id))
        {
            return Err(MaterializationError::NotSelected(id));
        }

        let blob = self
            .inventory
            .blobs
            .iter()
            .find(|b| b.id == id)
            .ok_or(MaterializationError::MissingAssetPayload(id))?;

        let entry = catalog()
            .iter()
            .find(|e| e.id == id)
            .ok_or(MaterializationError::MissingAssetPayload(id))?;

        let final_dest = self.layout.resolve_destination(&self.root, id)?;
        let guard = StagingGuard::create(&self.root)?;
        let temp_dir = &guard.path;

        let staged_dest = temp_dir.join(format!("staged-{}", id_tag(id)));
        let asset = materialize_blob_to_path(
            &self.inventory,
            id,
            entry.kind,
            blob.encoding,
            &mut reader,
            &guard.file,
            &staged_dest,
            &final_dest,
            self.limits,
        )?;

        guard
            .commit(&self.root, vec![(staged_dest, final_dest, asset)])?
            .pop()
            .ok_or(MaterializationError::MissingAssetPayload(id))
    }
}

/// Copy through fixed-size buffers; the byte limit is independent of memory use.
fn copy_and_hash<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    limit: u64,
    path: &Path,
) -> Result<(u64, [u8; 32]), MaterializationError> {
    let mut count = 0u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|e| map_io_error(path, e))?;
        if read == 0 {
            break;
        }
        count = count.saturating_add(read as u64);
        if count > limit {
            return Err(MaterializationError::BudgetExceeded {
                limit,
                requested: count,
            });
        }
        hasher.update(&buffer[..read]);
        writer
            .write_all(&buffer[..read])
            .map_err(|e| map_io_error(path, e))?;
    }
    Ok((count, hasher.finalize().into()))
}

/// Internal helper to extract/decompress a single blob into `staged_path`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn materialize_blob_to_path<R: Read>(
    inventory: &DeclaredInventory,
    id: AssetId,
    kind: Kind,
    encoding: Encoding,
    reader: R,
    staging: &File,
    staged_path: &Path,
    final_dest: &Path,
    limits: MaterializationLimits,
) -> Result<MaterializedAsset, MaterializationError> {
    let blob = inventory
        .blobs
        .iter()
        .find(|b| b.id == id)
        .ok_or(MaterializationError::MissingAssetPayload(id))?;
    let expected_mode = match kind {
        Kind::Executable => EXECUTABLE_PERMISSIONS,
        Kind::Image => PAYLOAD_PERMISSIONS,
    };
    let mut out_file = create_staged_file(staging, staged_path)?;
    // Compressed executables spool their verified encoding to private disk, not RAM.
    // Gzip image archives retain their encoded bytes in the final staged file.
    let mut encoded_file = if encoding == Encoding::Zstd {
        Some(create_staged_file(
            staging,
            &staged_path.with_file_name(format!("encoded-{}", id_tag(id))),
        )?)
    } else {
        None
    };
    let encoded_dest = encoded_file.as_mut().unwrap_or(&mut out_file);
    let (encoded_count, encoded_hash) = copy_and_hash(
        &mut reader.take(blob.bytes.saturating_add(1)),
        encoded_dest,
        limits.max_asset_bytes,
        staged_path,
    )?;
    if encoded_count != blob.bytes {
        return Err(MaterializationError::SizeMismatch {
            asset: id,
            expected: blob.bytes,
            observed: encoded_count,
        });
    }
    if encoded_hash != blob.digest {
        return Err(MaterializationError::DigestMismatch {
            asset: id,
            expected: blob.digest,
            observed: encoded_hash,
        });
    }
    let decompression_error = |error: io::Error| MaterializationError::DecompressionFailed {
        asset: id,
        encoding,
        message: error.to_string(),
    };
    let (written_bytes, written_hash) = match encoding {
        Encoding::Identity => (encoded_count, encoded_hash),
        Encoding::Zstd => {
            let mut encoded = encoded_file.ok_or(MaterializationError::MissingAssetPayload(id))?;
            encoded.rewind().map_err(|e| map_io_error(staged_path, e))?;
            let mut decoder =
                zstd::stream::read::Decoder::new(encoded).map_err(decompression_error)?;
            copy_and_hash(
                &mut decoder,
                &mut out_file,
                limits.max_asset_bytes,
                staged_path,
            )?
        },
        Encoding::Gzip => {
            out_file
                .rewind()
                .map_err(|e| map_io_error(staged_path, e))?;
            let mut decoder = flate2::bufread::GzDecoder::new(io::BufReader::new(&mut out_file));
            // Drain with a bounded output budget to verify the trailer without allocating.
            copy_and_hash(
                &mut decoder,
                &mut io::sink(),
                limits.max_asset_bytes,
                staged_path,
            )?;
            let mut probe = [0];
            if decoder
                .get_mut()
                .read(&mut probe)
                .map_err(decompression_error)?
                != 0
            {
                return Err(MaterializationError::DecompressionFailed {
                    asset: id,
                    encoding,
                    message: "data after gzip member".to_string(),
                });
            }
            (encoded_count, encoded_hash)
        },
    };
    out_file.flush().map_err(|e| map_io_error(staged_path, e))?;
    out_file
        .sync_all()
        .map_err(|e| map_io_error(staged_path, e))?;
    set_file_mode(&out_file, expected_mode).map_err(|e| map_io_error(staged_path, e))?;
    out_file
        .rewind()
        .map_err(|e| map_io_error(staged_path, e))?;
    let (on_disk_len, on_disk_hash) = copy_and_hash(
        &mut out_file,
        &mut io::sink(),
        limits.max_asset_bytes,
        staged_path,
    )?;
    if on_disk_len != written_bytes {
        return Err(MaterializationError::SizeMismatch {
            asset: id,
            expected: written_bytes,
            observed: on_disk_len,
        });
    }
    if on_disk_hash != written_hash {
        return Err(MaterializationError::DigestMismatch {
            asset: id,
            expected: written_hash,
            observed: on_disk_hash,
        });
    }
    Ok(MaterializedAsset {
        id,
        path: final_dest.to_path_buf(),
        kind,
        mode: expected_mode,
        bytes_written: written_bytes,
        sha256: written_hash,
    })
}

/// Validate path to prevent directory traversal outside `root`.
fn validate_and_join_path(root: &Path, rel: &str) -> Result<PathBuf, MaterializationError> {
    if rel.is_empty() || rel.contains('\\') || rel.contains(':') {
        return Err(MaterializationError::InvalidRelativePath(rel.to_string()));
    }
    if rel.starts_with('/') {
        return Err(MaterializationError::PathEscapesRoot(PathBuf::from(rel)));
    }
    for part in rel.split('/') {
        if part == ".." {
            return Err(MaterializationError::PathEscapesRoot(root.join(rel)));
        }
        if part.is_empty() || part == "." {
            return Err(MaterializationError::InvalidRelativePath(rel.to_string()));
        }
    }
    let joined = root.join(rel);
    // Path must start with root
    if !joined.starts_with(root) {
        return Err(MaterializationError::PathEscapesRoot(joined));
    }
    Ok(joined)
}

/// Pins owned directories and serializes materializers of the same root.
struct StagingGuard {
    path: PathBuf,
    name: String,
    root_dir: File,
    file: File,
    _lock: File,
    retain: bool,
}

impl StagingGuard {
    #[cfg(unix)]
    fn create(root: &Path) -> Result<Self, MaterializationError> {
        use rustix::fs::{CWD, FlockOperation, Mode, OFlags, flock, mkdirat, openat};
        fs::create_dir_all(root).map_err(|e| map_io_error(root, e))?;
        let root_dir = File::from(
            openat(
                CWD,
                root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| map_io_error(root, e.into()))?,
        );
        let lock_path = root.join(".materialization.lock");
        let lock = open_materialization_lock(&root_dir, &lock_path)?;
        if !lock
            .metadata()
            .map_err(|e| map_io_error(&lock_path, e))?
            .is_file()
        {
            return Err(MaterializationError::PathEscapesRoot(lock_path));
        }
        flock(&lock, FlockOperation::LockExclusive)
            .map_err(|e| map_io_error(&lock_path, e.into()))?;
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let name = format!(".staging-{}-{unique_id}", std::process::id());
        let path = root.join(&name);
        mkdirat(
            &root_dir,
            name.as_str(),
            Mode::RUSR | Mode::WUSR | Mode::XUSR,
        )
        .map_err(|e| map_io_error(&path, e.into()))?;
        let opened = openat(
            &root_dir,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        );
        let file = match opened {
            Ok(fd) => File::from(fd),
            Err(source) => {
                let _ =
                    rustix::fs::unlinkat(&root_dir, name.as_str(), rustix::fs::AtFlags::REMOVEDIR);
                return Err(map_io_error(&path, source.into()));
            },
        };
        Ok(Self {
            path,
            name,
            root_dir,
            file,
            _lock: lock,
            retain: false,
        })
    }

    #[cfg(not(unix))]
    fn create(_root: &Path) -> Result<Self, MaterializationError> {
        Err(MaterializationError::UnsupportedPlatform)
    }

    /// Preflight every destination, then retain originals until the whole batch succeeds.
    #[cfg(unix)]
    fn commit(
        mut self,
        root: &Path,
        staged: Vec<(PathBuf, PathBuf, MaterializedAsset)>,
    ) -> Result<Vec<MaterializedAsset>, MaterializationError> {
        use rustix::fs::{AtFlags, FileType, statat};
        let mut targets = Vec::new();
        let mut paths = std::collections::BTreeSet::new();
        for (source, destination, asset) in staged {
            if !paths.insert(destination.clone()) {
                return Err(MaterializationError::InvalidRelativePath(
                    destination.display().to_string(),
                ));
            }
            let (parent, name) = destination_parent(&self.root_dir, root, &destination)?;
            let had_existing = match statat(&parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile => true,
                Ok(_) => return Err(MaterializationError::PathEscapesRoot(destination)),
                Err(rustix::io::Errno::NOENT) => false,
                Err(e) => return Err(map_io_error(&destination, e.into())),
            };
            let source = source
                .file_name()
                .ok_or_else(|| {
                    MaterializationError::InvalidRelativePath(source.display().to_string())
                })?
                .to_owned();
            let backup = format!("backup-{}", id_tag(asset.id));
            targets.push(CommitTarget {
                parent,
                name,
                source,
                backup,
                had_existing,
                backed_up: false,
                installed: false,
                asset,
            });
        }
        for index in 0..targets.len() {
            if let Err(error) = targets[index].install(&self.file) {
                self.rollback(&targets[..=index])?;
                return Err(error);
            }
        }
        Ok(targets.into_iter().map(|target| target.asset).collect())
    }

    #[cfg(unix)]
    fn rollback(&mut self, targets: &[CommitTarget]) -> Result<(), MaterializationError> {
        let mut rollback_error = None;
        for target in targets.iter().rev() {
            if let Err(source) = target.rollback(&self.file) {
                rollback_error = Some(source);
            }
        }
        if let Some(source) = rollback_error {
            self.retain = true;
            return Err(MaterializationError::RollbackFailed {
                path: self.path.clone(),
                source: source.into(),
            });
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn commit(
        self,
        _root: &Path,
        _staged: Vec<(PathBuf, PathBuf, MaterializedAsset)>,
    ) -> Result<Vec<MaterializedAsset>, MaterializationError> {
        Err(MaterializationError::UnsupportedPlatform)
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if !self.retain {
            use rustix::fs::{AtFlags, unlinkat};
            // Never walk the staging pathname: it may have been replaced by a symlink.
            for entry in catalog() {
                for prefix in ["staged", "backup", "encoded"] {
                    let name = format!("{prefix}-{}", id_tag(entry.id));
                    let _ = unlinkat(&self.file, name.as_str(), AtFlags::empty());
                }
            }
            let _ = unlinkat(&self.root_dir, self.name.as_str(), AtFlags::REMOVEDIR);
        }
    }
}

#[cfg(unix)]
struct CommitTarget {
    parent: File,
    name: std::ffi::OsString,
    source: std::ffi::OsString,
    backup: String,
    had_existing: bool,
    backed_up: bool,
    installed: bool,
    asset: MaterializedAsset,
}

#[cfg(unix)]
impl CommitTarget {
    fn install(&mut self, staging: &File) -> Result<(), MaterializationError> {
        use rustix::fs::renameat;
        if self.had_existing {
            renameat(&self.parent, &self.name, staging, self.backup.as_str())
                .map_err(|e| map_io_error(&self.asset.path, e.into()))?;
            self.backed_up = true;
        }
        renameat(staging, &self.source, &self.parent, &self.name)
            .map_err(|e| map_io_error(&self.asset.path, e.into()))?;
        self.installed = true;
        Ok(())
    }

    fn rollback(&self, staging: &File) -> rustix::io::Result<()> {
        use rustix::fs::{AtFlags, renameat, unlinkat};
        if self.backed_up {
            renameat(staging, self.backup.as_str(), &self.parent, &self.name)
        } else if self.installed {
            unlinkat(&self.parent, &self.name, AtFlags::empty())
        } else {
            Ok(())
        }
    }
}

#[cfg(unix)]
fn open_materialization_lock(root: &File, path: &Path) -> Result<File, MaterializationError> {
    use rustix::fs::{Mode, OFlags, openat};
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    // Separate exclusive creation from opening an existing lock. In particular,
    // concurrent O_CREAT|O_NOFOLLOW calls can report ENOENT on Darwin.
    match openat(
        root,
        ".materialization.lock",
        flags | OFlags::CREATE | OFlags::EXCL,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(fd) => Ok(File::from(fd)),
        Err(rustix::io::Errno::EXIST) => {
            openat(root, ".materialization.lock", flags, Mode::empty())
                .map(File::from)
                .map_err(|e| map_io_error(path, e.into()))
        },
        Err(e) => Err(map_io_error(path, e.into())),
    }
}

#[cfg(unix)]
fn destination_parent(
    root_dir: &File,
    root: &Path,
    destination: &Path,
) -> Result<(File, std::ffi::OsString), MaterializationError> {
    use rustix::fs::{Mode, OFlags, mkdirat, openat};
    let relative = destination
        .strip_prefix(root)
        .map_err(|_| MaterializationError::PathEscapesRoot(destination.to_owned()))?;
    let mut parent = root_dir.try_clone().map_err(|e| map_io_error(root, e))?;
    let components = relative.components().collect::<Vec<_>>();
    let mut observed = root.to_owned();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            return Err(MaterializationError::PathEscapesRoot(
                destination.to_owned(),
            ));
        };
        observed.push(name);
        if index + 1 == components.len() {
            return Ok((parent, name.to_os_string()));
        }
        match mkdirat(&parent, *name, Mode::from_raw_mode(0o755)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {},
            Err(e) => return Err(map_io_error(&observed, e.into())),
        }
        parent = File::from(
            openat(
                &parent,
                *name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| map_io_error(&observed, e.into()))?,
        );
    }
    Err(MaterializationError::PathEscapesRoot(
        destination.to_owned(),
    ))
}

#[cfg(unix)]
fn create_staged_file(staging: &File, path: &Path) -> Result<File, MaterializationError> {
    use rustix::fs::{Mode, OFlags, openat};
    let name = path
        .file_name()
        .ok_or_else(|| MaterializationError::PathEscapesRoot(path.to_owned()))?;
    openat(
        staging,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(|e| map_io_error(path, e.into()))
}

#[cfg(not(unix))]
fn create_staged_file(_staging: &File, _path: &Path) -> Result<File, MaterializationError> {
    Err(MaterializationError::UnsupportedPlatform)
}

fn id_tag(id: AssetId) -> &'static str {
    match id {
        AssetId::Containerd => "containerd",
        AssetId::ContainerdShim => "containerd-shim-runc-v2",
        AssetId::Crun => "crun",
        AssetId::CniBridge => "cni-bridge",
        AssetId::CniHostLocal => "cni-host-local",
        AssetId::CniPortmap => "cni-portmap",
        AssetId::CniLoopback => "cni-loopback",
        AssetId::FuseOverlayfsSnapshotter => "fuse-overlayfs-snapshotter",
        AssetId::ImageCoredns => "image-coredns",
        AssetId::ImagePause => "image-pause",
        AssetId::ImageLocalPath => "image-local-path",
        AssetId::ImageLocalPathHelper => "image-local-path-helper",
        AssetId::ImagePortainerAgent => "image-portainer-agent",
        AssetId::ImageD2k => "image-d2k",
        AssetId::ImageDiorama => "image-diorama",
    }
}

fn map_io_error(path: &Path, source: io::Error) -> MaterializationError {
    if source.kind() == io::ErrorKind::PermissionDenied {
        MaterializationError::ReadOnlyDestination {
            path: path.to_path_buf(),
            source,
        }
    } else {
        MaterializationError::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

#[cfg(unix)]
fn set_file_mode(file: &File, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_file_mode(_file: &File, _mode: u32) -> io::Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Streaming POSIX Tar Archive Reader
// ---------------------------------------------------------------------------

enum ArchiveReader<R> {
    Plain(io::Chain<io::Cursor<Vec<u8>>, R>),
    Gzip(flate2::bufread::GzDecoder<io::BufReader<io::Chain<io::Cursor<Vec<u8>>, R>>>),
}

impl<R: Read> Read for ArchiveReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(r) => r.read(buf),
            Self::Gzip(r) => r.read(buf),
        }
    }
}

struct TarReader<R> {
    reader: ArchiveReader<R>,
    limits: MaterializationLimits,
    entries_count: usize,
    total_bytes: u64,
    finished: bool,
}

struct TarEntryReader<'a, R> {
    reader: &'a mut R,
    pub name: String,
    remaining: u64,
    padding: usize,
}

impl<R: Read> TarReader<R> {
    fn new(mut reader: R, limits: MaterializationLimits) -> Result<Self, MaterializationError> {
        // Detect gzip header (0x1f, 0x8b)
        let mut header = [0u8; 2];
        let n = read_exact_or_eof(&mut reader, &mut header)
            .map_err(|e| MaterializationError::CorruptArchive(e.to_string()))?;

        let chained = io::Cursor::new(header[..n].to_vec()).chain(reader);
        let archive_reader = if n == 2 && header[0] == 0x1f && header[1] == 0x8b {
            ArchiveReader::Gzip(flate2::bufread::GzDecoder::new(io::BufReader::new(chained)))
        } else {
            ArchiveReader::Plain(chained)
        };

        Ok(TarReader {
            reader: archive_reader,
            limits,
            entries_count: 0,
            total_bytes: 0,
            finished: false,
        })
    }

    fn next_entry(
        &mut self,
    ) -> Result<Option<TarEntryReader<'_, ArchiveReader<R>>>, MaterializationError> {
        if self.finished {
            return Ok(None);
        }

        let mut block = [0u8; 512];
        loop {
            let n = read_exact_or_eof(&mut self.reader, &mut block)
                .map_err(|e| MaterializationError::CorruptArchive(e.to_string()))?;
            if n == 0 {
                return Err(MaterializationError::CorruptArchive(
                    "missing tar EOF blocks".to_string(),
                ));
            }
            if n < 512 {
                return Err(MaterializationError::CorruptArchive(
                    "truncated tar header".to_string(),
                ));
            }

            // Two consecutive zero blocks signal end of archive
            if block.iter().all(|&b| b == 0) {
                // Read next block to check for second zero block
                self.reader
                    .read_exact(&mut block)
                    .map_err(|e| MaterializationError::CorruptArchive(e.to_string()))?;
                if block.iter().any(|&byte| byte != 0) {
                    return Err(MaterializationError::CorruptArchive(
                        "missing second tar EOF block".to_string(),
                    ));
                }
                self.finish()?;
                self.finished = true;
                return Ok(None);
            }

            // Verify tar header checksum
            let expected_checksum = parse_octal(&block[148..156]).ok_or_else(|| {
                MaterializationError::CorruptArchive("invalid tar checksum field".to_string())
            })?;

            let mut unsigned_sum = 0u32;
            for (idx, &byte) in block.iter().enumerate() {
                if (148..156).contains(&idx) {
                    unsigned_sum += 32; // treat checksum field as ASCII spaces
                } else {
                    unsigned_sum += u32::from(byte);
                }
            }

            if u64::from(unsigned_sum) != expected_checksum {
                return Err(MaterializationError::CorruptArchive(
                    "tar header checksum mismatch".to_string(),
                ));
            }

            let typeflag = block[156];
            let size = parse_octal(&block[124..136]).ok_or_else(|| {
                MaterializationError::CorruptArchive("invalid tar member size".to_string())
            })?;

            let name = parse_tar_name(&block)?;

            self.entries_count = self.entries_count.saturating_add(1);
            if self.entries_count > self.limits.max_archive_members {
                return Err(MaterializationError::CorruptArchive(
                    "archive member count limit exceeded".to_string(),
                ));
            }
            self.total_bytes = self.total_bytes.saturating_add(size);
            if self.total_bytes > self.limits.max_total_bytes {
                return Err(MaterializationError::BudgetExceeded {
                    limit: self.limits.max_total_bytes,
                    requested: self.total_bytes,
                });
            }

            // Only regular files (typeflag '0' or '\0')
            if typeflag != b'0' && typeflag != 0 {
                // Skip non-file entries (e.g. directories)
                let padding = ((512 - (size % 512)) % 512) as usize;
                let skip = size.checked_add(padding as u64).ok_or(
                    MaterializationError::CorruptArchive("size overflow".to_string()),
                )?;
                let skipped = io::copy(&mut (&mut self.reader).take(skip), &mut io::sink())
                    .map_err(|e| MaterializationError::CorruptArchive(e.to_string()))?;
                if skipped != skip {
                    return Err(MaterializationError::CorruptArchive(
                        "truncated non-file tar member".to_string(),
                    ));
                }
                continue;
            }

            let padding = ((512 - (size % 512)) % 512) as usize;
            return Ok(Some(TarEntryReader {
                reader: &mut self.reader,
                name,
                remaining: size,
                padding,
            }));
        }
    }

    /// Tar EOF is provisional until the bounded outer stream has ended cleanly.
    fn finish(&mut self) -> Result<(), MaterializationError> {
        let mut trailing = [0; 8192];
        loop {
            let read = self
                .reader
                .read(&mut trailing)
                .map_err(|e| MaterializationError::CorruptArchive(e.to_string()))?;
            if read == 0 {
                break;
            }
            self.total_bytes = self.total_bytes.saturating_add(read as u64);
            if self.total_bytes > self.limits.max_total_bytes {
                return Err(MaterializationError::BudgetExceeded {
                    limit: self.limits.max_total_bytes,
                    requested: self.total_bytes,
                });
            }
            if trailing[..read].iter().any(|&byte| byte != 0) {
                return Err(MaterializationError::CorruptArchive(
                    "nonzero data after tar EOF".to_string(),
                ));
            }
        }
        if let ArchiveReader::Gzip(decoder) = &mut self.reader {
            // One RFC1952 member: buffered decoding preserves bytes after its trailer.
            let mut probe = [0];
            if decoder
                .get_mut()
                .read(&mut probe)
                .map_err(|e| MaterializationError::CorruptArchive(e.to_string()))?
                != 0
            {
                return Err(MaterializationError::CorruptArchive(
                    "data after outer gzip member".to_string(),
                ));
            }
        }
        Ok(())
    }
}

impl<R: Read> Read for TarEntryReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            if self.padding > 0 {
                let mut pad = [0u8; 512];
                self.reader.read_exact(&mut pad[..self.padding])?;
                self.padding = 0;
            }
            return Ok(0);
        }

        let max = buf
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let n = self.reader.read(&mut buf[..max])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tar member truncated",
            ));
        }
        self.remaining -= n as u64;

        if self.remaining == 0 && self.padding > 0 {
            let mut pad = [0u8; 512];
            self.reader.read_exact(&mut pad[..self.padding])?;
            self.padding = 0;
        }

        Ok(n)
    }
}

fn read_exact_or_eof<R: Read>(reader: &mut R, mut buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while !buf.is_empty() {
        match reader.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                let tmp = buf;
                buf = &mut tmp[n..];
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {},
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

fn parse_octal(bytes: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(bytes).ok()?.trim().trim_matches('\0');
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(text, 8).ok()
}

fn parse_tar_name(block: &[u8; 512]) -> Result<String, MaterializationError> {
    let name_bytes = &block[0..100];
    let prefix_bytes = &block[345..500];

    let name = extract_null_terminated(name_bytes)
        .map_err(|_| MaterializationError::CorruptArchive("non-utf8 tar name".to_string()))?;
    let prefix = extract_null_terminated(prefix_bytes)
        .map_err(|_| MaterializationError::CorruptArchive("non-utf8 tar prefix".to_string()))?;

    let full_name = if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    };

    if full_name.is_empty()
        || full_name.starts_with('/')
        || full_name.split('/').any(|p| p == ".." || p == ".")
    {
        return Err(MaterializationError::CorruptArchive(
            "unsafe tar entry path".to_string(),
        ));
    }

    Ok(full_name)
}

fn extract_null_terminated(bytes: &[u8]) -> Result<String, std::str::Utf8Error> {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..len]).map(str::to_string)
}

#[cfg(all(test, unix))]
mod transaction_tests {
    use super::*;

    #[test]
    fn rollback_failure_retains_recovery_backup() {
        let root = std::env::temp_dir().join(format!(
            "diorama-retained-backup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("bin/containerd")).unwrap();
        let mut guard = StagingGuard::create(&root).unwrap();
        let backup = guard.path.join("backup-containerd");
        create_staged_file(&guard.file, &backup)
            .unwrap()
            .write_all(b"original")
            .unwrap();
        let target = CommitTarget {
            parent: File::open(root.join("bin")).unwrap(),
            name: "containerd".into(),
            source: "staged-containerd".into(),
            backup: "backup-containerd".into(),
            had_existing: true,
            backed_up: true,
            installed: false,
            asset: MaterializedAsset {
                id: AssetId::Containerd,
                path: root.join("bin/containerd"),
                kind: Kind::Executable,
                mode: EXECUTABLE_PERMISSIONS,
                bytes_written: 8,
                sha256: [0; 32],
            },
        };
        assert!(matches!(
            guard.rollback(&[target]),
            Err(MaterializationError::RollbackFailed { .. })
        ));
        drop(guard);
        assert_eq!(fs::read(backup).unwrap(), b"original");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn late_commit_error_rolls_back_new_and_replaced_files() {
        for replace_first in [false, true] {
            let root = std::env::temp_dir().join(format!(
                "diorama-rollback-{}-{}-{}",
                std::process::id(),
                replace_first,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(root.join("bin")).unwrap();
            let first = root.join("bin/containerd");
            let second = root.join("bin/crun");
            if replace_first {
                fs::write(&first, b"original-first").unwrap();
            }
            fs::write(&second, b"original-second").unwrap();
            let guard = StagingGuard::create(&root).unwrap();
            let staged_first = guard.path.join("staged-containerd");
            create_staged_file(&guard.file, &staged_first)
                .unwrap()
                .write_all(b"new-first")
                .unwrap();
            // The second verified staging file disappears before its rename. The real
            // filesystem error occurs after the first destination has been committed.
            let staged_second = guard.path.join("staged-crun");
            let assets = [
                (staged_first, first.clone(), AssetId::Containerd),
                (staged_second, second.clone(), AssetId::Crun),
            ]
            .into_iter()
            .map(|(staged, path, id)| {
                let asset = MaterializedAsset {
                    id,
                    path: path.clone(),
                    kind: Kind::Executable,
                    mode: EXECUTABLE_PERMISSIONS,
                    bytes_written: 9,
                    sha256: [0; 32],
                };
                (staged, path, asset)
            })
            .collect();
            assert!(guard.commit(&root, assets).is_err());
            if replace_first {
                assert_eq!(fs::read(&first).unwrap(), b"original-first");
            } else {
                assert!(!first.exists());
            }
            assert_eq!(fs::read(second).unwrap(), b"original-second");
            assert!(!fs::read_dir(&root).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".staging-")
            }));
            fs::remove_dir_all(root).unwrap();
        }
    }
}
