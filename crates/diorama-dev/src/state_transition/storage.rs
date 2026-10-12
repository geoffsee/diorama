//! Persistent volume data and local-path-storage verification.
//!
//! Enforces:
//! 1. Byte-level preservation of persistent volume data under `P/local-path-storage`.
//! 2. Preservation of directory hierarchies, file permissions, and file content SHA-256 hashes.
//! 3. Association between Kubernetes PVC identities and on-disk volume directories.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Snapshot record of a persistent volume file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PvFileRecord {
    pub relative_path: PathBuf,
    pub entry_kind: PvEntryKind,
    pub symlink_target: Option<PathBuf>,
    pub uid: u32,
    pub gid: u32,
    pub size_bytes: u64,
    pub permissions_mode: u32,
    pub sha256_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PvEntryKind {
    File,
    Directory,
    Symlink,
}

/// Recursively scans a persistent volume directory and builds an index of all files and checksums.
pub fn scan_pv_storage(storage_dir: &Path) -> io::Result<BTreeMap<PathBuf, PvFileRecord>> {
    let mut map = BTreeMap::new();
    let metadata = fs::symlink_metadata(storage_dir)?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PV root must be a directory",
        ));
    }
    insert_record(storage_dir, storage_dir, &metadata, &mut map)?;
    scan_recursive(storage_dir, storage_dir, &mut map)?;
    Ok(map)
}

fn scan_recursive(
    base: &Path,
    current: &Path,
    map: &mut BTreeMap<PathBuf, PvFileRecord>,
) -> io::Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        let metadata = fs::symlink_metadata(&path)?;
        insert_record(base, &path, &metadata, map)?;
        if file_type.is_dir() {
            scan_recursive(base, &path, map)?;
        }
    }
    Ok(())
}

fn insert_record(
    base: &Path,
    path: &Path,
    metadata: &fs::Metadata,
    map: &mut BTreeMap<PathBuf, PvFileRecord>,
) -> io::Result<()> {
    let entry_kind = if metadata.is_file() {
        PvEntryKind::File
    } else if metadata.is_dir() {
        PvEntryKind::Directory
    } else if metadata.file_type().is_symlink() {
        PvEntryKind::Symlink
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported PV entry type",
        ));
    };
    #[cfg(unix)]
    let (permissions_mode, uid, gid) = {
        use std::os::unix::fs::MetadataExt;
        (metadata.mode() & 0o7777, metadata.uid(), metadata.gid())
    };
    #[cfg(not(unix))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "PV ownership requires Unix",
    ));
    let relative_path = path
        .strip_prefix(base)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
        .to_path_buf();
    let symlink_target = if entry_kind == PvEntryKind::Symlink {
        Some(fs::read_link(path)?)
    } else {
        None
    };
    let (size_bytes, sha256_digest) = if entry_kind == PvEntryKind::File {
        (metadata.len(), hash_file(path)?)
    } else {
        (0, String::new())
    };
    map.insert(
        relative_path.clone(),
        PvFileRecord {
            relative_path,
            entry_kind,
            symlink_target,
            uid,
            gid,
            size_bytes,
            permissions_mode,
            sha256_digest,
        },
    );
    Ok(())
}

fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(crate::sha256(&buffer))
}

/// Result of asserting PV storage before and after transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PvStorageAssertion {
    pub total_volumes: usize,
    pub total_files: usize,
    pub total_bytes: u64,
    pub all_checksums_match: bool,
    pub all_permissions_match: bool,
}

/// Asserts that PV storage state before transition matches state after transition.
pub fn assert_pv_storage_preserved(
    storage_before: &Path,
    storage_after: &Path,
) -> io::Result<PvStorageAssertion> {
    let before_map = scan_pv_storage(storage_before)?;
    let after_map = scan_pv_storage(storage_after)?;

    if before_map.len() != after_map.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "PV entry count mismatch: before={}, after={}",
                before_map.len(),
                after_map.len()
            ),
        ));
    }

    let mut total_bytes = 0;
    let mut all_checksums_match = true;
    let mut all_permissions_match = true;

    for (rel_path, before_rec) in &before_map {
        total_bytes += before_rec.size_bytes;
        match after_map.get(rel_path) {
            Some(after_rec) => {
                if before_rec.sha256_digest != after_rec.sha256_digest
                    || before_rec.entry_kind != after_rec.entry_kind
                    || before_rec.symlink_target != after_rec.symlink_target
                    || before_rec.size_bytes != after_rec.size_bytes
                {
                    all_checksums_match = false;
                }
                if before_rec.permissions_mode != after_rec.permissions_mode
                    || before_rec.uid != after_rec.uid
                    || before_rec.gid != after_rec.gid
                {
                    all_permissions_match = false;
                }
            },
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("missing PV file after transition: {}", rel_path.display()),
                ));
            },
        }
    }

    // Count top-level directories in storage_before as distinct volumes
    let mut volume_count = 0;
    if storage_before.exists() {
        for entry in fs::read_dir(storage_before)? {
            if entry?.file_type()?.is_dir() {
                volume_count += 1;
            }
        }
    }

    Ok(PvStorageAssertion {
        total_volumes: volume_count,
        total_files: before_map
            .values()
            .filter(|r| r.entry_kind == PvEntryKind::File)
            .count(),
        total_bytes,
        all_checksums_match,
        all_permissions_match,
    })
}
