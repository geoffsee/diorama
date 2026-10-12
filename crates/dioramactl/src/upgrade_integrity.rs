//! Retained snapshot checksums: recovery never learns expected bytes from damaged state.
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    path::Path,
};

const RECORD: &str = ".snapshot-integrity.json";

fn inventory(root: &Path, dir: &Path, entries: &mut BTreeMap<String, String>) -> io::Result<()> {
    for item in fs::read_dir(dir)? {
        let path = item?.path();
        if path == root.join(RECORD) {
            continue;
        }
        let meta = path.symlink_metadata()?;
        let relative = path.strip_prefix(root).map_err(io::Error::other)?;
        let name = relative
            .to_str()
            .ok_or_else(|| io::Error::other("non-UTF8 backup path"))?;
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o7777
        };
        #[cfg(not(unix))]
        let mode = u32::from(meta.permissions().readonly());
        let value = if meta.is_dir() {
            inventory(root, &path, entries)?;
            format!("directory:{mode:o}")
        } else if meta.is_file() {
            let mut file = fs::File::open(&path)?;
            let mut hash = Sha256::new();
            let mut buffer = [0; 8192];
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
            }
            let mut digest = String::with_capacity(64);
            for byte in hash.finalize() {
                use std::fmt::Write;
                write!(&mut digest, "{byte:02x}").map_err(io::Error::other)?;
            }
            format!("file:{mode:o}:{}:{digest}", meta.len())
        } else {
            return Err(io::Error::other(format!(
                "unsafe backup entry {}",
                path.display()
            )));
        };
        entries.insert(name.into(), value);
    }
    Ok(())
}

/// Seal a completed quiesced snapshot, including its backend-specific artifacts.
/// This evidence detects accidental corruption; it is not an authenticated backup signature.
pub fn seal_backup(backup: &Path) -> io::Result<()> {
    let mut entries = BTreeMap::new();
    inventory(backup, backup, &mut entries)?;
    let mut record = tempfile::NamedTempFile::new_in(backup)?;
    serde_json::to_writer(&mut record, &entries)?;
    record.flush()?;
    record.as_file().sync_all()?;
    record
        .persist_noclobber(backup.join(RECORD))
        .map_err(|e| e.error)?;
    fs::File::open(backup)?.sync_all()
}

pub(crate) fn verify(backup: &Path) -> io::Result<()> {
    let record = backup.join(RECORD);
    if !record.symlink_metadata()?.is_file() {
        return Err(io::Error::other("unsafe snapshot integrity record"));
    }
    let expected: BTreeMap<String, String> = serde_json::from_reader(fs::File::open(record)?)?;
    let mut actual = BTreeMap::new();
    inventory(backup, backup, &mut actual)?;
    if expected != actual {
        return Err(io::Error::other(
            "snapshot contents differ from retained integrity evidence",
        ));
    }
    Ok(())
}
