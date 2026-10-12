use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::error::DatastoreError;

pub const BACKUP_FORMAT_VERSION: &str = "diorama-datastore-v1";
pub const BACKUP_META_FILE: &str = "backup-meta.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub format_version: String,
    pub revision: u64,
    pub timestamp_secs: u64,
    pub total_keys: usize,
    pub snapshot_sha256: String,
}

impl BackupMetadata {
    pub fn compute_file_sha256(path: &Path) -> Result<String, DatastoreError> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        let hash = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in hash {
            let _ = write!(&mut hex, "{byte:02x}");
        }
        Ok(hex)
    }
}
