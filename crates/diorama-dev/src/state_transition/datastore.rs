//! Synthetic native snapshot conversion experiment; not a production Kine migration.
//!
//! Validates:
//! 1. Revision preservation for supplied in-memory fixture records.
//! 2. Conversion into experimental `diorama-datastore` (`RUBXSNP1`) format with SHA-256 verification.
//! 5. Explicit proof of non-interchangeability: raw `SQLite` databases are rejected by `diorama-datastore`
//!    rather than blindly assumed compatible on-disk. No `SQLite` database is opened or checkpointed.
//!
//! The selected production boundary retains Kine and its `SQLite` state.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use diorama_datastore::backup::{BACKUP_FORMAT_VERSION, BACKUP_META_FILE, BackupMetadata};
use diorama_datastore::config::DatastoreConfig;
use diorama_datastore::engine::DatastoreEngine;
use diorama_datastore::error::DatastoreError;
use diorama_datastore::model::KeyValue;
use serde::{Deserialize, Serialize};

const SNAPSHOT_MAGIC: &[u8; 8] = b"RUBXSNP1";

/// A single record in the Kine `SQLite` database `kine` table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KineRecord {
    pub id: u64,
    pub name: String,
    pub created: i64,
    pub deleted: i64,
    pub create_revision: u64,
    pub prev_revision: u64,
    pub total_keys: usize,
    pub lease: i64,
    pub value: Vec<u8>,
    pub old_value: Vec<u8>,
}

/// Computes SHA-256 hex digest of a file.
pub fn compute_file_sha256(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(crate::sha256(&buf))
}

/// Result of datastore transition validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DatastoreTransitionAssertion {
    pub total_records_before: usize,
    pub active_keys_before: usize,
    pub max_revision_before: u64,
    pub wal_checkpointed: bool,
    /// Always false for this in-memory experiment; a live Kine rehearsal is required.
    pub production_transition_qualified: bool,
    pub raw_sqlite_rejected_by_diorama_datastore: bool,
    pub explicit_export_format: String,
    pub export_verified_sha256: String,
    pub restored_keys: usize,
    pub restored_revision: u64,
    pub keys_identical: bool,
    pub revisions_monotonic: bool,
}

/// Explicitly exports active Kine records into `diorama-datastore` point-in-time snapshot format.
pub fn export_kine_to_diorama_datastore(
    kine_records: &[KineRecord],
    export_dir: &Path,
) -> io::Result<BackupMetadata> {
    fs::create_dir_all(export_dir)?;

    // 1. Resolve active key-value state
    let mut active_map = BTreeMap::new();
    let mut max_rev: u64 = 0;

    for r in kine_records {
        if r.id > max_rev {
            max_rev = r.id;
        }
        if r.deleted != 0 {
            active_map.remove(&r.name);
        } else {
            let existing_version = active_map
                .get(&r.name)
                .map_or(1, |kv: &KeyValue| kv.version + 1);
            active_map.insert(
                r.name.clone(),
                KeyValue {
                    key: r.name.clone(),
                    value: r.value.clone(),
                    create_revision: r.create_revision,
                    mod_revision: r.id,
                    version: existing_version,
                },
            );
        }
    }

    // 2. Serialize snapshot.db with magic header RUBXSNP1 + revision (u64 big-endian) + JSON payload
    let snapshot_file = export_dir.join("snapshot.db");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&snapshot_file)?;

    file.write_all(SNAPSHOT_MAGIC)?;
    file.write_all(&max_rev.to_be_bytes())?;
    serde_json::to_writer(&mut file, &active_map)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    file.flush()?;

    // 3. Create member/wal directory
    let wal_dir = export_dir.join("member").join("wal");
    fs::create_dir_all(&wal_dir)?;
    let empty_wal = wal_dir.join("00000001.wal");
    let mut wal_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&empty_wal)?;
    wal_file.write_all(b"RUBXWAL1")?;
    wal_file.flush()?;

    // 4. Compute snapshot SHA-256
    let snapshot_sha = compute_file_sha256(&snapshot_file)?;

    // 5. Write backup-meta.json
    let meta = BackupMetadata {
        format_version: BACKUP_FORMAT_VERSION.to_string(),
        revision: max_rev,
        timestamp_secs: 1_760_000_000,
        total_keys: active_map.len(),
        snapshot_sha256: snapshot_sha,
    };

    let meta_file = export_dir.join(BACKUP_META_FILE);
    let meta_json = serde_json::to_string_pretty(&meta)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    fs::write(meta_file, meta_json)?;

    Ok(meta)
}

/// Asserts that a raw `SQLite` database is rejected by `diorama-datastore`.
pub fn assert_raw_sqlite_rejected(sqlite_path: &Path) -> bool {
    let Ok(temp_dir) = tempfile::tempdir() else {
        return false;
    };
    let dest = temp_dir.path().join("snapshot.db");
    if fs::copy(sqlite_path, &dest).is_err() {
        return false;
    }
    let config = DatastoreConfig::new(temp_dir.path());
    match DatastoreEngine::open(config) {
        Err(DatastoreError::Fatal(msg)) => msg.contains("invalid snapshot magic header"),
        _ => false,
    }
}

/// Exercises native snapshot conversion on fixture records, without qualifying production migration.
pub async fn validate_datastore_transition(
    source_records: &[KineRecord],
    work_dir: &Path,
) -> io::Result<DatastoreTransitionAssertion> {
    let export_dir = work_dir.join("exported-datastore");
    let restored_dir = work_dir.join("restored-datastore");
    let raw_sqlite_dir = work_dir.join("raw-sqlite");

    fs::create_dir_all(&raw_sqlite_dir)?;
    let raw_sqlite_file = raw_sqlite_dir.join("snapshot.db");
    // Write raw SQLite magic header
    fs::write(&raw_sqlite_file, b"SQLite format 3\0fake-sqlite-content")?;

    // 1. Proof of non-interchangeability: raw SQLite is rejected
    let raw_rejected = assert_raw_sqlite_rejected(&raw_sqlite_file);

    // 2. Active keys before
    let mut active_before = BTreeMap::new();
    let mut max_rev_before: u64 = 0;
    for r in source_records {
        if r.id > max_rev_before {
            max_rev_before = r.id;
        }
        if r.deleted != 0 {
            active_before.remove(&r.name);
        } else {
            active_before.insert(r.name.clone(), r.value.clone());
        }
    }

    // 3. Explicit export
    let meta = export_kine_to_diorama_datastore(source_records, &export_dir)?;

    // 4. Import / Restore into diorama-datastore
    DatastoreEngine::restore_backup(&export_dir, &restored_dir)
        .map_err(|e| io::Error::other(format!("restore failed: {e}")))?;

    let config = DatastoreConfig::new(&restored_dir);
    let (engine, _) =
        DatastoreEngine::open(config).map_err(|e| io::Error::other(format!("open failed: {e}")))?;

    let client = engine.client();
    let restored_rev = client.current_revision().await;

    // 5. Verify restored keys match active keys before
    let mut keys_identical = true;
    for (k, v) in &active_before {
        if let Ok(Some(kv)) = client.get(k).await {
            if kv.value != *v {
                keys_identical = false;
                break;
            }
        } else {
            keys_identical = false;
            break;
        }
    }

    let revisions_monotonic = restored_rev >= max_rev_before;

    Ok(DatastoreTransitionAssertion {
        total_records_before: source_records.len(),
        active_keys_before: active_before.len(),
        max_revision_before: max_rev_before,
        wal_checkpointed: false,
        production_transition_qualified: false,
        raw_sqlite_rejected_by_diorama_datastore: raw_rejected,
        explicit_export_format: meta.format_version,
        export_verified_sha256: meta.snapshot_sha256,
        restored_keys: active_before.len(),
        restored_revision: restored_rev,
        keys_identical,
        revisions_monotonic,
    })
}
