use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};

use crate::backup::{BACKUP_FORMAT_VERSION, BACKUP_META_FILE, BackupMetadata};
use crate::config::DatastoreConfig;
use crate::error::DatastoreError;
use crate::lock::DatastoreLock;
use crate::model::{DatastoreOp, KeyValue, WatchEvent, WatchEventType, WatchReceiver};
use crate::wal::{Wal, WalSummary};

const SNAPSHOT_MAGIC: &[u8; 8] = b"RUBXSNP1";
const BROADCAST_CAPACITY: usize = 4096;

pub struct EngineState {
    pub(crate) kv: BTreeMap<String, KeyValue>,
    pub(crate) revision: u64,
    pub(crate) wal: Wal,
    pub(crate) _lock: DatastoreLock,
    pub(crate) notifier: broadcast::Sender<WatchEvent>,
}

impl std::fmt::Debug for EngineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineState")
            .field("keys_count", &self.kv.len())
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct DatastoreEngine {
    state: Arc<RwLock<EngineState>>,
    config: DatastoreConfig,
}

impl std::fmt::Debug for DatastoreEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatastoreEngine")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl DatastoreEngine {
    #[must_use]
    pub fn client(&self) -> crate::client::DatastoreClient {
        crate::client::DatastoreClient::new(self.clone())
    }

    pub fn open(config: DatastoreConfig) -> Result<(Self, WalSummary), DatastoreError> {
        config.validate()?;

        // Ensure data directory exists
        std::fs::create_dir_all(&config.data_dir)?;

        // Acquire lock
        let lock = DatastoreLock::acquire(&config.data_dir)?;

        // Load snapshot if present
        let snapshot_path = config.snapshot_path();
        let (mut kv, mut revision) = if snapshot_path.exists() {
            Self::read_snapshot(&snapshot_path)?
        } else {
            (BTreeMap::new(), 0)
        };

        // Open WAL and replay
        let wal_path = config.wal_path();
        let (wal, records, summary) = Wal::open(&wal_path, config.auto_repair_wal)?;

        let snapshot_revision = revision;
        for record in records {
            if record.revision <= snapshot_revision {
                continue;
            }
            if record.revision > revision {
                revision = record.revision;
            }
            match record.op {
                DatastoreOp::Put { key, value } => {
                    let existing = kv.get(&key);
                    let (create_revision, version) = match existing {
                        Some(prev) => (prev.create_revision, prev.version + 1),
                        None => (record.revision, 1),
                    };
                    kv.insert(
                        key.clone(),
                        KeyValue {
                            key,
                            value,
                            create_revision,
                            mod_revision: record.revision,
                            version,
                        },
                    );
                },
                DatastoreOp::Delete { key } => {
                    kv.remove(&key);
                },
            }
        }

        let (notifier, _) = broadcast::channel(BROADCAST_CAPACITY);

        let engine = Self {
            state: Arc::new(RwLock::new(EngineState {
                kv,
                revision,
                wal,
                _lock: lock,
                notifier,
            })),
            config,
        };

        Ok((engine, summary))
    }

    pub fn config(&self) -> &DatastoreConfig {
        &self.config
    }

    pub async fn current_revision(&self) -> u64 {
        self.state.read().await.revision
    }

    pub async fn get(&self, key: &str) -> Result<Option<KeyValue>, DatastoreError> {
        let state = self.state.read().await;
        Ok(state.kv.get(key).cloned())
    }

    pub async fn list(&self, prefix: &str) -> Result<Vec<KeyValue>, DatastoreError> {
        let state = self.state.read().await;
        let mut results = Vec::new();
        for (k, v) in &state.kv {
            if k.starts_with(prefix) {
                results.push(v.clone());
            }
        }
        Ok(results)
    }

    pub async fn create(&self, key: &str, value: Vec<u8>) -> Result<KeyValue, DatastoreError> {
        let mut state = self.state.write().await;
        if state.kv.contains_key(key) {
            return Err(DatastoreError::KeyAlreadyExists(key.to_string()));
        }

        let next_rev = state.revision + 1;
        state.wal.append(
            next_rev,
            DatastoreOp::Put {
                key: key.to_string(),
                value: value.clone(),
            },
        )?;

        state.revision = next_rev;
        let kv = KeyValue {
            key: key.to_string(),
            value,
            create_revision: next_rev,
            mod_revision: next_rev,
            version: 1,
        };

        state.kv.insert(key.to_string(), kv.clone());

        let event = WatchEvent {
            event_type: WatchEventType::Put,
            kv: kv.clone(),
            prev_kv: None,
        };
        let _ = state.notifier.send(event);

        Ok(kv)
    }

    pub async fn update(
        &self,
        key: &str,
        value: Vec<u8>,
        expected_mod_revision: Option<u64>,
    ) -> Result<KeyValue, DatastoreError> {
        let mut state = self.state.write().await;
        let existing = state
            .kv
            .get(key)
            .ok_or_else(|| DatastoreError::KeyNotFound(key.to_string()))?;

        if let Some(expected) = expected_mod_revision
            && existing.mod_revision != expected
        {
            return Err(DatastoreError::RevisionMismatch {
                expected,
                actual: existing.mod_revision,
            });
        }

        let next_rev = state.revision + 1;
        let prev_kv = existing.clone();
        let create_rev = existing.create_revision;
        let next_ver = existing.version + 1;

        state.wal.append(
            next_rev,
            DatastoreOp::Put {
                key: key.to_string(),
                value: value.clone(),
            },
        )?;

        state.revision = next_rev;
        let kv = KeyValue {
            key: key.to_string(),
            value,
            create_revision: create_rev,
            mod_revision: next_rev,
            version: next_ver,
        };

        state.kv.insert(key.to_string(), kv.clone());

        let event = WatchEvent {
            event_type: WatchEventType::Put,
            kv: kv.clone(),
            prev_kv: Some(prev_kv),
        };
        let _ = state.notifier.send(event);

        Ok(kv)
    }

    pub async fn delete(
        &self,
        key: &str,
        expected_mod_revision: Option<u64>,
    ) -> Result<Option<KeyValue>, DatastoreError> {
        let mut state = self.state.write().await;
        let Some(existing) = state.kv.get(key).cloned() else {
            return Ok(None);
        };

        if let Some(expected) = expected_mod_revision
            && existing.mod_revision != expected
        {
            return Err(DatastoreError::RevisionMismatch {
                expected,
                actual: existing.mod_revision,
            });
        }

        let next_rev = state.revision + 1;
        state.wal.append(
            next_rev,
            DatastoreOp::Delete {
                key: key.to_string(),
            },
        )?;

        state.revision = next_rev;
        state.kv.remove(key);

        let event = WatchEvent {
            event_type: WatchEventType::Delete,
            kv: existing.clone(),
            prev_kv: Some(existing.clone()),
        };
        let _ = state.notifier.send(event);

        Ok(Some(existing))
    }

    pub async fn watch(&self, prefix: &str) -> WatchReceiver {
        let state = self.state.read().await;
        let raw_rx = state.notifier.subscribe();
        let (tx, rx) = tokio::sync::mpsc::channel(BROADCAST_CAPACITY);
        tokio::spawn(forward_watch_events(raw_rx, tx, prefix.to_string()));
        WatchReceiver::new(rx)
    }

    pub async fn checkpoint_snapshot(&self) -> Result<(), DatastoreError> {
        let state = self.state.read().await;
        let snapshot_path = self.config.snapshot_path();
        let temp_path = self.config.data_dir.join("snapshot.db.tmp");

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;

        file.write_all(SNAPSHOT_MAGIC)?;
        file.write_all(&state.revision.to_be_bytes())?;
        let kv_bytes = serde_json::to_vec(&state.kv)?;
        file.write_all(&kv_bytes)?;
        file.flush()?;
        file.sync_data()?;

        std::fs::rename(temp_path, snapshot_path)?;
        Ok(())
    }

    pub async fn create_backup(&self, backup_dir: &Path) -> Result<BackupMetadata, DatastoreError> {
        self.checkpoint_snapshot().await?;

        let snapshot_path = self.config.snapshot_path();
        if !snapshot_path.exists() {
            return Err(DatastoreError::Fatal(
                "missing snapshot file for backup".into(),
            ));
        }

        std::fs::create_dir_all(backup_dir)?;

        let dest_snapshot = backup_dir.join("snapshot.db");
        std::fs::copy(&snapshot_path, &dest_snapshot)?;

        let wal_path = self.config.wal_path();
        if wal_path.exists() {
            let dest_wal_dir = backup_dir.join("member/wal");
            std::fs::create_dir_all(&dest_wal_dir)?;
            std::fs::copy(&wal_path, dest_wal_dir.join("00000001.wal"))?;
        }

        let state = self.state.read().await;
        let sha256 = BackupMetadata::compute_file_sha256(&dest_snapshot)?;
        let timestamp_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let meta = BackupMetadata {
            format_version: BACKUP_FORMAT_VERSION.to_string(),
            revision: state.revision,
            timestamp_secs,
            total_keys: state.kv.len(),
            snapshot_sha256: sha256,
        };

        let meta_json = serde_json::to_vec_pretty(&meta)?;
        std::fs::write(backup_dir.join(BACKUP_META_FILE), meta_json)?;

        Ok(meta)
    }

    pub fn restore_backup(
        backup_dir: &Path,
        dest_data_dir: &Path,
    ) -> Result<BackupMetadata, DatastoreError> {
        let meta_file = backup_dir.join(BACKUP_META_FILE);
        if !meta_file.exists() {
            return Err(DatastoreError::Fatal(format!(
                "missing backup metadata file: {}",
                meta_file.display()
            )));
        }

        let meta_bytes = std::fs::read(&meta_file)?;
        let meta: BackupMetadata = serde_json::from_slice(&meta_bytes)
            .map_err(|e| DatastoreError::Fatal(format!("corrupt backup metadata: {e}")))?;

        if meta.format_version != BACKUP_FORMAT_VERSION {
            return Err(DatastoreError::Fatal(format!(
                "unsupported backup format version: expected {}, got {}",
                BACKUP_FORMAT_VERSION, meta.format_version
            )));
        }

        let src_snapshot = backup_dir.join("snapshot.db");
        if !src_snapshot.exists() {
            return Err(DatastoreError::Fatal(
                "backup is missing snapshot.db".into(),
            ));
        }

        let actual_sha256 = BackupMetadata::compute_file_sha256(&src_snapshot)?;
        if actual_sha256 != meta.snapshot_sha256 {
            return Err(DatastoreError::Fatal(format!(
                "backup snapshot checksum mismatch: expected {}, got {}",
                meta.snapshot_sha256, actual_sha256
            )));
        }

        std::fs::create_dir_all(dest_data_dir)?;
        let dest_snapshot = dest_data_dir.join("snapshot.db");
        std::fs::copy(&src_snapshot, dest_snapshot)?;

        let src_wal = backup_dir.join("member/wal/00000001.wal");
        if src_wal.exists() {
            let dest_wal_dir = dest_data_dir.join("member/wal");
            std::fs::create_dir_all(&dest_wal_dir)?;
            std::fs::copy(&src_wal, dest_wal_dir.join("00000001.wal"))?;
        }

        Ok(meta)
    }

    fn read_snapshot(path: &Path) -> Result<(BTreeMap<String, KeyValue>, u64), DatastoreError> {
        let mut file = File::open(path)?;
        let mut magic = [0u8; 8];
        match file.read_exact(&mut magic) {
            Ok(()) if &magic != SNAPSHOT_MAGIC => {
                return Err(DatastoreError::Fatal(
                    "invalid snapshot magic header".into(),
                ));
            },
            Ok(()) => {},
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(DatastoreError::Fatal(
                    "truncated snapshot magic header".into(),
                ));
            },
            Err(e) => return Err(DatastoreError::Io(e)),
        }

        let mut rev_bytes = [0u8; 8];
        match file.read_exact(&mut rev_bytes) {
            Ok(()) => {},
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(DatastoreError::Fatal("truncated snapshot header".into()));
            },
            Err(e) => return Err(DatastoreError::Io(e)),
        }
        let revision = u64::from_be_bytes(rev_bytes);

        let mut rest = Vec::new();
        file.read_to_end(&mut rest)?;
        let kv: BTreeMap<String, KeyValue> = serde_json::from_slice(&rest)
            .map_err(|e| DatastoreError::Fatal(format!("corrupt snapshot payload: {e}")))?;

        Ok((kv, revision))
    }
}

async fn forward_watch_events(
    mut raw_rx: broadcast::Receiver<WatchEvent>,
    tx: tokio::sync::mpsc::Sender<WatchEvent>,
    prefix: String,
) {
    loop {
        match raw_rx.recv().await {
            Ok(event) => {
                let matches = event.kv.key.starts_with(&prefix);
                if matches && tx.send(event).await.is_err() {
                    break;
                }
            },
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {},
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}
