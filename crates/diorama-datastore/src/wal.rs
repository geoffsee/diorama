use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::DatastoreError;
use crate::model::DatastoreOp;

pub const WAL_MAGIC: &[u8; 8] = b"RUBXWAL1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalRecord {
    pub index: u64,
    pub revision: u64,
    pub op: DatastoreOp,
    pub checksum: [u8; 32],
}

impl WalRecord {
    pub fn new(index: u64, revision: u64, op: DatastoreOp) -> Self {
        let checksum = Self::compute_checksum(index, revision, &op);
        Self {
            index,
            revision,
            op,
            checksum,
        }
    }

    pub fn compute_checksum(index: u64, revision: u64, op: &DatastoreOp) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(index.to_be_bytes());
        hasher.update(revision.to_be_bytes());
        if let Ok(op_bytes) = serde_json::to_vec(op) {
            hasher.update(op_bytes);
        }
        let out = hasher.finalize();
        let mut sum = [0u8; 32];
        sum.copy_from_slice(&out);
        sum
    }

    pub fn is_valid(&self) -> bool {
        self.checksum == Self::compute_checksum(self.index, self.revision, &self.op)
    }
}

#[derive(Debug)]
pub struct Wal {
    path: PathBuf,
    file: File,
    next_index: u64,
}

#[derive(Debug, Default)]
pub struct WalSummary {
    pub total_records: usize,
    pub max_revision: u64,
    pub repaired_corruptions: usize,
}

enum ReadRecordOutcome {
    Record(WalRecord, u64),
    Eof,
    Corrupted(String),
}

fn read_single_record(
    file: &mut File,
    next_index: u64,
) -> Result<ReadRecordOutcome, DatastoreError> {
    let mut len_buf = [0u8; 4];
    match file.read_exact(&mut len_buf) {
        Ok(()) => {},
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(ReadRecordOutcome::Eof);
        },
        Err(e) => return Err(DatastoreError::Io(e)),
    }

    let record_len = u32::from_be_bytes(len_buf) as usize;
    let pos = file.stream_position()?;
    let remaining = file.metadata()?.len().saturating_sub(pos);
    if record_len as u64 > remaining {
        return Ok(ReadRecordOutcome::Corrupted(format!(
            "WAL record length {record_len} exceeds remaining {remaining} bytes at index {next_index}"
        )));
    }
    let mut record_bytes = vec![0u8; record_len];
    if let Err(e) = file.read_exact(&mut record_bytes) {
        return Ok(ReadRecordOutcome::Corrupted(format!(
            "truncated WAL record at index {next_index}: {e}"
        )));
    }

    let record: WalRecord = match serde_json::from_slice(&record_bytes) {
        Ok(r) => r,
        Err(e) => {
            return Ok(ReadRecordOutcome::Corrupted(format!(
                "unparseable WAL record at index {next_index}: {e}"
            )));
        },
    };

    if !record.is_valid() {
        return Ok(ReadRecordOutcome::Corrupted(
            "checksum validation failed".into(),
        ));
    }

    Ok(ReadRecordOutcome::Record(record, 4 + record_len as u64))
}

fn repair_at_offset(
    file: &mut File,
    valid_pos: u64,
    summary: &mut WalSummary,
) -> Result<(), DatastoreError> {
    file.set_len(valid_pos)?;
    file.seek(SeekFrom::Start(valid_pos))?;
    summary.repaired_corruptions += 1;
    Ok(())
}

fn replay_wal_entries(
    file: &mut File,
    auto_repair: bool,
) -> Result<(Vec<WalRecord>, WalSummary, u64), DatastoreError> {
    let mut valid_records = Vec::new();
    let mut summary = WalSummary::default();
    let mut valid_pos = 8u64;
    let mut next_index = 1;

    loop {
        match read_single_record(file, next_index)? {
            ReadRecordOutcome::Eof => break,
            ReadRecordOutcome::Record(record, bytes_read) => {
                next_index = record.index + 1;
                summary.max_revision = summary.max_revision.max(record.revision);
                valid_records.push(record);
                valid_pos += bytes_read;
            },
            ReadRecordOutcome::Corrupted(reason) => {
                if auto_repair {
                    repair_at_offset(file, valid_pos, &mut summary)?;
                    break;
                }
                return Err(DatastoreError::CorruptWal {
                    index: next_index,
                    reason,
                });
            },
        }
    }
    summary.total_records = valid_records.len();
    Ok((valid_records, summary, next_index))
}

impl Wal {
    pub fn open(
        path: &Path,
        auto_repair: bool,
    ) -> Result<(Self, Vec<WalRecord>, WalSummary), DatastoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let file_len = file.metadata()?.len();

        let (valid_records, summary, next_index) = if file_len == 0 {
            file.write_all(WAL_MAGIC)?;
            file.flush()?;
            (Vec::new(), WalSummary::default(), 1)
        } else {
            let mut magic = [0u8; 8];
            if file.read_exact(&mut magic).is_err() || &magic != WAL_MAGIC {
                return Err(DatastoreError::CorruptWal {
                    index: 0,
                    reason: "invalid or missing WAL magic header".into(),
                });
            }
            replay_wal_entries(&mut file, auto_repair)?
        };
        file.seek(SeekFrom::End(0))?;

        Ok((
            Self {
                path: path.to_path_buf(),
                file,
                next_index,
            },
            valid_records,
            summary,
        ))
    }

    pub fn append(&mut self, revision: u64, op: DatastoreOp) -> Result<WalRecord, DatastoreError> {
        let record = WalRecord::new(self.next_index, revision, op);
        let record_bytes = serde_json::to_vec(&record)?;
        let len_u32 = u32::try_from(record_bytes.len())
            .map_err(|_| DatastoreError::Fatal("record payload exceeds 4GB limit".into()))?;
        let len_bytes = len_u32.to_be_bytes();

        self.file.write_all(&len_bytes)?;
        self.file.write_all(&record_bytes)?;
        self.file.flush()?;
        self.file.sync_data()?;

        self.next_index += 1;
        Ok(record)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
