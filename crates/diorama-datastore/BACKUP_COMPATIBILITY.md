# Datastore Storage Format, Backup Compatibility, and Migration

This document defines the storage format, consistent backup/restore prerequisites, and non-interchangeability boundaries for the KubeSolo Kubernetes state datastore in `crates/diorama-datastore`.

---

## 1. Storage Architecture and On-Disk Layout

`diorama-datastore` implements an etcd v3-compatible key-value storage engine using an in-memory index backed by monotonic 64-bit revisions, write-ahead logging (WAL), and point-in-time snapshot checkpoints.

### Directory Structure

```text
<data-dir>/
├── .lock                     # Exclusive flock advisory lock file (non-blocking)
├── snapshot.db               # Point-in-time consistent state snapshot
├── snapshot.db.tmp           # Atomic staging file for snapshot checkpointing
└── member/
    └── wal/
        └── 00000001.wal      # Length-prefixed, SHA-256 verified write-ahead log
```

### File Formats and Framing

#### 1. Snapshot File (`snapshot.db`)
- **Header**: 8-byte magic constant `RUBXSNP1` (`0x52 0x55 0x42 0x58 0x53 0x4E 0x50 0x31`).
- **Revision**: 8-byte big-endian `u64` encoding the snapshot revision at the checkpoint boundary.
- **Payload**: JSON-serialized canonical BTreeMap index containing active `KeyValue` records:
  - `key: String`
  - `value: Vec<u8>`
  - `create_revision: u64`
  - `mod_revision: u64`
  - `version: u64`

#### 2. Write-Ahead Log (`member/wal/00000001.wal`)
- **Header**: 8-byte magic constant `RUBXWAL1` (`0x52 0x55 0x42 0x58 0x57 0x41 0x4C 0x31`).
- **Frames**: Sequence of length-prefixed records:
  - `[0..4]`: 4-byte big-endian payload length (`u32`).
  - `[4..4+len]`: JSON-serialized `WalRecord`:
    - `index: u64`: Sequential 1-based log sequence number.
    - `revision: u64`: Monotonic 64-bit cluster resource version.
    - `op: DatastoreOp`: `Put { key, value }` or `Delete { key }`.
    - `checksum_sha256: [u8; 32]`: SHA-256 checksum over `(index || revision || op)`.

---

## 2. Backup and Restore Procedures

Consistent backups must capture a clean point-in-time state without partial transactions or corrupted frames.

### Consistent Online Backup (`DatastoreClient::create_backup`)
1. **Checkpointing**: The engine forces a consistent checkpoint via `checkpoint_snapshot()`, writing all in-memory entries and committed WAL mutations to `snapshot.db.tmp` followed by `fsync` and atomic rename to `snapshot.db`.
2. **Copying**: `snapshot.db` and active WAL segments in `member/wal/` are copied to the target backup directory.
3. **Descriptor Generation**: A metadata descriptor `backup-meta.json` is generated with:
   - `format_version`: `"diorama-datastore-v1"`
   - `revision`: Snapshot revision at backup time
   - `timestamp_secs`: Unix timestamp
   - `total_keys`: Count of active keys at backup time
   - `snapshot_sha256`: SHA-256 hex digest of the copied `snapshot.db`
4. **Lock Exclusion**: `.lock` is never copied; each restored instance must acquire its own exclusive lock.

### Offline Backup Procedure (Required Shutdown Steps)
If copying data files offline directly from disk without using the `create_backup` API:
1. Signal the supervisor coordinator for graceful shutdown (`StopPhase::Graceful`).
2. Await adapter completion: `DatastoreAdapter` triggers `checkpoint_snapshot()` on graceful stop.
3. Verify the datastore process has terminated and released `.lock`.
4. Copy `snapshot.db` and `member/wal/`.

### Consistent Restore Procedure (`DatastoreEngine::restore_backup`)
1. **Metadata Verification**: Checks for `backup-meta.json` and verifies that `format_version == "diorama-datastore-v1"`.
2. **Integrity Verification**: Reads `snapshot.db` from the backup and validates its SHA-256 checksum against `snapshot_sha256`.
3. **Atomic Copy**: Deploys `snapshot.db` and `member/wal/` to the destination data directory.
4. **Startup Replay**: On initial startup, the engine reads `snapshot.db`, skips any WAL records with `record.revision <= snapshot_revision`, and replays any pending uncompacted records.

---

## 3. Unsupported Format Reuse and Non-Interchangeability

> [!WARNING]
> No interchangeability between `diorama-datastore` and raw SQLite or Kine table databases is assumed.

1. **Raw SQLite Databases**:
   - Files beginning with `SQLite format 3\0` or SQLite WAL files are explicitly rejected with `DatastoreError::Fatal("invalid snapshot magic header")` and diagnostic code `datastore-fatal-error`.
   - The datastore does not attempt to parse or execute raw SQL tables.

2. **Foreign Backup Formats**:
   - Backups created by third-party tools or foreign format versions (e.g. `sqlite-kine-v1`) are rejected during restore with `DatastoreError::Fatal("unsupported backup format version")`.

3. **Tampered or Truncated Payloads**:
   - Any modification or bit-rot in `snapshot.db` produces a SHA-256 mismatch during `restore_backup`, preventing corrupted state from loading into the cluster.

---

## 4. Prerequisites for Epic E30 Migration

Migration of state to target release environments in Epic E30 requires:
1. **Revision Monotonicity**: Restored datastores resume cluster revisions from `backup_meta.revision + 1` without resets or regressions, guaranteeing Kubernetes `resourceVersion` consistency for informers and controllers.
2. **CAS Atomicity**: Compare-and-swap preconditions (`expected_mod_revision`) remain valid across backup/restore boundaries.
3. **Supervisor Integration**: When managed under `diorama-supervisor`, any fatal backup or WAL corruption halts startup immediately and surfaces `datastore-fatal-error` or `datastore-wal-corrupt` without restart loops hiding the primary failure.
