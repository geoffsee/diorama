# diorama-datastore

Embedded, durable etcd v3-compatible state store for diorama Kubernetes cluster operations.

## Architecture

- **Engine (`DatastoreEngine`)**: Monotonic 64-bit revision index supporting atomic compare-and-swap (CAS), multi-prefix queries, live watch event dispatching, point-in-time snapshot checkpointing, and WAL replay.
- **Write-Ahead Log (`Wal`)**: Length-prefixed, SHA-256 frame-verified operations logging with opt-in automatic corruption truncation repair.
- **Advisory Locking (`DatastoreLock`)**: Non-blocking `flock` exclusive locking ensuring single-process ownership and preserving lock contention diagnostics.
- **Supervisor Adapter (`DatastoreAdapter`)**: Coordinates startup readiness and snapshot checkpointing under `diorama-supervisor`, preserving primary failure diagnostics.
- **Backup & Restore (`BackupMetadata`)**: Point-in-time snapshot and WAL backups verified by SHA-256 digests and explicit format compatibility boundaries.

## Documentation

- [BACKUP_COMPATIBILITY.md](BACKUP_COMPATIBILITY.md): Storage format, online/offline backup procedures, non-interchangeability boundaries, and Epic E30 migration prerequisites.
