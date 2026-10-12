# Safe Asset Materialization (E06.02 / #49)

`Materializer` provides safe, transactional, and idempotent extraction of verified dependency
assets into configured writable host roots.

## Architecture and Safety Guarantees

1. **Path Safety and Isolation**:
   Every relative asset path is validated before creation. Path components containing
   traversal (`..`), empty components, Windows backslashes, drive-colons, or leading
   slashes are rejected with `MaterializationError::PathEscapesRoot` or
   `MaterializationError::InvalidRelativePath`. All destination paths must strictly
   reside within the caller-provided writable root.
   Unix directory descriptors pin the root, staging directory and destination parents.
   Each descendant directory is opened with `NOFOLLOW`; symlink/file substitutions
   cannot redirect reads, chmods, renames or cleanup into unrelated host paths.
   The configured root itself must be a directory, not a symlink. Non-Unix
   materialization fails explicitly rather than falling back to pathname writes.

2. **Staging and Atomicity**:
   Assets are never directly written or decompressed into their final destination paths.
   Extraction occurs in a private temporary staging directory
   (`<root>/.staging-<pid>-<timestamp>`) located within the same filesystem root.
   A RAII `StagingGuard` ensures that any failure or panic during extraction, decompression,
   or digest verification removes the owned staged files through their directory descriptor.
   Only when all bundled assets pass size, checksum, decompression, and on-disk
   reverification are all destination types preflighted. A per-root advisory lock
   serializes cooperating materializers. Original files are retained in private
   staging backups until every descriptor-relative rename succeeds. A synchronous
   commit error rolls back newly installed files and restores originals.
   If rollback itself fails, `RollbackFailed` identifies retained recovery files;
   those backups are never removed by the guard. Do not ignore that recovery error.
   Individual renames are atomic; the scattered canonical paths are not a single
   atomic snapshot for concurrent readers, and this is not a crash/power-loss recovery
   protocol. The root must be exclusively owned against noncooperating writers.
   Persisted node data and unrelated root contents are not part of the transaction.

3. **Disk Reverification Before Commit**:
   To prevent time-of-check to time-of-use (TOCTOU) corruption or partial disk writes,
   the bytes written to disk in staging are re-read and hashed with SHA-256 before any
   final placement. The observed on-disk size and SHA-256 must match the expected payload
   specifications exactly.

4. **Unix Permission Enforcement**:
   - Executables (`Kind::Executable`: `kube-apiserver`, `kubelet`, `containerd`, etc.) are
     materialized with Unix mode `0o755` (`rwxr-xr-x`).
   - Image payloads and archives (`Kind::Image`: `containerd/images/*.tar.gz`) are
     materialized with Unix mode `0o644` (`rw-r--r--`).

5. **Idempotence**:
   Calling materialization repeatedly on an already-populated root preserves file content
   and required permissions. Every supplied payload is reverified and staged on repeat
   calls; no existing pathname is read or chmodded in place. Replacement clears special
   permission bits as well as correcting ordinary permissions.

6. **Streaming Tar/Gzip Archive Support**:
   A built-in streaming POSIX USTAR reader (`TarReader`) supports both uncompressed `.tar`
   and gzip-compressed `.tar.gz` distribution archives without introducing external
   runtime dependencies, enforcing member count and byte limits.
   Members are staged immediately rather than accumulating the bundle in memory.
   Encoded zstd executables spool to private descriptor-relative files before decoding;
   gzip images retain their encoding and verify decoding with a bounded sink. Copying,
   hashing and disk reverification use fixed-size buffers. Byte limits bound disk and
   decoded output, not an allowed in-memory allocation. Every tar member type counts
   against member and declared-byte limits, including skipped nonregular entries.
   Tar requires both zero EOF blocks. A gzip distribution is exactly one RFC1952
   member, whose CRC32 and ISIZE trailer must validate before commit; concatenated
   members and encoded trailing bytes are rejected. Zero tar record padding is allowed.
