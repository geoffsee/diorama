# Stored configuration persistence

`write_document(&Path, &Config) -> Result<WriteOutcome, PersistenceError>` implements
E03.03's shared stored-document writer. It does not validate, apply environment or
flags, discover runtime settings, redact secrets, or start services. Callers validate
the final candidate and serialize their entire read-modify-write transaction. No
global lock, external-writer exclusion, or compare-and-swap guarantee is provided.

The source reference is KubeSolo
[`internal/config/file.go`](https://github.com/portainer/kubesolo/blob/2ef1c4787989f11f868f81bb84ae2afd4a49a81d/internal/config/file.go).
The independent baseline filesystem observations are in
[`config-api`](../../tools/parity/fixtures/config-api/README.md) and
[`config-write-links`](../../tools/parity/fixtures/config-write-links/README.md).
API and direct CLI callers retain their own validation and immutable-field policies.

The writer clones the input, fills only empty schema metadata, and renders before
filesystem changes. The shared renderer retains the documented empty-path and
Unicode-break data-preservation deviations. Existing nonempty metadata is preserved,
and the caller's object remains unchanged. Missing parent directories are created
with requested mode 0755 subject to umask. Existing directory modes are unchanged.

A same-directory file is opened with create-new semantics and initial mode 0600.
Exclusive creation prevents following preexisting temporary symlinks; bounded unique
name attempts fail rather than truncate a colliding entry. The document is written,
explicitly chmodded 0600, and synced before closing. Prior destination bytes are
streamed into a separate temporary backup, preserving their exact representation
without parsing or accumulating the whole old file in memory. That file is chmodded
0600, synced, closed, renamed to `.bak`, and its parent synced. Finally the document
is renamed over the destination and its parent synced. A first write skips backup;
a stale existing `.bak` is left alone when no destination exists.

Two deliberate backup deviations prevent disclosure or collateral modification:

- A new 0600 backup replaces an existing backup atomically, correcting Go's retained
  permissive modes and restrictive-umask behavior.
- Existing backup symlinks and hard links are replaced as directory entries; their
  referents are not written or chmodded. Go writes through those links.

Destination-symlink behavior remains compatible: the prior referent is read for the
backup, then the symlink entry is replaced by a regular configuration file. A dangling
destination link is treated as missing prior content. A backup directory blocks
replacement. Parent directories must be trusted and stable; this path-based API is
not a defense against concurrent malicious directory substitution. Unix filesystem
permissions are required; no Windows implementation is claimed.

`WriteOutcome.backup_created` means a prior document was backed up successfully.
Every failure carries its operation stage, path, original render/I/O source, and
explicit cleanup failures. `committed=false` means destination rename has not
succeeded: its original bytes remain intact, although created parent directories
and a successfully published backup can remain. `committed=true` means rename
succeeded and the new document is visible, but final directory sync failed. Callers
must not report that latter state as an unchanged destination or blindly retry.
The old bytes remain in the published backup if a prior document existed.

Staging files have explicit cleanup on error and best-effort Drop fallback. Cleanup
failure is secondary evidence and never masks the original operation error. The safe
standard-library implementation checks write and sync failures, then drops File;
Rust's standard library does not expose a separately fallible file close. No close
error injection or checked-close parity is claimed. No unsafe code or dependency is
added. Parent-directory sync is stronger than the baseline, but crash durability of
newly created ancestor directories, all filesystems, and power-loss recovery has not
been qualified. The destination and backup are two sequential atomic replacements,
not one multi-file transaction.

Tests use owned temporary directories. Restrictive umask is set only in a subprocess,
never in the parallel test process. Link and permission tests independently assert
referent bytes, inode replacement, and modes. Injected failures exercise every I/O
stage before its operation, including post-rename directory sync, and verify commit
state, source chaining, unchanged original bytes, and absence of staging files.
A separate cleanup-failure test checks that secondary evidence survives. These tests
do not simulate partial kernel writes, power loss, or competing external writers.
