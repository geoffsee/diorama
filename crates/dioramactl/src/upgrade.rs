//! Version-aware host and container upgrades (`dioramactl upgrade`).
//!
//! The engine in [`run_upgrade`] sequences prepare → stop → backup → replace → start and rolls
//! back automatically when replace or start fails. Backends own artifact-specific effects:
//!
//! - [`HostBackend`] replaces only the configured diorama binary and its service.
//! - [`ContainerBackend`] replaces only the named container, preserving its image repository,
//!   arguments, ports, MTU, PKI and registry mounts from the recorded container spec.
//!
//! External runtimes, the running installer and neighbouring installations are never touched:
//! container names are validated and all commands address exactly one named unit.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub use crate::upgrade_integrity::seal_backup;
use diorama_config::semver::{compare_versions, parse_version, supports_config_file};

/// Directory under the data path holding pre-upgrade backups.
pub const BACKUP_DIR: &str = "backups";
/// Container spec file recorded at install time under the data path.
pub const CONTAINER_SPEC_FILE: &str = "container.spec";
/// State directories (relative to the data path) captured before an upgrade.
pub const BACKED_UP_STATE_DIRS: [&str; 2] = ["pki", "kine/db"];
/// Default service unit name.
pub const SERVICE_NAME: &str = "diorama";

/// Direction of a requested version transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    Same,
    Upgrade,
    Downgrade,
}

/// Classifies `from` → `to`; versions that do not parse are rejected.
pub fn classify_transition(from: &str, to: &str) -> Result<Transition, String> {
    for v in [from, to] {
        if parse_version(v).is_none() {
            return Err(format!(
                "unsupported version '{v}': expected vMAJOR.MINOR.PATCH"
            ));
        }
    }
    Ok(match compare_versions(from, to) {
        Some(std::cmp::Ordering::Less) => Transition::Upgrade,
        Some(std::cmp::Ordering::Greater) => Transition::Downgrade,
        _ => Transition::Same,
    })
}

/// Executes external programs; abstracted so lifecycle ordering is testable.
pub trait Runner: std::fmt::Debug {
    fn run(&mut self, program: &str, args: &[String]) -> io::Result<String>;
    /// Observe a process exit code without interpreting diagnostic text.
    fn status_code(&mut self, program: &str, args: &[String]) -> io::Result<Option<i32>> {
        self.run(program, args).map(|_| Some(0))
    }
}

/// Runs real processes.
#[derive(Debug, Default)]
pub struct ProcessRunner;

impl Runner for ProcessRunner {
    fn status_code(&mut self, program: &str, args: &[String]) -> io::Result<Option<i32>> {
        Ok(std::process::Command::new(program)
            .args(args)
            .output()?
            .status
            .code())
    }
    fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
        let out = std::process::Command::new(program).args(args).output()?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(io::Error::other(format!(
                "{program} {} failed: {}",
                args.first().map_or("", String::as_str),
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }
}

/// Artifact-specific steps of a transition.
pub trait TransitionBackend {
    /// Check artifact rollback material before any recovery service effects.
    fn validate_snapshot(&mut self, _dir: &Path) -> io::Result<()> {
        Ok(())
    }
    /// Reconstruct crash-lost backend state from receipt and verified observations.
    fn recover_transition(&mut self, _receipt: &UpgradeReceipt) -> io::Result<()> {
        Ok(())
    }
    fn current_version(&mut self) -> io::Result<String>;
    /// Fetch/verify the new artifact without mutating the running installation.
    fn prepare(&mut self, target: &str) -> io::Result<()>;
    /// Record artifact-specific rollback material in `dir`.
    fn snapshot(&mut self, dir: &Path) -> io::Result<()>;
    fn stop(&mut self) -> io::Result<()>;
    fn replace(&mut self, target: &str) -> io::Result<()>;
    fn start(&mut self) -> io::Result<()>;
    /// Restore the pre-upgrade artifact from `dir` (does not start it).
    fn restore(&mut self, dir: &Path) -> io::Result<()>;
    /// Drop temporary rollback material after a successful start.
    fn commit(&mut self) -> io::Result<()> {
        Ok(())
    }
    /// Config-file migration hook run after replacement and before start.
    fn migrate_config(&mut self, _target: &str, _stderr: &mut dyn Write) -> io::Result<bool> {
        Ok(false)
    }
}

/// Outcome of a completed run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpgradeOutcome {
    Unchanged,
    Upgraded { backup: PathBuf },
    RolledBack { backup: PathBuf, cause: String },
}

fn copy_tree(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    fs::set_permissions(dst, fs::metadata(src)?.permissions())?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let to = dst.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_tree(&entry.path(), &to)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), &to)?;
        }
        // Do not silently omit state redirected outside this installation.
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "symlink or unsupported entry in upgrade state",
            ));
        }
    }
    Ok(())
}

/// Copies PKI/datastore state and the config file into a fresh backup directory.
pub fn backup_state(
    data_path: &Path,
    config: Option<&Path>,
    from: &str,
    stamp: u64,
) -> io::Result<PathBuf> {
    for name in BACKED_UP_STATE_DIRS {
        reject_symlink_state(data_path, name)?;
    }
    reject_symlink_state(data_path, BACKUP_DIR)?;
    let parent = data_path.join(BACKUP_DIR);
    fs::create_dir_all(&parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(&format!("pre-upgrade-{from}-{stamp}-"))
        .tempdir_in(parent)?;
    let dir = temporary.path();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    for name in BACKED_UP_STATE_DIRS {
        let src = data_path.join(name);
        if src.is_dir() {
            copy_tree(&src, &dir.join(name))?;
        }
    }
    if let Some(cfg) = config.filter(|c| c.is_file()) {
        fs::copy(cfg, dir.join("config.yaml"))?;
    }
    Ok(temporary.keep())
}

fn restore_state(data: &Path, config: Option<&Path>, backup: &Path) -> io::Result<()> {
    for name in BACKED_UP_STATE_DIRS {
        reject_symlink_state(data, name)?;
        let path = data.join(name);
        remove_owned_entry(&path)?;
        let saved = backup.join(name);
        if saved.is_dir() {
            copy_tree(&saved, &path)?;
        }
    }
    if let Some(path) = config {
        let saved = backup.join("config.yaml");
        if saved.is_file() {
            atomic_copy(&saved, path)?;
        } else {
            remove_owned_entry(path)?;
        }
    }
    Ok(())
}

pub(crate) fn reject_symlink_state(data: &Path, relative: &str) -> io::Result<()> {
    let mut path = data.to_path_buf();
    for part in std::iter::once(None).chain(Path::new(relative).components().map(Some)) {
        if let Some(part) = part {
            path.push(part);
        }
        match path.symlink_metadata() {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("refusing symlinked state path {}", path.display()),
                ));
            },
            Ok(_) => {},
            Err(e) if e.kind() == io::ErrorKind::NotFound => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub(crate) fn remove_owned_entry(path: &Path) -> io::Result<()> {
    match path.symlink_metadata() {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn atomic_copy(source: &Path, destination: &Path) -> io::Result<()> {
    atomic_copy_with_mode(source, destination, false)
}

fn atomic_copy_with_mode(source: &Path, destination: &Path, executable: bool) -> io::Result<()> {
    let mut staged =
        tempfile::NamedTempFile::new_in(destination.parent().unwrap_or(Path::new(".")))?;
    let mut file = fs::File::open(source)?;
    io::copy(&mut file, staged.as_file_mut())?;
    staged
        .as_file()
        .set_permissions(file.metadata()?.permissions())?;
    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt;
        staged
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    staged.as_file().sync_all()?;
    staged.persist(destination).map_err(|e| e.error)?;
    Ok(())
}

fn restart_after_failure(backend: &mut dyn TransitionBackend, cause: io::Error) -> io::Error {
    match backend.start() {
        Ok(()) => cause,
        Err(restart) => io::Error::other(format!(
            "{cause}; restarting previous deployment failed: {restart}"
        )),
    }
}

fn remove_receipt(data: &Path, receipt: &Path) -> io::Result<()> {
    match fs::remove_file(receipt) {
        Ok(()) => fs::File::open(data)?.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn stage_commit_receipt(data: &Path, pending: &Path, committing: &Path) -> io::Result<()> {
    // Keep a durable, recognized receipt while checking pending cleanup.
    // Removing the only receipt here would leave an interruption gap.
    fs::hard_link(pending, committing)?;
    fs::File::open(data)?.sync_all()?;
    remove_receipt(data, pending)
}

fn finish_commit_receipt(data: &Path, committing: &Path, completed: &Path) -> io::Result<()> {
    fs::rename(committing, completed)?;
    fs::File::open(data)?.sync_all()?;
    remove_receipt(data, completed)
}

fn rollback_receipt_error(
    error: &io::Error,
    cause: &io::Error,
    from: &str,
    receipt: &Path,
    backup: &Path,
) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "upgrade failed ({cause}); rolled back to {from}, but cleaning receipt {} failed: {error}; backup kept at {}. Rollback is complete; inspect receipt cleanup before retrying.",
            receipt.display(),
            backup.display()
        ),
    )
}

fn report_upgraded(target: &str, stderr: &mut dyn Write) {
    let _ = writeln!(stderr, "  [ok] Upgraded to {target}");
    if supports_config_file(target) {
        let _ = writeln!(
            stderr,
            "  Restart required for configuration changes to take effect."
        );
    }
}

fn save_upgrade_receipt(
    data: &Path,
    pending: &Path,
    from: &str,
    target: &str,
    backup: &Path,
) -> io::Result<()> {
    let record = format!(
        "from={from}\ntarget={target}\nbackup={}\n",
        backup.display()
    );
    let mut marker = tempfile::NamedTempFile::new_in(data)?;
    marker.write_all(record.as_bytes())?;
    marker.as_file().sync_all()?;
    marker.persist_noclobber(pending).map_err(|e| e.error)?;
    fs::File::open(data)?.sync_all()
}

/// Acquire the persistent per-installation lock shared by upgrade and cleanup.
pub(crate) fn lock_installation(data: &Path) -> io::Result<fs::File> {
    reject_symlink_state(data, "")?;
    fs::create_dir_all(data)?;
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(data.join(".upgrade.lock"))?;
    lock.try_lock().map_err(|e| {
        io::Error::other(format!(
            "another upgrade or cleanup owns this installation: {e}"
        ))
    })?;
    Ok(lock)
}

/// Runs a transition; failures after the service is stopped restore and restart the old unit.
pub fn run_upgrade(
    backend: &mut dyn TransitionBackend,
    data_path: &Path,
    config: Option<&Path>,
    target: &str,
    stamp: u64,
    stderr: &mut dyn Write,
) -> io::Result<UpgradeOutcome> {
    let _lock = lock_installation(data_path)?;
    let pending = data_path.join(".upgrade-pending");
    let committing = data_path.join(".upgrade-committing");
    let completed = data_path.join(".upgrade-completed");
    if let Some(receipt) = [&pending, &committing].into_iter().find(|p| p.exists()) {
        return Err(io::Error::other(format!(
            "an interrupted upgrade requires recovery using {}",
            receipt.display()
        )));
    }
    // Only this phase proves the old artifact has already been committed away.
    remove_receipt(data_path, &completed)?;
    let from = backend.current_version()?;
    match classify_transition(&from, target).map_err(io::Error::other)? {
        Transition::Same => {
            writeln!(stderr, "  [ok] Already at {target}; nothing to do")?;
            return Ok(UpgradeOutcome::Unchanged);
        },
        Transition::Downgrade => writeln!(
            stderr,
            "  [warn] Downgrading {from} -> {target}; datastore compatibility is not verified"
        )?,
        Transition::Upgrade => writeln!(stderr, "  > Upgrading {from} -> {target}")?,
    }

    // Stage 1: fetch with the old version still running; failure changes nothing.
    backend
        .prepare(target)
        .map_err(|e| io::Error::new(e.kind(), format!("prepare failed: {e}")))?;
    // Quiesce writers before copying the datastore, then restart on backup failure.
    if let Err(cause) = backend.stop() {
        return Err(restart_after_failure(
            backend,
            io::Error::new(cause.kind(), format!("stop failed: {cause}")),
        ));
    }
    let backup = match backup_state(data_path, config, &from, stamp).and_then(|dir| {
        if let Err(error) = backend
            .snapshot(&dir)
            .and_then(|()| backend.validate_snapshot(&dir))
            .and_then(|()| seal_backup(&dir))
            .and_then(|()| validate_backup_integrity(&dir).map_err(io::Error::other))
        {
            fs::remove_dir_all(&dir).map_err(|cleanup| {
                io::Error::other(format!(
                    "snapshot failed ({error}); partial backup cleanup failed ({cleanup}) at {}",
                    dir.display()
                ))
            })?;
            return Err(error);
        }
        Ok(dir)
    }) {
        Ok(dir) => dir,
        Err(cause) => return Err(restart_after_failure(backend, cause)),
    };
    if let Err(e) = save_upgrade_receipt(data_path, &pending, &from, target, &backup) {
        return Err(restart_after_failure(backend, e));
    }
    // From this point interruptions leave a durable recovery receipt and preserve the backup.
    let attempt = backend
        .replace(target)
        .and_then(|()| {
            backend.migrate_config(target, stderr)?;
            Ok(())
        })
        .and_then(|()| backend.start())
        .and_then(|()| stage_commit_receipt(data_path, &pending, &committing))
        .and_then(|()| backend.commit());
    match attempt {
        Ok(()) => {
            // The commit may have destroyed the old container. Receipt I/O errors
            // now describe cleanup, never a failed transition requiring rollback.
            let cleanup = finish_commit_receipt(data_path, &committing, &completed);
            if let Err(error) = cleanup {
                let _ = writeln!(
                    stderr,
                    "  [warn] Upgrade committed; receipt cleanup failed: {error}. Inspect upgrade receipts; any retained receipt requires cleanup, not rollback."
                );
            }
            report_upgraded(target, stderr);
            Ok(UpgradeOutcome::Upgraded { backup })
        },
        Err(cause) => {
            // Reporting failure must never prevent recovery after the deployment was stopped.
            let _ = writeln!(stderr, "  [fail] {cause}; rolling back to {from}");
            backend
                .restore(&backup)
                .and_then(|()| restore_state(data_path, config, &backup))
                .and_then(|()| backend.start())
                .map_err(|e| {
                    io::Error::other(format!(
                        "upgrade failed ({cause}) and rollback failed ({e}); backup kept at {}",
                        backup.display()
                    ))
                })?;
            for receipt in [&pending, &committing] {
                remove_receipt(data_path, receipt)
                    .map_err(|e| rollback_receipt_error(&e, &cause, &from, receipt, &backup))?;
            }
            writeln!(stderr, "  [ok] Rolled back to {from}")?;
            Ok(UpgradeOutcome::RolledBack {
                backup,
                cause: cause.to_string(),
            })
        },
    }
}

/// Stage kind for an upgrade receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptKind {
    Pending,
    Committing,
    Completed,
}

/// Information recorded in an upgrade receipt file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeReceipt {
    pub kind: ReceiptKind,
    pub path: PathBuf,
    pub from: String,
    pub target: String,
    pub backup: PathBuf,
}

impl std::fmt::Display for UpgradeReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} receipt at {} (from={} target={} backup={})",
            self.kind,
            self.path.display(),
            self.from,
            self.target,
            self.backup.display()
        )
    }
}

/// Parses an upgrade receipt file (`.upgrade-pending`, `.upgrade-committing`, or `.upgrade-completed`).
pub fn parse_receipt_file(path: &Path, kind: ReceiptKind) -> io::Result<UpgradeReceipt> {
    let content = fs::read_to_string(path)?;
    let mut from = None;
    let mut target = None;
    let mut backup = None;
    for line in content.lines() {
        let line = line.trim();
        if let Some((k, v)) = line.split_once('=') {
            match k {
                "from" => from = Some(v.to_string()),
                "target" => target = Some(v.to_string()),
                "backup" => backup = Some(PathBuf::from(v)),
                _ => {},
            }
        }
    }
    let from = from.unwrap_or_default();
    let target = target.unwrap_or_default();
    let backup = backup.unwrap_or_default();
    Ok(UpgradeReceipt {
        kind,
        path: path.to_path_buf(),
        from,
        target,
        backup,
    })
}

/// Locates and parses any active upgrade receipt under `data_path`.
pub fn find_active_receipt(data_path: &Path) -> io::Result<Option<UpgradeReceipt>> {
    let pending = data_path.join(".upgrade-pending");
    let committing = data_path.join(".upgrade-committing");
    let completed = data_path.join(".upgrade-completed");

    let mut active: Option<UpgradeReceipt> = None;
    for (path, kind) in [
        (pending, ReceiptKind::Pending),
        (committing, ReceiptKind::Committing),
        (completed, ReceiptKind::Completed),
    ] {
        match path.symlink_metadata() {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
            Ok(meta) if !meta.is_file() => return Err(io::Error::other("unsafe upgrade receipt")),
            Ok(_) => {},
        }
        let record = parse_receipt_file(&path, kind)?;
        if let Some(first) = &active {
            if kind == ReceiptKind::Completed {
                return Err(io::Error::other(
                    "completed and active upgrade receipts coexist; retaining evidence",
                ));
            }
            if first.from != record.from
                || first.target != record.target
                || first.backup != record.backup
            {
                return Err(io::Error::other(
                    "conflicting upgrade receipts; retaining evidence",
                ));
            }
        } else {
            active = Some(record);
        }
    }
    Ok(active)
}

/// Failure cause when validating pre-upgrade backup integrity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackupIntegrityError {
    NotFound(PathBuf),
    NotADirectory(PathBuf),
    InsecurePermissions { path: PathBuf, mode: u32 },
    SymlinkRejected(PathBuf),
    MissingStateDirectory { backup: PathBuf, dir: &'static str },
    EmptyStateDirectory { backup: PathBuf, dir: &'static str },
    Io(String),
}

impl std::fmt::Display for BackupIntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(p) => write!(f, "backup directory not found: {}", p.display()),
            Self::NotADirectory(p) => write!(f, "backup path is not a directory: {}", p.display()),
            Self::InsecurePermissions { path, mode } => {
                write!(
                    f,
                    "backup directory {} has insecure permissions 0o{:o}, expected 0o700",
                    path.display(),
                    mode
                )
            },
            Self::SymlinkRejected(p) => {
                write!(f, "backup path contains unsafe symlink: {}", p.display())
            },
            Self::MissingStateDirectory { backup, dir } => {
                write!(
                    f,
                    "backup at {} missing required state directory '{}'",
                    backup.display(),
                    dir
                )
            },
            Self::EmptyStateDirectory { backup, dir } => {
                write!(
                    f,
                    "backup at {} contains empty state directory '{}'",
                    backup.display(),
                    dir
                )
            },
            Self::Io(e) => write!(f, "I/O error validating backup: {e}"),
        }
    }
}

impl std::error::Error for BackupIntegrityError {}

/// Verifies that a pre-upgrade backup directory is valid, accessible, and contains required state.
///
/// Ensures:
/// 1. Path exists, is a directory, and is not a symlink.
/// 2. Required directories `pki` and `kine/db` exist and are non-empty.
/// 3. The backup is private and its complete tree matches retained checksummed evidence.
/// 4. No links or special entries are present, including intermediate directories.
///
/// This verifies byte preservation, not original SQLite/PKI semantic health.
pub fn validate_backup_integrity(backup: &Path) -> Result<(), BackupIntegrityError> {
    let meta = match backup.symlink_metadata() {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(BackupIntegrityError::NotFound(backup.to_path_buf()));
        },
        Err(e) => return Err(BackupIntegrityError::Io(e.to_string())),
    };
    if meta.file_type().is_symlink() {
        return Err(BackupIntegrityError::SymlinkRejected(backup.to_path_buf()));
    }
    if !meta.is_dir() {
        return Err(BackupIntegrityError::NotADirectory(backup.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o7777;
        if mode != 0o700 {
            return Err(BackupIntegrityError::InsecurePermissions {
                path: backup.into(),
                mode,
            });
        }
    }

    for dir in BACKED_UP_STATE_DIRS {
        let state_dir = backup.join(dir);
        let smeta = match state_dir.symlink_metadata() {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(BackupIntegrityError::MissingStateDirectory {
                    backup: backup.to_path_buf(),
                    dir,
                });
            },
            Err(e) => return Err(BackupIntegrityError::Io(e.to_string())),
        };
        if smeta.file_type().is_symlink() {
            return Err(BackupIntegrityError::SymlinkRejected(state_dir));
        }
        if !smeta.is_dir() {
            return Err(BackupIntegrityError::MissingStateDirectory {
                backup: backup.to_path_buf(),
                dir,
            });
        }
        let mut entries =
            fs::read_dir(&state_dir).map_err(|e| BackupIntegrityError::Io(e.to_string()))?;
        if entries.next().is_none() {
            return Err(BackupIntegrityError::EmptyStateDirectory {
                backup: backup.to_path_buf(),
                dir,
            });
        }
    }
    crate::upgrade_integrity::verify(backup).map_err(|e| BackupIntegrityError::Io(e.to_string()))
}

/// Outcome of executing operator recovery on an interrupted upgrade.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryOutcome {
    RolledBack { from: String, backup: PathBuf },
    Committed { target: String },
    AlreadyClean,
}

fn validate_recovery_source(
    backend: &mut dyn TransitionBackend,
    data: &Path,
    receipt: &UpgradeReceipt,
) -> io::Result<()> {
    reject_symlink_state(data, BACKUP_DIR)?;
    let root = data.join(BACKUP_DIR);
    if receipt.backup.parent() != Some(root.as_path()) || receipt.backup.file_name().is_none() {
        return Err(io::Error::other(
            "recovery backup is outside the owned backup directory; retaining receipt",
        ));
    }
    validate_backup_integrity(&receipt.backup).map_err(|e| io::Error::other(format!(
        "recovery refused: backup at {} is invalid or unavailable ({e}); retaining receipt and data untouched for operator inspection", receipt.backup.display()
    )))?;
    backend.validate_snapshot(&receipt.backup)?;
    backend.recover_transition(receipt)
}

fn clean_rollback_receipts(data: &Path, receipt: &UpgradeReceipt) -> io::Result<()> {
    for name in [".upgrade-pending", ".upgrade-committing"] {
        remove_receipt(data, &data.join(name)).map_err(|e| io::Error::new(e.kind(), format!(
            "rollback to {} completed, but receipt cleanup failed ({e}); inspect {} and backup {} before retrying",
            receipt.from, data.join(name).display(), receipt.backup.display()
        )))?;
    }
    Ok(())
}

fn mark_rollback_pending(data: &Path, receipt: &UpgradeReceipt) -> io::Result<()> {
    // Persist rollback intent before changing artifacts or live state. A retry must never
    // finalize a target after a partially completed restoration.
    fs::rename(&receipt.path, data.join(".upgrade-pending"))?;
    fs::File::open(data)?.sync_all()
}

/// Executes operator recovery from an interrupted upgrade using retained receipts and backups.
///
/// Refuses to proceed if the backup is missing, incomplete, or corrupted, ensuring existing state
/// and diagnostics are retained untouched rather than destroyed.
pub fn recover_interrupted_upgrade(
    backend: &mut dyn TransitionBackend,
    data_path: &Path,
    config: Option<&Path>,
    stderr: &mut dyn Write,
) -> io::Result<RecoveryOutcome> {
    let _lock = lock_installation(data_path)?;
    let active = find_active_receipt(data_path)?;
    let Some(receipt) = active else {
        writeln!(
            stderr,
            "  [ok] No active upgrade receipt; installation is clean"
        )?;
        return Ok(RecoveryOutcome::AlreadyClean);
    };
    if classify_transition(&receipt.from, &receipt.target).is_err() {
        return Err(io::Error::other(
            "invalid recovery receipt versions; retaining receipt",
        ));
    }
    if receipt.kind != ReceiptKind::Completed {
        validate_recovery_source(backend, data_path, &receipt)?;
    }

    match receipt.kind {
        ReceiptKind::Completed => {
            writeln!(stderr, "  > Finalizing post-commit receipt cleanup...")?;
            remove_receipt(data_path, &receipt.path)?;
            writeln!(stderr, "  [ok] Cleaned completed receipt")?;
            Ok(RecoveryOutcome::Committed {
                target: receipt.target,
            })
        },
        ReceiptKind::Committing => {
            writeln!(
                stderr,
                "  [warn] Upgrade was interrupted during commit phase ({receipt})"
            )?;
            let completed = data_path.join(".upgrade-completed");
            match backend.start() {
                Ok(()) => {
                    writeln!(
                        stderr,
                        "  > Target installation is running; finalizing commit..."
                    )?;
                    backend.commit().map_err(|e| io::Error::new(e.kind(), format!(
                        "target start succeeded but commit failed ({e}); retaining committing receipt {} and backup {}", receipt.path.display(), receipt.backup.display()
                    )))?;
                    if let Err(error) = finish_commit_receipt(data_path, &receipt.path, &completed)
                    {
                        let _ = writeln!(
                            stderr,
                            "  [warn] Upgrade committed; receipt cleanup incomplete ({error}); inspect retained receipts and backup {}",
                            receipt.backup.display()
                        );
                    }
                    let _ = writeln!(stderr, "  [ok] Upgrade committed to {}", receipt.target);
                    Ok(RecoveryOutcome::Committed {
                        target: receipt.target,
                    })
                },
                Err(cause) => {
                    writeln!(
                        stderr,
                        "  [fail] Target failed to start: {cause}; checking rollback..."
                    )?;
                    validate_backup_integrity(&receipt.backup).map_err(|e| {
                        io::Error::other(format!(
                            "cannot roll back interrupted commit: backup validation failed ({e}); retaining receipt and state for operator inspection"
                        ))
                    })?;
                    mark_rollback_pending(data_path, &receipt)?;
                    backend.stop()?;
                    backend.restore(&receipt.backup)?;
                    restore_state(data_path, config, &receipt.backup)?;
                    backend.start()?;
                    clean_rollback_receipts(data_path, &receipt)?;
                    writeln!(stderr, "  [ok] Rolled back to {}", receipt.from)?;
                    Ok(RecoveryOutcome::RolledBack {
                        from: receipt.from,
                        backup: receipt.backup,
                    })
                },
            }
        },
        ReceiptKind::Pending => {
            writeln!(
                stderr,
                "  > Recovering interrupted upgrade (from {} to {})...",
                receipt.from, receipt.target
            )?;
            // Stop current backend if running
            backend.stop()?;

            // Execute rollback to pre-upgrade backup
            backend.restore(&receipt.backup)?;
            restore_state(data_path, config, &receipt.backup)?;
            backend.start()?;

            // Remove pending receipt
            clean_rollback_receipts(data_path, &receipt)?;
            writeln!(
                stderr,
                "  [ok] Rolled back to pre-upgrade state ({})",
                receipt.from
            )?;
            Ok(RecoveryOutcome::RolledBack {
                from: receipt.from,
                backup: receipt.backup,
            })
        },
    }
}

/// Host-mode backend: one binary and one service unit.
#[derive(Debug)]
pub struct HostBackend<'a, R: Runner> {
    pub binary: PathBuf,
    pub staged: PathBuf,
    pub service: String,
    pub runner: &'a mut R,
    pub systemd: bool,
    pub service_file: Option<PathBuf>,
    pub legacy_config: Option<PathBuf>,
}

impl<R: Runner> HostBackend<'_, R> {
    fn svc(&mut self, verb: &str) -> io::Result<()> {
        let (prog, args) = if self.systemd {
            ("systemctl", vec![verb.to_string(), self.service.clone()])
        } else {
            ("service", vec![self.service.clone(), verb.to_string()])
        };
        self.runner.run(prog, &args).map(|_| ())
    }
}

impl<R: Runner> TransitionBackend for HostBackend<'_, R> {
    fn validate_snapshot(&mut self, dir: &Path) -> io::Result<()> {
        if !dir.join("kubesolo.bin").symlink_metadata()?.is_file() {
            return Err(io::Error::other("backup binary is not a regular file"));
        }
        if self.service_file.is_some() {
            match dir.join("service.unit").symlink_metadata() {
                Ok(metadata) if !metadata.is_file() => {
                    return Err(io::Error::other(
                        "backup service unit is not a regular file",
                    ));
                },
                Ok(_) => {},
                Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    fn current_version(&mut self) -> io::Result<String> {
        let out = self
            .runner
            .run(&self.binary.to_string_lossy(), &["--version".to_string()])?;
        out.split_whitespace()
            .find(|w| parse_version(w).is_some())
            .map(str::to_string)
            .ok_or_else(|| io::Error::other("cannot determine installed version"))
    }

    fn prepare(&mut self, _target: &str) -> io::Result<()> {
        if self.staged.is_file() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "staged binary missing",
            ))
        }
    }

    fn snapshot(&mut self, dir: &Path) -> io::Result<()> {
        fs::copy(&self.binary, dir.join("kubesolo.bin"))?;
        if let Some(unit) = self.service_file.as_ref().filter(|p| p.is_file()) {
            fs::copy(unit, dir.join("service.unit"))?;
        }
        Ok(())
    }

    fn stop(&mut self) -> io::Result<()> {
        match self.svc("stop") {
            Ok(()) => Ok(()),
            Err(error) => {
                let inactive = !self.systemd
                    && matches!(
                        self.runner
                            .status_code("service", &[self.service.clone(), "status".into()]),
                        Ok(Some(3))
                    );
                if inactive { Ok(()) } else { Err(error) }
            },
        }
    }

    fn replace(&mut self, _target: &str) -> io::Result<()> {
        atomic_copy_with_mode(&self.staged, &self.binary, true)
    }

    fn start(&mut self) -> io::Result<()> {
        self.svc("start")
    }

    fn restore(&mut self, dir: &Path) -> io::Result<()> {
        self.stop()?;
        atomic_copy_with_mode(&dir.join("kubesolo.bin"), &self.binary, true)?;
        if let (Some(unit), true) = (&self.service_file, dir.join("service.unit").is_file()) {
            atomic_copy(&dir.join("service.unit"), unit)?;
            let mut marker = unit.as_os_str().to_owned();
            marker.push(".migration-pending");
            remove_owned_entry(Path::new(&marker))?;
            if self.systemd {
                self.runner.run("systemctl", &["daemon-reload".into()])?;
            }
        }
        Ok(())
    }

    fn migrate_config(&mut self, target: &str, stderr: &mut dyn Write) -> io::Result<bool> {
        let Some(unit) = self.service_file.clone().filter(|p| p.is_file()) else {
            return Ok(false);
        };
        let result = crate::migrate::migrate_legacy_service(
            &unit,
            self.legacy_config.as_deref(),
            target,
            None,
            stderr,
        )?;
        let migrated = matches!(result, crate::ServiceMigrationResult::Migrated { .. });
        if migrated && self.systemd {
            self.runner.run("systemctl", &["daemon-reload".into()])?;
        }
        Ok(migrated)
    }
}

/// Recorded container deployment; everything except the image tag is preserved on upgrade.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContainerSpec {
    pub name: String,
    pub image: String,
    pub args: Vec<String>,
    pub ports: Vec<String>,
    pub mounts: Vec<String>,
    pub env: Vec<String>,
    pub mtu: Option<String>,
}

fn valid_container_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

impl ContainerSpec {
    /// Parses `key=value` lines (`name`, `image`, `arg`, `port`, `mount`, `env`, `mtu`).
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut spec = Self::default();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| format!("line {}: expected key=value", n + 1))?;
            match k {
                "name" => spec.name = v.to_string(),
                "image" => spec.image = v.to_string(),
                "arg" => spec.args.push(v.to_string()),
                "port" => spec.ports.push(v.to_string()),
                "mount" => spec.mounts.push(v.to_string()),
                "env" => spec.env.push(v.to_string()),
                "mtu" => spec.mtu = Some(v.to_string()),
                other => return Err(format!("line {}: unknown key '{other}'", n + 1)),
            }
        }
        if !valid_container_name(&spec.name) {
            return Err(format!("invalid container name '{}'", spec.name));
        }
        if spec.image.is_empty() || spec.image.starts_with('-') {
            return Err("invalid or missing image".to_string());
        }
        Ok(spec)
    }

    /// Image repository without tag or digest.
    pub fn repository(&self) -> &str {
        let no_digest = self.image.split('@').next().unwrap_or(&self.image);
        match no_digest.rfind(':') {
            Some(i) if !no_digest[i..].contains('/') => &no_digest[..i],
            _ => no_digest,
        }
    }

    pub fn tag(&self) -> Option<&str> {
        let no_digest = self.image.split('@').next().unwrap_or(&self.image);
        no_digest
            .rfind(':')
            .filter(|&i| !no_digest[i..].contains('/'))
            .map(|i| &no_digest[i + 1..])
    }

    /// Spec with the image tag replaced and every other setting preserved.
    #[must_use]
    pub fn with_version(&self, version: &str) -> Self {
        Self {
            image: format!("{}:{version}", self.repository()),
            ..self.clone()
        }
    }

    pub fn run_args(&self, name: &str) -> Vec<String> {
        let mut a: Vec<String> = vec!["run".into(), "-d".into(), "--name".into(), name.into()];
        for p in &self.ports {
            a.extend(["-p".into(), p.clone()]);
        }
        for m in &self.mounts {
            a.extend(["-v".into(), m.clone()]);
        }
        for e in &self.env {
            a.extend(["-e".into(), e.clone()]);
        }
        if let Some(mtu) = &self.mtu {
            a.extend(["-e".into(), format!("KUBESOLO_MTU={mtu}")]);
        }
        a.push(self.image.clone());
        a.extend(self.args.iter().cloned());
        a
    }

    pub fn render(&self) -> String {
        let mut m = BTreeMap::new();
        m.insert("name", vec![self.name.clone()]);
        m.insert("image", vec![self.image.clone()]);
        let mut lines: Vec<String> = Vec::new();
        for (k, vs) in m {
            for v in vs {
                lines.push(format!("{k}={v}"));
            }
        }
        for (k, vs) in [
            ("arg", &self.args),
            ("port", &self.ports),
            ("mount", &self.mounts),
            ("env", &self.env),
        ] {
            for v in vs {
                lines.push(format!("{k}={v}"));
            }
        }
        if let Some(mtu) = &self.mtu {
            lines.push(format!("mtu={mtu}"));
        }
        lines.push(String::new());
        lines.join("\n")
    }
}

/// Container-mode backend: replaces exactly the named container.
#[derive(Debug)]
pub struct ContainerBackend<'a, R: Runner> {
    pub engine: String,
    pub spec: ContainerSpec,
    pub runner: &'a mut R,
    replaced: bool,
    spec_path: Option<PathBuf>,
    target: Option<String>,
    recovering_target: bool,
}

impl<'a, R: Runner> ContainerBackend<'a, R> {
    pub fn new(engine: &str, spec: ContainerSpec, runner: &'a mut R) -> Self {
        Self {
            engine: engine.to_string(),
            spec,
            runner,
            replaced: false,
            spec_path: None,
            target: None,
            recovering_target: false,
        }
    }

    /// Associates the installed version record with this deployment.
    #[must_use]
    pub fn with_spec_path(mut self, path: PathBuf) -> Self {
        self.spec_path = Some(path);
        self
    }

    fn old_name(&self) -> String {
        format!("{}-pre-upgrade", self.spec.name)
    }

    fn eng(&mut self, args: &[&str]) -> io::Result<String> {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        let engine = self.engine.clone();
        self.runner.run(&engine, &args)
    }

    fn quiesce_rollback_container(&mut self) -> io::Result<()> {
        let old = self.old_name();
        self.eng(&["stop", &old])?;
        let running = self.eng(&["inspect", "--format", "{{.State.Running}}", &old])?;
        if running.trim() != "false" {
            return Err(io::Error::other(
                "rollback container quiescence is not confirmed",
            ));
        }
        Ok(())
    }
}

impl<R: Runner> TransitionBackend for ContainerBackend<'_, R> {
    fn validate_snapshot(&mut self, dir: &Path) -> io::Result<()> {
        ContainerSpec::parse(&fs::read_to_string(dir.join(CONTAINER_SPEC_FILE))?)
            .map(|_| ())
            .map_err(io::Error::other)
    }

    fn recover_transition(&mut self, receipt: &UpgradeReceipt) -> io::Result<()> {
        let saved = ContainerSpec::parse(&fs::read_to_string(
            receipt.backup.join(CONTAINER_SPEC_FILE),
        )?)
        .map_err(io::Error::other)?;
        if saved.name != self.spec.name || saved.tag() != Some(receipt.from.as_str()) {
            return Err(io::Error::other(
                "container backup identity does not match receipt/installation",
            ));
        }
        let name = saved.name.clone();
        let old = format!("{name}-pre-upgrade");
        let names = self.eng(&["ps", "-a", "--format", "{{.Names}}"])?;
        let present = names.lines().any(|n| n == name);
        let rollback = names.lines().any(|n| n == old);
        if rollback {
            let image = self.eng(&["inspect", "--format", "{{.Config.Image}}", &old])?;
            if image.trim() != saved.image {
                return Err(io::Error::other(
                    "rollback container image does not match backup",
                ));
            }
        }
        if present {
            let image = self.eng(&["inspect", "--format", "{{.Config.Image}}", &name])?;
            let expected = if rollback || receipt.kind == ReceiptKind::Committing {
                saved.with_version(&receipt.target).image
            } else {
                saved.image.clone()
            };
            if image.trim() != expected {
                return Err(io::Error::other(
                    "active container image does not match recovery phase",
                ));
            }
        } else if !rollback || receipt.kind == ReceiptKind::Committing {
            return Err(io::Error::other(
                "recovery container is missing; retaining receipt",
            ));
        }
        self.spec = saved;
        self.replaced = rollback;
        self.target = Some(receipt.target.clone());
        self.recovering_target = rollback || receipt.kind == ReceiptKind::Committing;
        Ok(())
    }
    fn current_version(&mut self) -> io::Result<String> {
        self.spec
            .tag()
            .map(str::to_string)
            .ok_or_else(|| io::Error::other("container image has no version tag"))
    }

    fn prepare(&mut self, target: &str) -> io::Result<()> {
        let image = self.spec.with_version(target).image;
        self.eng(&["pull", &image]).map(|_| ())
    }

    fn snapshot(&mut self, dir: &Path) -> io::Result<()> {
        fs::write(dir.join(CONTAINER_SPEC_FILE), self.spec.render())
    }

    fn stop(&mut self) -> io::Result<()> {
        let name = self.spec.name.clone();
        match self.eng(&["stop", &name]) {
            Ok(_) => Ok(()),
            Err(error) => {
                let names = self.eng(&["ps", "-a", "--format", "{{.Names}}"])?;
                if names.lines().any(|n| n == name) {
                    Err(error)
                } else {
                    Ok(())
                }
            },
        }
    }

    fn replace(&mut self, target: &str) -> io::Result<()> {
        let (name, old) = (self.spec.name.clone(), self.old_name());
        self.eng(&["rename", &name, &old])?;
        self.replaced = true;
        self.target = Some(target.to_string());
        let args = self.spec.with_version(target).run_args(&name);
        let engine = self.engine.clone();
        self.runner.run(&engine, &args).map(|_| ())
    }

    fn start(&mut self) -> io::Result<()> {
        // After replace the new container is already running; before it, restart the old one.
        if self.recovering_target && self.replaced {
            self.quiesce_rollback_container()?;
        }
        if self.replaced || self.recovering_target {
            let name = self.spec.name.clone();
            self.eng(&["start", &name])?;
            let status = self.eng(&["inspect", "--format", "{{.State.Running}}", &name])?;
            if status.trim() != "true" {
                return Err(io::Error::other("replacement container is not running"));
            }
            Ok(())
        } else {
            let name = self.spec.name.clone();
            self.eng(&["start", &name]).map(|_| ())
        }
    }

    fn restore(&mut self, dir: &Path) -> io::Result<()> {
        if self.recovering_target && !self.replaced {
            return Err(io::Error::other(
                "rollback container no longer exists; retaining commit receipt",
            ));
        }
        let (name, old) = (self.spec.name.clone(), self.old_name());
        if self.replaced {
            // Reconstructed rollback containers can have restarted since the
            // original quiesce. Prove this writer is stopped before any restore.
            self.quiesce_rollback_container()?;
            // A failed launch may not have created a container. Verify absence explicitly.
            if self.eng(&["rm", "-f", &name]).is_err() {
                let names = self.eng(&["ps", "-a", "--format", "{{.Names}}"])?;
                if names.lines().any(|n| n == name) {
                    return Err(io::Error::other(
                        "cannot remove failed replacement container",
                    ));
                }
            }
            self.eng(&["rename", &old, &name])?;
            self.replaced = false;
        }
        self.recovering_target = false;
        if let Some(path) = &self.spec_path {
            atomic_copy(&dir.join(CONTAINER_SPEC_FILE), path)?;
        }
        Ok(())
    }

    fn commit(&mut self) -> io::Result<()> {
        let target = self
            .target
            .as_deref()
            .ok_or_else(|| io::Error::other("no staged container version"))?;
        let next = self.spec.with_version(target);
        if let Some(path) = &self.spec_path {
            let mut staged =
                tempfile::NamedTempFile::new_in(path.parent().unwrap_or(Path::new(".")))?;
            staged.write_all(next.render().as_bytes())?;
            staged.as_file().sync_all()?;
            staged.persist(path).map_err(|e| e.error)?;
        }
        let old = self.old_name();
        if let Err(error) = self.eng(&["rm", &old]) {
            if !self.recovering_target {
                return Err(error);
            }
            let names = self.eng(&["ps", "-a", "--format", "{{.Names}}"])?;
            if names.lines().any(|n| n == old) {
                return Err(error);
            }
        }
        self.spec = next;
        Ok(())
    }
}

/// Command entry point: chooses container mode when a recorded spec exists under the data path.
pub fn execute_upgrade(
    options: &crate::UpgradeOptions,
    inputs: &mut dyn crate::CheckInputs,
    _stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    if options.recover {
        return execute_recovery(options, inputs, stderr);
    }
    writeln!(stderr, "\n  dioramactl  upgrade\n")?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut runner = ProcessRunner;
    let spec_path = options.path.join(CONTAINER_SPEC_FILE);
    let result = if spec_path.is_file() {
        let spec = fs::read_to_string(&spec_path)
            .map_err(|e| e.to_string())
            .and_then(|t| ContainerSpec::parse(&t));
        match spec {
            Ok(spec) => {
                let mut backend = ContainerBackend::new("docker", spec, &mut runner)
                    .with_spec_path(spec_path.clone());
                run_upgrade(
                    &mut backend,
                    &options.path,
                    None,
                    &options.version,
                    stamp,
                    stderr,
                )
            },
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    } else {
        let stage = tempfile::tempdir()?;
        let staged = match stage_host_artifact(options, inputs, stage.path()) {
            Ok(p) => p,
            Err(e) => {
                writeln!(stderr, "  [fail] staging artifact: {e}")?;
                return Ok(1);
            },
        };
        let evidence = inputs.discover().map_err(io::Error::other)?;
        let init = match diorama_platform::classify(&evidence).init {
            diorama_platform::Observation::Present(init) => init,
            diorama_platform::Observation::Absent => {
                return Err(io::Error::other("init system absent"));
            },
            diorama_platform::Observation::Unknown(e) => {
                return Err(io::Error::other(format!("init detection failed: {e:?}")));
            },
        };
        let mut backend = HostBackend {
            binary: PathBuf::from(crate::DEFAULT_INSTALL_PATH),
            staged,
            service: SERVICE_NAME.to_string(),
            runner: &mut runner,
            systemd: init == diorama_platform::InitSystem::Systemd,
            service_file: crate::migrate::service_file_path(init).map(PathBuf::from),
            legacy_config: None,
        };
        run_upgrade(
            &mut backend,
            &options.path,
            Some(Path::new(diorama_config::DEFAULT_CONFIG_PATH)),
            &options.version,
            stamp,
            stderr,
        )
    };
    match result {
        Ok(UpgradeOutcome::RolledBack { cause, .. }) => {
            writeln!(stderr, "  upgrade failed and was rolled back: {cause}")?;
            Ok(1)
        },
        Ok(_) => Ok(0),
        Err(e) => {
            writeln!(stderr, "  [fail] {e}")?;
            Ok(1)
        },
    }
}

fn execute_recovery(
    options: &crate::UpgradeOptions,
    inputs: &mut dyn crate::CheckInputs,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    let mut runner = ProcessRunner;
    let spec_path = options.path.join(CONTAINER_SPEC_FILE);
    let outcome = if spec_path.is_file() {
        let spec =
            ContainerSpec::parse(&fs::read_to_string(&spec_path)?).map_err(io::Error::other)?;
        let mut backend =
            ContainerBackend::new("docker", spec, &mut runner).with_spec_path(spec_path);
        recover_interrupted_upgrade(&mut backend, &options.path, None, stderr)
    } else {
        let evidence = inputs.discover().map_err(io::Error::other)?;
        let diorama_platform::Observation::Present(init) =
            diorama_platform::classify(&evidence).init
        else {
            return Err(io::Error::other("recovery requires a detected init system"));
        };
        let mut backend = HostBackend {
            binary: PathBuf::from(crate::DEFAULT_INSTALL_PATH),
            staged: PathBuf::new(),
            service: SERVICE_NAME.into(),
            runner: &mut runner,
            systemd: init == diorama_platform::InitSystem::Systemd,
            service_file: crate::migrate::service_file_path(init).map(PathBuf::from),
            legacy_config: None,
        };
        recover_interrupted_upgrade(
            &mut backend,
            &options.path,
            Some(Path::new(diorama_config::DEFAULT_CONFIG_PATH)),
            stderr,
        )
    };
    match outcome {
        Ok(_) => Ok(0),
        Err(error) => {
            writeln!(stderr, "  [fail] {error}")?;
            Ok(1)
        },
    }
}

fn stage_host_artifact(
    options: &crate::UpgradeOptions,
    inputs: &mut dyn crate::CheckInputs,
    stage: &Path,
) -> io::Result<PathBuf> {
    let source = if let Some(path) = &options.offline_install {
        path.clone()
    } else {
        let evidence = inputs.discover().map_err(io::Error::other)?;
        let target =
            crate::resolve_target(None, None, Some(&evidence)).map_err(io::Error::other)?;
        let name = crate::artifact_archive_name(&options.version, target, false);
        let url =
            crate::artifact_download_url(&options.version, &name, options.custom_url.as_deref());
        let dest = stage.join(&name);
        inputs.download_file(&url, &dest, options.proxy.as_deref(), None)?;
        dest
    };
    let is_archive = source
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| {
            n.to_ascii_lowercase().ends_with(".tar.gz") || n.to_ascii_lowercase().ends_with(".tgz")
        });
    if !is_archive {
        return Ok(source);
    }
    let out = stage.join("extract");
    fs::create_dir_all(&out)?;
    ProcessRunner.run(
        "tar",
        &[
            "-xzf".into(),
            source.to_string_lossy().into_owned(),
            "-C".into(),
            out.to_string_lossy().into_owned(),
        ],
    )?;
    let bin = out.join("kubesolo");
    if bin.is_file() {
        Ok(bin)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "archive does not contain 'kubesolo'",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct Fake {
        log: Vec<String>,
        fail_on: Option<String>,
        version: String,
    }

    impl Runner for Fake {
        fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
            let line = format!("{program} {}", args.join(" "));
            self.log.push(line.clone());
            if args.first().is_some_and(|a| a == "inspect") {
                if args
                    .last()
                    .is_some_and(|name| name.ends_with("-pre-upgrade"))
                {
                    return Ok("false".into());
                }
                return Ok("true".into());
            }
            if self
                .fail_on
                .as_ref()
                .is_some_and(|f| line.contains(f.as_str()))
            {
                return Err(io::Error::other(format!("injected: {line}")));
            }
            Ok(self.version.clone())
        }
    }

    #[derive(Debug)]
    struct FailFirstStart(Fake, bool);

    impl Runner for FailFirstStart {
        fn run(&mut self, p: &str, a: &[String]) -> io::Result<String> {
            if a.first().is_some_and(|v| v == "start") && !self.1 {
                self.1 = true;
                self.0.log.push("start-failed".into());
                return Err(io::Error::other("boom"));
            }
            self.0.run(p, a)
        }
    }

    fn data_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::create_dir_all(d.path().join("pki")).unwrap();
        fs::write(d.path().join("pki/ca.crt"), "CA").unwrap();
        fs::create_dir_all(d.path().join("kine/db")).unwrap();
        fs::write(d.path().join("kine/db/state.db"), "DB").unwrap();
        d
    }

    fn host<'a>(d: &Path, runner: &'a mut Fake) -> HostBackend<'a, Fake> {
        let bin = d.join("kubesolo");
        fs::write(&bin, "old").unwrap();
        let staged = d.join("staged");
        fs::write(&staged, "new").unwrap();
        HostBackend {
            binary: bin,
            staged,
            service: SERVICE_NAME.into(),
            runner,
            systemd: true,
            service_file: None,
            legacy_config: None,
        }
    }

    #[test]
    fn transition_classification() {
        assert_eq!(
            classify_transition("v1.1.8", "v1.2.0"),
            Ok(Transition::Upgrade)
        );
        assert_eq!(
            classify_transition("v1.2.0", "v1.1.8"),
            Ok(Transition::Downgrade)
        );
        assert_eq!(classify_transition("v1.2.0", "1.2.0"), Ok(Transition::Same));
        assert!(classify_transition("v1.2.0", "latest").is_err());
    }

    #[test]
    fn host_upgrade_replaces_binary_and_backs_up_state() {
        let d = data_dir();
        let bins = tempfile::tempdir().unwrap();
        let mut r = Fake {
            version: "kubesolo v1.1.8".into(),
            ..Fake::default()
        };
        let mut b = host(bins.path(), &mut r);
        let mut err = Vec::new();
        let out = run_upgrade(&mut b, d.path(), None, "v1.3.0", 7, &mut err).unwrap();
        let UpgradeOutcome::Upgraded { backup } = out else {
            panic!("{out:?}")
        };
        assert_eq!(
            fs::read_to_string(bins.path().join("kubesolo")).unwrap(),
            "new"
        );
        assert_eq!(fs::read_to_string(backup.join("pki/ca.crt")).unwrap(), "CA");
        assert_eq!(
            fs::read_to_string(backup.join("kine/db/state.db")).unwrap(),
            "DB"
        );
        assert_eq!(
            fs::read_to_string(backup.join("kubesolo.bin")).unwrap(),
            "old"
        );
        let log = r.log.join("|");
        assert!(
            log.contains("systemctl stop diorama|systemctl start diorama"),
            "{log}"
        );
        assert!(String::from_utf8(err).unwrap().contains("Restart required"));
    }

    #[test]
    fn host_start_failure_rolls_back() {
        let d = data_dir();
        let bins = tempfile::tempdir().unwrap();
        let mut r = Fake {
            version: "v1.1.8".into(),
            ..Fake::default()
        };
        r.version = "v1.1.8".into();
        let mut runner = FailFirstStart(r, false);
        let bin = bins.path().join("kubesolo");
        fs::write(&bin, "old").unwrap();
        let staged = bins.path().join("staged");
        fs::write(&staged, "new").unwrap();
        let mut b = HostBackend {
            binary: bin.clone(),
            staged,
            service: SERVICE_NAME.into(),
            runner: &mut runner,
            systemd: true,
            service_file: None,
            legacy_config: None,
        };
        let out = run_upgrade(&mut b, d.path(), None, "v1.2.0", 1, &mut Vec::new()).unwrap();
        assert!(matches!(out, UpgradeOutcome::RolledBack { .. }), "{out:?}");
        assert_eq!(fs::read_to_string(bin).unwrap(), "old");
        assert_eq!(
            runner
                .0
                .log
                .iter()
                .filter(|l| l.contains("start diorama"))
                .count(),
            1
        );
    }

    #[test]
    fn prepare_failure_changes_nothing() {
        let d = data_dir();
        let bins = tempfile::tempdir().unwrap();
        let mut r = Fake {
            version: "v1.1.8".into(),
            ..Fake::default()
        };
        let mut b = host(bins.path(), &mut r);
        fs::remove_file(&b.staged).unwrap();
        assert!(run_upgrade(&mut b, d.path(), None, "v1.2.0", 1, &mut Vec::new()).is_err());
        assert!(!d.path().join(BACKUP_DIR).exists());
        assert!(!r.log.iter().any(|l| l.contains("stop")));
    }

    #[test]
    fn same_version_is_noop() {
        let d = data_dir();
        let bins = tempfile::tempdir().unwrap();
        let mut r = Fake {
            version: "v1.2.0".into(),
            ..Fake::default()
        };
        let mut b = host(bins.path(), &mut r);
        let out = run_upgrade(&mut b, d.path(), None, "v1.2.0", 1, &mut Vec::new()).unwrap();
        assert_eq!(out, UpgradeOutcome::Unchanged);
    }

    const SPEC: &str = "name=diorama\nimage=ghcr.io/example/kubesolo:v1.1.8\narg=--debug\nport=6443:6443\nport=9090:9090\nmount=/var/lib/diorama/pki:/var/lib/diorama/pki\nmount=/etc/diorama/registries.yaml:/etc/diorama/registries.yaml:ro\nmtu=1400\n";

    #[test]
    fn container_spec_roundtrip_and_preservation() {
        let spec = ContainerSpec::parse(SPEC).unwrap();
        assert_eq!(spec.repository(), "ghcr.io/example/kubesolo");
        assert_eq!(spec.tag(), Some("v1.1.8"));
        assert_eq!(ContainerSpec::parse(&spec.render()).unwrap(), spec);
        let next = spec.with_version("v1.2.0");
        assert_eq!(next.image, "ghcr.io/example/kubesolo:v1.2.0");
        let args = next.run_args("diorama").join(" ");
        for needle in [
            "-p 6443:6443",
            "-p 9090:9090",
            "pki:/var/lib/diorama/pki",
            "registries.yaml",
            "KUBESOLO_MTU=1400",
            "--debug",
        ] {
            assert!(args.contains(needle), "{needle} missing in {args}");
        }
    }

    #[test]
    fn container_spec_rejects_unsafe_names() {
        assert!(ContainerSpec::parse("name=--rm\nimage=x:v1.0.0\n").is_err());
        assert!(ContainerSpec::parse("name=a b\nimage=x:v1.0.0\n").is_err());
        assert!(ContainerSpec::parse("name=a\nimage=-x\n").is_err());
        assert!(ContainerSpec::parse("name=a\nimage=x\nbogus=1\n").is_err());
    }

    #[test]
    fn container_upgrade_touches_only_named_container() {
        let d = data_dir();
        let mut r = Fake::default();
        let spec = ContainerSpec::parse(SPEC).unwrap();
        let mut b = ContainerBackend::new("docker", spec, &mut r);
        let out = run_upgrade(&mut b, d.path(), None, "v1.2.0", 3, &mut Vec::new()).unwrap();
        assert!(matches!(out, UpgradeOutcome::Upgraded { .. }));
        let log = r.log.join("\n");
        assert!(
            log.starts_with("docker pull ghcr.io/example/kubesolo:v1.2.0"),
            "{log}"
        );
        assert!(log.contains("docker stop diorama"));
        assert!(log.contains("docker rename diorama diorama-pre-upgrade"));
        assert!(log.contains("docker rm diorama-pre-upgrade"));
        assert!(!log.contains("rm -f"));
        assert!(
            r.log
                .iter()
                .all(|l| !l.contains("prune") && !l.contains(" kill"))
        );
    }

    #[test]
    fn container_run_failure_restores_old_container() {
        let d = data_dir();
        let mut r = Fake {
            fail_on: Some("run -d".into()),
            ..Fake::default()
        };
        let spec = ContainerSpec::parse(SPEC).unwrap();
        let mut b = ContainerBackend::new("docker", spec, &mut r);
        let out = run_upgrade(&mut b, d.path(), None, "v1.2.0", 3, &mut Vec::new()).unwrap();
        let UpgradeOutcome::RolledBack { backup, .. } = out else {
            panic!()
        };
        assert!(backup.join(CONTAINER_SPEC_FILE).is_file());
        let log = r.log.join("\n");
        assert!(
            log.contains("docker rm -f diorama\ndocker rename diorama-pre-upgrade diorama"),
            "{log}"
        );
    }

    #[test]
    fn container_pull_failure_leaves_container_running() {
        let d = data_dir();
        let mut r = Fake {
            fail_on: Some("pull".into()),
            ..Fake::default()
        };
        let spec = ContainerSpec::parse(SPEC).unwrap();
        let mut b = ContainerBackend::new("docker", spec, &mut r);
        assert!(run_upgrade(&mut b, d.path(), None, "v1.2.0", 3, &mut Vec::new()).is_err());
        assert!(r.log.iter().all(|l| !l.contains("stop")));
    }
}
