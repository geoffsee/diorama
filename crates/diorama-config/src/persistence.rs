//! Atomic replacement of stored documents. Callers own validation and writer coordination.
use crate::{API_VERSION, Config, ConfigError, KIND, render_effective_yaml};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistenceStage {
    Render,
    CreateDirectory,
    CreateTemporary,
    WriteTemporary,
    PermissionTemporary,
    SyncTemporary,
    ReadPrevious,
    CreateBackupTemporary,
    WriteBackupTemporary,
    PermissionBackupTemporary,
    SyncBackupTemporary,
    RenameBackup,
    SyncBackupDirectory,
    RenameDestination,
    SyncDestinationDirectory,
}

#[derive(Debug)]
pub enum PersistenceSource {
    Io(io::Error),
    Render(ConfigError),
}
impl fmt::Display for PersistenceSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Render(error) => error.fmt(f),
        }
    }
}
impl Error for PersistenceSource {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(match self {
            Self::Io(error) => error,
            Self::Render(error) => error,
        })
    }
}
#[derive(Debug)]
pub struct CleanupFailure {
    pub path: PathBuf,
    pub source: io::Error,
}
#[derive(Debug)]
pub struct PersistenceError {
    pub stage: PersistenceStage,
    pub path: PathBuf,
    /// True only after destination replacement; retry must account for the new document.
    pub committed: bool,
    pub source: PersistenceSource,
    pub cleanup_failures: Vec<CleanupFailure>,
}
impl fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "configuration {:?} at {} (committed={}): {}",
            self.stage,
            self.path.display(),
            self.committed,
            self.source
        )
    }
}
impl Error for PersistenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteOutcome {
    pub backup_created: bool,
}

struct Temporary {
    path: PathBuf,
    present: bool,
}
impl Temporary {
    fn cleanup(&mut self) -> io::Result<()> {
        if self.present {
            match fs::remove_file(&self.path) {
                Ok(()) => {},
                Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                Err(error) => return Err(error),
            }
            self.present = false;
        }
        Ok(())
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}
static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);
fn create_temporary(parent: &Path, destination: &Path) -> io::Result<(Temporary, File)> {
    for _ in 0..128 {
        let mut name = std::ffi::OsString::from(".");
        name.push(destination.file_name().unwrap_or_default());
        name.push(format!(
            ".tmp-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        ));
        let path = parent.join(name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                return Ok((
                    Temporary {
                        path,
                        present: true,
                    },
                    file,
                ));
            },
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "temporary filename attempts exhausted",
    ))
}
fn failure(
    stage: PersistenceStage,
    path: &Path,
    committed: bool,
    source: io::Error,
) -> PersistenceError {
    PersistenceError {
        stage,
        path: path.to_owned(),
        committed,
        source: PersistenceSource::Io(source),
        cleanup_failures: Vec::new(),
    }
}
fn step<T>(
    stage: PersistenceStage,
    path: &Path,
    committed: bool,
    inject: &mut impl FnMut(PersistenceStage) -> io::Result<()>,
    operation: impl FnOnce() -> io::Result<T>,
) -> Result<T, PersistenceError> {
    inject(stage)
        .and_then(|()| operation())
        .map_err(|error| failure(stage, path, committed, error))
}

/// Persist a stored configuration without applying environment, validation, or runtime discovery.
///
/// Callers must serialize read-modify-write transactions. Parent directories must be trusted:
/// this is not protection against an adversary replacing directory entries concurrently.
/// A destination symlink is read for its prior bytes, then its entry is replaced.
/// Existing backup links are replaced without writing through to their referents.
pub fn write_document(path: &Path, config: &Config) -> Result<WriteOutcome, PersistenceError> {
    write_with(path, config, &mut |_| Ok(()))
}
fn write_with(
    path: &Path,
    config: &Config,
    inject: &mut impl FnMut(PersistenceStage) -> io::Result<()>,
) -> Result<WriteOutcome, PersistenceError> {
    let mut document = config.clone();
    if document.api_version.is_empty() {
        document.api_version = API_VERSION.into();
    }
    if document.kind.is_empty() {
        document.kind = KIND.into();
    }
    let raw = render_effective_yaml(&document).map_err(|source| PersistenceError {
        stage: PersistenceStage::Render,
        path: path.to_owned(),
        committed: false,
        source: PersistenceSource::Render(source),
        cleanup_failures: Vec::new(),
    })?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut backup_name = path.as_os_str().to_owned();
    backup_name.push(".bak");
    let backup_path = PathBuf::from(backup_name);
    let mut temporary = Vec::<Temporary>::new();
    let result: Result<WriteOutcome, PersistenceError> = (|| {
        step(
            PersistenceStage::CreateDirectory,
            parent,
            false,
            inject,
            || {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o755)
                    .create(parent)
            },
        )?;
        let (guard, mut file) = step(
            PersistenceStage::CreateTemporary,
            parent,
            false,
            inject,
            || create_temporary(parent, path),
        )?;
        temporary.push(guard);
        let temporary_path = temporary[0].path.clone();
        step(
            PersistenceStage::WriteTemporary,
            &temporary_path,
            false,
            inject,
            || file.write_all(raw.as_bytes()),
        )?;
        step(
            PersistenceStage::PermissionTemporary,
            &temporary_path,
            false,
            inject,
            || file.set_permissions(fs::Permissions::from_mode(0o600)),
        )?;
        step(
            PersistenceStage::SyncTemporary,
            &temporary_path,
            false,
            inject,
            || file.sync_all(),
        )?;
        drop(file); // std::File does not expose separately fallible close; sync errors were checked.
        let backup_created = publish_backup(path, parent, &backup_path, &mut temporary, inject)?;
        step(
            PersistenceStage::RenameDestination,
            path,
            false,
            inject,
            || fs::rename(&temporary_path, path),
        )?;
        temporary[0].present = false;
        step(
            PersistenceStage::SyncDestinationDirectory,
            parent,
            true,
            inject,
            || File::open(parent)?.sync_all(),
        )?;
        Ok(WriteOutcome { backup_created })
    })();
    match result {
        Ok(outcome) => Ok(outcome),
        Err(mut error) => {
            for guard in &mut temporary {
                if let Err(source) = guard.cleanup() {
                    error.cleanup_failures.push(CleanupFailure {
                        path: guard.path.clone(),
                        source,
                    });
                }
            }
            Err(error)
        },
    }
}

fn publish_backup(
    path: &Path,
    parent: &Path,
    backup_path: &Path,
    temporary: &mut Vec<Temporary>,
    inject: &mut impl FnMut(PersistenceStage) -> io::Result<()>,
) -> Result<bool, PersistenceError> {
    let previous = step(
        PersistenceStage::ReadPrevious,
        path,
        false,
        inject,
        || match File::open(path) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        },
    )?;
    let backup_created = previous.is_some();
    if let Some(mut previous) = previous {
        let (guard, mut backup) = step(
            PersistenceStage::CreateBackupTemporary,
            parent,
            false,
            inject,
            || create_temporary(parent, backup_path),
        )?;
        temporary.push(guard);
        let staging_backup = temporary[1].path.clone();
        step(
            PersistenceStage::WriteBackupTemporary,
            &staging_backup,
            false,
            inject,
            || io::copy(&mut previous, &mut backup).map(|_| ()),
        )?;
        step(
            PersistenceStage::PermissionBackupTemporary,
            &staging_backup,
            false,
            inject,
            || backup.set_permissions(fs::Permissions::from_mode(0o600)),
        )?;
        step(
            PersistenceStage::SyncBackupTemporary,
            &staging_backup,
            false,
            inject,
            || backup.sync_all(),
        )?;
        drop(backup);
        drop(previous);
        step(
            PersistenceStage::RenameBackup,
            backup_path,
            false,
            inject,
            || fs::rename(&staging_backup, backup_path),
        )?;
        temporary[1].present = false;
        step(
            PersistenceStage::SyncBackupDirectory,
            parent,
            false,
            inject,
            || File::open(parent)?.sync_all(),
        )?;
    }
    Ok(backup_created)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn injected_stage_errors_preserve_commit_state_and_remove_staging_files() {
        let stages = [
            PersistenceStage::CreateDirectory,
            PersistenceStage::CreateTemporary,
            PersistenceStage::WriteTemporary,
            PersistenceStage::PermissionTemporary,
            PersistenceStage::SyncTemporary,
            PersistenceStage::ReadPrevious,
            PersistenceStage::CreateBackupTemporary,
            PersistenceStage::WriteBackupTemporary,
            PersistenceStage::PermissionBackupTemporary,
            PersistenceStage::SyncBackupTemporary,
            PersistenceStage::RenameBackup,
            PersistenceStage::SyncBackupDirectory,
            PersistenceStage::RenameDestination,
            PersistenceStage::SyncDestinationDirectory,
        ];
        for stage in stages {
            let root = std::env::temp_dir().join(format!(
                "diorama-write-fault-{}-{}",
                std::process::id(),
                NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let path = root.join("config.yaml");
            fs::write(&path, b"old bytes").unwrap();
            let error = write_with(&path, &Config::default(), &mut |current| {
                if current == stage {
                    Err(io::Error::other("injected stage failure"))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert_eq!(error.stage, stage);
            assert!(error.cleanup_failures.is_empty());
            let committed = stage == PersistenceStage::SyncDestinationDirectory;
            assert_eq!(error.committed, committed);
            if committed {
                assert_ne!(fs::read(&path).unwrap(), b"old bytes");
            } else {
                assert_eq!(fs::read(&path).unwrap(), b"old bytes");
            }
            assert!(
                error
                    .source()
                    .unwrap()
                    .source()
                    .unwrap()
                    .downcast_ref::<io::Error>()
                    .is_some()
            );
            for entry in fs::read_dir(&root).unwrap() {
                assert!(
                    !entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .contains(".tmp-")
                );
            }
            fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn explicit_cleanup_failure_is_preserved() {
        let root = std::env::temp_dir().join(format!(
            "diorama-cleanup-fault-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("config.yaml");
        let error = write_with(&path, &Config::default(), &mut |stage| {
            if stage == PersistenceStage::WriteTemporary {
                let temporary = fs::read_dir(&root)?
                    .next()
                    .ok_or_else(|| io::Error::other("missing staging file"))??
                    .path();
                fs::remove_file(&temporary)?;
                fs::create_dir(&temporary)?;
                return Err(io::Error::other("injected primary error"));
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.stage, PersistenceStage::WriteTemporary);
        assert_eq!(error.cleanup_failures.len(), 1);
        assert!(error.cleanup_failures[0].path.is_dir());
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
