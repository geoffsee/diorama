use rustix::fs::{FlockOperation, flock};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use crate::error::DatastoreError;

#[derive(Debug)]
pub struct DatastoreLock {
    file: File,
    path: PathBuf,
}

impl DatastoreLock {
    pub fn acquire(dir: &Path) -> Result<Self, DatastoreError> {
        let lock_path = dir.join(".lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;

        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Self {
                file,
                path: lock_path,
            }),
            Err(errno) => {
                if errno == rustix::io::Errno::WOULDBLOCK || errno == rustix::io::Errno::AGAIN {
                    Err(DatastoreError::LockContention(format!(
                        "datastore lock held by another process at {}",
                        lock_path.display()
                    )))
                } else {
                    Err(DatastoreError::Io(errno.into()))
                }
            },
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for DatastoreLock {
    fn drop(&mut self) {
        let _ = flock(&self.file, FlockOperation::Unlock);
    }
}
