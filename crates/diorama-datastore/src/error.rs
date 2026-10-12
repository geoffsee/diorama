use std::fmt;
use std::io;

#[derive(Debug)]
pub enum DatastoreError {
    Io(io::Error),
    Serialization(serde_json::Error),
    LockContention(String),
    AuthenticationConfig(String),
    UnsafePath(String),
    KeyNotFound(String),
    KeyAlreadyExists(String),
    RevisionMismatch { expected: u64, actual: u64 },
    Compacted(u64),
    CorruptWal { index: u64, reason: String },
    Fatal(String),
}

impl fmt::Display for DatastoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "datastore I/O error: {err}"),
            Self::Serialization(err) => write!(f, "datastore serialization error: {err}"),
            Self::LockContention(msg) => write!(f, "datastore lock contention: {msg}"),
            Self::AuthenticationConfig(msg) => {
                write!(f, "datastore authentication configuration error: {msg}")
            },
            Self::UnsafePath(msg) => write!(f, "datastore unsafe path: {msg}"),
            Self::KeyNotFound(key) => write!(f, "key not found: {key}"),
            Self::KeyAlreadyExists(key) => write!(f, "key already exists: {key}"),
            Self::RevisionMismatch { expected, actual } => {
                write!(
                    f,
                    "resource version mismatch: expected revision {expected}, actual is {actual}"
                )
            },
            Self::Compacted(rev) => write!(f, "revision {rev} has been compacted"),
            Self::CorruptWal { index, reason } => {
                write!(f, "corrupt WAL record at index {index}: {reason}")
            },
            Self::Fatal(msg) => write!(f, "fatal datastore error: {msg}"),
        }
    }
}

impl std::error::Error for DatastoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Serialization(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for DatastoreError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for DatastoreError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err)
    }
}

impl DatastoreError {
    pub fn is_lock_contention(&self) -> bool {
        matches!(self, Self::LockContention(_))
    }

    pub fn is_auth_failure(&self) -> bool {
        matches!(self, Self::AuthenticationConfig(_))
    }

    pub fn is_corruption(&self) -> bool {
        matches!(self, Self::CorruptWal { .. })
    }

    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::LockContention(_) => "datastore-lock-contention",
            Self::AuthenticationConfig(_) => "datastore-auth-failure",
            Self::CorruptWal { .. } => "datastore-wal-corrupt",
            Self::UnsafePath(_) => "datastore-unsafe-path",
            Self::Io(_) => "datastore-io-error",
            Self::Serialization(_) => "datastore-serialization-error",
            Self::KeyNotFound(_) => "datastore-key-not-found",
            Self::KeyAlreadyExists(_) => "datastore-key-already-exists",
            Self::RevisionMismatch { .. } => "datastore-revision-mismatch",
            Self::Compacted(_) => "datastore-revision-compacted",
            Self::Fatal(_) => "datastore-fatal-error",
        }
    }
}
