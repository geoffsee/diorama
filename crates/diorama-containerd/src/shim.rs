//! Shim resolution and execution environment for containerd.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};

/// The standard registered containerd v2 runtime type.
pub const RUNTIME_RUNC_V2: &str = "io.containerd.runc.v2";

/// The default binary name for the runc v2 shim.
pub const DEFAULT_SHIM_BINARY_NAME: &str = "containerd-shim-runc-v2";

#[derive(Debug, PartialEq, Eq)]
pub enum ShimError {
    NotFound { name: String, path: String },
    NotExecutable { path: PathBuf },
    InvalidRuntimeType { actual: String, expected: String },
    DisallowedRuntimePath { path: PathBuf },
}

impl fmt::Display for ShimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { name, path } => {
                write!(f, "shim binary '{name}' not found in PATH '{path}'")
            },
            Self::NotExecutable { path } => {
                write!(f, "shim binary at '{}' is not executable", path.display())
            },
            Self::InvalidRuntimeType { actual, expected } => {
                write!(
                    f,
                    "runtime_type must be registered type '{expected}', got '{actual}'"
                )
            },
            Self::DisallowedRuntimePath { path } => {
                write!(
                    f,
                    "runtime_path must not be set (got '{}'); containerd must resolve shim via PATH",
                    path.display()
                )
            },
        }
    }
}

impl std::error::Error for ShimError {}

/// Prepend the containerd binary/shim directory to the PATH environment string.
///
/// containerd resolves shims named by `runtime_type = "io.containerd.runc.v2"`
/// by searching `PATH` for `containerd-shim-runc-v2`. Prepending the managed
/// directory ensures the embedded shim is discovered first without mutating
/// global directories like `/usr/local/bin` or setting `runtime_path`.
#[must_use]
pub fn build_containerd_path(shim_dir: &Path, existing_path: Option<&OsStr>) -> OsString {
    let mut paths = vec![shim_dir.to_path_buf()];
    if let Some(existing) = existing_path {
        for path in env::split_paths(existing) {
            if path != shim_dir {
                paths.push(path);
            }
        }
    }
    env::join_paths(paths).unwrap_or_else(|_| OsString::from(shim_dir))
}

/// Resolve a shim binary name within a given PATH environment string.
#[must_use]
pub fn find_shim_in_path(binary_name: &str, path_env: &OsStr) -> Option<PathBuf> {
    for dir in env::split_paths(path_env) {
        let candidate = dir.join(binary_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Validate that a runtime type conforms to the registered containerd contract
/// and does not attempt an out-of-band `runtime_path` specification.
pub fn validate_runtime_spec(
    runtime_type: &str,
    runtime_path: Option<&Path>,
) -> Result<(), ShimError> {
    if runtime_type != RUNTIME_RUNC_V2 {
        return Err(ShimError::InvalidRuntimeType {
            actual: runtime_type.to_string(),
            expected: RUNTIME_RUNC_V2.to_string(),
        });
    }

    if let Some(path) = runtime_path {
        return Err(ShimError::DisallowedRuntimePath {
            path: path.to_path_buf(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_path_prepends_shim_directory() {
        let shim_dir = Path::new("/custom/containerd/bin");
        let existing = OsStr::new("/usr/bin:/bin");
        let combined = build_containerd_path(shim_dir, Some(existing));
        let paths: Vec<PathBuf> = env::split_paths(&combined).collect();
        assert_eq!(paths[0], shim_dir);
        assert_eq!(paths[1], Path::new("/usr/bin"));
        assert_eq!(paths[2], Path::new("/bin"));
    }

    #[test]
    fn build_path_handles_empty_or_none_existing() {
        let shim_dir = Path::new("/custom/containerd/bin");
        let combined = build_containerd_path(shim_dir, None);
        let paths: Vec<PathBuf> = env::split_paths(&combined).collect();
        assert_eq!(paths, vec![shim_dir.to_path_buf()]);
    }

    #[test]
    fn build_path_deduplicates_existing_shim_dir() {
        let shim_dir = Path::new("/custom/bin");
        let existing = OsStr::new("/usr/bin:/custom/bin:/bin");
        let combined = build_containerd_path(shim_dir, Some(existing));
        let paths: Vec<PathBuf> = env::split_paths(&combined).collect();
        assert_eq!(paths.len(), 3);
        assert_eq!(paths[0], shim_dir);
        assert_eq!(paths[1], Path::new("/usr/bin"));
        assert_eq!(paths[2], Path::new("/bin"));
    }

    #[test]
    fn runtime_spec_validation() {
        assert!(validate_runtime_spec("io.containerd.runc.v2", None).is_ok());

        assert_eq!(
            validate_runtime_spec("custom.runtime.v1", None).unwrap_err(),
            ShimError::InvalidRuntimeType {
                actual: "custom.runtime.v1".to_string(),
                expected: "io.containerd.runc.v2".to_string(),
            }
        );

        assert_eq!(
            validate_runtime_spec(
                "io.containerd.runc.v2",
                Some(Path::new("/usr/local/bin/containerd-shim-runc-v2"))
            )
            .unwrap_err(),
            ShimError::DisallowedRuntimePath {
                path: PathBuf::from("/usr/local/bin/containerd-shim-runc-v2"),
            }
        );
    }
}
