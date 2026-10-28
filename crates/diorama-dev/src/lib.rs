//! Repository development and policy checks.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

pub mod language_policy;
pub mod proto_schema;
pub mod release_bundle;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

/// Find the repository from an explicit starting path.
pub fn repository_root(start: &Path) -> Result<PathBuf> {
    for path in start.canonicalize()?.ancestors() {
        if path.join("Cargo.toml").is_file() && path.join("rust-toolchain.toml").is_file() {
            return Ok(path.to_path_buf());
        }
    }
    Err(format!("repository root not found from {}", start.display()).into())
}

/// Read at most `limit` bytes, rejecting an oversized input rather than truncating it.
pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let maximum = limit.checked_add(1).ok_or("invalid input byte limit")?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(i32::try_from(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits(),
        )?);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(format!("{} is not a regular input file", path.display()).into());
    }
    let mut bytes = Vec::new();
    file.take(maximum).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len())? > limit {
        return Err(format!("{} exceeds {limit} bytes", path.display()).into());
    }
    Ok(bytes)
}

/// Run a command with inherited output and propagate unsuccessful status.
pub fn run_checked(command: &mut Command) -> Result<()> {
    let status = command.status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!("command {command:?} failed: {status}")).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reads_accept_exact_limit_and_reject_excess() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("input");
        std::fs::write(&path, b"abc")?;
        assert_eq!(read_bounded(&path, 3)?, b"abc");
        assert!(read_bounded(&path, 2).is_err());
        assert!(read_bounded(&path, u64::MAX).is_err());
        assert!(read_bounded(directory.path(), 3).is_err());
        #[cfg(unix)]
        {
            let link = directory.path().join("link");
            std::os::unix::fs::symlink(&path, &link)?;
            assert!(read_bounded(&link, 3).is_err());
        }
        Ok(())
    }
}
