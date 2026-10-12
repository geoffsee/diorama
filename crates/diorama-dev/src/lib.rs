//! Repository maintenance tools. This crate is not a node runtime dependency.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

pub mod defaults;
#[cfg(not(test))]
pub mod drift;
pub mod fixture_capture;
pub mod fixture_oracles;
pub mod json;
pub mod language_policy;
#[path = "parity/process.rs"]
pub mod process;
pub mod resolved_capture;
pub mod resolved_report;
pub mod state_transition;
#[cfg(not(test))]
pub mod upstream;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

/// Find the repository from an explicit starting path, without consulting the shell.
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

pub fn sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    Sha256::digest(bytes)
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

/// Run a maintenance command with inherited output and propagate unsuccessful status.
pub fn run_checked(command: &mut Command) -> Result<()> {
    let status = command.status()?;
    if !status.success() {
        return Err(io::Error::other(format!("command {command:?} failed: {status}")).into());
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

    #[test]
    fn hashes_known_bytes() {
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

#[path = "fixture_oracles/probes.rs"]
pub mod preflight_probes;

pub mod api_json;
pub mod component_boundary;
pub mod conformance;
pub mod disposable_node;
pub mod operator_rehearsal;
pub mod perf;
pub mod platform_management;
pub mod platform_soak;
pub mod provenance;
pub mod recovery_rehearsal;
pub mod release;
pub mod release_qualification;
