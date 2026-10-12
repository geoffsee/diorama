//! Shared Rust parity runner. VM and container ownership remain explicit.
mod archive;
mod contract;
mod driver;
#[cfg(test)]
mod historical;
pub(crate) mod lifecycle;
pub mod process;
mod runner;
pub(crate) mod seed;
pub(crate) mod vm;

use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
pub(crate) type Result<T> = diorama_dev::Result<T>;
pub(crate) fn require(value: bool, message: impl Into<String>) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(message.into().into())
    }
}
pub(crate) fn read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(i32::try_from(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits(),
        )?)
        .open(path)?;
    require(file.metadata()?.is_file(), "regular input file required")?;
    let mut bytes = Vec::new();
    file.take(maximum.checked_add(1).ok_or("invalid byte limit")?)
        .read_to_end(&mut bytes)?;
    require(bytes.len() as u64 <= maximum, "input byte limit")?;
    Ok(bytes)
}
pub(crate) fn digest(path: &Path, sha512: bool) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(i32::try_from(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits(),
        )?)
        .open(path)?;
    require(file.metadata()?.is_file(), "regular digest input")?;
    let mut short = Sha256::new();
    let mut long = Sha512::new();
    let mut buffer = [0; 8192];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        require(total <= 1024 * 1024 * 1024, "digest size limit")?;
        if sha512 {
            long.update(&buffer[..n]);
        } else {
            short.update(&buffer[..n]);
        }
    }
    let bytes = if sha512 {
        long.finalize().to_vec()
    } else {
        short.finalize().to_vec()
    };
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(encoded)
}
pub(crate) fn write_json(path: &Path, value: &Value, exclusive: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).mode(0o600).custom_flags(i32::try_from(
        (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits(),
    )?);
    if exclusive {
        options.create_new(true);
    } else {
        options.create(true);
    }
    let mut file = options.open(path)?;
    require(file.metadata()?.is_file(), "regular JSON output required")?;
    if !exclusive {
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
    }
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    Ok(())
}
pub(crate) fn json_file(path: &Path) -> Result<Value> {
    diorama_dev::json::parse(&read(path, 8 * 1024 * 1024)?)
}
pub(crate) fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
pub(crate) fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}
#[derive(Debug)]
pub(crate) struct Options {
    pub values: BTreeMap<String, OsString>,
    pub privileged: bool,
}
impl Options {
    pub(crate) fn parse(args: &[OsString]) -> Result<Self> {
        let mut values = BTreeMap::new();
        let mut privileged = false;
        let mut iter = args.iter();
        while let Some(key) = iter.next() {
            let key = key.to_str().ok_or("option UTF-8")?;
            if key == "--allow-privileged-vm" {
                require(!privileged, "duplicate privilege flag")?;
                privileged = true;
                continue;
            }
            require(
                [
                    "--artifact",
                    "--suite",
                    "--output",
                    "--image-cache",
                    "--inject-failure",
                    "--driver",
                    "--repo",
                ]
                .contains(&key),
                format!("unknown option: {key}"),
            )?;
            require(
                values
                    .insert(
                        key.into(),
                        iter.next().ok_or("option requires value")?.clone(),
                    )
                    .is_none(),
                "duplicate option",
            )?;
        }
        Ok(Self { values, privileged })
    }
    pub(crate) fn path(&self, key: &str) -> Result<PathBuf> {
        Ok(PathBuf::from(
            self.values
                .get(key)
                .ok_or_else(|| format!("required {key}"))?,
        ))
    }
    pub(crate) fn injected(&self) -> Result<Option<&str>> {
        let value = self
            .values
            .get("--inject-failure")
            .map(|s| s.to_str().ok_or("failure flag UTF-8"))
            .transpose()?;
        require(
            value.is_none_or(|v| ["setup", "test"].contains(&v)),
            "invalid injected failure",
        )?;
        Ok(value)
    }
    pub(crate) fn root(&self) -> Result<PathBuf> {
        diorama_dev::repository_root(&self.values.get("--repo").map_or_else(
            || std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            PathBuf::from,
        ))
    }
}
pub(crate) fn run_with_cancellation(
    options: &Options,
    cancellation: process::Cancellation,
) -> Result<u8> {
    runner::run(options, cancellation)
}
pub(crate) fn main(arguments: &[OsString]) -> Result<u8> {
    let Some(command) = arguments.first().and_then(|a| a.to_str()) else {
        return Err(
            "usage: diorama-parity {validate|stage|driver|run|vm|prepare-upstream} [options]".into(),
        );
    };
    if command == "__exec" {
        return process::child_exec(arguments);
    }
    let options = Options::parse(&arguments[1..])?;
    if command == "validate" || command == "stage" {
        let artifact: contract::Artifact =
            serde_json::from_value(json_file(&options.path("--artifact")?)?)?;
        let suite: contract::Suite = serde_json::from_value(json_file(&options.path("--suite")?)?)?;
        contract::validate(&artifact, &suite)?;
        if command == "stage" {
            contract::stage_files(&suite.cases, &options.path("--output")?)?;
        }
        return Ok(0);
    }
    let cancellation = process::Cancellation::default();
    let signals = process::SignalGuard::install(cancellation.clone())?;
    let outcome = match command {
        "driver" => driver::run(&cancellation),
        "run" => run_with_cancellation(&options, cancellation),
        "vm" => vm::run(&options, &cancellation),
        "prepare-upstream" => runner::prepare_upstream(&options, cancellation),
        _ => Err(format!("unknown subcommand {command}").into()),
    };
    drop(signals);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn shell_quote_never_expands_literals() {
        assert_eq!(quote("a'b $(x)"), "'a'\"'\"'b $(x)'");
    }
    #[test]
    fn cache_reader_rejects_symlink_and_oversize() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("target");
        fs::write(&target, b"abc")?;
        std::os::unix::fs::symlink(&target, dir.path().join("link"))?;
        assert!(read(&dir.path().join("link"), 5).is_err());
        assert!(read(&target, 2).is_err());
        assert_eq!(read(&target, 3)?, b"abc");
        Ok(())
    }
    #[test]
    fn json_output_rejects_fifo_without_blocking_and_parser_rejects_duplicate_keys() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let fifo = dir.path().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()?
                .success()
        );
        assert!(write_json(&fifo, &serde_json::json!({}), false).is_err());
        let path = dir.path().join("json");
        fs::write(&path, b"{\"key\":1,\"key\":2}")?;
        assert!(json_file(&path).is_err());
        Ok(())
    }
}
