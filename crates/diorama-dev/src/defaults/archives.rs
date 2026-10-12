//! Checksum-locked source preparation for the disposable defaults workflow.
use super::{capture::arguments, directory, load, require};
use crate::{
    Result,
    process::{Cancellation, CommandFailure, Commands, SignalGuard},
};
use serde_json::Value;
use std::{fs, path::Path, time::Duration};

fn verify(path: &Path, pin: &Value) -> Result<()> {
    let size = pin["bytes"].as_u64().ok_or("archive byte count")?;
    require(size > 0 && size <= 128 * 1024 * 1024, "archive size bound")?;
    let raw = crate::read_bounded(path, size)?;
    require(raw.len() as u64 == size, "archive length differs")?;
    require(
        crate::sha256(&raw) == pin["sha256"],
        "archive digest differs",
    )
}

pub fn prepare(cache: &Path) -> Result<i32> {
    let inputs = load(&directory().join("inputs.json"))?;
    require(!cache.is_symlink(), "archive cache symlink rejected")?;
    fs::create_dir_all(cache)?;
    let cancellation = Cancellation::default();
    let _signals = SignalGuard::install(cancellation.clone())?;
    for name in ["source", "go"] {
        require(!cancellation.requested(), "archive preparation cancelled")?;
        prepare_one(cache, name, &inputs[name], cancellation.clone())?;
    }
    require(!cancellation.requested(), "archive preparation cancelled")?;
    Ok(0)
}

fn prepare_one(cache: &Path, name: &str, pin: &Value, cancellation: Cancellation) -> Result<()> {
    let path = cache.join(format!("{name}.tar.gz"));
    if fs::symlink_metadata(&path).is_ok() {
        return verify(&path, pin);
    }
    let url = pin["url"].as_str().ok_or("archive URL")?;
    let size = pin["bytes"].as_u64().ok_or("archive byte count")?;
    require(
        url.starts_with("https://") && size > 0 && size <= 128 * 1024 * 1024,
        "bounded HTTPS archive required",
    )?;
    let context = tempfile::Builder::new()
        .prefix("diorama-default-archive-")
        .tempdir_in(cache)?;
    let logs = context.path().join("commands");
    fs::create_dir(&logs)?;
    let partial = context.path().join("download.tar.gz");
    let commands = Commands {
        output: logs,
        cancellation,
    };
    let mut argv = arguments(&[
        "curl",
        "--fail",
        "--location",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--max-time",
        "60",
        "--max-filesize",
        &size.to_string(),
        "--output",
    ]);
    argv.push(partial.as_os_str().to_owned());
    argv.push(url.into());
    let result = commands.run("download", &argv, Duration::from_secs(70), b"", true, 65536);
    if let Err(error) = result {
        if error
            .downcast_ref::<CommandFailure>()
            .is_some_and(|failure| !failure.cleanup_complete)
        {
            let _retained_context = context.keep();
        }
        return Err(error);
    }
    verify(&partial, pin)?;
    require(
        !commands.cancellation.requested(),
        "archive preparation cancelled",
    )?;
    // Link publication cannot replace a concurrent cache entry; validate whichever won.
    match fs::hard_link(&partial, &path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => verify(&path, pin),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn cached_archives_reject_corruption_truncation_and_symlinks() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("source.tar.gz");
        let pin = json!({"bytes":4,"sha256":crate::sha256(b"safe")});
        fs::write(&path, b"safe")?;
        prepare_one(dir.path(), "source", &pin, Cancellation::default())?;
        for raw in [b"evil".as_slice(), b"saf", b"safeextra"] {
            fs::write(&path, raw)?;
            assert!(prepare_one(dir.path(), "source", &pin, Cancellation::default()).is_err());
        }
        fs::remove_file(&path)?;
        let target = dir.path().join("target");
        fs::write(&target, b"safe")?;
        std::os::unix::fs::symlink(&target, &path)?;
        assert!(prepare_one(dir.path(), "source", &pin, Cancellation::default()).is_err());
        Ok(())
    }
}
