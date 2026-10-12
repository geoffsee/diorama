pub(super) use super::oracle::require;
use diorama_dev::{
    Result,
    process::{Cancellation, CommandFailure, CommandRequest, Commands, OutputMode},
};
use serde_json::Value;
use std::{
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
pub(super) fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let file = fs::File::from(fd);
    require(file.metadata()?.is_file(), "regular input")?;
    let mut raw = Vec::new();
    file.take(limit.checked_add(1).ok_or("limit overflow")?)
        .read_to_end(&mut raw)?;
    require(u64::try_from(raw.len())? <= limit, "byte limit")?;
    Ok(raw)
}
pub(super) fn load(path: &Path) -> Result<Value> {
    diorama_dev::json::parse(&read(path, 16 * 1024 * 1024)?)
}
pub(super) fn save(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}
pub(super) fn digest(path: &Path) -> Result<String> {
    Ok(diorama_dev::sha256(&read(path, 256 * 1024 * 1024)?))
}
pub(super) fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn fields(row: &Value, names: &[&str]) -> Result<()> {
    require(
        row.as_object()
            .is_some_and(|o| o.len() == names.len() && names.iter().all(|k| o.contains_key(*k))),
        "exact fields",
    )
}
pub(super) fn text(row: &Value) -> Result<&str> {
    row.as_str().ok_or_else(|| "expected string".into())
}
pub(super) fn files(path: &Path) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if [
            "target",
            "evidence",
            "rust-evidence",
            "evidence-rust",
            ".git",
            "__pycache__",
            ".DS_Store",
        ]
        .iter()
        .any(|name| entry.file_name() == *name)
        {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_dir() {
            result.extend(files(&entry.path())?);
        } else if kind.is_file() {
            result.push(entry.path());
        } else {
            return Err("source symlink/special file".into());
        }
    }
    result.sort();
    Ok(result)
}
pub(super) const DIRECTORIES: [&str; 8] = [
    ".cargo",
    "crates",
    "third_party",
    "tools/upstream",
    "tools/dev",
    "tools/supervisor-process",
    "tools/supervisor-output",
    "tools/supervisor-signals",
];
pub(super) fn inventory(root: &Path) -> Result<Value> {
    let mut paths = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
        .map(|s| root.join(s))
        .to_vec();
    for name in DIRECTORIES {
        paths.extend(files(&root.join(name))?);
    }
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            Ok((
                p.strip_prefix(root)?
                    .to_str()
                    .ok_or("source UTF8")?
                    .to_owned(),
                Value::String(digest(&p)?),
            ))
        })
        .collect::<Result<serde_json::Map<_, _>>>()
        .map(Value::Object)
}
pub(super) fn relevant(name: &str) -> bool {
    name.ends_with("Cargo.toml")
        || ["Cargo.lock", "rust-toolchain.toml"].contains(&name)
        || name.starts_with(".cargo/")
        || name.starts_with("tools/dev/src/")
        || name.starts_with("crates/diorama-supervisor/")
            && Path::new(name).extension().is_some_and(|ext| ext == "rs")
        || ["process", "output", "signals"].iter().any(|family| {
            name.starts_with(&format!("tools/supervisor-{family}/"))
                && !name.ends_with("README.md")
                && !name.ends_with("provenance.json")
        })
}
pub(super) fn selected(value: &Value) -> Result<Value> {
    Ok(value
        .as_object()
        .ok_or("inventory object")?
        .iter()
        .filter(|(k, _)| relevant(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect())
}
pub(super) fn uncertain(error: &diorama_dev::Error) -> bool {
    error
        .downcast_ref::<CommandFailure>()
        .is_some_and(|e| !e.cleanup_complete)
}
pub(super) fn retain<T>(directory: tempfile::TempDir, result: Result<T>) -> Result<T> {
    if result.as_ref().is_err_and(uncertain) {
        eprintln!("unsettled command; retained {}", directory.keep().display());
    }
    result
}
pub(super) fn run(
    directory: &Path,
    label: &str,
    argv: &[OsString],
    seconds: u64,
    limit: u64,
    cancellation: Cancellation,
) -> Result<Vec<u8>> {
    Ok(Commands {
        output: directory.into(),
        cancellation,
    }
    .capture(CommandRequest {
        label,
        argv,
        timeout: Duration::from_secs(seconds),
        input: b"",
        required: true,
        byte_limit: limit,
        mode: OutputMode::Merged,
        environment: None,
        current_directory: None,
        launcher: None,
    })?
    .stdout_bytes)
}
pub(super) fn control(argv: &[OsString], cancellation: Cancellation) -> Result<String> {
    let directory = tempfile::tempdir()?;
    let result = (|| {
        Ok(String::from_utf8(run(
            directory.path(),
            "control",
            argv,
            30,
            65536,
            cancellation,
        )?)?
        .trim()
        .into())
    })();
    retain(directory, result)
}
pub(super) fn verify_command(directory: &Path, label: &str, argv: &Value) -> Result<String> {
    let path = directory.join(format!("{label}.command.json"));
    let row = load(&path)?;
    fields(
        &row,
        &[
            "spawned",
            "owned_pid",
            "owner_directory",
            "owned_process_group_absent",
            "cleanup_complete",
            "output_eof",
            "cleanup_errors",
            "exit_code",
            "timeout",
            "cancelled",
            "argv",
            "merged_output",
            "output_limit",
            "stdout_sha256",
            "stderr_sha256",
        ],
    )?;
    for key in [
        "spawned",
        "owned_process_group_absent",
        "cleanup_complete",
        "output_eof",
        "merged_output",
    ] {
        require(row[key] == true, "command settlement")?;
    }
    for key in ["timeout", "cancelled", "output_limit"] {
        require(row[key] == false, "command failure flag")?;
    }
    require(
        row["exit_code"] == 0 && row["cleanup_errors"] == serde_json::json!([]),
        "command success",
    )?;
    require(
        row["owned_pid"]
            .as_u64()
            .is_some_and(|pid| pid > 0 && u32::try_from(pid).is_ok()),
        "owned PID",
    )?;
    let owner = Path::new(text(&row["owner_directory"])?);
    require(
        owner.is_absolute()
            && owner
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("diorama-process-")),
        "owner metadata",
    )?;
    require(
        &row["argv"] == argv
            && row["stdout_sha256"] == digest(&directory.join(format!("{label}.log")))?
            && row["stderr_sha256"] == diorama_dev::sha256(b""),
        "command raw binding",
    )?;
    digest(&path)
}
