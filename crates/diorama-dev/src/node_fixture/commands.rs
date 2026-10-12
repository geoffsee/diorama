use super::common::{Result, Value, digest, fields, load, require, retain, sha256, text};
use crate::parity::process::{Cancellation, CommandRequest, Commands, OutputMode};
use std::{ffi::OsString, path::Path, time::Duration};
pub(super) fn args(value: &Value) -> Result<Vec<OsString>> {
    value
        .as_array()
        .ok_or("argv array")?
        .iter()
        .map(|v| text(v).map(OsString::from))
        .collect()
}
pub(super) fn run(
    directory: &Path,
    label: &str,
    argv: &Value,
    seconds: u64,
    limit: u64,
    cancellation: &Cancellation,
) -> Result<Vec<u8>> {
    Ok(Commands {
        output: directory.into(),
        cancellation: cancellation.clone(),
    }
    .capture(CommandRequest {
        label,
        argv: &args(argv)?,
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
pub(super) fn control(argv: &Value, cancellation: &Cancellation) -> Result<String> {
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
pub(super) fn verify(directory: &Path, label: &str, argv: &Value) -> Result<String> {
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
        require(row[key] == true, "settled command")?;
    }
    for key in ["timeout", "cancelled", "output_limit"] {
        require(row[key] == false, "command failure flag")?;
    }
    require(
        row["exit_code"] == 0 && row["cleanup_errors"] == serde_json::json!([]),
        "successful command cleanup",
    )?;
    require(
        row["owned_pid"]
            .as_u64()
            .is_some_and(|p| p > 0 && u32::try_from(p).is_ok()),
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
            && row["stderr_sha256"] == sha256(b""),
        "command raw binding",
    )?;
    digest(&path)
}
