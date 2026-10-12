pub(super) use diorama_dev::{Result, sha256};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
pub(super) use serde_json::json;
use serde_json::{Map, Value};
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
pub(super) fn check(value: bool, message: &str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}
pub(super) fn root() -> Result<PathBuf> {
    diorama_dev::repository_root(&std::env::current_dir()?)
}
pub(super) fn fields(value: &Value, names: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or("expected object")?;
    check(
        object.len() == names.len() && names.iter().all(|name| object.contains_key(*name)),
        "exact object fields",
    )
}
pub(super) fn string(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(|| "expected string".into())
}
pub(super) fn array(value: &Value) -> Result<&Vec<Value>> {
    value.as_array().ok_or_else(|| "expected array".into())
}
pub(super) fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("integer-only JSON without duplicate keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut out = Vec::new();
                while let Some(Strict(value)) = access.next_element()? {
                    out.push(value);
                }
                Ok(Strict(out.into()))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut out = Map::new();
                while let Some((key, Strict(value))) = access.next_entry::<String, Strict>()? {
                    out.insert(key, value)
                        .is_none()
                        .then_some(())
                        .ok_or_else(|| de::Error::custom("duplicate JSON key"))?;
                }
                Ok(Strict(out.into()))
            }
        }
        decoder.deserialize_any(V)
    }
}
pub(super) fn strict(raw: &[u8]) -> Result<Value> {
    Ok(serde_json::from_slice::<Strict>(raw)?.0)
}
pub(super) fn stream_json(raw: &[u8]) -> Result<Vec<Value>> {
    serde_json::Deserializer::from_slice(raw)
        .into_iter::<Strict>()
        .map(|v| v.map(|v| v.0).map_err(Into::into))
        .collect()
}
pub(super) fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    // Open atomically with NOFOLLOW/NONBLOCK; metadata is from the opened descriptor.
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let file = File::from(fd);
    check(file.metadata()?.is_file(), "regular input required")?;
    let mut raw = Vec::new();
    file.take(limit.checked_add(1).ok_or("invalid limit")?)
        .read_to_end(&mut raw)?;
    check(u64::try_from(raw.len())? <= limit, "input byte limit")?;
    Ok(raw)
}
pub(super) fn digest(path: &Path) -> Result<String> {
    Ok(sha256(&read(path, 256 * 1024 * 1024)?))
}
pub(super) fn load(path: &Path) -> Result<Value> {
    strict(&read(path, 4 * 1024 * 1024)?)
}
pub(super) fn save(path: &Path, value: &Value) -> Result<()> {
    let mut raw = serde_json::to_vec_pretty(value)?;
    raw.push(b'\n');
    fs::write(path, raw)?;
    Ok(())
}
pub(super) fn files(path: &Path) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
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
        .any(|n| name == *n)
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
pub(super) fn inventory(root: &Path, family: &str) -> Result<Value> {
    let mut paths = vec!["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
        .into_iter()
        .map(|n| root.join(n))
        .collect::<Vec<_>>();
    for dir in [
        ".cargo",
        "crates",
        "tools/dev",
        "tools/assets-manifest",
        &format!("tools/assets-{family}"),
    ] {
        for path in files(&root.join(dir))? {
            let name = path
                .strip_prefix(root)?
                .to_str()
                .ok_or("source path UTF8")?;
            if name.ends_with("Cargo.toml")
                || name.starts_with(".cargo/")
                || name.starts_with("tools/dev/src/")
                || name.starts_with("crates/diorama-assets/")
                    && ["rs", "json", "bin"]
                        .iter()
                        .any(|e| path.extension().is_some_and(|x| x == *e))
                || name.starts_with("crates/diorama-platform/")
                    && path.extension().is_some_and(|x| x == "rs")
                || (name.starts_with(&format!("tools/assets-{family}/"))
                    || name.starts_with("tools/assets-manifest/"))
                    && !["README.md", "provenance.json"]
                        .iter()
                        .any(|n| path.file_name().is_some_and(|v| v == *n))
            {
                paths.push(path);
            }
        }
    }
    if family == "elf" {
        paths.push(root.join("experiments/component-boundary/inputs.json"));
    }
    paths.sort();
    paths.dedup();
    let mut out = Map::new();
    for path in paths {
        out.insert(
            path.strip_prefix(root)?
                .to_str()
                .ok_or("source path")?
                .into(),
            digest(&path)?.into(),
        );
    }
    Ok(out.into())
}
pub(super) fn clean_revision(root: &Path, sources: &Value) -> Result<String> {
    let relevant = sources
        .as_object()
        .ok_or("source map")?
        .keys()
        .collect::<Vec<_>>();
    check(
        output(
            Command::new("git")
                .current_dir(root)
                .args(["status", "--porcelain", "--untracked-files=all", "--"])
                .args(relevant),
        )?
        .is_empty(),
        "clean committed fixture source required",
    )?;
    let revision = output(
        Command::new("git")
            .current_dir(root)
            .args(["rev-parse", "HEAD"]),
    )?;
    check(hex(&revision, 40), "source revision")?;
    Ok(revision)
}
static CANCELLATION: std::sync::OnceLock<diorama_dev::process::Cancellation> =
    std::sync::OnceLock::new();
pub(super) fn cancellation() -> diorama_dev::process::Cancellation {
    CANCELLATION
        .get_or_init(diorama_dev::process::Cancellation::default)
        .clone()
}
pub(super) fn uncertain(error: &diorama_dev::Error) -> bool {
    error
        .downcast_ref::<diorama_dev::process::CommandFailure>()
        .is_some_and(|failure| !failure.cleanup_complete)
}
pub(super) fn retain<T>(directory: tempfile::TempDir, result: Result<T>) -> Result<T> {
    if result.as_ref().is_err_and(uncertain) {
        eprintln!(
            "asset fixture: unsettled command; retained {}",
            directory.keep().display()
        );
    }
    result
}
pub(super) fn bounded(command: &mut Command, path: &Path, seconds: u64, limit: u64) -> Result<()> {
    bounded_with(command, path, seconds, limit, cancellation())
}
fn bounded_with(
    command: &Command,
    path: &Path,
    seconds: u64,
    limit: u64,
    cancellation: diorama_dev::process::Cancellation,
) -> Result<()> {
    use diorama_dev::process::{CommandRequest, Commands, OutputMode};
    check(
        path.extension().is_some_and(|value| value == "log"),
        "command log extension",
    )?;
    let argv = std::iter::once(command.get_program().to_os_string())
        .chain(command.get_args().map(std::ffi::OsStr::to_os_string))
        .collect::<Vec<_>>();
    let environment = if command.get_envs().next().is_some() {
        let mut values = std::env::vars_os()
            .map(|(key, value)| {
                Ok((
                    key.into_string().map_err(|_| "environment name UTF8")?,
                    value.into_string().map_err(|_| "environment value UTF8")?,
                ))
            })
            .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
        for (key, value) in command.get_envs() {
            let key = key.to_str().ok_or("environment name UTF8")?;
            if let Some(value) = value {
                values.insert(
                    key.into(),
                    value.to_str().ok_or("environment value UTF8")?.into(),
                );
            } else {
                values.remove(key);
            }
        }
        Some(values)
    } else {
        None
    };
    let commands = Commands {
        output: path.parent().ok_or("log parent")?.into(),
        cancellation,
    };
    commands.capture(CommandRequest {
        label: path
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or("log name")?,
        argv: &argv,
        timeout: Duration::from_secs(seconds),
        input: b"",
        required: true,
        byte_limit: limit,
        mode: OutputMode::Merged,
        environment: environment.as_ref(),
        current_directory: command.get_current_dir(),
        launcher: None,
    })?;
    Ok(())
}
pub(super) fn output(command: &mut Command) -> Result<String> {
    control(command, cancellation())
}
pub(super) fn persistent_control(command: &Command, path: &Path, cleanup: bool) -> Result<String> {
    let latch = if cleanup {
        diorama_dev::process::Cancellation::default()
    } else {
        cancellation()
    };
    bounded_with(command, path, 30, 65536, latch)?;
    Ok(String::from_utf8(read(path, 65536)?)?.trim().to_owned())
}
fn control(command: &Command, cancellation: diorama_dev::process::Cancellation) -> Result<String> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("log.log");
    let result = (|| {
        bounded_with(command, &path, 30, 65536, cancellation)?;
        Ok(String::from_utf8(read(&path, 65536)?)?.trim().to_owned())
    })();
    retain(tmp, result)
}
pub(super) fn publish_result(path: &Path, report: &mut Value, status: Result<()>) -> Result<()> {
    publish_with_cancellation(path, report, status, &cancellation())
}
pub(super) fn publish_with_cancellation(
    path: &Path,
    report: &mut Value,
    status: Result<()>,
    cancellation: &diorama_dev::process::Cancellation,
) -> Result<()> {
    report["cancelled"] = cancellation.requested().into();
    let status = status.and_then(|()| {
        check(
            !cancellation.requested(),
            "capture cancelled before publication",
        )
    });
    if let Err(error) = &status
        && let Some(failure) = error.downcast_ref::<diorama_dev::process::CommandFailure>()
    {
        report["failed_command"] = failure.receipt.clone();
    }
    let publication = save(path, report);
    if let Err(error) = status {
        if let Err(problem) = publication {
            eprintln!(
                "asset fixture: cannot publish {}: {problem}",
                path.display()
            );
        }
        return Err(error);
    }
    publication
}
pub(super) fn b64(raw: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for part in raw.chunks(3) {
        let n = (u32::from(part[0]) << 16)
            | (u32::from(*part.get(1).unwrap_or(&0)) << 8)
            | u32::from(*part.get(2).unwrap_or(&0));
        for shift in [18, 12, 6, 0] {
            out.push(char::from(T[((n >> shift) & 63) as usize]));
        }
        if part.len() < 3 {
            out.pop();
            out.push('=');
        }
        if part.len() < 2 {
            out.pop();
            out.pop();
            out.push_str("==");
        }
    }
    out
}
pub(super) fn unb64(text: &str) -> Result<Vec<u8>> {
    check(
        text.len().is_multiple_of(4) && text.len() <= 2 * 1024 * 1024,
        "base64 bound",
    )?;
    let mut out = Vec::new();
    for part in text.as_bytes().chunks(4) {
        let mut n = 0u32;
        let mut pad = 0;
        for byte in part {
            let value = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    pad += 1;
                    0
                },
                _ => return Err("base64 alphabet".into()),
            };
            n = (n << 6) | u32::from(value);
        }
        check(pad <= 2, "base64 padding")?;
        out.extend_from_slice(&n.to_be_bytes()[1..4 - pad]);
    }
    check(b64(&out) == text, "canonical base64")?;
    Ok(out)
}

pub(super) fn verify_command(path: &Path, argv: &Value, raw_hash: &str) -> Result<String> {
    let record = load(path)?;
    fields(
        &record,
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
        check(record[key] == true, "settled command observation")?;
    }
    for key in ["timeout", "cancelled", "output_limit"] {
        check(record[key] == false, "command failure flag")?;
    }
    check(
        record["cleanup_errors"] == json!([]) && record["exit_code"] == 0,
        "successful command cleanup",
    )?;
    check(
        record["owned_pid"]
            .as_u64()
            .is_some_and(|pid| pid > 0 && u32::try_from(pid).is_ok()),
        "owned PID",
    )?;
    let owner = Path::new(string(&record["owner_directory"])?);
    check(
        owner.is_absolute()
            && owner
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("diorama-process-")),
        "owned process metadata path",
    )?;
    check(
        &record["argv"] == argv
            && record["stdout_sha256"] == raw_hash
            && record["stderr_sha256"] == sha256(b""),
        "command raw identity",
    )?;
    digest(path)
}
