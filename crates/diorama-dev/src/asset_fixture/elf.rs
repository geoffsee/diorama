use super::common::{
    Result, bounded, check, digest, fields, hex, inventory, json, load, output, read, sha256,
    strict, string,
};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, path::Path, process::Command};
const CAP: u64 = 256 * 1024 * 1024;
fn number(data: &[u8], offset: usize, size: usize) -> Result<u64> {
    let raw = data
        .get(offset..offset.checked_add(size).ok_or("ELF offset")?)
        .ok_or("ELF field")?;
    let mut bytes = [0u8; 8];
    check(size <= 8, "ELF scalar")?;
    bytes[..size].copy_from_slice(raw);
    Ok(u64::from_le_bytes(bytes))
}
fn span(data: &[u8], offset: u64, length: u64) -> Result<&[u8]> {
    let end = offset.checked_add(length).ok_or("ELF range overflow")?;
    data.get(usize::try_from(offset)?..usize::try_from(end)?)
        .ok_or_else(|| "ELF range".into())
}
pub(super) fn inspect(data: &[u8]) -> Result<Value> {
    check(
        data.starts_with(b"\x7fELF\x02\x01\x01"),
        "ELF64 little endian",
    )?;
    check(
        number(data, 20, 4)? == 1 && number(data, 52, 2)? == 64 && number(data, 54, 2)? == 56,
        "ELF header",
    )?;
    let count = number(data, 56, 2)?;
    check(count <= 128, "program header cap")?;
    let phoff = number(data, 32, 8)?;
    let mut loads = Vec::new();
    let mut interpreter = None;
    let mut dynamic = None;
    for index in 0..count {
        let header = span(
            data,
            phoff.checked_add(index * 56).ok_or("phoff overflow")?,
            56,
        )?;
        let tag = number(header, 0, 4)?;
        let offset = number(header, 8, 8)?;
        let address = number(header, 16, 8)?;
        let length = number(header, 32, 8)?;
        let bytes = span(data, offset, length)?;
        if tag == 1 {
            loads.push((address, length, offset));
        }
        if tag == 3 {
            check(
                interpreter.is_none()
                    && bytes.last() == Some(&0)
                    && bytes[..bytes.len() - 1].is_ascii(),
                "interpreter",
            )?;
            interpreter = Some(std::str::from_utf8(&bytes[..bytes.len() - 1])?.to_owned());
        }
        if tag == 2 {
            check(dynamic.is_none(), "duplicate dynamic")?;
            dynamic = Some(bytes);
        }
    }
    let mut needed = Vec::new();
    if let Some(dynamic) = dynamic {
        check(
            dynamic.len() % 16 == 0 && dynamic.len() / 16 <= 4096,
            "dynamic bounds",
        )?;
        let mut tags = BTreeMap::new();
        let mut offsets = Vec::new();
        let mut ended = false;
        for pair in dynamic.chunks_exact(16) {
            let tag = number(pair, 0, 8)?;
            let value = number(pair, 8, 8)?;
            if tag == 0 {
                ended = true;
                break;
            }
            if tag == 1 {
                offsets.push(value);
            } else {
                tags.insert(tag, value);
            }
        }
        check(ended, "dynamic terminator")?;
        if !offsets.is_empty() {
            let start = *tags.get(&5).ok_or("string address")?;
            let size = *tags.get(&10).ok_or("string size")?;
            let mut candidates = Vec::new();
            for (address, length, offset) in loads {
                if start >= address
                    && start.checked_add(size).ok_or("string overflow")?
                        <= address.checked_add(length).ok_or("segment overflow")?
                {
                    candidates.push(span(
                        data,
                        offset.checked_add(start - address).ok_or("string offset")?,
                        size,
                    )?);
                }
            }
            check(candidates.len() == 1, "unique dynamic string mapping")?;
            for offset in offsets {
                let tail = candidates[0]
                    .get(usize::try_from(offset)?..)
                    .ok_or("needed offset")?;
                let end = tail
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or("needed terminator")?;
                check(tail[..end].is_ascii(), "needed ASCII")?;
                needed.push(std::str::from_utf8(&tail[..end])?.to_owned());
            }
        }
    }
    Ok(
        json!({"bytes":data.len(),"machine":number(data,18,2)?,"elf_type":number(data,16,2)?,"entry":number(data,24,8)?,"flags":number(data,48,4)?,"interpreter":interpreter,"needed":needed}),
    )
}
pub(super) fn records(raw: &[u8], artifacts: &Value) -> Result<Value> {
    let text = std::str::from_utf8(raw)?;
    super::native::summary(text, 1)?;
    check(
        text.lines()
            .filter(|line| line.starts_with("test ") && !line.starts_with("test result:"))
            .collect::<Vec<_>>()
            == ["test four_locked_release_executables ... ok"],
        "exact ELF test inventory",
    )?;
    check(
        text.lines()
            .filter(|line| line.starts_with("DIORAMA_"))
            .all(|line| line.starts_with("DIORAMA_ELF ")),
        "unknown ELF record",
    )?;
    let mut out = BTreeMap::new();
    for line in text.lines().filter_map(|l| l.strip_prefix("DIORAMA_ELF ")) {
        let row = strict(line.as_bytes())?;
        fields(
            &row,
            &[
                "role",
                "architecture",
                "bytes",
                "machine",
                "elf_type",
                "entry",
                "flags",
                "interpreter",
                "needed",
                "loader",
                "loader_relation",
                "sha256",
            ],
        )?;
        let name = format!(
            "{}-{}",
            string(&row["role"])?,
            string(&row["architecture"])?
        );
        let artifact = artifacts.get(&name).ok_or("unknown ELF artifact")?;
        for key in ["bytes", "machine", "elf_type", "entry", "flags"] {
            check(row[key].as_u64().is_some(), "ELF unsigned numeric field")?;
        }
        check(
            row["interpreter"].is_null() || row["interpreter"].is_string(),
            "ELF interpreter type",
        )?;
        check(
            row["needed"]
                .as_array()
                .is_some_and(|names| names.iter().all(Value::is_string)),
            "ELF dependency types",
        )?;

        check(row["sha256"] == artifact["sha256"], "ELF byte identity")?;
        for (key, value) in artifact["oracle"].as_object().ok_or("oracle")? {
            check(&row[key] == value, "independent ELF field")?;
        }
        check(
            row["machine"]
                == if row["architecture"] == "arm64" {
                    json!(183)
                } else {
                    json!(62)
                },
            "target machine",
        )?;
        let loader = match row["interpreter"].as_str() {
            Some("/lib64/ld-linux-x86-64.so.2" | "/lib/ld-linux-aarch64.so.1") => "Glibc",
            Some("/lib/ld-musl-x86_64.so.1" | "/lib/ld-musl-aarch64.so.1") => "Musl",
            _ => "Unknown",
        };
        check(
            row["loader"] == loader
                && row["loader_relation"]
                    == if loader == "Musl" {
                        "KnownMismatch"
                    } else {
                        "Unresolved"
                    },
            "loader limited claim",
        )?;
        check(out.insert(name, row).is_none(), "duplicate ELF result")?;
    }
    check(out.len() == 4, "four ELF artifacts")?;
    Ok(json!(out.values().collect::<Vec<_>>()))
}
pub(super) fn verify(root: &Path, directory: &Path) -> Result<()> {
    let report = load(&directory.join("receipt.json"))?;
    fields(
        &report,
        &[
            "schema",
            "cancelled",
            "revision",
            "source_sha256",
            "artifacts",
            "errors",
            "qualification",
            "logs",
            "command_sha256",
        ],
    )?;
    check(
        report["schema"] == 3
            && report["cancelled"] == false
            && hex(string(&report["revision"])?, 40)
            && report["errors"] == json!([]),
        "Rust ELF receipt",
    )?;
    check(
        report["qualification"] == "read-only ELF inspection; no artifact execution",
        "ELF scope",
    )?;
    let inputs = load(&root.join("experiments/component-boundary/inputs.json"))?;
    let mut expected = Map::new();
    for (arch, roles) in inputs["artifacts"].as_object().ok_or("artifact pins")? {
        for (role, record) in roles.as_object().ok_or("roles")? {
            expected.insert(format!("{role}-{arch}"), record.clone());
        }
    }
    let artifacts = report["artifacts"].as_object().ok_or("artifacts")?;
    check(artifacts.len() == expected.len(), "artifact inventory")?;
    for (name, row) in artifacts {
        fields(row, &["sha256", "url", "oracle"])?;
        let pin = expected.get(name).ok_or("artifact pin")?;
        check(
            row["sha256"] == pin["sha256"] && row["url"] == pin["url"],
            "release pin",
        )?;
        fields(
            &row["oracle"],
            &[
                "bytes",
                "machine",
                "elf_type",
                "entry",
                "flags",
                "interpreter",
                "needed",
            ],
        )?;
        check(
            row["oracle"]["bytes"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= CAP),
            "ELF byte bound",
        )?;
    }
    fields(&report["logs"], &["run0.log", "run1.log"])?;
    fields(&report["command_sha256"], &["run0", "run1"])?;
    let mut observations = Vec::new();
    for name in ["run0.log", "run1.log"] {
        let raw = read(&directory.join(name), 8 * 1024 * 1024)?;
        check(report["logs"][name] == sha256(&raw), "ELF log binding")?;
        observations.push(records(&raw, &report["artifacts"])?);
        let label = name.strip_suffix(".log").ok_or("log suffix")?;
        check(
            report["command_sha256"][label]
                == super::common::verify_command(
                    &directory.join(format!("{label}.command.json")),
                    &json!(ELF_COMMAND),
                    &sha256(&raw),
                )?,
            "ELF command receipt binding",
        )?;
    }
    check(
        observations[0] == observations[1],
        "repeated ELF observations",
    )
}
pub(super) fn cached(path: &Path, expected: &Value) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            check(metadata.is_file(), "cache entry must be a regular file")?;
            let bytes = read(path, CAP)?;
            check(sha256(&bytes) == *expected, "cached artifact SHA")?;
            Ok(Some(bytes))
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
fn download(cache: &Path, path: &Path, pin: &Value) -> Result<()> {
    let temporary = tempfile::tempdir_in(cache)?;
    let result = (|| {
        let downloaded = temporary.path().join("artifact");
        bounded(
            Command::new("curl")
                .args([
                    "--fail",
                    "--location",
                    "--proto",
                    "=https",
                    "--proto-redir",
                    "=https",
                    "--connect-timeout",
                    "30",
                    "--max-time",
                    "300",
                    "--max-filesize",
                    "268435456",
                    "--output",
                ])
                .arg(&downloaded)
                .arg(string(&pin["url"])?),
            &temporary.path().join("download.log"),
            310,
            65536,
        )?;
        check(digest(&downloaded)? == pin["sha256"], "download SHA")?;
        std::fs::hard_link(downloaded, path)?;
        Ok(())
    })();
    super::common::retain(temporary, result)
}
pub(super) fn capture(root: &Path, directory: &Path, cache: &Path) -> Result<()> {
    let source = inventory(root, "elf")?;
    let revision = super::common::clean_revision(root, &source)?;
    check(
        !cache
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink()),
        "cache symlink",
    )?;
    std::fs::create_dir_all(cache)?;
    std::fs::create_dir(directory)?;
    let mut report = json!({"schema":3,"revision":revision,"source_sha256":source,"artifacts":{},"errors":[],"qualification":"read-only ELF inspection; no artifact execution","logs":{},"command_sha256":{}});
    let result = (|| -> Result<()> {
        let inputs = load(&root.join("experiments/component-boundary/inputs.json"))?;
        for (arch, roles) in inputs["artifacts"].as_object().ok_or("pins")? {
            for (role, pin) in roles.as_object().ok_or("roles")? {
                let name = format!("{role}-{arch}");
                let path = cache.join(&name);
                let prior = cached(&path, &pin["sha256"])?;
                if prior.is_none() {
                    download(cache, &path, pin)?;
                }
                let raw = match prior {
                    Some(bytes) => bytes,
                    None => read(&path, CAP)?,
                };
                check(sha256(&raw) == pin["sha256"], "artifact SHA")?;
                report["artifacts"][&name] =
                    json!({"sha256":pin["sha256"],"url":pin["url"],"oracle":inspect(&raw)?});
            }
        }
        run_twice(root, directory, cache)?;
        check(
            source == inventory(root, "elf")?,
            "source changed during capture",
        )?;
        check(
            output(
                Command::new("git")
                    .current_dir(root)
                    .args(["rev-parse", "HEAD"]),
            )? == revision,
            "HEAD changed during capture",
        )?;
        for (name, record) in report["artifacts"].as_object().ok_or("artifacts")? {
            check(
                digest(&cache.join(name))? == record["sha256"],
                "artifact changed",
            )?;
        }
        Ok(())
    })();
    if let Err(error) = &result {
        report["errors"] = json!([error.to_string()]);
    }
    if result.as_ref().is_err_and(super::common::uncertain) {
        return super::common::publish_result(&directory.join("receipt.json"), &mut report, result);
    }
    for name in ["run0.log", "run1.log"] {
        if directory.join(name).exists() {
            report["logs"][name] = digest(&directory.join(name))?.into();
            let label = name.strip_suffix(".log").ok_or("log suffix")?;
            let receipt = directory.join(format!("{label}.command.json"));
            if receipt.exists() {
                report["command_sha256"][label] = digest(&receipt)?.into();
            }
        }
    }
    super::common::publish_result(&directory.join("receipt.json"), &mut report, result)?;
    verify(root, directory)
}

const ELF_COMMAND: [&str; 12] = [
    "cargo",
    "test",
    "-p",
    "diorama-assets",
    "--release",
    "--locked",
    "--offline",
    "--test",
    "elf_real",
    "--",
    "--ignored",
    "--nocapture",
];
fn run_twice(root: &Path, directory: &Path, cache: &Path) -> Result<()> {
    for index in 0..2 {
        let path = directory.join(format!("run{index}.log"));
        bounded(
            Command::new("cargo")
                .current_dir(root)
                .env("DIORAMA_ELF_FIXTURES", cache.canonicalize()?)
                .args(&ELF_COMMAND[1..]),
            &path,
            900,
            8 * 1024 * 1024,
        )?;
    }
    Ok(())
}
