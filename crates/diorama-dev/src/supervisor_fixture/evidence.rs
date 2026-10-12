use super::{
    common::{
        DIRECTORIES, control, digest, fields, hex, inventory, load, read, require, retain, run,
        save, selected, text, uncertain, verify_command,
    },
    oracle,
};
use diorama_dev::{Result, process::Cancellation};
use serde_json::{Value, json};
use std::{ffi::OsString, fs, path::Path};
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
pub(super) fn binaries(family: &str) -> Result<Vec<&'static str>> {
    match family {
        "process" => Ok(vec!["process-tests", "fixture"]),
        "output" => Ok(vec!["output-tests", "fixture"]),
        "signals" => Ok(vec!["signals.test", "owned_signals.test", "fixture"]),
        _ => Err("unknown supervisor family".into()),
    }
}
fn runtime_command(family: &str, tag: &str, name: &str) -> Result<Value> {
    let script = match family {
        "process" => {
            "sha256sum /process-tests /fixture; /process-tests --ignored --exact disposable_process_cases --nocapture; status=$?; /fixture namespace; inventory=$?; test \"$status\" -eq 0 && test \"$inventory\" -eq 0"
        },
        "output" => {
            "sha256sum /output-tests /fixture; /output-tests --ignored --exact disposable_output_cases --nocapture; status=$?; /fixture namespace; inventory=$?; test \"$status\" -eq 0 && test \"$inventory\" -eq 0"
        },
        "signals" => {
            "sha256sum /signals.test /owned_signals.test /fixture; /signals.test --nocapture && /owned_signals.test --ignored --exact disposable_owned_signals --nocapture; status=$?; /fixture namespace; inventory=$?; test \"$status\" -eq 0 && test \"$inventory\" -eq 0"
        },
        _ => return Err("unknown supervisor family".into()),
    };
    Ok(json!([
        "docker",
        "run",
        "--name",
        format!("{tag}-{name}"),
        "--init",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        if family == "signals" {
            "--pids-limit=128"
        } else {
            "--pids-limit=96"
        },
        "--memory=512m",
        "--cpus=2",
        "--tmpfs",
        if family == "process" {
            "/tmp:rw,nosuid,nodev,size=64m"
        } else {
            "/tmp:rw,nosuid,nodev,size=16m"
        },
        "--env",
        format!(
            "DIORAMA_{}_DISPOSABLE=1",
            if family == "signals" {
                "SIGNAL".into()
            } else {
                family.to_uppercase()
            }
        ),
        "--ulimit",
        "fsize=1048576:1048576",
        tag,
        "/bin/sh",
        "-c",
        script
    ]))
}
fn argv(value: &Value) -> Result<Vec<OsString>> {
    value
        .as_array()
        .ok_or("argv array")?
        .iter()
        .map(|v| text(v).map(OsString::from))
        .collect()
}
fn build_command(family: &str, tag: &str, context: &str) -> Value {
    json!([
        "docker",
        "build",
        "--progress=plain",
        "--build-arg",
        format!("QUALIFICATION_NONCE={tag}"),
        "--platform=linux/arm64",
        "-t",
        tag,
        "-f",
        format!("{context}/tools/supervisor-{family}/Capture.Dockerfile"),
        context
    ])
}
pub(super) fn records(family: &str, raw: &[u8]) -> Result<(Value, Value)> {
    let raw = std::str::from_utf8(raw)?;
    oracle::namespace(raw)?;
    let names = binaries(family)?;
    let mut hashes = serde_json::Map::new();
    for name in &names {
        let ending = format!("  /{name}");
        let values = raw
            .lines()
            .filter_map(|s| s.strip_suffix(&ending))
            .collect::<Vec<_>>();
        require(
            values.len() == 1 && hex(values[0], 64),
            "runtime binary identity",
        )?;
        hashes.insert((*name).into(), values[0].into());
    }
    let result = regex::Regex::new(
        r"^test result: ok\. 1 passed; 0 failed; ([01]) ignored; 0 measured; ([012]) filtered out; finished in [0-9.]+s$",
    )?;
    let completions = raw
        .lines()
        .filter_map(|s| {
            result
                .captures(s)
                .map(|c| (c[1].to_owned(), c[2].to_owned()))
        })
        .collect::<Vec<_>>();
    require(
        completions
            == if family == "signals" {
                vec![("1".into(), "0".into()), ("0".into(), "0".into())]
            } else {
                vec![(
                    "0".into(),
                    if family == "process" {
                        "2".into()
                    } else {
                        "1".into()
                    },
                )]
            },
        "exact test completion",
    )?;
    for line in raw.lines() {
        require(
            !line.starts_with("test result:") || result.is_match(line),
            "failed test summary",
        )?;
        require(
            !line.starts_with("DIORAMA_")
                || match family {
                    "process" => {
                        line.starts_with("DIORAMA_PROCESS ") || line.starts_with("DIORAMA_NAMESPACE ")
                    },
                    "output" => {
                        line.starts_with("DIORAMA_OUTPUT ")
                            || line.starts_with("DIORAMA_OUTPUT_COMPLETE ")
                            || line.starts_with("DIORAMA_NAMESPACE ")
                    },
                    _ => {
                        line.starts_with("DIORAMA_QUALIFICATION ")
                            || line.starts_with("DIORAMA_OWNED_QUALIFICATION ")
                            || line.starts_with("DIORAMA_OWNED_SIGNAL ")
                            || line.starts_with("DIORAMA_NAMESPACE ")
                    },
                },
            "unknown record marker",
        )?;
    }
    let rows = match family {
        "process" => oracle::process(raw)?,
        "output" => oracle::output(raw)?,
        _ => oracle::signals(raw)?,
    };
    Ok((rows, hashes.into()))
}
fn builder(raw: &[u8], tag: &str, names: &[&str]) -> Result<Value> {
    let raw = std::str::from_utf8(raw)?;
    let mut open = false;
    let mut complete = false;
    let mut hashes = serde_json::Map::new();
    let prefix = regex::Regex::new(r"^#\d+ \d+(?:\.\d+)? (.*)$")?;
    for line in raw.lines() {
        let Some(captures) = prefix.captures(line) else {
            continue;
        };
        let line = &captures[1];
        let marker = line.split_once("DIORAMA_BUILD_");
        if let Some((_, suffix)) = marker {
            if suffix == format!("BEGIN {tag}") {
                require(!open && !complete, "duplicate build frame")?;
                open = true;
            } else if suffix == format!("END {tag}") {
                require(open && !complete, "build frame end")?;
                open = false;
                complete = true;
            } else {
                return Err("unexpected builder marker".into());
            }
            continue;
        }
        if open {
            let (_, tail) = line.split_once("  /out/").ok_or("builder frame row")?;
            let prefix = line.split_once("  /out/").ok_or("builder frame")?.0;
            let hash = prefix.split_whitespace().last().ok_or("builder digest")?;
            require(names.contains(&tail) && hex(hash, 64), "builder binary")?;
            require(
                hashes.insert(tail.into(), hash.into()).is_none(),
                "duplicate builder digest",
            )?;
        }
    }
    require(
        complete && !open && hashes.len() == names.len(),
        "complete builder frame",
    )?;
    Ok(hashes.into())
}
pub(super) fn verify(root: &Path, family: &str, directory: &Path, full: bool) -> Result<()> {
    exact_evidence_files(directory)?;
    let report = load(&directory.join("receipt.json"))?;
    fields(
        &report,
        &[
            "schema",
            "cancelled",
            "family",
            "revision",
            "dirty",
            "tag",
            "source_sha256",
            "source_inventory_sha256",
            "build_command",
            "build_log_sha256",
            "build_binary_sha256",
            "image_id",
            "containers",
            "runs",
            "command_sha256",
            "errors",
            "cleanup_errors",
            "remaining_containers",
            "remaining_images",
        ],
    )?;
    require(
        report["schema"] == 3
            && report["cancelled"] == false
            && report["family"] == family
            && report["dirty"] == false
            && hex(text(&report["revision"])?, 40),
        "clean Rust receipt",
    )?;
    let tag = text(&report["tag"])?;
    require(
        tag.strip_prefix(&format!("diorama-supervisor-{family}-"))
            .is_some_and(|s| hex(s, 32)),
        "owned tag",
    )?;
    for key in [
        "errors",
        "cleanup_errors",
        "remaining_containers",
        "remaining_images",
    ] {
        require(report[key] == json!([]), "clean capture")?;
    }
    require(
        text(&report["image_id"])?
            .strip_prefix("sha256:")
            .is_some_and(|s| hex(s, 64)),
        "image identity",
    )?;
    verify_sources(root, directory, &report, full)?;
    let arguments = report["build_command"].as_array().ok_or("build command")?;
    let context = text(arguments.last().ok_or("build context")?)?;
    require(
        context.starts_with("/tmp/diorama-supervisor-context-") && !context.contains(".."),
        "owned context",
    )?;
    require(
        report["build_command"] == build_command(family, tag, context),
        "exact build command",
    )?;
    let raw = read(&directory.join("build.log"), 16 * 1024 * 1024)?;
    require(
        report["build_log_sha256"] == diorama_dev::sha256(&raw),
        "build log binding",
    )?;
    let built = builder(&raw, tag, &binaries(family)?)?;
    require(
        report["build_binary_sha256"] == built,
        "build binary binding",
    )?;
    fields(&report["command_sha256"], &COMMAND_LABELS)?;
    verify_controls(directory, &report, tag)?;
    require(
        report["command_sha256"]["build"]
            == verify_command(directory, "build", &report["build_command"])?,
        "build process binding",
    )?;
    fields(&report["runs"], &["first", "repeat"])?;
    require(
        report["containers"] == json!([format!("{tag}-first"), format!("{tag}-repeat")]),
        "owned container inventory",
    )?;
    verify_runs(family, directory, &report, tag, &built)
}
const COMMAND_LABELS: [&str; 9] = [
    "build",
    "first",
    "repeat",
    "image-inspect",
    "cleanup-1",
    "cleanup-2",
    "cleanup-3",
    "cleanup-4",
    "cleanup-5",
];
fn control_commands(tag: &str) -> [(&'static str, Value); 6] {
    [
        (
            "image-inspect",
            json!(["docker", "image", "inspect", "--format", "{{.Id}}", tag]),
        ),
        (
            "cleanup-1",
            json!(["docker", "rm", "-f", format!("{tag}-first")]),
        ),
        (
            "cleanup-2",
            json!(["docker", "rm", "-f", format!("{tag}-repeat")]),
        ),
        ("cleanup-3", json!(["docker", "rmi", "-f", tag])),
        (
            "cleanup-4",
            json!([
                "docker",
                "ps",
                "-a",
                "--filter",
                format!("name={tag}"),
                "--format",
                "{{.Names}}"
            ]),
        ),
        (
            "cleanup-5",
            json!(["docker", "image", "ls", tag, "--format", "{{.ID}}"]),
        ),
    ]
}
fn verify_controls(directory: &Path, report: &Value, tag: &str) -> Result<()> {
    for (label, command) in control_commands(tag) {
        require(
            report["command_sha256"][label] == verify_command(directory, label, &command)?,
            "control command binding",
        )?;
        let raw = read(&directory.join(format!("{label}.log")), 65536)?;
        if label == "image-inspect" {
            require(
                raw == format!("{}\n", text(&report["image_id"])?).as_bytes(),
                "raw image identity",
            )?;
        } else if ["cleanup-4", "cleanup-5"].contains(&label) {
            require(raw.is_empty(), "raw empty owned inventory")?;
        }
    }
    Ok(())
}
fn exact_evidence_files(directory: &Path) -> Result<()> {
    let mut expected = ["receipt.json", "source-inventory.json"]
        .map(OsString::from)
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    for label in COMMAND_LABELS {
        expected.insert(format!("{label}.log").into());
        expected.insert(format!("{label}.command.json").into());
    }
    let actual = fs::read_dir(directory)?
        .map(|entry| {
            let entry = entry?;
            require(entry.file_type()?.is_file(), "regular evidence entry")?;
            Ok(entry.file_name())
        })
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    require(actual == expected, "exact evidence file inventory")
}
fn verify_runs(
    family: &str,
    directory: &Path,
    report: &Value,
    tag: &str,
    built: &Value,
) -> Result<()> {
    let mut normalized = Vec::new();
    for name in ["first", "repeat"] {
        let row = &report["runs"][name];
        fields(row, &["command", "raw_sha256", "binary_sha256", "records"])?;
        require(
            row["command"] == runtime_command(family, tag, name)?,
            "contained runtime command",
        )?;
        let raw = read(&directory.join(format!("{name}.log")), 1024 * 1024)?;
        require(
            row["raw_sha256"] == diorama_dev::sha256(&raw),
            "runtime log binding",
        )?;
        let (records, binaries) = records(family, &raw)?;
        require(
            row["records"] == records && row["binary_sha256"] == binaries && &binaries == built,
            "raw/builder/runtime consistency",
        )?;
        require(
            report["command_sha256"][name] == verify_command(directory, name, &row["command"])?,
            "runtime process binding",
        )?;
        normalized.push(oracle::normalize(&records));
    }
    require(normalized[0] == normalized[1], "repeated semantics")
}
fn verify_sources(root: &Path, directory: &Path, report: &Value, full: bool) -> Result<()> {
    let historical = load(&directory.join("source-inventory.json"))?;
    let entries = historical.as_object().ok_or("historical source map")?;
    require(!entries.is_empty(), "historical source inventory")?;
    for (name, hash) in entries {
        require(
            !name.starts_with('/')
                && !name
                    .split('/')
                    .any(|s| s.is_empty() || s == "." || s == "..")
                && hex(text(hash)?, 64),
            "historical path/hash",
        )?;
        require(
            ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"].contains(&name.as_str())
                || DIRECTORIES
                    .iter()
                    .any(|d| name.starts_with(&format!("{d}/"))),
            "historical scope",
        )?;
    }
    require(
        report["source_sha256"] == historical
            && report["source_inventory_sha256"]
                == digest(&directory.join("source-inventory.json"))?,
        "historical inventory binding",
    )?;
    let current = inventory(root)?;
    require(
        selected(&historical)? == selected(&current)?,
        "current relevant source inventory",
    )?;
    if full {
        require(historical == current, "complete current source inventory")?;
    }
    Ok(())
}
pub(super) fn capture(
    root: &Path,
    family: &str,
    directory: &Path,
    cancellation: &Cancellation,
) -> Result<()> {
    binaries(family)?;
    let sources = inventory(root)?;
    let mut status = vec![
        OsString::from("git"),
        "-C".into(),
        root.as_os_str().into(),
        "status".into(),
        "--porcelain".into(),
        "--untracked-files=all".into(),
        "--".into(),
    ];
    status.extend(
        selected(&sources)?
            .as_object()
            .ok_or("source map")?
            .keys()
            .map(OsString::from),
    );
    require(
        control(&status, cancellation.clone())?.is_empty(),
        "clean committed relevant source required",
    )?;
    let revision = control(
        &[
            "git".into(),
            "-C".into(),
            root.as_os_str().into(),
            "rev-parse".into(),
            "HEAD".into(),
        ],
        cancellation.clone(),
    )?;
    let mut random = [0u8; 16];
    std::io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut random)?;
    let tag = format!(
        "diorama-supervisor-{family}-{}",
        &diorama_dev::sha256(&random)[..32]
    );
    fs::create_dir(directory)?;
    save(&directory.join("source-inventory.json"), &sources)?;
    let mut report = json!({"schema":3,"family":family,"revision":revision,"dirty":false,"tag":tag,"source_sha256":sources,"source_inventory_sha256":digest(&directory.join("source-inventory.json"))?,"build_command":[],"build_log_sha256":null,"build_binary_sha256":null,"image_id":null,"containers":[],"runs":{},"command_sha256":{},"errors":[],"cleanup_errors":[],"remaining_containers":null,"remaining_images":null});
    let result = execute(root, family, directory, &mut report, cancellation.clone());
    if let Err(error) = &result {
        report["errors"] = json!([error.to_string()]);
    }
    let result = if result.as_ref().is_err_and(uncertain) {
        report["cleanup_errors"] = json!(["unsettled command; no further cleanup attempted"]);
        result
    } else {
        let mut index = 0;
        let cleanup = cleanup(&mut report, &tag, |args| {
            index += 1;
            Ok(String::from_utf8(run(
                directory,
                &format!("cleanup-{index}"),
                args,
                30,
                65536,
                Cancellation::default(),
            )?)?
            .trim()
            .into())
        });
        for (label, command) in control_commands(&tag) {
            if let Ok(hash) = verify_command(directory, label, &command) {
                report["command_sha256"][label] = hash.into();
            }
        }
        if cleanup.is_err() { cleanup } else { result }
    };
    report["cancelled"] = cancellation.requested().into();
    let result = result.and_then(|()| {
        require(
            !cancellation.requested(),
            "capture cancelled before publication",
        )
    });
    if let Err(error) = &result
        && let Some(failure) = error.downcast_ref::<diorama_dev::process::CommandFailure>()
    {
        report["failed_command"] = failure.receipt.clone();
    }
    let publication = save(&directory.join("receipt.json"), &report);
    if let Err(error) = result {
        if let Err(problem) = publication {
            eprintln!("receipt publication failed: {problem}");
        }
        return Err(error);
    }
    publication?;
    verify(root, family, directory, true)
}
fn execute(
    root: &Path,
    family: &str,
    directory: &Path,
    report: &mut Value,
    cancellation: Cancellation,
) -> Result<()> {
    let context = tempfile::Builder::new()
        .prefix("diorama-supervisor-context-")
        .tempdir_in("/tmp")?;
    let result = (|| {
        let sources = report["source_sha256"].as_object().ok_or("source map")?;
        for name in sources.keys() {
            let destination = context.path().join(name);
            fs::create_dir_all(destination.parent().ok_or("destination parent")?)?;
            fs::copy(root.join(name), destination)?;
        }
        require(
            inventory(context.path())? == report["source_sha256"],
            "copied source identity",
        )?;
        let tag = text(&report["tag"])?.to_owned();
        report["build_command"] =
            build_command(family, &tag, context.path().to_str().ok_or("context UTF8")?);
        let raw = run(
            directory,
            "build",
            &argv(&report["build_command"])?,
            1800,
            16 * 1024 * 1024,
            cancellation.clone(),
        )?;
        report["build_log_sha256"] = diorama_dev::sha256(&raw).into();
        report["build_binary_sha256"] = builder(&raw, &tag, &binaries(family)?)?;
        report["command_sha256"]["build"] =
            verify_command(directory, "build", &report["build_command"])?.into();
        let inspect = control_commands(&tag)[0].1.clone();
        let raw = run(
            directory,
            "image-inspect",
            &argv(&inspect)?,
            30,
            65536,
            cancellation.clone(),
        )?;
        report["image_id"] = String::from_utf8(raw)?.trim().into();
        report["command_sha256"]["image-inspect"] =
            verify_command(directory, "image-inspect", &inspect)?.into();
        for name in ["first", "repeat"] {
            report["containers"]
                .as_array_mut()
                .ok_or("container list")?
                .push(format!("{tag}-{name}").into());
            let command = runtime_command(family, &tag, name)?;
            let raw = run(
                directory,
                name,
                &argv(&command)?,
                if family == "signals" { 180 } else { 100 },
                1024 * 1024,
                cancellation.clone(),
            )?;
            let (records, binaries) = records(family, &raw)?;
            report["command_sha256"][name] = verify_command(directory, name, &command)?.into();
            report["runs"][name] = json!({"command":command,"raw_sha256":diorama_dev::sha256(&raw),"binary_sha256":binaries,"records":records});
        }
        require(
            inventory(root)? == report["source_sha256"],
            "source changed during capture",
        )?;
        require(
            control(
                &[
                    "git".into(),
                    "-C".into(),
                    root.as_os_str().into(),
                    "rev-parse".into(),
                    "HEAD".into(),
                ],
                cancellation,
            )? == report["revision"],
            "HEAD changed during capture",
        )?;
        Ok(())
    })();
    retain(context, result)
}
pub(super) fn cleanup(
    report: &mut Value,
    tag: &str,
    mut control: impl FnMut(&[OsString]) -> Result<String>,
) -> Result<()> {
    for args in [
        vec![
            "docker".into(),
            "rm".into(),
            "-f".into(),
            format!("{tag}-first").into(),
        ],
        vec![
            "docker".into(),
            "rm".into(),
            "-f".into(),
            format!("{tag}-repeat").into(),
        ],
        vec!["docker".into(), "rmi".into(), "-f".into(), tag.into()],
    ] {
        if let Err(error) = control(&args) {
            report["cleanup_errors"]
                .as_array_mut()
                .ok_or("cleanup array")?
                .push(error.to_string().into());
            if uncertain(&error) {
                return Err(error);
            }
        }
    }
    for (field, args) in [
        (
            "remaining_containers",
            vec![
                "docker".into(),
                "ps".into(),
                "-a".into(),
                "--filter".into(),
                format!("name={tag}").into(),
                "--format".into(),
                "{{.Names}}".into(),
            ],
        ),
        (
            "remaining_images",
            vec![
                "docker".into(),
                "image".into(),
                "ls".into(),
                tag.into(),
                "--format".into(),
                "{{.ID}}".into(),
            ],
        ),
    ] {
        match control(&args) {
            Ok(value) => report[field] = json!(value.lines().collect::<Vec<_>>()),
            Err(error) => {
                report["cleanup_errors"]
                    .as_array_mut()
                    .ok_or("cleanup array")?
                    .push(error.to_string().into());
                if uncertain(&error) {
                    report["remaining_containers"] = Value::Null;
                    report["remaining_images"] = Value::Null;
                    return Err(error);
                }
            },
        }
    }
    Ok(())
}
