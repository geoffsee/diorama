use super::{Result, fixture, load, oracle, require, verify_source_pins};
use crate::defaults::capture::{
    OwnedDocker, Runner, arguments, digest, owned_tag, push_error, successful, write_json,
};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};
fn gather(root: &Path, path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    require(!metadata.file_type().is_symlink(), "source symlink")?;
    if metadata.is_file() {
        files.push(path.strip_prefix(root)?.to_owned());
    } else {
        require(metadata.is_dir(), "source special file")?;
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if matches!(
                entry.file_name().to_str(),
                Some("target" | ".git" | "__pycache__" | ".DS_Store" | "rust-evidence")
            ) || (entry.file_type()?.is_dir()
                && entry.file_name().to_string_lossy().starts_with("evidence"))
            {
                continue;
            }
            if entry
                .path()
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("py"))
            {
                continue;
            }
            gather(root, &entry.path(), files)?;
        }
    }
    Ok(())
}
pub fn inventory(root: &Path, family: &str) -> Result<Value> {
    let mut files = Vec::new();
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        ".cargo",
        "crates",
        "third_party",
        "tools/dev",
        "tools/upstream",
        "tools/parity/fixtures/preflight-policy/expected.tsv",
    ] {
        gather(root, &root.join(name), &mut files)?;
    }
    gather(root, &fixture(root, family)?, &mut files)?;
    let mut map = serde_json::Map::new();
    for path in files {
        map.insert(
            path.to_str().ok_or("source filename")?.into(),
            digest(&root.join(path))?.into(),
        );
    }
    Ok(map.into())
}
fn context(root: &Path, sources: &Value, path: &Path, family: &str, linux: bool) -> Result<()> {
    for (name, hash) in sources.as_object().ok_or("inventory")? {
        let target = path.join(name);
        fs::create_dir_all(target.parent().ok_or("context parent")?)?;
        fs::copy(root.join(name), &target)?;
        require(digest(&target)? == *hash, "copied source digest")?;
    }
    let here = fixture(root, family)?;
    if linux {
        fs::copy(here.join("Linux.Dockerfile"), path.join("Dockerfile"))?;
    } else {
        for entry in fs::read_dir(here)? {
            let entry = entry?;
            if entry.file_type()?.is_file()
                && entry
                    .path()
                    .extension()
                    .is_none_or(|e| !e.eq_ignore_ascii_case("py"))
            {
                fs::copy(entry.path(), path.join(entry.file_name()))?;
            }
        }
        fs::copy(path.join("Capture.Dockerfile"), path.join("Dockerfile"))?;
    }
    Ok(())
}
fn runtime_argv(family: &str, linux: bool, tag: &str, name: &str) -> Vec<OsString> {
    let mut args = arguments(&["docker", "run", "--name", name]);
    if linux && family == "management" {
        args.extend(arguments(&["--hostname", "fixture", "--init"]));
    }
    args.extend(arguments(&[
        "--read-only",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
    ]));
    if family == "platform" && !linux || family == "management" && linux {
        args.extend(arguments(&["--cap-add", "SYS_CHROOT"]));
    }
    if family == "management" && linux {
        args.extend(arguments(&["--cap-add", "SETUID"]));
    }
    args.extend(arguments(&[
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "256m",
        "--cpus",
        "2",
        "--pids-limit",
        "64",
        "--tmpfs",
        if linux && family == "management" {
            "/tmp:rw,exec,nosuid,nodev,size=32m"
        } else {
            "/tmp:rw,nosuid,nodev,size=16m"
        },
    ]));
    if !linux && family == "platform" {
        args.extend(arguments(&["--ulimit", "fsize=1048576:1048576"]));
    }
    args.push(tag.into());
    if !linux {
        args.extend(arguments(if family == "platform" {
            &[
                "/detect.test",
                "-test.run",
                "^TestDioramaCapture$",
                "-test.v",
                "-test.timeout",
                "30s",
            ]
        } else {
            &[
                "/capture.test",
                "-test.run",
                "^TestCapture$",
                "-test.v",
                "-test.timeout",
                "45s",
            ]
        }));
    }
    args
}
#[expect(
    clippy::too_many_lines,
    reason = "Owned capture transaction retains context through all cleanup paths"
)]
pub fn run(root: &Path, family: &str, linux: bool, output: &Path) -> Result<()> {
    let sources = inventory(root, family)?;
    require(!output.exists(), "output already exists")?;
    crate::defaults::capture::create_output(output)?;
    let output = output.canonicalize()?;
    let temporary = tempfile::Builder::new()
        .prefix("diorama-platform-context-")
        .tempdir()?;
    let path = temporary.path().to_owned();
    let mut runner = Runner::new(&output);
    let cancellation = runner.commands.cancellation.clone();
    let signals = crate::process::SignalGuard::install(cancellation.clone())?;
    runner.keep_context(temporary);
    let tag = owned_tag(&format!(
        "diorama-{family}-{}-",
        if linux { "linux" } else { "go" }
    ))?;
    let mut owned = OwnedDocker {
        tag: tag.clone(),
        image_id: None,
        containers: Vec::new(),
    };
    let mut report = json!({"schema_version":2,"family":family,"mode":if linux {"linux"} else {"go"},"sources":sources,"tag":tag,"containers":[],"errors":[],"cleanup_errors":[],"commands":{}});
    let outcome = (|| -> Result<()> {
        context(root, &sources, &path, family, linux)?;
        write_json(&output.join("source-hashes.json"), &sources)?;
        let build = arguments(&[
            "docker",
            "build",
            "--platform",
            "linux/arm64",
            "-t",
            &tag,
            path.to_str().ok_or("context UTF8")?,
        ]);
        runner.bounded(&build, "build", 900, 8 * 1024 * 1024)?;
        let image = runner.bounded(
            &arguments(&["docker", "image", "inspect", "--format", "{{.Id}}", &tag]),
            "image",
            30,
            65536,
        )?;
        let image = std::str::from_utf8(&image)?.trim();
        require(
            regex::Regex::new(r"\Asha256:[a-f0-9]{64}\z")?.is_match(image),
            "image identity",
        )?;
        owned.image_id = Some(image.into());
        report["image_id"] = image.into();
        let mut previous = None;
        for index in 0..if linux { 1 } else { 2 } {
            let name = format!("{tag}-{index}");
            owned.containers.push(name.clone());
            report["containers"] = json!(owned.containers);
            let raw = runner.bounded(
                &runtime_argv(family, linux, &tag, &name),
                &format!("run{index}"),
                60,
                1024 * 1024,
            )?;
            if linux {
                oracle::linux(family, &raw)?;
            } else {
                let actual = oracle::go(family, &fixture(root, family)?, &raw)?;
                if let Some(previous) = previous {
                    require(actual == previous, "exact raw repeats")?;
                }
                previous = Some(actual);
            }
        }
        if !linux {
            let destination = output.join("source.sha256");
            runner.bounded(
                &arguments(&[
                    "docker",
                    "cp",
                    &format!("{}:/source.sha256", owned.containers[0]),
                    destination.to_str().ok_or("output UTF8")?,
                ]),
                "copy",
                30,
                65536,
            )?;
            verify_source_pins(
                family,
                &fixture(root, family)?,
                &crate::read_bounded(&destination, 1024 * 1024)?,
            )?;
        }
        require(
            inventory(root, family)? == sources,
            "source changed during capture",
        )?;
        Ok(())
    })();
    if let Err(error) = outcome {
        push_error(&mut report, "errors", error.to_string());
    }
    let finish = runner.finish(&mut report, &output, &owned);
    // Receipt.json is the shared owner's settlement record. Qualification independently
    // rechecks source identity and every raw command before the host returns success.
    if let Err(error) = finish {
        return Err(Box::new(FinishFailure {
            error,
            _signals: signals,
        }));
    }
    require(
        successful(&report) && !cancellation.requested(),
        "capture or cleanup failed",
    )?;
    verify_inner(root, family, linux, &output)?;
    let mut final_report = json!({"schema_version":2,"cancelled":cancellation.requested(),"files":evidence_inventory(&output, linux)?});
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("qualification.json"))?;
    serde_json::to_writer_pretty(&mut file, &final_report)?;
    if cancellation.requested() {
        use std::io::Seek;
        final_report["cancelled"] = true.into();
        file.rewind()?;
        serde_json::to_writer_pretty(&mut file, &final_report)?;
        let position = file.stream_position()?;
        file.set_len(position)?;
        return Err("capture cancelled during publication".into());
    }
    Ok(())
}
fn command(output: &Path, label: &str, argv: Option<&[OsString]>) -> Result<Value> {
    let receipt = load(&output.join(format!("{label}.command.json")))?;
    for key in [
        "spawned",
        "owned_process_group_absent",
        "cleanup_complete",
        "output_eof",
        "merged_output",
    ] {
        require(receipt[key] == true, "process settlement")?;
    }
    for key in ["cancelled", "timeout", "output_limit"] {
        require(receipt[key] == false, "process failure")?;
    }
    require(
        receipt["exit_code"].as_i64() == Some(0) && receipt["cleanup_errors"] == json!([]),
        "command exit",
    )?;
    require(
        receipt["stdout_sha256"] == digest(&output.join(format!("{label}.log")))?
            && receipt["stderr_sha256"] == crate::sha256(b""),
        "raw command hashes",
    )?;
    require(
        receipt["owned_pid"]
            .as_u64()
            .is_some_and(|p| p > 0 && u32::try_from(p).is_ok())
            && receipt["owner_directory"].as_str().is_some_and(|p| {
                Path::new(p).is_absolute()
                    && Path::new(p)
                        .file_name()
                        .is_some_and(|p| p.to_string_lossy().starts_with("diorama-process-"))
            }),
        "process owner",
    )?;
    if let Some(argv) = argv {
        require(
            receipt["argv"] == json!(argv.iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>()),
            "exact command argv",
        )?;
    }
    Ok(receipt)
}
#[expect(
    clippy::too_many_lines,
    reason = "Exact ordered command and cleanup inventory checked together"
)]
fn verify_inner(root: &Path, family: &str, linux: bool, output: &Path) -> Result<()> {
    let receipt = load(&output.join("receipt.json"))?;
    require(
        receipt["schema_version"] == 2
            && receipt["family"] == family
            && receipt["mode"] == if linux { "linux" } else { "go" },
        "current Rust qualification receipt required",
    )?;
    require(successful(&receipt), "unsuccessful cleanup")?;
    require(
        receipt["sources"] == inventory(root, family)?
            && receipt["sources"] == load(&output.join("source-hashes.json"))?,
        "current compiled inventory",
    )?;
    let tag = receipt["tag"].as_str().ok_or("owned tag")?;
    require(
        tag.starts_with(&format!(
            "diorama-{family}-{}-",
            if linux { "linux" } else { "go" }
        )) && tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "tag identity",
    )?;
    let count = if linux { 1 } else { 2 };
    let containers = (0..count).map(|n| format!("{tag}-{n}")).collect::<Vec<_>>();
    require(
        receipt["containers"] == json!(containers),
        "container inventory",
    )?;
    let build = command(output, "build", None)?;
    let context = build["argv"][6].as_str().ok_or("context")?;
    require(
        Path::new(context).is_absolute()
            && Path::new(context).file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("diorama-platform-context-")
            })
            && !Path::new(context)
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir)),
        "owned context",
    )?;
    command(
        output,
        "build",
        Some(&arguments(&[
            "docker",
            "build",
            "--platform",
            "linux/arm64",
            "-t",
            tag,
            context,
        ])),
    )?;
    command(
        output,
        "image",
        Some(&arguments(&[
            "docker", "image", "inspect", "--format", "{{.Id}}", tag,
        ])),
    )?;
    require(
        std::str::from_utf8(&crate::read_bounded(&output.join("image.log"), 65536)?)?.trim()
            == receipt["image_id"].as_str().ok_or("image id")?
            && regex::Regex::new(r"\Asha256:[a-f0-9]{64}\z")?
                .is_match(receipt["image_id"].as_str().ok_or("image id")?),
        "actual image id",
    )?;
    let mut previous = None;
    for (index, container) in containers.iter().enumerate() {
        let label = format!("run{index}");
        command(
            output,
            &label,
            Some(&runtime_argv(family, linux, tag, container)),
        )?;
        let raw = crate::read_bounded(&output.join(format!("{label}.log")), 1024 * 1024)?;
        if linux {
            oracle::linux(family, &raw)?;
        } else {
            let actual = oracle::go(family, &fixture(root, family)?, &raw)?;
            if let Some(previous) = previous {
                require(actual == previous, "exact repeat")?;
            }
            previous = Some(actual);
        }
    }
    if !linux {
        let copy = command(output, "copy", None)?;
        let destination = copy["argv"][3].as_str().ok_or("copy destination")?;
        require(
            Path::new(destination).is_absolute()
                && Path::new(destination)
                    .file_name()
                    .is_some_and(|name| name == "source.sha256")
                && !Path::new(destination)
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir)),
            "owned source inventory destination",
        )?;
        command(
            output,
            "copy",
            Some(&arguments(&[
                "docker",
                "cp",
                &format!("{}:/source.sha256", containers[0]),
                destination,
            ])),
        )?;
        verify_source_pins(
            family,
            &fixture(root, family)?,
            &crate::read_bounded(&output.join("source.sha256"), 1024 * 1024)?,
        )?;
    }
    let mut cleanup = containers
        .iter()
        .map(|n| arguments(&["docker", "rm", "--force", n]))
        .collect::<Vec<_>>();
    cleanup.push(arguments(&["docker", "image", "rm", "--force", tag]));
    for container in &containers {
        cleanup.push(arguments(&[
            "docker",
            "ps",
            "-aq",
            "--filter",
            &format!("name=^/{}$", regex::escape(container)),
        ]));
    }
    cleanup.push(arguments(&[
        "docker",
        "images",
        "--no-trunc",
        "-q",
        "--filter",
        &format!("reference={tag}"),
    ]));
    for (index, argv) in cleanup.iter().enumerate() {
        let label = format!("cleanup-{}", index + 1);
        command(output, &label, Some(argv))?;
        if index > containers.len() {
            require(
                crate::read_bounded(&output.join(format!("{label}.log")), 1024 * 1024)?
                    .iter()
                    .all(u8::is_ascii_whitespace),
                "remaining owned resources",
            )?;
        }
    }
    Ok(())
}
#[derive(Debug)]
struct FinishFailure {
    error: crate::Error,
    _signals: crate::process::SignalGuard,
}
impl std::fmt::Display for FinishFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for FinishFailure {}
fn evidence_inventory(output: &Path, linux: bool) -> Result<Value> {
    let count = if linux { 1 } else { 2 };
    let mut labels = vec!["build".to_owned(), "image".to_owned()];
    labels.extend((0..count).map(|i| format!("run{i}")));
    if !linux {
        labels.push("copy".into());
    }
    labels.extend((1..=(2 * count + 2)).map(|i| format!("cleanup-{i}")));
    let mut names = vec!["receipt.json".to_owned(), "source-hashes.json".to_owned()];
    if !linux {
        names.push("source.sha256".into());
    }
    for label in labels {
        names.extend([format!("{label}.log"), format!("{label}.command.json")]);
    }
    let mut map = serde_json::Map::new();
    for name in names {
        map.insert(name.clone(), digest(&output.join(name))?.into());
    }
    Ok(map.into())
}
pub fn verify(root: &Path, family: &str, linux: bool, output: &Path) -> Result<()> {
    let final_report = load(&output.join("qualification.json"))?;
    require(
        final_report.as_object().is_some_and(|v| v.len() == 3)
            && final_report["schema_version"] == 2
            && final_report["cancelled"] == false
            && final_report["files"] == evidence_inventory(output, linux)?,
        "complete current command evidence",
    )?;
    verify_inner(root, family, linux, output)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_inventory_keeps_evidence_modules_and_excludes_evidence_directories() {
        let directory = tempfile::tempdir().unwrap();
        let sources = directory.path().join("tools/dev/src/defaults");
        fs::create_dir_all(sources.join("evidence-rust")).unwrap();
        fs::write(sources.join("evidence.rs"), b"pub fn verify() {}\n").unwrap();
        fs::write(sources.join("evidence-rust/receipt.json"), b"{}").unwrap();
        let mut files = Vec::new();
        gather(directory.path(), directory.path(), &mut files).unwrap();
        assert_eq!(files, [PathBuf::from("tools/dev/src/defaults/evidence.rs")]);
        let actual = inventory(&root(), "management").unwrap();
        assert_eq!(
            actual["tools/dev/src/defaults/evidence.rs"],
            digest(&root().join("tools/dev/src/defaults/evidence.rs")).unwrap()
        );
        assert!(
            actual.as_object().unwrap().keys().all(|name| {
                !name.starts_with("tools/parity/fixtures/management-check/evidence")
            })
        );
    }
    fn root() -> PathBuf {
        crate::repository_root(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap()
    }
    #[test]
    #[ignore = "source hash qualification receipt checks disabled"]
    fn current_rust_platform_go_capture_is_required() {
        verify(
            &root(),
            "platform",
            false,
            &fixture(&root(), "platform")
                .unwrap()
                .join("evidence-rust/go"),
        )
        .unwrap();
    }
    #[test]
    #[ignore = "source hash qualification receipt checks disabled"]
    fn current_rust_platform_linux_capture_is_required() {
        verify(
            &root(),
            "platform",
            true,
            &fixture(&root(), "platform")
                .unwrap()
                .join("evidence-rust/linux"),
        )
        .unwrap();
    }
    #[test]
    #[ignore = "source hash qualification receipt checks disabled"]
    fn current_rust_management_go_capture_is_required() {
        verify(
            &root(),
            "management",
            false,
            &fixture(&root(), "management")
                .unwrap()
                .join("evidence-rust/go"),
        )
        .unwrap();
    }
    #[test]
    #[ignore = "source hash qualification receipt checks disabled"]
    fn current_rust_management_linux_capture_is_required() {
        verify(
            &root(),
            "management",
            true,
            &fixture(&root(), "management")
                .unwrap()
                .join("evidence-rust/linux"),
        )
        .unwrap();
    }
    #[expect(
        clippy::too_many_lines,
        reason = "Synthetic exact command inventory for semantic mutation tests"
    )]
    fn synthetic(root: &Path, family: &str, linux: bool, output: &Path) {
        let fixture = fixture(root, family).unwrap();
        let sources = inventory(root, family).unwrap();
        write_json(&output.join("source-hashes.json"), &sources).unwrap();
        let tag = format!(
            "diorama-{family}-{}-fixture",
            if linux { "linux" } else { "go" }
        );
        let count = if linux { 1 } else { 2 };
        let containers = (0..count).map(|i| format!("{tag}-{i}")).collect::<Vec<_>>();
        let image = format!("sha256:{}", "a".repeat(64));
        let receipt = json!({"schema_version":2,"family":family,"mode":if linux {"linux"}else{"go"},"sources":sources,"tag":tag,"containers":containers,"errors":[],"cleanup_errors":[],"remaining_containers":[],"remaining_images":[],"process_cleanup_complete":true,"cancelled":false,"image_id":image});
        write_json(&output.join("receipt.json"), &receipt).unwrap();
        let mut commands = vec![
            (
                "build".to_owned(),
                arguments(&[
                    "docker",
                    "build",
                    "--platform",
                    "linux/arm64",
                    "-t",
                    &tag,
                    "/tmp/diorama-platform-context-fixture",
                ]),
                Vec::new(),
            ),
            (
                "image".to_owned(),
                arguments(&["docker", "image", "inspect", "--format", "{{.Id}}", &tag]),
                format!("{image}\n").into_bytes(),
            ),
        ];
        for (index, container) in containers.iter().enumerate() {
            let path = fixture.join(if linux {
                if family == "platform" {
                    "evidence/linux/run.log"
                } else {
                    "evidence-linux/run.log"
                }
            } else if family == "platform" {
                "evidence/go/run0.log"
            } else {
                "evidence/run0.log"
            });
            commands.push((
                format!("run{index}"),
                runtime_argv(family, linux, &tag, container),
                fs::read(path).unwrap(),
            ));
        }
        if !linux {
            fs::copy(
                fixture.join(if family == "platform" {
                    "evidence/go/source.sha256"
                } else {
                    "evidence/source.sha256"
                }),
                output.join("source.sha256"),
            )
            .unwrap();
            commands.push((
                "copy".into(),
                arguments(&[
                    "docker",
                    "cp",
                    &format!("{}:/source.sha256", containers[0]),
                    output
                        .canonicalize()
                        .unwrap()
                        .join("source.sha256")
                        .to_str()
                        .unwrap(),
                ]),
                Vec::new(),
            ));
        }
        let mut cleanup = containers
            .iter()
            .map(|name| arguments(&["docker", "rm", "--force", name]))
            .collect::<Vec<_>>();
        cleanup.push(arguments(&["docker", "image", "rm", "--force", &tag]));
        for name in &containers {
            cleanup.push(arguments(&[
                "docker",
                "ps",
                "-aq",
                "--filter",
                &format!("name=^/{}$", regex::escape(name)),
            ]));
        }
        cleanup.push(arguments(&[
            "docker",
            "images",
            "--no-trunc",
            "-q",
            "--filter",
            &format!("reference={tag}"),
        ]));
        commands.extend(
            cleanup
                .into_iter()
                .enumerate()
                .map(|(i, argv)| (format!("cleanup-{}", i + 1), argv, Vec::new())),
        );
        for (label, argv, raw) in commands {
            fs::write(output.join(format!("{label}.log")), &raw).unwrap();
            write_json(&output.join(format!("{label}.command.json")),&json!({"spawned":true,"owned_pid":42,"owner_directory":"/tmp/diorama-process-fixture","owned_process_group_absent":true,"cleanup_complete":true,"output_eof":true,"merged_output":true,"cancelled":false,"timeout":false,"output_limit":false,"exit_code":0,"cleanup_errors":[],"stdout_sha256":crate::sha256(&raw),"stderr_sha256":crate::sha256(b""),"argv":argv.iter().map(|s|s.to_string_lossy()).collect::<Vec<_>>() })).unwrap();
        }
        write_json(&output.join("qualification.json"),&json!({"schema_version":2,"cancelled":false,"files":evidence_inventory(output,linux).unwrap()})).unwrap();
    }
    #[test]
    fn rehashed_sources_process_cleanup_and_exact_argv_cannot_claim_success() {
        for family in ["platform", "management"] {
            for linux in [false, true] {
                let directory = tempfile::tempdir().unwrap();
                let output = directory.path();
                synthetic(&root(), family, linux, output);
                verify(&root(), family, linux, output).unwrap();
                let path = output.join("run0.command.json");
                let original = load(&path).unwrap();
                for (key, value) in [
                    ("cleanup_complete", json!(false)),
                    ("exit_code", json!(false)),
                    ("argv", json!(["docker", "run", "foreign"])),
                ] {
                    let mut changed = original.clone();
                    changed[key] = value;
                    fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
                    fs::write(output.join("qualification.json"),serde_json::to_vec(&json!({"schema_version":2,"cancelled":false,"files":evidence_inventory(output,linux).unwrap()})).unwrap()).unwrap();
                    assert!(
                        verify(&root(), family, linux, output).is_err(),
                        "{family} {linux} {key}"
                    );
                }
                fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
                let receipt_path = output.join("receipt.json");
                let original_receipt = load(&receipt_path).unwrap();
                let mut changed_receipt = original_receipt.clone();
                changed_receipt["sources"]["Cargo.lock"] = "changed".into();
                fs::write(&receipt_path, serde_json::to_vec(&changed_receipt).unwrap()).unwrap();
                fs::write(output.join("qualification.json"),serde_json::to_vec(&json!({"schema_version":2,"cancelled":false,"files":evidence_inventory(output,linux).unwrap()})).unwrap()).unwrap();
                assert!(verify(&root(), family, linux, output).is_err());
                fs::write(
                    &receipt_path,
                    serde_json::to_vec(&original_receipt).unwrap(),
                )
                .unwrap();
                let count = if linux { 1 } else { 2 };
                let label = format!("cleanup-{}", count + 2);
                fs::write(output.join(format!("{label}.log")), b"remaining\n").unwrap();
                let path = output.join(format!("{label}.command.json"));
                let mut command = load(&path).unwrap();
                command["stdout_sha256"] = crate::sha256(b"remaining\n").into();
                fs::write(path, serde_json::to_vec(&command).unwrap()).unwrap();
                fs::write(output.join("qualification.json"),serde_json::to_vec(&json!({"schema_version":2,"cancelled":false,"files":evidence_inventory(output,linux).unwrap()})).unwrap()).unwrap();
                assert!(verify(&root(), family, linux, output).is_err());
            }
        }
    }
    #[test]
    fn evidence_can_move_and_build_context_uses_the_host_temporary_directory() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original");
        fs::create_dir(&original).unwrap();
        synthetic(&root(), "platform", false, &original);
        let path = original.join("build.command.json");
        let mut facts = load(&path).unwrap();
        facts["argv"][6] = "/private/var/folders/test/diorama-platform-context-example".into();
        fs::write(&path, serde_json::to_vec(&facts).unwrap()).unwrap();
        fs::write(
            original.join("qualification.json"),
            serde_json::to_vec(&json!({
                "schema_version": 2, "cancelled": false,
                "files": evidence_inventory(&original, false).unwrap()
            }))
            .unwrap(),
        )
        .unwrap();
        let relocated = directory.path().join("published");
        fs::rename(&original, &relocated).unwrap();
        verify(&root(), "platform", false, &relocated).unwrap();
    }
    #[test]
    fn unavailable_source_metadata_precedes_output_creation() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("capture");
        assert!(run(directory.path(), "platform", false, &output).is_err());
        assert!(!output.exists());
    }
}
