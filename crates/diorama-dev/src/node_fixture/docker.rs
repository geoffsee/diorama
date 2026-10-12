use super::{
    assessment, build, commands,
    common::{
        Result, Value, digest, fields, hex, inventory, json, load, read, require, retain, save,
        sha256, text, uncertain,
    },
};
use crate::parity::process::Cancellation;
use std::{fs, path::Path};
pub(super) fn build_command(family: &str, tag: &str, nonce: &str, context: &str) -> Value {
    json!([
        "docker",
        "build",
        "--platform=linux/arm64",
        "--progress=plain",
        "--build-arg",
        format!("QUALIFICATION_NONCE={nonce}"),
        "-t",
        tag,
        "-f",
        if family == "probes" {
            format!("{context}/tools/parity/fixtures/preflight-probes/Capture.Dockerfile")
        } else {
            format!(
                "{context}/tools/node-{family}/{}.Dockerfile",
                if matches!(family, "assessment" | "probes") {
                    "Capture"
                } else {
                    "Build"
                }
            )
        },
        context
    ])
}
pub(super) fn run_command(family: &str, tag: &str, name: &str) -> Result<Value> {
    if family == "probes" {
        return Ok(json!([
            "docker",
            "run",
            "--name",
            format!("{tag}-{name}"),
            "--read-only",
            "--network=none",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory=256m",
            "--cpus=2",
            "--pids-limit=64",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=16m",
            "--env",
            "DIORAMA_PREFLIGHT_DISPOSABLE=1",
            tag,
            "/bin/sh",
            "-c",
            "cat /out/binaries.sha256; for binary in /out/diorama_platform-* /out/preflight_probe-*; do \"$binary\" --nocapture || exit; \"$binary\" --ignored --nocapture || exit; done"
        ]));
    }
    if matches!(family, "assessment" | "probes") {
        return Ok(json!([
            "docker",
            "run",
            "--name",
            format!("{tag}-{name}"),
            "--init",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=96",
            "--memory=512m",
            "--cpus=2",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=16m",
            "--tmpfs",
            "/usr/sbin:rw,exec,nosuid,nodev,size=1m,uid=65532,gid=65532,mode=0755",
            "--env",
            "DIORAMA_NODE_DISPOSABLE=1",
            "--env",
            "PRIVATE_SENTINEL=must-not-reach-probe",
            tag,
            "/bin/sh",
            "-c",
            "sha256sum /out/host_preflight /out/iptables_probe /out/assess_host /out/node-fixture; /out/host_preflight && /out/iptables_probe --ignored --exact disposable_fixed_probe --nocapture && /out/host_preflight --ignored --exact disposable_configured_assessment --nocapture && /node-fixture consumer; status=$?; /node-fixture namespace; inventory=$?; test \"$status\" -eq 0 && test \"$inventory\" -eq 0"
        ]));
    }
    let names = build::binaries(family)?;
    let paths = names
        .iter()
        .map(|n| format!("/out/{n}"))
        .collect::<Vec<_>>()
        .join(" ");
    let (consumer, flags, tests) = if family == "network" {
        (
            "prepare_host_network",
            "--disable-ipv6 --no-container-mode --container-runtime-endpoint=unix:///tmp/external-runtime/containerd.sock",
            "/out/host_network && ",
        )
    } else {
        (
            "prepare_node_host",
            "--container-mode --container-runtime-endpoint=unix:///tmp/external-runtime/containerd.sock",
            "for binary in diorama host_preparation host_network; do echo TEST_${binary}_BEGIN; /out/$binary || exit 1; echo TEST_${binary}_END; done && ",
        )
    };
    let script = format!(
        "sha256sum {paths} && {tests}for case in version help print-config; do echo CLI_${{case}}_BEGIN; if [ \"$case\" = print-config ]; then /out/{consumer} {flags} --print-config 2>&1 || exit 1; else /out/{consumer} --$case 2>&1 || exit 1; fi; echo CLI_${{case}}_END; done"
    );
    Ok(json!([
        "docker",
        "run",
        "--name",
        format!("{tag}-{name}"),
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=64",
        "--memory=512m",
        "--cpus=2",
        tag,
        "/bin/sh",
        "-c",
        script
    ]))
}
fn runs(family: &str) -> [&'static str; 2] {
    if matches!(family, "assessment" | "probes") {
        ["first", "repeat"]
    } else {
        ["artifact", "test"]
    }
}
fn observations(root: &Path, family: &str, raw: &[u8]) -> Result<(Value, Value)> {
    if family == "probes" {
        return diorama_dev::preflight_probes::records(raw);
    }
    let raw = std::str::from_utf8(raw)?;
    if matches!(family, "assessment" | "probes") {
        assessment::records(raw)
    } else {
        Ok((
            json!({"safe_tests_and_cli":true}),
            build::verify_run(root, family, raw)?,
        ))
    }
}
fn normalized(value: &Value) -> Value {
    match value {
        Value::Object(o) => o
            .iter()
            .filter(|(k, _)| *k != "elapsed_ms")
            .map(|(k, v)| (k.clone(), normalized(v)))
            .collect(),
        Value::Array(a) => a.iter().map(normalized).collect(),
        _ => value.clone(),
    }
}
pub(super) fn verify(root: &Path, family: &str, directory: &Path, binary: bool) -> Result<Value> {
    let report = load(&directory.join("receipt.json"))?;
    fields(&report, RECEIPT_FIELDS)?;
    require(
        report["schema"] == 3
            && report["family"] == family
            && report["dirty"] == false
            && report["cancelled"] == false
            && hex(text(&report["revision"])?, 40),
        "clean Rust source receipt",
    )?;
    let tag = text(&report["tag"])?;
    let nonce = text(&report["nonce"])?;
    require(
        hex(nonce, 32) && tag == format!("diorama-node-{family}-{nonce}"),
        "owned image identity",
    )?;
    require(
        report["containers"] == json!(runs(family).map(|n| format!("{tag}-{n}"))),
        "owned containers",
    )?;
    for key in [
        "errors",
        "cleanup_errors",
        "remaining_containers",
        "remaining_images",
    ] {
        require(report[key] == json!([]), "complete cleanup")?;
    }
    require(
        text(&report["image_id"])?
            .strip_prefix("sha256:")
            .is_some_and(|s| hex(s, 64)),
        "image identity",
    )?;
    require(
        report["source_sha256"] == digest(&directory.join("source-hashes.json"))?,
        "current compiled/harness source inventory",
    )?;
    let command = report["build_command"].as_array().ok_or("build command")?;
    let context = text(command.last().ok_or("build context")?)?;
    require(
        context.starts_with("/tmp/diorama-node-context-") && !context.contains(".."),
        "owned build context",
    )?;
    require(
        report["build_command"] == build_command(family, tag, nonce, context),
        "exact build command",
    )?;
    let raw = read(&directory.join("build.log"), 32 * 1024 * 1024)?;
    require(report["build_sha256"] == sha256(&raw), "build raw binding")?;
    let built = build::builder_hashes(std::str::from_utf8(&raw)?, family, nonce)?;
    require(report["builder_sha256"] == built, "builder binary binding")?;
    require(
        report["commands"]["build"]
            == commands::verify(directory, "build", &report["build_command"])?,
        "builder command settlement",
    )?;
    verify_runs(root, family, directory, &report, &built)?;
    verify_controls(family, directory, &report)?;
    if matches!(family, "assessment" | "probes") {
        fields(
            &report["commands"],
            &[
                "build",
                "first",
                "repeat",
                "image-inspect",
                "cleanup-1",
                "cleanup-2",
                "cleanup-3",
                "cleanup-4",
                "cleanup-5",
            ],
        )?;
        require(
            report["artifact_sha256"].is_null(),
            "assessment no exported artifact",
        )?;
        evidence_files(family, directory, &report, false)?;
        return Ok(Value::Null);
    }
    let metadata = verify_artifact(family, directory, &report, &built, binary)?;
    evidence_files(family, directory, &report, binary)?;
    Ok(metadata)
}
fn evidence_files(family: &str, directory: &Path, report: &Value, binary: bool) -> Result<()> {
    let mut expected = ["receipt.json", "source-hashes.json"]
        .map(str::to_owned)
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    for label in report["commands"].as_object().ok_or("commands")?.keys() {
        expected.insert(format!("{label}.log"));
        expected.insert(format!("{label}.command.json"));
    }
    if !matches!(family, "assessment" | "probes") {
        expected.insert("artifact.json".into());
        if binary {
            expected.extend(build::binaries(family)?.into_iter().map(str::to_owned));
        }
    }
    let mut actual = std::collections::BTreeSet::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        require(entry.file_type()?.is_file(), "regular evidence files only")?;
        actual.insert(
            entry
                .file_name()
                .into_string()
                .map_err(|_| "evidence filename")?,
        );
    }
    require(actual == expected, "exact evidence inventory")
}
fn verify_runs(
    root: &Path,
    family: &str,
    directory: &Path,
    report: &Value,
    built: &Value,
) -> Result<()> {
    let names = if matches!(family, "assessment" | "probes") {
        vec!["first", "repeat"]
    } else {
        vec!["test"]
    };
    fields(&report["runs"], &names)?;
    let mut records = Vec::new();
    for name in names {
        let row = &report["runs"][name];
        fields(row, &["command", "raw_sha256", "binary_sha256", "records"])?;
        require(
            row["command"] == run_command(family, text(&report["tag"])?, name)?,
            "contained runtime",
        )?;
        let raw = read(&directory.join(format!("{name}.log")), 1024 * 1024)?;
        let (rows, hashes) = observations(root, family, &raw)?;
        require(
            row["raw_sha256"] == sha256(&raw)
                && row["records"] == rows
                && row["binary_sha256"] == hashes
                && &hashes == built,
            "raw/runtime/builder identity",
        )?;
        require(
            report["commands"][name] == commands::verify(directory, name, &row["command"])?,
            "runtime command settlement",
        )?;
        records.push(normalized(&rows));
    }
    if matches!(family, "assessment" | "probes") {
        require(records[0] == records[1], "repeated semantics")?;
    }
    Ok(())
}
fn verify_artifact(
    family: &str,
    directory: &Path,
    report: &Value,
    built: &Value,
    binary: bool,
) -> Result<Value> {
    let path = directory.join("artifact.json");
    let metadata = load(&path)?;
    require(
        report["artifact_sha256"] == digest(&path)?,
        "artifact metadata binding",
    )?;
    fields(&metadata, &["target", "revision", "files"])?;
    require(
        metadata["target"] == "aarch64-unknown-linux-musl"
            && metadata["revision"] == report["revision"],
        "artifact target/revision",
    )?;
    let names = build::binaries(family)?;
    fields(&metadata["files"], &names)?;
    let mut command_names = [
        "build",
        "test",
        "create",
        "image-inspect",
        "cleanup-1",
        "cleanup-2",
        "cleanup-3",
        "cleanup-4",
        "cleanup-5",
    ]
    .map(str::to_owned)
    .to_vec();
    let tag = text(&report["tag"])?;
    let create = json!([
        "docker",
        "create",
        "--name",
        format!("{tag}-artifact"),
        tag,
        "/bin/true"
    ]);
    require(
        report["commands"]["create"] == commands::verify(directory, "create", &create)?,
        "artifact container",
    )?;
    for name in names {
        let row = &metadata["files"][name];
        fields(row, &["sha256", "size"])?;
        require(
            row["sha256"] == built[name]
                && row["size"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n < 64 * 1024 * 1024),
            "artifact identity/size",
        )?;
        if binary {
            let raw = read(&directory.join(name), 64 * 1024 * 1024)?;
            require(
                row["size"] == u64::try_from(raw.len())? && row["sha256"] == sha256(&raw),
                "artifact bytes",
            )?;
        }
        let label = format!("copy-{name}");
        command_names.push(label.clone());
        let receipt = load(&directory.join(format!("{label}.command.json")))?;
        let argv = receipt["argv"].as_array().ok_or("copy arguments")?;
        require(argv.len() == 4, "copy argument count")?;
        let destination = Path::new(text(&argv[3])?);
        require(
            destination.is_absolute() && destination.file_name().is_some_and(|n| n == name),
            "artifact copy destination",
        )?;
        require(
            receipt["argv"]
                == json!([
                    "docker",
                    "cp",
                    format!("{tag}-artifact:/out/{name}"),
                    argv[3]
                ]),
            "owned artifact copy",
        )?;
        require(
            report["commands"][&label] == commands::verify(directory, &label, &receipt["argv"])?,
            "copy settlement",
        )?;
    }
    fields(
        &report["commands"],
        &command_names.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    Ok(metadata)
}
pub(super) fn capture(
    root: &Path,
    family: &str,
    directory: &Path,
    cancellation: &Cancellation,
) -> Result<()> {
    if !matches!(family, "assessment" | "probes") {
        build::binaries(family)?;
    }
    let source = inventory(root, family)?;
    let mut status = json!([
        "git",
        "-C",
        root,
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--"
    ]);
    status.as_array_mut().ok_or("status argv")?.extend(
        source
            .as_object()
            .ok_or("source map")?
            .keys()
            .map(|s| Value::String(s.clone())),
    );
    require(
        commands::control(&status, cancellation)?.is_empty(),
        "clean committed sources required",
    )?;
    let revision = commands::control(
        &json!(["git", "-C", root, "rev-parse", "HEAD"]),
        cancellation,
    )?;
    require(hex(&revision, 40), "source revision")?;
    let mut bytes = [0u8; 16];
    std::io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut bytes)?;
    let nonce = sha256(&bytes)[..32].to_owned();
    let tag = format!("diorama-node-{family}-{nonce}");
    fs::create_dir(directory)?;
    save(&directory.join("source-hashes.json"), &source)?;
    let mut report = json!({"schema":3,"family":family,"revision":revision,"dirty":false,"cancelled":false,"tag":tag,"nonce":nonce,"source_sha256":digest(&directory.join("source-hashes.json"))?,"build_command":[],"build_sha256":null,"builder_sha256":null,"image_id":null,"containers":runs(family).map(|n|format!("{tag}-{n}")),"runs":{},"commands":{},"errors":[],"cleanup_errors":[],"remaining_containers":null,"remaining_images":null,"artifact_sha256":null});
    let result = execute(root, family, directory, &source, &mut report, cancellation);
    if let Err(error) = &result {
        report["errors"] = json!([error.to_string()]);
    }
    let result = if result.as_ref().is_err_and(uncertain) {
        report["cleanup_errors"] = json!(["unsettled command; further cleanup not attempted"]);
        result
    } else {
        let mut sequence = 0;
        let mut proofs = serde_json::Map::new();
        let cleanup = cleanup(&mut report, family, &tag, |argv| {
            sequence += 1;
            let label = format!("cleanup-{sequence}");
            let raw = commands::run(directory, &label, argv, 30, 65536, &Cancellation::default())?;
            proofs.insert(
                label.clone(),
                commands::verify(directory, &label, argv)?.into(),
            );
            Ok(String::from_utf8(raw)?.trim().to_owned())
        });
        report["commands"]
            .as_object_mut()
            .ok_or("commands")?
            .extend(proofs);
        if cleanup.is_err() { cleanup } else { result }
    };
    report["cancelled"] = cancellation.requested().into();
    let result =
        result.and_then(|()| require(!cancellation.requested(), "cancelled before publication"));
    if let Err(error) = &result
        && let Some(failure) = error.downcast_ref::<crate::parity::process::CommandFailure>()
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
    let verified = verify(root, family, directory, true).map(|_| ());
    if verified.is_err() || cancellation.requested() {
        report["cancelled"] = json!(cancellation.requested());
        report["errors"] = json!([verified.as_ref().err().map_or(
            "cancelled during final verification".to_owned(),
            ToString::to_string
        )]);
        save(&directory.join("receipt.json"), &report)?;
        verified?;
        return Err("cancelled during final verification".into());
    }
    Ok(())
}
fn execute(
    root: &Path,
    family: &str,
    directory: &Path,
    source: &Value,
    report: &mut Value,
    cancellation: &Cancellation,
) -> Result<()> {
    let context = tempfile::Builder::new()
        .prefix("diorama-node-context-")
        .tempdir_in("/tmp")?;
    let result = (|| {
        for name in source.as_object().ok_or("source map")?.keys() {
            let target = context.path().join(name);
            fs::create_dir_all(target.parent().ok_or("target parent")?)?;
            fs::copy(root.join(name), target)?;
        }
        require(
            inventory(context.path(), family)? == *source,
            "copied source hashes",
        )?;
        let tag = text(&report["tag"])?.to_owned();
        let nonce = text(&report["nonce"])?.to_owned();
        let command = build_command(
            family,
            &tag,
            &nonce,
            context.path().to_str().ok_or("context UTF8")?,
        );
        report["build_command"] = command.clone();
        let raw = commands::run(
            directory,
            "build",
            &command,
            if family == "probes" { 900 } else { 1800 },
            if family == "probes" {
                8 * 1024 * 1024
            } else {
                32 * 1024 * 1024
            },
            cancellation,
        )?;
        report["build_sha256"] = sha256(&raw).into();
        report["commands"]["build"] = commands::verify(directory, "build", &command)?.into();
        report["builder_sha256"] =
            build::builder_hashes(std::str::from_utf8(&raw)?, family, &nonce)?;
        let argv = image_command(&tag);
        let raw = commands::run(directory, "image-inspect", &argv, 30, 65536, cancellation)?;
        report["image_id"] = String::from_utf8(raw)?.trim().into();
        report["commands"]["image-inspect"] =
            commands::verify(directory, "image-inspect", &argv)?.into();
        if !matches!(family, "assessment" | "probes") {
            export_artifacts(family, directory, report, cancellation)?;
        }
        for name in if matches!(family, "assessment" | "probes") {
            vec!["first", "repeat"]
        } else {
            vec!["test"]
        } {
            let command = run_command(family, &tag, name)?;
            let raw = commands::run(
                directory,
                name,
                &command,
                if family == "probes" { 60 } else { 100 },
                1024 * 1024,
                cancellation,
            )?;
            let (rows, hashes) = observations(root, family, &raw)?;
            report["commands"][name] = commands::verify(directory, name, &command)?.into();
            report["runs"][name] = json!({"command":command,"raw_sha256":sha256(&raw),"binary_sha256":hashes,"records":rows});
        }
        require(
            inventory(root, family)? == *source
                && commands::control(
                    &json!(["git", "-C", root, "rev-parse", "HEAD"]),
                    cancellation,
                )? == report["revision"],
            "source changed during capture",
        )?;
        Ok(())
    })();
    retain(context, result)
}
fn export_artifacts(
    family: &str,
    directory: &Path,
    report: &mut Value,
    cancellation: &Cancellation,
) -> Result<()> {
    let tag = text(&report["tag"])?.to_owned();
    let create = json!([
        "docker",
        "create",
        "--name",
        format!("{tag}-artifact"),
        tag,
        "/bin/true"
    ]);
    commands::run(directory, "create", &create, 30, 65536, cancellation)?;
    report["commands"]["create"] = commands::verify(directory, "create", &create)?.into();
    let mut metadata =
        json!({"target":"aarch64-unknown-linux-musl","revision":report["revision"],"files":{}});
    for name in build::binaries(family)? {
        let label = format!("copy-{name}");
        let path = directory.canonicalize()?.join(name);
        let command = json!(["docker", "cp", format!("{tag}-artifact:/out/{name}"), path]);
        commands::run(directory, &label, &command, 30, 65536, cancellation)?;
        report["commands"][&label] = commands::verify(directory, &label, &command)?.into();
        let bytes = read(&path, 64 * 1024 * 1024)?;
        metadata["files"][name] = json!({"sha256":sha256(&bytes),"size":bytes.len()});
    }
    save(&directory.join("artifact.json"), &metadata)?;
    report["artifact_sha256"] = digest(&directory.join("artifact.json"))?.into();
    Ok(())
}
pub(super) fn cleanup(
    report: &mut Value,
    family: &str,
    tag: &str,
    mut control: impl FnMut(&Value) -> Result<String>,
) -> Result<()> {
    let mut argv = runs(family)
        .into_iter()
        .map(|n| json!(["docker", "rm", "-f", format!("{tag}-{n}")]))
        .collect::<Vec<_>>();
    argv.push(json!(["docker", "rmi", "-f", tag]));
    for command in argv {
        if let Err(error) = control(&command) {
            report["cleanup_errors"]
                .as_array_mut()
                .ok_or("cleanup errors")?
                .push(error.to_string().into());
            if uncertain(&error) {
                return Err(error);
            }
        }
    }
    for (key, command) in [
        (
            "remaining_containers",
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
            "remaining_images",
            json!(["docker", "image", "ls", tag, "--format", "{{.ID}}"]),
        ),
    ] {
        match control(&command) {
            Ok(value) => report[key] = json!(value.lines().collect::<Vec<_>>()),
            Err(error) => {
                report["cleanup_errors"]
                    .as_array_mut()
                    .ok_or("cleanup errors")?
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
fn image_command(tag: &str) -> Value {
    json!(["docker", "image", "inspect", "--format", "{{.Id}}", tag])
}
pub(super) fn control_commands(family: &str, tag: &str) -> Vec<(String, Value)> {
    let mut result = vec![("image-inspect".into(), image_command(tag))];
    let mut commands = runs(family)
        .into_iter()
        .map(|name| json!(["docker", "rm", "-f", format!("{tag}-{name}")]))
        .collect::<Vec<_>>();
    commands.push(json!(["docker", "rmi", "-f", tag]));
    commands.push(json!([
        "docker",
        "ps",
        "-a",
        "--filter",
        format!("name={tag}"),
        "--format",
        "{{.Names}}"
    ]));
    commands.push(json!(["docker", "image", "ls", tag, "--format", "{{.ID}}"]));
    result.extend(
        commands
            .into_iter()
            .enumerate()
            .map(|(index, argv)| (format!("cleanup-{}", index + 1), argv)),
    );
    result
}
fn verify_controls(family: &str, directory: &Path, report: &Value) -> Result<()> {
    for (label, argv) in control_commands(family, text(&report["tag"])?) {
        require(
            report["commands"][&label] == commands::verify(directory, &label, &argv)?,
            "settled Docker control proof",
        )?;
        let raw = read(&directory.join(format!("{label}.log")), 65536)?;
        let raw = std::str::from_utf8(&raw)?.trim();
        if label == "image-inspect" {
            require(report["image_id"] == raw, "raw image identity")?;
        }
        if label == "cleanup-4" || label == "cleanup-5" {
            require(raw.is_empty(), "raw owned inventories must be empty")?;
        }
    }
    Ok(())
}
const RECEIPT_FIELDS: &[&str] = &[
    "schema",
    "family",
    "revision",
    "dirty",
    "cancelled",
    "tag",
    "nonce",
    "source_sha256",
    "build_command",
    "build_sha256",
    "builder_sha256",
    "image_id",
    "containers",
    "runs",
    "commands",
    "errors",
    "cleanup_errors",
    "remaining_containers",
    "remaining_images",
    "artifact_sha256",
];
