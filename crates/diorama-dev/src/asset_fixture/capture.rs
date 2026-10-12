use super::common::{
    Result, array, bounded, check, digest, fields, hex, inventory, json, load, output, read, save,
    sha256, string,
};
use serde_json::Value;
use std::{fs, path::Path, process::Command};
pub(super) fn binaries(family: &str) -> Result<Vec<&'static str>> {
    match family {
        "decode" => Ok(vec!["decode-tests", "decoded_elf-tests", "fixture"]),
        "archive" => Ok(vec!["producer", "archive-tests", "fixture"]),
        "layer" => Ok(vec!["producer", "layer-tests", "fixture"]),
        "manifest" => Ok(vec!["producer", "manifest-tests", "fixture"]),
        _ => Err("unknown Docker family".into()),
    }
}
pub(super) fn command(family: &str, tag: &str, name: &str) -> Result<Vec<String>> {
    binaries(family)?;
    let script = if family == "decode" {
        "sha256sum /decode-tests /decoded_elf-tests /fixture; printf 'DIORAMA_SUITE decode\\n'; /decode-tests --nocapture --test-threads=1; decode_status=$?; printf 'DIORAMA_SUITE decoded_elf\\n'; /decoded_elf-tests --nocapture --test-threads=1; elf_status=$?; /fixture namespace; inventory=$?; test \"$decode_status\" -eq 0 && test \"$elf_status\" -eq 0 && test \"$inventory\" -eq 0"
    } else if family == "archive" {
        "sha256sum /producer /archive-tests /fixture && /fixture archive-runtime; runtime_status=$?; /fixture namespace; inventory=$?; test \"$runtime_status\" -eq 0 && test \"$inventory\" -eq 0"
    } else if family == "manifest" {
        "sha256sum /producer /manifest-tests /fixture && /fixture manifest-runtime; runtime_status=$?; /fixture namespace; inventory=$?; test \"$runtime_status\" -eq 0 && test \"$inventory\" -eq 0"
    } else {
        "sha256sum /producer /layer-tests /fixture && /fixture layer-runtime; runtime_status=$?; /fixture namespace; inventory=$?; test \"$runtime_status\" -eq 0 && test \"$inventory\" -eq 0"
    };
    Ok([
        "docker",
        "run",
        "--name",
        &format!("{tag}-{name}"),
        "--init",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=64",
        "--memory=256m",
        "--cpus=2",
        "--tmpfs",
        if family == "manifest" {
            "/tmp:rw,nosuid,nodev,size=96m"
        } else {
            "/tmp:rw,nosuid,nodev,size=16m"
        },
        tag,
        "/bin/sh",
        "-c",
        script,
    ]
    .iter()
    .map(|v| (*v).into())
    .collect())
}
pub(super) fn records(family: &str, path: &Path) -> Result<(Value, Value)> {
    match family {
        "decode" => super::native::records(path),
        "archive" => super::archive::records(path),
        "layer" => super::layer::records(path),
        "manifest" => super::manifest::records(path),
        _ => Err("unknown record family".into()),
    }
}
fn receipt_header(report: &Value, family: &str) -> Result<()> {
    fields(
        report,
        &[
            "schema",
            "cancelled",
            "family",
            "revision",
            "dirty",
            "tag",
            "source_sha256",
            "source_inventory_sha256",
            "containers",
            "errors",
            "cleanup_errors",
            "remaining_containers",
            "remaining_images",
            "image_id",
            "build_command",
            "build_log_sha256",
            "build_binary_sha256",
            "command_sha256",
            "runs",
        ],
    )?;
    check(
        report["schema"] == 3
            && report["cancelled"] == false
            && report["family"] == family
            && hex(string(&report["revision"])?, 40)
            && report["dirty"] == false,
        "Rust clean source receipt",
    )?;
    Ok(())
}
pub(super) fn verify(root: &Path, family: &str, directory: &Path) -> Result<()> {
    if family == "elf" {
        return super::elf::verify(root, directory);
    }
    let names = binaries(family)?;
    let report = load(&directory.join("receipt.json"))?;
    receipt_header(&report, family)?;
    let tag = string(&report["tag"])?;
    let prefix = format!("diorama-{family}-");
    check(
        tag.strip_prefix(&prefix).is_some_and(|v| hex(v, 32)),
        "owned tag",
    )?;
    check(
        report["containers"] == json!([format!("{tag}-first"), format!("{tag}-repeat")]),
        "owned containers",
    )?;
    for key in [
        "errors",
        "cleanup_errors",
        "remaining_containers",
        "remaining_images",
    ] {
        check(report[key] == json!([]), "successful cleanup")?;
    }
    check(
        string(&report["image_id"])?
            .strip_prefix("sha256:")
            .is_some_and(|v| hex(v, 64)),
        "image id",
    )?;
    let sources = load(&directory.join("source-inventory.json"))?;
    check(
        report["source_inventory_sha256"] == digest(&directory.join("source-inventory.json"))?
            && report["source_sha256"] == sources,
        "exact current source inventory",
    )?;
    let build_command = array(&report["build_command"])?;
    let context = string(build_command.last().ok_or("build command")?)?;
    check(
        context.starts_with("/tmp/diorama-asset-context-") && !context.contains(".."),
        "owned context",
    )?;
    check(
        report["build_command"]
            == json!([
                "docker",
                "build",
                "--progress=plain",
                "--build-arg",
                format!("QUALIFICATION_NONCE={tag}"),
                "--platform=linux/arm64",
                "-t",
                tag,
                "-f",
                format!("{context}/tools/assets-{family}/Capture.Dockerfile"),
                context
            ]),
        "exact build command",
    )?;
    let raw = read(&directory.join("build.log"), 16 * 1024 * 1024)?;
    check(
        report["build_log_sha256"] == sha256(&raw),
        "build log digest",
    )?;
    let built = super::native::builder(std::str::from_utf8(&raw)?, tag, &names)?;
    check(
        report["build_binary_sha256"] == built,
        "builder recorded digests",
    )?;
    fields(&report["runs"], &["first", "repeat"])?;
    verify_controls(directory, &report, tag)?;
    check(
        report["command_sha256"]["build"]
            == super::common::verify_command(
                &directory.join("build.command.json"),
                &report["build_command"],
                string(&report["build_log_sha256"])?,
            )?,
        "build command receipt binding",
    )?;

    verify_runs(family, directory, &report, tag, &built)
}
pub(super) fn controls(tag: &str) -> Vec<(&'static str, Value)> {
    vec![
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
    let controls = controls(tag);
    let mut labels = vec!["build", "first", "repeat"];
    labels.extend(controls.iter().map(|(label, _)| *label));
    fields(&report["command_sha256"], &labels)?;
    let mut expected = std::collections::BTreeSet::from([
        "receipt.json".to_owned(),
        "source-inventory.json".to_owned(),
    ]);
    for label in labels {
        expected.insert(format!("{label}.log"));
        expected.insert(format!("{label}.command.json"));
    }
    let mut actual = std::collections::BTreeSet::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        check(entry.file_type()?.is_file(), "regular evidence file")?;
        actual.insert(
            entry
                .file_name()
                .into_string()
                .map_err(|_| "evidence filename")?,
        );
    }
    check(actual == expected, "exact evidence files")?;
    for (label, argv) in controls {
        let raw = read(&directory.join(format!("{label}.log")), 65536)?;
        check(
            report["command_sha256"][label]
                == super::common::verify_command(
                    &directory.join(format!("{label}.command.json")),
                    &argv,
                    &sha256(&raw),
                )?,
            "control command receipt binding",
        )?;
        let text = std::str::from_utf8(&raw)?.trim();
        if label == "image-inspect" {
            check(report["image_id"] == text, "raw image identity")?;
        } else if matches!(label, "cleanup-4" | "cleanup-5") {
            check(text.is_empty(), "raw empty cleanup inventory")?;
        }
    }
    Ok(())
}
fn verify_runs(
    family: &str,
    directory: &Path,
    report: &Value,
    tag: &str,
    built: &Value,
) -> Result<()> {
    let mut observations = Vec::new();
    for name in ["first", "repeat"] {
        let run = &report["runs"][name];
        fields(run, &["command", "raw_sha256", "binary_sha256", "records"])?;
        check(
            run["command"] == json!(command(family, tag, name)?),
            "isolated command",
        )?;
        let path = directory.join(format!("{name}.log"));
        check(run["raw_sha256"] == digest(&path)?, "raw log binding")?;
        let (rows, hashes) = records(family, &path)?;
        check(
            report["command_sha256"][name]
                == super::common::verify_command(
                    &directory.join(format!("{name}.command.json")),
                    &run["command"],
                    string(&run["raw_sha256"])?,
                )?,
            "runtime command receipt binding",
        )?;

        check(
            run["records"] == rows && run["binary_sha256"] == hashes && &hashes == built,
            "builder/runtime/raw consistency",
        )?;
        observations.push(rows);
    }
    check(
        observations[0] == observations[1],
        "repeated independent observations",
    )
}
fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
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
            copy_tree(&entry.path(), &target.join(name))?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target.join(name))?;
        } else {
            return Err("source contains symlink/special file".into());
        }
    }
    Ok(())
}
fn execute(
    root: &Path,
    family: &str,
    directory: &Path,
    report: &mut Value,
    cache: Option<&Path>,
) -> Result<()> {
    let context = tempfile::Builder::new()
        .prefix("diorama-asset-context-")
        .tempdir_in("/tmp")?;
    let result = (|| {
        if family == "manifest" {
            super::manifest::copy_inputs(
                cache.ok_or("manifest input cache required")?,
                &context.path().join("manifest-inputs"),
            )?;
        }
        execute_in(root, family, directory, report, context.path())
    })();
    super::common::retain(context, result)
}
pub(super) fn context_directories(family: &str) -> Vec<String> {
    let mut names = [
        ".cargo",
        "crates",
        "third_party",
        "tools/upstream",
        "tools/dev",
        "tools/assets-manifest",
    ]
    .map(str::to_owned)
    .to_vec();
    if family != "manifest" {
        names.push(format!("tools/assets-{family}"));
    }
    names
}
fn execute_in(
    root: &Path,
    family: &str,
    directory: &Path,
    report: &mut Value,
    context: &Path,
) -> Result<()> {
    let sources = report["source_sha256"].clone();
    let revision = string(&report["revision"])?.to_owned();
    let tag = string(&report["tag"])?.to_owned();
    for name in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"] {
        fs::copy(root.join(name), context.join(name))?;
    }
    for name in context_directories(family) {
        copy_tree(&root.join(&name), &context.join(&name))?;
    }
    check(
        inventory(context, family)? == sources,
        "copied source inventory",
    )?;
    let context_str = context.to_str().ok_or("context path")?;
    let build = vec![
        "docker".to_owned(),
        "build".into(),
        "--progress=plain".into(),
        "--build-arg".into(),
        format!("QUALIFICATION_NONCE={tag}"),
        "--platform=linux/arm64".into(),
        "-t".into(),
        tag.clone(),
        "-f".into(),
        format!("{context_str}/tools/assets-{family}/Capture.Dockerfile"),
        context_str.into(),
    ];
    report["build_command"] = json!(build);
    bounded(
        Command::new(&build[0]).args(&build[1..]),
        &directory.join("build.log"),
        1800,
        16 * 1024 * 1024,
    )?;
    report["build_log_sha256"] = digest(&directory.join("build.log"))?.into();
    report["command_sha256"]["build"] = super::common::verify_command(
        &directory.join("build.command.json"),
        &report["build_command"],
        string(&report["build_log_sha256"])?,
    )?
    .into();

    report["build_binary_sha256"] = super::native::builder(
        &String::from_utf8(read(&directory.join("build.log"), 16 * 1024 * 1024)?)?,
        &tag,
        &binaries(family)?,
    )?;
    report["image_id"] = super::common::persistent_control(
        Command::new("docker").args(["image", "inspect", "--format", "{{.Id}}", &tag]),
        &directory.join("image-inspect.log"),
        false,
    )?
    .into();
    report["command_sha256"]["image-inspect"] =
        digest(&directory.join("image-inspect.command.json"))?.into();
    for name in ["first", "repeat"] {
        report["containers"]
            .as_array_mut()
            .ok_or("container list")?
            .push(format!("{tag}-{name}").into());
        let args = command(family, &tag, name)?;
        let log = directory.join(format!("{name}.log"));
        bounded(
            Command::new(&args[0]).args(&args[1..]),
            &log,
            100,
            2 * 1024 * 1024,
        )?;
        let (rows, hashes) = records(family, &log)?;
        report["runs"][name] = json!({"command":args,"raw_sha256":digest(&log)?,"binary_sha256":hashes,"records":rows});
        report["command_sha256"][name] = super::common::verify_command(
            &directory.join(format!("{name}.command.json")),
            &report["runs"][name]["command"],
            string(&report["runs"][name]["raw_sha256"])?,
        )?
        .into();
    }
    check(
        inventory(root, family)? == sources,
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
    Ok(())
}
pub(super) fn docker(root: &Path, family: &str, directory: &Path) -> Result<()> {
    docker_cached(root, family, directory, None)
}
pub(super) fn docker_cached(
    root: &Path,
    family: &str,
    directory: &Path,
    cache: Option<&Path>,
) -> Result<()> {
    binaries(family)?;
    let sources = inventory(root, family)?;
    let revision = super::common::clean_revision(root, &sources)?;
    let mut random = [0u8; 16];
    std::io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut random)?;
    let nonce = sha256(&random)[..32].to_owned();
    let tag = format!("diorama-{family}-{nonce}");
    fs::create_dir(directory)?;
    save(&directory.join("source-inventory.json"), &sources)?;
    let mut report = json!({"schema":3,"family":family,"revision":revision,"dirty":false,"tag":tag,"source_sha256":sources,"source_inventory_sha256":digest(&directory.join("source-inventory.json"))?,"containers":[],"errors":[],"cleanup_errors":[],"remaining_containers":null,"remaining_images":null,"image_id":null,"build_command":[],"build_log_sha256":null,"build_binary_sha256":null,"command_sha256":{},"runs":{}});
    let result = execute(root, family, directory, &mut report, cache);

    if let Err(error) = &result {
        report["errors"] = json!([error.to_string()]);
    }
    if result.as_ref().is_err_and(super::common::uncertain) {
        report["cleanup_errors"] = json!(["unsettled command; further cleanup not attempted"]);
        return super::common::publish_result(&directory.join("receipt.json"), &mut report, result);
    }
    let mut proofs = Vec::new();
    let mut index = 0;
    let cleanup_result = cleanup(&mut report, &tag, |args| {
        index += 1;
        let label = format!("cleanup-{index}");
        let result = super::common::persistent_control(
            Command::new("docker").args(args),
            &directory.join(format!("{label}.log")),
            true,
        );
        let proof = directory.join(format!("{label}.command.json"));
        if proof.exists() {
            match digest(&proof) {
                Ok(hash) => proofs.push((label, hash)),
                Err(error) if result.is_ok() => return Err(error),
                // Keep the typed ownership failure so cleanup stops when settlement is unknown.
                Err(_) => {},
            }
        }
        result
    });
    for (label, hash) in proofs {
        report["command_sha256"][label] = hash.into();
    }
    let status = if cleanup_result.is_err() {
        cleanup_result
    } else {
        result
    };
    super::common::publish_result(&directory.join("receipt.json"), &mut report, status)?;
    verify(root, family, directory)
}
pub(super) fn cleanup(
    report: &mut Value,
    tag: &str,
    mut control: impl FnMut(&[&str]) -> Result<String>,
) -> Result<()> {
    let mut cleanup = Vec::new();
    for name in [format!("{tag}-first"), format!("{tag}-repeat")] {
        if let Err(e) = control(&["rm", "-f", &name]) {
            cleanup.push(e.to_string());
            if super::common::uncertain(&e) {
                report["cleanup_errors"] = json!(cleanup);
                return Err(e);
            }
        }
    }
    if let Err(e) = control(&["rmi", "-f", tag]) {
        cleanup.push(e.to_string());
        if super::common::uncertain(&e) {
            report["cleanup_errors"] = json!(cleanup);
            return Err(e);
        }
    }
    report["cleanup_errors"] = json!(cleanup);
    for (field, args) in [
        (
            "remaining_containers",
            vec![
                "ps",
                "-a",
                "--filter",
                &format!("name={tag}"),
                "--format",
                "{{.Names}}",
            ],
        ),
        (
            "remaining_images",
            vec!["image", "ls", &tag, "--format", "{{.ID}}"],
        ),
    ] {
        match control(&args) {
            Ok(text) => report[field] = json!(text.lines().collect::<Vec<_>>()),
            Err(e) => {
                report["cleanup_errors"]
                    .as_array_mut()
                    .ok_or("cleanup list")?
                    .push(e.to_string().into());
                if super::common::uncertain(&e) {
                    report["remaining_containers"] = Value::Null;
                    report["remaining_images"] = Value::Null;
                    return Err(e);
                }
            },
        }
    }
    Ok(())
}
pub(super) fn namespace() -> Result<()> {
    let pid = std::process::id();
    let stat = String::from_utf8(read(Path::new("/proc/self/stat"), 8192)?)?;
    let tail = stat.rsplit_once(") ").ok_or("proc stat")?.1;
    let parent = tail
        .split_whitespace()
        .nth(1)
        .ok_or("parent PID")?
        .parse::<u32>()?;
    let mut processes = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if let Some(id) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        {
            check(processes.len() < 64, "namespace process bound")?;
            processes.push(id);
        }
    }
    processes.sort_unstable();
    println!(
        "DIORAMA_NAMESPACE {}",
        json!({"init":1,"shell":parent,"helper":pid,"processes":processes})
    );
    Ok(())
}
