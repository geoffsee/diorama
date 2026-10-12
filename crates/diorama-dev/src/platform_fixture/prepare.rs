//! Public pinned package closure and actual Go baseline oracle preparation.
use super::{
    Options, Path, Result, Value, digest, equal, fixture, json, load, read, require,
    source_inventory,
};
use diorama_dev::defaults::capture::{OwnedDocker, Runner, arguments, owned_tag, push_error};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Seek, Write};
fn publish(path: &Path, bytes: &[u8], expected: &str) -> Result<()> {
    require(
        diorama_dev::sha256(bytes) == expected,
        "verified cache content",
    )?;
    require(!path.is_symlink(), "cache symlink")?;
    if path.exists() {
        equal(
            &json!(digest(path)?),
            &json!(expected),
            "existing cache content",
        )?;
        return Ok(());
    }
    let mut partial = tempfile::NamedTempFile::new_in(path.parent().ok_or("cache parent")?)?;
    partial.write_all(bytes)?;
    partial.persist_noclobber(path)?;
    Ok(())
}
#[allow(
    clippy::too_many_lines,
    reason = "Keep prepared build context and owned Docker lifecycle in one scope"
)]
pub(super) fn run(root: &Path, options: &Options) -> Result<u8> {
    let output = options.path("--output")?;
    diorama_dev::defaults::capture::create_output(output)?;
    let cache = options.path("--cache")?;
    require(!cache.is_symlink(), "cache directory symlink")?;
    fs::create_dir_all(cache)?;
    let here = fixture(root, "alpine-preparation");
    let inputs = load(&here.join("inputs.json"))?;
    let tag = owned_tag("diorama-alpine-prepare")?;
    let mut owned = OwnedDocker {
        tag,
        image_id: None,
        containers: vec![],
    };
    let mut runner = Runner::new(output);
    let cancellation = runner.commands.cancellation.clone();
    let signals = diorama_dev::process::SignalGuard::install(cancellation.clone())?;
    runner.launcher = Some(std::env::current_exe()?);
    let mut report = json!({"schema_version":2,"image_tag":owned.tag,"containers":[],"errors":[],"cleanup_errors":[],"source_sha256":source_inventory(root,"alpine")?});
    let operation = (|| -> Result<()> {
        let index = cache.join("APKINDEX.tar.gz");
        equal(
            &json!(digest(&index)?),
            &inputs["packages"]["index_sha256"],
            "index pin",
        )?;
        let context = tempfile::Builder::new()
            .prefix("diorama-alpine-prepare-source-")
            .tempdir()?;
        let context_path = context.path().to_owned();
        for name in ["Prepare.Dockerfile", "go.mod", "baseline_test.go"] {
            fs::write(
                context_path.join(name),
                read(&here.join(name), 8 * 1024 * 1024)?,
            )?;
        }
        fs::write(
            context_path.join("APKINDEX.tar.gz"),
            read(&index, 8 * 1024 * 1024)?,
        )?;
        runner.keep_context(context);
        runner.bounded(
            &[
                "docker".into(),
                "build".into(),
                "--platform".into(),
                "linux/arm64".into(),
                "-t".into(),
                owned.tag.clone().into(),
                "-f".into(),
                context_path.join("Prepare.Dockerfile").into(),
                context_path.clone().into(),
            ],
            "build",
            900,
            8 * 1024 * 1024,
        )?;
        report["image"] = diorama_dev::defaults::capture::inspect_image(&mut runner, &mut owned)?;
        report["image_id"] = json!(owned.image_id);
        let name = format!("{}-resolve", owned.tag);
        owned.containers.push(name.clone());
        report["containers"] = json!(owned.containers);
        let resolution = runner.bounded(
            &arguments(&[
                "docker",
                "run",
                "--name",
                &name,
                "--read-only",
                "--network",
                "none",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--memory",
                "256m",
                "--pids-limit",
                "64",
                "--tmpfs",
                "/tmp:rw,size=16m",
                "--tmpfs",
                "/var/cache/apk:rw,size=16m",
                &owned.tag,
                "apk",
                "fetch",
                "--simulate",
                "--recursive",
                "--url",
                "--no-network",
                "--repositories-file",
                "/repositories",
                "nftables=1.1.6-r1",
                "iptables=1.8.13-r0",
                "openrc=0.63.2-r0",
            ]),
            "resolution",
            60,
            65536,
        )?;
        let names = String::from_utf8(resolution)?
            .lines()
            .filter(|line| {
                line.starts_with("/repo/aarch64/") || line.starts_with("file:///repo/aarch64/")
            })
            .map(|line| line.rsplit('/').next().unwrap_or("").to_owned())
            .collect::<Vec<_>>();
        require(
            !names.is_empty()
                && names.len() <= 64
                && names.iter().collect::<BTreeSet<_>>().len() == names.len(),
            "unique nonempty resolved closure",
        )?;
        let accepted = inputs["packages"]["selected"]
            .as_object()
            .ok_or("package pins")?;
        equal(
            &json!(names.iter().collect::<BTreeSet<_>>()),
            &json!(accepted.keys().collect::<BTreeSet<_>>()),
            "package resolution drift",
        )?;
        for (source, dest) in [
            ("/preflight.test", "preflight.test"),
            ("/source.sha256", "source.sha256"),
        ] {
            let path = context_path.join(dest);
            runner.bounded(
                &[
                    "docker".into(),
                    "cp".into(),
                    format!("{name}:{source}").into(),
                    path.clone().into(),
                ],
                &format!("copy-{}", dest.replace('.', "-")),
                30,
                65536,
            )?;
            let bytes = read(&path, 16 * 1024 * 1024)?;
            let expected = if dest == "preflight.test" {
                inputs["oracle"]["binary_sha256"]
                    .as_str()
                    .ok_or("oracle hash")?
                    .to_owned()
            } else {
                diorama_dev::sha256(&bytes)
            };
            publish(&cache.join(dest), &bytes, &expected)?;
        }
        let source = text_source(&cache.join("source.sha256"))?;
        publish(
            &output.join("source.sha256"),
            source.as_bytes(),
            &diorama_dev::sha256(source.as_bytes()),
        )?;
        require(
            source.lines().next()
                == Some(&format!(
                    "{}  preflight.go",
                    inputs["oracle"]["source_sha256"]
                        .as_str()
                        .ok_or("source pin")?
                )),
            "unchanged Go baseline source",
        )?;
        let packages = cache.join("packages");
        require(!packages.is_symlink(), "packages directory symlink")?;
        fs::create_dir_all(&packages)?;
        publish(
            &packages.join("APKINDEX.tar.gz"),
            &read(&index, 8 * 1024 * 1024)?,
            inputs["packages"]["index_sha256"]
                .as_str()
                .ok_or("index hash")?,
        )?;
        let mut pins = serde_json::Map::new();
        for (index, name) in names.into_iter().enumerate() {
            require(
                Path::new(&name).extension() == Some(std::ffi::OsStr::new("apk"))
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"+_.-".contains(&b)),
                "safe package basename",
            )?;
            let pin = &accepted[&name];
            let url = format!("https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/{name}");
            equal(&pin["url"], &json!(url), "official package URL")?;
            let downloaded = context_path.join(&name);
            runner.bounded(
                &[
                    "curl".into(),
                    "--fail".into(),
                    "--location".into(),
                    "--proto".into(),
                    "=https".into(),
                    "--max-time".into(),
                    "30".into(),
                    "--max-filesize".into(),
                    "16777216".into(),
                    "--output".into(),
                    downloaded.clone().into(),
                    url.clone().into(),
                ],
                &format!("download-{index:03}"),
                40,
                65536,
            )?;
            let bytes = read(&downloaded, 16 * 1024 * 1024)?;
            equal(&json!(bytes.len()), &pin["bytes"], "package size")?;
            publish(
                &packages.join(&name),
                &bytes,
                pin["sha256"].as_str().ok_or("package digest")?,
            )?;
            pins.insert(name, pin.clone());
        }
        report["packages"] = Value::Object(pins);
        report["index_sha256"] = inputs["packages"]["index_sha256"].clone();
        report["oracle_sha256"] = json!(digest(&cache.join("preflight.test"))?);
        report["baseline_source_and_binary"] = json!(source);
        let bytes = serde_json::to_vec_pretty(&report["packages"])?;
        publish(
            &cache.join("package-pins.json"),
            &bytes,
            &diorama_dev::sha256(&bytes),
        )?;
        equal(
            &source_inventory(root, "alpine")?,
            &report["source_sha256"],
            "source stable through preparation",
        )?;
        Ok(())
    })();
    if let Err(error) = operation {
        push_error(&mut report, "errors", error.to_string());
    }
    if let Err(error) = runner.finish(&mut report, output, &owned) {
        return Err(Box::new(RetainedCapture {
            error,
            _signals: signals,
        }));
    }
    publish_qualification(output, &report, &cancellation, || {})
}
#[derive(Debug)]
struct RetainedCapture {
    error: diorama_dev::Error,
    _signals: diorama_dev::process::SignalGuard,
}
impl std::fmt::Display for RetainedCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for RetainedCapture {}
fn publish_qualification(
    output: &Path,
    report: &Value,
    cancellation: &diorama_dev::process::Cancellation,
    after_publish: impl FnOnce(),
) -> Result<u8> {
    let inventory = super::guest::evidence_inventory(output)?;
    let mut qualification =
        json!({"schema_version":2,"files":inventory,"cancelled":cancellation.requested()});
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("qualification.json"))?;
    serde_json::to_writer_pretty(&mut file, &qualification)?;
    after_publish();
    if cancellation.requested() {
        qualification["cancelled"] = json!(true);
        file.rewind()?;
        serde_json::to_writer_pretty(&mut file, &qualification)?;
        let position = file.stream_position()?;
        file.set_len(position)?;
    }
    Ok(u8::from(
        !diorama_dev::defaults::capture::successful(report) || cancellation.requested(),
    ))
}
fn text_source(path: &Path) -> Result<String> {
    Ok(String::from_utf8(read(path, 65536)?)?)
}
fn verify_publication(output: &Path) -> Result<Value> {
    let qualification = load(&output.join("qualification.json"))?;
    equal(
        &qualification["schema_version"],
        &json!(2),
        "preparation publication schema",
    )?;
    equal(
        &qualification["cancelled"],
        &json!(false),
        "uncancelled final publication",
    )?;
    let report = load(&output.join("receipt.json"))?;
    let mut inventory = super::guest::evidence_inventory(output)?;
    inventory
        .as_object_mut()
        .ok_or("inventory object")?
        .remove("qualification.json");
    equal(
        &qualification["files"],
        &inventory,
        "exact preparation raw inventory",
    )?;
    equal(
        &report["schema_version"],
        &json!(2),
        "current Rust preparation schema",
    )?;
    require(
        diorama_dev::defaults::capture::successful(&report),
        "package/oracle preparation cleanup",
    )?;
    Ok(report)
}
pub(super) fn verify(root: &Path, output: &Path) -> Result<()> {
    let report = verify_publication(output)?;
    equal(
        &report["source_sha256"],
        &source_inventory(root, "alpine")?,
        "current preparation sources",
    )?;
    let inputs = load(&fixture(root, "alpine-preparation").join("inputs.json"))?;
    verify_commands(output, &report, &inputs)?;
    equal(
        &report["packages"],
        &inputs["packages"]["selected"],
        "full pinned package closure",
    )?;
    equal(
        &report["index_sha256"],
        &inputs["packages"]["index_sha256"],
        "index identity",
    )?;
    equal(
        &report["oracle_sha256"],
        &inputs["oracle"]["binary_sha256"],
        "oracle identity",
    )?;
    let source = report["baseline_source_and_binary"]
        .as_str()
        .ok_or("baseline source observation")?;
    require(
        source.lines().next()
            == Some(&format!(
                "{}  preflight.go",
                inputs["oracle"]["source_sha256"]
                    .as_str()
                    .ok_or("source digest")?
            )),
        "unchanged baseline source",
    )?;
    Ok(())
}
fn resolution_argv(tag: &str, name: &str) -> Vec<String> {
    [
        "docker",
        "run",
        "--name",
        name,
        "--read-only",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "256m",
        "--pids-limit",
        "64",
        "--tmpfs",
        "/tmp:rw,size=16m",
        "--tmpfs",
        "/var/cache/apk:rw,size=16m",
        tag,
        "apk",
        "fetch",
        "--simulate",
        "--recursive",
        "--url",
        "--no-network",
        "--repositories-file",
        "/repositories",
        "nftables=1.1.6-r1",
        "iptables=1.8.13-r0",
        "openrc=0.63.2-r0",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
fn closure(raw: &[u8], inputs: &Value) -> Result<Vec<String>> {
    let names = std::str::from_utf8(raw)?
        .lines()
        .filter(|line| {
            line.starts_with("/repo/aarch64/") || line.starts_with("file:///repo/aarch64/")
        })
        .map(|line| line.rsplit('/').next().unwrap_or("").to_owned())
        .collect::<Vec<_>>();
    require(
        !names.is_empty()
            && names.len() <= 64
            && names.iter().collect::<BTreeSet<_>>().len() == names.len(),
        "unique bounded resolved package closure",
    )?;
    let pins = inputs["packages"]["selected"]
        .as_object()
        .ok_or("package pins")?;
    equal(
        &json!(names.iter().collect::<BTreeSet<_>>()),
        &json!(pins.keys().collect::<BTreeSet<_>>()),
        "actual APK resolution pins",
    )?;
    Ok(names)
}
fn build_argv(tag: &str, context: &str) -> Vec<String> {
    [
        "docker",
        "build",
        "--platform",
        "linux/arm64",
        "-t",
        tag,
        "-f",
        &format!("{context}/Prepare.Dockerfile"),
        context,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
fn prepare_plan(
    output: &Path,
    report: &Value,
    inputs: &Value,
) -> Result<std::collections::BTreeMap<String, Vec<String>>> {
    let tag = report["image_tag"].as_str().ok_or("owned image tag")?;
    require(
        tag.starts_with("diorama-alpine-prepare")
            && tag.len() > "diorama-alpine-prepare".len()
            && tag
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "owned preparation image tag",
    )?;
    let container = format!("{tag}-resolve");
    equal(
        &report["containers"],
        &json!([container]),
        "single owned resolver",
    )?;
    let build = load(&output.join("build.command.json"))?;
    let context = build["argv"]
        .as_array()
        .and_then(|a| a.last())
        .and_then(Value::as_str)
        .ok_or("build context")?;
    require(
        Path::new(context).is_absolute()
            && Path::new(context).file_name().is_some_and(|n| {
                n.to_string_lossy()
                    .starts_with("diorama-alpine-prepare-source-")
            })
            && !Path::new(context)
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
        "owned preparation context",
    )?;
    let mut plan = std::collections::BTreeMap::new();
    plan.insert("build".into(), build_argv(tag, context));
    plan.insert(
        "image-inspect".into(),
        ["docker", "image", "inspect", tag]
            .into_iter()
            .map(str::to_owned)
            .collect(),
    );
    plan.insert("resolution".into(), resolution_argv(tag, &container));
    for (source, dest) in [
        ("/preflight.test", "preflight.test"),
        ("/source.sha256", "source.sha256"),
    ] {
        plan.insert(
            format!("copy-{}", dest.replace('.', "-")),
            vec![
                "docker".into(),
                "cp".into(),
                format!("{container}:{source}"),
                format!("{context}/{dest}"),
            ],
        );
    }
    let names = closure(&read(&output.join("resolution.log"), 65536)?, inputs)?;
    for (index, name) in names.iter().enumerate() {
        let url = format!("https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/{name}");
        equal(
            &inputs["packages"]["selected"][name]["url"],
            &json!(url),
            "official package URL",
        )?;
        plan.insert(
            format!("download-{index:03}"),
            vec![
                "curl".into(),
                "--fail".into(),
                "--location".into(),
                "--proto".into(),
                "=https".into(),
                "--max-time".into(),
                "30".into(),
                "--max-filesize".into(),
                "16777216".into(),
                "--output".into(),
                format!("{context}/{name}"),
                url,
            ],
        );
    }
    for (index, argv) in cleanup_plan(tag, &container).into_iter().enumerate() {
        plan.insert(format!("cleanup-{}", index + 1), argv);
    }
    Ok(plan)
}
fn cleanup_plan(tag: &str, container: &str) -> Vec<Vec<String>> {
    Vec::from([
        vec![
            "docker".into(),
            "rm".into(),
            "--force".into(),
            container.into(),
        ],
        vec![
            "docker".into(),
            "image".into(),
            "rm".into(),
            "--force".into(),
            tag.into(),
        ],
        vec![
            "docker".into(),
            "ps".into(),
            "-aq".into(),
            "--filter".into(),
            format!("name=^/{}$", regex::escape(container)),
        ],
        vec![
            "docker".into(),
            "images".into(),
            "--no-trunc".into(),
            "-q".into(),
            "--filter".into(),
            format!("reference={tag}"),
        ],
    ])
}
fn verify_commands(output: &Path, report: &Value, inputs: &Value) -> Result<()> {
    for key in ["process_failures", "retained_build_contexts"] {
        equal(
            &report[key],
            &json!([]),
            "no retained failed command or context",
        )?;
    }
    let plan = prepare_plan(output, report, inputs)?;
    let mut expected = BTreeSet::from([
        "qualification.json".to_owned(),
        "receipt.json".into(),
        "source.sha256".into(),
    ]);
    for (label, argv) in plan {
        let raw = super::command_evidence::verify_merged_command(output, &label, &argv, &[0])?;
        if label == "image-inspect" {
            verify_image(&raw, report)?;
        }
        if ["cleanup-3", "cleanup-4"].contains(&label.as_str()) {
            require(
                std::str::from_utf8(&raw)?.trim().is_empty(),
                "owned preparation resource remains",
            )?;
        }
        expected.insert(format!("{label}.log"));
        expected.insert(format!("{label}.command.json"));
    }
    let actual = super::guest::evidence_inventory(output)?
        .as_object()
        .ok_or("raw inventory")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    equal(
        &json!(actual),
        &json!(expected),
        "exact mandatory preparation artifacts",
    )?;
    let source = text_source(&output.join("source.sha256"))?;
    equal(
        &report["baseline_source_and_binary"],
        &json!(source),
        "raw copied source inventory",
    )?;
    equal(
        &json!(source),
        &json!(format!(
            "{}  preflight.go\n{}  /preflight.test\n",
            inputs["oracle"]["source_sha256"]
                .as_str()
                .ok_or("source pin")?,
            inputs["oracle"]["binary_sha256"]
                .as_str()
                .ok_or("binary pin")?
        )),
        "exact source and compiled binary pins",
    )
}
fn verify_image(raw: &[u8], report: &Value) -> Result<()> {
    let image = diorama_dev::json::parse(raw)?;
    equal(&image, &report["image"], "raw image inspection")?;
    let id = image[0]["Id"].as_str().ok_or("image ID")?;
    require(
        image.as_array().is_some_and(|rows| rows.len() == 1)
            && image[0]["Os"] == "linux"
            && image[0]["Architecture"] == "arm64"
            && regex::Regex::new("^sha256:[a-f0-9]{64}$")?.is_match(id),
        "exact Linux arm64 preparation image",
    )?;
    equal(
        &report["image_id"],
        &json!(id),
        "owned inspected image identity",
    )
}

#[cfg(test)]
mod evidence_tests {
    use super::*;
    fn write_json(path: &Path, value: &Value) -> Result<()> {
        fs::write(path, serde_json::to_vec(value)?)?;
        Ok(())
    }
    fn command(output: &Path, label: &str, argv: &[String], raw: &[u8]) -> Result<()> {
        fs::write(output.join(format!("{label}.log")), raw)?;
        write_json(
            &output.join(format!("{label}.command.json")),
            &json!({"argv":argv,"spawned":true,"exit_code":0,"owned_pid":1234,"owner_directory":"/tmp/synthetic-owner","owned_process_group_absent":true,"cleanup_complete":true,"cleanup_errors":[],"output_eof":true,"timeout":false,"cancelled":false,"merged_output":true,"output_limit":false,"stdout_sha256":diorama_dev::sha256(raw),"stderr_sha256":diorama_dev::sha256(b"")}),
        )
    }
    fn report() -> Value {
        json!({"schema_version":2,"image_tag":"diorama-alpine-prepareunit","containers":["diorama-alpine-prepareunit-resolve"],"errors":[],"cleanup_errors":[],"process_failures":[],"retained_build_contexts":[],"remaining_containers":[],"remaining_images":[],"process_cleanup_complete":true,"cancelled":false})
    }
    fn fixture() -> Result<(tempfile::TempDir, Value)> {
        let root = diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
        let inputs = load(&super::super::fixture(&root, "alpine-preparation").join("inputs.json"))?;
        let dir = tempfile::tempdir()?;
        let output = dir.path();
        let mut report = report();
        let id = format!("sha256:{}", "a".repeat(64));
        report["image_id"] = json!(id);
        report["image"] = json!([{"Id":id,"Architecture":"arm64","Os":"linux"}]);
        let source = format!(
            "{}  preflight.go\n{}  /preflight.test\n",
            inputs["oracle"]["source_sha256"]
                .as_str()
                .ok_or("source pin")?,
            inputs["oracle"]["binary_sha256"]
                .as_str()
                .ok_or("binary pin")?
        );
        report["baseline_source_and_binary"] = json!(source);
        fs::write(output.join("source.sha256"), source)?;
        let mut raw = String::new();
        for name in inputs["packages"]["selected"]
            .as_object()
            .ok_or("pins")?
            .keys()
        {
            use std::fmt::Write as _;
            writeln!(&mut raw, "/repo/aarch64/{name}")?;
        }
        fs::write(output.join("resolution.log"), &raw)?;
        write_json(
            &output.join("build.command.json"),
            &json!({"argv":["/tmp/diorama-alpine-prepare-source-synthetic"]}),
        )?;
        let plan = prepare_plan(output, &report, &inputs)?;
        for (label, argv) in plan {
            let bytes = match label.as_str() {
                "image-inspect" => serde_json::to_vec(&report["image"])?,
                "resolution" => raw.as_bytes().to_vec(),
                _ => vec![],
            };
            command(output, &label, &argv, &bytes)?;
        }
        write_json(&output.join("receipt.json"), &report)?;
        publish_qualification(
            output,
            &report,
            &diorama_dev::process::Cancellation::default(),
            || {},
        )?;
        verify_publication(output)?;
        verify_commands(output, &report, &inputs)?;
        Ok((dir, inputs))
    }
    fn reseal(output: &Path) -> Result<()> {
        let mut inventory = super::super::guest::evidence_inventory(output)?;
        inventory
            .as_object_mut()
            .ok_or("inventory")?
            .remove("qualification.json");
        write_json(
            &output.join("qualification.json"),
            &json!({"schema_version":2,"files":inventory,"cancelled":false}),
        )
    }
    #[test]
    fn cancellation_during_final_publication_cannot_claim_success() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let report = report();
        write_json(&dir.path().join("receipt.json"), &report)?;
        let cancellation = diorama_dev::process::Cancellation::default();
        assert_eq!(
            publish_qualification(dir.path(), &report, &cancellation, || cancellation
                .request())?,
            1
        );
        assert!(verify_publication(dir.path()).is_err());
        Ok(())
    }
    #[test]
    fn rehashed_prepare_cleanup_exit_argv_and_missing_command_fabrications_fail() -> Result<()> {
        for kind in [
            "cleanup", "exit", "argv", "missing", "image", "source", "closure",
        ] {
            let (dir, inputs) = fixture()?;
            let output = dir.path();
            match kind {
                "cleanup" => {
                    let path = output.join("cleanup-3.command.json");
                    let mut value = load(&path)?;
                    fs::write(output.join("cleanup-3.log"), b"owned-still-present\n")?;
                    value["stdout_sha256"] = json!(diorama_dev::sha256(b"owned-still-present\n"));
                    write_json(&path, &value)?;
                },
                "exit" | "argv" => {
                    let path = output.join("download-000.command.json");
                    let mut value = load(&path)?;
                    if kind == "exit" {
                        value["exit_code"] = json!(1);
                    } else {
                        value["argv"] = json!(["curl", "https://unreviewed.invalid"]);
                    }
                    write_json(&path, &value)?;
                },
                "missing" => fs::remove_file(output.join("copy-preflight-test.command.json"))?,
                "image" => {
                    let mut report = load(&output.join("receipt.json"))?;
                    report["image"][0]["Id"] = json!(format!("sha256:{}", "b".repeat(64)));
                    let raw = serde_json::to_vec(&report["image"])?;
                    fs::write(output.join("image-inspect.log"), &raw)?;
                    let path = output.join("image-inspect.command.json");
                    let mut receipt = load(&path)?;
                    receipt["stdout_sha256"] = json!(diorama_dev::sha256(&raw));
                    write_json(&path, &receipt)?;
                    write_json(&output.join("receipt.json"), &report)?;
                },
                "source" => {
                    let raw = "fabricated source\n";
                    fs::write(output.join("source.sha256"), raw)?;
                    let mut report = load(&output.join("receipt.json"))?;
                    report["baseline_source_and_binary"] = json!(raw);
                    write_json(&output.join("receipt.json"), &report)?;
                },
                _ => {
                    let raw = b"/repo/aarch64/unknown.apk\n";
                    fs::write(output.join("resolution.log"), raw)?;
                    let path = output.join("resolution.command.json");
                    let mut value = load(&path)?;
                    value["stdout_sha256"] = json!(diorama_dev::sha256(raw));
                    write_json(&path, &value)?;
                },
            }
            reseal(output)?;
            let report = verify_publication(output)?;
            assert!(verify_commands(output, &report, &inputs).is_err(), "{kind}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_publication_rejects_wrong_bytes_and_links_without_overwrite() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("cache");
        let hash = diorama_dev::sha256(b"expected");
        assert!(publish(&path, b"wrong", &hash).is_err());
        assert!(!path.exists());
        publish(&path, b"expected", &hash)?;
        assert!(publish(&path, b"changed", &diorama_dev::sha256(b"changed")).is_err());
        assert_eq!(fs::read(&path)?, b"expected");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link)?;
        assert!(publish(&link, b"expected", &hash).is_err());
        Ok(())
    }
}
