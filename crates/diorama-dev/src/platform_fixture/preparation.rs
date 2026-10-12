//! Read-only prerequisite artifact verification shared by Alpine qualification.
use super::{
    BTreeMap, Path, Result, Value, digest, equal, fixture, json, load, require, source_inventory,
    text,
};
use std::collections::BTreeSet;
#[allow(
    clippy::too_many_lines,
    reason = "Independent exact prerequisite behavior oracle"
)]
pub(crate) fn verify_run(raw: &str) -> Result<Value> {
    require(
        raw.matches("test result: ok. 6 passed;").count() == 1
            && raw.matches("test result: ok. 7 passed;").count() == 2,
        "Rust prerequisite test completion",
    )?;
    let regex = regex::Regex::new(r"(?m)^([a-f0-9]{64})  /out/([a-z-]+)$")?;
    let binaries = regex
        .captures_iter(raw)
        .map(|c| (c[2].to_owned(), c[1].to_owned()))
        .collect::<Vec<_>>();
    require(
        binaries.len() == 5
            && binaries
                .iter()
                .map(|(_, hash)| hash)
                .collect::<BTreeSet<_>>()
                .len()
                == 5,
        "five distinct compiled identities",
    )?;
    equal(
        &json!(
            binaries
                .iter()
                .map(|(name, _)| name)
                .collect::<BTreeSet<_>>()
        ),
        &json!([
            "check-tests",
            "fixture-command",
            "preparation-tests",
            "dioramactl",
            "dioramactl-tests"
        ]),
        "binary inventory",
    )?;
    let records = raw
        .lines()
        .filter_map(|line| line.strip_prefix("DIORAMA_PREPARATION "))
        .map(|line| diorama_dev::json::parse(line.as_bytes()))
        .collect::<Result<Vec<_>>>()?;
    require(records.len() == 1, "one preparation observation")?;
    let record = &records[0];
    equal(
        &json!(
            record
                .as_object()
                .ok_or("record object")?
                .keys()
                .collect::<Vec<_>>()
        ),
        &json!(["cases"]),
        "record keys",
    )?;
    let rows = record["cases"].as_array().ok_or("case array")?;
    let mut names = [
        "opt_out",
        "prepare",
        "repeat",
        "no_effect_success",
        "register_failure",
        "nonroot",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    names.extend((0..20).map(|i| format!("signal_{i}")));
    require(
        rows.len() == names.len(),
        "exact preparation case inventory",
    )?;
    let apk = "/sbin/apk add --no-cache nftables iptables";
    let update = "/sbin/rc-update add cgroups boot";
    let start = "/sbin/rc-service cgroups start";
    for (row, name) in rows.iter().zip(names) {
        equal(
            &json!(
                row.as_object()
                    .ok_or("case object")?
                    .keys()
                    .collect::<Vec<_>>()
            ),
            &json!([
                "actions",
                "exit",
                "name",
                "owned_child_absent",
                "signal_sent",
                "stderr",
                "stdout"
            ]),
            "case schema",
        )?;
        equal(&row["name"], &json!(name), "case name")?;
        let success = ["prepare", "repeat"].contains(&name.as_str());
        equal(&row["exit"], &json!(i32::from(!success)), "case exit")?;
        equal(&row["stdout"], &json!(""), "stdout")?;
        let stderr = row["stderr"].as_str().ok_or("stderr string")?;
        let actions = match name.as_str() {
            "opt_out" | "nonroot" => vec![],
            "prepare" | "repeat" => vec![apk, update, start],
            "register_failure" => vec![apk, update],
            _ => vec![apk],
        };
        equal(&row["actions"], &json!(actions), "exact command order")?;
        let signal = name
            .strip_prefix("signal_")
            .map(str::parse::<u32>)
            .transpose()?;
        equal(
            &row["owned_child_absent"],
            &json!(signal.is_some()),
            "owned child absence",
        )?;
        equal(
            &row["signal_sent"],
            &json!(signal.map(|number| if number % 2 == 0 { 2 } else { 15 })),
            "delivered signal",
        )?;
        require(
            stderr.contains("All 7 checks passed") == success,
            "no false success",
        )?;
        if ["register_failure", "no_effect_success"].contains(&name.as_str()) || signal.is_some() {
            require(
                stderr.contains("host state may have changed"),
                "partial effects warning",
            )?;
        }
    }
    Ok(json!({"record":record,"binaries":binaries.into_iter().collect::<BTreeMap<_,_>>()}))
}
#[allow(
    clippy::too_many_lines,
    clippy::items_after_statements,
    reason = "Audit exact compiled inventory and artifact provenance together"
)]
pub(crate) fn verify_core(root: &Path, directory: &Path) -> Result<Value> {
    let receipt = load(&directory.join("receipt.json"))?;
    equal(
        &receipt["schema_version"],
        &json!(2),
        "current Rust prerequisite capture schema",
    )?;
    let revision = receipt["revision"].as_str().ok_or("source revision")?;
    require(
        regex::Regex::new(r"^[a-f0-9]{40}$")?.is_match(revision),
        "exact source revision",
    )?;
    require(
        regex::Regex::new(r"^sha256:[a-f0-9]{64}$")?
            .is_match(receipt["image_id"].as_str().ok_or("builder image")?),
        "exact builder image",
    )?;
    equal(
        &receipt["source_sha256"],
        &source_inventory(root, "prerequisite")?,
        "current prerequisite harness sources",
    )?;
    let containers = receipt["containers"]
        .as_array()
        .ok_or("container inventory")?;
    require(
        containers.len() == 1,
        "single owned qualification container",
    )?;
    let container = containers[0].as_str().ok_or("container name")?;
    require(
        regex::Regex::new(r"^diorama-preparation-linux-[a-f0-9]{32}-test$")?.is_match(container),
        "owned container identity",
    )?;
    let tag = container.strip_suffix("-test").ok_or("container suffix")?;
    equal(
        &receipt["command"],
        &json!([
            "docker",
            "run",
            "--name",
            container,
            "--hostname",
            "fixture",
            "--init",
            "--read-only",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "SYS_CHROOT",
            "--cap-add",
            "SETUID",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            "256m",
            "--cpus",
            "2",
            "--pids-limit",
            "64",
            "--tmpfs",
            "/tmp:rw,exec,nosuid,nodev,size=32m",
            tag
        ]),
        "exact isolated qualification command",
    )?;
    for key in [
        "errors",
        "cleanup_errors",
        "remaining_containers",
        "remaining_images",
    ] {
        equal(&receipt[key], &json!([]), key)?;
    }
    equal(
        &receipt["process_cleanup_complete"],
        &json!(true),
        "settled prerequisite commands",
    )?;
    equal(
        &receipt["cancelled"],
        &json!(false),
        "uncancelled prerequisite capture",
    )?;
    let argv = receipt["command"]
        .as_array()
        .ok_or("run argv")?
        .iter()
        .map(|arg| {
            arg.as_str()
                .map(str::to_owned)
                .ok_or("string argument".into())
        })
        .collect::<Result<Vec<String>>>()?;
    super::command_evidence::verify_merged_command(directory, "run", &argv, &[0])?;
    equal(&receipt["platform"], &json!("linux/arm64"), "platform")?;
    equal(
        &receipt["target"],
        &json!("aarch64-unknown-linux-musl"),
        "target",
    )?;
    equal(
        &receipt["uncommitted_implementation"],
        &json!(true),
        "working tree qualification",
    )?;
    let raw = text(&directory.join("run.log"))?;
    equal(
        &receipt["run_sha256"],
        &json!(diorama_dev::sha256(raw.as_bytes())),
        "raw run digest",
    )?;
    let result = verify_run(&raw)?;
    equal(
        &receipt["artifact_sha256"],
        &result["binaries"]["dioramactl"],
        "observed artifact identity",
    )?;
    let inventory = load(&directory.join("source-hashes.json"))?;
    equal(
        &receipt["inventory_sha256"],
        &json!(digest(&directory.join("source-hashes.json"))?),
        "source inventory digest",
    )?;
    let here = fixture(root, "prerequisite-preparation");
    equal(
        &inventory["Dockerfile"],
        &json!(digest(&here.join("Linux.Dockerfile"))?),
        "builder source",
    )?;
    let mut current = BTreeSet::from([
        "Cargo.toml".to_owned(),
        "Cargo.lock".into(),
        "rust-toolchain.toml".into(),
    ]);
    fn files(root: &Path, path: &Path, current: &mut BTreeSet<String>, all: bool) -> Result<()> {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            require(!kind.is_symlink(), "source inventory symlink")?;
            if entry.file_name() == "target" {
                continue;
            }
            if kind.is_dir() {
                files(root, &entry.path(), current, all)?;
            } else if kind.is_file() && (all || entry.file_name() == "Cargo.toml") {
                current.insert(
                    entry
                        .path()
                        .strip_prefix(root)?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
        Ok(())
    }
    for directory in ["crates", "third_party", "tools/upstream", "tools/dev"] {
        files(root, &root.join(directory), &mut current, false)?;
    }
    for directory in [
        ".cargo",
        "tools/dev/src",
        "crates/dioramactl/src",
        "crates/dioramactl/tests",
        "crates/diorama-platform/src",
        "crates/diorama-platform/tests",
        "crates/diorama-supervisor/src",
        "crates/diorama-supervisor/tests",
    ] {
        let path = root.join(directory);
        if path.exists() {
            files(root, &path, &mut current, true)?;
        }
    }
    for name in [
        "management-check/cases.json",
        "management-check/expected.json",
        "prerequisite-preparation/fixture-command.rs",
    ] {
        current.insert(format!("tools/parity/fixtures/{name}"));
    }
    let relevant = |name: &str| {
        name == "Cargo.toml"
            || name == "Cargo.lock"
            || name == "rust-toolchain.toml"
            || name.ends_with("/Cargo.toml")
            || name.starts_with(".cargo/")
            || name.starts_with("tools/dev/src/")
            || [
                "crates/dioramactl/",
                "crates/diorama-platform/",
                "crates/diorama-supervisor/",
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix))
                && Path::new(name).extension() == Some(std::ffi::OsStr::new("rs"))
            || [
                "tools/parity/fixtures/management-check/cases.json",
                "tools/parity/fixtures/management-check/expected.json",
                "tools/parity/fixtures/prerequisite-preparation/fixture-command.rs",
            ]
            .contains(&name)
    };
    current.retain(|name| relevant(name));
    equal(
        &json!(
            inventory
                .as_object()
                .ok_or("compiled inventory")?
                .keys()
                .filter(|name| relevant(name))
                .collect::<BTreeSet<_>>()
        ),
        &json!(current),
        "exact compiled source namespace",
    )?;
    for name in current {
        equal(
            &inventory[&name],
            &json!(digest(&root.join(&name))?),
            &format!("compiled source {name}"),
        )?;
    }
    let artifact = load(&directory.join("artifact.json"))?;
    equal(
        &artifact["sha256"],
        &receipt["artifact_sha256"],
        "artifact metadata",
    )?;
    equal(
        &artifact["revision"],
        &receipt["revision"],
        "artifact revision",
    )?;
    let binary = directory.join("dioramactl");
    {
        equal(
            &json!(digest(&binary)?),
            &artifact["sha256"],
            "exported binary",
        )?;
        equal(
            &json!(std::fs::metadata(binary)?.len()),
            &artifact["size"],
            "exported size",
        )?;
    }
    verify_commands(directory, &receipt, tag, container)?;
    Ok(receipt)
}
pub(crate) fn evidence_inventory(directory: &Path) -> Result<Value> {
    let mut names = vec![
        "receipt.json".to_owned(),
        "source-hashes.json".into(),
        "artifact.json".into(),
        "dioramactl".into(),
    ];
    for label in [
        "revision",
        "build",
        "image-inspect",
        "run",
        "artifact-copy",
        "cleanup-1",
        "cleanup-2",
        "cleanup-3",
        "cleanup-4",
    ] {
        names.extend([format!("{label}.log"), format!("{label}.command.json")]);
    }
    let mut inventory = BTreeMap::new();
    for name in names {
        inventory.insert(name.clone(), digest(&directory.join(name))?);
    }
    Ok(json!(inventory))
}
pub(crate) fn verify(root: &Path, directory: &Path) -> Result<Value> {
    let qualification = load(&directory.join("qualification.json"))?;
    equal(
        &qualification["schema_version"],
        &json!(2),
        "current final qualification",
    )?;
    equal(
        &qualification["cancelled"],
        &json!(false),
        "uncancelled final verification",
    )?;
    equal(
        &qualification["files"],
        &evidence_inventory(directory)?,
        "full command and artifact inventory",
    )?;
    verify_core(root, directory)
}
fn verify_commands(directory: &Path, receipt: &Value, tag: &str, container: &str) -> Result<()> {
    use super::command_evidence::verify_merged_command as command;
    let recorded = load(&directory.join("revision.command.json"))?;
    let original_root = recorded["argv"][2]
        .as_str()
        .ok_or("recorded checkout path")?;
    require(
        Path::new(original_root).is_absolute()
            && !Path::new(original_root)
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir)),
        "absolute original checkout without traversal",
    )?;

    let output = Path::new(
        receipt["output_directory"]
            .as_str()
            .ok_or("original output directory")?,
    );
    require(output.is_absolute(), "absolute original output")?;
    let revision = command(
        directory,
        "revision",
        &[
            "git".into(),
            "-C".into(),
            original_root.into(),
            "rev-parse".into(),
            "HEAD".into(),
        ],
        &[0],
    )?;
    equal(
        &json!(std::str::from_utf8(&revision)?.trim()),
        &receipt["revision"],
        "actual revision",
    )?;
    let build = load(&directory.join("build.command.json"))?;
    let context = build["argv"][6].as_str().ok_or("build context")?;
    require(
        Path::new(context).is_absolute()
            && !Path::new(context)
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
            && Path::new(context).file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("diorama-prerequisite-build-")
            }),
        "owned context",
    )?;
    command(
        directory,
        "build",
        &[
            "docker".into(),
            "build".into(),
            "--platform".into(),
            "linux/arm64".into(),
            "-t".into(),
            tag.into(),
            context.into(),
        ],
        &[0],
    )?;
    let image = command(
        directory,
        "image-inspect",
        &[
            "docker".into(),
            "image".into(),
            "inspect".into(),
            tag.into(),
        ],
        &[0],
    )?;
    verify_image(&image, receipt, tag)?;
    command(
        directory,
        "artifact-copy",
        &[
            "docker".into(),
            "cp".into(),
            format!("{container}:/dioramactl"),
            output
                .join("dioramactl")
                .to_str()
                .ok_or("artifact UTF8")?
                .into(),
        ],
        &[0],
    )?;
    let cleanup = cleanup_argv(tag, container);
    for (index, argv) in cleanup.iter().enumerate() {
        let raw = command(directory, &format!("cleanup-{}", index + 1), argv, &[0])?;
        if index >= 2 {
            require(
                raw.iter().all(u8::is_ascii_whitespace),
                "owned Docker inventory not empty",
            )?;
        }
    }
    Ok(())
}
fn verify_image(image: &[u8], receipt: &Value, tag: &str) -> Result<()> {
    let rows = diorama_dev::json::parse(image)?;
    require(
        rows.as_array().is_some_and(|rows| rows.len() == 1),
        "single inspected image",
    )?;
    equal(&rows, &receipt["image"], "actual image inspection")?;
    equal(&rows[0]["Id"], &receipt["image_id"], "owned image identity")?;
    require(
        rows[0]["RepoTags"]
            .as_array()
            .is_some_and(|tags| tags.contains(&json!(format!("{tag}:latest")))),
        "owned inspected image tag",
    )?;
    Ok(())
}
fn cleanup_argv(tag: &str, container: &str) -> [Vec<String>; 4] {
    [
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
    ]
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_prerequisite_observations_reject_exit_action_and_signal_mutations() -> Result<()> {
        let root = diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
        let raw = text(&fixture(&root, "prerequisite-preparation").join("evidence-linux/run.log"))?;
        verify_run(&raw)?;
        let line = raw
            .lines()
            .find(|line| line.starts_with("DIORAMA_PREPARATION "))
            .ok_or("actual observation")?;
        let original = diorama_dev::json::parse(
            line.strip_prefix("DIORAMA_PREPARATION ")
                .ok_or("marker")?
                .as_bytes(),
        )?;
        for key in ["exit", "actions", "owned_child_absent", "signal_sent"] {
            let mut record = original.clone();
            record["cases"][6][key] = match key {
                "exit" => json!(0),
                "actions" => json!([]),
                "owned_child_absent" => json!(false),
                _ => json!(15),
            };
            let changed = raw.replace(
                line,
                &format!("DIORAMA_PREPARATION {}", serde_json::to_string(&record)?),
            );
            assert!(verify_run(&changed).is_err(), "{key}");
        }
        assert!(
            verify_run(&raw.replace("test result: ok. 6 passed;", "test result: ok. 5 passed;"))
                .is_err()
        );
        Ok(())
    }
    #[test]
    fn prerequisite_commands_reject_rehashed_cleanup_and_wrong_image() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root =
            diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?.canonicalize()?;
        let output = directory.path().canonicalize()?;
        let tag = format!("diorama-preparation-linux-{}", "a".repeat(32));
        let container = format!("{tag}-test");
        let id = format!("sha256:{}", "b".repeat(64));
        let image = json!([{"Id":id,"RepoTags":[format!("{tag}:latest")]}]);
        let revision = "c".repeat(40);
        let report =
            json!({"revision":revision,"image":image,"image_id":id,"output_directory":output});
        synthetic_commands(&root, &output, &tag, &container, &report)?;
        verify_commands(&output, &report, &tag, &container)?;
        let mut changed = report.clone();
        changed["image_id"] = json!(format!("sha256:{}", "d".repeat(64)));
        assert!(verify_commands(&output, &changed, &tag, &container).is_err());
        for label in ["cleanup-3", "cleanup-4"] {
            let path = output.join(format!("{label}.command.json"));
            let original = load(&path)?;
            let mut changed = original.clone();
            std::fs::write(output.join(format!("{label}.log")), b"leftover\n")?;
            changed["stdout_sha256"] = json!(diorama_dev::sha256(b"leftover\n"));
            crate::parity::write_json(&path, &changed, false)?;
            assert!(verify_commands(&output, &report, &tag, &container).is_err());
            std::fs::write(output.join(format!("{label}.log")), b"")?;
            crate::parity::write_json(&path, &original, false)?;
        }
        std::fs::remove_file(output.join("build.command.json"))?;
        assert!(verify_commands(&output, &report, &tag, &container).is_err());
        assert!(evidence_inventory(&output).is_err());
        Ok(())
    }
    #[test]
    fn recorded_checkout_and_output_paths_survive_evidence_relocation() -> Result<()> {
        let original = tempfile::tempdir()?;
        let moved = tempfile::tempdir()?;
        let output = original.path().canonicalize()?;
        let tag = format!("diorama-preparation-linux-{}", "a".repeat(32));
        let container = format!("{tag}-test");
        let image_id = format!("sha256:{}", "b".repeat(64));
        let report = json!({"revision":"c".repeat(40),"image":[{"Id":image_id,"RepoTags":[format!("{tag}:latest")]}],"image_id":image_id,"output_directory":output});
        // This source checkout need not exist on the machine replaying the receipt.
        synthetic_commands(
            Path::new("/original/build/checkout"),
            &output,
            &tag,
            &container,
            &report,
        )?;
        for entry in std::fs::read_dir(&output)? {
            let entry = entry?;
            std::fs::copy(entry.path(), moved.path().join(entry.file_name()))?;
        }
        verify_commands(moved.path(), &report, &tag, &container)?;
        let path = moved.path().join("revision.command.json");
        let receipt = load(&path)?;
        for original_root in ["relative/checkout", "/original/../different"] {
            let mut changed = receipt.clone();
            changed["argv"][2] = json!(original_root);
            crate::parity::write_json(&path, &changed, false)?;
            assert!(verify_commands(moved.path(), &report, &tag, &container).is_err());
        }
        for (index, value) in [
            (0, "not-git"),
            (1, "--git-dir"),
            (3, "status"),
            (4, "other-revision"),
        ] {
            let mut changed = receipt.clone();
            changed["argv"][index] = json!(value);
            crate::parity::write_json(&path, &changed, false)?;
            assert!(verify_commands(moved.path(), &report, &tag, &container).is_err());
        }
        Ok(())
    }
    fn synthetic_commands(
        root: &Path,
        output: &Path,
        tag: &str,
        container: &str,
        report: &Value,
    ) -> Result<()> {
        let mut rows = vec![
            (
                "revision".to_owned(),
                vec![
                    "git".into(),
                    "-C".into(),
                    root.to_str().ok_or("root")?.into(),
                    "rev-parse".into(),
                    "HEAD".into(),
                ],
                report["revision"]
                    .as_str()
                    .ok_or("revision")?
                    .as_bytes()
                    .to_vec(),
            ),
            (
                "build".into(),
                vec![
                    "docker".into(),
                    "build".into(),
                    "--platform".into(),
                    "linux/arm64".into(),
                    "-t".into(),
                    tag.into(),
                    "/tmp/diorama-prerequisite-build-fixture".into(),
                ],
                vec![],
            ),
            (
                "image-inspect".into(),
                vec![
                    "docker".into(),
                    "image".into(),
                    "inspect".into(),
                    tag.into(),
                ],
                serde_json::to_vec(&report["image"])?,
            ),
            (
                "artifact-copy".into(),
                vec![
                    "docker".into(),
                    "cp".into(),
                    format!("{container}:/dioramactl"),
                    output.join("dioramactl").to_str().ok_or("output")?.into(),
                ],
                vec![],
            ),
        ];
        rows.extend(
            cleanup_argv(tag, container)
                .into_iter()
                .enumerate()
                .map(|(i, argv)| (format!("cleanup-{}", i + 1), argv, vec![])),
        );
        for (label, argv, raw) in rows {
            let receipt = json!({"spawned":true,"owned_process_group_absent":true,"cleanup_complete":true,"output_eof":true,"cleanup_errors":[],"timeout":false,"cancelled":false,"merged_output":true,"output_limit":false,"owned_pid":123,"owner_directory":"/tmp/diorama-process-test","argv":argv,"exit_code":0,"stdout_sha256":diorama_dev::sha256(&raw),"stderr_sha256":diorama_dev::sha256(b"")});
            std::fs::write(output.join(format!("{label}.log")), raw)?;
            crate::parity::write_json(
                &output.join(format!("{label}.command.json")),
                &receipt,
                true,
            )?;
        }
        Ok(())
    }
}
