use super::super::{capture, common::*};
use super::*;
use std::{fmt::Write as _, fs};

#[test]
fn mutation_cases_have_explicit_rehashed_or_fixed_identity() {
    let rows = cases().unwrap();
    assert_eq!(rows.len(), 20);
    for row in rows {
        let raw = row["raw"].as_str().unwrap();
        assert_eq!(row["manifest_bytes"], raw.len());
        assert_eq!(
            row["manifest_sha256"] == sha256(raw.as_bytes()),
            row["name"] != "raw-identity"
        );
    }
}
#[test]
#[ignore = "source hash qualification receipt checks disabled"]
fn current_manifest_evidence_is_required() {
    let root = super::super::common::root().unwrap();
    super::super::capture::verify(
        &root,
        "manifest",
        &root.join("tools/assets-manifest/rust-evidence"),
    )
    .unwrap();
}
#[test]
#[ignore = "explicit retained archive and compiled consumer required"]
fn retained_consumer_matches_independent_cases() {
    let archive = std::env::var_os("DIORAMA_MANIFEST_ARCHIVE").unwrap();
    let consumer = std::env::var_os("DIORAMA_MANIFEST_CONSUMER").unwrap();
    let directory = tempfile::tempdir().unwrap();
    std::fs::copy(archive, directory.path().join("coredns.tar.gz")).unwrap();
    let mut requests = cases().unwrap();
    for row in &mut requests {
        row.as_object_mut().unwrap().remove("expected");
    }
    save(&directory.path().join("cases.json"), &json!(requests)).unwrap();
    let output = Command::new(consumer)
        .args(&CONSUMER[1..])
        .env("DIORAMA_MANIFEST_FIXTURE", directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let raw = std::str::from_utf8(&output.stdout).unwrap();
    consumer_records(raw).unwrap_or_else(|error| panic!("{error}: {raw}"));
}
fn bind(directory: &Path, receipt: &mut Value, label: &str, argv: &Value) -> Result<()> {
    let record = json!({"spawned":true,"owned_pid":123,"owner_directory":"/tmp/diorama-process-invented","owned_process_group_absent":true,"cleanup_complete":true,"output_eof":true,"cleanup_errors":[],"exit_code":0,"timeout":false,"cancelled":false,"argv":argv,"merged_output":true,"output_limit":false,"stdout_sha256":digest(&directory.join(format!("{label}.log")))?,"stderr_sha256":sha256(b"")});
    let path = directory.join(format!("{label}.command.json"));
    save(&path, &record)?;
    receipt["command_sha256"][label] = digest(&path)?.into();
    Ok(())
}

fn synthetic(directory: &Path) -> Result<Value> {
    let tag = format!("diorama-manifest-{}", "b".repeat(32));
    let context = "/tmp/diorama-asset-context-invented";
    let sources = inventory(&root()?, "manifest")?;
    save(&directory.join("source-inventory.json"), &sources)?;
    let raw = invented_raw()?;
    fs::write(directory.join("first.log"), &raw)?;
    fs::write(directory.join("repeat.log"), &raw)?;
    let (observations, binaries) = records(&directory.join("first.log"))?;
    let mut build = format!("#1 0.1 DIORAMA_BUILD_BEGIN {tag}\n");
    for name in capture::binaries("manifest")? {
        writeln!(build, "#1 0.2 {}  /out/{name}", string(&binaries[name])?)?;
    }
    writeln!(build, "#1 0.3 DIORAMA_BUILD_END {tag}")?;
    fs::write(directory.join("build.log"), build)?;
    let command = json!([
        "docker",
        "build",
        "--progress=plain",
        "--build-arg",
        format!("QUALIFICATION_NONCE={tag}"),
        "--platform=linux/arm64",
        "-t",
        tag,
        "-f",
        format!("{context}/tools/assets-manifest/Capture.Dockerfile"),
        context
    ]);
    let mut receipt = json!({"schema":3,"cancelled":false,"family":"manifest","revision":"c".repeat(40),"dirty":false,"tag":tag,"source_sha256":sources,"source_inventory_sha256":digest(&directory.join("source-inventory.json"))?,"containers":[format!("{tag}-first"),format!("{tag}-repeat")],"errors":[],"cleanup_errors":[],"remaining_containers":[],"remaining_images":[],"image_id":format!("sha256:{}","d".repeat(64)),"build_command":command,"build_log_sha256":digest(&directory.join("build.log"))?,"build_binary_sha256":binaries,"command_sha256":{},"runs":{}});
    bind(directory, &mut receipt, "build", &command)?;
    for name in ["first", "repeat"] {
        let command = json!(capture::command("manifest", &tag, name)?);
        receipt["runs"][name] = json!({"command":command,"raw_sha256":sha256(raw.as_bytes()),"binary_sha256":binaries,"records":observations});
        bind(directory, &mut receipt, name, &command)?;
    }
    for (label, argv) in capture::controls(&tag) {
        fs::write(
            directory.join(format!("{label}.log")),
            if label == "image-inspect" {
                format!("{}\n", string(&receipt["image_id"])?)
            } else {
                String::new()
            },
        )?;
        bind(directory, &mut receipt, label, &argv)?;
    }
    save(&directory.join("receipt.json"), &receipt)?;
    capture::verify(&root()?, "manifest", directory)?;
    Ok(receipt)
}

#[test]
fn manifest_receipts_bind_source_raw_commands_and_cleanup_after_rehash() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let original = synthetic(directory.path())?;
    for (key, value) in [
        ("schema", json!(1)),
        ("dirty", json!(true)),
        ("cancelled", json!(true)),
        ("source_sha256", json!({})),
        ("source_inventory_sha256", json!("0".repeat(64))),
        ("build_binary_sha256", json!({})),
        ("build_log_sha256", json!("0".repeat(64))),
        ("cleanup_errors", json!(["failed"])),
        ("remaining_containers", json!(["owned"])),
        ("remaining_images", Value::Null),
    ] {
        let mut changed = original.clone();
        changed[key] = value;
        save(&directory.path().join("receipt.json"), &changed)?;
        assert!(
            capture::verify(&root()?, "manifest", directory.path()).is_err(),
            "{key}"
        );
    }
    for label in [
        "build",
        "first",
        "repeat",
        "image-inspect",
        "cleanup-1",
        "cleanup-2",
        "cleanup-3",
        "cleanup-4",
        "cleanup-5",
    ] {
        let path = directory.path().join(format!("{label}.command.json"));
        let command = load(&path)?;
        for (key, value) in [
            ("argv", json!(["different"])),
            ("output_eof", json!(false)),
            ("cleanup_complete", json!(false)),
            ("exit_code", json!(1)),
            ("timeout", json!(true)),
            ("cancelled", json!(true)),
            ("output_limit", json!(true)),
            ("owned_process_group_absent", json!(false)),
        ] {
            let mut changed = command.clone();
            changed[key] = value;
            save(&path, &changed)?;
            let mut receipt = original.clone();
            receipt["command_sha256"][label] = digest(&path)?.into();
            save(&directory.path().join("receipt.json"), &receipt)?;
            assert!(
                capture::verify(&root()?, "manifest", directory.path()).is_err(),
                "{label}/{key}"
            );
        }
        save(&path, &command)?;
    }
    Ok(())
}
#[test]
fn equal_manifest_runtime_binary_substitution_still_fails_builder_binding() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut receipt = synthetic(directory.path())?;
    let old = string(&receipt["build_binary_sha256"]["producer"])?.to_owned();
    for name in ["first", "repeat"] {
        let path = directory.path().join(format!("{name}.log"));
        fs::write(&path, invented_raw()?.replace(&old, &"f".repeat(64)))?;
        let (rows, hashes) = records(&path)?;
        receipt["runs"][name]["raw_sha256"] = digest(&path)?.into();
        receipt["runs"][name]["records"] = rows;
        receipt["runs"][name]["binary_sha256"] = hashes;
        let command = receipt["runs"][name]["command"].clone();
        bind(directory.path(), &mut receipt, name, &command)?;
    }
    save(&directory.path().join("receipt.json"), &receipt)?;
    assert!(capture::verify(&root()?, "manifest", directory.path()).is_err());
    Ok(())
}
#[test]
fn manifest_graph_requires_complete_pins_and_its_own_main_module() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let pinned = root()?.join("tools/assets-manifest/modules.json");
    let rows = load(&pinned)?;
    let rows = array(&rows)?;
    let path = directory.path().join("graph.json");
    let write = |main: &str, rows: &[Value]| -> Result<()> {
        let mut raw = format!("{}\n", json!({"Path":main,"Main":true}));
        for row in rows {
            writeln!(raw, "{row}")?;
        }
        fs::write(&path, raw)?;
        Ok(())
    };
    let module = "diorama.invalid/assets-manifest-fixture";
    write(module, rows)?;
    archive::graph_module(&path, &pinned, module)?;
    write("diorama.invalid/assets-archive-fixture", rows)?;
    assert!(archive::graph_module(&path, &pinned, module).is_err());
    for key in ["Sum", "GoModSum", "Version", "Path"] {
        let mut changed = rows.clone();
        changed[0].as_object_mut().ok_or("module")?.remove(key);
        write(module, &changed)?;
        assert!(
            archive::graph_module(&path, &pinned, module).is_err(),
            "{key}"
        );
    }
    for (key, value) in [
        ("Replace", json!({"Path":"evil"})),
        ("Error", json!("failed")),
        ("Sum", json!("h1:changed")),
    ] {
        let mut changed = rows.clone();
        changed[0][key] = value;
        write(module, &changed)?;
        assert!(archive::graph_module(&path, &pinned, module).is_err());
    }
    write(module, &rows[..rows.len() - 1])?;
    assert!(archive::graph_module(&path, &pinned, module).is_err());
    Ok(())
}
fn invented_raw() -> Result<String> {
    let oracle = oracle::pinned_observation()?;
    let mut raw = String::new();
    for name in ["producer", "manifest-tests", "fixture"] {
        writeln!(raw, "{}  /{name}", "a".repeat(64))?;
    }
    writeln!(
        raw,
        "{PRODUCER}\nDIORAMA_ORACLE {oracle}\nrunning 1 test\ntest verify_pinned_crane_manifest ... ok"
    )?;
    writeln!(
        raw,
        "DIORAMA_BOUND {}",
        json!({"outer_sha256":oracle["outer_sha256"],"outer_bytes":oracle["outer_bytes"],"config_sha256":oracle["config_sha256"],"config_bytes":oracle["config_bytes"],"layers":oracle["layers"]})
    )?;
    let cases = cases()?;
    let expected = expected_cases(&cases)?;
    for row in &cases {
        writeln!(raw, "DIORAMA_MANIFEST {}", expected[string(&row["name"])?])?;
    }
    writeln!(
        raw,
        "DIORAMA_SYNTHETIC 8\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.1s"
    )?;
    writeln!(
        raw,
        "DIORAMA_COMPLETE {}",
        json!({"cases":cases.iter().map(|v|&v["name"]).collect::<Vec<_>>(),"consumer_command":CONSUMER})
    )?;
    writeln!(
        raw,
        "DIORAMA_NAMESPACE {}",
        json!({"init":1,"shell":7,"helper":8,"processes":[1,7,8]})
    )?;
    Ok(raw)
}
#[test]
fn manifest_logs_reject_rehashed_semantic_and_inventory_mutations() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("run.log");
    let raw = invented_raw()?;
    fs::write(&path, &raw)?;
    records(&path)?;
    for changed in [
        raw.replace("v0.21.5", "v0.21.4"),
        raw.replace("... ok", "... FAILED"),
        raw.replace("1 passed;", "0 passed;"),
        raw.replacen("DIORAMA_MANIFEST ", "DIORAMA_OTHER ", 1),
        raw.replace("\"budget_unchanged\":true", "\"budget_unchanged\":1"),
        raw.replace("\"status\":\"Config\"", "\"status\":\"ok\""),
        raw.replace("DIORAMA_SYNTHETIC 8", "DIORAMA_SYNTHETIC 7"),
        raw.replace("\"processes\":[1,7,8]", "\"processes\":[1,7,8,9]"),
        format!("{raw}DIORAMA_COMPLETE {{}}\n"),
    ] {
        assert_ne!(raw, changed);
        fs::write(&path, changed)?;
        assert!(records(&path).is_err());
    }
    for prefix in ["DIORAMA_ORACLE ", "DIORAMA_BOUND ", "DIORAMA_MANIFEST "] {
        let mut lines = raw.lines().map(str::to_owned).collect::<Vec<_>>();
        let index = lines
            .iter()
            .position(|line| line.starts_with(prefix))
            .unwrap();
        let mut row = strict(lines[index].strip_prefix(prefix).unwrap().as_bytes())?;
        if prefix == "DIORAMA_MANIFEST " {
            row["manifest_sha256"] = "0".repeat(64).into();
        } else {
            row["layers"][0]["diff_id"] = "0".repeat(64).into();
        }
        lines[index] = format!("{prefix}{row}");
        fs::write(&path, lines.join("\n") + "\n")?;
        assert!(records(&path).is_err());
        lines.remove(index);
        fs::write(&path, lines.join("\n") + "\n")?;
        assert!(records(&path).is_err());
    }
    Ok(())
}
#[test]
fn manifest_control_proofs_survive_relocation_and_reject_rehashed_lies() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let original = synthetic(directory.path())?;
    for label in ["image-inspect", "cleanup-4", "cleanup-5"] {
        let path = directory.path().join(format!("{label}.log"));
        let raw = fs::read(&path)?;
        let command_path = directory.path().join(format!("{label}.command.json"));
        let command = load(&command_path)?;
        fs::write(&path, "sha256:unremoved\n")?;
        let mut receipt = original.clone();
        bind(directory.path(), &mut receipt, label, &command["argv"])?;
        save(&directory.path().join("receipt.json"), &receipt)?;
        assert!(capture::verify(&root()?, "manifest", directory.path()).is_err());
        fs::write(path, raw)?;
        save(&command_path, &command)?;
    }
    save(&directory.path().join("receipt.json"), &original)?;
    let relocated = tempfile::tempdir()?;
    for entry in fs::read_dir(directory.path())? {
        let entry = entry?;
        fs::copy(entry.path(), relocated.path().join(entry.file_name()))?;
    }
    capture::verify(&root()?, "manifest", relocated.path())?;
    fs::remove_file(relocated.path().join("cleanup-5.command.json"))?;
    assert!(capture::verify(&root()?, "manifest", relocated.path()).is_err());
    Ok(())
}
#[test]
fn every_asset_family_binds_and_copies_compile_time_manifest_inputs() -> Result<()> {
    for family in ["elf", "decode", "archive", "layer", "manifest"] {
        let sources = inventory(&root()?, family)?;
        for name in ["inputs.json", "archive-pin.json", "arm64-manifest.json"] {
            assert_eq!(
                sources[format!("tools/assets-manifest/{name}")],
                digest(&root()?.join(format!("tools/assets-manifest/{name}")))?
            );
        }
        let directories = capture::context_directories(family);
        assert_eq!(
            directories
                .iter()
                .filter(|name| *name == "tools/assets-manifest")
                .count(),
            1
        );
        assert!(directories.contains(&format!("tools/assets-{family}")));
    }
    Ok(())
}
