use super::super::{capture, common::*};
use super::*;
use std::{fmt::Write as _, fs};

fn historical_raw() -> Result<String> {
    // Old execution bytes exercise the new oracle, never the current-capture gate.
    let raw = String::from_utf8(read(
        &root()?.join("tools/assets-layer/evidence/first.log"),
        2 * 1024 * 1024,
    )?)?;
    let mut lines = raw.lines().map(str::to_owned).collect::<Vec<_>>();
    lines.insert(2, format!("{}  /fixture", "a".repeat(64)));
    Ok(lines.join("\n") + "\n")
}

fn bind(directory: &Path, receipt: &mut Value, label: &str, argv: &Value) -> Result<()> {
    let record = json!({"spawned":true,"owned_pid":123,"owner_directory":"/tmp/diorama-process-invented","owned_process_group_absent":true,"cleanup_complete":true,"output_eof":true,"cleanup_errors":[],"exit_code":0,"timeout":false,"cancelled":false,"argv":argv,"merged_output":true,"output_limit":false,"stdout_sha256":digest(&directory.join(format!("{label}.log")))?,"stderr_sha256":sha256(b"")});
    let path = directory.join(format!("{label}.command.json"));
    save(&path, &record)?;
    receipt["command_sha256"][label] = digest(&path)?.into();
    Ok(())
}

fn synthetic(directory: &Path) -> Result<Value> {
    let tag = format!("diorama-layer-{}", "b".repeat(32));
    let context = "/tmp/diorama-asset-context-invented";
    let sources = inventory(&root()?, "layer")?;
    save(&directory.join("source-inventory.json"), &sources)?;
    let raw = historical_raw()?;
    fs::write(directory.join("first.log"), &raw)?;
    fs::write(directory.join("repeat.log"), &raw)?;
    let (observations, binaries) = records(&directory.join("first.log"))?;
    let mut build = format!("#1 0.1 DIORAMA_BUILD_BEGIN {tag}\n");
    for name in capture::binaries("layer")? {
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
        format!("{context}/tools/assets-layer/Capture.Dockerfile"),
        context
    ]);
    let mut receipt = json!({"schema":3,"cancelled":false,"family":"layer","revision":"c".repeat(40),"dirty":false,"tag":tag,"source_sha256":sources,"source_inventory_sha256":digest(&directory.join("source-inventory.json"))?,"containers":[format!("{tag}-first"),format!("{tag}-repeat")],"errors":[],"cleanup_errors":[],"remaining_containers":[],"remaining_images":[],"image_id":format!("sha256:{}","d".repeat(64)),"build_command":command,"build_log_sha256":digest(&directory.join("build.log"))?,"build_binary_sha256":binaries,"command_sha256":{},"runs":{}});
    bind(directory, &mut receipt, "build", &command)?;
    for name in ["first", "repeat"] {
        let command = json!(capture::command("layer", &tag, name)?);
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
    capture::verify(&root()?, "layer", directory)?;
    Ok(receipt)
}

#[test]
fn historical_layer_bytes_satisfy_new_independent_oracle() -> Result<()> {
    let directory = tempfile::tempdir()?;
    fs::write(directory.path().join("run.log"), historical_raw()?)?;
    assert_eq!(
        records(&directory.path().join("run.log"))?
            .0
            .as_object()
            .ok_or("rows")?
            .len(),
        12
    );
    assert!(
        capture::verify(
            &root()?,
            "layer",
            &root()?.join("tools/assets-layer/evidence")
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn layer_records_reject_missing_duplicate_failed_and_unrelated_rows() -> Result<()> {
    let raw = historical_raw()?;
    let expected = "test verify_pinned_crane_layers ... ok";
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("run.log");
    for changed in [
        raw.replace("v0.21.5", "v0.21.4"),
        raw.replace("go1.26.2", "go1.26.5"),
        raw.replace("... ok", "... FAILED"),
        raw.replace("1 passed;", "0 passed;"),
        raw.replacen("DIORAMA_LAYER ", "DIORAMA_UNKNOWN ", 1),
        format!("{raw}DIORAMA_COMPLETE {{}}\n"),
        raw.replace(expected, &format!("{expected}\n{expected}")),
        raw.replace(expected, &format!("test unrelated ... ok\n{expected}")),
        raw.replace(expected, &format!("test unrelated ... FAILED\n{expected}")),
        raw.replacen("DIORAMA_UPSTREAM ", "DIORAMA_INPUT ", 1),
    ] {
        assert_ne!(changed, raw);
        fs::write(&path, changed)?;
        assert!(records(&path).is_err());
    }
    Ok(())
}

#[test]
fn layer_raw_observation_types_hashes_and_retained_budget_cannot_be_rewritten() -> Result<()> {
    let raw = historical_raw()?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("run.log");
    for (pointer, replacement) in [
        ("/retained_budget", json!(1)),
        ("/retry_retained_budget", json!(1)),
        ("/retained_budget", json!(false)),
        ("/retry_retained_budget", json!(false)),
        ("/archive_sha256", json!("0".repeat(64))),
        ("/observed/outer_sha256", json!("0".repeat(64))),
        ("/observed/outer_bytes", json!(true)),
        ("/observed/layers/0/frames", json!(true)),
        ("/observed/layers/0/decoded_bytes", json!(true)),
        ("/observed/layers/0/stored_bytes", json!(true)),
        ("/observed/layers/0/codec", json!("identity")),
        ("/observed/layers/0/diff_id", json!("0".repeat(64))),
    ] {
        let mut lines = raw.lines().map(str::to_owned).collect::<Vec<_>>();
        let index = lines
            .iter()
            .position(|line| line.starts_with("DIORAMA_LAYER "))
            .ok_or("layer record")?;
        let mut row = strict(
            lines[index]
                .strip_prefix("DIORAMA_LAYER ")
                .ok_or("prefix")?
                .as_bytes(),
        )?;
        *row.pointer_mut(pointer).ok_or("record field")? = replacement;
        lines[index] = format!("DIORAMA_LAYER {row}");
        fs::write(&path, lines.join("\n") + "\n")?;
        assert!(records(&path).is_err(), "{pointer}");
    }
    Ok(())
}

#[test]
fn layer_receipts_bind_source_raw_commands_and_cleanup_after_rehash() -> Result<()> {
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
            capture::verify(&root()?, "layer", directory.path()).is_err(),
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
                capture::verify(&root()?, "layer", directory.path()).is_err(),
                "{label}/{key}"
            );
        }
        save(&path, &command)?;
    }
    Ok(())
}

#[test]
fn equal_layer_runtime_binary_substitution_still_fails_builder_binding() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut receipt = synthetic(directory.path())?;
    let old = string(&receipt["build_binary_sha256"]["producer"])?.to_owned();
    for name in ["first", "repeat"] {
        let path = directory.path().join(format!("{name}.log"));
        fs::write(&path, historical_raw()?.replace(&old, &"f".repeat(64)))?;
        let (rows, hashes) = records(&path)?;
        receipt["runs"][name]["raw_sha256"] = digest(&path)?.into();
        receipt["runs"][name]["records"] = rows;
        receipt["runs"][name]["binary_sha256"] = hashes;
        let command = receipt["runs"][name]["command"].clone();
        bind(directory.path(), &mut receipt, name, &command)?;
    }
    save(&directory.path().join("receipt.json"), &receipt)?;
    assert!(capture::verify(&root()?, "layer", directory.path()).is_err());
    Ok(())
}

#[test]
fn layer_graph_requires_complete_pins_and_its_own_main_module() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let pinned = root()?.join("tools/assets-layer/modules.json");
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
    let module = "diorama.invalid/assets-layer-fixture";
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

#[test]
fn layer_cleanup_claims_and_typed_receipt_records_remain_bound_after_rehash() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let original = synthetic(directory.path())?;
    for label in ["image-inspect", "cleanup-4", "cleanup-5"] {
        let path = directory.path().join(format!("{label}.log"));
        let raw = fs::read(&path)?;
        let command_path = directory.path().join(format!("{label}.command.json"));
        let command = load(&command_path)?;
        fs::write(&path, "sha256:unremoved-or-substituted\n")?;
        let mut changed = original.clone();
        bind(directory.path(), &mut changed, label, &command["argv"])?;
        save(&directory.path().join("receipt.json"), &changed)?;
        assert!(capture::verify(&root()?, "layer", directory.path()).is_err());
        fs::write(path, raw)?;
        save(&command_path, &command)?;
    }
    for (pointer, value) in [
        ("/retained_budget", json!(1)),
        ("/retry_retained_budget", json!(1)),
        ("/observed/layers/0/frames", json!(true)),
    ] {
        let mut changed = original.clone();
        *changed["runs"]["first"]["records"]["gzip"]
            .pointer_mut(pointer)
            .ok_or("typed record")? = value;
        save(&directory.path().join("receipt.json"), &changed)?;
        assert!(capture::verify(&root()?, "layer", directory.path()).is_err());
    }
    save(&directory.path().join("receipt.json"), &original)?;
    let relocated = tempfile::tempdir()?;
    for entry in fs::read_dir(directory.path())? {
        let entry = entry?;
        fs::copy(entry.path(), relocated.path().join(entry.file_name()))?;
    }
    capture::verify(&root()?, "layer", relocated.path())?;
    fs::remove_file(relocated.path().join("cleanup-5.command.json"))?;
    assert!(capture::verify(&root()?, "layer", relocated.path()).is_err());
    Ok(())
}

#[test]
fn layer_namespace_and_missing_preflight_reject_before_qualification() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("run.log");
    let raw = historical_raw()?;
    for replacement in [
        json!({"init":1,"shell":7,"helper":7,"processes":[1,7,7]}),
        json!({"init":1,"shell":7,"helper":8,"processes":[1,7,8,9]}),
        json!({"init":true,"shell":7,"helper":8,"processes":[1,7,8]}),
    ] {
        let changed = raw
            .lines()
            .map(|line| {
                if line.starts_with("DIORAMA_NAMESPACE ") {
                    format!("DIORAMA_NAMESPACE {replacement}")
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(&path, changed)?;
        assert!(records(&path).is_err());
    }
    let output = directory.path().join("absent-output");
    assert!(capture::docker(&directory.path().join("missing-root"), "layer", &output).is_err());
    assert!(!output.exists());
    Ok(())
}

#[test]
#[ignore = "source hash qualification receipt checks disabled"]
fn published_layer_requires_current_rust_capture() -> Result<()> {
    capture::verify(
        &root()?,
        "layer",
        &root()?.join("tools/assets-layer/rust-evidence"),
    )
}
