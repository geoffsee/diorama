use super::*;
use std::fmt::Write as _;
fn root() -> Result<std::path::PathBuf> {
    diorama_dev::repository_root(&std::env::current_dir()?)
}
fn historical(family: &str) -> Result<String> {
    let modern = root()?.join(format!("tools/supervisor-{family}/evidence/first.log"));
    let name = if family == "signals" && !modern.exists() {
        "run"
    } else {
        "first"
    };
    Ok(String::from_utf8(read(
        &root()?.join(format!("tools/supervisor-{family}/evidence/{name}.log")),
        1024 * 1024,
    )?)?)
}
fn raw(family: &str) -> Result<String> {
    // These bytes exercise parsers only; synthetic receipts are never published evidence.
    let original = historical(family)?
        .replace("  /out/signals.test", "  /signals.test")
        .replace("  /out/owned_signals.test", "  /owned_signals.test");
    if original.lines().any(|line| line.ends_with("  /fixture")) {
        Ok(original)
    } else {
        Ok(format!("{}  /fixture\n{original}", "f".repeat(64)))
    }
}
fn staged(directory: &Path, family: &str) -> Result<Value> {
    let tag = format!("diorama-supervisor-{family}-{}", "a".repeat(32));
    let source = inventory(&root()?)?;
    save(&directory.join("source-inventory.json"), &source)?;
    let raw = raw(family)?;
    let (rows, hashes) = records(family, raw.as_bytes())?;
    let mut build = format!("#1 0.1 DIORAMA_BUILD_BEGIN {tag}\n");
    for name in binaries(family)? {
        writeln!(build, "#1 0.2 {}  /out/{name}", text(&hashes[name])?)?;
    }
    writeln!(build, "#1 0.3 DIORAMA_BUILD_END {tag}")?;
    fs::write(directory.join("build.log"), &build)?;
    let mut receipt = json!({"schema":3,"cancelled":false,"family":family,"revision":"b".repeat(40),"dirty":false,"tag":tag,"source_sha256":source,"source_inventory_sha256":digest(&directory.join("source-inventory.json"))?,"build_command":build_command(family,&tag,"/tmp/diorama-supervisor-context-synthetic"),"build_log_sha256":diorama_dev::sha256(build.as_bytes()),"build_binary_sha256":hashes,"image_id":format!("sha256:{}","c".repeat(64)),"containers":[format!("{tag}-first"),format!("{tag}-repeat")],"runs":{},"command_sha256":{},"errors":[],"cleanup_errors":[],"remaining_containers":[],"remaining_images":[]});
    for name in ["first", "repeat"] {
        fs::write(directory.join(format!("{name}.log")), &raw)?;
        receipt["runs"][name] = json!({"command":runtime_command(family,&tag,name)?,"raw_sha256":diorama_dev::sha256(raw.as_bytes()),"binary_sha256":hashes,"records":rows});
    }
    for (label, _) in control_commands(&tag) {
        fs::write(
            directory.join(format!("{label}.log")),
            if label == "image-inspect" {
                format!("{}\n", text(&receipt["image_id"])?)
            } else {
                String::new()
            },
        )?;
    }
    for label in COMMAND_LABELS {
        bind_command(directory, &mut receipt, label)?;
    }
    save(&directory.join("receipt.json"), &receipt)?;
    verify(&root()?, family, directory, true)?;
    Ok(receipt)
}
fn bind_command(directory: &Path, receipt: &mut Value, label: &str) -> Result<()> {
    let controls = control_commands(text(&receipt["tag"])?);
    let argv = if let Some((_, args)) = controls.iter().find(|(name, _)| *name == label) {
        args
    } else if label == "build" {
        &receipt["build_command"]
    } else {
        &receipt["runs"][label]["command"]
    };
    let command = json!({"spawned":true,"owned_pid":42,"owner_directory":"/tmp/diorama-process-synthetic","owned_process_group_absent":true,"cleanup_complete":true,"output_eof":true,"cleanup_errors":[],"exit_code":0,"timeout":false,"cancelled":false,"argv":argv,"merged_output":true,"output_limit":false,"stdout_sha256":digest(&directory.join(format!("{label}.log")))?,"stderr_sha256":diorama_dev::sha256(b"")});
    let path = directory.join(format!("{label}.command.json"));
    save(&path, &command)?;
    receipt["command_sha256"][label] = digest(&path)?.into();
    Ok(())
}
#[test]
fn historical_raw_bytes_satisfy_independent_semantics() -> Result<()> {
    for family in ["process", "output", "signals"] {
        records(family, raw(family)?.as_bytes())?;
    }
    Ok(())
}
#[test]
fn process_fields_types_startup_and_deadlines_are_required() -> Result<()> {
    let original = oracle::process(&historical("process")?)?;
    for (index, key, value) in [
        (0, "leader_reaped", json!(false)),
        (0, "thread_joined", json!(false)),
        (0, "complete", json!(1)),
        (0, "term_attempted", json!(false)),
        (0, "exit_code", json!(17)),
        (2, "elapsed_ms", json!(100)),
        (2, "elapsed_ms", json!(35001)),
        (10, "error", Value::Null),
        (10, "spawned", json!(true)),
        (10, "leader_reaped", json!(true)),
        (10, "thread_joined", json!(false)),
        (11, "elapsed_ms", json!(0)),
        (11, "term_attempted", json!(false)),
        (11, "error", json!("process_spawn_failed")),
    ] {
        let mut rows = original.clone();
        rows[index][key] = value;
        let mut raw = String::new();
        for row in rows.as_array().ok_or("rows")? {
            writeln!(raw, "DIORAMA_PROCESS {row}")?;
        }
        assert!(oracle::process(&raw).is_err(), "{index}/{key}");
    }
    Ok(())
}
#[test]
fn cancelled_prefix_counts_vary_but_each_raw_run_remains_strict() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let original = staged(directory.path(), "output")?;
    let raw = raw("output")?;
    let pattern = regex::Regex::new(r"(status=Cancelled bytes=)\d+")?;
    for size in [0, 6, 64] {
        let changed = pattern
            .replace_all(&raw, format!("${{1}}{size}"))
            .into_owned();
        let (rows, _) = records("output", changed.as_bytes())?;
        let mut receipt = original.clone();
        receipt["runs"]["repeat"]["records"] = rows;
        receipt["runs"]["repeat"]["raw_sha256"] = diorama_dev::sha256(changed.as_bytes()).into();
        fs::write(directory.path().join("repeat.log"), changed)?;
        bind_command(directory.path(), &mut receipt, "repeat")?;
        save(&directory.path().join("receipt.json"), &receipt)?;
        verify(&root()?, "output", directory.path(), true)?;
        assert_eq!(
            receipt["runs"]["repeat"]["records"]["probe-failure"]["bytes"],
            size
        );
    }
    for changed in [
        pattern.replace_all(&raw, "${1}65").into_owned(),
        raw.replace("status=Complete bytes=8", "status=Complete bytes=7"),
        raw.replace("status=Cancelled", "status=Complete"),
        raw.replace("joined=true", "joined=false"),
        raw.replace("reaped=true", "reaped=false"),
    ] {
        assert_ne!(changed, raw);
        assert!(records("output", changed.as_bytes()).is_err());
    }
    let rows = records("output", raw.as_bytes())?.0;
    for (key, value) in [
        ("bytes", json!(7)),
        ("status", json!("Cancelled")),
        ("joined", json!(false)),
    ] {
        let mut changed = rows.clone();
        changed["merged"][key] = value;
        assert_ne!(oracle::normalize(&rows), oracle::normalize(&changed));
    }
    Ok(())
}
#[test]
fn output_and_signal_semantic_mutations_fail() -> Result<()> {
    for (family, pairs) in [
        (
            "output",
            vec![
                ("status=LimitExceeded", "status=Complete"),
                ("joined=true", "joined=false"),
                ("reaped=true", "reaped=false"),
                ("cases=13", "cases=12"),
                ("bytes=64", "bytes=65"),
            ],
        ),
        (
            "signals",
            vec![
                ("combined_cases=61", "combined_cases=60"),
                ("owner_joined=true", "owner_joined=false"),
                ("dependent_started=false", "dependent_started=true"),
                ("sentinel_survived=true", "sentinel_survived=false"),
                ("case=force iteration=20", "case=full iteration=20"),
                ("cases=160", "cases=159"),
                ("all_children_reaped=true", "all_children_reaped=false"),
            ],
        ),
    ] {
        let original = raw(family)?;
        for (old, new) in pairs {
            let changed = original.replacen(old, new, 1);
            assert_ne!(original, changed);
            assert!(records(family, changed.as_bytes()).is_err());
        }
    }
    let original = raw("signals")?;
    let rows = original
        .lines()
        .map(|line| {
            if line.starts_with("DIORAMA_OWNED_SIGNAL case=force ") {
                format!(
                    "{}elapsed_ms=35001",
                    line.split_once("elapsed_ms=").expect("elapsed").0
                )
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(records("signals", rows.as_bytes()).is_err());
    Ok(())
}
#[test]
fn namespace_duplicates_unknown_markers_and_completion_fail() -> Result<()> {
    for family in ["process", "output", "signals"] {
        let original = raw(family)?;
        for replacement in [
            r#"{"init":1,"shell":2,"helper":2,"processes":[1,2,2]}"#,
            r#"{"init":1,"shell":2,"helper":3,"processes":[1,2,3,4]}"#,
            r#"{"init":true,"shell":2,"helper":3,"processes":[1,2,3]}"#,
        ] {
            let changed = original
                .lines()
                .map(|s| {
                    if s.starts_with("DIORAMA_NAMESPACE ") {
                        format!("DIORAMA_NAMESPACE {replacement}")
                    } else {
                        s.into()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(records(family, changed.as_bytes()).is_err());
        }
        for changed in [
            format!("{original}\nDIORAMA_NAMESPACE {{}}"),
            format!("{original}\nDIORAMA_UNKNOWN {{}}"),
            original.replace("1 passed;", "0 passed;"),
        ] {
            assert!(records(family, changed.as_bytes()).is_err());
        }
    }
    Ok(())
}
#[test]
fn all_receipt_fields_and_owned_commands_are_bound() -> Result<()> {
    let directory = tempfile::tempdir()?;
    for family in ["process", "output", "signals"] {
        let original = staged(directory.path(), family)?;
        for key in original.as_object().ok_or("receipt")?.keys() {
            let mut changed = original.clone();
            changed.as_object_mut().ok_or("receipt")?.remove(key);
            save(&directory.path().join("receipt.json"), &changed)?;
            assert!(
                verify(&root()?, family, directory.path(), false).is_err(),
                "missing {key}"
            );
        }
        for (key, value) in [
            ("schema", json!(true)),
            ("cancelled", json!(true)),
            ("dirty", json!(true)),
            ("errors", json!(["failure"])),
            ("cleanup_errors", json!(["failure"])),
            ("remaining_containers", json!(["survivor"])),
            ("remaining_images", Value::Null),
            ("source_sha256", json!({})),
            ("containers", json!([])),
        ] {
            let mut changed = original.clone();
            changed[key] = value;
            save(&directory.path().join("receipt.json"), &changed)?;
            assert!(
                verify(&root()?, family, directory.path(), false).is_err(),
                "{key}"
            );
        }
        for label in ["first", "repeat"] {
            let mut changed = original.clone();
            changed["runs"][label]["command"][5] = "--privileged".into();
            bind_command(directory.path(), &mut changed, label)?;
            save(&directory.path().join("receipt.json"), &changed)?;
            assert!(verify(&root()?, family, directory.path(), true).is_err());
        }
    }
    Ok(())
}
#[test]
fn command_settlement_mutations_fail_after_rehash() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let original = staged(directory.path(), "process")?;
    for label in ["build", "first", "repeat"] {
        let path = directory.path().join(format!("{label}.command.json"));
        let command = load(&path)?;
        for (key, value) in [
            ("exit_code", json!(1)),
            ("output_eof", json!(false)),
            ("owned_process_group_absent", json!(false)),
            ("cleanup_complete", json!(false)),
            ("output_limit", json!(true)),
            ("timeout", json!(true)),
            ("cancelled", json!(true)),
            ("stdout_sha256", json!("0".repeat(64))),
        ] {
            let mut changed = command.clone();
            changed[key] = value;
            save(&path, &changed)?;
            let mut receipt = original.clone();
            receipt["command_sha256"][label] = digest(&path)?.into();
            save(&directory.path().join("receipt.json"), &receipt)?;
            assert!(verify(&root()?, "process", directory.path(), true).is_err());
        }
        save(&path, &command)?;
    }
    Ok(())
}
#[test]
fn source_scope_tracks_dependencies_and_removed_inputs() -> Result<()> {
    let source = inventory(&root()?)?;
    let selected = selected(&source)?;
    for name in [
        "Cargo.lock",
        "rust-toolchain.toml",
        "crates/diorama-supervisor/src/process.rs",
        "crates/diorama-supervisor/tests/process_ownership.rs",
        "tools/dev/src/parity/process.rs",
    ] {
        let mut changed = source.clone();
        changed.as_object_mut().ok_or("source")?.remove(name);
        assert_ne!(super::selected(&changed)?, selected, "{name}");
    }
    let mut unrelated = source.clone();
    unrelated["crates/diorama-config/unrelated.rs"] = "0".repeat(64).into();
    assert_eq!(super::selected(&unrelated)?, selected);
    Ok(())
}
#[test]
fn raw_and_builder_identity_cannot_be_replaced_together() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let original = staged(directory.path(), "process")?;
    let first = directory.path().join("first.log");
    let bytes = read(&first, 1024 * 1024)?;
    fs::write(&first, [bytes.as_slice(), b"changed diagnostic"].concat())?;
    assert!(verify(&root()?, "process", directory.path(), false).is_err());
    fs::write(&first, &bytes)?;
    let mut changed = original.clone();
    for name in ["first", "repeat"] {
        let path = directory.path().join(format!("{name}.log"));
        let log = String::from_utf8(read(&path, 1024 * 1024)?)?.replace(
            text(&original["runs"][name]["binary_sha256"]["process-tests"])?,
            &"0".repeat(64),
        );
        fs::write(&path, log.as_bytes())?;
        let (rows, hashes) = records("process", log.as_bytes())?;
        changed["runs"][name]["records"] = rows;
        changed["runs"][name]["binary_sha256"] = hashes;
        changed["runs"][name]["raw_sha256"] = diorama_dev::sha256(log.as_bytes()).into();
        bind_command(directory.path(), &mut changed, name)?;
    }
    save(&directory.path().join("receipt.json"), &changed)?;
    assert!(verify(&root()?, "process", directory.path(), false).is_err());
    let build = read(&directory.path().join("build.log"), 16 * 1024 * 1024)?;
    assert!(builder(&build, "other", &binaries("process")?).is_err());
    assert!(
        builder(
            &[build.as_slice(), build.as_slice()].concat(),
            text(&original["tag"])?,
            &binaries("process")?
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn inventory_rehash_does_not_hide_missing_current_input_or_extra_evidence() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let original = staged(directory.path(), "signals")?;
    let mut source = original["source_sha256"].clone();
    source
        .as_object_mut()
        .ok_or("source")?
        .remove("crates/diorama-supervisor/src/coordinator.rs");
    save(&directory.path().join("source-inventory.json"), &source)?;
    let mut changed = original;
    changed["source_sha256"] = source;
    changed["source_inventory_sha256"] =
        digest(&directory.path().join("source-inventory.json"))?.into();
    save(&directory.path().join("receipt.json"), &changed)?;
    assert!(verify(&root()?, "signals", directory.path(), false).is_err());
    staged(directory.path(), "signals")?;
    fs::write(directory.path().join("unexpected"), b"extra")?;
    assert!(verify(&root()?, "signals", directory.path(), false).is_err());
    Ok(())
}
#[test]
fn cleanup_failures_retain_unknown_inventories_and_stop_if_unsettled() -> Result<()> {
    let mut report =
        json!({"cleanup_errors":[],"remaining_containers":null,"remaining_images":null});
    let mut calls = 0;
    cleanup(&mut report, "owned", |_| {
        calls += 1;
        Err("daemon unavailable".into())
    })?;
    assert_eq!(calls, 5);
    assert_eq!(
        report["cleanup_errors"].as_array().ok_or("errors")?.len(),
        5
    );
    assert!(report["remaining_containers"].is_null());
    calls = 0;
    assert!(
        cleanup(&mut report, "owned", |_| {
            calls += 1;
            Err(Box::new(diorama_dev::process::CommandFailure {
                message: "unsettled".into(),
                cleanup_complete: false,
                receipt: json!({}),
                owner: None,
            }))
        })
        .is_err()
    );
    assert_eq!(calls, 1);
    Ok(())
}
#[test]
fn strict_input_and_metadata_preflight_prevent_side_effects() -> Result<()> {
    for bytes in [b"{\"a\":1,\"a\":2}".as_slice(), b"NaN", b"1e400"] {
        assert!(diorama_dev::json::parse(bytes).is_err());
    }
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("output");
    assert!(
        capture(
            &directory.path().join("missing"),
            "signals",
            &output,
            &Cancellation::default()
        )
        .is_err()
    );
    assert!(!output.exists());
    let path = directory.path().join("bytes");
    fs::write(&path, b"abcd")?;
    assert!(read(&path, 3).is_err());
    std::os::unix::fs::symlink(&path, directory.path().join("link"))?;
    assert!(read(&directory.path().join("link"), 4).is_err());
    Ok(())
}
#[test]
#[ignore = "source hash qualification receipt checks disabled"]
fn published_process_evidence_is_required() -> Result<()> {
    verify(
        &root()?,
        "process",
        &root()?.join("tools/supervisor-process/rust-evidence"),
        false,
    )
}
#[test]
#[ignore = "source hash qualification receipt checks disabled"]
fn published_output_evidence_is_required() -> Result<()> {
    verify(
        &root()?,
        "output",
        &root()?.join("tools/supervisor-output/rust-evidence"),
        false,
    )
}
#[test]
#[ignore = "source hash qualification receipt checks disabled"]
fn published_signal_evidence_is_required() -> Result<()> {
    verify(
        &root()?,
        "signals",
        &root()?.join("tools/supervisor-signals/rust-evidence"),
        false,
    )
}

#[test]
fn rehashed_control_proofs_reject_fabricated_images_and_cleanup() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let original = staged(directory.path(), "process")?;
    let tag = text(&original["tag"])?;
    for (label, _) in control_commands(tag) {
        let path = directory.path().join(format!("{label}.command.json"));
        let valid = load(&path)?;
        for (key, value) in [
            ("argv", json!(["true"])),
            ("exit_code", json!(1)),
            ("owned_process_group_absent", json!(false)),
            ("cancelled", json!(true)),
            ("output_eof", json!(false)),
        ] {
            let mut changed = valid.clone();
            changed[key] = value;
            save(&path, &changed)?;
            let mut report = original.clone();
            report["command_sha256"][label] = digest(&path)?.into();
            assert!(
                verify_controls(directory.path(), &report, tag).is_err(),
                "{label} {key}"
            );
        }
        save(&path, &valid)?;
        fs::remove_file(&path)?;
        assert!(verify_controls(directory.path(), &original, tag).is_err());
        save(&path, &valid)?;
    }
    for label in ["image-inspect", "cleanup-4", "cleanup-5"] {
        let log = directory.path().join(format!("{label}.log"));
        let saved = fs::read(&log)?;
        fs::write(&log, b"fabricated residue\n")?;
        let mut report = original.clone();
        bind_command(directory.path(), &mut report, label)?;
        assert!(
            verify_controls(directory.path(), &report, tag).is_err(),
            "{label} raw"
        );
        fs::write(&log, saved)?;
        bind_command(directory.path(), &mut report, label)?;
    }
    verify_controls(directory.path(), &original, tag)?;
    Ok(())
}
