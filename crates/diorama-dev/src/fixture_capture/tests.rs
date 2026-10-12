use super::*;
use std::fmt::Write as _;

fn root() -> Result<PathBuf> {
    crate::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))
}

fn replace(path: &Path, value: &Value) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn rebind_artifacts(output: &Path) -> Result<()> {
    let path = output.join("provenance.json");
    if path.exists() {
        fs::remove_file(path)?;
    }
    publish_provenance(output)
}

fn synthetic_policy_sources(
    profile: &Profile,
    output: &Path,
    outputs: &mut serde_json::Map<String, Value>,
    labels: &mut Vec<String>,
) -> Result<()> {
    if let Some(family) = policy_family(profile) {
        let pins = oracle::policy::pins(family)?;
        let mut raw = String::new();
        for (name, hash) in pins.as_object().ok_or("source map")? {
            writeln!(&mut raw, "{}  {name}", hash.as_str().ok_or("digest")?)?;
        }
        for component in profile.components {
            writeln!(&mut raw, "{}  /{component}.test", "a".repeat(64))?;
        }
        fs::write(output.join("source.sha256"), raw)?;
        outputs.insert(
            "source.sha256".into(),
            capture::digest(&output.join("source.sha256"))?.into(),
        );
        fs::write(output.join("source-copy.log"), b"")?;
        labels.push("source-copy".into());
    }
    Ok(())
}

fn synthetic_records(family: &str, profile: &Profile, expected: &Value) -> Result<String> {
    let rows = if profile.multiple_records {
        expected.as_array().ok_or("record array")?.clone()
    } else {
        vec![expected.clone()]
    };
    let mut raw = rows
        .iter()
        .map(|row| Ok(format!("DIORAMA_CAPTURE {}\n", serde_json::to_string(row)?)))
        .collect::<Result<Vec<_>>>()?
        .concat();
    if policy_family(profile).is_some() {
        let name = if family == "preflight-policy" {
            "TestDioramaCapture"
        } else {
            "TestCapture"
        };
        writeln!(&mut raw, "--- PASS: {name} (0.01s)")?;
    }
    Ok(raw)
}

/// Synthetic success is used only to test the verifier, never as qualification evidence.
fn synthetic(family: &str) -> Result<tempfile::TempDir> {
    let root = root()?;
    let profile = profile(family)?;
    let temporary = tempfile::tempdir()?;
    let output = temporary.path();
    let tag = format!("diorama-{family}-synthetic");
    let mut labels = vec!["build".to_owned(), "image-inspect".to_owned()];
    fs::write(output.join("build.log"), b"synthetic build")?;
    let image_id = format!("sha256:{}", "a".repeat(64));
    replace(&output.join("image-inspect.log"), &json!([{"Id":image_id}]))?;
    let mut outputs = serde_json::Map::new();
    let mut containers = Vec::new();
    for component in profile.components {
        let expected = expected(family, component)?;
        let name = format!("{component}.json");
        capture::write_json(&output.join(&name), &expected)?;
        outputs.insert(name.clone(), capture::digest(&output.join(&name))?.into());
        for index in 0..profile.repeats {
            let label = format!("{component}-{index}");
            containers.push(format!("{tag}-{label}"));
            let raw = synthetic_records(family, &profile, &expected)?;
            fs::write(output.join(format!("{label}.log")), raw)?;
            labels.push(label);
        }
    }
    for index in 1..=containers.len() * 2 + 2 {
        let label = format!("cleanup-{index}");
        fs::write(output.join(format!("{label}.log")), b"")?;
        labels.push(label);
    }
    synthetic_policy_sources(&profile, output, &mut outputs, &mut labels)?;
    for label in labels {
        let mut facts = json!({"spawned":true,"exit_code":0,"timeout":false,"cancelled":false,
            "output_limit":false,"merged_output":true,"cleanup_complete":true,"owned_process_group_absent":true,
            "cleanup_errors":[],"output_eof":true,"stdout_sha256":capture::digest(&output.join(format!("{label}.log")))?,
            "stderr_sha256":crate::sha256(b"")});
        let control = if label == "source-copy" {
            Some(vec![
                "docker".into(),
                "cp".into(),
                format!("{}:/source.sha256", containers[0]).into(),
                output.join("source.sha256").into_os_string(),
            ])
        } else if label == "build" {
            Some(capture::arguments(&[
                "docker",
                "build",
                "--platform",
                "linux/arm64",
                "--tag",
                &tag,
                "--file",
                &format!(
                    "/tmp/diorama-fixture-build-synthetic/{}",
                    profile.dockerfile
                ),
                "/tmp/diorama-fixture-build-synthetic",
            ]))
        } else if label == "image-inspect" {
            Some(capture::arguments(&["docker", "image", "inspect", &tag]))
        } else if let Some(index) = label.strip_prefix("cleanup-") {
            Some(cleanup_commands(&tag, &containers)[index.parse::<usize>()? - 1].clone())
        } else {
            None
        };
        if let Some(argv) = control {
            facts["argv"] = json!(
                argv.iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
            );
        }
        for component in profile.components {
            if label.starts_with(&format!("{component}-")) {
                facts["argv"] = json!(
                    runtime_args(family, &tag, &format!("{tag}-{label}"), component)
                        .iter()
                        .map(|arg| arg.to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                );
            }
        }
        capture::write_json(&output.join(format!("{label}.command.json")), &facts)?;
    }
    let receipt = json!({"schema_version":2,"family":family,"revision":REVISION,
        "source_archive_sha256":SOURCE,"builder":BUILDER,"source_sha256":sources(&root,&profile)?,
        "baseline_source_sha256":baseline(&root,&profile)?,"image":tag,"containers":containers,
        "image_id":image_id,"image_inspect":[{"Id":image_id}],"runner_sha256":"a".repeat(64),
        "repeat_count":2,"identical_repeats":true,"outputs":outputs,"errors":[],"cleanup_errors":[],
        "remaining_containers":[],"remaining_images":[],"process_failures":[],
        "process_cleanup_complete":true,"cancelled":false,"retained_build_contexts":[]});
    capture::write_json(&output.join("receipt.json"), &receipt)?;
    publish_provenance(output)?;
    verify_evidence(&root, family, output)?;
    Ok(temporary)
}

#[test]
fn rejects_omitted_sources_outputs_baseline_and_raw_artifacts() -> Result<()> {
    for family in ["credentials", "runtime-mapping", "webhooks", "node-config"] {
        let directory = synthetic(family)?;
        let receipt_path = directory.path().join("receipt.json");
        let original = oracle::load(&receipt_path)?;
        for key in ["source_sha256", "baseline_source_sha256", "outputs"] {
            let mut changed = original.clone();
            let map = changed[key].as_object_mut().ok_or("map")?;
            let first = map.keys().next().ok_or("empty map")?.clone();
            map.remove(&first);
            replace(&receipt_path, &changed)?;
            rebind_artifacts(directory.path())?;
            assert!(
                verify_evidence(&root()?, family, directory.path()).is_err(),
                "{family} {key}"
            );
        }
        replace(&receipt_path, &original)?;
        rebind_artifacts(directory.path())?;
        let provenance_path = directory.path().join("provenance.json");
        let mut provenance = oracle::load(&provenance_path)?;
        provenance["fixture_sha256"]
            .as_object_mut()
            .ok_or("hash map")?
            .remove("build.log");
        replace(&provenance_path, &provenance)?;
        assert!(verify_evidence(&root()?, family, directory.path()).is_err());
    }
    Ok(())
}

#[test]
fn rejects_rebound_cleanup_command_and_repeat_mutations() -> Result<()> {
    let directory = synthetic("credentials")?;
    let output = directory.path();
    let command_path = output.join("apiserver-1.command.json");
    let original = oracle::load(&command_path)?;
    for (field, changed) in [
        ("timeout", json!(true)),
        ("cancelled", json!(true)),
        ("output_limit", json!(true)),
        ("output_eof", json!(false)),
        ("owned_process_group_absent", json!(false)),
        ("exit_code", json!(7)),
        ("cleanup_complete", json!(false)),
        ("merged_output", json!(false)),
        ("cleanup_errors", json!(["failed"])),
        ("stdout_sha256", json!("0".repeat(64))),
        ("argv", json!(["docker", "run", "--privileged"])),
    ] {
        let mut changed_command = original.clone();
        changed_command[field] = changed;
        replace(&command_path, &changed_command)?;
        rebind_artifacts(output)?;
        assert!(
            verify_evidence(&root()?, "credentials", output).is_err(),
            "{field}"
        );
    }
    replace(&command_path, &original)?;
    let log_path = output.join("apiserver-1.log");
    let record = fs::read(&log_path)?;
    for kind in ["missing", "duplicate", "changed"] {
        let raw = match kind {
            "missing" => Vec::new(),
            "duplicate" => [record.clone(), record.clone()].concat(),
            _ => {
                let mut changed = expected("credentials", "apiserver")?;
                changed["checks"]["key_valid"] = 1.into();
                format!("DIORAMA_CAPTURE {changed}\n").into_bytes()
            },
        };
        fs::write(&log_path, &raw)?;
        let mut rebound = original.clone();
        rebound["stdout_sha256"] = crate::sha256(&raw).into();
        replace(&command_path, &rebound)?;
        rebind_artifacts(output)?;
        assert!(
            verify_evidence(&root()?, "credentials", output).is_err(),
            "{kind}"
        );
    }
    Ok(())
}

#[test]
fn captured_record_parser_rejects_missing_duplicate_and_invalid_json() {
    for raw in [
        b"".as_slice(),
        b"DIORAMA_CAPTURE {}\nDIORAMA_CAPTURE {}\n",
        b"DIORAMA_CAPTURE {\"x\":1,\"x\":2}",
        b"DIORAMA_CAPTURE {\"x\":NaN}",
        b"DIORAMA_CAPTURE \xff",
    ] {
        assert!(records(raw, false).is_err());
    }
    assert!(records(b"DIORAMA_CAPTURE {}\nDIORAMA_CAPTURE {}\n", true).is_ok());
}

#[test]
fn resource_capture_checks_multirecord_output_and_node_dns_arguments() -> Result<()> {
    synthetic("config-api")?;
    synthetic("config-write-links")?;
    let output = synthetic("resources-pki")?;
    let path = output.path().join("pki.json");
    let mut changed = oracle::load(&path)?;
    changed[0]["fresh"]["ca"]["key_mode"] = json!("0644");
    replace(&path, &changed)?;
    assert!(verify_evidence(&root()?, "resources-pki", output.path()).is_err());
    let args = runtime_args("node-config", "tag", "name", "kubelet");
    assert!(
        args.windows(4)
            .any(|values| values == ["--dns", "192.0.2.53", "--dns-search", "."])
    );
    Ok(())
}

#[test]
fn policy_captures_reject_rehashed_commands_inventory_and_baseline_weakness_changes() -> Result<()>
{
    for family in ["preflight-policy", "constrained-policy"] {
        let directory = synthetic(family)?;
        let output = directory.path();
        for label in ["build", "image-inspect", "source-copy", "cleanup-1"] {
            let path = output.join(format!("{label}.command.json"));
            let original = oracle::load(&path)?;
            let mut changed = original.clone();
            changed["argv"] = json!(["true"]);
            replace(&path, &changed)?;
            rebind_artifacts(output)?;
            assert!(
                verify_evidence(&root()?, family, output).is_err(),
                "{label}"
            );
            replace(&path, &original)?;
        }
        let profile = profile(family)?;
        let label = format!("cleanup-{}", profile.components.len() * 2 + 2);
        fs::write(
            output.join(format!("{label}.log")),
            b"remaining-container\n",
        )?;
        let path = output.join(format!("{label}.command.json"));
        let original = oracle::load(&path)?;
        let mut changed = original.clone();
        changed["stdout_sha256"] = capture::digest(&output.join(format!("{label}.log")))?.into();
        replace(&path, &changed)?;
        rebind_artifacts(output)?;
        assert!(verify_evidence(&root()?, family, output).is_err());
        fs::write(output.join(format!("{label}.log")), b"")?;
        replace(&path, &original)?;
        let component = profile.components[0];
        let path = output.join(format!("{component}.json"));
        let mut changed = oracle::load(&path)?;
        changed[0] = json!("invented\ttrue");
        replace(&path, &changed)?;
        let receipt_path = output.join("receipt.json");
        let mut receipt = oracle::load(&receipt_path)?;
        receipt["outputs"][format!("{component}.json")] = capture::digest(&path)?.into();
        replace(&receipt_path, &receipt)?;
        rebind_artifacts(output)?;
        assert!(verify_evidence(&root()?, family, output).is_err());
    }
    Ok(())
}

#[test]
#[ignore = "source hash qualification receipt checks disabled"]
fn published_rust_fixture_captures_bind_current_sources_and_commands() -> Result<()> {
    let root = root()?;
    for family in [
        "credentials",
        "preflight-policy",
        "constrained-policy",
        "runtime-mapping",
        "webhooks",
        "node-config",
        "resources-pki",
        "config-api",
        "config-write-links",
        "config-linebreak",
        "config-print-preservation",
        "config-scalar-base",
        "config-scalar-extra",
    ] {
        let profile = profile(family)?;
        verify_evidence(
            &root,
            family,
            &root.join(profile.directory).join("rust-evidence"),
        )?;
    }
    Ok(())
}
