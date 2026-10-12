//! Invented constrained envelopes seeded from retained raw VM protocol receipts.
//! These temporary records exercise verifier mutations and are never published qualification.
use super::super::{common::save, docker_tests};
use super::*;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn parsed(path: &Path) -> Result<Value> {
    diorama_dev::json::parse(&read(path, 32 * 1024 * 1024)?)
}
fn rehash_command(directory: &Path, label: &str) -> Result<()> {
    let path = directory.join(format!("{label}.command.json"));
    let mut command = parsed(&path)?;
    for stream in ["stdout", "stderr"] {
        command[format!("{stream}_sha256")] =
            digest(&directory.join(format!("{label}.{stream}")))?.into();
    }
    save(&path, &command)
}
fn publish_invented(directory: &Path, report: &mut Value) -> Result<()> {
    report["evidence_sha256"] = guest::evidence_inventory(directory)?;
    save(&directory.join("result.json"), report)
}
fn staged(directory: &Path) -> Result<Value> {
    let source = root().join("tools/node-container/rust-evidence/first");
    for entry in fs::read_dir(&source)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            fs::copy(entry.path(), directory.join(entry.file_name()))?;
        }
    }
    let build = directory.join("artifact-build");
    fs::create_dir(&build)?;
    docker_tests::staged(&build, "constrained")?;
    for name in build::binaries("constrained")? {
        fs::remove_file(build.join(name))?;
    }
    let metadata = load(&build.join("artifact.json"))?;
    let inputs = load(&root().join("tools/node-constrained/inputs.json"))?;
    let mut report = parsed(&directory.join("result.json"))?;
    report["adapter"] = json!("qemu-disposable-node-constrained");
    report["inputs"] = inputs.clone();
    report["source_sha256"] = inventory(&root(), "constrained")?;
    report["revision"] = metadata["revision"].clone();
    report["artifact_metadata"] = metadata.clone();
    for extension in ["command.json", "stdout", "stderr", "stdin"] {
        fs::rename(
            directory.join(format!("container-cases.{extension}")),
            directory.join(format!("constrained-cases.{extension}")),
        )?;
    }
    let original =
        load(&root().join("tools/node-constrained/evidence/first/artifact-build/artifact.json"))?;
    let raw = String::from_utf8(read(
        &root().join("tools/node-constrained/evidence/first/constrained-cases.stdout"),
        8 * 1024 * 1024,
    )?)?;
    let old = text(&original["files"]["prepare_node_host"]["sha256"])?;
    assert!(raw.contains(old));
    let raw = raw.replace(
        old,
        text(&metadata["files"]["prepare_node_host"]["sha256"])?,
    );
    let setup = diorama_dev::json::parse(raw.lines().next().ok_or("setup")?.as_bytes())?;
    let raw = raw.replace(
        text(&setup["external"]["exe_sha256"])?,
        text(&metadata["files"]["constrained-guest"]["sha256"])?,
    );
    fs::write(directory.join("constrained-cases.stdout"), &raw)?;
    report["observation"] = json!(raw);
    fs::copy(
        root().join("tools/node-constrained/guest.sh"),
        directory.join("constrained-cases.stdin"),
    )?;
    let path = directory.join("constrained-cases.command.json");
    let mut command = parsed(&path)?;
    command["byte_limit"] = json!(8 * 1024 * 1024);
    save(&path, &command)?;
    rehash_command(directory, "constrained-cases")?;
    let wanted = expected(&root(), "constrained", &inputs, &metadata)?;
    fs::write(
        directory.join("verify-guest-inputs.stdin"),
        checks(&wanted)?,
    )?;
    let mut stdout = String::new();
    for name in wanted.keys() {
        writeln!(stdout, "{name}: OK")?;
    }
    fs::write(directory.join("verify-guest-inputs.stdout"), stdout)?;
    let path = directory.join("verify-guest-inputs.command.json");
    let mut command = parsed(&path)?;
    let arguments = command["argv"].as_array_mut().ok_or("argv")?;
    *arguments.last_mut().ok_or("command")? = json!(check_command("constrained")?);
    save(&path, &command)?;
    rehash_command(directory, "verify-guest-inputs")?;
    publish_invented(directory, &mut report)?;
    assert_eq!(verify(&root(), "constrained", directory)?["real_passes"], 4);
    Ok(report)
}
#[test]
#[ignore = "receipt checks disabled"]
fn complete_invented_constrained_guest_binds_current_builder() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let report = staged(dir.path())?;
    assert_eq!(report["revision"], report["artifact_metadata"]["revision"]);
    assert_eq!(
        verify(&root(), "constrained", dir.path())?["read_only"],
        true
    );
    Ok(())
}
#[test]
#[ignore = "source hash qualification receipt checks disabled"]
fn raw_receipt_source_tool_and_cleanup_bindings() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let original = staged(dir.path())?;
    for (key, value) in [
        ("owned_process_group_absent", json!(false)),
        ("owned_temporary_directory_removed", json!(false)),
        ("qemu_exit_code", json!(true)),
        ("errors", json!(["failure"])),
        ("source_sha256", json!({})),
        ("artifact_metadata", json!({})),
        ("tools", json!({})),
        ("firmware", json!({})),
        ("working_tree_snapshot", json!(true)),
        ("serial_log_truncated", json!(true)),
        ("observation", json!("different")),
    ] {
        let mut changed = original.clone();
        changed[key] = value;
        save(&dir.path().join("result.json"), &changed)?;
        assert!(verify(&root(), "constrained", dir.path()).is_err(), "{key}");
    }
    Ok(())
}
#[test]
#[ignore = "receipt checks disabled"]
fn guest_exact_input_inventory_and_cloud_receipt() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut report = staged(dir.path())?;
    let path = dir.path().join("verify-guest-inputs.stdout");
    let original = String::from_utf8(read(&path, 256 * 1024)?)?;
    assert!(original.contains("constrained-guest: OK\n"));
    fs::write(&path, original.replace("constrained-guest: OK\n", ""))?;
    rehash_command(dir.path(), "verify-guest-inputs")?;
    publish_invented(dir.path(), &mut report)?;
    assert!(verify(&root(), "constrained", dir.path()).is_err());
    fs::write(&path, original)?;
    rehash_command(dir.path(), "verify-guest-inputs")?;
    let cloud = json!({"status":"error"});
    save(&dir.path().join("cloud-init.stdout"), &cloud)?;
    report["cloud_init"] = cloud;
    rehash_command(dir.path(), "cloud-init")?;
    publish_invented(dir.path(), &mut report)?;
    assert!(verify(&root(), "constrained", dir.path()).is_err());
    Ok(())
}

#[test]
#[ignore = "receipt checks disabled"]
fn rehashed_constrained_command_requires_exact_output_bound() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let original = staged(dir.path())?;
    let path = dir.path().join("constrained-cases.command.json");
    let command = parsed(&path)?;
    for bound in [None, Some(json!(16 * 1024 * 1024)), Some(json!(true))] {
        let mut changed = command.clone();
        if let Some(value) = bound {
            changed["byte_limit"] = value;
        } else {
            changed
                .as_object_mut()
                .ok_or("command")?
                .remove("byte_limit");
        }
        save(&path, &changed)?;
        let mut report = original.clone();
        publish_invented(dir.path(), &mut report)?;
        assert!(verify(&root(), "constrained", dir.path()).is_err());
    }
    Ok(())
}
