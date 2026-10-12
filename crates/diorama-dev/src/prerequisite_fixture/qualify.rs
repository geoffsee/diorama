use super::{Path, Result, require};
use diorama_dev::defaults::capture::{OwnedDocker, Runner, arguments, push_error, successful};
use serde_json::json;
use std::{collections::BTreeMap, fs};
fn copy(
    root: &Path,
    path: &Path,
    destination: &Path,
    inventory: &mut BTreeMap<String, String>,
) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if ["target", ".git", "__pycache__"]
            .iter()
            .any(|name| entry.file_name() == *name)
        {
            continue;
        }
        require(!kind.is_symlink(), "source symlink")?;
        let relative = entry.path().strip_prefix(root)?.to_path_buf();
        let target = destination.join(&relative);
        if kind.is_dir() {
            fs::create_dir_all(&target)?;
            copy(root, &entry.path(), destination, inventory)?;
        } else {
            require(kind.is_file(), "regular build source")?;
            fs::create_dir_all(target.parent().ok_or("source parent")?)?;
            fs::copy(entry.path(), &target)?;
            inventory.insert(
                relative.to_str().ok_or("source UTF8")?.into(),
                crate::parity::digest(&target, false)?,
            );
        }
    }
    Ok(())
}
#[allow(
    clippy::too_many_lines,
    reason = "Keep owned build context and Docker cleanup together"
)]
pub(super) fn run(root: &Path, output: &Path) -> Result<u8> {
    let root_path = root.canonicalize()?;
    let root = root_path.as_path();
    let sources = crate::platform_fixture::source_inventory(root, "prerequisite")?;
    let here = root.join("tools/parity/fixtures/prerequisite-preparation");
    crate::parity::read(&here.join("fixture-command.rs"), 1024 * 1024)?;
    diorama_dev::defaults::capture::create_output(output)?;
    let output_path = output.canonicalize()?;
    let output = output_path.as_path();
    let mut runner = Runner::new(output);
    let cancellation = runner.commands.cancellation.clone();
    let signals = diorama_dev::process::SignalGuard::install(cancellation.clone())?;
    runner.launcher = Some(std::env::current_exe()?);
    let mut entropy = [0u8; 32];
    std::io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut entropy)?;
    let mut owned = OwnedDocker {
        tag: format!(
            "diorama-preparation-linux-{}",
            &diorama_dev::sha256(&entropy)[..32]
        ),
        image_id: None,
        containers: vec![],
    };
    let mut report = json!({"schema_version":2,"output_directory":output,"platform":"linux/arm64","target":"aarch64-unknown-linux-musl","uncommitted_implementation":true,"source_sha256":sources,"errors":[],"cleanup_errors":[],"containers":[]});
    let operation = (|| -> Result<()> {
        let revision = String::from_utf8(runner.bounded(
            &[
                "git".into(),
                "-C".into(),
                root.into(),
                "rev-parse".into(),
                "HEAD".into(),
            ],
            "revision",
            10,
            4096,
        )?)?
        .trim()
        .to_owned();
        require(
            regex::Regex::new("^[a-f0-9]{40}$")?.is_match(&revision),
            "source revision",
        )?;
        report["revision"] = json!(revision);
        let context = tempfile::Builder::new()
            .prefix("diorama-prerequisite-build-")
            .tempdir()?;
        let destination = context.path().to_path_buf();
        let mut inventory = BTreeMap::new();
        for name in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"] {
            fs::copy(root.join(name), destination.join(name))?;
            inventory.insert(
                name.into(),
                crate::parity::digest(&destination.join(name), false)?,
            );
        }
        for name in [
            "crates",
            "third_party",
            ".cargo",
            "tools/upstream",
            "tools/dev",
        ] {
            fs::create_dir_all(destination.join(name))?;
            copy(root, &root.join(name), &destination, &mut inventory)?;
        }
        for name in [
            "prerequisite-preparation/fixture-command.rs",
            "management-check/cases.json",
            "management-check/expected.json",
        ] {
            let relative = format!("tools/parity/fixtures/{name}");
            let target = destination.join(&relative);
            fs::create_dir_all(target.parent().ok_or("fixture parent")?)?;
            fs::copy(root.join(&relative), &target)?;
            inventory.insert(relative, crate::parity::digest(&target, false)?);
        }
        fs::copy(
            here.join("Linux.Dockerfile"),
            destination.join("Dockerfile"),
        )?;
        inventory.insert(
            "Dockerfile".into(),
            crate::parity::digest(&destination.join("Dockerfile"), false)?,
        );
        crate::parity::write_json(&output.join("source-hashes.json"), &json!(inventory), true)?;
        report["inventory_sha256"] = json!(crate::parity::digest(
            &output.join("source-hashes.json"),
            false
        )?);
        runner.keep_context(context);
        runner.bounded(
            &[
                "docker".into(),
                "build".into(),
                "--platform".into(),
                "linux/arm64".into(),
                "-t".into(),
                owned.tag.clone().into(),
                destination.into(),
            ],
            "build",
            900,
            8 * 1024 * 1024,
        )?;
        report["image"] = diorama_dev::defaults::capture::inspect_image(&mut runner, &mut owned)?;
        report["image_id"] = json!(owned.image_id);
        let name = format!("{}-test", owned.tag);
        owned.containers.push(name.clone());
        report["containers"] = json!(owned.containers);
        let argv = arguments(&[
            "docker",
            "run",
            "--name",
            &name,
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
            &owned.tag,
        ]);
        report["command"] = json!(
            argv.iter()
                .map(|arg| arg.to_string_lossy())
                .collect::<Vec<_>>()
        );
        let raw = runner.bounded(&argv, "run", 180, 1024 * 1024)?;
        let result = crate::platform_fixture::preparation::verify_run(std::str::from_utf8(&raw)?)?;
        report["run_sha256"] = json!(diorama_dev::sha256(&raw));
        runner.bounded(
            &[
                "docker".into(),
                "cp".into(),
                format!("{name}:/dioramactl").into(),
                output.join("dioramactl").into(),
            ],
            "artifact-copy",
            30,
            65536,
        )?;
        let binary = crate::parity::read(&output.join("dioramactl"), 64 * 1024 * 1024)?;
        let hash = diorama_dev::sha256(&binary);
        require(
            result["binaries"]["dioramactl"] == json!(hash),
            "exported artifact identity",
        )?;
        report["artifact_sha256"] = json!(hash);
        crate::parity::write_json(
            &output.join("artifact.json"),
            &json!({"sha256":hash,"size":binary.len(),"target":"aarch64-unknown-linux-musl","revision":revision}),
            true,
        )?;
        for (name, hash) in inventory {
            if name != "Dockerfile" {
                require(
                    crate::parity::digest(&root.join(name), false)? == hash,
                    "source changed during build",
                )?;
            }
        }
        require(
            crate::platform_fixture::source_inventory(root, "prerequisite")? == sources,
            "harness changed during capture",
        )?;
        Ok(())
    })();
    if let Err(error) = operation {
        push_error(&mut report, "errors", error.to_string());
    }
    if let Err(error) = runner.finish(&mut report, output, &owned) {
        return Err(Box::new(FinishFailure {
            error,
            _signals: signals,
        }));
    }
    if successful(&report) {
        crate::platform_fixture::preparation::verify_core(root, output)?;
        let mut final_report = json!({"schema_version":2,"cancelled":cancellation.requested(),"files":crate::platform_fixture::preparation::evidence_inventory(output)?});
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output.join("qualification.json"))?;
        serde_json::to_writer_pretty(&mut file, &final_report)?;
        if cancellation.requested() {
            use std::io::Seek;
            final_report["cancelled"] = json!(true);
            file.rewind()?;
            serde_json::to_writer_pretty(&mut file, &final_report)?;
            let length = file.stream_position()?;
            file.set_len(length)?;
            return Ok(1);
        }
        Ok(0)
    } else {
        Ok(1)
    }
}
#[derive(Debug)]
struct FinishFailure {
    error: diorama_dev::Error,
    _signals: diorama_dev::process::SignalGuard,
}
impl std::fmt::Display for FinishFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for FinishFailure {}
