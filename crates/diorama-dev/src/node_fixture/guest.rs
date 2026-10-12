//! Node-specific inputs and observations layered on the reviewed owned VM boundary.
use super::{
    build, commands,
    common::{Result, Value, digest, inventory, json, load, read, require, text},
    constrained_verify, container, docker, network,
};
use crate::platform_fixture::{
    alpine, command_evidence,
    guest::{self, GuestSpec},
};
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};
fn helpers(family: &str) -> Result<Vec<&'static str>> {
    match family {
        "network" => Ok(vec!["modprobe-double.sh", "iptables-double.sh"]),
        "container" => Ok(vec!["launch.sh", "namespace.sh"]),
        "constrained" => Ok(vec!["namespace.sh", "guard-failure.sh", "module-wait.sh"]),
        _ => Err("node guest family".into()),
    }
}
fn here(root: &Path, family: &str) -> PathBuf {
    root.join(format!("tools/node-{family}"))
}
fn expected(
    root: &Path,
    family: &str,
    inputs: &Value,
    metadata: &Value,
) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for (name, pin) in inputs["packages"]["selected"]
        .as_object()
        .ok_or("package pins")?
    {
        require(
            Path::new(name).file_name().and_then(|s| s.to_str()) == Some(name),
            "package basename",
        )?;
        result.insert(format!("repo/aarch64/{name}"), text(&pin["sha256"])?.into());
    }
    result.insert(
        "repo/aarch64/APKINDEX.tar.gz".into(),
        text(&inputs["packages"]["index_sha256"])?.into(),
    );
    for name in helpers(family)? {
        result.insert(name.into(), digest(&here(root, family).join(name))?);
    }
    for name in build::binaries(family)? {
        result.insert(
            name.into(),
            text(&metadata["files"][name]["sha256"])?.into(),
        );
    }
    Ok(result)
}
fn checks(expected: &BTreeMap<String, String>) -> Result<String> {
    let mut value = String::new();
    for (name, hash) in expected {
        writeln!(value, "{hash}  {name}")?;
    }
    Ok(value)
}
fn check_command(family: &str) -> Result<String> {
    Ok(format!(
        "cd /tmp/diorama-bundle && sha256sum -c - && chmod 0755 {}",
        build::binaries(family)?.join(" ")
    ))
}
fn semantic(root: &Path, family: &str, raw: &str, metadata: &Value) -> Result<Value> {
    match family {
        "network" => network::semantic(root, raw),
        "container" => container::semantic(root, raw, metadata),
        "constrained" => constrained_verify::semantic(root, raw, metadata),
        _ => Err("node guest family".into()),
    }
}
fn pins(cache: &Path, inputs: &Value) -> Result<()> {
    require(
        !fs::symlink_metadata(cache)?.file_type().is_symlink(),
        "package cache symlink",
    )?;
    for (name, pin) in inputs["packages"]["selected"]
        .as_object()
        .ok_or("package pins")?
    {
        require(
            Path::new(name).file_name().and_then(|s| s.to_str()) == Some(name),
            "package basename",
        )?;
        let bytes = read(&cache.join("packages").join(name), 64 * 1024 * 1024)?;
        require(
            pin["bytes"].as_u64() == Some(u64::try_from(bytes.len())?)
                && pin["sha256"] == diorama_dev::sha256(&bytes),
            "exact cached package pin",
        )?;
    }
    let index = read(&cache.join("packages/APKINDEX.tar.gz"), 8 * 1024 * 1024)?;
    require(
        inputs["packages"]["index_sha256"] == diorama_dev::sha256(&index),
        "package index pin",
    )
}
pub(super) fn verify(root: &Path, family: &str, directory: &Path) -> Result<Value> {
    helpers(family)?;
    let inputs = load(&here(root, family).join("inputs.json"))?;
    let report = alpine::verify_guest_envelope(
        directory,
        &inputs,
        &format!("qemu-disposable-node-{family}"),
        false,
    )?;
    require(
        report["working_tree_snapshot"] == false,
        "current clean node source",
    )?;
    let metadata = docker::verify(root, family, &directory.join("artifact-build"), false)?;
    require(
        report["artifact_metadata"] == metadata && report["revision"] == metadata["revision"],
        "built candidate identity",
    )?;
    let wanted = expected(root, family, &inputs, &metadata)?;
    let (stdout, stderr) = command_evidence::remote(
        directory,
        &report,
        "verify-guest-inputs",
        &check_command(family)?,
        &[0],
    )?;
    let mut success = String::new();
    for name in wanted.keys() {
        writeln!(success, "{name}: OK")?;
    }
    require(
        stdout == success.as_bytes() && stderr.is_empty(),
        "every guest input verified",
    )?;
    require(
        read(&directory.join("verify-guest-inputs.stdin"), 256 * 1024)?
            == checks(&wanted)?.as_bytes(),
        "exact guest input hashes",
    )?;
    let label = format!("{family}-cases");
    let (raw, _) = if family == "constrained" {
        command_evidence::remote_constrained(directory, &report)?
    } else {
        command_evidence::remote(
            directory,
            &report,
            &label,
            "DIORAMA_RUN_PREPARATION=1 sh -s",
            &[0],
        )?
    };
    require(
        read(&directory.join(format!("{label}.stdin")), 256 * 1024)?
            == read(&here(root, family).join("guest.sh"), 256 * 1024)?,
        "actual current guest script",
    )?;
    let raw = std::str::from_utf8(&raw)?;
    require(report["observation"] == raw, "raw guest observation")?;
    let mut argv = command_evidence::ssh(&report)?;
    argv[0] = "scp".into();
    argv.truncate(argv.len() - 3);
    let port = text(&report["ssh_forward"])?
        .strip_prefix("127.0.0.1:")
        .ok_or("loopback SSH")?;
    argv.extend([
        "-P".into(),
        port.into(),
        "-r".into(),
        format!("{}/bundle", text(&report["owned_temporary_directory"])?),
        "root@127.0.0.1:/tmp/diorama-bundle".into(),
    ]);
    command_evidence::verify_command(directory, "copy-inputs", &argv, &[0])?;
    semantic(root, family, raw, &metadata)
}
pub(super) struct Capture<'a> {
    pub root: &'a Path,
    pub family: &'a str,
    pub output: &'a Path,
    pub image: &'a Path,
    pub cache: &'a Path,
    pub artifact: &'a Path,
    pub injection: Option<&'a str>,
}
fn archive(artifact: &Path, output: &Path) -> Result<()> {
    let archived = output.join("artifact-build");
    fs::create_dir(&archived)?;
    for entry in fs::read_dir(artifact)? {
        let entry = entry?;
        if entry
            .path()
            .extension()
            .is_some_and(|e| e == "json" || e == "log")
        {
            fs::write(
                archived.join(entry.file_name()),
                read(&entry.path(), 32 * 1024 * 1024)?,
            )?;
        }
    }
    Ok(())
}
pub(super) fn capture(
    spec: &Capture<'_>,
    cancellation: &crate::parity::process::Cancellation,
) -> Result<()> {
    let Capture {
        root,
        family,
        output,
        image,
        cache,
        artifact,
        injection,
    } = *spec;
    helpers(family)?;
    require(
        injection.is_none_or(|s| matches!(s, "setup" | "test")),
        "failure injection",
    )?;
    let metadata = docker::verify(root, family, artifact, true)?;
    let inputs = load(&here(root, family).join("inputs.json"))?;
    pins(cache, &inputs)?;
    let source = inventory(root, family)?;
    let status = commands::control(
        &json!([
            "git",
            "-C",
            root,
            "status",
            "--porcelain",
            "--untracked-files=all"
        ]),
        cancellation,
    )?;
    require(status.is_empty(), "clean committed checkout required")?;
    let revision = commands::control(
        &json!(["git", "-C", root, "rev-parse", "HEAD"]),
        cancellation,
    )?;
    require(
        metadata["revision"] == revision,
        "artifact current revision",
    )?;
    let guest_spec = GuestSpec {
        output,
        image_cache: image,
        inputs: inputs.clone(),
        source_sha256: source.clone(),
        revision,
        adapter: &format!("qemu-disposable-node-{family}"),
        injection,
    };
    guest::capture(&guest_spec, cancellation.clone(), |guest| {
        guest.report["working_tree_snapshot"] = json!(false);
        guest.report["artifact_metadata"] = metadata.clone();
        archive(artifact, output)?;
        let bundle = guest.private()?.join("bundle");
        fs::create_dir_all(bundle.join("repo/aarch64"))?;
        let wanted = expected(root, family, &inputs, &metadata)?;
        for name in wanted.keys() {
            let source = if let Some(file) = name.strip_prefix("repo/aarch64/") {
                cache.join("packages").join(file)
            } else if helpers(family)?.contains(&name.as_str()) {
                here(root, family).join(name)
            } else {
                artifact.join(name)
            };
            fs::write(bundle.join(name), read(&source, 64 * 1024 * 1024)?)?;
        }
        guest.upload_directory("copy-inputs", &bundle, "/tmp/diorama-bundle")?;
        guest.remote(
            "verify-guest-inputs",
            &check_command(family)?,
            30,
            checks(&wanted)?.as_bytes(),
            true,
        )?;
        let script = read(&here(root, family).join("guest.sh"), 256 * 1024)?;
        let result = if family == "constrained" {
            guest.remote_constrained(&script)?
        } else {
            guest.remote(
                &format!("{family}-cases"),
                "DIORAMA_RUN_PREPARATION=1 sh -s",
                if family == "network" { 420 } else { 480 },
                &script,
                true,
            )?
        };
        let raw = String::from_utf8(result.stdout_bytes)?;
        semantic(root, family, &raw, &metadata)?;
        guest.report["observation"] = raw.into();
        require(
            inventory(root, family)? == source,
            "source unchanged during guest",
        )?;
        docker::verify(root, family, artifact, true)?;
        Ok(())
    })?;
    let verified = verify(root, family, output).map(|_| ());
    finish_verification(output, cancellation, verified)
}
fn finish_verification(
    output: &Path,
    cancellation: &crate::parity::process::Cancellation,
    verified: Result<()>,
) -> Result<()> {
    if verified.is_err() || cancellation.requested() {
        let path = output.join("result.json");
        let mut report = diorama_dev::json::parse(&read(&path, 16 * 1024 * 1024)?)?;
        report["status"] = json!("failed");
        report["cancelled"] = json!(cancellation.requested());
        report["errors"]
            .as_array_mut()
            .ok_or("guest errors")?
            .push(json!(verified.as_ref().err().map_or(
                "cancelled during final verification".to_owned(),
                ToString::to_string
            )));
        super::common::save(&path, &report)?;
        verified?;
        return Err("cancelled during final verification".into());
    }
    Ok(())
}
pub(super) fn cli(
    root: &Path,
    family: &str,
    args: &[&str],
    cancellation: &crate::parity::process::Cancellation,
) -> Result<()> {
    let mut options = BTreeMap::new();
    let mut allowed = false;
    let mut index = 0;
    while index < args.len() {
        let key = args[index];
        index += 1;
        if key == "--allow-privileged-vm" {
            require(!allowed, "duplicate privilege opt-in")?;
            allowed = true;
            continue;
        }
        require(
            matches!(
                key,
                "--output"
                    | "--image-cache"
                    | "--input-cache"
                    | "--artifact-directory"
                    | "--inject-failure"
            ),
            "unknown VM option",
        )?;
        let value = *args.get(index).ok_or("missing VM option value")?;
        index += 1;
        require(options.insert(key, value).is_none(), "duplicate VM option")?;
    }
    require(allowed, "explicit --allow-privileged-vm required")?;
    capture(
        &Capture {
            root,
            family,
            output: Path::new(options.get("--output").ok_or("--output required")?),
            image: Path::new(
                options
                    .get("--image-cache")
                    .ok_or("--image-cache required")?,
            ),
            cache: Path::new(
                options
                    .get("--input-cache")
                    .ok_or("--input-cache required")?,
            ),
            artifact: Path::new(
                options
                    .get("--artifact-directory")
                    .ok_or("--artifact-directory required")?,
            ),
            injection: options.get("--inject-failure").copied(),
        },
        cancellation,
    )
}
pub(super) fn published(root: &Path, family: &str) -> Result<()> {
    let directory = here(root, family);
    let first = verify(root, family, &directory.join("rust-evidence/first"))?;
    require(
        first == verify(root, family, &directory.join("rust-evidence/repeat"))?,
        "repeated node semantics",
    )?;
    let provenance = load(&directory.join("rust-provenance.json"))?;
    super::common::fields(&provenance, &["files"])?;
    let files = guest::evidence_inventory(&directory.join("rust-evidence"))?;
    require(
        provenance["files"] == files,
        "exact published raw provenance",
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_pins_reject_size_digest_symlink_and_unbounded_index() -> Result<()> {
        let dir = tempfile::tempdir()?;
        fs::create_dir(dir.path().join("packages"))?;
        fs::write(dir.path().join("packages/pin.apk"), b"package")?;
        fs::write(dir.path().join("packages/APKINDEX.tar.gz"), b"index")?;
        let valid = json!({"packages":{"selected":{"pin.apk":{"bytes":7,"sha256":diorama_dev::sha256(b"package")}},"index_sha256":diorama_dev::sha256(b"index")}});
        pins(dir.path(), &valid)?;
        for (key, value) in [("bytes", json!(8)), ("sha256", json!("0".repeat(64)))] {
            let mut bad = valid.clone();
            bad["packages"]["selected"]["pin.apk"][key] = value;
            assert!(pins(dir.path(), &bad).is_err());
        }
        fs::remove_file(dir.path().join("packages/pin.apk"))?;
        std::os::unix::fs::symlink("APKINDEX.tar.gz", dir.path().join("packages/pin.apk"))?;
        assert!(pins(dir.path(), &valid).is_err());
        fs::remove_file(dir.path().join("packages/pin.apk"))?;
        fs::write(dir.path().join("packages/pin.apk"), b"package")?;
        fs::File::create(dir.path().join("packages/APKINDEX.tar.gz"))?
            .set_len(8 * 1024 * 1024 + 1)?;
        assert!(pins(dir.path(), &valid).is_err());
        Ok(())
    }
    #[test]
    fn explicit_privilege_and_unique_complete_options_precede_effects() {
        for args in [
            vec![],
            vec!["--output", "/tmp/unused"],
            vec!["--allow-privileged-vm", "--allow-privileged-vm"],
            vec!["--allow-privileged-vm", "--unknown", "x"],
        ] {
            assert!(
                cli(
                    Path::new("/nonexistent"),
                    "network",
                    &args,
                    &crate::parity::process::Cancellation::default()
                )
                .is_err()
            );
        }
    }
    #[test]
    #[ignore = "receipt checks disabled"]
    fn published_network_guest_requires_current_rust_capture() -> Result<()> {
        published(
            &diorama_dev::repository_root(&std::env::current_dir()?)?,
            "network",
        )
    }
    #[test]
    #[ignore = "receipt checks disabled"]
    fn published_container_guest_requires_current_rust_capture() -> Result<()> {
        published(
            &diorama_dev::repository_root(&std::env::current_dir()?)?,
            "container",
        )
    }
}
#[cfg(test)]
mod cancellation_tests {
    use super::*;
    #[test]
    fn late_verification_cancellation_rewrites_success_receipt() -> Result<()> {
        let directory = tempfile::tempdir()?;
        super::super::common::save(
            &directory.path().join("result.json"),
            &json!({"status":"passed","errors":[]}),
        )?;
        let cancellation = crate::parity::process::Cancellation::default();
        cancellation.request();
        assert!(finish_verification(directory.path(), &cancellation, Ok(())).is_err());
        let report = load(&directory.path().join("result.json"))?;
        assert_eq!(report["status"], "failed");
        assert_eq!(report["cancelled"], true);
        assert!(!report["errors"].as_array().ok_or("errors")?.is_empty());
        Ok(())
    }
}
#[cfg(test)]
#[path = "constrained_envelope_tests.rs"]
mod constrained_envelope_tests;
