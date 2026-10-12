//! Disposable official API server and Kine protocol qualification.
pub(crate) mod capture;
mod http;
pub(crate) mod runtime;
mod scenario;
use crate::{Result, defaults::capture::digest};
use serde_json::{Map, Value};
use std::{
    fs,
    path::{Path, PathBuf},
};
/// Bind every maintenance source and manifest copied to the fixture image.
pub fn source_inventory(root: &Path, profile: &str) -> Result<Value> {
    let fixture = match profile {
        "api-json" => "tools/api-json",
        "component-boundary" => "experiments/component-boundary",
        _ => return Err("unknown component fixture".into()),
    };
    let mut paths = vec![
        root.join("Cargo.toml"),
        root.join("Cargo.lock"),
        root.join("rust-toolchain.toml"),
        root.join("tools/dev/Cargo.toml"),
    ];
    for directory in ["crates", "third_party", "tools/upstream", ".cargo"] {
        build_inputs(&root.join(directory), directory == ".cargo", &mut paths)?;
    }
    sources(&root.join("tools/dev/src"), &mut paths)?;

    sources(&root.join("tools/dev/tests"), &mut paths)?;
    for name in ["inputs.json", "Dockerfile", ".dockerignore"] {
        paths.push(root.join(fixture).join(name));
    }
    let mut inventory = Map::new();
    for path in paths {
        inventory.insert(
            path.strip_prefix(root)?
                .to_str()
                .ok_or("source path UTF8")?
                .to_owned(),
            digest(&path)?.into(),
        );
    }
    Ok(inventory.into())
}
fn build_inputs(directory: &Path, config: bool, paths: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if matches!(entry.file_name().to_str(), Some("target" | ".git")) {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_symlink() || (!kind.is_file() && !kind.is_dir()) {
            return Err("build input inventory special file".into());
        }
        if kind.is_dir() {
            build_inputs(&entry.path(), config, paths)?;
        } else if config || entry.file_name() == "Cargo.toml" {
            paths.push(entry.path());
        }
    }
    Ok(())
}
fn sources(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() || (!kind.is_file() && !kind.is_dir()) {
            return Err("source inventory special file".into());
        }
        if kind.is_dir() {
            sources(&entry.path(), paths)?;
        } else if entry.path().extension().is_some_and(|e| e == "rs") {
            paths.push(entry.path());
        }
    }
    Ok(())
}
#[derive(Debug)]
struct RuntimeFailure {
    _owner: Box<runtime::Runtime>,
    message: String,
}
impl std::fmt::Display for RuntimeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for RuntimeFailure {}
pub fn run_runtime(profile: &str) -> Result<()> {
    let mut runtime = runtime::Runtime::new(profile)?;
    let result = if profile == "api-json" {
        crate::api_json::scenario::run(&mut runtime)
    } else {
        scenario::run(&mut runtime)
    };
    if let Err(error) = result {
        runtime.report["error"] = error.to_string().into();
    }
    if let Err(error) = runtime.shutdown() {
        runtime.report["cleanup_error"] = error.to_string().into();
    }
    runtime.report["cancelled"] = runtime.cancelled().into();
    let passed = runtime.report.get("error").is_none()
        && runtime.report.get("cleanup_error").is_none()
        && !runtime.cancelled()
        && !runtime.owners_remain();
    runtime.report["status"] = if passed { "passed" } else { "failed" }.into();
    let publication = (|| -> Result<fs::File> {
        if profile == "api-json" && runtime.report["fixture"].is_object() {
            crate::defaults::capture::write_json(
                Path::new("/evidence/fixtures.json"),
                &runtime.report["fixture"],
            )?;
        }
        create_report(Path::new("/evidence/result.json"), &runtime.report)
    })();
    if runtime.owners_remain() {
        return Err(Box::new(RuntimeFailure {
            _owner: Box::new(runtime),
            message: "owned runtime settlement unconfirmed; disposable state retained".into(),
        }));
    }
    let mut published = publication?;
    if runtime.cancelled() {
        runtime.report["cancelled"] = true.into();
        runtime.report["status"] = "failed".into();
        rewrite_report(&mut published, &runtime.report)?;
        return Err("component fixture cancelled during publication".into());
    }
    crate::api_json::require(passed, "component fixture failed; inspect owned evidence")
}
pub fn cli(profile: &str, args: &[String]) -> Result<()> {
    match args {
        [command] if command == "stage-sources" => {
            crate::api_json::require(
                std::env::var("DIORAMA_DISPOSABLE_BUILD").as_deref() == Ok(profile),
                "source staging requires explicit disposable build",
            )?;
            let root = Path::new("/source");
            let inventory = source_inventory(root, profile)?;
            for name in inventory.as_object().ok_or("source inventory")?.keys() {
                let destination = Path::new("/experiment/sources").join(name);
                fs::create_dir_all(destination.parent().ok_or("source parent")?)?;
                fs::copy(root.join(name), destination)?;
            }
            Ok(())
        },
        [command] if command == "fetch" => capture::fetch(profile),
        [command] if command == "runtime" => run_runtime(profile),
        [command, flag, output] if command == "capture" && flag == "--output" => {
            capture::capture(profile, Path::new(output))
        },
        [command, output] if command == "verify" && profile == "component-boundary" => {
            verify(Path::new(output))
        },
        _ => Err("usage: <capture --output DIR|fetch|runtime|verify DIR>".into()),
    }
}
pub fn verify(directory: &Path) -> Result<()> {
    let result = crate::api_json::load(&directory.join("result.json"))?;
    let runner = crate::api_json::load(&directory.join("runner-result.json"))?;
    capture::verify_commands(directory, &runner)?;
    let root = crate::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
    let sources = source_inventory(&root, "component-boundary")?;
    crate::api_json::require(
        result["schema_version"] == 2 && runner["schema_version"] == 2,
        "current Rust boundary receipt required",
    )?;
    crate::api_json::require(
        result["status"] == "passed"
            && result["cancelled"] == false
            && result.get("error").is_none()
            && result.get("cleanup_error").is_none(),
        "boundary runtime failed",
    )?;
    crate::api_json::require(
        runner["exit_code"].as_i64() == Some(0) && crate::defaults::capture::successful(&runner),
        "boundary runner failed",
    )?;
    crate::api_json::require(
        result["source_sha256"] == sources && runner["source_sha256"] == sources,
        "boundary current sources",
    )?;
    crate::api_json::require(
        result["inputs"]
            == crate::api_json::load(&root.join("experiments/component-boundary/inputs.json"))?,
        "boundary input pins",
    )?;
    let checks = result["checks"].as_array().ok_or("boundary checks")?;
    for required in [
        "runtime digest kube-apiserver",
        "runtime digest kine",
        "unauthenticated request rejected",
        "authenticated identity without RBAC permission rejected",
        "authenticated create succeeded",
        "authenticated read succeeded",
        "authenticated update succeeded",
        "SQLite integrity check passed",
        "independent SQLite query found persisted API object",
        "same updated object survived component restart",
        "update acknowledged before abrupt datastore termination",
        "intentional datastore SIGKILL observed",
        "existing API process recovered after datastore-only restart",
        "acknowledged update survived abrupt datastore restart",
        "authenticated delete succeeded",
        "deleted object is absent",
        "deletion survived second component restart",
        "all owned component processes reaped",
    ] {
        crate::api_json::require(
            checks.contains(&Value::from(required)),
            "missing boundary observation",
        )?;
    }
    let shutdowns = result["shutdowns"].as_array().ok_or("boundary shutdowns")?;
    crate::api_json::require(shutdowns.len() == 7, "boundary exact shutdown inventory")?;
    let mut injected = 0;
    for (row, expected) in shutdowns.iter().zip([
        "kube-apiserver",
        "kine",
        "kine",
        "kube-apiserver",
        "kine",
        "kube-apiserver",
        "kine",
    ]) {
        crate::api_json::require(
            row["component"] == expected,
            "boundary shutdown dependency order",
        )?;
        crate::api_json::require(
            row["owned_group_remained"] == false,
            "boundary owned group remains",
        )?;
        if row.get("injected_failure").is_some() {
            injected += 1;
            crate::api_json::require(
                row["component"] == "kine"
                    && row["injected_failure"] == "SIGKILL"
                    && row["exit_code"].as_i64() == Some(-9),
                "boundary injected fault",
            )?;
        } else {
            crate::api_json::require(
                matches!(row["component"].as_str(), Some("kine" | "kube-apiserver"))
                    && matches!(row["exit_code"].as_i64(), Some(0 | -15))
                    && row["forced"] == false
                    && row.get("error") == Some(&Value::Null),
                "boundary unclean shutdown",
            )?;
        }
    }
    crate::api_json::require(
        injected == 1 && result["datastore_outage"].is_object(),
        "boundary outage evidence",
    )
}
pub(crate) fn verify_runner_commands(directory: &Path, runner: &Value) -> Result<()> {
    capture::verify_commands(directory, runner)
}

fn create_report(path: &Path, value: &Value) -> Result<fs::File> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    rewrite_report(&mut file, value)?;
    Ok(file)
}
fn rewrite_report(file: &mut fs::File, value: &Value) -> Result<()> {
    use std::io::{Seek, Write};
    file.rewind()?;
    serde_json::to_writer_pretty(&mut *file, value)?;
    file.write_all(b"\n")?;
    let length = file.stream_position()?;
    file.set_len(length)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "source hash qualification receipt checks disabled"]
    fn current_rust_boundary_capture_is_required_for_qualification() {
        let root = crate::repository_root(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
        verify(&root.join("experiments/component-boundary/evidence-rust")).unwrap();
    }
    #[test]
    fn source_inventory_covers_runtime_transport_oracles_and_fixture_inputs() {
        let root = crate::repository_root(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
        let inventory = source_inventory(&root, "api-json").unwrap();
        for name in [
            "Cargo.lock",
            ".cargo/config.toml",
            "crates/diorama-kube/Cargo.toml",
            "tools/upstream/Cargo.toml",
            "third_party/saphyr-parser/Cargo.toml",
            "tools/dev/src/component_boundary/runtime.rs",
            "tools/dev/src/component_boundary/http.rs",
            "tools/dev/src/api_json/mod.rs",
            "tools/dev/src/parity/process.rs",
            "tools/api-json/inputs.json",
            "tools/api-json/Dockerfile",
        ] {
            assert!(inventory.get(name).is_some(), "{name}");
        }
        assert!(inventory.as_object().unwrap().keys().all(|name| {
            !Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("py"))
        }));
    }
}
