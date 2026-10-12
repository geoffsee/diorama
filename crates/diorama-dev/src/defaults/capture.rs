//! Shared owned Docker capture orchestration. Failed process ownership is retained explicitly.
use crate::{
    Result,
    defaults::{directory, load, require},
    json,
    process::{Cancellation, CommandFailure, CommandRequest, Commands, OutputMode, SignalGuard},
    read_bounded, sha256,
};
use serde_json::{Value, json as value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
const HEX: &[u8; 16] = b"0123456789abcdef";
pub fn digest(path: &Path) -> Result<String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            (rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOFOLLOW)
                .bits()
                .try_into()?,
        )
        .open(path)?;
    require(file.metadata()?.is_file(), "regular digest input required")?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    Ok(hash
        .finalize()
        .iter()
        .flat_map(|b| {
            [
                char::from(HEX[usize::from(b >> 4)]),
                char::from(HEX[usize::from(b & 15)]),
            ]
        })
        .collect())
}
pub fn arguments(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}
#[derive(Debug)]
pub struct Runner {
    pub commands: Commands,
    pub launcher: Option<PathBuf>,
    pub environment: Option<BTreeMap<String, String>>,
    retained: Vec<CommandFailure>,
    contexts: Vec<tempfile::TempDir>,
    retained_contexts: Vec<PathBuf>,
    sequence: usize,
    signals: Option<SignalGuard>,
}
#[derive(Debug)]
pub struct CaptureFailure {
    pub owner: Runner,
    pub message: String,
}
impl std::fmt::Display for CaptureFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; process ownership and build contexts retained",
            self.message
        )
    }
}
impl std::error::Error for CaptureFailure {}
#[derive(Debug)]
pub struct OwnedDocker {
    pub tag: String,
    pub image_id: Option<String>,
    pub containers: Vec<String>,
}
impl Runner {
    pub fn new(output: &Path) -> Self {
        Self {
            commands: Commands {
                output: output.to_owned(),
                cancellation: Cancellation::default(),
            },
            retained: Vec::new(),
            launcher: None,
            environment: None,
            contexts: Vec::new(),
            retained_contexts: Vec::new(),
            sequence: 0,
            signals: None,
        }
    }
    /// Install after the executable's early `__exec` dispatch. Guard lives with retained owners.
    pub fn with_signals(output: &Path) -> Result<Self> {
        let mut runner = Self::new(output);
        runner.signals = Some(SignalGuard::install(runner.commands.cancellation.clone())?);
        Ok(runner)
    }
    pub fn keep_context(&mut self, context: tempfile::TempDir) {
        self.contexts.push(context);
    }
    pub fn bounded(
        &mut self,
        argv: &[OsString],
        label: &str,
        seconds: u64,
        limit: u64,
    ) -> Result<Vec<u8>> {
        require(
            !self.uncertain(),
            "prior process cleanup is unconfirmed; capture stopped",
        )?;
        require(!self.commands.cancellation.requested(), "capture cancelled")?;
        match self.commands.capture(CommandRequest {
            label,
            argv,
            timeout: Duration::from_secs(seconds),
            input: &[],
            required: true,
            byte_limit: limit,
            mode: OutputMode::Merged,
            environment: self.environment.as_ref(),
            current_directory: None,
            launcher: self.launcher.as_deref(),
        }) {
            Ok(result) => Ok(result.stdout_bytes),
            Err(error) => {
                let message = error.to_string();
                self.retained.push(error);
                Err(message.into())
            },
        }
    }
    fn cleanup(
        &mut self,
        report: &mut Value,
        label: &str,
        args: &[OsString],
    ) -> Option<Vec<String>> {
        if self.uncertain() {
            push_error(
                report,
                "cleanup_errors",
                format!("{label}: not attempted while process cleanup is unconfirmed"),
            );
            return None;
        }
        self.sequence += 1;
        let log = format!("cleanup-{}", self.sequence);
        // A settled cancellation permanently stops capture, but must not prevent owned cleanup.
        let cleanup = Commands {
            output: self.commands.output.clone(),
            cancellation: Cancellation::default(),
        };
        let outcome = cleanup.capture(CommandRequest {
            label: &log,
            argv: args,
            timeout: Duration::from_secs(30),
            input: &[],
            required: true,
            byte_limit: 1024 * 1024,
            mode: OutputMode::Merged,
            environment: self.environment.as_ref(),
            current_directory: None,
            launcher: self.launcher.as_deref(),
        });
        let bytes = match outcome {
            Ok(result) => Ok(result.stdout_bytes),
            Err(failure) => {
                let message = failure.to_string();
                self.retained.push(failure);
                Err(message)
            },
        };
        match bytes {
            Ok(raw) => match String::from_utf8(raw) {
                Ok(text) => Some(text.lines().map(str::to_owned).collect()),
                Err(error) => {
                    push_error(report, "cleanup_errors", format!("{label}: {error}"));
                    None
                },
            },
            Err(error) => {
                push_error(report, "cleanup_errors", format!("{label}: {error}"));
                None
            },
        }
    }
    /// Attempts every exact owned cleanup, publishes facts, and returns uncertain owners to caller.
    pub fn finish(mut self, report: &mut Value, output: &Path, owned: &OwnedDocker) -> Result<()> {
        for name in &owned.containers {
            self.cleanup(
                report,
                &format!("remove {name}"),
                &arguments(&["docker", "rm", "--force", name]),
            );
        }
        self.cleanup(
            report,
            "remove image",
            &arguments(&["docker", "image", "rm", "--force", &owned.tag]),
        );
        let mut remaining = Vec::new();
        let mut inspection_failed = false;
        for name in &owned.containers {
            let filter = format!("name=^/{}$", regex::escape(name));
            match self.cleanup(
                report,
                "inspect container",
                &arguments(&["docker", "ps", "-aq", "--filter", &filter]),
            ) {
                Some(rows) => remaining.extend(rows),
                None => inspection_failed = true,
            }
        }
        report["remaining_containers"] = if inspection_failed {
            Value::Null
        } else {
            value!(remaining)
        };
        let filter = format!("reference={}", owned.tag);
        report["remaining_images"] = self
            .cleanup(
                report,
                "inspect image",
                &arguments(&["docker", "images", "--no-trunc", "-q", "--filter", &filter]),
            )
            .map_or(Value::Null, |rows| value!(rows));
        let uncertain = self
            .retained
            .iter()
            .any(|failure| !failure.cleanup_complete);
        report["process_cleanup_complete"] = value!(!uncertain);
        report["process_failures"] = value!(
            self.retained
                .iter()
                .map(|failure| failure.receipt.clone())
                .collect::<Vec<_>>()
        );
        if uncertain {
            self.retain_contexts();
        }
        report["retained_build_contexts"] = value!(self.retained_contexts);
        report["cancelled"] = value!(self.commands.cancellation.requested());
        let publication = write_json(&output.join("receipt.json"), report);
        if uncertain {
            let message = publication.err().map_or_else(
                || "owned process cleanup is unconfirmed".to_owned(),
                |error| {
                    format!(
                        "owned process cleanup is unconfirmed; receipt publication failed: {error}"
                    )
                },
            );
            return Err(Box::new(CaptureFailure {
                owner: self,
                message,
            }));
        }
        publication
    }
    fn retain_contexts(&mut self) {
        for context in self.contexts.drain(..) {
            self.retained_contexts.push(context.keep());
        }
    }
    fn uncertain(&self) -> bool {
        self.retained
            .iter()
            .any(|failure| !failure.cleanup_complete)
    }
}
impl Drop for Runner {
    fn drop(&mut self) {
        if self
            .retained
            .iter()
            .any(|failure| !failure.cleanup_complete)
        {
            self.retain_contexts();
        }
    }
}
pub fn push_error(report: &mut Value, key: &str, message: String) {
    if !report[key].is_array() {
        report[key] = value!([]);
    }
    if let Some(errors) = report[key].as_array_mut() {
        errors.push(message.into());
    }
}
pub fn write_json(path: &Path, value: &Value) -> Result<()> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    Ok(())
}
#[derive(Debug)]
pub struct CaptureArgs {
    pub source: PathBuf,
    pub go: PathBuf,
    pub output: PathBuf,
}
pub fn parse_args(args: &[String]) -> Result<CaptureArgs> {
    let mut options = BTreeMap::new();
    let mut it = args.iter();
    while let Some(key) = it.next() {
        require(
            ["--source-archive", "--go-archive", "--output"].contains(&key.as_str()),
            "unknown capture option",
        )?;
        require(
            options
                .insert(
                    key.as_str(),
                    it.next().ok_or("missing capture option value")?,
                )
                .is_none(),
            "duplicate capture option",
        )?;
    }
    Ok(CaptureArgs {
        source: PathBuf::from(
            options
                .get("--source-archive")
                .ok_or("--source-archive is required")?,
        ),
        go: PathBuf::from(
            options
                .get("--go-archive")
                .ok_or("--go-archive is required")?,
        ),
        output: PathBuf::from(options.get("--output").ok_or("--output is required")?),
    })
}
pub fn validate_archives(inputs: &Value, args: &CaptureArgs) -> Result<()> {
    for (kind, path) in [("source", &args.source), ("go", &args.go)] {
        require(
            inputs[kind]["bytes"].as_u64() == Some(fs::metadata(path)?.len())
                && inputs[kind]["sha256"] == digest(path)?,
            &format!("{kind} input identity mismatch"),
        )?;
    }
    Ok(())
}
pub fn create_output(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(path)?;
    Ok(())
}
pub fn owned_tag(prefix: &str) -> Result<String> {
    let unique = tempfile::Builder::new().prefix(prefix).tempdir()?;
    let name = unique
        .path()
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("invalid owned tag")?
        .to_ascii_lowercase();
    Ok(name)
}
pub fn source_inventory(fixture: &Path) -> Result<Value> {
    let fixture = fixture.canonicalize()?;
    let root = crate::repository_root(&fixture)?;
    let mut paths = Vec::new();
    visit(&root.join("tools/dev/src"), &mut paths)?;
    if root.join("tools/dev/tests").is_dir() {
        visit(&root.join("tools/dev/tests"), &mut paths)?;
    }
    paths.extend([
        root.join("Cargo.toml"),
        root.join("Cargo.lock"),
        root.join("rust-toolchain.toml"),
        root.join(".cargo/config.toml"),
        root.join("tools/dev/Cargo.toml"),
        fixture.join("inputs.json"),
        fixture.join("Dockerfile"),
        fixture.join("main.go"),
    ]);
    if fixture.join("apiserver.go").is_file() {
        paths.push(fixture.join("apiserver.go"));
    }
    for name in [
        "expected.json",
        "apiserver.expected.json",
        "source-anchors.json",
        "provenance.json",
        "evidence/modules.sha256",
        "evidence/receipt.json",
    ] {
        if fixture.join(name).exists() {
            paths.push(fixture.join(name));
        }
    }
    let mut result = serde_json::Map::new();
    for path in paths {
        result.insert(
            path.strip_prefix(&root)?
                .to_str()
                .ok_or("invalid source path")?
                .to_owned(),
            digest(&path)?.into(),
        );
    }
    Ok(result.into())
}
pub fn inspect_image(runner: &mut Runner, owned: &mut OwnedDocker) -> Result<Value> {
    let raw = runner.bounded(
        &arguments(&["docker", "image", "inspect", &owned.tag]),
        "image-inspect",
        30,
        1024 * 1024,
    )?;
    let inspect = json::parse(&raw)?;
    let id = inspect[0]["Id"].as_str().ok_or("missing owned image ID")?;
    require(
        inspect.as_array().is_some_and(|items| items.len() == 1)
            && inspect[0]["Os"] == "linux"
            && inspect[0]["Architecture"] == "arm64"
            && id.starts_with("sha256:")
            && id.len() == 71
            && id[7..].bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid image ID",
    )?;
    owned.image_id = Some(id.to_owned());
    Ok(inspect)
}
pub fn build(
    runner: &mut Runner,
    owned: &OwnedDocker,
    fixture: &Path,
    args: &CaptureArgs,
    inputs: &Value,
    files: &[&str],
) -> Result<()> {
    let context = tempfile::Builder::new()
        .prefix("diorama-official-build-")
        .tempdir()?;
    fs::copy(&args.source, context.path().join("source.tar.gz"))?;
    fs::copy(&args.go, context.path().join("go.tar.gz"))?;
    for name in files {
        fs::copy(fixture.join(name), context.path().join(name))?;
    }
    let source = format!(
        "SOURCE_SHA256={}",
        inputs["source"]["sha256"]
            .as_str()
            .ok_or("invalid source hash")?
    );
    let mut command = arguments(&[
        "docker",
        "build",
        "--network",
        "none",
        "--platform",
        "linux/arm64",
        "--tag",
        &owned.tag,
        "--build-arg",
        &source,
    ]);
    command.push(context.path().as_os_str().to_owned());
    runner.keep_context(context);
    runner.bounded(&command, "build", 1800, 8 * 1024 * 1024)?;
    Ok(())
}
pub fn run_args(
    owned: &OwnedDocker,
    name: &str,
    index: usize,
    entrypoint: Option<&str>,
) -> Vec<OsString> {
    let host = format!("fixture-{index}");
    let mut argv = arguments(&["docker", "run", "--name", name, "--hostname", &host]);
    if let Some(entrypoint) = entrypoint {
        argv.extend(arguments(&["--entrypoint", entrypoint]));
    }
    argv.extend(arguments(&[
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "512m",
        "--cpus",
        "2",
        "--pids-limit",
        "64",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=16m",
        &owned.tag,
    ]));
    argv
}
pub fn successful(report: &Value) -> bool {
    [
        "errors",
        "cleanup_errors",
        "remaining_containers",
        "remaining_images",
    ]
    .iter()
    .all(|key| report[*key] == value!([]))
        && report["process_cleanup_complete"] == true
        && report["cancelled"] == false
}
pub fn cli(args: &[String]) -> Result<i32> {
    let args = parse_args(args)?;
    let fixture = directory();
    let inputs = load(&fixture.join("inputs.json"))?;
    validate_archives(&inputs, &args)?;
    create_output(&args.output)?;
    let mut owned = OwnedDocker {
        tag: owned_tag("diorama-official-defaults-")?,
        image_id: None,
        containers: Vec::new(),
    };
    let mut report = value!({"schema_version":2,"inputs":inputs,"source_sha256":source_inventory(&fixture)?,"image":owned.tag,"containers":[],"errors":[],"cleanup_errors":[]});
    let mut runner = Runner::with_signals(&args.output)?;
    let result = (|| -> Result<()> {
        build(
            &mut runner,
            &owned,
            &fixture,
            &args,
            &inputs,
            &["main.go", "apiserver.go", "Dockerfile"],
        )?;
        report["image_inspect"] = inspect_image(&mut runner, &mut owned)?;
        for (variant, binary) in [
            ("run", "/out/extract"),
            ("apiserver", "/out/extract-apiserver"),
        ] {
            let mut records = Vec::new();
            for index in 0..2 {
                let name = format!("{}-{variant}-{index}", owned.tag);
                owned.containers.push(name.clone());
                let label = format!("{variant}{index}");
                let raw = runner.bounded(
                    &run_args(&owned, &name, index, Some(binary)),
                    &label,
                    60,
                    2 * 1024 * 1024,
                )?;
                json::parse(&raw)?;
                fs::write(args.output.join(format!("{label}.json")), &raw)?;
                records.push(raw);
            }
            require(records[0] == records[1], "nondeterministic extraction")?;
        }
        report["identical_repeats"] = value!(true);
        report["hostnames"] = value!(["fixture-0", "fixture-1"]);
        report["output_sha256"] = digest(&args.output.join("run0.json"))?.into();
        report["apiserver_output_sha256"] = digest(&args.output.join("apiserver0.json"))?.into();
        let base = load(&args.output.join("run0.json"))?;
        let api = load(&args.output.join("apiserver0.json"))?;
        report["registry_difference"] = registry_difference(
            &base["registered_feature_gates"],
            &api["registered_feature_gates"],
        )?;
        let source = format!("{}:/out/modules.sha256", owned.containers[0]);
        let mut copy = arguments(&["docker", "cp", &source]);
        copy.push(
            args.output
                .canonicalize()?
                .join("modules.sha256")
                .into_os_string(),
        );
        runner.bounded(&copy, "copy-modules", 30, 1024 * 1024)?;
        report["modules_sha256"] = value!(digest(&args.output.join("modules.sha256"))?);
        super::evidence::verify_modules(
            &read_bounded(&args.output.join("modules.sha256"), 1024 * 1024)?,
            &report,
            false,
        )?;
        require(
            report["source_sha256"] == source_inventory(&fixture)?,
            "capture sources changed during execution",
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        push_error(&mut report, "errors", error.to_string());
    }
    report["containers"] = value!(owned.containers);
    report["image_id"] = value!(owned.image_id);
    runner.finish(&mut report, &args.output, &owned)?;
    Ok(i32::from(!successful(&report)))
}
fn registry_difference(before: &Value, after: &Value) -> Result<Value> {
    let a = before.as_object().ok_or("missing feature registry")?;
    let b = after.as_object().ok_or("missing feature registry")?;
    Ok(
        value!({"added":b.keys().filter(|key|!a.contains_key(*key)).collect::<Vec<_>>(),"removed":a.keys().filter(|key|!b.contains_key(*key)).collect::<Vec<_>>(),"changed":a.keys().filter(|key|b.contains_key(*key)&&a[*key]!=b[*key]).collect::<Vec<_>>()}),
    )
}
/// Current-source gate; historical receipts intentionally fail after the driver migration.
pub fn verify_evidence(fixture: &Path, output: &Path, resolved: bool) -> Result<()> {
    let report = load(&output.join("receipt.json"))?;
    require(
        report["schema_version"] == 2,
        "current Rust capture receipt required",
    )?;
    require(successful(&report), "capture or owned cleanup failed")?;
    super::evidence::verify(output, &report, resolved)?;
    require(
        report["identical_repeats"] == true,
        "capture did not repeat identically",
    )?;
    require(
        report["inputs"] == load(&fixture.join("inputs.json"))?,
        "capture inputs mismatch",
    )?;
    require(
        report["source_sha256"] == source_inventory(fixture)?,
        "current capture source inventory mismatch",
    )?;
    require(
        report["retained_build_contexts"] == value!([]) && report["process_failures"] == value!([]),
        "capture retained failed process or context",
    )?;
    let variants: Vec<_> = if resolved {
        vec![("run", "output_sha256", None)]
    } else {
        vec![
            ("run", "output_sha256", Some(false)),
            ("apiserver", "apiserver_output_sha256", Some(true)),
        ]
    };
    for (prefix, key, api) in variants {
        let first = read_bounded(&output.join(format!("{prefix}0.json")), 2 * 1024 * 1024)?;
        let repeat = read_bounded(&output.join(format!("{prefix}1.json")), 2 * 1024 * 1024)?;
        require(first == repeat, "capture repeat bytes differ")?;
        let hash = sha256(&first);
        if resolved {
            require(
                report[key]["run0.json"] == hash && report[key]["run1.json"] == hash,
                "capture output digest mismatch",
            )?;
            crate::resolved_capture::verify_file(&output.join("run0.json"))?;
        } else {
            require(report[key] == hash, "capture output digest mismatch")?;
            let actual = json::parse(&first)?;
            let api = api.ok_or("missing capture variant")?;
            let expected = crate::defaults::load_expected(
                &fixture.join(if api {
                    "apiserver.expected.json"
                } else {
                    "expected.json"
                }),
                api,
            )?;
            require(
                crate::defaults::differences(&expected, &actual).is_empty(),
                "capture default drift",
            )?;
        }
    }
    if !resolved {
        require(
            report["registry_difference"] == value!({"added":[],"removed":[],"changed":[]}),
            "feature registry difference",
        )?;
        require(
            report["hostnames"] == value!(["fixture-0", "fixture-1"]),
            "capture hostname controls",
        )?;
    }
    Ok(())
}
fn visit(path: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        require(
            !entry.file_type()?.is_symlink(),
            "source inventory contains symlink",
        )?;
        if entry.file_type()?.is_dir() {
            visit(&path, paths)?;
        } else if path.extension().is_some_and(|v| v == "rs") {
            paths.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_receipt_publication_preserves_uncertain_owner_and_context() {
        let output = tempfile::tempdir().unwrap();
        fs::create_dir(output.path().join("receipt.json")).unwrap();
        let context = tempfile::tempdir().unwrap();
        let path = context.path().to_owned();
        let mut runner = Runner::new(output.path());
        runner.keep_context(context);
        runner.retained.push(CommandFailure {
            message: "injected unsettled command".into(),
            cleanup_complete: false,
            receipt: value!({"cleanup_complete":false}),
            owner: None,
        });
        let owned = OwnedDocker {
            tag: "owned-test".into(),
            image_id: None,
            containers: vec![],
        };
        let error = runner
            .finish(&mut value!({}), output.path(), &owned)
            .unwrap_err();
        let failure = error
            .downcast_ref::<CaptureFailure>()
            .expect("typed retained owner");
        assert_eq!(failure.owner.retained.len(), 1);
        assert!(failure.message.contains("receipt publication failed"));
        drop(error);
        assert!(path.exists());
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn uncertain_process_retains_context_and_prevents_all_later_commands() {
        let output = tempfile::tempdir().unwrap();
        let context = tempfile::tempdir().unwrap();
        let context_path = context.path().to_owned();
        fs::write(context.path().join("retained"), b"fixture").unwrap();
        let mut runner = Runner::new(output.path());
        runner.keep_context(context);
        runner.retained.push(CommandFailure {
            message: "injected uncertain cleanup".into(),
            cleanup_complete: false,
            receipt: value!({"cleanup_complete":false}),
            owner: None,
        });
        assert!(
            runner
                .bounded(&arguments(&["should-never-execute"]), "unexpected", 1, 32)
                .is_err()
        );
        let owned = OwnedDocker {
            tag: "owned-test".into(),
            image_id: None,
            containers: vec!["owned-a".into(), "owned-b".into()],
        };
        let mut report = value!({"errors":[],"cleanup_errors":[]});
        let error = runner
            .finish(&mut report, output.path(), &owned)
            .unwrap_err();
        assert!(error.downcast_ref::<CaptureFailure>().is_some());
        assert!(context_path.join("retained").exists());
        assert_eq!(report["remaining_containers"], Value::Null);
        assert_eq!(report["remaining_images"], Value::Null);
        assert_eq!(report["process_cleanup_complete"], false);
        assert_eq!(report["retained_build_contexts"], value!([context_path]));
        assert_eq!(fs::read_dir(output.path()).unwrap().count(), 1);
        drop(error);
        assert!(context_path.exists());
        fs::remove_dir_all(context_path).unwrap();
    }
    #[test]
    fn cancellation_stops_capture_without_clearing_the_latch() {
        let output = tempfile::tempdir().unwrap();
        let mut runner = Runner::new(output.path());
        runner.commands.cancellation.request();
        assert!(
            runner
                .bounded(&arguments(&["should-never-execute"]), "unexpected", 1, 32)
                .is_err()
        );
        assert!(runner.commands.cancellation.requested());
        assert_eq!(fs::read_dir(output.path()).unwrap().count(), 0);
    }
    #[test]
    fn cancellation_after_successful_work_prevents_publication_success() {
        let mut report = value!({"errors":[],"cleanup_errors":[],"remaining_containers":[],
            "remaining_images":[],"process_cleanup_complete":true,"cancelled":false});
        assert!(successful(&report));
        report["cancelled"] = value!(true);
        assert!(!successful(&report));
        report.as_object_mut().unwrap().remove("cancelled");
        assert!(!successful(&report));
    }
    #[test]
    fn digest_rejects_fifo_and_symlink_without_blocking() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        assert!(digest(&fifo).is_err());
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&fifo, &link).unwrap();
        assert!(digest(&link).is_err());
    }
    #[test]
    fn source_snapshot_requires_exact_relevant_inventory() {
        let fixture = directory();
        let source = source_inventory(&fixture).unwrap();
        let object = source.as_object().unwrap();
        for required in [
            "Cargo.lock",
            "tools/dev/Cargo.toml",
            "tools/dev/src/defaults/capture.rs",
            "tools/dev/src/resolved_capture/mod.rs",
            "tools/defaults/main.go",
            "tools/defaults/apiserver.go",
            "tools/defaults/Dockerfile",
        ] {
            assert!(object.contains_key(required), "{required}");
        }
        assert!(
            object
                .keys()
                .all(|key| Path::new(key).extension().is_none_or(|ext| ext != "py"))
        );
    }
}
