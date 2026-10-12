use super::source_inventory;
use crate::{
    Result,
    api_json::{load, require},
    defaults::capture::{OwnedDocker, Runner, arguments, digest, push_error},
};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
fn fixture(root: &Path, profile: &str) -> Result<PathBuf> {
    match profile {
        "api-json" => Ok(root.join("tools/api-json")),
        "component-boundary" => Ok(root.join("experiments/component-boundary")),
        _ => Err("unknown component fixture".into()),
    }
}
#[derive(Debug)]
struct FetchFailure {
    _runner: Runner,
    message: String,
}
impl std::fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for FetchFailure {}
#[derive(Debug)]
struct HostFailure {
    error: crate::Error,
    _signals: crate::process::SignalGuard,
}
impl std::fmt::Display for HostFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for HostFailure {}
pub(super) fn fetch(profile: &str) -> Result<()> {
    require(
        cfg!(target_os = "linux")
            && std::env::var("DIORAMA_DISPOSABLE_BUILD").as_deref() == Ok(profile),
        "fetch requires explicit disposable image build",
    )?;
    let inputs = load(Path::new("/experiment/inputs.json"))?;
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        _ => return Err("unsupported fixture architecture".into()),
    };
    let pins = inputs["artifacts"][arch]
        .as_object()
        .ok_or("artifact pins")?;
    require(
        pins.len() == 2 && pins.contains_key("kine") && pins.contains_key("kube-apiserver"),
        "exact artifact inventory",
    )?;
    let temporary = tempfile::tempdir()?;
    let mut runner = Runner::with_signals(temporary.path())?;
    let context = tempfile::tempdir_in("/usr/local/bin")?;
    let context_path = context.path().to_owned();
    runner.keep_context(context);
    let result = (|| -> Result<()> {
        for (name, pin) in pins {
            let url = pin["url"].as_str().ok_or("artifact URL")?;
            require(url.starts_with("https://"), "artifact HTTPS required")?;
            let path = context_path.join(name);
            let mut args = arguments(&[
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--connect-timeout",
                "30",
                "--max-time",
                "300",
                "--max-filesize",
                "268435456",
                "--output",
            ]);
            args.push(path.as_os_str().to_owned());
            args.extend(arguments(&[url]));
            runner.bounded(&args, &format!("fetch-{name}"), 310, 256 * 1024 * 1024)?;
            require(digest(&path)? == pin["sha256"], "artifact digest mismatch")?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
            require(
                !runner.commands.cancellation.requested(),
                "artifact fetch cancelled before publication",
            )?;
            fs::hard_link(path, Path::new("/usr/local/bin").join(name))?;
        }
        require(
            !runner.commands.cancellation.requested(),
            "artifact fetch cancelled",
        )?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            let logs = temporary.keep();
            Err(Box::new(FetchFailure {
                _runner: runner,
                message: format!(
                    "artifact fetch failed: {error}; logs retained at {}",
                    logs.display()
                ),
            }))
        },
    }
}
fn copy_sources(root: &Path, context: &Path, inventory: &Value) -> Result<()> {
    // The complete Rust workspace lets Cargo resolve members while building only diorama-dev.
    for name in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"] {
        fs::copy(root.join(name), context.join(name))?;
    }
    for name in [
        ".cargo",
        "crates",
        "third_party",
        "tools/dev",
        "tools/upstream",
        "tools/api-json",
        "experiments/component-boundary",
    ] {
        copy_tree(&root.join(name), &context.join(name))?;
    }
    for (name, hash) in inventory.as_object().ok_or("source inventory")? {
        require(
            digest(&context.join(name))? == *hash,
            "copied source digest",
        )?;
    }
    Ok(())
}
fn copy_tree(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if [
            "target",
            "evidence",
            "rust-evidence",
            "evidence-rust",
            ".git",
            "__pycache__",
            ".DS_Store",
        ]
        .iter()
        .any(|n| name == *n)
        {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_tree(&entry.path(), &target.join(name))?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target.join(name))?;
        } else {
            return Err("source context contains special file".into());
        }
    }
    Ok(())
}
#[expect(
    clippy::too_many_lines,
    reason = "One owned orchestration boundary retains runner and context through diagnostics and cleanup"
)]
pub(super) fn capture(profile: &str, output: &Path) -> Result<()> {
    let root = crate::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
    let source = source_inventory(&root, profile)?;
    let fixture = fixture(&root, profile)?;
    fs::create_dir(output)?;
    let destination = output.canonicalize()?;
    let output = destination.as_path();
    let mut runner = Runner::new(output);
    let cancellation = runner.commands.cancellation.clone();
    let signals = crate::process::SignalGuard::install(cancellation.clone())?;
    let tag = crate::defaults::capture::owned_tag(&format!("diorama-{profile}-"))?;
    let name = format!("{tag}-capture");
    let owned = OwnedDocker {
        tag: tag.clone(),
        image_id: None,
        containers: vec![name.clone()],
    };
    let mut report = json!({"schema_version":2,"exit_code":1,"errors":[],"cleanup_errors":[],"source_sha256":source,"owned_container":name,"owned_image":tag});
    let status = (|| -> Result<()> {
        let context = tempfile::Builder::new()
            .prefix("diorama-component-context-")
            .tempdir_in("/tmp")?;
        let path = context.path().to_owned();
        runner.keep_context(context);
        copy_sources(&root, &path, &source)?;
        let dockerfile = path.join(fixture.strip_prefix(&root)?).join("Dockerfile");
        let mut build = arguments(&["docker", "build", "--progress=plain", "--tag", &tag, "-f"]);
        build.push(dockerfile.into_os_string());
        build.push(path.into_os_string());
        runner.bounded(&build, "build", 900, 16 * 1024 * 1024)?;
        runner.bounded(
            &arguments(&[
                "docker",
                "create",
                "--name",
                &name,
                "--network=none",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--memory=1g",
                "--cpus=2",
                "--pids-limit=256",
                &tag,
            ]),
            "create",
            30,
            65536,
        )?;
        runner.bounded(
            &arguments(&["docker", "start", "--attach", &name]),
            "execute",
            600,
            2 * 1024 * 1024,
        )?;
        report["exit_code"] = 0.into();
        Ok(())
    })();
    if let Err(error) = status {
        push_error(&mut report, "errors", error.to_string());
    }
    // Independent diagnostics continue after settled failures. Runner blocks uncertain ownership.
    let mut copy = arguments(&["docker", "cp", &format!("{name}:/evidence/.")]);
    copy.push(output.as_os_str().to_owned());
    for (label, args) in [
        ("copy-evidence", copy),
        (
            "container-inspect",
            arguments(&["docker", "inspect", &name]),
        ),
        (
            "image-inspect",
            arguments(&["docker", "image", "inspect", &tag]),
        ),
    ] {
        match runner.bounded(&args, label, 30, 8 * 1024 * 1024) {
            Ok(bytes) if label != "copy-evidence" => {
                if let Err(error) = fs::write(output.join(format!("{label}.json")), bytes) {
                    push_error(
                        &mut report,
                        "errors",
                        format!("{label} publication: {error}"),
                    );
                }
            },
            Ok(_) => {},
            Err(error) => push_error(&mut report, "errors", format!("{label}: {error}")),
        }
    }
    let finish = runner.finish(&mut report, output, &owned);
    match command_inventory(output) {
        Ok(commands) => report["commands"] = commands,
        Err(error) => push_error(&mut report, "errors", format!("command evidence: {error}")),
    }
    if !crate::defaults::capture::successful(&report) {
        report["exit_code"] = 1.into();
    }
    if !source_inventory(&root, profile).is_ok_and(|current| current == source) {
        push_error(
            &mut report,
            "errors",
            "source changed or unreadable during capture".into(),
        );
        report["exit_code"] = 1.into();
    }
    if cancellation.requested() {
        report["cancelled"] = true.into();
        report["exit_code"] = 1.into();
    }
    let publication = super::create_report(&output.join("runner-result.json"), &report);
    let _signals = match finish {
        Ok(()) => signals,
        Err(error) => {
            return Err(Box::new(HostFailure {
                error,
                _signals: signals,
            }));
        },
    };
    let mut published = publication?;
    require(
        report["exit_code"] == 0,
        "component capture or cleanup failed",
    )?;
    if profile == "api-json" {
        crate::api_json::check_capture(output)?;
    } else {
        super::verify(output)?;
    }
    if cancellation.requested() {
        report["cancelled"] = true.into();
        report["exit_code"] = 1.into();
        super::rewrite_report(&mut published, &report)?;
        return Err("component capture cancelled during final verification".into());
    }
    Ok(())
}
fn command_inventory(output: &Path) -> Result<Value> {
    let mut commands = serde_json::Map::new();
    for name in [
        "build",
        "create",
        "execute",
        "copy-evidence",
        "container-inspect",
        "image-inspect",
        "cleanup-1",
        "cleanup-2",
        "cleanup-3",
        "cleanup-4",
    ] {
        commands.insert(name.into(), json!({"receipt_sha256":digest(&output.join(format!("{name}.command.json")))?,"log_sha256":digest(&output.join(format!("{name}.log")))?}));
    }
    Ok(commands.into())
}
pub(super) fn verify_commands(output: &Path, runner: &Value) -> Result<()> {
    require(
        runner["commands"] == command_inventory(output)?,
        "runner command evidence hashes",
    )?;
    let tag = runner["owned_image"].as_str().ok_or("owned image")?;
    let container = runner["owned_container"]
        .as_str()
        .ok_or("owned container")?;
    require(
        (tag.starts_with("diorama-api-json-") || tag.starts_with("diorama-component-boundary-"))
            && tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && container == format!("{tag}-capture"),
        "owned resource identity",
    )?;
    for (label, hashes) in runner["commands"].as_object().ok_or("command inventory")? {
        let receipt = load(&output.join(format!("{label}.command.json")))?;
        require(
            receipt["owned_pid"]
                .as_u64()
                .is_some_and(|pid| pid > 0 && u32::try_from(pid).is_ok())
                && receipt["owner_directory"].as_str().is_some_and(|p| {
                    Path::new(p).is_absolute()
                        && Path::new(p)
                            .file_name()
                            .is_some_and(|n| n.to_string_lossy().starts_with("diorama-process-"))
                }),
            "command process ownership",
        )?;
        for key in [
            "spawned",
            "owned_process_group_absent",
            "cleanup_complete",
            "output_eof",
            "merged_output",
        ] {
            require(receipt[key] == true, "command settlement")?;
        }
        for key in ["timeout", "cancelled", "output_limit"] {
            require(receipt[key] == false, "command failure flag")?;
        }
        require(
            receipt["cleanup_errors"] == json!([]) && receipt["exit_code"].as_i64() == Some(0),
            "command unsuccessful",
        )?;
        require(
            receipt["stdout_sha256"] == hashes["log_sha256"]
                && receipt["stderr_sha256"] == crate::sha256(b""),
            "command raw log binding",
        )?;
        verify_argv(label, &receipt["argv"], tag, container)?;
        if matches!(label.as_str(), "cleanup-3" | "cleanup-4") {
            require(
                crate::read_bounded(&output.join(format!("{label}.log")), 8 * 1024 * 1024)?
                    .iter()
                    .all(u8::is_ascii_whitespace),
                "owned Docker inventory not empty",
            )?;
        }
    }
    verify_inspections(output, tag, container)?;
    Ok(())
}
fn verify_inspections(output: &Path, tag: &str, container: &str) -> Result<()> {
    let mut inspections = Vec::new();
    for label in ["container-inspect", "image-inspect"] {
        let raw = load(&output.join(format!("{label}.log")))?;
        require(
            raw == load(&output.join(format!("{label}.json")))?,
            "inspection copy differs from command",
        )?;
        require(
            raw.as_array().is_some_and(|rows| rows.len() == 1),
            "inspection object count",
        )?;
        inspections.push(raw[0].clone());
    }
    let container_row = &inspections[0];
    let image = &inspections[1];
    require(
        container_row["Name"] == format!("/{container}")
            && container_row["Config"]["Image"] == tag
            && container_row["Image"] == image["Id"]
            && image["Id"]
                .as_str()
                .is_some_and(|id| id.starts_with("sha256:") && id.len() == 71),
        "inspection owned identity",
    )?;
    require(
        container_row["State"]["Running"] == false
            && container_row["State"]["ExitCode"].as_i64() == Some(0)
            && container_row["State"]["OOMKilled"] == false
            && container_row["State"]["Error"] == "",
        "container final status",
    )?;
    let host = &container_row["HostConfig"];
    require(
        host["NetworkMode"] == "none"
            && host["CapDrop"] == json!(["ALL"])
            && host["SecurityOpt"] == json!(["no-new-privileges"])
            && host["Memory"].as_u64() == Some(1_073_741_824)
            && host["NanoCpus"].as_u64() == Some(2_000_000_000)
            && host["PidsLimit"].as_u64() == Some(256)
            && container_row["Config"]["User"] == "65532:65532",
        "container runtime isolation",
    )?;
    Ok(())
}
#[cfg(test)]
pub(crate) fn synthetic_command_evidence(output: &Path) -> Value {
    // Synthetic validator input only: never published as execution evidence.
    let tag = "diorama-api-json-fixture";
    let container = format!("{tag}-capture");
    let rows = [
        (
            "build",
            json!([
                "docker",
                "build",
                "--progress=plain",
                "--tag",
                tag,
                "-f",
                "/tmp/diorama-component-context-fixture/tools/api-json/Dockerfile",
                "/tmp/diorama-component-context-fixture"
            ]),
        ),
        (
            "create",
            json!([
                "docker",
                "create",
                "--name",
                container,
                "--network=none",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--memory=1g",
                "--cpus=2",
                "--pids-limit=256",
                tag
            ]),
        ),
        ("execute", json!(["docker", "start", "--attach", container])),
        (
            "copy-evidence",
            json!(["docker", "cp", format!("{container}:/evidence/."), output]),
        ),
        ("container-inspect", json!(["docker", "inspect", container])),
        ("image-inspect", json!(["docker", "image", "inspect", tag])),
        ("cleanup-1", json!(["docker", "rm", "--force", container])),
        (
            "cleanup-2",
            json!(["docker", "image", "rm", "--force", tag]),
        ),
        (
            "cleanup-3",
            json!([
                "docker",
                "ps",
                "-aq",
                "--filter",
                format!("name=^/{}$", regex::escape(&container))
            ]),
        ),
        (
            "cleanup-4",
            json!([
                "docker",
                "images",
                "--no-trunc",
                "-q",
                "--filter",
                format!("reference={tag}")
            ]),
        ),
    ];
    for (name, argv) in rows {
        let raw = match name {
            "cleanup-3" | "cleanup-4" => String::new(),
            "container-inspect" => json!([{"Name":format!("/{container}"),"Config":{"Image":tag,"User":"65532:65532"},"Image":format!("sha256:{}", "a".repeat(64)),"State":{"Running":false,"ExitCode":0,"OOMKilled":false,"Error":""},"HostConfig":{"NetworkMode":"none","CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Memory":1_073_741_824_u64,"NanoCpus":2_000_000_000_u64,"PidsLimit":256}}]).to_string(),
            "image-inspect" => json!([{"Id":format!("sha256:{}", "a".repeat(64))}]).to_string(),
            _ => format!("synthetic {name}\n"),
        };
        if matches!(name, "container-inspect" | "image-inspect") {
            fs::write(output.join(format!("{name}.json")), &raw).unwrap();
        }

        fs::write(output.join(format!("{name}.log")), &raw).unwrap();
        crate::defaults::capture::write_json(&output.join(format!("{name}.command.json")), &json!({"spawned":true,"owned_pid":123,"owner_directory":"/tmp/diorama-process-fixture","owned_process_group_absent":true,"cleanup_complete":true,"output_eof":true,"merged_output":true,"timeout":false,"cancelled":false,"output_limit":false,"cleanup_errors":[],"exit_code":0,"stdout_sha256":crate::sha256(raw.as_bytes()),"stderr_sha256":crate::sha256(b""),"argv":argv})).unwrap();
    }
    json!({"schema_version":2,"exit_code":0,"errors":[],"cleanup_errors":[],"cancelled":false,"remaining_containers":[],"remaining_images":[],"process_cleanup_complete":true,"owned_image":tag,"owned_container":container,"commands":command_inventory(output).unwrap()})
}

fn verify_argv(label: &str, command: &Value, tag: &str, container: &str) -> Result<()> {
    let argv = command.as_array().ok_or("command argv")?;
    require(
        argv.first() == Some(&Value::from("docker")),
        "command executable",
    )?;
    let expected = match label {
        "create" => Some(json!([
            "docker",
            "create",
            "--name",
            container,
            "--network=none",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory=1g",
            "--cpus=2",
            "--pids-limit=256",
            tag
        ])),
        "execute" => Some(json!(["docker", "start", "--attach", container])),
        "container-inspect" => Some(json!(["docker", "inspect", container])),
        "image-inspect" => Some(json!(["docker", "image", "inspect", tag])),
        "cleanup-1" => Some(json!(["docker", "rm", "--force", container])),
        "cleanup-2" => Some(json!(["docker", "image", "rm", "--force", tag])),
        "cleanup-3" => Some(json!([
            "docker",
            "ps",
            "-aq",
            "--filter",
            format!("name=^/{}$", regex::escape(container))
        ])),
        "cleanup-4" => Some(json!([
            "docker",
            "images",
            "--no-trunc",
            "-q",
            "--filter",
            format!("reference={tag}")
        ])),
        "copy-evidence" => {
            require(
                argv.len() == 4
                    && argv[1] == "cp"
                    && argv[2] == format!("{container}:/evidence/.")
                    && argv[3].as_str().is_some_and(|p| Path::new(p).is_absolute()),
                "copy evidence command",
            )?;
            None
        },
        "build" => {
            require(
                argv.len() == 8
                    && argv[..5]
                        == [
                            json!("docker"),
                            json!("build"),
                            json!("--progress=plain"),
                            json!("--tag"),
                            json!(tag),
                        ]
                    && argv[5] == "-f",
                "build command",
            )?;
            let context = argv[7].as_str().ok_or("build context")?;
            require(
                context.starts_with("/tmp/diorama-component-context-")
                    && !context.contains("..")
                    && argv[6].as_str().is_some_and(|p| {
                        p == format!(
                            "{context}/{}/Dockerfile",
                            if tag.starts_with("diorama-api-json-") {
                                "tools/api-json"
                            } else {
                                "experiments/component-boundary"
                            }
                        )
                    }),
                "owned build context",
            )?;
            None
        },
        _ => return Err("unexpected command evidence".into()),
    };
    if let Some(expected) = expected {
        require(*command == expected, "exact owned command")?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rehashed_cleanup_inventory_and_inspection_mutations_fail() {
        for label in [
            "cleanup-3",
            "cleanup-4",
            "container-inspect",
            "image-inspect",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let output = directory.path();
            let mut runner = synthetic_command_evidence(output);
            verify_commands(output, &runner).unwrap();
            let log = output.join(format!("{label}.log"));
            let bytes = if label.starts_with("cleanup") {
                b"remaining-owned-resource\n".to_vec()
            } else {
                let mut value = load(&log).unwrap();
                value[0]["Id"] = "foreign".into();
                value[0]["Name"] = "/foreign".into();
                let bytes = serde_json::to_vec(&value).unwrap();
                fs::write(output.join(format!("{label}.json")), &bytes).unwrap();
                bytes
            };
            fs::write(&log, &bytes).unwrap();
            let path = output.join(format!("{label}.command.json"));
            let mut receipt = load(&path).unwrap();
            receipt["stdout_sha256"] = crate::sha256(&bytes).into();
            fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
            runner["commands"] = command_inventory(output).unwrap();
            assert!(verify_commands(output, &runner).is_err(), "{label}");
        }
        let directory = tempfile::tempdir().unwrap();
        let runner = synthetic_command_evidence(directory.path());
        fs::write(directory.path().join("image-inspect.json"), b"[]").unwrap();
        assert!(verify_commands(directory.path(), &runner).is_err());
    }
    #[test]
    fn docker_commands_require_exact_isolation_and_owned_cleanup() {
        let tag = "diorama-api-json-unique";
        let container = "diorama-api-json-unique-capture";
        let command = json!([
            "docker",
            "create",
            "--name",
            container,
            "--network=none",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory=1g",
            "--cpus=2",
            "--pids-limit=256",
            tag
        ]);
        verify_argv("create", &command, tag, container).unwrap();
        for (index, mutation) in [
            (3, json!("unowned")),
            (4, json!("--network=host")),
            (5, json!("--privileged")),
            (10, json!("other-image")),
        ] {
            let mut changed = command.clone();
            changed[index] = mutation;
            assert!(verify_argv("create", &changed, tag, container).is_err());
        }
        assert!(
            verify_argv(
                "cleanup-1",
                &json!(["docker", "rm", "--force", "unowned"]),
                tag,
                container
            )
            .is_err()
        );
        assert!(
            verify_argv(
                "cleanup-2",
                &json!(["docker", "image", "rm", "--force", "sha256:shared-image-id"]),
                tag,
                container
            )
            .is_err()
        );
        assert!(
            verify_argv(
                "build",
                &json!([
                    "docker",
                    "build",
                    "--progress=plain",
                    "--tag",
                    tag,
                    "-f",
                    "/tmp/other/Dockerfile",
                    "/tmp/other"
                ]),
                tag,
                container
            )
            .is_err()
        );
    }
    #[test]
    fn copied_source_rejects_symlinks_and_preserves_exact_bytes() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        fs::write(source.path().join("source.rs"), b"source").unwrap();
        copy_tree(source.path(), destination.path()).unwrap();
        assert_eq!(
            fs::read(destination.path().join("source.rs")).unwrap(),
            b"source"
        );
        std::os::unix::fs::symlink("source.rs", source.path().join("alias")).unwrap();
        assert!(copy_tree(source.path(), destination.path()).is_err());
    }
}
