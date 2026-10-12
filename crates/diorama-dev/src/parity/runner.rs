//! Owned Docker adapters. Every inventory failure is retained as failed cleanup.
use super::{
    Options, Result,
    contract::{self, Artifact, Suite},
    process::{Cancellation, CommandFailure, Commands},
    require,
};
use serde_json::{Value, json};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;
const RUST: &str = "rust@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97";
// Same pinned Debian/CGO baseline builder; the Rust static driver needs no interpreter.
const DEBIAN: &str = "golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd";
#[derive(Debug, Default)]
struct Failures {
    messages: Vec<String>,
    retained: Vec<CommandFailure>,
}
impl Failures {
    fn push(&mut self, message: String) {
        self.messages.push(message);
    }
    fn record(&mut self, label: &str, error: diorama_dev::Error) {
        self.messages.push(format!("{label}: {error}"));
        if let Ok(failure) = error.downcast::<CommandFailure>()
            && !failure.cleanup_complete
        {
            self.retained.push(*failure);
        }
    }
    fn uncertain(&self) -> bool {
        !self.retained.is_empty()
    }
    fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "owned command cleanup uncertain; {} retained owners",
            self.retained.len()
        )
    }
}
impl std::error::Error for Failures {}
fn final_status(status: u8, cancellation: &Cancellation, errors: &mut Failures) -> u8 {
    if cancellation.requested() {
        errors.push("cancelled through Docker settlement".into());
    }
    if errors.is_empty() { status } else { 1 }
}
fn invoke(
    commands: &Commands,
    label: &str,
    argv: impl AsRef<[OsString]>,
    timeout: u64,
    limit: u64,
) -> Result<super::process::CommandResult> {
    commands.run(
        label,
        argv.as_ref(),
        Duration::from_secs(timeout),
        b"",
        true,
        limit,
    )
}
fn copy_tree(source: &Path, target: &Path, total: &mut u64) -> Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if ["target", "evidence", ".git", "__pycache__"]
            .iter()
            .any(|n| name == *n)
        {
            continue;
        }
        let kind = entry.file_type()?;
        require(!kind.is_symlink(), "source symlink in driver build context")?;
        if kind.is_dir() {
            copy_tree(&entry.path(), &target.join(name), total)?;
        } else if kind.is_file() {
            let bytes = super::read(&entry.path(), 32 * 1024 * 1024)?;
            *total += bytes.len() as u64;
            require(*total <= 256 * 1024 * 1024, "driver source context bound")?;
            fs::write(target.join(name), bytes)?;
        }
    }
    Ok(())
}
fn image_context(
    root: &Path,
    context: &Path,
    artifact_path: &Path,
    suite_path: &Path,
    artifact: &Artifact,
    suite: &Suite,
    driver: Option<&OsString>,
) -> Result<String> {
    let binary = artifact_path
        .parent()
        .ok_or("artifact directory")?
        .join(&artifact.binary)
        .canonicalize()?;
    require(
        super::digest(&binary, false)? == artifact.sha256,
        "artifact digest mismatch",
    )?;
    fs::copy(binary, context.join("executable"))?;
    fs::set_permissions(
        context.join("executable"),
        fs::Permissions::from_mode(0o755),
    )?;
    fs::copy(artifact_path, context.join("artifact.json"))?;
    fs::copy(suite_path, context.join("suite.json"))?;
    contract::stage_files(&suite.cases, &context.join("fixtures"))?;
    let prelude = if let Some(driver) = driver {
        fs::copy(Path::new(driver), context.join("diorama-parity"))?;
        format!("FROM {DEBIAN}\nCOPY diorama-parity /artifact/diorama-parity\n")
    } else {
        let source = context.join("source");
        fs::create_dir(&source)?;
        let mut total = 0;
        for name in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"] {
            fs::copy(root.join(name), source.join(name))?;
        }
        for name in [
            ".cargo",
            "crates",
            "third_party",
            "tools/upstream",
            "tools/dev",
        ] {
            copy_tree(&root.join(name), &source.join(name), &mut total)?;
        }
        format!(
            "FROM {RUST} AS driver\nWORKDIR /source\nCOPY source/ ./\nRUN cargo build --release --locked -p diorama-dev --bin diorama-parity\nFROM {DEBIAN}\nCOPY --from=driver /source/target/release/diorama-parity /artifact/diorama-parity\n"
        )
    };
    let dockerfile = format!(
        "{prelude}WORKDIR /artifact\nCOPY executable artifact.json suite.json ./\nCOPY fixtures /fixtures\nRUN mkdir /evidence && chmod 0700 /evidence\nENTRYPOINT [\"/artifact/diorama-parity\",\"driver\"]\n"
    );
    fs::write(context.join("Dockerfile"), &dockerfile)?;
    Ok(diorama_dev::sha256(dockerfile.as_bytes()))
}
fn inventory(commands: &Commands, label: &str, kind: &str, target: &str) -> Result<bool> {
    let filter = if kind == "container" {
        format!("name=^/{target}$")
    } else if kind == "image" {
        format!("reference={target}")
    } else {
        format!("name={target}")
    };
    let argv = if kind == "volume" {
        vec![
            "docker".into(),
            "volume".into(),
            "ls".into(),
            "--filter".into(),
            filter.into(),
            "--format".into(),
            "{{.Name}}".into(),
        ]
    } else {
        vec![
            "docker".into(),
            kind.into(),
            "ls".into(),
            "--all".into(),
            "--filter".into(),
            filter.into(),
            "--quiet".into(),
        ]
    };
    let result = invoke(commands, label, argv, 30, 256 * 1024)?;
    Ok(if kind == "volume" {
        result.stdout.lines().any(|line| line == target)
    } else {
        !result.stdout.trim().is_empty()
    })
}
fn cleanup(commands: &Commands, kind: &str, target: &str, errors: &mut Failures) {
    if errors.uncertain() {
        return;
    }
    match inventory(commands, &format!("{kind}-inventory"), kind, target) {
        Ok(true) => {
            let removal = if kind == "container" {
                vec![
                    "docker".into(),
                    "rm".into(),
                    "--force".into(),
                    target.into(),
                ]
            } else {
                vec!["docker".into(), kind.into(), "rm".into(), target.into()]
            };
            if let Err(e) = invoke(commands, &format!("{kind}-remove"), removal, 30, 256 * 1024) {
                errors.record(&format!("{kind} removal"), e);
            }
        },
        Ok(false) => {},
        Err(e) => errors.record(&format!("{kind} inventory unknown"), e),
    }
    if errors.uncertain() {
        return;
    }
    match inventory(commands, &format!("{kind}-verify-removal"), kind, target) {
        Ok(false) => {},
        Ok(true) => errors.push(format!("owned {kind} remains")),
        Err(e) => errors.record(&format!("{kind} final inventory unknown"), e),
    }
}
#[allow(
    clippy::too_many_lines,
    reason = "Keep owned Docker resources and their settlement in one scope"
)]
pub(crate) fn run(options: &Options, cancellation: Cancellation) -> Result<u8> {
    let root = options.root()?;
    let output = options.path("--output")?;
    fs::create_dir_all(output.parent().ok_or("output parent")?)?;
    fs::create_dir(&output)?;
    let context = tempfile::Builder::new()
        .prefix("diorama-parity-context-")
        .tempdir()?;
    let token = diorama_dev::sha256(context.path().as_os_str().as_encoded_bytes());
    let owned = format!("diorama-parity-{}", &token[..24]);
    let image = format!("{owned}:test");
    let volume = format!("{owned}-evidence");
    let commands = Commands {
        output: output.clone(),
        cancellation,
    };
    let cleanup_commands = Commands {
        output: output.clone(),
        cancellation: Cancellation::default(),
    };
    let mut errors = Failures::default();
    let mut status = 1;
    let mut hashes = Value::Object(serde_json::Map::new());
    let outcome = (|| -> Result<()> {
        let artifact_path = options.path("--artifact")?;
        let suite_path = options.path("--suite")?;
        let artifact: Artifact = serde_json::from_value(super::json_file(&artifact_path)?)?;
        let suite: Suite = serde_json::from_value(super::json_file(&suite_path)?)?;
        contract::validate(&artifact, &suite)?;
        hashes["Dockerfile"] = json!(image_context(
            &root,
            context.path(),
            &artifact_path,
            &suite_path,
            &artifact,
            &suite,
            options.values.get("--driver")
        )?);
        hashes["suite"] = json!(super::digest(&suite_path, false)?);
        hashes["artifact_descriptor"] = json!(super::digest(&artifact_path, false)?);
        hashes["runner"] = json!(super::digest(&std::env::current_exe()?, false)?);
        invoke(
            &commands,
            "build",
            vec![
                "docker".into(),
                "build".into(),
                "--tag".into(),
                image.clone().into(),
                context.path().into(),
            ],
            900,
            8 * 1024 * 1024,
        )?;
        let mut create = super::args(&[
            "docker",
            "create",
            "--name",
            &owned,
            "--network=none",
            "--cap-drop=ALL",
            "--cap-add=SETUID",
            "--cap-add=SETGID",
            "--cap-add=KILL",
            "--security-opt=no-new-privileges",
            "--memory=1g",
            "--pids-limit=128",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
            "--mount",
            &format!("type=volume,source={volume},target=/evidence"),
        ]);
        if let Some(injection) = options.injected()? {
            create.extend(super::args(&[
                "--env",
                &format!("PARITY_INJECT_FAILURE={injection}"),
            ]));
        }
        create.push(image.clone().into());
        invoke(&commands, "create", create, 30, 256 * 1024)?;
        invoke(
            &commands,
            "image-inspect",
            super::args(&["docker", "image", "inspect", &image]),
            30,
            256 * 1024,
        )?;
        let result = commands.run(
            "container",
            &super::args(&["docker", "start", "--attach", &owned]),
            Duration::from_mins(10),
            b"",
            false,
            8 * 1024 * 1024,
        )?;
        status = u8::try_from(result.code).unwrap_or(1);
        Ok(())
    })();
    if let Err(error) = outcome {
        errors.record("prepare-or-run", error);
    }
    let inventory = if errors.uncertain() {
        Ok(false)
    } else {
        inventory(
            &cleanup_commands,
            "evidence-container-inventory",
            "container",
            &owned,
        )
    };
    let present = match inventory {
        Ok(present) => present,
        Err(error) => {
            errors.record("evidence container inventory", error);
            false
        },
    };
    if present
        && let Err(error) = invoke(
            &cleanup_commands,
            "container-inspect",
            super::args(&["docker", "container", "inspect", &owned]),
            30,
            256 * 1024,
        )
    {
        errors.record("container inspection", error);
    }
    if present && !errors.uncertain() {
        let copied = invoke(
            &cleanup_commands,
            "evidence-archive",
            super::args(&["docker", "cp", &format!("{owned}:/evidence/."), "-"]),
            30,
            64 * 1024 * 1024,
        );
        match copied {
            Ok(_) => {
                let publication =
                    super::read(&output.join("evidence-archive.stdout"), 64 * 1024 * 1024)
                        .and_then(|bytes| super::archive::publish(&bytes, &output));
                if let Err(error) = publication {
                    errors.record("evidence publication", error);
                }
            },
            Err(e) => errors.record("evidence copy", e),
        }
    }
    cleanup(&cleanup_commands, "container", &owned, &mut errors);
    cleanup(&cleanup_commands, "image", &image, &mut errors);
    cleanup(&cleanup_commands, "volume", &volume, &mut errors);
    if !errors.is_empty() {
        status = 1;
    }
    let context_path = context.path().to_path_buf();
    let context_removed = if errors.uncertain() {
        let _ = context.keep();
        false
    } else {
        match context.close() {
            Ok(()) => true,
            Err(error) => {
                errors.push(format!("build context cleanup: {error}"));
                false
            },
        }
    };
    status = final_status(status, &commands.cancellation, &mut errors);
    let published = super::write_json(
        &output.join("runner-result.json"),
        &json!({"schema_version":1,"exit_code":status,"errors":errors.messages,"source_sha256":hashes,"owned_container":owned,"owned_image":image,"owned_volume":volume,"owned_context":context_path,"owned_context_removed":context_removed,"cleanup_uncertain":errors.uncertain(),"retained_commands":errors.retained.iter().map(|e|&e.receipt).collect::<Vec<_>>()}),
        true,
    );
    if errors.uncertain() {
        Err(Box::new(errors))
    } else {
        published?;
        Ok(status)
    }
}
pub(crate) fn prepare_upstream(options: &Options, cancellation: Cancellation) -> Result<u8> {
    let root = options.root()?;
    let output = options.path("--output")?;
    fs::create_dir(&output)?;
    let token = tempfile::Builder::new()
        .prefix("diorama-upstream-")
        .tempdir()?;
    let hash = diorama_dev::sha256(token.path().as_os_str().as_encoded_bytes());
    let image = format!("diorama-parity-build:{}", &hash[..24]);
    let container = format!("diorama-parity-build-{}", &hash[..24]);
    let commands = Commands {
        output: output.clone(),
        cancellation,
    };
    let cleanup_commands = Commands {
        output: output.clone(),
        cancellation: Cancellation::default(),
    };
    let mut errors = Failures::default();
    let outcome = (|| -> Result<()> {
        let source = root.join("tools/parity");
        let dockerfile = source.join("Upstream.Dockerfile");
        invoke(
            &commands,
            "build",
            vec![
                "docker".into(),
                "build".into(),
                "--file".into(),
                dockerfile.as_os_str().to_owned(),
                "--tag".into(),
                image.clone().into(),
                source.into(),
            ],
            1800,
            8 * 1024 * 1024,
        )?;
        invoke(
            &commands,
            "create",
            super::args(&[
                "docker",
                "create",
                "--name",
                &container,
                &image,
                "/not-executed",
            ]),
            30,
            256 * 1024,
        )?;
        // The trusted pinned build owns these two exact artifacts. No archive is extracted.
        for name in ["kubesolo", "build-info.txt"] {
            invoke(
                &commands,
                &format!("copy-{name}").replace('.', "-"),
                vec![
                    "docker".into(),
                    "cp".into(),
                    format!("{container}:/artifact/{name}").into(),
                    output.join(name).into(),
                ],
                60,
                256 * 1024,
            )?;
            require(
                fs::symlink_metadata(output.join(name))?.is_file(),
                "regular upstream artifact required",
            )?;
        }
        invoke(
            &commands,
            "image-inspect",
            super::args(&["docker", "image", "inspect", &image]),
            30,
            256 * 1024,
        )?;
        let artifact = json!({"schema_version":1,"kind":"go","binary":"kubesolo","sha256":super::digest(&output.join("kubesolo"),false)?,"version":"2ef1c4787989f11f868f81bb84ae2afd4a49a81d","source":{"repository":"https://github.com/portainer/kubesolo","revision":"2ef1c4787989f11f868f81bb84ae2afd4a49a81d"},"build":{"variant":"external_deps","toolchain":"go1.26.5","cgo":true,"dockerfile_sha256":super::digest(&dockerfile,false)?,"source_archive_sha256":"9d5f3ce1f3fbda971fb1e2fb6da18ae3880caeec677f0e5d928a3bbe7bb76aec"}});
        super::write_json(&output.join("artifact.json"), &artifact, true)?;
        Ok(())
    })();
    if let Err(error) = outcome {
        errors.record("prepare upstream", error);
    }
    cleanup(&cleanup_commands, "container", &container, &mut errors);
    cleanup(&cleanup_commands, "image", &image, &mut errors);
    if errors.uncertain() {
        let _ = token.keep();
    }
    let status = final_status(0, &commands.cancellation, &mut errors);
    let published = super::write_json(
        &output.join("preparation-result.json"),
        &json!({"exit_code":status,"errors":errors.messages,"owned_container":container,"owned_image":image,"cleanup_uncertain":errors.uncertain(),"retained_commands":errors.retained.iter().map(|e|&e.receipt).collect::<Vec<_>>()}),
        true,
    );
    if errors.uncertain() {
        Err(Box::new(errors))
    } else {
        published?;
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_during_independent_cleanup_prevents_success() {
        let capture = Cancellation::default();
        let cleanup = Cancellation::default();
        let mut errors = Failures::default();
        assert_eq!(final_status(0, &capture, &mut errors), 0);
        capture.request();
        assert!(!cleanup.requested());
        assert_eq!(final_status(0, &capture, &mut errors), 1);
        assert!(
            errors
                .messages
                .iter()
                .any(|message| message.contains("cancelled through Docker settlement"))
        );
    }
}
