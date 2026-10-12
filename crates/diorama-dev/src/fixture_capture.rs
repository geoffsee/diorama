//! Owned, bounded captures of pinned distribution Go harnesses.
use crate::{
    Result,
    defaults::capture::{self, OwnedDocker, Runner},
    fixture_oracles as oracle,
};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

const REVISION: &str = "2ef1c4787989f11f868f81bb84ae2afd4a49a81d";
const SOURCE: &str = "9d5f3ce1f3fbda971fb1e2fb6da18ae3880caeec677f0e5d928a3bbe7bb76aec";
const BUILDER: &str = "golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd";

fn baseline(root: &Path, profile: &Profile) -> Result<Value> {
    if let Some(family) = policy_family(profile) {
        return oracle::policy::pins(family);
    }
    if [
        "tools/parity/fixtures/config-api",
        "tools/parity/fixtures/config-write-links",
    ]
    .contains(&profile.directory)
    {
        let provenance = oracle::load(&root.join(profile.directory).join("provenance.json"))?;
        oracle::equal(&provenance["reference_revision"], &json!(REVISION))?;
        return Ok(if profile.directory.ends_with("config-api") {
            provenance["sources"].clone()
        } else {
            provenance["reference_source_sha256"].clone()
        });
    }
    if profile.directory == "tools/parity/fixtures" {
        let provenance = oracle::load(
            &root
                .join(profile.directory)
                .join("resources/provenance.json"),
        )?;
        oracle::equal(&provenance["reference_revision"], &json!(REVISION))?;
        return Ok(provenance["sources"].clone());
    }
    if profile.repeats != 2 {
        return Ok(Value::Null);
    }
    let provenance = oracle::load(&root.join(profile.directory).join("provenance.json"))?;
    oracle::equal(&provenance["revision"], &json!(REVISION))?;
    let common = ["go.mod", "go.sum"];
    let specific: &[&str] = match profile.components {
        ["apiserver", "kubelet"] => &[
            "pkg/kubernetes/apiserver/kubeconfig.go",
            "pkg/kubernetes/apiserver/service_account.go",
            "pkg/kubernetes/kubelet/kubeconfig.go",
        ],
        ["mapping"] => &[
            "internal/config/defaults.go",
            "internal/config/embedded.go",
            "internal/runtime/cri/endpoint.go",
            "types/config.go",
            "types/const.go",
            "types/types.go",
            "types/var.go",
        ],
        ["kubelet", "containerd"] => &[
            "pkg/kubernetes/kubelet/config.go",
            "pkg/kubernetes/kubelet/args.go",
            "pkg/kubernetes/kubelet/service.go",
            "pkg/runtime/containerd/config.go",
            "pkg/runtime/containerd/service.go",
            "internal/runtime/network/ip.go",
            "internal/runtime/filesystem/file.go",
            "types/const.go",
        ],
        ["webhook"] => &[
            "pkg/kubernetes/webhook/config.go",
            "pkg/kubernetes/webhook/executor.go",
            "pkg/kubernetes/webhook/loadbalancer.go",
            "pkg/kubernetes/webhook/loadbalancer_test.go",
            "pkg/kubernetes/webhook/patch.go",
            "pkg/kubernetes/webhook/service.go",
            "pkg/kubernetes/webhook/webhooks.go",
        ],
        _ => return Err("unknown baseline source inventory".into()),
    };
    let sources = provenance["source_sha256"]
        .as_object()
        .ok_or("baseline source map missing")?;
    let names = common
        .into_iter()
        .chain(specific.iter().copied())
        .collect::<std::collections::BTreeSet<_>>();
    if sources
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != names
    {
        return Err("baseline source inventory mismatch".into());
    }
    for hash in sources.values() {
        let hash = hash.as_str().ok_or("baseline digest type")?;
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid baseline source digest".into());
        }
    }
    Ok(provenance["source_sha256"].clone())
}

#[derive(Debug)]
pub struct Profile {
    pub directory: &'static str,
    pub dockerfile: &'static str,
    pub harnesses: &'static [&'static str],
    pub components: &'static [&'static str],
    pub repeats: usize,
    pub multiple_records: bool,
}

fn policy_family(profile: &Profile) -> Option<&'static str> {
    match profile.directory {
        "tools/parity/fixtures/preflight-policy" => Some("preflight-policy"),
        "tools/parity/fixtures/constrained-policy" => Some("constrained-policy"),
        _ => None,
    }
}

pub fn profile(family: &str) -> Result<Profile> {
    let mut profile = Profile {
        directory: "",
        dockerfile: "Capture.Dockerfile",
        harnesses: &[],
        components: &[],
        repeats: 2,
        multiple_records: false,
    };
    match family {
        "preflight-policy" => {
            profile.directory = "tools/parity/fixtures/preflight-policy";
            profile.harnesses = &["go.mod", "preflight_capture_test.go"];
            profile.components = &["preflight"];
        },
        "constrained-policy" => {
            profile.directory = "tools/parity/fixtures/constrained-policy";
            profile.harnesses = &[
                "go.mod",
                "extract.go",
                "network_test.go",
                "system_test.go",
                "proxy_test.go",
                "embedded_test.go",
            ];
            profile.components = &["network", "system", "proxy", "embedded"];
        },
        "credentials" => {
            profile.directory = "tools/parity/fixtures/credentials";
            profile.harnesses = &["apiserver_capture_test.go", "kubelet_capture_test.go"];
            profile.components = &["apiserver", "kubelet"];
        },
        "runtime-mapping" => {
            profile.directory = "tools/parity/fixtures/runtime-mapping";
            profile.harnesses = &["mapping_capture_test.go"];
            profile.components = &["mapping"];
        },
        "webhooks" => {
            profile.directory = "tools/parity/fixtures/webhooks";
            profile.harnesses = &["webhook_capture_test.go"];
            profile.components = &["webhook"];
        },
        "node-config" => {
            profile.directory = "tools/parity/fixtures/node-config";
            profile.harnesses = &["kubelet_capture_test.go", "containerd_capture_test.go"];
            profile.components = &["kubelet", "containerd"];
        },
        "config-api" => {
            profile.directory = "tools/parity/fixtures/config-api";
            profile.harnesses = &["file_capture_test.go", "api_capture_test.go"];
            profile.components = &["config", "configapi"];
            profile.multiple_records = true;
        },
        "config-write-links" => {
            profile.directory = "tools/parity/fixtures/config-write-links";
            profile.harnesses = &["file_capture_test.go"];
            profile.components = &["config"];
            profile.multiple_records = true;
        },
        "resources-pki" => {
            profile.directory = "tools/parity/fixtures";
            profile.dockerfile = "resources/Capture.Dockerfile";
            profile.harnesses = &[
                "resources/coredns_capture_test.go",
                "resources/localpath_capture_test.go",
                "resources/portainer_capture_test.go",
                "resources/d2k_capture_test.go",
                "pki/pki_capture_test.go",
            ];
            profile.components = &["coredns", "localpath", "portainer", "d2k", "pki"];
            profile.multiple_records = true;
        },
        "config-linebreak" | "config-print-preservation" => {
            profile.directory = if family == "config-linebreak" {
                "crates/diorama-config/tests/fixtures/linebreak"
            } else {
                "crates/diorama-config/tests/fixtures/print-preservation"
            };
            profile.harnesses = &["file_capture_test.go", "api_capture_test.go"];
            profile.components = &["config"];
            profile.repeats = 1;
            profile.multiple_records = true;
        },
        "config-scalar-base" | "config-scalar-extra" => {
            profile.directory = if family == "config-scalar-base" {
                "crates/diorama-config/tests/fixtures/scalar-signs/base"
            } else {
                "crates/diorama-config/tests/fixtures/scalar-signs/extra"
            };
            profile.dockerfile = "Dockerfile";
            profile.harnesses = &["scalar_capture_test.go"];
            profile.components = &["scalar"];
            profile.repeats = 1;
        },
        _ => return Err("unknown capture family".into()),
    }
    Ok(profile)
}

pub fn expected(family: &str, component: &str) -> Result<Value> {
    match family {
        "preflight-policy" | "constrained-policy" => oracle::policy::expected(family, component),
        "credentials" => oracle::credentials::expected(component),
        "runtime-mapping" if component == "mapping" => Ok(oracle::mapping::expected()),
        "webhooks" if component == "webhook" => oracle::webhook::expected(),
        "node-config" => oracle::node_config::expected(component),
        "config-api" => oracle::config_api::expected(component),
        "config-write-links" if component == "config" => oracle::config_links::expected(),
        "resources-pki" if component == "pki" => Ok(oracle::pki::expected()),
        "resources-pki" => oracle::resources::expected(component),
        _ => Err("family/component has no independent complete oracle".into()),
    }
}

/// Bind the complete maintenance source and the exact harness inventory.
pub fn sources(root: &Path, profile: &Profile) -> Result<Value> {
    fn visit(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                return Err("symlink in maintenance sources".into());
            }
            if kind.is_dir() {
                visit(&entry.path(), paths)?;
            } else if entry.path().extension().is_some_and(|ext| ext == "rs") {
                paths.push(entry.path());
            }
        }
        Ok(())
    }
    let mut paths = Vec::new();
    visit(&root.join("tools/dev/src"), &mut paths)?;
    visit(&root.join("tools/dev/tests"), &mut paths)?;
    paths.extend([
        root.join("Cargo.toml"),
        root.join("Cargo.lock"),
        root.join("rust-toolchain.toml"),
        root.join("tools/dev/Cargo.toml"),
    ]);
    let fixture = root.join(profile.directory);
    if let Some(family) = policy_family(profile) {
        paths.push(fixture.join(if family == "preflight-policy" {
            "expected.tsv"
        } else {
            "expected.json"
        }));
        if family == "constrained-policy" {
            paths.push(fixture.join("source-pins.json"));
        }
    }
    if profile.directory == "tools/parity/fixtures" {
        paths.push(fixture.join("resources/provenance.json"));
        paths.push(fixture.join("resources/expected.json"));
    } else if profile.repeats == 2 {
        paths.push(fixture.join("provenance.json"));
    }
    if profile.directory == "tools/parity/fixtures/node-config" {
        for component in profile.components {
            paths.push(fixture.join("expected").join(format!("{component}.json")));
        }
    }
    if [
        "tools/parity/fixtures/config-api",
        "tools/parity/fixtures/config-write-links",
    ]
    .contains(&profile.directory)
    {
        paths.push(root.join("tools/parity/fixtures/config-api/config.json"));
        paths.push(root.join("tools/parity/fixtures/config-api/configapi.json"));
        paths.push(root.join("tools/parity/fixtures/config-api/provenance.json"));
        paths.push(root.join("tools/parity/fixtures/config-write-links/replacement.yaml"));
    }
    paths.push(fixture.join(profile.dockerfile));
    paths.extend(profile.harnesses.iter().map(|name| fixture.join(name)));
    let mut result = serde_json::Map::new();
    for path in paths {
        let name = path
            .strip_prefix(root)?
            .to_str()
            .ok_or("non UTF-8 source path")?
            .to_owned();
        result.insert(name, capture::digest(&path)?.into());
    }
    Ok(result.into())
}

fn records(raw: &[u8], multiple: bool) -> Result<Value> {
    if raw.len() as u64 > oracle::LIMIT {
        return Err("capture exceeds byte limit".into());
    }
    let records = std::str::from_utf8(raw)?
        .lines()
        .filter_map(|line| line.strip_prefix("DIORAMA_CAPTURE "))
        .map(|line| crate::json::parse(line.as_bytes()))
        .collect::<Result<Vec<_>>>()?;
    if records.is_empty() || (!multiple && records.len() != 1) {
        return Err("incorrect capture record count".into());
    }
    if multiple {
        Ok(Value::Array(records))
    } else {
        records
            .into_iter()
            .next()
            .ok_or_else(|| "capture missing".into())
    }
}

fn verify_builder(fixture: &Path, profile: &Profile) -> Result<()> {
    // Fixed builder and source pins must be present in every selected Dockerfile.
    let dockerfile = String::from_utf8(crate::read_bounded(
        &fixture.join(profile.dockerfile),
        64 * 1024,
    )?)?;
    if ![REVISION, SOURCE, BUILDER]
        .iter()
        .all(|pin| dockerfile.contains(pin))
    {
        return Err("capture Dockerfile no longer uses the selected immutable baseline".into());
    }
    Ok(())
}

pub fn run(root: &Path, family: &str, output: &Path) -> Result<i32> {
    let profile = profile(family)?;
    let source_inventory = sources(root, &profile)?;
    let fixture = root.join(profile.directory);
    verify_builder(&fixture, &profile)?;
    capture::create_output(output)?;
    let mut owned = OwnedDocker {
        tag: capture::owned_tag(&format!("diorama-{family}-"))?,
        image_id: None,
        containers: Vec::new(),
    };
    let mut report = json!({"schema_version":2,"family":family,"revision":REVISION,
        "source_archive_sha256":SOURCE,"builder":BUILDER,"source_sha256":source_inventory,
        "baseline_source_sha256":baseline(root,&profile)?,"image":owned.tag,
        "runner_sha256":capture::digest(&std::env::current_exe()?)?,
        "containers":[],"outputs":{},"errors":[],"cleanup_errors":[]});
    let mut runner = Runner::with_signals(output)?;
    let result = (|| -> Result<()> {
        let context = tempfile::Builder::new()
            .prefix("diorama-fixture-build-")
            .tempdir()?;
        for name in profile
            .harnesses
            .iter()
            .copied()
            .chain(std::iter::once(profile.dockerfile))
        {
            let destination = context.path().join(name);
            fs::create_dir_all(destination.parent().ok_or("capture input parent")?)?;
            fs::copy(fixture.join(name), destination)?;
        }
        let mut argv = capture::arguments(&[
            "docker",
            "build",
            "--platform",
            "linux/arm64",
            "--tag",
            &owned.tag,
            "--file",
        ]);
        argv.push(context.path().join(profile.dockerfile).into_os_string());
        argv.push(context.path().as_os_str().to_owned());
        runner.keep_context(context);
        runner.bounded(
            &argv,
            "build",
            if policy_family(&profile).is_some() {
                900
            } else {
                1800
            },
            8 * 1024 * 1024,
        )?;
        report["image_inspect"] = capture::inspect_image(&mut runner, &mut owned)?;
        for component in profile.components {
            let mut previous = None;
            for repeat in 0..profile.repeats {
                let name = format!("{}-{component}-{repeat}", owned.tag);
                owned.containers.push(name.clone());
                let label = format!("{component}-{repeat}");
                let argv = runtime_args(family, &owned.tag, &name, component);
                let raw = runner.bounded(
                    &argv,
                    &label,
                    match family {
                        "constrained-policy" => 45,
                        "preflight-policy" => 75,
                        _ => 110,
                    },
                    oracle::LIMIT,
                )?;
                if policy_family(&profile).is_some() {
                    oracle::policy::verify_completion(family, &raw)?;
                }
                let value = records(&raw, profile.multiple_records)?;
                if profile.repeats == 2 {
                    oracle::equal(&value, &expected(family, component)?)?;
                }
                if let Some(prior) = &previous {
                    oracle::equal(&value, prior)?;
                }
                previous = Some(value);
            }
            let filename = format!("{component}.json");
            capture::write_json(&output.join(&filename), &previous.ok_or("no capture runs")?)?;
            report["outputs"][&filename] = capture::digest(&output.join(&filename))?.into();
        }
        copy_policy_sources(&profile, &mut runner, &owned, output, &mut report)?;
        report["identical_repeats"] = json!(profile.repeats == 2);
        report["repeat_count"] = json!(profile.repeats);
        oracle::equal(&sources(root, &profile)?, &source_inventory)?;
        Ok(())
    })();
    if let Err(error) = result {
        capture::push_error(&mut report, "errors", error.to_string());
    }
    report["containers"] = json!(owned.containers);
    report["image_id"] = json!(owned.image_id);
    runner.finish(&mut report, output, &owned)?;
    publish_provenance(output)?;
    Ok(i32::from(!capture::successful(&report)))
}

fn copy_policy_sources(
    profile: &Profile,
    runner: &mut Runner,
    owned: &OwnedDocker,
    output: &Path,
    report: &mut Value,
) -> Result<()> {
    if let Some(family) = policy_family(profile) {
        let source = format!(
            "{}:/source.sha256",
            owned.containers.first().ok_or("capture container")?
        );
        runner.bounded(
            &[
                "docker".into(),
                "cp".into(),
                source.into(),
                output.join("source.sha256").into_os_string(),
            ],
            "source-copy",
            30,
            65536,
        )?;
        oracle::policy::verify_sources(
            family,
            &crate::read_bounded(&output.join("source.sha256"), oracle::LIMIT)?,
            profile.components,
        )?;
        report["outputs"]["source.sha256"] = capture::digest(&output.join("source.sha256"))?.into();
    }
    Ok(())
}

fn publish_provenance(output: &Path) -> Result<()> {
    let mut artifacts = serde_json::Map::new();
    for entry in fs::read_dir(output)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err("nonregular capture artifact".into());
        }
        artifacts.insert(
            entry
                .file_name()
                .to_str()
                .ok_or("non UTF-8 artifact")?
                .to_owned(),
            capture::digest(&entry.path())?.into(),
        );
    }
    capture::write_json(
        &output.join("provenance.json"),
        &json!({"schema_version":2,
        "revision":REVISION,"fixture_sha256":artifacts}),
    )?;
    Ok(())
}

fn runtime_args(family: &str, tag: &str, name: &str, component: &str) -> Vec<OsString> {
    if ["preflight-policy", "constrained-policy"].contains(&family) {
        let mut args = capture::arguments(&[
            "docker",
            "run",
            "--name",
            name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "SYS_CHROOT",
        ]);
        if family == "constrained-policy" {
            args.extend(capture::arguments(&["--cap-add", "SETUID"]));
        }
        args.extend(capture::arguments(&[
            "--security-opt",
            "no-new-privileges",
            "--memory",
            "256m",
            "--cpus",
            "2",
            "--pids-limit",
            "64",
            "--tmpfs",
            if family == "constrained-policy" {
                "/tmp:rw,nosuid,nodev,size=32m"
            } else {
                "/tmp:rw,nosuid,nodev,size=16m"
            },
            "--ulimit",
            "fsize=1048576:1048576",
            tag,
            &format!("/{component}.test"),
            "-test.run",
            if family == "constrained-policy" {
                "^TestCapture$"
            } else {
                "^TestDioramaCapture$"
            },
            "-test.v",
            "-test.timeout",
            if family == "constrained-policy" {
                "30s"
            } else {
                "60s"
            },
        ]));
        return args;
    }
    let mut args = capture::arguments(&[
        "docker",
        "run",
        "--name",
        name,
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
        "128",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=64m",
        "--ulimit",
        "fsize=1048576:1048576",
        tag,
        &format!("/out/{component}.test"),
        "-test.run",
        "^TestDioramaCapture$",
        "-test.v",
        "-test.timeout",
        "90s",
    ]);
    if family == "node-config" {
        args.splice(
            6..6,
            capture::arguments(&["--dns", "192.0.2.53", "--dns-search", "."]),
        );
    }
    args
}

fn verify_receipt_fields(receipt: &Value) -> Result<()> {
    let fields = [
        "schema_version",
        "family",
        "revision",
        "source_archive_sha256",
        "builder",
        "source_sha256",
        "baseline_source_sha256",
        "image",
        "runner_sha256",
        "containers",
        "outputs",
        "errors",
        "cleanup_errors",
        "image_inspect",
        "image_id",
        "identical_repeats",
        "repeat_count",
        "remaining_containers",
        "remaining_images",
        "process_cleanup_complete",
        "process_failures",
        "retained_build_contexts",
        "cancelled",
    ];
    if receipt
        .as_object()
        .ok_or("receipt object")?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != fields.into_iter().collect()
    {
        return Err("receipt field inventory differs".into());
    }
    Ok(())
}

/// Require current Rust inputs, complete outputs, successful owned commands and two real records.
pub fn verify_evidence(root: &Path, family: &str, output: &Path) -> Result<()> {
    let profile = profile(family)?;
    let receipt = oracle::load(&output.join("receipt.json"))?;
    verify_receipt_fields(&receipt)?;
    for (key, value) in [
        ("schema_version", json!(2)),
        ("family", json!(family)),
        ("revision", json!(REVISION)),
        ("source_archive_sha256", json!(SOURCE)),
        ("builder", json!(BUILDER)),
        ("source_sha256", sources(root, &profile)?),
        ("baseline_source_sha256", baseline(root, &profile)?),
        ("repeat_count", json!(profile.repeats)),
        ("identical_repeats", json!(profile.repeats == 2)),
        ("process_failures", json!([])),
    ] {
        oracle::equal(
            receipt
                .get(key)
                .ok_or_else(|| format!("missing receipt {key}"))?,
            &value,
        )?;
    }
    if !capture::successful(&receipt) {
        return Err("capture cleanup or execution failed".into());
    }
    let binary = receipt["runner_sha256"]
        .as_str()
        .ok_or("runner digest missing")?;
    if binary.len() != 64 || !binary.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid runner digest".into());
    }
    let tag = receipt["image"].as_str().ok_or("image tag missing")?;
    if !tag.starts_with(&format!("diorama-{family}-"))
        || !tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err("invalid owned image tag".into());
    }
    let containers = profile
        .components
        .iter()
        .flat_map(|component| {
            (0..profile.repeats).map(move |index| format!("{tag}-{component}-{index}"))
        })
        .collect::<Vec<_>>();
    oracle::equal(&receipt["containers"], &json!(containers))?;
    verify_control_commands(output, &profile, tag, &containers, &receipt)?;
    oracle::equal(&receipt["image_id"], &receipt["image_inspect"][0]["Id"])?;
    if !receipt["image_id"].as_str().is_some_and(|id| {
        id.len() == 71
            && id.starts_with("sha256:")
            && id[7..].bytes().all(|b| b.is_ascii_hexdigit())
    }) {
        return Err("invalid captured image ID".into());
    }
    let mut outputs = serde_json::Map::new();
    let mut labels = vec!["build".to_owned(), "image-inspect".to_owned()];
    for component in profile.components {
        let name = format!("{component}.json");
        outputs.insert(name.clone(), capture::digest(&output.join(&name))?.into());
        let value = oracle::load(&output.join(name))?;
        if profile.repeats == 2 {
            oracle::equal(&value, &expected(family, component)?)?;
        }
        for index in 0..profile.repeats {
            let label = format!("{component}-{index}");
            let raw = crate::read_bounded(&output.join(format!("{label}.log")), oracle::LIMIT)?;
            if policy_family(&profile).is_some() {
                oracle::policy::verify_completion(family, &raw)?;
            }
            oracle::equal(&records(&raw, profile.multiple_records)?, &value)?;
            let facts = oracle::load(&output.join(format!("{label}.command.json")))?;
            let argv = runtime_args(family, tag, &format!("{tag}-{label}"), component)
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            oracle::equal(&facts["argv"], &json!(argv))?;
            labels.push(label);
        }
    }
    verify_policy_sources(&profile, output, &containers, &mut outputs, &mut labels)?;
    oracle::equal(&receipt["outputs"], &Value::Object(outputs))?;
    // One removal and one observation for each owned container, plus image removal/observation.
    for index in 1..=profile.components.len() * profile.repeats * 2 + 2 {
        labels.push(format!("cleanup-{index}"));
    }
    let mut inventory = std::collections::BTreeSet::from(["receipt.json".to_owned()]);
    inventory.extend(profile.components.iter().map(|name| format!("{name}.json")));
    if policy_family(&profile).is_some() {
        inventory.insert("source.sha256".into());
    }
    for label in labels {
        let log = format!("{label}.log");
        let command = format!("{label}.command.json");
        verify_command(output, &label)?;
        inventory.extend([log, command]);
    }
    verify_artifacts(output, inventory)
}

fn verify_policy_sources(
    profile: &Profile,
    output: &Path,
    containers: &[String],
    outputs: &mut serde_json::Map<String, Value>,
    labels: &mut Vec<String>,
) -> Result<()> {
    if let Some(family) = policy_family(profile) {
        let source_path = output.join("source.sha256");
        oracle::policy::verify_sources(
            family,
            &crate::read_bounded(&source_path, oracle::LIMIT)?,
            profile.components,
        )?;
        outputs.insert(
            "source.sha256".into(),
            capture::digest(&source_path)?.into(),
        );
        let command = oracle::load(&output.join("source-copy.command.json"))?;
        let destination = command["argv"]
            .as_array()
            .and_then(|argv| argv.last())
            .and_then(Value::as_str)
            .ok_or("source copy destination")?;
        let path = Path::new(destination);
        if !path.is_absolute()
            || path.file_name().is_none_or(|name| name != "source.sha256")
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err("invalid source copy destination".into());
        }
        verify_argv(
            output,
            "source-copy",
            &[
                "docker".into(),
                "cp".into(),
                format!("{}:/source.sha256", containers[0]).into(),
                destination.into(),
            ],
        )?;
        labels.push("source-copy".into());
    }
    Ok(())
}

fn verify_command(output: &Path, label: &str) -> Result<()> {
    let facts = oracle::load(&output.join(format!("{label}.command.json")))?;
    for (key, value) in [
        ("spawned", json!(true)),
        ("exit_code", json!(0)),
        ("timeout", json!(false)),
        ("cancelled", json!(false)),
        ("output_limit", json!(false)),
        ("merged_output", json!(true)),
        ("cleanup_complete", json!(true)),
        ("owned_process_group_absent", json!(true)),
        ("cleanup_errors", json!([])),
        ("output_eof", json!(true)),
        (
            "stdout_sha256",
            json!(capture::digest(&output.join(format!("{label}.log")))?),
        ),
        ("stderr_sha256", json!(crate::sha256(b""))),
    ] {
        oracle::equal(
            facts
                .get(key)
                .ok_or_else(|| format!("missing command {key}"))?,
            &value,
        )?;
    }
    Ok(())
}

fn cleanup_commands(tag: &str, containers: &[String]) -> Vec<Vec<OsString>> {
    let mut commands = containers
        .iter()
        .map(|name| capture::arguments(&["docker", "rm", "--force", name]))
        .collect::<Vec<_>>();
    commands.push(capture::arguments(&[
        "docker", "image", "rm", "--force", tag,
    ]));
    for name in containers {
        commands.push(capture::arguments(&[
            "docker",
            "ps",
            "-aq",
            "--filter",
            &format!("name=^/{}$", regex::escape(name)),
        ]));
    }
    commands.push(capture::arguments(&[
        "docker",
        "images",
        "--no-trunc",
        "-q",
        "--filter",
        &format!("reference={tag}"),
    ]));
    commands
}

fn verify_argv(output: &Path, label: &str, argv: &[OsString]) -> Result<()> {
    let facts = oracle::load(&output.join(format!("{label}.command.json")))?;
    oracle::equal(
        &facts["argv"],
        &json!(
            argv.iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        ),
    )
}

fn verify_control_commands(
    output: &Path,
    profile: &Profile,
    tag: &str,
    containers: &[String],
    receipt: &Value,
) -> Result<()> {
    let facts = oracle::load(&output.join("build.command.json"))?;
    let argv = facts["argv"].as_array().ok_or("build argv")?;
    let context = argv.last().and_then(Value::as_str).ok_or("build context")?;
    let path = Path::new(context);
    if !path.is_absolute()
        || !path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("diorama-fixture-build-"))
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("invalid owned build context".into());
    }
    let mut build = capture::arguments(&[
        "docker",
        "build",
        "--platform",
        "linux/arm64",
        "--tag",
        tag,
        "--file",
    ]);
    build.push(path.join(profile.dockerfile).into_os_string());
    build.push(path.into());
    verify_argv(output, "build", &build)?;
    verify_argv(
        output,
        "image-inspect",
        &capture::arguments(&["docker", "image", "inspect", tag]),
    )?;
    oracle::equal(
        &oracle::load(&output.join("image-inspect.log"))?,
        &receipt["image_inspect"],
    )?;
    for (index, argv) in cleanup_commands(tag, containers).iter().enumerate() {
        let label = format!("cleanup-{}", index + 1);
        verify_argv(output, &label, argv)?;
        if index > containers.len() {
            let raw = crate::read_bounded(&output.join(format!("{label}.log")), oracle::LIMIT)?;
            if !std::str::from_utf8(&raw)?.trim().is_empty() {
                return Err("owned Docker resources remain in raw inventory".into());
            }
        }
    }
    Ok(())
}

fn verify_artifacts(
    output: &Path,
    mut inventory: std::collections::BTreeSet<String>,
) -> Result<()> {
    let provenance = oracle::load(&output.join("provenance.json"))?;
    oracle::equal(&provenance["schema_version"], &json!(2))?;
    oracle::equal(&provenance["revision"], &json!(REVISION))?;
    let mut hashes = serde_json::Map::new();
    for name in &inventory {
        hashes.insert(name.clone(), capture::digest(&output.join(name))?.into());
    }
    oracle::equal(&provenance["fixture_sha256"], &hashes.into())?;
    inventory.insert("provenance.json".into());
    let actual = fs::read_dir(output)?
        .map(|entry| {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                return Err("nonregular capture artifact".into());
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| "non UTF-8 artifact".into())
        })
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    if actual != inventory {
        return Err("capture artifact inventory mismatch".into());
    }
    Ok(())
}

pub fn cli(args: &[OsString]) -> Result<i32> {
    if args.len() != 3 || args[1] != "--output" {
        return Err("capture FAMILY --output NEW-DIRECTORY".into());
    }
    let family = args[0].to_str().ok_or("non UTF-8 fixture family")?;
    let root = crate::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
    run(&root, family, Path::new(&args[2]))
}

#[cfg(test)]
mod tests;
