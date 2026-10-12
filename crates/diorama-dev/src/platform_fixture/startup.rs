use super::{
    BTreeMap, Options, Path, Result, Value, digest, equal, fixture, json, load, read, require,
    source_inventory,
};
fn baseline_provenance(root: &Path) -> Result<()> {
    let here = fixture(root, "cli-startup");
    let provenance = load(&here.join("provenance.json"))?;
    equal(
        &json!(
            provenance["source_sha256"]
                .as_object()
                .ok_or("baseline source map")?
                .keys()
                .collect::<Vec<_>>()
        ),
        &json!([
            "cmd/kubesolo/main.go",
            "go.mod",
            "go.sum",
            "internal/config/file.go",
            "internal/config/flags/flags.go",
            "internal/config/loader.go"
        ]),
        "baseline source inventory",
    )?;
    equal(
        &json!(
            provenance["kingpin_source_sha256"]
                .as_object()
                .ok_or("kingpin source map")?
                .keys()
                .collect::<Vec<_>>()
        ),
        &json!(["app.go", "envar.go", "flags.go", "global.go", "parser.go"]),
        "kingpin source inventory",
    )?;
    equal(
        &provenance["observations_sha256"],
        &json!(digest(&here.join("observations.json"))?),
        "reviewed observation digest",
    )?;
    Ok(())
}
pub(super) const BINARY: &str = "67348b2560d0f831de20ef722c53cc317e385ab7cfbf406633fbbb6a7b73f81e";
pub(super) const REVISION: &str = "2ef1c4787989f11f868f81bb84ae2afd4a49a81d";
const CASE_IDS: &[&str] = &[
    "version-long",
    "version-short",
    "version-invalid-bool-env",
    "version-invalid-int-env",
    "version-invalid-map-env",
    "version-directory-file",
    "version-before-full",
    "version-invalid-explicit-int",
    "version-unknown-flag",
    "unknown-before-version",
    "help-long-name",
    "help-invalid-env",
    "help-invalid-explicit-int",
    "help-unknown-flag",
    "short-h",
    "duplicate-bool",
    "duplicate-positive-negative",
    "duplicate-version-alias",
    "duplicate-string",
    "bool-equals-false",
    "bool-equals-true",
    "bool-following-false",
    "bool-empty-equals",
    "string-empty-argv",
    "string-empty-equals",
    "integer-empty-equals",
    "empty-positional",
    "delimiter-empty-tail",
    "delimiter-flag-is-positional",
    "missing-argument",
    "invalid-env-overridden-boolean",
    "invalid-env-overridden-integer",
    "directory-before-string-map-env",
    "primitive-env-before-directory",
    "empty-full-env",
    "empty-config-env",
    "empty-config-equals",
    "no-version-print",
    "no-help",
];
fn normalize(stderr: &str) -> Result<Value> {
    let mut result = vec![];
    for line in stderr.split_inclusive('\n') {
        match diorama_dev::json::parse(line.as_bytes()) {
            Ok(Value::Object(mut value)) => {
                value.remove("time");
                result.push(Value::Object(value));
            },
            Ok(_) => result.push(json!(line)),
            Err(error) => {
                // Ordinary prose is expected; structured JSON lines must remain strict.
                if line.trim_start().starts_with('{') {
                    return Err(error);
                }
                result.push(json!(line));
            },
        }
    }
    Ok(json!(result))
}
#[allow(
    clippy::too_many_lines,
    reason = "Source-specified startup case inventory and stream verification"
)]
fn observations(root: &Path, directory: &Path) -> Result<Value> {
    let here = fixture(root, "cli-startup");
    let suite = load(&here.join("suite.json"))?;
    let record = load(&directory.join("result.json"))?;
    let runner = load(&directory.join("runner-result.json"))?;
    let wanted = suite["cases"].as_array().ok_or("suite cases")?;
    let cases = record["cases"].as_array().ok_or("observed cases")?;
    equal(
        &json!(wanted.iter().map(|c| &c["id"]).collect::<Vec<_>>()),
        &json!(CASE_IDS),
        "source-specified case inventory",
    )?;
    equal(
        &json!(cases.iter().map(|c| &c["id"]).collect::<Vec<_>>()),
        &json!(CASE_IDS),
        "observed case inventory",
    )?;
    equal(&record["status"], &json!("passed"), "driver status")?;
    equal(&runner["exit_code"], &json!(0), "runner exit")?;
    equal(&runner["errors"], &json!([]), "runner errors")?;
    equal(
        &runner["cleanup_uncertain"],
        &json!(false),
        "settled runner",
    )?;
    equal(
        &runner["owned_context_removed"],
        &json!(true),
        "context cleanup",
    )?;
    equal(
        &runner["retained_commands"],
        &json!([]),
        "retained commands",
    )?;
    let suite_hash = json!(digest(&here.join("suite.json"))?);
    equal(&record["suite_sha256"], &suite_hash, "driver suite hash")?;
    equal(
        &runner["source_sha256"]["suite"],
        &suite_hash,
        "runner suite hash",
    )?;
    equal(
        &record["artifact"]["source"]["revision"],
        &json!(REVISION),
        "baseline revision",
    )?;
    equal(
        &record["artifact"]["sha256"],
        &json!(BINARY),
        "baseline binary",
    )?;
    cleanup_evidence(directory, &runner)?;
    let mut output = serde_json::Map::new();
    for (index, (wanted, actual)) in wanted.iter().zip(cases).enumerate() {
        for key in ["id", "argv"] {
            equal(&actual[key], &wanted[key], key)?;
        }
        for (key, value) in [
            ("status", json!("passed")),
            ("failures", json!([])),
            ("owned_process_group_absent", json!(true)),
            ("artifact_uid_inventory_confirmed", json!(true)),
            ("timeout", json!(false)),
            ("cancelled", json!(false)),
        ] {
            equal(&actual[key], &value, key)?;
        }
        require(
            actual.get("remaining_artifact_pids").is_none() && actual.get("errors").is_none(),
            "artifact cleanup errors",
        )?;
        equal(
            &actual["exit_code"],
            &wanted["expect"]["exit_code"],
            "case exit",
        )?;
        let mut streams = BTreeMap::new();
        for kind in ["stdout", "stderr"] {
            let name = format!("{index:03}.{kind}");
            equal(
                &actual[format!("{kind}_file")],
                &json!(name),
                "stream filename",
            )?;
            let raw = read(&directory.join(name), 256 * 1024)?;
            equal(
                &actual[format!("{kind}_sha256")],
                &json!(diorama_dev::sha256(&raw)),
                "stream identity",
            )?;
            streams.insert(kind, String::from_utf8(raw)?);
        }
        streams.insert(
            "combined",
            format!("{}{}", streams["stdout"], streams["stderr"]),
        );
        for (kind, stream) in &streams {
            if let Some(exact) = wanted["expect"].get(format!("{kind}_equals")) {
                equal(&json!(stream), exact, "exact expectation")?;
            }
            if let Some(markers) = wanted["expect"].get(format!("{kind}_contains")) {
                for marker in markers.as_array().ok_or("marker array")? {
                    require(
                        stream.contains(marker.as_str().ok_or("string marker")?),
                        "missing independently specified marker",
                    )?;
                }
            }
        }
        output.insert(CASE_IDS[index].into(),json!({"exit_code":actual["exit_code"],"stdout":streams["stdout"],"stderr":normalize(&streams["stderr"])?}));
    }
    require(
        !output["version-before-full"]["stderr"]
            .to_string()
            .contains("deprecated"),
        "full warning preceded version",
    )?;
    Ok(Value::Object(output))
}
pub(super) fn verify(root: &Path, directory: &Path) -> Result<Value> {
    baseline_provenance(root)?;
    let capture = load(&directory.join("capture.json"))?;
    equal(
        &capture["schema_version"],
        &json!(2),
        "current Rust capture schema",
    )?;
    equal(&capture["status"], &json!("passed"), "capture status")?;
    equal(
        &capture["cancelled"],
        &json!(false),
        "uncancelled publication",
    )?;
    equal(&capture["errors"], &json!([]), "capture errors")?;
    let mut inventory = super::guest::evidence_inventory(directory)?;
    inventory
        .as_object_mut()
        .ok_or("inventory object")?
        .remove("capture.json");
    equal(
        &capture["evidence_sha256"],
        &inventory,
        "exact raw startup evidence inventory",
    )?;
    let runner = load(&directory.join("runner-result.json"))?;
    equal(
        &capture["runner_binary_sha256"],
        &runner["source_sha256"]["runner"],
        "actual runner binary",
    )?;
    let record = load(&directory.join("result.json"))?;
    equal(
        &capture["driver_binary_sha256"],
        &record["driver_sha256"],
        "executed Linux driver binary",
    )?;
    equal(
        &capture["result_sha256"],
        &json!(digest(&directory.join("result.json"))?),
        "raw driver result",
    )?;
    equal(
        &capture["runner_result_sha256"],
        &json!(digest(&directory.join("runner-result.json"))?),
        "raw runner result",
    )?;
    let output = observations(root, directory)?;
    equal(
        &output,
        &load(&fixture(root, "cli-startup").join("observations.json"))?,
        "reviewed independent observations",
    )?;
    Ok(output)
}
pub(super) fn capture(root: &Path, options: &Options) -> Result<u8> {
    let cancellation = crate::parity::process::Cancellation::default();
    let _signals = crate::parity::process::SignalGuard::install(cancellation.clone())?;
    baseline_provenance(root)?;
    require(
        !options.values.contains_key("--runner"),
        "runner is this source-bound Rust executable",
    )?;
    let descriptor = options.path("--artifact")?;
    let artifact = load(descriptor)?;
    equal(
        &artifact["sha256"],
        &json!(BINARY),
        "pinned startup artifact",
    )?;
    equal(
        &artifact["source"]["revision"],
        &json!(REVISION),
        "pinned baseline revision",
    )?;
    let binary = descriptor
        .parent()
        .ok_or("artifact parent")?
        .join(artifact["binary"].as_str().ok_or("artifact binary")?);
    equal(
        &json!(digest(&binary)?),
        &json!(BINARY),
        "actual baseline binary",
    )?;
    let driver = options.path("--driver")?;
    let driver_hash = digest(driver)?;
    let sources = source_inventory(root, "startup")?;
    let output = options.path("--output")?;
    let argv = vec![
        "run".into(),
        "--repo".into(),
        root.into(),
        "--artifact".into(),
        descriptor.into(),
        "--suite".into(),
        fixture(root, "cli-startup").join("suite.json").into(),
        "--output".into(),
        output.into(),
        "--driver".into(),
        driver.into(),
    ];
    let runner_options = crate::parity::Options::parse(&argv[1..])?;
    require(
        !cancellation.requested(),
        "cancelled before startup capture",
    )?;
    let execution = crate::parity::run_with_cancellation(&runner_options, cancellation.clone());
    let status = execution.as_ref().copied().unwrap_or(1);
    let mut capture = json!({"schema_version":2,"source_sha256":sources,"runner_binary_sha256":digest(&std::env::current_exe()?)?,"driver_binary_sha256":driver_hash,"status":"failed","errors":[]});
    let verified = (|| -> Result<()> {
        require(status == 0, "parity runner failed")?;
        equal(
            &source_inventory(root, "startup")?,
            &sources,
            "source stable through capture",
        )?;
        equal(
            &observations(root, output)?,
            &load(&fixture(root, "cli-startup").join("observations.json"))?,
            "independent startup observations",
        )?;
        let record = load(&output.join("result.json"))?;
        equal(
            &record["driver_sha256"],
            &json!(driver_hash),
            "executed driver",
        )?;
        capture["result_sha256"] = json!(digest(&output.join("result.json"))?);
        capture["runner_result_sha256"] = json!(digest(&output.join("runner-result.json"))?);
        capture["status"] = json!("passed");
        capture["evidence_sha256"] = super::guest::evidence_inventory(output)?;
        Ok(())
    })();
    if let Err(error) = &verified {
        capture["status"] = json!("failed");
        capture["errors"] = json!([error.to_string()]);
    }
    let publication = super::guest::publish_cancellable(
        &output.join("capture.json"),
        &mut capture,
        &cancellation,
        true,
    );
    execution?;
    publication?;
    verified?;
    Ok(u8::from(capture["status"] != "passed"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalization_preserves_all_fields_except_wall_clock() -> Result<()> {
        equal(
            &normalize("{\"time\":\"one\",\"level\":\"warn\",\"message\":\"a\"}\nplain\n")?,
            &json!([{"level":"warn","message":"a"},"plain\n"]),
            "normalization",
        )?;
        assert!(normalize("{\"level\":1,\"level\":2}\n").is_err());
        Ok(())
    }
    #[test]
    #[ignore = "receipt checks disabled"]
    fn published_startup_requires_current_rust_captures() -> Result<()> {
        let root = diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
        for run in ["first", "repeat"] {
            verify(
                &root,
                &fixture(&root, "cli-startup")
                    .join("evidence-rust")
                    .join(run),
            )?;
        }
        Ok(())
    }
}
fn inventory_argv(kind: &str, target: &str) -> Vec<String> {
    if kind == "volume" {
        [
            "docker",
            "volume",
            "ls",
            "--filter",
            &format!("name={target}"),
            "--format",
            "{{.Name}}",
        ]
        .map(str::to_owned)
        .to_vec()
    } else {
        [
            "docker",
            kind,
            "ls",
            "--all",
            "--filter",
            &if kind == "container" {
                format!("name=^/{target}$")
            } else {
                format!("reference={target}")
            },
            "--quiet",
        ]
        .map(str::to_owned)
        .to_vec()
    }
}
fn cleanup_evidence(directory: &Path, runner: &Value) -> Result<()> {
    let container = runner["owned_container"]
        .as_str()
        .ok_or("owned container")?;
    require(
        container
            .strip_prefix("diorama-parity-")
            .is_some_and(|s| s.len() == 24 && s.bytes().all(|b| b.is_ascii_hexdigit())),
        "owned startup container identity",
    )?;
    equal(
        &runner["owned_image"],
        &json!(format!("{container}:test")),
        "owned startup image",
    )?;
    equal(
        &runner["owned_volume"],
        &json!(format!("{container}-evidence")),
        "owned startup volume",
    )?;
    for kind in ["container", "image", "volume"] {
        let target = runner[format!("owned_{kind}")]
            .as_str()
            .ok_or("owned resource")?;
        let argv = inventory_argv(kind, target);
        let (before, _) = super::command_evidence::verify_command(
            directory,
            &format!("{kind}-inventory"),
            &argv,
            &[0],
        )?;
        let before = std::str::from_utf8(&before)?;
        let existed = if kind == "volume" {
            before.lines().any(|line| line == target)
        } else {
            !before.trim().is_empty()
        };
        if existed {
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
            super::command_evidence::verify_command(
                directory,
                &format!("{kind}-remove"),
                &removal,
                &[0],
            )?;
        } else {
            for extension in ["stdout", "stderr", "command.json"] {
                require(
                    !directory
                        .join(format!("{kind}-remove.{extension}"))
                        .exists(),
                    "no removal without observed ownership",
                )?;
            }
        }
        let (after, _) = super::command_evidence::verify_command(
            directory,
            &format!("{kind}-verify-removal"),
            &argv,
            &[0],
        )?;
        require(
            std::str::from_utf8(&after)?.trim().is_empty(),
            "raw owned resource absence",
        )?;
    }
    Ok(())
}
#[cfg(test)]
mod cleanup_tests {
    use super::*;
    fn command(directory: &Path, label: &str, argv: &[String], raw: &[u8]) -> Result<()> {
        std::fs::write(directory.join(format!("{label}.stdout")), raw)?;
        std::fs::write(directory.join(format!("{label}.stderr")), b"")?;
        crate::parity::write_json(
            &directory.join(format!("{label}.command.json")),
            &json!({"spawned":true,"owned_pid":1234,"owner_directory":"/tmp/owned-test","owned_process_group_absent":true,"cleanup_complete":true,"output_eof":true,"cleanup_errors":[],"timeout":false,"cancelled":false,"merged_output":false,"output_limit":false,"argv":argv,"exit_code":0,"stdout_sha256":diorama_dev::sha256(raw),"stderr_sha256":diorama_dev::sha256(b"")}),
            false,
        )
    }
    #[test]
    fn rehashed_empty_inventory_cannot_hide_wrong_commands_or_unsettled_cleanup() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let container = format!("diorama-parity-{}", "a".repeat(24));
        let runner = json!({"owned_container":container,"owned_image":format!("{container}:test"),"owned_volume":format!("{container}-evidence")});
        for kind in ["container", "image", "volume"] {
            let target = runner[format!("owned_{kind}")].as_str().ok_or("target")?;
            for suffix in ["inventory", "verify-removal"] {
                command(
                    directory.path(),
                    &format!("{kind}-{suffix}"),
                    &inventory_argv(kind, target),
                    b"",
                )?;
            }
        }
        cleanup_evidence(directory.path(), &runner)?;
        let path = directory
            .path()
            .join("container-verify-removal.command.json");
        let valid = load(&path)?;
        for (key, value) in [
            ("argv", json!(["true"])),
            ("exit_code", json!(1)),
            ("cleanup_complete", json!(false)),
            ("output_eof", json!(false)),
            ("owned_process_group_absent", json!(false)),
            ("timeout", json!(true)),
            ("cancelled", json!(true)),
            ("output_limit", json!(true)),
        ] {
            let mut mutated = valid.clone();
            mutated[key] = value;
            crate::parity::write_json(&path, &mutated, false)?;
            assert!(
                cleanup_evidence(directory.path(), &runner).is_err(),
                "{key}"
            );
        }
        let argv = inventory_argv("container", &container);
        command(
            directory.path(),
            "container-verify-removal",
            &argv,
            b"still-owned\n",
        )?;
        assert!(cleanup_evidence(directory.path(), &runner).is_err());
        Ok(())
    }
}
