//! Bind current captures to settled commands and their raw output.
use super::{
    capture::{self, OwnedDocker},
    load, require,
};
use crate::{Result, json, read_bounded, sha256};
use serde_json::{Value, json as value};
use std::{collections::BTreeSet, ffi::OsString, fs, path::Path};
type Variants = Vec<(&'static str, Option<&'static str>)>;

fn command(
    output: &Path,
    label: &str,
    argv: &[OsString],
    inventory: &mut BTreeSet<String>,
) -> Result<Vec<u8>> {
    let receipt = format!("{label}.command.json");
    let log = format!("{label}.log");
    let facts = load(&output.join(&receipt))?;
    require(
        facts["owned_pid"]
            .as_u64()
            .is_some_and(|pid| pid > 0 && i32::try_from(pid).is_ok()),
        "invalid owned command PID",
    )?;
    require(
        facts["owner_directory"].as_str().is_some_and(|path| {
            Path::new(path).is_absolute()
                && !Path::new(path)
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
        }),
        "invalid command owner directory",
    )?;
    let raw = read_bounded(&output.join(&log), 8 * 1024 * 1024)?;
    for (key, expected) in [
        ("spawned", value!(true)),
        ("exit_code", value!(0)),
        ("timeout", value!(false)),
        ("cancelled", value!(false)),
        ("output_limit", value!(false)),
        ("merged_output", value!(true)),
        ("cleanup_complete", value!(true)),
        ("owned_process_group_absent", value!(true)),
        ("cleanup_errors", value!([])),
        ("output_eof", value!(true)),
        ("stdout_sha256", value!(sha256(&raw))),
        ("stderr_sha256", value!(sha256(b""))),
        (
            "argv",
            value!(
                argv.iter()
                    .map(|arg| arg.to_string_lossy())
                    .collect::<Vec<_>>()
            ),
        ),
    ] {
        require(
            facts.get(key) == Some(&expected),
            &format!("{label}: invalid {key}"),
        )?;
    }
    inventory.extend([receipt, log]);
    Ok(raw)
}

fn owned(report: &Value, resolved: bool) -> Result<(OwnedDocker, Variants)> {
    let tag = report["image"].as_str().ok_or("missing owned image")?;
    let prefix = if resolved {
        "diorama-resolved-"
    } else {
        "diorama-official-defaults-"
    };
    require(
        tag.starts_with(prefix)
            && tag.len() > prefix.len()
            && tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid owned tag",
    )?;
    let variants = if resolved {
        vec![("run", None)]
    } else {
        vec![
            ("run", Some("/out/extract")),
            ("apiserver", Some("/out/extract-apiserver")),
        ]
    };
    let names = variants
        .iter()
        .flat_map(|(variant, _)| {
            (0..2).map(move |index| {
                if resolved {
                    format!("{tag}-{index}")
                } else {
                    format!("{tag}-{variant}-{index}")
                }
            })
        })
        .collect::<Vec<_>>();
    require(
        report["containers"] == value!(names),
        "owned container inventory mismatch",
    )?;
    let owned = OwnedDocker {
        tag: tag.into(),
        image_id: None,
        containers: names,
    };
    Ok((owned, variants))
}
fn build(
    output: &Path,
    report: &Value,
    owned: &OwnedDocker,
    inventory: &mut BTreeSet<String>,
) -> Result<()> {
    let tag = &owned.tag;

    let build = load(&output.join("build.command.json"))?;
    let context = build["argv"]
        .as_array()
        .and_then(|a| a.last())
        .and_then(Value::as_str)
        .ok_or("missing build context")?;
    let path = Path::new(context);
    require(
        path.is_absolute()
            && path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("diorama-official-build-"))
            && !path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
        "invalid build context",
    )?;
    let source = format!(
        "SOURCE_SHA256={}",
        report["inputs"]["source"]["sha256"]
            .as_str()
            .ok_or("missing source hash")?
    );
    command(
        output,
        "build",
        &capture::arguments(&[
            "docker",
            "build",
            "--network",
            "none",
            "--platform",
            "linux/arm64",
            "--tag",
            tag,
            "--build-arg",
            &source,
            context,
        ]),
        inventory,
    )?;
    Ok(())
}
fn image(
    output: &Path,
    report: &Value,
    owned: &OwnedDocker,
    inventory: &mut BTreeSet<String>,
) -> Result<()> {
    let tag = &owned.tag;
    let raw = command(
        output,
        "image-inspect",
        &capture::arguments(&["docker", "image", "inspect", tag]),
        inventory,
    )?;
    let inspect = json::parse(&raw)?;
    require(
        inspect == report["image_inspect"],
        "raw image inspection mismatch",
    )?;
    let id = inspect[0]["Id"].as_str().ok_or("missing image ID")?;
    require(
        inspect.as_array().is_some_and(|a| a.len() == 1)
            && inspect[0]["Os"] == "linux"
            && inspect[0]["Architecture"] == "arm64"
            && id.starts_with("sha256:")
            && id.len() == 71
            && id[7..].bytes().all(|b| b.is_ascii_hexdigit())
            && report["image_id"] == id,
        "image identity mismatch",
    )?;
    Ok(())
}
fn runs(
    output: &Path,
    owned: &OwnedDocker,
    variants: &[(&str, Option<&str>)],
    resolved: bool,
    inventory: &mut BTreeSet<String>,
) -> Result<()> {
    for (variant_index, (prefix, entrypoint)) in variants.iter().enumerate() {
        for index in 0..2 {
            let label = format!("{prefix}{index}");
            let raw = command(
                output,
                &label,
                &capture::run_args(
                    owned,
                    &owned.containers[variant_index * 2 + index],
                    index,
                    *entrypoint,
                ),
                inventory,
            )?;
            let file = format!("{label}.json");
            let data = read_bounded(&output.join(&file), 2 * 1024 * 1024)?;
            if resolved {
                let text = std::str::from_utf8(&raw)?;
                let records = text
                    .lines()
                    .filter_map(|line| line.strip_prefix("DIORAMA_RESOLVED="))
                    .collect::<Vec<_>>();
                require(records.len() == 1, "resolved raw record inventory")?;
                require(
                    json::parse(records[0].as_bytes())? == json::parse(&data)?,
                    "resolved raw output mismatch",
                )?;
            } else {
                require(raw == data, "raw constructor output mismatch")?;
            }
            inventory.insert(file);
        }
    }
    Ok(())
}
fn modules(
    output: &Path,
    report: &Value,
    owned: &OwnedDocker,
    resolved: bool,
    inventory: &mut BTreeSet<String>,
) -> Result<()> {
    let copy = load(&output.join("copy-modules.command.json"))?;
    let destination = copy["argv"]
        .as_array()
        .and_then(|a| a.last())
        .and_then(Value::as_str)
        .ok_or("missing modules destination")?;
    require(
        Path::new(destination).is_absolute()
            && Path::new(destination)
                .file_name()
                .is_some_and(|n| n == "modules.sha256")
            && !Path::new(destination)
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
        "invalid modules destination",
    )?;
    command(
        output,
        "copy-modules",
        &capture::arguments(&[
            "docker",
            "cp",
            &format!("{}:/out/modules.sha256", owned.containers[0]),
            destination,
        ]),
        inventory,
    )?;
    let raw = read_bounded(&output.join("modules.sha256"), 1024 * 1024)?;
    verify_modules(&raw, report, resolved)?;
    Ok(())
}
pub(crate) fn verify_modules(raw: &[u8], report: &Value, resolved: bool) -> Result<()> {
    let fixture = if resolved {
        crate::resolved_capture::directory()
    } else {
        super::directory()
    };
    let historical = if fixture.join("evidence/receipt.json").exists() {
        load(&fixture.join("evidence/receipt.json"))?
    } else {
        load(&fixture.join("inputs.json"))?
    };
    let source_pin = if historical.get("inputs").is_some() {
        &historical["inputs"]["source"]
    } else {
        &historical["source"]
    };
    require(
        source_pin == &report["inputs"]["source"],
        "module inventory source pin mismatch",
    )?;
    let expected = read_bounded(&fixture.join("evidence/modules.sha256"), 1024 * 1024)?;
    require(raw == expected, "pinned source module inventory mismatch")?;
    require(
        report["modules_sha256"] == value!(sha256(raw)),
        "module inventory digest mismatch",
    )
}
fn cleanup(output: &Path, owned: &OwnedDocker, inventory: &mut BTreeSet<String>) -> Result<()> {
    let tag = &owned.tag;
    let mut cleanup = owned
        .containers
        .iter()
        .map(|name| capture::arguments(&["docker", "rm", "--force", name]))
        .collect::<Vec<_>>();
    cleanup.push(capture::arguments(&[
        "docker", "image", "rm", "--force", tag,
    ]));
    for name in &owned.containers {
        cleanup.push(capture::arguments(&[
            "docker",
            "ps",
            "-aq",
            "--filter",
            &format!("name=^/{}$", regex::escape(name)),
        ]));
    }
    cleanup.push(capture::arguments(&[
        "docker",
        "images",
        "--no-trunc",
        "-q",
        "--filter",
        &format!("reference={tag}"),
    ]));
    for (index, argv) in cleanup.iter().enumerate() {
        let raw = command(output, &format!("cleanup-{}", index + 1), argv, inventory)?;
        if index > owned.containers.len() {
            require(
                std::str::from_utf8(&raw)?.trim().is_empty(),
                "owned Docker resource remains",
            )?;
        }
    }
    Ok(())
}
pub(super) fn verify(output: &Path, report: &Value, resolved: bool) -> Result<()> {
    let (owned, variants) = owned(report, resolved)?;
    let mut inventory = BTreeSet::from(["receipt.json".into(), "modules.sha256".into()]);
    build(output, report, &owned, &mut inventory)?;
    image(output, report, &owned, &mut inventory)?;
    runs(output, &owned, &variants, resolved, &mut inventory)?;
    modules(output, report, &owned, resolved, &mut inventory)?;
    cleanup(output, &owned, &mut inventory)?;
    let actual = fs::read_dir(output)?
        .map(|entry| {
            let entry = entry?;
            require(entry.file_type()?.is_file(), "nonregular evidence artifact")?;
            entry
                .file_name()
                .into_string()
                .map_err(|_| "invalid artifact name".into())
        })
        .collect::<Result<BTreeSet<_>>>()?;
    require(actual == inventory, "evidence artifact inventory mismatch")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn write_fixture_json(path: &Path, value: &Value) -> Result<()> {
        fs::write(path, serde_json::to_vec(value)?)?;
        Ok(())
    }
    fn receipt(output: &Path, label: &str, argv: &[OsString], raw: &[u8]) -> Result<()> {
        fs::write(output.join(format!("{label}.log")), raw)?;
        write_fixture_json(
            &output.join(format!("{label}.command.json")),
            &value!({
                "spawned":true,"exit_code":0,"timeout":false,"cancelled":false,
                "output_limit":false,"merged_output":true,"cleanup_complete":true,
                "owned_process_group_absent":true,"cleanup_errors":[],"output_eof":true,
                "stdout_sha256":sha256(raw),"stderr_sha256":sha256(b""),"argv":argv.iter().map(|arg|arg.to_string_lossy()).collect::<Vec<_>>(),
                "owned_pid":1234,"owner_directory":"/tmp/synthetic-command-owner"
            }),
        )
    }
    fn fixture(resolved: bool) -> Result<(tempfile::TempDir, Value)> {
        let output = tempfile::tempdir()?;
        let historical = if resolved {
            crate::resolved_capture::directory()
        } else {
            super::super::directory()
        };
        let input = load(&historical.join("inputs.json"))?;
        let tag = if resolved {
            "diorama-resolved-synthetic"
        } else {
            "diorama-official-defaults-synthetic"
        };
        let variants = if resolved {
            vec![("run", None)]
        } else {
            vec![
                ("run", Some("/out/extract")),
                ("apiserver", Some("/out/extract-apiserver")),
            ]
        };
        let names = variants
            .iter()
            .flat_map(|(label, _)| {
                (0..2).map(move |index| {
                    if resolved {
                        format!("{tag}-{index}")
                    } else {
                        format!("{tag}-{label}-{index}")
                    }
                })
            })
            .collect::<Vec<_>>();
        let id = format!("sha256:{}", "a".repeat(64));
        let inspect = value!([{"Id":id,"Os":"linux","Architecture":"arm64"}]);
        let module = read_bounded(&historical.join("evidence/modules.sha256"), 1024 * 1024)?;
        let report = value!({"image":tag,"image_id":id,"image_inspect":inspect,"inputs":input,"containers":names,"modules_sha256":sha256(&module)});
        let owned = OwnedDocker {
            tag: tag.into(),
            image_id: Some(id),
            containers: names,
        };
        receipt(
            output.path(),
            "build",
            &capture::arguments(&[
                "docker",
                "build",
                "--network",
                "none",
                "--platform",
                "linux/arm64",
                "--tag",
                tag,
                "--build-arg",
                &format!(
                    "SOURCE_SHA256={}",
                    report["inputs"]["source"]["sha256"]
                        .as_str()
                        .ok_or("hash")?
                ),
                "/tmp/diorama-official-build-synthetic",
            ]),
            b"build complete\n",
        )?;
        receipt(
            output.path(),
            "image-inspect",
            &capture::arguments(&["docker", "image", "inspect", tag]),
            &serde_json::to_vec(&inspect)?,
        )?;
        run_fixture(output.path(), &owned, &variants, resolved)?;
        receipt(
            output.path(),
            "copy-modules",
            &capture::arguments(&[
                "docker",
                "cp",
                &format!("{}:/out/modules.sha256", owned.containers[0]),
                "/tmp/synthetic-output/modules.sha256",
            ]),
            b"",
        )?;
        fs::write(output.path().join("modules.sha256"), module)?;
        cleanup_fixture(output.path(), &owned)?;
        write_fixture_json(&output.path().join("receipt.json"), &report)?;
        verify(output.path(), &report, resolved)?;
        Ok((output, report))
    }
    fn run_fixture(
        output: &Path,
        owned: &OwnedDocker,
        variants: &[(&str, Option<&str>)],
        resolved: bool,
    ) -> Result<()> {
        for (position, (label, entrypoint)) in variants.iter().enumerate() {
            for index in 0..2 {
                let label = format!("{label}{index}");
                let raw = if resolved {
                    b"DIORAMA_RESOLVED={}\n".as_slice()
                } else {
                    b"{}\n".as_slice()
                };
                receipt(
                    output,
                    &label,
                    &capture::run_args(
                        owned,
                        &owned.containers[position * 2 + index],
                        index,
                        *entrypoint,
                    ),
                    raw,
                )?;
                fs::write(output.join(format!("{label}.json")), b"{}\n")?;
            }
        }
        Ok(())
    }
    fn cleanup_fixture(output: &Path, owned: &OwnedDocker) -> Result<()> {
        let mut commands = owned
            .containers
            .iter()
            .map(|name| capture::arguments(&["docker", "rm", "--force", name]))
            .collect::<Vec<_>>();
        commands.push(capture::arguments(&[
            "docker", "image", "rm", "--force", &owned.tag,
        ]));
        for name in &owned.containers {
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
            &format!("reference={}", owned.tag),
        ]));
        for (index, argv) in commands.iter().enumerate() {
            receipt(output, &format!("cleanup-{}", index + 1), argv, b"")?;
        }
        Ok(())
    }
    #[test]
    #[ignore = "receipt checks disabled"]
    fn rehashed_command_and_cleanup_fabrications_are_rejected() -> Result<()> {
        for resolved in [false, true] {
            for (key, value) in [
                ("exit_code", value!(1)),
                ("argv", value!(["docker", "run", "unowned"])),
                ("owned_pid", value!(0)),
                ("owner_directory", value!("relative")),
                ("cancelled", value!(true)),
                ("owned_process_group_absent", value!(false)),
                ("output_eof", value!(false)),
            ] {
                let (output, report) = fixture(resolved)?;
                let path = output.path().join("run0.command.json");
                let mut facts = load(&path)?;
                facts[key] = value;
                write_fixture_json(&path, &facts)?;
                assert!(
                    verify(output.path(), &report, resolved).is_err(),
                    "{resolved} {key}"
                );
            }
            let (output, report) = fixture(resolved)?;
            let label = if resolved { "cleanup-4" } else { "cleanup-6" };
            let path = output.path().join(format!("{label}.command.json"));
            let mut facts = load(&path)?;
            fs::write(
                output.path().join(format!("{label}.log")),
                b"still-owned-container\n",
            )?;
            facts["stdout_sha256"] = value!(sha256(b"still-owned-container\n"));
            write_fixture_json(&path, &facts)?;
            assert!(verify(output.path(), &report, resolved).is_err());
            let (output, mut report) = fixture(resolved)?;
            report["image_inspect"][0]["Architecture"] = value!("amd64");
            let raw = serde_json::to_vec(&report["image_inspect"])?;
            fs::write(output.path().join("image-inspect.log"), &raw)?;
            let path = output.path().join("image-inspect.command.json");
            let mut facts = load(&path)?;
            facts["stdout_sha256"] = value!(sha256(&raw));
            write_fixture_json(&path, &facts)?;
            assert!(verify(output.path(), &report, resolved).is_err());
        }
        Ok(())
    }
    #[test]
    #[ignore = "receipt checks disabled"]
    fn module_mutation_cannot_refresh_its_own_digest_and_extra_artifacts_fail() -> Result<()> {
        for resolved in [false, true] {
            let (output, mut report) = fixture(resolved)?;
            fs::write(
                output.path().join("modules.sha256"),
                b"fabricated module list\n",
            )?;
            report["modules_sha256"] = value!(sha256(b"fabricated module list\n"));
            assert!(verify(output.path(), &report, resolved).is_err());
            let (output, report) = fixture(resolved)?;
            fs::write(output.path().join("unrecorded"), b"extra")?;
            assert!(verify(output.path(), &report, resolved).is_err());
            let (output, report) = fixture(resolved)?;
            fs::write(
                output.path().join("run0.log"),
                b"DIORAMA_RESOLVED={\"changed\":true}\n",
            )?;
            let mut facts = load(&output.path().join("run0.command.json"))?;
            facts["stdout_sha256"] = value!(sha256(b"DIORAMA_RESOLVED={\"changed\":true}\n"));
            write_fixture_json(&output.path().join("run0.command.json"), &facts)?;
            assert!(verify(output.path(), &report, resolved).is_err());
        }
        Ok(())
    }
}
