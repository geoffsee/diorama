//! Independent expected Alpine host effects and exact receipt validation.
use super::{
    BTreeMap, Path, Result, Value, digest, equal, fixture, guest, json, load, preparation, require,
    text,
};
use std::collections::BTreeSet;
const NETWORK_ERROR: &str = "required Alpine networking packages not found: nftables, iptables. kube-proxy needs both nftables (nft) and iptables (iptables-nft wrapper). Run the installer with --install-prereqs to install them automatically, or run: apk add nftables iptables";
const CGROUP_ERROR: &str = "cgroup controllers are not available on this Alpine system. Run: rc-update add cgroups boot && rc-service cgroups start — or re-run the installer with --install-prereqs";
pub(super) const WARNING: &str = "Unable to activate module keys_to_console, helper tool not found at /usr/lib/cloud-init/write-ssh-key-fingerprints";
const ADDED: [&str; 8] = [
    "gmp-6.3.0-r4",
    "iptables-1.8.13-r0",
    "iptables-openrc-1.8.13-r0",
    "jansson-2.15.0-r0",
    "libnftnl-1.3.1-r0",
    "libxtables-1.8.13-r0",
    "nftables-1.1.6-r1",
    "nftables-openrc-1.1.6-r1",
];
const CONTROLLERS: &str = "cpuset cpu io memory hugetlb pids dmem";
fn marker(text: &str, value: &str) -> Result<()> {
    require(
        text.lines().filter(|line| *line == value).count() == 1,
        format!("exact marker {value}"),
    )
}
fn records(text: &str) -> Result<Value> {
    Ok(json!(
        text.lines()
            .filter_map(|line| line.strip_prefix("DIORAMA_ALPINE_BASELINE "))
            .map(|line| diorama_dev::json::parse(line.as_bytes()))
            .collect::<Result<Vec<_>>>()?
    ))
}
fn packages(text: &str, name: &str) -> Result<BTreeSet<String>> {
    let begin = format!("PACKAGES_{name}_BEGIN\n");
    let end = format!("PACKAGES_{name}_END");
    require(
        text.matches(&begin).count() == 1 && text.matches(&end).count() == 1,
        "package inventory markers",
    )?;
    let lines = text
        .split_once(&begin)
        .ok_or("package start")?
        .1
        .split_once(&end)
        .ok_or("package end")?
        .0
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let set = lines.iter().cloned().collect::<BTreeSet<_>>();
    require(
        lines.len() > 100 && set.iter().eq(lines.iter()),
        "complete sorted unique installed package inventory",
    )?;
    Ok(set)
}
fn package_effects(before: &str, reboot: &str) -> Result<Value> {
    let initial = packages(before, "before")?;
    let installed = packages(before, "installed")?;
    require(
        installed
            .difference(&initial)
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == ADDED.into_iter().collect()
            && initial.is_subset(&installed),
        "exact eight-package installation delta",
    )?;
    require(
        packages(reboot, "reboot")? == installed,
        "reboot package inventory",
    )?;
    for pin in [
        "openrc-0.63.2-r0",
        "apk-tools-3.0.8-r0",
        "linux-virt-6.18.52-r0",
        "alpine-release-3.24.2-r0",
    ] {
        require(initial.contains(pin), "guest system version pin")?;
    }
    marker(before, "CONTROLLERS_before ABSENT")?;
    for (name, text) in [("after", before), ("repeated", before), ("reboot", reboot)] {
        marker(text, &format!("CONTROLLERS_{name} {CONTROLLERS}"))?;
    }
    Ok(json!({"initial":initial,"installed":installed,"controllers":CONTROLLERS}))
}
pub(super) fn baseline_semantic(before: &str, reboot: &str) -> Result<Value> {
    let expected = json!([
        {"action":"network","install":false,"error":NETWORK_ERROR},
        {"action":"cgroups","install":false,"error":CGROUP_ERROR},
        {"action":"network","install":true,"error":""},
        {"action":"network","install":true,"error":""},
        {"action":"cgroups","install":true,"error":""},
        {"action":"cgroups","install":true,"error":""}]);
    equal(&records(before)?, &expected, "baseline preparation calls")?;
    equal(
        &records(reboot)?,
        &json!([{"action":"cgroups","install":false,"error":""}]),
        "baseline reboot call",
    )?;
    for value in [
        "DIORAMA_ALPINE_BOOT_COMPLETE",
        "DIORAMA_NO_OPT_IN_UNCHANGED",
        "DIORAMA_PACKAGE_REPEAT_UNCHANGED",
        "DIORAMA_PREPARATION_COMPLETE",
    ] {
        marker(before, value)?;
    }
    marker(reboot, "DIORAMA_REBOOT_COMPLETE")?;
    let mut effects = package_effects(before, reboot)?;
    effects["records"] = expected;
    Ok(effects)
}
fn cases(text: &str) -> Result<Vec<Value>> {
    let mut cases = vec![];
    let mut remaining = text;
    while let Some((_, tail)) = remaining.split_once("CASE_") {
        let (name, tail) = tail.split_once("_BEGIN\nEXIT ").ok_or("case frame start")?;
        require(
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
            "case name",
        )?;
        let (code, tail) = tail
            .split_once("\nSTDOUT_BEGIN\n")
            .ok_or("case exit frame")?;
        let code = code.parse::<u32>()?;
        let (stdout, tail) = tail
            .split_once("STDOUT_END\nSTDERR_BEGIN\n")
            .ok_or("stdout frame")?;
        let ending = format!("STDERR_END\nCASE_{name}_END");
        let (stderr, tail) = tail.split_once(&ending).ok_or("stderr/end frame")?;
        cases.push(json!({"name":name,"exit":code,"stdout":stdout,"stderr":stderr}));
        remaining = tail;
    }
    require(
        text.matches("CASE_").count() == cases.len() * 2,
        "complete case frames",
    )?;
    Ok(cases)
}
#[allow(
    clippy::too_many_lines,
    reason = "Source-specified independent observable behavior oracle"
)]
pub(super) fn rust_semantic(root: &Path, before: &str, reboot: &str) -> Result<Value> {
    let mut rows = cases(before)?;
    rows.extend(cases(reboot)?);
    equal(
        &json!(rows.iter().map(|r| &r["name"]).collect::<Vec<_>>()),
        &json!([
            "opt_out",
            "package_failure",
            "service_failure",
            "injected_no_effect_service",
            "prepare",
            "repeat",
            "reboot"
        ]),
        "Rust case order",
    )?;
    equal(
        &json!(rows.iter().map(|r| &r["exit"]).collect::<Vec<_>>()),
        &json!([1, 1, 1, 1, 0, 0, 0]),
        "Rust exit classification",
    )?;
    let mut plans = vec![];
    for row in &rows {
        equal(&row["stdout"], &json!(""), "Rust stdout")?;
        let stderr = row["stderr"].as_str().ok_or("stderr string")?;
        require(
            stderr.contains("All 7 checks passed") == (row["exit"] == 0),
            "no false success",
        )?;
        if ["package_failure", "service_failure"]
            .contains(&row["name"].as_str().ok_or("case name")?)
        {
            require(
                stderr.contains("prerequisite preparation command failed or exceeded its deadline")
                    && stderr.contains("host state may have changed"),
                "action failure and partial effects",
            )?;
        }
        plans.push(
            stderr
                .lines()
                .filter(|line| line.contains("> Preparing"))
                .map(str::trim)
                .collect::<Vec<_>>(),
        );
    }
    equal(
        &json!(plans),
        &json!([
            [],
            ["> Preparing Alpine networking packages"],
            [
                "> Preparing Alpine networking packages",
                "> Preparing Alpine cgroups service"
            ],
            ["> Preparing Alpine cgroups service"],
            ["> Preparing Alpine cgroups service"],
            [],
            []
        ]),
        "ordered plans and idempotence",
    )?;
    require(
        rows[3]["stderr"]
            .as_str()
            .ok_or("stderr")?
            .contains("prerequisite is still missing after preparation"),
        "no-effect service rejected",
    )?;
    require(
        rows[0]["stderr"]
            .as_str()
            .ok_or("stderr")?
            .contains("required Alpine networking tools are missing"),
        "actual opt-out blocker",
    )?;
    let here = fixture(root, "alpine-rust-preparation");
    let inputs = load(&here.join("inputs.json"))?;
    let mut hashes = BTreeMap::new();
    for name in ["ORIGINAL", "DOUBLE", "RESTORED"] {
        let prefix = format!("SERVICE_{name} ");
        let values = before
            .lines()
            .filter_map(|line| line.strip_prefix(&prefix))
            .collect::<Vec<_>>();
        require(values.len() == 1, "one service identity marker")?;
        let hash = values[0]
            .strip_suffix("  /etc/init.d/cgroups")
            .ok_or("service path")?;
        require(
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "service hash",
        )?;
        hashes.insert(name, hash);
    }
    require(
        hashes["ORIGINAL"] == hashes["RESTORED"] && hashes["ORIGINAL"] != hashes["DOUBLE"],
        "service restored",
    )?;
    equal(
        &json!(hashes["ORIGINAL"]),
        &inputs["openrc_service_sha256"],
        "official OpenRC service",
    )?;
    equal(
        &json!(hashes["DOUBLE"]),
        &json!(digest(&here.join("service-double.sh"))?),
        "explicit no-effect service",
    )?;
    for value in [
        "NO_OPT_IN_UNCHANGED",
        "PACKAGE_FAILURE_UNCHANGED",
        "RUST_PREPARATION_COMPLETE",
    ] {
        marker(before, value)?;
    }
    marker(reboot, "RUST_REBOOT_COMPLETE")?;
    let mut effects = package_effects(before, reboot)?;
    equal(
        &json!(packages(before, "after_service_failure")?),
        &effects["installed"],
        "partial package effects retained",
    )?;
    effects["cases"] = json!(rows);
    Ok(effects)
}
pub(super) fn cloud(code: i64, cloud: &Value) -> Result<()> {
    require([0, 2].contains(&code), "cloud-init exit classification")?;
    equal(&cloud["status"], &json!("done"), "cloud completion")?;
    equal(&cloud["errors"], &json!([]), "cloud errors")?;
    let warnings = &cloud["recoverable_errors"];
    let admitted = json!({"WARNING":[WARNING]});
    require(
        warnings == &admitted || (warnings == &json!({}) && code != 2),
        "only known bootstrap warning",
    )?;
    for stage in ["init-local", "init", "modules-config", "modules-final"] {
        equal(&cloud[stage]["errors"], &json!([]), "cloud stage errors")?;
    }
    Ok(())
}
#[allow(
    clippy::too_many_lines,
    reason = "Audit all shared VM trust-boundary fields together"
)]
pub(crate) fn verify_guest_envelope(
    directory: &Path,
    inputs: &Value,
    adapter: &str,
    require_reboot: bool,
) -> Result<Value> {
    let report = verify_guest_fields(directory, inputs, adapter, require_reboot)?;
    super::command_evidence::shared(directory, &report, inputs, require_reboot)?;
    Ok(report)
}
#[allow(
    clippy::too_many_lines,
    reason = "Independent immutable envelope checks"
)]
fn verify_guest_fields(
    directory: &Path,
    inputs: &Value,
    adapter: &str,
    require_reboot: bool,
) -> Result<Value> {
    let report = load(&directory.join("result.json"))?;
    equal(
        &report["evidence_sha256"],
        &guest::evidence_inventory(directory)?,
        "exact raw evidence inventory",
    )?;
    equal(
        &report["schema_version"],
        &json!(2),
        "current Rust capture schema",
    )?;
    equal(&report["adapter"], &json!(adapter), "expected adapter")?;
    for (key, value) in [
        ("status", json!("passed")),
        ("cancelled", json!(false)),
        ("errors", json!([])),
        ("owned_process_group_absent", json!(true)),
        ("owned_temporary_directory_removed", json!(true)),
        ("explicit_privilege_opt_in", json!(true)),
        ("qemu_exit_code", json!(0)),
        ("shutdown", json!("guest-poweroff")),
        ("privileged_mount_probe", json!("passed")),
        ("serial_log_truncated", json!(false)),
        ("retained_commands", json!([])),
    ] {
        equal(&report[key], &value, key)?;
    }
    require(
        report["working_tree_snapshot"].is_boolean(),
        "explicit snapshot policy",
    )?;
    let revision = report["revision"].as_str().ok_or("revision")?;
    require(
        revision.len() == 40
            && revision
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "exact revision",
    )?;
    equal(&report["inputs"], inputs, "accepted inputs")?;
    let tools = report["tools"]
        .as_object()
        .ok_or("host tools")?
        .iter()
        .map(|(n, v)| (n.clone(), v["sha256"].clone()))
        .collect::<serde_json::Map<_, _>>();
    equal(
        &Value::Object(tools),
        &inputs["host_tools"],
        "pinned host tools",
    )?;
    equal(&report["firmware"], &inputs["firmware"], "pinned firmware")?;
    for (label, key) in [
        ("cloud-init", "cloud_init"),
        ("reboot-cloud-init", "reboot_cloud_init"),
    ] {
        if label == "reboot-cloud-init" && !require_reboot {
            require(
                report.get(key).is_none() && report.get(format!("{key}_exit")).is_none(),
                "unexpected reboot cloud lifecycle",
            )?;
            continue;
        }
        equal(
            &report[key],
            &load(&directory.join(format!("{label}.stdout")))?,
            "raw cloud-init observation",
        )?;
        cloud(
            report[format!("{key}_exit")]
                .as_i64()
                .ok_or("integer cloud exit")?,
            &report[key],
        )?;
    }
    let private = report["owned_temporary_directory"]
        .as_str()
        .ok_or("private path")?;
    require(
        private.starts_with("/tmp/diorama-vm-") && !private.contains([',', '\n']),
        "owned private directory",
    )?;
    let port = report["ssh_forward"].as_str().ok_or("SSH forward")?;
    let number = port
        .strip_prefix("127.0.0.1:")
        .ok_or("loopback SSH only")?
        .parse::<u16>()?;
    require(number > 0, "nonzero SSH port")?;
    equal(
        &report["qemu_argv"],
        &json!(qemu_argv(private, port)),
        "exact VM boundary",
    )?;
    let key = report["guest_host_public_key"]
        .as_str()
        .ok_or("guest public key")?;
    let parts = key.split_whitespace().collect::<Vec<_>>();
    require(
        parts.len() == 3
            && parts[0] == "ssh-ed25519"
            && parts[2] == "diorama-alpine-fixture-host"
            && parts[1]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)),
        "fixture-only host key",
    )?;
    if require_reboot {
        let old = text(&directory.join("before-reboot-id.stdout"))?;
        let new = text(&directory.join("reboot-readiness.stdout"))?;
        require(
            old.trim() != new.trim()
                && [old.trim(), new.trim()].into_iter().all(|s| {
                    s.len() == 36 && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
                }),
            "actual fresh kernel boot",
        )?;
    } else {
        for name in report["evidence_sha256"]
            .as_object()
            .ok_or("evidence inventory")?
            .keys()
        {
            require(
                !name.starts_with("reboot-")
                    && !name.starts_with("guest-reboot.")
                    && !name.starts_with("before-reboot-"),
                "unexpected reboot command lifecycle",
            )?;
        }
        for name in [
            "before-reboot-id.stdout",
            "reboot-readiness.stdout",
            "reboot-cloud-init.stdout",
            "reboot-verification.stdout",
        ] {
            require(!directory.join(name).exists(), "unexpected reboot evidence")?;
        }
    }
    Ok(report)
}
pub(super) fn verify(root: &Path, profile: &str, directory: &Path) -> Result<Value> {
    verify_with_baseline(root, profile, directory, None)
}
pub(super) fn verify_with_baseline(
    root: &Path,
    profile: &str,
    directory: &Path,
    baseline_directory: Option<&Path>,
) -> Result<Value> {
    let here = fixture(
        root,
        if profile == "alpine" {
            "alpine-preparation"
        } else {
            "alpine-rust-preparation"
        },
    );
    let inputs = load(&here.join("inputs.json"))?;
    let report = verify_guest_envelope(
        directory,
        &inputs,
        if profile == "alpine" {
            "qemu-disposable-alpine-preparation"
        } else {
            "qemu-disposable-alpine-rust-preparation"
        },
        true,
    )?;
    equal(
        &report["working_tree_snapshot"],
        &json!(true),
        "Alpine snapshot policy",
    )?;
    let before = text(&directory.join("baseline-inventory.stdout"))?;
    super::command_evidence::alpine(directory, &report, root, profile, &inputs)?;
    equal(&report["observation"], &json!(before), "raw observation")?;
    let reboot = text(&directory.join("reboot-verification.stdout"))?;
    if profile == "alpine" {
        baseline_semantic(&before, &reboot)
    } else {
        preparation::verify(root, &directory.join("artifact-build"))?;
        candidate_metadata(
            &load(&directory.join("artifact-build/artifact.json"))?,
            &inputs,
            report["revision"].as_str().ok_or("guest revision")?,
        )?;
        let effects = rust_semantic(root, &before, &reboot)?;
        let published = fixture(root, "alpine-preparation").join("evidence-rust/first");
        let (baseline, _) = verified_baseline(
            root,
            baseline_directory.unwrap_or(&published),
            Some(
                report["baseline_result_sha256"]
                    .as_str()
                    .ok_or("baseline result digest")?,
            ),
        )?;
        baseline_parity(&effects, &baseline)?;
        Ok(effects)
    }
}
pub(super) fn candidate_metadata(metadata: &Value, inputs: &Value, revision: &str) -> Result<()> {
    for key in ["sha256", "size", "target"] {
        equal(
            &metadata[key],
            &inputs["artifact"][key],
            "candidate byte and target pin",
        )?;
    }
    require(
        revision.len() == 40
            && revision
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "exact capture revision",
    )?;
    equal(
        &metadata["revision"],
        &json!(revision),
        "current qualified artifact and guest source revision",
    )
}
pub(super) fn verified_baseline(
    root: &Path,
    directory: &Path,
    expected_digest: Option<&str>,
) -> Result<(Value, String)> {
    let path = directory.join("result.json");
    let before = digest(&path)?;
    if let Some(expected) = expected_digest {
        equal(
            &json!(before),
            &json!(expected),
            "bound external baseline result",
        )?;
    }
    let observations = verify(root, "alpine", directory)?;
    equal(
        &json!(digest(&path)?),
        &json!(before),
        "baseline stable during verification",
    )?;
    Ok((observations, before))
}
pub(super) fn baseline_parity(effects: &Value, baseline: &Value) -> Result<()> {
    for key in ["initial", "installed", "controllers"] {
        equal(
            &effects[key],
            &baseline[key],
            "current baseline preparation parity",
        )?;
    }
    Ok(())
}
pub(super) fn qemu_argv(private: &str, port: &str) -> Vec<String> {
    [
        "qemu-system-aarch64",
        "-machine",
        "virt,accel=hvf",
        "-cpu",
        "host",
        "-smp",
        "2",
        "-m",
        "2048",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-qmp",
        &format!("unix:{private}/qmp.sock,server=on,wait=off"),
        "-drive",
        "if=pflash,format=raw,readonly=on,file=/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
        "-drive",
        &format!("if=pflash,format=raw,file={private}/vars.fd"),
        "-drive",
        &format!("if=virtio,format=qcow2,file={private}/disk.qcow2"),
        "-drive",
        &format!("if=virtio,format=raw,readonly=on,file={private}/seed.iso"),
        "-netdev",
        &format!("user,id=n0,restrict=on,hostfwd=tcp:{port}-:22"),
        "-device",
        "virtio-net-pci,netdev=n0",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bootstrap_admits_only_exact_known_degradation() -> Result<()> {
        let mut value = json!({"status":"done","errors":[],"recoverable_errors":{},"init-local":{"errors":[]},"init":{"errors":[]},"modules-config":{"errors":[]},"modules-final":{"errors":[]}});
        cloud(0, &value)?;
        assert!(cloud(2, &value).is_err());
        value["recoverable_errors"] = json!({"WARNING":[WARNING]});
        cloud(2, &value)?;
        value["modules-final"]["errors"] = json!(["failure"]);
        assert!(cloud(0, &value).is_err());
        Ok(())
    }
    #[test]
    fn malformed_case_frames_fail() {
        assert!(cases("CASE_a_BEGIN\nEXIT 0\nSTDOUT_BEGIN\nx").is_err());
        assert!(cases("CASE_a_END").is_err());
    }
    fn historical(root: &Path, name: &str) -> Result<(String, String)> {
        let directory = fixture(root, name).join("evidence/first");
        Ok((
            text(&directory.join("baseline-inventory.stdout"))?,
            text(&directory.join("reboot-verification.stdout"))?,
        ))
    }
    #[test]
    fn baseline_effect_mutations_preserve_independent_expectations() -> Result<()> {
        let root = diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
        let (before, reboot) = historical(&root, "alpine-preparation")?;
        baseline_semantic(&before, &reboot)?;
        for (old, new) in [
            (
                "CONTROLLERS_after cpuset cpu io memory hugetlb pids dmem",
                "CONTROLLERS_after cpu io memory hugetlb pids dmem",
            ),
            ("DIORAMA_NO_OPT_IN_UNCHANGED", ""),
            (NETWORK_ERROR, "different failure"),
            ("nftables-1.1.6-r1", "nftables-1.1.7-r0"),
            ("\"install\":false", "\"install\":0"),
        ] {
            require(before.contains(old), "mutation target")?;
            assert!(
                baseline_semantic(&before.replace(old, new), &reboot).is_err(),
                "{old}"
            );
        }
        Ok(())
    }
    #[test]
    fn rust_effect_mutations_reject_false_success_and_service_drift() -> Result<()> {
        let root = diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
        let (before, reboot) = historical(&root, "alpine-rust-preparation")?;
        rust_semantic(&root, &before, &reboot)?;
        for (old, new) in [
            (
                "CASE_package_failure_BEGIN\nEXIT 1",
                "CASE_package_failure_BEGIN\nEXIT 0",
            ),
            ("host state may have changed", "nothing changed"),
            ("NO_OPT_IN_UNCHANGED", ""),
            ("PACKAGE_FAILURE_UNCHANGED", ""),
            (
                "prerequisite is still missing after preparation",
                "prepared",
            ),
            ("CONTROLLERS_after cpuset", "CONTROLLERS_after"),
        ] {
            require(before.contains(old), "mutation target")?;
            assert!(
                rust_semantic(&root, &before.replace(old, new), &reboot).is_err(),
                "{old}"
            );
        }
        Ok(())
    }
    #[test]
    #[ignore = "receipt checks disabled"]
    fn envelope_rejects_mutated_cleanup_boundary_and_reboot() -> Result<()> {
        let root = diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
        let original = fixture(&root, "alpine-preparation").join("evidence/first");
        let dir = tempfile::tempdir()?;
        for entry in std::fs::read_dir(&original)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                std::fs::copy(entry.path(), dir.path().join(entry.file_name()))?;
            }
        }
        // Synthetic envelope unit fixture only: historical observations are not promoted to current capture evidence.
        let mut valid = load(&dir.path().join("result.json"))?;
        valid["schema_version"] = json!(2);
        valid["cancelled"] = json!(false);
        valid["serial_log_truncated"] = json!(false);
        valid["retained_commands"] = json!([]);
        valid["evidence_sha256"] = guest::evidence_inventory(dir.path())?;
        let inputs = valid["inputs"].clone();
        let adapter = valid["adapter"].as_str().ok_or("adapter")?.to_owned();
        crate::parity::write_json(&dir.path().join("result.json"), &valid, false)?;
        verify_guest_fields(dir.path(), &inputs, &adapter, true)?;
        assert!(
            verify_guest_envelope(dir.path(), &inputs, &adapter, true).is_err(),
            "historical logs lack current command receipts"
        );
        for kind in ["cleanup", "extra_drive", "network", "cloud"] {
            let mut bad = valid.clone();
            match kind {
                "cleanup" => {
                    bad.as_object_mut()
                        .ok_or("object")?
                        .remove("owned_process_group_absent");
                },
                "extra_drive" => bad["qemu_argv"]
                    .as_array_mut()
                    .ok_or("argv")?
                    .extend([json!("-drive"), json!("file=/host/example,format=raw")]),
                "network" => {
                    for arg in bad["qemu_argv"].as_array_mut().ok_or("argv")? {
                        let text = arg.as_str().ok_or("argv text")?;
                        *arg = json!(text.replace("restrict=on", "restrict=off"));
                    }
                },
                _ => bad["reboot_cloud_init"]["status"] = json!("running"),
            }
            crate::parity::write_json(&dir.path().join("result.json"), &bad, false)?;
            assert!(
                verify_guest_fields(dir.path(), &inputs, &adapter, true).is_err(),
                "{kind}"
            );
        }
        crate::parity::write_json(&dir.path().join("result.json"), &valid, false)?;
        std::fs::copy(
            dir.path().join("before-reboot-id.stdout"),
            dir.path().join("reboot-readiness.stdout"),
        )?;
        valid["evidence_sha256"] = guest::evidence_inventory(dir.path())?;
        crate::parity::write_json(&dir.path().join("result.json"), &valid, false)?;
        assert!(verify_guest_fields(dir.path(), &inputs, &adapter, true).is_err());
        Ok(())
    }
    #[test]
    #[ignore = "source hash qualification receipt checks disabled"]
    fn published_alpine_requires_current_rust_captures() -> Result<()> {
        let root = diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
        super::super::prepare::verify(
            &root,
            &fixture(&root, "alpine-preparation").join("evidence-rust/prepare"),
        )?;
        for (profile, name) in [
            ("alpine", "alpine-preparation"),
            ("alpine-rust", "alpine-rust-preparation"),
        ] {
            let first = verify(
                &root,
                profile,
                &fixture(&root, name).join("evidence-rust/first"),
            )?;
            let repeat = verify(
                &root,
                profile,
                &fixture(&root, name).join("evidence-rust/repeat"),
            )?;
            equal(&first, &repeat, "independent repeated guests")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod dependency_tests {
    use super::*;
    #[test]
    fn fresh_qualified_revision_retains_exact_artifact_byte_and_target_pins() -> Result<()> {
        let root = diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
        let inputs = load(&fixture(&root, "alpine-rust-preparation").join("inputs.json"))?;
        let revision = "a".repeat(40);
        let mut metadata = inputs["artifact"].clone();
        metadata["revision"] = json!(revision);
        candidate_metadata(&metadata, &inputs, &revision)?;
        for (key, value) in [
            ("revision", json!("b".repeat(40))),
            ("sha256", json!("c".repeat(64))),
            ("size", json!(true)),
            ("target", json!("aarch64-unknown-linux-gnu")),
        ] {
            let mut bad = metadata.clone();
            bad[key] = value;
            assert!(
                candidate_metadata(&bad, &inputs, &revision).is_err(),
                "{key}"
            );
        }
        assert!(candidate_metadata(&metadata, &inputs, "moving-ref").is_err());
        Ok(())
    }
    #[test]
    fn external_baseline_requires_bound_digest_and_full_current_verification() -> Result<()> {
        let root = diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
        let dir = tempfile::tempdir()?;
        assert!(verified_baseline(&root, dir.path(), None).is_err());
        std::fs::write(dir.path().join("result.json"), b"{}\n")?;
        let actual = digest(&dir.path().join("result.json"))?;
        assert!(
            verified_baseline(&root, dir.path(), Some(&"0".repeat(64)))
                .unwrap_err()
                .to_string()
                .contains("bound external baseline result")
        );
        assert!(
            verified_baseline(&root, dir.path(), Some(&actual)).is_err(),
            "matching a self-reported hash cannot bypass full baseline verification"
        );
        let effects =
            json!({"initial":["base"],"installed":["base","added"],"controllers":["cpu"]});
        baseline_parity(&effects, &effects)?;
        for key in ["initial", "installed", "controllers"] {
            let mut changed = effects.clone();
            changed[key] = json!([]);
            assert!(baseline_parity(&effects, &changed).is_err(), "{key}");
        }
        Ok(())
    }
}
