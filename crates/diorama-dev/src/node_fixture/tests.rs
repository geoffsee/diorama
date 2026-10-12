use super::{
    assessment, build,
    common::{Result, Value, json, load, parse, read},
    container, network,
};
use std::path::PathBuf;
fn root() -> Result<PathBuf> {
    diorama_dev::repository_root(&std::env::current_dir()?)
}
fn log(family: &str) -> Result<String> {
    Ok(String::from_utf8(read(
        &root()?.join(format!(
            "tools/node-{family}/evidence/first/{family}-cases.stdout"
        )),
        8 * 1024 * 1024,
    )?)?)
}
fn metadata() -> Result<Value> {
    load(&root()?.join("tools/node-container/evidence/first/artifact-build/artifact.json"))
}
#[test]
#[ignore = "receipt checks disabled"]
fn retained_guest_bytes_satisfy_independent_semantics() -> Result<()> {
    network::semantic(&root()?, &log("network")?)?;
    container::semantic(&root()?, &log("container")?, &metadata()?)?;
    Ok(())
}
#[test]
fn typed_json_bounds_and_special_files_are_rejected() -> Result<()> {
    for raw in [
        b"{\"x\":1,\"x\":2}".as_slice(),
        b"{\"x\":1.5}",
        b"NaN",
        b"1e400",
    ] {
        assert!(parse(raw).is_err());
    }
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("data");
    std::fs::write(&path, b"12345")?;
    assert!(read(&path, 4).is_err());
    assert!(read(directory.path(), 8).is_err());
    std::os::unix::fs::symlink(&path, directory.path().join("link"))?;
    assert!(read(&directory.path().join("link"), 8).is_err());
    Ok(())
}
fn network_change(raw: &str, case: &str, change: impl FnOnce(&mut Value)) -> Result<String> {
    let (body, _) = super::common::block(raw, &format!("CASE_{case}"))?;
    let (stdout, _) = super::common::block(body, "STDOUT")?;
    let mut value = parse(stdout.as_bytes())?;
    change(&mut value);
    Ok(raw.replacen(stdout, &format!("{value}\n"), 1))
}
#[test]
fn network_module_order_and_owner_claims_are_required() -> Result<()> {
    let raw = log("network")?;
    for key in ["spawned", "joined", "reaped"] {
        let changed = network_change(&raw, "double_failed", |v| {
            v["modules"][0][key] = false.into();
        })?;
        assert!(network::semantic(&root()?, &changed).is_err());
    }
    for mutation in 0..3 {
        let changed = network_change(&raw, "real_first", |v| {
            let rows = v["modules"].as_array_mut().expect("modules");
            match mutation {
                0 => {
                    rows.remove(0);
                },
                1 => rows.swap(0, 1),
                _ => rows[1] = rows[0].clone(),
            }
        })?;
        assert!(network::semantic(&root()?, &changed).is_err());
    }
    Ok(())
}
#[test]
fn network_cancel_guards_limits_and_fresh_readback_cannot_be_relabeled() -> Result<()> {
    let raw = log("network")?;
    for (case, key, value) in [
        ("guard_failed", "shared_effects_possible", json!(true)),
        ("guard_failed", "family", json!("Present(NfTables)")),
        ("double_cancel", "status", json!("Completed")),
        ("double_cancel", "shared_effects_possible", json!(false)),
    ] {
        let changed = network_change(&raw, case, |v| v[key] = value)?;
        assert!(network::semantic(&root()?, &changed).is_err());
    }
    for (case, index, key, value) in [
        ("double_limits", 0, "outcome", json!("Failed")),
        ("double_cancel", 0, "ownership_lost", json!(true)),
        ("double_failed", 0, "exit", json!(true)),
    ] {
        let changed = network_change(&raw, case, |v| v["modules"][index][key] = value)?;
        assert!(network::semantic(&root()?, &changed).is_err());
    }
    for (case, index, value) in [
        ("real_first", 1, "ObservedDisabled"),
        ("real_repeat", 0, "ObservedDisabled"),
    ] {
        let changed = network_change(&raw, case, |v| v["ipv6"][index]["outcome"] = value.into())?;
        assert!(network::semantic(&root()?, &changed).is_err());
    }
    let changed = network_change(&raw, "double_cancel", |v| {
        v["ipv6"] = json!([{"path":network::CONTROLS[0],"outcome":"ObservedDisabled"}]);
    })?;
    assert!(network::semantic(&root()?, &changed).is_err());
    Ok(())
}
#[test]
fn network_independent_scalars_restoration_and_case_boundaries_are_required() -> Result<()> {
    let raw = log("network")?;
    for (old, new) in [
        ("SCALARS_initial all=0", "SCALARS_initial all=1"),
        ("RESTORED_modprobe ", "LOST_modprobe "),
        ("ORIGINAL_KIND_iptables ", "ORIGINAL_KIND_other "),
        ("DOUBLE_modprobe ", "DOUBLE_other "),
        ("NETWORK_GUEST_COMPLETE", "NETWORK_GUEST_INCOMPLETE"),
        ("CASE_real_first_END", "CASE_real_repeat_END"),
    ] {
        assert!(raw.contains(old));
        assert!(network::semantic(&root()?, &raw.replacen(old, new, 1)).is_err());
    }
    let (body, _) = super::common::block(&raw, "CASE_guard_failed")?;
    assert!(
        network::semantic(
            &root()?,
            &format!("{raw}CASE_guard_failed_BEGIN\n{body}CASE_guard_failed_END\n")
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn configuration_fields_require_unique_correct_sections() -> Result<()> {
    let good = "apiVersion: kubesolo.io/v1alpha1\nkind: Config\nnetwork:\n  disableIPv6: false\nruntime:\n  containerMode: true\n  endpoint: unix:///tmp/external-runtime/containerd.sock\n";
    network::config(good, true)?;
    for bad in [
        good.replace("network:", "other:"),
        good.replace("runtime:", "other:"),
        format!("{good}runtime:\n"),
        good.replace("containerMode: true", "containerMode: false"),
    ] {
        assert!(network::config(&bad, true).is_err());
    }
    Ok(())
}
#[test]
fn mount_tree_controller_and_pid_limits_reject_ambiguous_observations() -> Result<()> {
    let good = "1 0 8:1 / / rw - ext4 root rw\n2 1 0:2 / /proc rw - proc proc rw\n";
    container::mounts(good)?;
    for bad in [
        good.trim_end().into(),
        good.replace("2 1", "2 2"),
        good.replace("2 1", "1 1"),
        good.replace("/proc", "relative"),
        good.replace("/proc", "/pro\\999c"),
        good.replace("rw -", "rw shared:0 -"),
    ] {
        assert!(container::mounts(&bad).is_err());
    }
    for bad in ["cpu cpu", "CPU", "1cpu", &"x".repeat(65)] {
        assert!(container::names(bad).is_err());
    }
    for bad in ["0", "-1", "4294967296", "01"] {
        assert!(container::pids(bad).is_err());
    }
    Ok(())
}
#[test]
#[ignore = "receipt checks disabled"]
fn container_protocol_and_independent_scope_are_required() -> Result<()> {
    let raw = log("container")?;
    let metadata = metadata()?;
    for (old, new) in [
        ("INIT_ABSENT", "INIT_PRESENT"),
        ("domain\n", "domain threaded\n"),
        ("SIGNAL_NO_PREPARATION", "SIGNAL_PREPARATION"),
        ("CONTAINER_GUEST_COMPLETE", "CONTAINER_GUEST_INCOMPLETE"),
        ("GLOBAL_ROOT_ID ", "GLOBAL_ROOT_OTHER "),
        ("OBSERVER_MNT_NS ", "OBSERVER_OTHER_NS "),
        (
            "\"preparation_started\":false",
            "\"preparation_started\":true",
        ),
        ("\"reason\":\"cancelled\"", "\"reason\":\"eof\""),
    ] {
        assert!(raw.contains(old), "{old}");
        assert!(
            container::semantic(&root()?, &raw.replacen(old, new, 1), &metadata).is_err(),
            "{old}"
        );
    }
    let changed = raw.replacen(text_hash(&metadata)?, &"0".repeat(64), 1);
    assert!(container::semantic(&root()?, &changed, &metadata).is_err());
    Ok(())
}
fn text_hash(meta: &Value) -> Result<&str> {
    super::common::text(&meta["files"]["prepare_node_host"]["sha256"])
}
#[test]
fn all_safe_build_tests_and_cli_frames_are_checked() -> Result<()> {
    for family in ["network", "container"] {
        let directory = root()?.join(format!("tools/node-{family}/evidence/first/artifact-build"));
        let raw = String::from_utf8(read(
            &directory.join(if directory.join("test.log").exists() {
                "test.log"
            } else {
                "run.log"
            }),
            32 * 1024 * 1024,
        )?)?;
        build::verify_run(&root()?, family, &raw)?;
        for changed in [
            raw.replacen(" ... ok", " ... FAILED", 1),
            raw.replacen("CLI_help_END", "CLI_help_LOST", 1),
            format!("test unexpected ... FAILED\n{raw}"),
        ] {
            // Container tests are framed; an unframed diagnostic cannot add a test to a frame.
            if family == "container" && changed.starts_with("test unexpected") {
                continue;
            }
            assert!(build::verify_run(&root()?, family, &changed).is_err());
        }
    }
    Ok(())
}
#[test]
fn assessment_adverse_probe_claims_and_namespace_are_required() -> Result<()> {
    let original = String::from_utf8(read(
        &root()?.join("tools/node-assessment/evidence/first.log"),
        1024 * 1024,
    )?)?;
    let raw = if original.contains("  /out/node-fixture\n") {
        original
    } else {
        format!("{}  /out/node-fixture\n{original}", "f".repeat(64))
    };
    assessment::records(&raw)?;
    for (old, new) in [
        ("Some(Deadline)", "None"),
        ("joined=true", "joined=false"),
        (
            "external_sentinel_preserved=true",
            "external_sentinel_preserved=false",
        ),
        ("probe_absent=true", "probe_absent=false"),
        ("  /out/assess_host", "  /out/other"),
    ] {
        assert!(assessment::records(&raw.replacen(old, new, 1)).is_err());
    }
    Ok(())
}
