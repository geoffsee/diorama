//! Invented observations exercise rejection paths; they never qualify a VM capture.
use super::super::common::{inventory, read};
use super::*;
use std::{fs, os::unix::fs::symlink, path::PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn metadata() -> Value {
    json!({"files":{"prepare_node_host":{"sha256":"a".repeat(64)},"constrained-guest":{"sha256":"c".repeat(64)}}})
}
fn mounts(readonly: bool) -> String {
    format!(
        "1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 0:2 / /proc rw - proc proc rw\n3 2 0:2 /sys /proc/sys {},nosuid,nodev,noexec - proc proc rw\n",
        if readonly { "ro" } else { "rw" }
    )
}
fn live(pid: u64, namespace: u64, hash: char) -> Value {
    json!({"pid":pid,"starttime":1000+pid,"exe_sha256":hash.to_string().repeat(64),"mnt":format!("mnt:[{namespace}]"),"cgroup":"0::/fixture\n"})
}
fn keeper() -> Value {
    let mut v = live(100, 10, 'c');
    v["socket"] = json!({"device":1,"inode":20,"mode":0o140_600,"uid":0,"gid":0});
    v["configuration"] = json!({"identity":{"device":1,"inode":21,"mode":0o100_600,"uid":0,"gid":0},"sha256":"d".repeat(64)});
    v
}
fn configuration() -> &'static str {
    "apiVersion: kubesolo.io/v1alpha1\nkind: Config\nnetwork:\n  disableIPv6: true\nruntime:\n  containerMode: false\n  endpoint: unix:///tmp/external-runtime/containerd.sock\n"
}
fn consumer_result(name: &str, pass: u64, pid: u64) -> Value {
    let stopped = matches!(name, "guard" | "cancel");
    let status = match name {
        "guard" => "GuardStopped",
        "cancel" => "Cancelled",
        _ => "Completed",
    };
    let names = if name == "guard" {
        &MODULES[..0]
    } else if name == "cancel" {
        &MODULES[..1]
    } else {
        &MODULES[..]
    };
    let modules=names.iter().map(|module|json!({"name":module,"outcome":if name=="cancel"{"Cancelled"}else{"Success"},"spawned":true,"joined":true,"reaped":true,"ownership_lost":false,"exit":if name=="cancel"{Value::Null}else{json!(0)},"after":if name=="cancel"{Value::Null}else{json!({"loaded":"Present(true)","builtin_index":"Absent","available_index":"Present(true)"})}})).collect::<Vec<_>>();
    json!({"schema":1,"event":"result","pass":pass,"pid":pid,"status":status,"shared_effects_possible":name!="guard","container":{"status":if stopped{"NotStarted"}else{"NotRequested"},"layout":null,"mount":null,"init":null,"migration":null,"available":[],"enabled_before":[],"enabled_after":null,"missing_after":[],"attempts":[],"shared_effects_possible":false},"network":{"status":status,"assessment":if name=="guard"{"Unknown"}else{"Observed"},"runtime":"External","family":if name=="guard"{"Unknown(Io)"}else{"Present(NfTables)"},"modules":modules,"ipv6":if stopped{json!([])}else{json!(CONTROLS.map(|path|json!({"path":path,"outcome":if name=="correct"{"AlreadyDisabled"}else{"WriteFailed(Io)"}})))}}})
}
fn records() -> Result<Vec<Value>> {
    let inputs = load(&root().join("tools/node-constrained/inputs.json"))?;
    let pin = &inputs["namespace_launcher"];
    let mut rows = vec![
        json!({"schema":1,"event":"setup","launcher_argv":["/usr/bin/unshare","--mount","--propagation","private"],"unshare_version":pin["version"],"unshare_sha256":pin["sha256"],"candidate_sha256":"a".repeat(64),"external":keeper()}),
        json!({"schema":1,"event":"cli","argv":["--no-container-mode","--disable-ipv6","--container-runtime-endpoint=unix:///tmp/external-runtime/containerd.sock","--print-config"],"exit":0,"stdout":configuration(),"stderr":""}),
    ];
    for (index, name) in CASES.iter().enumerate() {
        let pid = 200 + index as u64;
        let scalar = u64::from(*name == "correct");
        let stopped = matches!(*name, "guard" | "cancel");
        let before = json!({"schema":1,"event":"before","case":name,"external":keeper(),"sentinels":{"/etc/init.d":"init","/etc/cni/net.d":"cni","/tmp/external-runtime":"runtime"},"observer_mnt":"mnt:[10]","root_enabled":"cpu memory\n","observer_mounts":mounts(false),"outside_values":[scalar,scalar,scalar]});
        rows.push(before.clone());
        for phase in if stopped {
            &["READY"][..]
        } else {
            &["READY", "FIRST", "SECOND"][..]
        } {
            let mut row = before.clone();
            row["event"] = json!("observation");
            row["phase"] = json!(phase);
            row["identity"] = live(pid, 20 + index as u64, 'a');
            row["mounts"] = json!(mounts(true));
            row["visible_values"] = json!([scalar, scalar, scalar]);
            rows.push(row);
        }
        if *name == "cancel" {
            rows.push(json!({"schema":1,"event":"double_started","case":name,"module":"br_netfilter","identity":live(300,20+index as u64,'e')}));
        }
        let mut events = vec![
            json!({"schema":1,"event":"READY","pid":pid}),
            consumer_result(name, 1, pid),
        ];
        if !stopped {
            events.extend([
                json!({"schema":1,"event":"FIRST","pid":pid}),
                consumer_result(name, 2, pid),
                json!({"schema":1,"event":"SECOND","pid":pid}),
                json!({"schema":1,"event":"DONE","pid":pid}),
            ]);
        }
        rows.push(json!({"schema":1,"event":"consumer","case":name,"pid":pid,"exit":u64::from(stopped),"events":events,"stderr":""}));
        if *name == "guard" {
            rows.push(json!({"schema":1,"event":"guard_calls","value":"GUARD_DOUBLE\n"}));
        }
        if *name == "cancel" {
            rows.push(json!({"schema":1,"event":"double_absent","pid":300}));
        }
        let mut after = before;
        after["event"] = json!("after");
        after["pid_absent"] = json!(pid);
        rows.push(after);
    }
    rows.push(json!({"schema":1,"event":"complete","keeper_pid_absent":100,"socket_removed":true}));
    Ok(rows)
}
fn encoded(rows: &[Value]) -> Result<String> {
    Ok(rows
        .iter()
        .map(serde_json::to_string)
        .collect::<std::result::Result<Vec<_>, _>>()?
        .join("\n")
        + "\n")
}
fn event<'a>(
    rows: &'a mut [Value],
    name: &str,
    case: Option<&str>,
    phase: Option<&str>,
) -> &'a mut Value {
    rows.iter_mut()
        .find(|r| {
            r["event"] == name
                && case.is_none_or(|c| r["case"] == c)
                && phase.is_none_or(|p| r["phase"] == p)
        })
        .expect("invented event")
}
fn reject(change: impl FnOnce(&mut Vec<Value>)) -> Result<()> {
    let mut rows = records()?;
    change(&mut rows);
    assert!(semantic(&root(), &encoded(&rows)?, &metadata()).is_err());
    Ok(())
}
fn observation(rows: &mut [Value]) -> &mut Value {
    event(rows, "observation", Some("correct"), Some("READY"))
}
fn network<'a>(rows: &'a mut [Value], case: &str) -> &'a mut Value {
    &mut event(rows, "consumer", Some(case), None)["events"][1]["network"]
}

#[test]
fn complete_invented_records() -> Result<()> {
    assert_eq!(
        semantic(&root(), &encoded(&records()?)?, &metadata())?,
        json!({"cases":CASES,"real_passes":4,"read_only":true,"external_preserved":true,"nft_only_kernel_qualified":false})
    );
    Ok(())
}
#[test]
fn json_duplicate_nonfinite_and_float() {
    for raw in [
        r#"{"x":1,"x":2}"#,
        r#"{"x":NaN}"#,
        r#"{"x":Infinity}"#,
        r#"{"x":1.0}"#,
    ] {
        assert!(parse(raw.as_bytes()).is_err());
    }
}
#[test]
fn regular_bounded_nofollow_reads() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let p = dir.path().join("data");
    fs::write(&p, b"12345")?;
    assert!(read(&p, 4).is_err());
    symlink(&p, dir.path().join("link"))?;
    assert!(read(&dir.path().join("link"), 8).is_err());
    assert!(read(dir.path(), 8).is_err());
    Ok(())
}
#[test]
fn fixture_inventory_excludes_publication_only() -> Result<()> {
    let dir = tempfile::tempdir()?;
    for name in [
        ".cargo",
        "crates",
        "third_party",
        "tools/upstream",
        "tools/dev",
        "tools/parity",
        "tools/node-constrained",
        "tools/node-container",
    ] {
        fs::create_dir_all(dir.path().join(name))?;
    }
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "tools/dev/evidence.rs",
    ] {
        fs::write(dir.path().join(name), "original")?;
    }
    let old = inventory(dir.path(), "constrained")?;
    let here = dir.path().join("tools/node-constrained");
    fs::write(here.join("README.md"), "facts")?;
    fs::write(here.join("provenance.json"), "{}")?;
    fs::create_dir(here.join("evidence"))?;
    fs::write(here.join("evidence/raw"), "record")?;
    assert_eq!(inventory(dir.path(), "constrained")?, old);
    fs::write(dir.path().join("tools/dev/evidence.rs"), "changed")?;
    assert_ne!(inventory(dir.path(), "constrained")?, old);
    Ok(())
}
#[test]
fn exact_order_missing_extra_and_duplicate_events() -> Result<()> {
    reject(|r| {
        r.pop();
    })?;
    reject(|r| r.push(r.last().expect("last").clone()))?;
    reject(|r| r.insert(2, r[2].clone()))?;
    reject(|r| r.reverse())
}
#[test]
fn kernel_pid_and_schema_strict_types() -> Result<()> {
    for v in [json!(0), json!(true), json!(1u64 << 32)] {
        reject(|r| observation(r)["identity"]["pid"] = v)?;
    }
    for v in [json!(true), json!(2)] {
        reject(|r| r[0]["schema"] = v)?;
    }
    Ok(())
}
#[test]
fn config_exact_flags_and_semantic_parent() -> Result<()> {
    reject(|r| {
        r[1]["argv"]
            .as_array_mut()
            .expect("argv")
            .push(json!("--container-mode"));
    })?;
    for s in [
        configuration().replace("runtime:", "wrong:"),
        configuration().replace("containerMode: false", "containerMode: true"),
    ] {
        reject(|r| r[1]["stdout"] = json!(s))?;
    }
    reject(|r| r[1]["stderr"] = json!("warning"))
}
#[test]
fn same_live_pid_starttime_exe_namespace() -> Result<()> {
    for (k, v) in [
        ("pid", json!(999)),
        ("starttime", json!(999)),
        ("exe_sha256", json!("f".repeat(64))),
        ("mnt", json!("mnt:[99]")),
    ] {
        reject(|r| event(r, "observation", Some("correct"), Some("SECOND"))["identity"][k] = v)?;
    }
    reject(|r| observation(r)["identity"]["mnt"] = json!("mnt:[10]"))
}
#[test]
fn live_external_socket_configuration_and_identity_preserved() -> Result<()> {
    for (pointer, v) in [
        ("/pid", json!(999)),
        ("/starttime", json!(999)),
        ("/exe_sha256", json!("f".repeat(64))),
        ("/socket/inode", json!(99)),
        ("/configuration/sha256", json!("f".repeat(64))),
    ] {
        reject(|r| {
            *event(r, "observation", Some("needs_write"), Some("SECOND"))["external"]
                .pointer_mut(pointer)
                .expect("external field") = v;
        })?;
    }
    reject(|r| r[0]["external"]["socket"]["mode"] = json!(0o100_600))
}
#[test]
fn readonly_mount_and_descendants_cannot_be_writable() -> Result<()> {
    for value in [
        mounts(false),
        mounts(true) + "4 3 0:2 /sys/net /proc/sys/net rw - proc proc rw\n",
        mounts(true).replace(" rw - ext4", " rw shared:1 - ext4"),
    ] {
        reject(|r| observation(r)["mounts"] = json!(value))?;
    }
    Ok(())
}
#[test]
fn mount_table_complete_acyclic_and_bounded() {
    for raw in [
        mounts(true).trim_end().to_owned(),
        mounts(true) + &mounts(true),
        mounts(true).replace("3 2", "3 3"),
        mounts(true).replace("3 2", "3 99"),
        "x".repeat(1_048_577),
    ] {
        assert!(mount_table(&raw).is_err());
    }
}
#[test]
fn independent_readbacks_and_outside_sentinels() -> Result<()> {
    for (k, v) in [
        ("visible_values", json!([1, 1, 1])),
        ("outside_values", json!([1, 1, 1])),
        ("observer_mnt", json!("mnt:[999]")),
        ("observer_mounts", json!(mounts(true))),
        ("sentinels", json!({})),
    ] {
        reject(|r| event(r, "observation", Some("needs_write"), Some("FIRST"))[k] = v)?;
    }
    Ok(())
}
#[test]
fn readonly_failures_never_report_success_or_shortcircuit_attempts() -> Result<()> {
    reject(|r| network(r, "needs_write")["ipv6"][0]["outcome"] = json!("ObservedDisabled"))?;
    reject(|r| {
        network(r, "needs_write")["ipv6"]
            .as_array_mut()
            .expect("ipv6")
            .pop();
    })?;
    reject(|r| {
        network(r, "needs_write")["modules"]
            .as_array_mut()
            .expect("modules")
            .reverse();
    })?;
    for (k, v) in [("joined", false), ("ownership_lost", true)] {
        reject(|r| network(r, "needs_write")["modules"][0][k] = json!(v))?;
    }
    Ok(())
}
#[test]
fn no_container_mode_effects() -> Result<()> {
    for (k, v) in [
        ("status", json!("Completed")),
        ("shared_effects_possible", json!(true)),
        ("mount", json!({})),
        ("attempts", json!([{}])),
        ("migration", json!({})),
    ] {
        reject(|r| event(r, "consumer", Some("correct"), None)["events"][1]["container"][k] = v)?;
    }
    Ok(())
}
#[test]
fn guard_and_cancellation_stop_later_effects() -> Result<()> {
    reject(|r| network(r, "guard")["modules"] = json!([{"name":"overlay"}]))?;
    reject(|r| {
        network(r, "cancel")["ipv6"] = json!([{"path":CONTROLS[0],"outcome":"AlreadyDisabled"}]);
    })?;
    reject(|r| {
        event(r, "consumer", Some("cancel"), None)["events"]
            .as_array_mut()
            .expect("events")
            .push(json!({"event":"DONE"}));
    })?;
    reject(|r| event(r, "double_absent", None, None)["pid"] = json!(999))
}
#[test]
fn cgroup_controller_state_and_launcher_scope_unchanged() -> Result<()> {
    reject(|r| {
        event(r, "observation", Some("correct"), Some("SECOND"))["identity"]["cgroup"] =
            json!("0::/migrated\n");
    })?;
    reject(|r| {
        event(r, "observation", Some("correct"), Some("SECOND"))["root_enabled"] =
            json!("cpu memory io\n");
    })?;
    for flag in ["--cgroup", "--fork"] {
        reject(|r| {
            r[0]["launcher_argv"]
                .as_array_mut()
                .expect("launcher")
                .insert(2, json!(flag));
        })?;
    }
    Ok(())
}
#[test]
fn boolean_scalar_readbacks_are_not_numeric_kernel_values() -> Result<()> {
    reject(|rows| {
        for row in rows {
            if row["case"] == "correct" && row.get("outside_values").is_some() {
                row["outside_values"] = json!([true, true, true]);
            }
        }
    })
}
#[test]
fn reaping_and_keeper_cleanup_required() -> Result<()> {
    reject(|r| event(r, "after", Some("correct"), None)["pid_absent"] = json!(999))?;
    reject(|r| r.last_mut().expect("complete")["socket_removed"] = json!(false))?;
    reject(|r| r.last_mut().expect("complete")["keeper_pid_absent"] = json!(999))
}

#[test]
#[ignore = "receipt checks disabled"]
fn published_first_approved_build_required() -> Result<()> {
    super::super::docker::verify(
        &root(),
        "constrained",
        &root().join("tools/node-constrained/rust-evidence/first/artifact-build"),
        false,
    )?;
    Ok(())
}
#[test]
#[ignore = "receipt checks disabled"]
fn published_repeat_approved_build_required() -> Result<()> {
    super::super::docker::verify(
        &root(),
        "constrained",
        &root().join("tools/node-constrained/rust-evidence/repeat/artifact-build"),
        false,
    )?;
    Ok(())
}
#[test]
#[ignore = "receipt checks disabled"]
fn published_first_real_guest_required() -> Result<()> {
    super::super::guest::verify(
        &root(),
        "constrained",
        &root().join("tools/node-constrained/rust-evidence/first"),
    )?;
    Ok(())
}
#[test]
#[ignore = "receipt checks disabled"]
fn published_repeat_real_guest_required() -> Result<()> {
    super::super::guest::verify(
        &root(),
        "constrained",
        &root().join("tools/node-constrained/rust-evidence/repeat"),
    )?;
    Ok(())
}
#[test]
#[ignore = "receipt checks disabled"]
fn published_exact_inventory_required() -> Result<()> {
    super::super::guest::published(&root(), "constrained")
}

#[test]
#[ignore = "receipt checks disabled"]
fn historical_observations_preserve_independent_four_case_semantics() -> Result<()> {
    for pass in ["first", "repeat"] {
        let directory = root().join(format!("tools/node-constrained/evidence/{pass}"));
        let raw = String::from_utf8(read(
            &directory.join("constrained-cases.stdout"),
            8 * 1024 * 1024,
        )?)?;
        let mut metadata = load(&directory.join("artifact-build/artifact.json"))?;
        // Historical parser compatibility only: this interpreter identity is not a current builder proof.
        let setup = parse(raw.lines().next().ok_or("historical setup")?.as_bytes())?;
        metadata["files"]["constrained-guest"] = json!({"sha256":setup["external"]["exe_sha256"]});
        assert_eq!(semantic(&root(), &raw, &metadata)?["real_passes"], 4);
    }
    Ok(())
}

#[test]
fn failure_logs_are_bounded_and_missing_logs_are_explicit() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("log");
    fs::write(&path, "x".repeat(65536) + "OMITTED_TAIL")?;
    assert_eq!(
        super::super::constrained_diagnostics::failure_log(&path),
        json!({"text":"x".repeat(65536),"truncated":true,"error":null})
    );
    fs::remove_file(&path)?;
    assert_eq!(
        super::super::constrained_diagnostics::failure_log(&path),
        json!({"text":"","truncated":false,"error":"NotFound"})
    );
    Ok(())
}
#[test]
fn settlement_precedes_failed_log_publication_without_success_conversion() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let out = dir.path().join("out");
    let err = dir.path().join("err");
    for fails in [false, true] {
        let row = super::super::constrained_diagnostics::failure_record(
            "needs_write",
            Some(123),
            "original protocol assertion",
            &out,
            &err,
            || {
                fs::write(&out, "partial READY\n")?;
                fs::write(&err, "consumer assertion\n")?;
                if fails {
                    Err("owned cleanup failed".into())
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(row["event"], "consumer_failure");
        assert_eq!(row["message"], "original protocol assertion");
        assert_eq!(row["stdout"]["text"], "partial READY\n");
        assert_eq!(row["stderr"]["text"], "consumer assertion\n");
        assert_eq!(
            row["cleanup_error"],
            if fails {
                json!("owned cleanup failed")
            } else {
                Value::Null
            }
        );
        reject(|rows| rows.insert(rows.len() - 1, row))?;
        fs::remove_file(&out)?;
        fs::remove_file(&err)?;
    }
    Ok(())
}

#[test]
fn keeper_executable_requires_approved_builder_identity() -> Result<()> {
    let raw = encoded(&records()?)?;
    let mut pin = metadata();
    pin["files"]["constrained-guest"]["sha256"] = json!("e".repeat(64));
    assert!(semantic(&root(), &raw, &pin).is_err());
    pin["files"]
        .as_object_mut()
        .ok_or("files")?
        .remove("constrained-guest");
    assert!(semantic(&root(), &raw, &pin).is_err());
    Ok(())
}
