use super::{
    build,
    common::{
        Result, Value, block, fields, json, load, parse, read, require, scalar, sha256, text,
    },
    network,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Mount {
    parent: u64,
    device: String,
    root: String,
    point: String,
    shared: bool,
    private: bool,
    filesystem: String,
}
fn mount_path(raw: &str) -> Result<String> {
    require(
        raw.starts_with('/') && !raw.contains('\0'),
        "absolute mount path",
    )?;
    let mut result = String::new();
    let mut rest = raw;
    while let Some((prefix, tail)) = rest.split_once('\\') {
        result.push_str(prefix);
        let escape = tail.get(..3).ok_or("kernel mount escape")?;
        result.push(match escape {
            "040" => ' ',
            "011" => '\t',
            "012" => '\n',
            "134" => '\\',
            _ => return Err("kernel mount escape".into()),
        });
        rest = &tail[3..];
    }
    result.push_str(rest);
    Ok(result)
}
pub(super) fn mounts(raw: &str) -> Result<BTreeMap<u64, Mount>> {
    require(
        raw.len() <= 1024 * 1024 && raw.ends_with('\n') && raw.is_ascii(),
        "complete bounded mount table",
    )?;
    let mut rows = BTreeMap::new();
    for line in raw.lines() {
        let fields = line.split(' ').collect::<Vec<_>>();
        require(
            line.len() <= 16384
                && (10..=128).contains(&fields.len())
                && fields.iter().all(|f| !f.is_empty()),
            "mount fields",
        )?;
        let separators = fields
            .iter()
            .enumerate()
            .filter(|(_, s)| **s == "-")
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        require(separators.len() == 1, "mount separator")?;
        let sep = separators[0];
        require(sep >= 6 && fields.len() == sep + 4, "mount shape")?;
        for field in &fields[..2] {
            require(
                field.bytes().all(|c| c.is_ascii_digit()),
                "mount decimal identity",
            )?;
        }
        let identity = fields[0].parse::<u64>()?;
        require(
            identity > 0 && !rows.contains_key(&identity),
            "unique mount identity",
        )?;
        let optional = &fields[6..sep];
        let shared = optional
            .iter()
            .filter(|s| s.starts_with("shared:"))
            .collect::<Vec<_>>();
        require(
            shared.len() <= 1
                && shared.iter().all(|s| {
                    s.strip_prefix("shared:").is_some_and(|s| {
                        !s.starts_with('0')
                            && !s.is_empty()
                            && s.bytes().all(|c| c.is_ascii_digit())
                    })
                }),
            "shared propagation field",
        )?;
        rows.insert(
            identity,
            Mount {
                parent: fields[1].parse()?,
                device: fields[2].into(),
                root: mount_path(fields[3])?,
                point: mount_path(fields[4])?,
                shared: !shared.is_empty(),
                private: !optional.contains(&"unbindable")
                    && !optional.iter().any(|s| {
                        ["shared:", "master:", "propagate_from:"]
                            .iter()
                            .any(|p| s.starts_with(p))
                    }),
                filesystem: fields[sep + 1].into(),
            },
        );
    }
    require(
        !rows.is_empty() && rows.len() <= 4096,
        "mount record budget",
    )?;
    let roots = rows
        .iter()
        .filter(|(_, r)| r.point == "/")
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    require(roots.len() == 1, "one namespace root")?;
    for id in rows.keys() {
        let mut seen = BTreeSet::new();
        let mut current = *id;
        while current != roots[0] {
            require(
                seen.len() < 256 && seen.insert(current),
                "bounded acyclic mount tree",
            )?;
            current = rows.get(&current).ok_or("complete mount tree")?.parent;
        }
    }
    Ok(rows)
}
fn topology(rows: &BTreeMap<u64, Mount>) -> BTreeMap<u64, Mount> {
    rows.iter()
        .map(|(k, v)| {
            let mut row = v.clone();
            row.shared = false;
            row.private = false;
            (*k, row)
        })
        .collect()
}
pub(super) fn names(raw: &str) -> Result<BTreeSet<String>> {
    require(raw.len() <= 4096, "controller bytes")?;
    let tokens = raw.split_whitespace().collect::<Vec<_>>();
    let syntax = regex::Regex::new(r"^[a-z][a-z0-9_]{0,63}$")?;
    let values = tokens
        .iter()
        .map(|s| (*s).to_owned())
        .collect::<BTreeSet<_>>();
    require(
        tokens.len() <= 32
            && values.len() == tokens.len()
            && values.iter().all(|s| syntax.is_match(s)),
        "controller set",
    )?;
    Ok(values)
}
pub(super) fn pids(raw: &str) -> Result<Vec<u32>> {
    require(raw.len() <= 65536, "PID bytes")?;
    let tokens = raw.split_whitespace().collect::<Vec<_>>();
    require(tokens.len() <= 4096, "PID count")?;
    tokens
        .into_iter()
        .map(|s| {
            require(
                !s.starts_with('0')
                    && !s.is_empty()
                    && s.len() <= 10
                    && s.bytes().all(|c| c.is_ascii_digit()),
                "PID syntax",
            )?;
            Ok(s.parse::<u32>()?)
        })
        .collect()
}
struct Observation {
    values: BTreeMap<String, String>,
    pid: u32,
    starttime: u64,
    mounts: BTreeMap<u64, Mount>,
    available: BTreeSet<String>,
}
fn observation_fields(body: &str) -> Result<(BTreeMap<String, String>, String)> {
    let mut remaining = body.to_owned();
    let mut values = BTreeMap::new();
    for (name, pattern) in [
        ("PID", r"[1-9][0-9]*"),
        ("EXE", r"[a-f0-9]{64}  /proc/[1-9][0-9]*/exe"),
        ("MNT_NS", r"mnt:\[[0-9]+\]"),
        ("CGROUP_NS", r"cgroup:\[[0-9]+\]"),
        ("OBSERVER_MNT_NS", r"mnt:\[[0-9]+\]"),
        ("OBSERVER_CGROUP_NS", r"cgroup:\[[0-9]+\]"),
        ("GLOBAL_ROOT_ID", r"[0-9]+:[0-9]+"),
        ("ROOT_ID", r"[0-9]+:[0-9]+"),
        ("VISIBLE_ROOT_ID", r"[0-9]+:[0-9]+"),
    ] {
        let (value, rest) = scalar(&remaining, name, pattern)?;
        values.insert(name.to_owned(), value);
        remaining = rest;
    }
    for name in [
        "STAT",
        "CANDIDATE_MOUNTS",
        "OBSERVER_MOUNTS",
        "PROCESS_CGROUP",
        "ROOT_TYPE",
        "ROOT_MEMBERS",
        "AVAILABLE",
        "ROOT_ENABLED",
        "PARENT_ENABLED",
        "SIBLING",
        "EXTERNAL",
    ] {
        let (value, rest) = block(&remaining, name)?;
        values.insert(name.into(), value.into());
        remaining = rest;
    }
    Ok((values, remaining))
}
fn observation(body: &str, phase: &str, artifact: &str) -> Result<Observation> {
    let (mut values, mut remaining) = observation_fields(body)?;
    let pid = values["PID"].parse::<u32>()?;
    require(
        values["EXE"] == format!("{artifact}  /proc/{pid}/exe"),
        "independent executable",
    )?;
    let stat = values["STAT"].trim_end_matches('\n');
    let (prefix, tail) = stat.rsplit_once(") ").ok_or("process stat")?;
    require(
        prefix.starts_with(&format!("{pid} (")),
        "process stat identity",
    )?;
    let parts = tail.split_whitespace().collect::<Vec<_>>();
    require(
        parts.len() >= 20
            && !["Z", "X"].contains(&parts[0])
            && parts[19].bytes().all(|c| c.is_ascii_digit()),
        "live process starttime",
    )?;
    let starttime = parts[19].parse::<u64>()?;
    require(starttime > 0, "positive starttime")?;
    require(
        values["MNT_NS"] != values["OBSERVER_MNT_NS"]
            && values["CGROUP_NS"] != values["OBSERVER_CGROUP_NS"],
        "isolated namespaces",
    )?;
    require(
        values["ROOT_ID"] == values["VISIBLE_ROOT_ID"]
            && values["ROOT_ID"] != values["GLOBAL_ROOT_ID"],
        "anchored delegated nonroot bind",
    )?;
    require(values["ROOT_TYPE"] == "domain\n", "domain root")?;
    let available = names(&values["AVAILABLE"])?;
    require(
        ["cpuset", "cpu", "io", "memory", "pids"]
            .iter()
            .all(|s| available.contains(*s)),
        "required controllers",
    )?;
    require(
        available.is_subset(&names(&values["PARENT_ENABLED"])?),
        "parent delegation",
    )?;
    let table = mounts(&values["CANDIDATE_MOUNTS"])?;
    mounts(&values["OBSERVER_MOUNTS"])?;
    require(
        table
            .values()
            .any(|r| r.point == "/sys/fs/cgroup" && r.filesystem == "cgroup2"),
        "visible cgroup2",
    )?;
    let expected = if phase.ends_with("READY") {
        require(table.values().all(|r| r.private), "private before effects")?;
        require(
            pids(&values["ROOT_MEMBERS"])? == [pid]
                && names(&values["ROOT_ENABLED"])?.is_empty()
                && remaining == "INIT_ABSENT\n",
            "initial root membership",
        )?;
        format!(
            "/diorama-container-{}",
            phase.split('_').next().ok_or("phase")?
        )
    } else {
        for name in ["INIT_MEMBERS", "INIT_TYPE", "INIT_ENABLED"] {
            let (value, rest) = block(&remaining, name)?;
            values.insert(name.into(), value.into());
            remaining = rest;
        }
        require(remaining.is_empty(), "observation field inventory")?;
        require(
            pids(&values["ROOT_MEMBERS"])?.is_empty() && pids(&values["INIT_MEMBERS"])? == [pid],
            "actual root to init migration",
        )?;
        require(
            values["INIT_TYPE"] == "domain\n" && names(&values["INIT_ENABLED"])?.is_empty(),
            "init no child delegation",
        )?;
        require(
            names(&values["ROOT_ENABLED"])? == available && table.values().all(|r| r.shared),
            "positive delegation and recursive shared mounts",
        )?;
        "/diorama-container-real/init".into()
    };
    require(
        values["PROCESS_CGROUP"] == format!("0::{expected}\n"),
        "outside process membership",
    )?;
    footprint(&values)?;
    Ok(Observation {
        values,
        pid,
        starttime,
        mounts: table,
        available,
    })
}
fn footprint(values: &BTreeMap<String, String>) -> Result<()> {
    let sibling = values["SIBLING"].lines().collect::<Vec<_>>();
    require(sibling.len() == 4, "sibling inventory")?;
    for (line, name) in sibling.iter().zip([
        "cgroup.type",
        "cgroup.procs",
        "cgroup.subtree_control",
        "pids.max",
    ]) {
        require(
            line.strip_suffix(&format!("  /sys/fs/cgroup/diorama-container-sibling/{name}"))
                .is_some_and(|s| super::common::hex(s, 64)),
            "sibling binding",
        )?;
    }
    require(
        values["EXTERNAL"].lines().count() == 2,
        "external inventory",
    )?;
    for (name, bytes) in [
        ("config.toml", "host-owned configuration sentinel\n"),
        ("state", "host-owned state sentinel\n"),
    ] {
        let expected = format!("{}  /tmp/external-runtime/{name}", sha256(bytes.as_bytes()));
        require(
            values["EXTERNAL"]
                .lines()
                .filter(|s| *s == expected)
                .count()
                == 1,
            "external sentinel",
        )?;
    }
    Ok(())
}
fn consumer(body: &str, scenario: &str) -> Result<(u32, Vec<Value>)> {
    let (code, rest) = scalar(body, "EXIT", "[01]")?;
    let (out, rest) = block(&rest, "STDOUT")?;
    let output = out.to_owned();
    let (err, remaining) = block(&rest, "STDERR")?;
    require(
        remaining.is_empty() && err.is_empty(),
        "consumer framing/stderr",
    )?;
    let (pid, out) = scalar(&output, "LAUNCH_PID", "[1-9][0-9]*")?;
    let pid = pid.parse::<u32>()?;
    let (private, out) = block(&out, "PRIVATE_BEFORE_BIND")?;
    require(
        mounts(private)?.values().all(|r| r.private),
        "recursive private before bind",
    )?;
    let events = out
        .lines()
        .map(|s| parse(s.as_bytes()))
        .collect::<Result<Vec<_>>>()?;
    for event in &events {
        require(event.is_object() && event["schema"] == 1, "event schema")?;
    }
    let expected = if scenario == "signal" {
        vec!["READY", "protocol_failure"]
    } else {
        vec!["READY", "result", "FIRST", "result", "SECOND", "DONE"]
    };
    require(
        events
            .iter()
            .map(|e| text(&e["event"]))
            .collect::<Result<Vec<_>>>()?
            == expected,
        "ordered protocol events",
    )?;
    for event in &events {
        if ["READY", "FIRST", "SECOND", "DONE"].contains(&text(&event["event"])?) {
            require(
                *event == json!({"schema":1,"event":event["event"],"pid":pid}),
                "barrier fields/PID",
            )?;
        }
    }
    if scenario == "signal" {
        require(
            code == "1"
                && events[1]
                    == json!({"schema":1,"event":"protocol_failure","phase":"READY","reason":"cancelled","preparation_started":false,"shared_effects_possible":false}),
            "pre-G signal suppresses effects",
        )?;
    } else {
        require(code == "0", "real consumer exit")?;
    }
    Ok((pid, events))
}
fn result(value: &Value, pass: u8, observed: &Observation) -> Result<String> {
    fields(
        value,
        &[
            "schema",
            "event",
            "pass",
            "pid",
            "status",
            "shared_effects_possible",
            "network",
            "container",
        ],
    )?;
    require(
        value["pass"] == pass
            && value["pid"] == observed.pid
            && value["status"] == "Completed"
            && value["shared_effects_possible"] == true,
        "completed pass/PID effects",
    )?;
    let family = network_result(&value["network"])?;
    container_result(&value["container"], pass, observed)?;
    Ok(family)
}
fn network_result(network: &Value) -> Result<String> {
    fields(
        network,
        &[
            "status",
            "assessment",
            "runtime",
            "family",
            "modules",
            "ipv6",
        ],
    )?;
    require(
        network["status"] == "Completed"
            && network["assessment"] == "Observed"
            && network["runtime"] == "External"
            && network["ipv6"] == json!([]),
        "fresh network/external ownership",
    )?;
    let family = text(&network["family"])?;
    network::module_rows(&network["modules"], &network::modules(family)?, true)?;
    for row in network["modules"].as_array().ok_or("modules")? {
        require(
            row["outcome"] == "Success" && row["exit"] == 0,
            "real command successful, not loaded claim",
        )?;
    }
    Ok(family.into())
}
fn container_result(container: &Value, pass: u8, observed: &Observation) -> Result<()> {
    fields(
        container,
        &[
            "status",
            "layout",
            "mount",
            "init",
            "migration",
            "available",
            "enabled_before",
            "enabled_after",
            "missing_after",
            "attempts",
            "shared_effects_possible",
        ],
    )?;
    require(
        container["status"] == "Completed"
            && container["layout"] == "V2"
            && container["shared_effects_possible"] == true,
        "container completion",
    )?;
    for (name, attempted) in [("mount", true), ("init", pass == 1), ("migration", true)] {
        require(
            container[name] == json!({"attempted":attempted,"result":"Ok(())"}),
            "actual preparation operation",
        )?;
    }
    let set = |row: &Value| -> Result<BTreeSet<String>> {
        let array = row.as_array().ok_or("controller array")?;
        let values = array
            .iter()
            .map(|v| text(v).map(str::to_owned))
            .collect::<Result<BTreeSet<_>>>()?;
        require(values.len() == array.len(), "unique controller array")?;
        Ok(values)
    };
    require(
        set(&container["available"])? == observed.available,
        "available readback",
    )?;
    require(
        set(&container["enabled_before"])?
            == if pass == 1 {
                BTreeSet::new()
            } else {
                observed.available.clone()
            },
        "initial enabled report",
    )?;
    fields(&container["enabled_after"], &["names"])?;
    require(
        set(&container["enabled_after"]["names"])? == observed.available,
        "enabled report observer equality",
    )?;
    require(
        container["missing_after"] == json!([])
            && container["attempts"]
                == json!([{"controllers":container["available"],"mutation":{"attempted":true,"result":"Ok(())"}}]),
        "single successful bulk request",
    )?;
    Ok(())
}
fn setup_protocols(root: &Path, raw: &str) -> Result<String> {
    require(raw.len() <= 8 * 1024 * 1024, "guest output limit")?;
    let (setup, rest) = block(raw, "SETUP")?;
    let pin = &load(&root.join("tools/node-container/inputs.json"))?["namespace_launcher"];
    require(
        setup
            .lines()
            .filter(|s| *s == text(&pin["version"]).unwrap_or(""))
            .count()
            == 1,
        "pinned namespace launcher version",
    )?;
    let expected = format!(
        "UNSHARE_SHA256 {}  {}",
        text(&pin["sha256"])?,
        text(&pin["program"])?
    );
    require(
        setup.lines().filter(|s| *s == expected).count() == 1,
        "namespace launcher bytes",
    )?;
    let mut remaining = rest;
    for name in ["help", "version", "print"] {
        let (body, rest) = block(&remaining, &format!("CLI_{name}"))?;
        let (_, body) = scalar(body, "EXIT", "0")?;
        let (out, body) = block(&body, "STDOUT")?;
        let output = out.to_owned();
        let (err, tail) = block(&body, "STDERR")?;
        require(tail.is_empty(), "CLI framing")?;
        match name {
            "help" => require(
                output.is_empty()
                    && err.as_bytes() == read(&root.join("crates/diorama-kube/src/help.txt"), 65536)?,
                "complete effect-free help",
            )?,
            "version" => require(
                output.is_empty()
                    && parse(err.as_bytes())?
                        == json!({"level":"info","message":"kubesolo version","version":"0.1.0"}),
                "version",
            )?,
            _ => {
                require(err.is_empty(), "print stderr")?;
                network::config(&output, true)?;
            },
        }
        remaining = rest;
    }
    let (tests, rest) = block(&remaining, "INJECTED_TESTS")?;
    build::verify_tests(root, tests)?;
    remaining = rest;
    for (mode, reason) in [("eof", "eof"), ("wrong", "wrong_byte")] {
        let (body, rest) = block(&remaining, &format!("PROTOCOL_{mode}"))?;
        let (_, body) = scalar(body, "EXIT", "1")?;
        let (err, body) = block(&body, "STDERR")?;
        require(err.is_empty(), "protocol stderr")?;
        let events = body
            .lines()
            .map(|s| parse(s.as_bytes()))
            .collect::<Result<Vec<_>>>()?;
        require(events.len() == 2, "protocol events")?;
        fields(&events[0], &["schema", "event", "pid"])?;
        require(
            events[0]["schema"] == 1
                && events[0]["event"] == "READY"
                && events[0]["pid"].as_u64().is_some_and(|p| p > 0),
            "protocol READY",
        )?;
        require(
            events[1]
                == json!({"schema":1,"event":"protocol_failure","phase":"READY","reason":reason,"preparation_started":false,"shared_effects_possible":false}),
            "protocol failure no effects",
        )?;
        remaining = rest;
    }
    Ok(remaining)
}
pub(super) fn semantic(root: &Path, raw: &str, metadata: &Value) -> Result<Value> {
    let mut remaining = setup_protocols(root, raw)?;
    let mut observations = BTreeMap::new();
    for phase in ["signal_READY", "real_READY", "real_FIRST", "real_SECOND"] {
        let (body, rest) = block(&remaining, &format!("OBS_{phase}"))?;
        observations.insert(
            phase,
            observation(
                body,
                phase,
                text(&metadata["files"]["prepare_node_host"]["sha256"])?,
            )?,
        );
        remaining = rest;
    }
    let mut outputs = BTreeMap::new();
    for scenario in ["signal", "real"] {
        let (body, rest) = block(&remaining, &format!("CONSUMER_{scenario}"))?;
        let output = consumer(body, scenario)?;
        require(
            output.0 == observations[format!("{scenario}_READY").as_str()].pid,
            "launcher/candidate PID",
        )?;
        outputs.insert(scenario, output);
        remaining = rest;
    }
    let reference = &observations["signal_READY"];
    for observed in observations.values() {
        for key in [
            "OBSERVER_MNT_NS",
            "OBSERVER_CGROUP_NS",
            "OBSERVER_MOUNTS",
            "PARENT_ENABLED",
            "SIBLING",
            "EXTERNAL",
            "GLOBAL_ROOT_ID",
        ] {
            require(
                observed.values[key] == reference.values[key],
                "outside scope unchanged",
            )?;
        }
    }
    let real = &observations["real_READY"];
    let mut family = String::new();
    for (pass, phase) in [(1, "real_FIRST"), (2, "real_SECOND")] {
        let observed = &observations[phase];
        require(
            observed.pid == real.pid && observed.starttime == real.starttime,
            "same live process",
        )?;
        for key in ["EXE", "MNT_NS", "CGROUP_NS", "ROOT_ID", "VISIBLE_ROOT_ID"] {
            require(
                observed.values[key] == real.values[key],
                "same anchored namespace/root",
            )?;
        }
        require(
            topology(&observed.mounts) == topology(&real.mounts),
            "same anchored mount topology",
        )?;
        family = result(
            &outputs["real"].1[2 * usize::from(pass) - 1],
            pass,
            observed,
        )?;
    }
    require(
        remaining
            == format!(
                "SIGNAL_NO_PREPARATION\nPID_ABSENT {}\nREAL_PROCESS_EXITED\nPID_ABSENT {}\nCONTAINER_GUEST_COMPLETE\n",
                reference.pid, real.pid
            ),
        "complete final cleanup",
    )?;
    let mut prior = 0;
    for marker in [
        "SETUP_BEGIN",
        "CLI_help_BEGIN",
        "CLI_version_BEGIN",
        "CLI_print_BEGIN",
        "INJECTED_TESTS_BEGIN",
        "PROTOCOL_eof_BEGIN",
        "PROTOCOL_wrong_BEGIN",
        "OBS_signal_READY_BEGIN",
        "CONSUMER_signal_BEGIN",
        "OBS_real_READY_BEGIN",
        "OBS_real_FIRST_BEGIN",
        "OBS_real_SECOND_BEGIN",
        "CONSUMER_real_BEGIN",
    ] {
        let position = raw.find(marker).ok_or("chronology marker")?;
        require(position >= prior, "event chronology")?;
        prior = position;
    }
    Ok(json!({"passes":2,"controllers":real.available,"family":family,"injected_tests":38}))
}
