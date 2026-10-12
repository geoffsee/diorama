//! Independent constrained-host observations; does not call preparation APIs.
use super::common::{Result, Value, fields, hex, json, load, parse, require, text};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
pub(super) const CASES: [&str; 4] = ["correct", "needs_write", "guard", "cancel"];
pub(super) const CONTROLS: [&str; 3] = [
    "/proc/sys/net/ipv6/conf/all/disable_ipv6",
    "/proc/sys/net/ipv6/conf/default/disable_ipv6",
    "/proc/sys/net/ipv6/conf/lo/disable_ipv6",
];
const MODULES: [&str; 13] = [
    "br_netfilter",
    "overlay",
    "xt_comment",
    "xt_conntrack",
    "xt_MASQUERADE",
    "xt_addrtype",
    "xt_multiport",
    "xt_nat",
    "nft_compat",
    "nft_numgen",
    "nft_redir",
    "nft_limit",
    "nft_tproxy",
];
const OUTSIDE: [&str; 6] = [
    "external",
    "sentinels",
    "observer_mnt",
    "root_enabled",
    "observer_mounts",
    "outside_values",
];
#[derive(Debug)]
pub(super) struct Mount {
    parent: u64,
    pub point: String,
    pub fs: String,
    pub private: bool,
    pub readonly: bool,
}
fn uint(v: &Value, min: u64, max: u64) -> Result<u64> {
    v.as_u64()
        .filter(|n| *n >= min && *n <= max)
        .ok_or_else(|| "integer bound".into())
}
fn decimal(s: &str) -> Result<u64> {
    require(
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
        "decimal field",
    )?;
    Ok(s.parse()?)
}
fn mount_path(s: &str) -> Result<String> {
    require(
        s.starts_with('/') && !s.contains('\0'),
        "absolute mount path",
    )?;
    let mut out = String::new();
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'\\' {
            let escape = [bytes.next(), bytes.next(), bytes.next()];
            out.push(match escape {
                [Some(b'0'), Some(b'4'), Some(b'0')] => ' ',
                [Some(b'0'), Some(b'1'), Some(b'1')] => '\t',
                [Some(b'0'), Some(b'1'), Some(b'2')] => '\n',
                [Some(b'1'), Some(b'3'), Some(b'4')] => '\\',
                _ => return Err("kernel mount escape".into()),
            });
        } else {
            out.push(char::from(b));
        }
    }
    Ok(out)
}
pub(super) fn mount_table(raw: &str) -> Result<BTreeMap<u64, Mount>> {
    require(
        raw.len() <= 1024 * 1024 && raw.ends_with('\n') && raw.is_ascii(),
        "complete bounded mount table",
    )?;
    let mut rows = BTreeMap::new();
    for line in raw.lines() {
        let parts = line.split(' ').collect::<Vec<_>>();
        require(
            line.len() <= 16384
                && (10..=128).contains(&parts.len())
                && parts.iter().all(|s| !s.is_empty()),
            "mount fields",
        )?;
        let separators = parts
            .iter()
            .enumerate()
            .filter(|(_, s)| **s == "-")
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        require(separators.len() == 1, "mount separator")?;
        let sep = separators[0];
        require(sep >= 6 && parts.len() == sep + 4, "mount shape")?;
        let id = decimal(parts[0])?;
        require(id > 0, "mount id")?;
        let parent = decimal(parts[1])?;
        mount_path(parts[3])?;
        let optional = &parts[6..sep];
        let shared = optional
            .iter()
            .filter_map(|s| s.strip_prefix("shared:"))
            .collect::<Vec<_>>();
        require(shared.len() <= 1, "shared field")?;
        for s in shared {
            require(!s.starts_with('0') && decimal(s)? > 0, "shared identity")?;
        }
        require(
            rows.insert(
                id,
                Mount {
                    parent,
                    point: mount_path(parts[4])?,
                    fs: parts[sep + 1].into(),
                    private: !optional.iter().any(|s| {
                        *s == "unbindable"
                            || s.starts_with("shared:")
                            || s.starts_with("master:")
                            || s.starts_with("propagate_from:")
                    }),
                    readonly: parts[5].split(',').any(|s| s == "ro"),
                },
            )
            .is_none(),
            "unique mount id",
        )?;
    }
    require(!rows.is_empty() && rows.len() <= 4096, "mount record bound")?;
    let roots = rows
        .iter()
        .filter(|(_, m)| m.point == "/")
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    require(roots.len() == 1, "one namespace root")?;
    for id in rows.keys() {
        let mut seen = BTreeSet::new();
        let mut current = *id;
        while current != roots[0] {
            require(
                seen.len() < 256 && seen.insert(current),
                "acyclic bounded mount tree",
            )?;
            current = rows.get(&current).ok_or("incomplete mount tree")?.parent;
        }
    }
    Ok(rows)
}
fn identity(v: &Value) -> Result<()> {
    fields(v, &["pid", "starttime", "exe_sha256", "mnt", "cgroup"])?;
    uint(&v["pid"], 1, u64::from(u32::MAX))?;
    uint(&v["starttime"], 1, u64::MAX)?;
    require(hex(text(&v["exe_sha256"])?, 64), "executable digest")?;
    let cgroup = text(&v["cgroup"])?;
    require(
        cgroup.len() < 8192
            && cgroup.starts_with("0::/")
            && cgroup.ends_with('\n')
            && cgroup.lines().count() == 1,
        "v2 membership",
    )?;
    let ns = text(&v["mnt"])?
        .strip_prefix("mnt:[")
        .and_then(|s| s.strip_suffix(']'))
        .ok_or("mount namespace")?;
    decimal(ns)?;
    Ok(())
}
fn file_identity(v: &Value) -> Result<u64> {
    fields(v, &["device", "inode", "mode", "uid", "gid"])?;
    for k in ["device", "inode", "mode", "uid", "gid"] {
        uint(&v[k], u64::from(k == "inode"), u64::MAX)?;
    }
    uint(&v["mode"], 0, u64::MAX)
}
fn external(v: &Value) -> Result<()> {
    fields(
        v,
        &[
            "pid",
            "starttime",
            "exe_sha256",
            "mnt",
            "cgroup",
            "socket",
            "configuration",
        ],
    )?;
    let i = ["pid", "starttime", "exe_sha256", "mnt", "cgroup"]
        .into_iter()
        .map(|k| (k.into(), v[k].clone()))
        .collect::<serde_json::Map<_, _>>();
    identity(&i.into())?;
    require(
        file_identity(&v["socket"])? & 0o170_000 == 0o140_000,
        "Unix socket identity",
    )?;
    fields(&v["configuration"], &["identity", "sha256"])?;
    require(
        file_identity(&v["configuration"]["identity"])? & 0o170_000 == 0o100_000
            && hex(text(&v["configuration"]["sha256"])?, 64),
        "regular config identity",
    )
}
fn config(raw: &str) -> Result<()> {
    let lines = raw.lines().collect::<Vec<_>>();
    for required in ["apiVersion: kubesolo.io/v1alpha1", "kind: Config"] {
        require(
            lines.iter().filter(|s| **s == required).count() == 1,
            "config identity",
        )?;
    }
    let mut sections = BTreeMap::<&str, Vec<&str>>::new();
    let mut current = None;
    for line in &lines {
        if !line.is_empty() && !line.starts_with(char::is_whitespace) {
            current = line.strip_suffix(':').filter(|s| {
                s.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
                    && s.bytes().all(|b| b.is_ascii_alphanumeric())
            });
            if let Some(section) = current {
                require(
                    sections.insert(section, vec![]).is_none(),
                    "duplicate config section",
                )?;
            }
        } else if let Some(section) = current {
            sections
                .get_mut(section)
                .ok_or("config section")?
                .push(line);
        }
    }
    for (section, line) in [
        ("network", "  disableIPv6: true"),
        ("runtime", "  containerMode: false"),
        (
            "runtime",
            "  endpoint: unix:///tmp/external-runtime/containerd.sock",
        ),
    ] {
        require(
            lines.iter().filter(|s| **s == line).count() == 1
                && sections
                    .get(section)
                    .is_some_and(|s| s.iter().filter(|v| **v == line).count() == 1),
            "effective constrained flag",
        )?;
    }
    Ok(())
}
fn result(v: &Value, pid: &Value, case: &str, pass: u64) -> Result<()> {
    fields(
        v,
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
        v["schema"].as_u64() == Some(1)
            && v["event"] == "result"
            && v["pass"].as_u64() == Some(pass)
            && &v["pid"] == pid,
        "typed result identity",
    )?;
    let stopped = matches!(case, "guard" | "cancel");
    let status = match case {
        "guard" => "GuardStopped",
        "cancel" => "Cancelled",
        _ => "Completed",
    };
    require(
        v["status"] == status && v["shared_effects_possible"] == json!(case != "guard"),
        "preparation disposition",
    )?;
    require(
        v["container"]
            == json!({"status":if stopped{"NotStarted"}else{"NotRequested"},"layout":null,"mount":null,"init":null,"migration":null,"available":[],"enabled_before":[],"enabled_after":null,"missing_after":[],"attempts":[],"shared_effects_possible":false}),
        "no container effects",
    )?;
    let net = &v["network"];
    fields(
        net,
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
        net["status"] == status
            && net["runtime"] == "External"
            && net["assessment"]
                == if case == "guard" {
                    "Unknown"
                } else {
                    "Observed"
                },
        "network disposition",
    )?;
    if case == "guard" {
        return require(
            net["modules"] == json!([])
                && net["ipv6"] == json!([])
                && net["family"] == "Unknown(Io)",
            "guard suppresses later effects",
        );
    }
    require(net["family"] == "Present(NfTables)", "pinned nft userspace")?;
    verify_modules(net, case)?;
    if case == "cancel" {
        return require(net["ipv6"] == json!([]), "no post cancellation sysctls");
    }
    require(net["ipv6"]==json!(CONTROLS.map(|path|json!({"path":path,"outcome":if case=="correct"{"AlreadyDisabled"}else{"WriteFailed(Io)"}}))),"three exact readonly outcomes")
}
fn verify_modules(net: &Value, case: &str) -> Result<()> {
    let modules = net["modules"].as_array().ok_or("module array")?;
    let names = if case == "cancel" {
        &MODULES[..1]
    } else {
        &MODULES[..]
    };
    require(modules.len() == names.len(), "module attempt count")?;
    for (step, name) in modules.iter().zip(names) {
        fields(
            step,
            &[
                "name",
                "outcome",
                "spawned",
                "joined",
                "reaped",
                "ownership_lost",
                "exit",
                "after",
            ],
        )?;
        require(
            step["name"] == *name
                && ["spawned", "joined", "reaped"]
                    .iter()
                    .all(|k| step[k] == true)
                && step["ownership_lost"] == false,
            "ordered settled module",
        )?;
        if case == "cancel" {
            require(
                step["outcome"] == "Cancelled" && step["after"].is_null(),
                "cancelled module",
            )?;
        } else {
            require(
                step["outcome"] == "Success" && step["exit"].as_i64() == Some(0),
                "real module success",
            )?;
            fields(
                &step["after"],
                &["loaded", "builtin_index", "available_index"],
            )?;
            for value in step["after"]
                .as_object()
                .ok_or("module readbacks")?
                .values()
            {
                let s = text(value)?;
                require(
                    matches!(s, "Present(true)" | "Present(false)" | "Absent")
                        || s.strip_prefix("Unknown(")
                            .and_then(|s| s.strip_suffix(')'))
                            .is_some_and(|s| {
                                !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphabetic())
                            }),
                    "typed module observations",
                )?;
            }
        }
    }
    Ok(())
}
struct Records {
    rows: Vec<Value>,
    cursor: usize,
}
impl Records {
    fn take(&mut self, event: &str, case: Option<&str>) -> Result<Value> {
        let row = self.rows.get(self.cursor).ok_or("missing event")?.clone();
        self.cursor += 1;
        require(
            row["schema"].as_u64() == Some(1)
                && row["event"] == event
                && case.is_none_or(|c| row["case"] == c),
            "ordered typed event",
        )?;
        Ok(row)
    }
}
fn outside(row: &Value, before: &Value) -> Result<()> {
    for key in OUTSIDE {
        require(row[key] == before[key], "outside resources unchanged")?;
    }
    Ok(())
}
fn observe(
    row: &Value,
    before: &Value,
    keeper: &Value,
    candidate: &Value,
    value: u64,
    phase: &str,
) -> Result<()> {
    fields(
        row,
        &[
            "schema",
            "event",
            "case",
            "phase",
            "identity",
            "external",
            "sentinels",
            "observer_mnt",
            "root_enabled",
            "observer_mounts",
            "mounts",
            "visible_values",
            "outside_values",
        ],
    )?;
    require(row["phase"] == phase, "observation phase")?;
    identity(&row["identity"])?;
    require(
        &row["identity"]["exe_sha256"] == candidate
            && row["identity"]["mnt"] != row["observer_mnt"]
            && row["identity"]["pid"] != keeper["pid"]
            && row["identity"]["cgroup"] == keeper["cgroup"],
        "live isolated candidate",
    )?;
    outside(row, before)?;
    require(
        row["visible_values"] == json!([value, value, value]),
        "independent scalar readback",
    )?;
    let mounts = mount_table(text(&row["mounts"])?)?;
    require(
        mounts.values().all(|m| m.private),
        "recursively private mounts",
    )?;
    let sys = mounts
        .values()
        .filter(|m| m.point == "/proc/sys")
        .collect::<Vec<_>>();
    require(
        sys.len() == 1 && sys[0].fs == "proc",
        "actual proc sys bind mount",
    )?;
    require(
        mounts
            .values()
            .filter(|m| m.point == "/proc/sys" || m.point.starts_with("/proc/sys/"))
            .all(|m| m.readonly),
        "readonly sysctl descendants",
    )
}
fn case(records: &mut Records, name: &str, keeper: &Value, candidate: &Value) -> Result<()> {
    let value = u64::from(name == "correct");
    let before = records.take("before", Some(name))?;
    fields(
        &before,
        &[
            "schema",
            "event",
            "case",
            "external",
            "sentinels",
            "observer_mnt",
            "root_enabled",
            "observer_mounts",
            "outside_values",
        ],
    )?;
    require(
        &before["external"] == keeper && before["outside_values"] == json!([value, value, value]),
        "initial external and scalar state",
    )?;
    fields(
        &before["sentinels"],
        &["/etc/init.d", "/etc/cni/net.d", "/tmp/external-runtime"],
    )?;
    mount_table(text(&before["observer_mounts"])?)?;
    let phases: &[&str] = if matches!(name, "guard" | "cancel") {
        &["READY"]
    } else {
        &["READY", "FIRST", "SECOND"]
    };
    let mut observed = Vec::new();
    for phase in phases {
        let row = records.take("observation", Some(name))?;
        observe(&row, &before, keeper, candidate, value, phase)?;
        if let Some(first) = observed.first() {
            let first: &Value = first;
            require(
                row["identity"] == first["identity"] && row["mounts"] == first["mounts"],
                "same live candidate and topology",
            )?;
        }
        observed.push(row);
    }
    let pid = &observed[0]["identity"]["pid"];
    let mut double = Value::Null;
    if name == "cancel" {
        let row = records.take("double_started", Some(name))?;
        fields(&row, &["schema", "event", "case", "module", "identity"])?;
        identity(&row["identity"])?;
        require(
            row["module"] == "br_netfilter"
                && &row["identity"]["pid"] != pid
                && row["identity"]["pid"] != keeper["pid"]
                && row["identity"]["mnt"] == observed[0]["identity"]["mnt"],
            "owned module double context",
        )?;
        double = row["identity"]["pid"].clone();
    }
    verify_consumer(records, name, pid, &double)?;
    let after = records.take("after", Some(name))?;
    fields(
        &after,
        &[
            "schema",
            "event",
            "case",
            "external",
            "sentinels",
            "observer_mnt",
            "root_enabled",
            "observer_mounts",
            "outside_values",
            "pid_absent",
        ],
    )?;
    require(&after["pid_absent"] == pid, "candidate reaped")?;
    outside(&after, &before)
}
fn verify_consumer(records: &mut Records, name: &str, pid: &Value, double: &Value) -> Result<()> {
    let consumer = records.take("consumer", Some(name))?;
    fields(
        &consumer,
        &["schema", "event", "case", "pid", "exit", "events", "stderr"],
    )?;
    let stopped = matches!(name, "guard" | "cancel");
    require(
        &consumer["pid"] == pid
            && consumer["stderr"] == ""
            && consumer["exit"].as_i64() == Some(i64::from(stopped)),
        "consumer receipt",
    )?;
    let events = consumer["events"].as_array().ok_or("consumer events")?;
    require(
        events.len() == if stopped { 2 } else { 6 },
        "exact consumer events",
    )?;
    require(
        events[0] == json!({"schema":1,"event":"READY","pid":pid}),
        "READY barrier",
    )?;
    result(&events[1], pid, name, 1)?;
    if !stopped {
        require(
            events[2] == json!({"schema":1,"event":"FIRST","pid":pid})
                && events[4] == json!({"schema":1,"event":"SECOND","pid":pid})
                && events[5] == json!({"schema":1,"event":"DONE","pid":pid}),
            "repeat barriers",
        )?;
        result(&events[3], pid, name, 2)?;
    } else if name == "guard" {
        require(
            records.take("guard_calls", None)?
                == json!({"schema":1,"event":"guard_calls","value":"GUARD_DOUBLE\n"}),
            "one failed guard",
        )?;
    } else {
        require(
            records.take("double_absent", None)?
                == json!({"schema":1,"event":"double_absent","pid":double}),
            "owned double absent",
        )?;
    }
    Ok(())
}
pub(super) fn semantic(root: &Path, raw: &str, metadata: &Value) -> Result<Value> {
    require(
        raw.len() <= 8 * 1024 * 1024 && raw.ends_with('\n'),
        "complete bounded guest records",
    )?;
    let mut records = Records {
        rows: raw
            .lines()
            .map(|line| parse(line.as_bytes()))
            .collect::<Result<_>>()?,
        cursor: 0,
    };
    let setup = records.take("setup", None)?;
    fields(
        &setup,
        &[
            "schema",
            "event",
            "launcher_argv",
            "unshare_version",
            "unshare_sha256",
            "candidate_sha256",
            "external",
        ],
    )?;
    let inputs = load(&root.join("tools/node-constrained/inputs.json"))?;
    let pin = &inputs["namespace_launcher"];
    require(
        pin["program"] == "/usr/bin/unshare"
            && pin["argv"] == json!(["--mount", "--propagation", "private"])
            && ["fork", "pid_namespace", "cgroup_namespace"]
                .iter()
                .all(|k| pin[k] == false),
        "explicit namespace policy",
    )?;
    require(
        setup["launcher_argv"]
            == json!(["/usr/bin/unshare", "--mount", "--propagation", "private"])
            && setup["unshare_version"] == pin["version"]
            && setup["unshare_sha256"] == pin["sha256"],
        "actual pinned namespace tool",
    )?;
    let candidate = &metadata["files"]["prepare_node_host"]["sha256"];
    require(
        setup["candidate_sha256"] == *candidate && hex(text(candidate)?, 64),
        "approved candidate",
    )?;
    let keeper = &setup["external"];
    external(keeper)?;
    require(
        keeper["exe_sha256"] == metadata["files"]["constrained-guest"]["sha256"],
        "approved keeper executable",
    )?;
    let cli = records.take("cli", None)?;
    fields(
        &cli,
        &["schema", "event", "argv", "exit", "stdout", "stderr"],
    )?;
    require(
        cli["argv"]
            == json!([
                "--no-container-mode",
                "--disable-ipv6",
                "--container-runtime-endpoint=unix:///tmp/external-runtime/containerd.sock",
                "--print-config"
            ])
            && cli["exit"].as_i64() == Some(0)
            && cli["stderr"] == "",
        "effect free guest flag grammar",
    )?;
    config(text(&cli["stdout"])?)?;
    for name in CASES {
        case(&mut records, name, keeper, candidate)?;
    }
    require(
        records.take("complete", None)?
            == json!({"schema":1,"event":"complete","keeper_pid_absent":keeper["pid"],"socket_removed":true})
            && records.cursor == records.rows.len(),
        "complete owned keeper cleanup and exact chronology",
    )?;
    Ok(
        json!({"cases":CASES,"real_passes":4,"read_only":true,"external_preserved":true,"nft_only_kernel_qualified":false}),
    )
}
#[cfg(test)]
#[path = "constrained_tests.rs"]
mod tests;
