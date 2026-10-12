use super::common::{Result, Value, block, digest, fields, json, parse, require, text};
use std::path::Path;
pub(super) const COMMON: [&str; 8] = [
    "br_netfilter",
    "overlay",
    "xt_comment",
    "xt_conntrack",
    "xt_MASQUERADE",
    "xt_addrtype",
    "xt_multiport",
    "xt_nat",
];
pub(super) const CONTROLS: [&str; 3] = [
    "/proc/sys/net/ipv6/conf/all/disable_ipv6",
    "/proc/sys/net/ipv6/conf/default/disable_ipv6",
    "/proc/sys/net/ipv6/conf/lo/disable_ipv6",
];
pub(super) const CASES: [&str; 9] = [
    "help",
    "version",
    "print",
    "guard_failed",
    "double_failed",
    "double_limits",
    "double_cancel",
    "real_first",
    "real_repeat",
];
pub(super) fn modules(family: &str) -> Result<Vec<&'static str>> {
    let backend: &[&str] = match family {
        "Present(NfTables)" => &[
            "nft_compat",
            "nft_numgen",
            "nft_redir",
            "nft_limit",
            "nft_tproxy",
        ],
        "Present(Legacy)" => &["ip_tables", "iptable_filter", "iptable_nat", "nf_conntrack"],
        _ => return Err("known observed backend required".into()),
    };
    Ok(COMMON.iter().chain(backend).copied().collect())
}
pub(super) fn module_rows(rows: &Value, names: &[&str], observed: bool) -> Result<()> {
    let rows = rows.as_array().ok_or("module array")?;
    require(rows.len() == names.len(), "ordered module inventory")?;
    let observation =
        regex::Regex::new(r"^(?:Present\((?:true|false)\)|Absent|Unknown\([A-Za-z]+\))$")?;
    for (row, name) in rows.iter().zip(names) {
        fields(
            row,
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
        require(row["name"] == *name, "module order")?;
        for key in ["spawned", "joined", "reaped"] {
            require(row[key] == true, "module owner settled")?;
        }
        require(
            row["ownership_lost"] == false
                && (row["exit"].is_null() || row["exit"].as_i64().is_some()),
            "module exit ownership",
        )?;
        if observed {
            fields(
                &row["after"],
                &["loaded", "builtin_index", "available_index"],
            )?;
            for fact in row["after"].as_object().ok_or("after object")?.values() {
                require(
                    observation.is_match(text(fact)?),
                    "typed module observation",
                )?;
            }
        } else {
            require(row["after"].is_null(), "no post-cancel observation")?;
        }
    }
    Ok(())
}
fn outcome(raw: &str) -> Result<Value> {
    let value = parse(raw.as_bytes())?;
    fields(
        &value,
        &[
            "schema",
            "status",
            "assessment",
            "runtime",
            "family",
            "shared_effects_possible",
            "modules",
            "ipv6",
        ],
    )?;
    require(
        value["schema"] == 1
            && value["shared_effects_possible"].is_boolean()
            && value["runtime"] == "External",
        "consumer types/runtime",
    )?;
    require(
        value["modules"].as_array().is_some_and(|a| a.len() <= 13)
            && value["ipv6"].as_array().is_some_and(|a| a.len() <= 3),
        "consumer attempt limits",
    )?;
    Ok(value)
}
pub(super) fn config(raw: &str, container: bool) -> Result<()> {
    let lines = raw.lines().collect::<Vec<_>>();
    for line in ["apiVersion: kubesolo.io/v1alpha1", "kind: Config"] {
        require(
            lines.iter().filter(|s| **s == line).count() == 1,
            "root config field",
        )?;
    }
    let section = regex::Regex::new(r"^([A-Za-z][A-Za-z0-9]*):$")?;
    let mut sections = std::collections::BTreeMap::<String, Vec<&str>>::new();
    let mut current = None;
    for line in &lines {
        if line.chars().next().is_some_and(|c| !c.is_whitespace()) {
            current = section.captures(line).map(|c| c[1].to_owned());
            if let Some(name) = &current {
                require(
                    sections.insert(name.clone(), Vec::new()).is_none(),
                    "duplicate configuration section",
                )?;
            }
        } else if let Some(name) = &current {
            sections.get_mut(name).ok_or("section")?.push(line);
        }
    }
    for (name, line) in [
        (
            "network",
            if container {
                "  disableIPv6: false"
            } else {
                "  disableIPv6: true"
            },
        ),
        (
            "runtime",
            if container {
                "  containerMode: true"
            } else {
                "  containerMode: false"
            },
        ),
        (
            "runtime",
            "  endpoint: unix:///tmp/external-runtime/containerd.sock",
        ),
    ] {
        require(
            lines.iter().filter(|s| **s == line).count() == 1
                && sections
                    .get(name)
                    .is_some_and(|rows| rows.iter().filter(|s| **s == line).count() == 1),
            "effective guest configuration",
        )?;
    }
    require(
        !raw.contains("\"shared_effects_possible\""),
        "configuration exit before preparation",
    )
}
fn cases(raw: &str) -> Result<serde_json::Map<String, Value>> {
    require(raw.len() <= 8 * 1024 * 1024, "guest observation cap")?;
    let pattern = regex::Regex::new(
        r"(?s)CASE_([a-z_]+)_BEGIN\nEXIT ([0-9]+)\nSTDOUT_BEGIN\n(.*?)STDOUT_END\nSTDERR_BEGIN\n(.*?)STDERR_END\nCASE_([a-z_]+)_END\n",
    )?;
    let rows = pattern.captures_iter(raw).collect::<Vec<_>>();
    require(
        rows.len() == CASES.len() && raw.matches("CASE_").count() == rows.len() * 2,
        "complete unique case frames",
    )?;
    let mut results = serde_json::Map::new();
    for ((row, name), code) in rows.iter().zip(CASES).zip([0, 0, 0, 1, 0, 0, 1, 0, 0]) {
        require(
            &row[1] == name && &row[5] == name && row[2].parse::<u8>()? == code,
            "case order and exit",
        )?;
        let stdout = &row[3];
        let stderr = &row[4];
        match name {
            "help" => require(
                stdout.is_empty() && stderr.starts_with("usage: kubesolo"),
                "effect-free help",
            )?,
            "version" => require(
                stdout.is_empty()
                    && parse(stderr.as_bytes())?
                        == json!({"level":"info","message":"kubesolo version","version":"0.1.0"}),
                "version",
            )?,
            "print" => {
                require(stderr.is_empty(), "print stderr")?;
                config(stdout, false)?;
            },
            _ => {
                require(stderr.is_empty(), "consumer stderr")?;
                results.insert(name.into(), outcome(stdout)?);
            },
        }
    }
    Ok(results)
}
pub(super) fn semantic(root: &Path, raw: &str) -> Result<Value> {
    let results = cases(raw)?;
    let guard = &results["guard_failed"];
    require(
        guard["status"] == "GuardStopped"
            && guard["assessment"] == "Unknown"
            && guard["shared_effects_possible"] == false
            && guard["modules"] == json!([])
            && guard["ipv6"] == json!([])
            && text(&guard["family"])?.starts_with("Unknown("),
        "guard suppresses preparation",
    )?;
    let family = text(&results["real_first"]["family"])?;
    let names = modules(family)?;
    preparations(&results, family, &names)?;
    let cancel = &results["double_cancel"];
    require(
        cancel["status"] == "Cancelled"
            && cancel["assessment"] == "Observed"
            && cancel["family"] == family
            && cancel["shared_effects_possible"] == true
            && cancel["ipv6"] == json!([]),
        "cancel latch stops effects",
    )?;
    module_rows(&cancel["modules"], &COMMON[..1], false)?;
    require(
        cancel["modules"][0]["outcome"] == "Cancelled",
        "acknowledged cancellation",
    )?;
    independent_records(root, raw, &names)?;
    Ok(json!({"family":family,"modules":names,"cases":CASES}))
}
fn preparations(
    results: &serde_json::Map<String, Value>,
    family: &str,
    names: &[&str],
) -> Result<()> {
    for name in [
        "double_failed",
        "double_limits",
        "real_first",
        "real_repeat",
    ] {
        let result = &results[name];
        require(
            result["status"] == "Completed"
                && result["assessment"] == "Observed"
                && result["shared_effects_possible"] == true
                && result["family"] == family,
            "settled preparation",
        )?;
        module_rows(&result["modules"], names, true)?;
        let ipv6 = result["ipv6"].as_array().ok_or("IPv6 array")?;
        require(ipv6.len() == 3, "all IPv6 controls")?;
        for (step, path) in ipv6.iter().zip(CONTROLS) {
            fields(step, &["path", "outcome"])?;
            require(
                step["path"] == path
                    && step["outcome"]
                        == if name != "real_repeat" && path == CONTROLS[0] {
                            "ObservedDisabled"
                        } else {
                            "AlreadyDisabled"
                        },
                "fresh per-step readback",
            )?;
        }
        for step in result["modules"].as_array().ok_or("modules")? {
            require(
                ["Success", "Failed", "Deadline", "CaptureFailed"]
                    .contains(&text(&step["outcome"])?),
                "ordinary settled outcome",
            )?;
            if name == "double_failed" {
                require(
                    step["outcome"] == "Failed" && step["exit"] == 17,
                    "failure double",
                )?;
            }
            if name == "double_limits" {
                require(
                    step["outcome"]
                        == match text(&step["name"])? {
                            "br_netfilter" => "Deadline",
                            "overlay" => "CaptureFailed",
                            _ => "Failed",
                        },
                    "execution/output limits",
                )?;
            }
            if step["outcome"] == "Success" {
                require(step["exit"] == 0, "successful exit")?;
            }
        }
    }
    Ok(())
}
fn independent_records(root: &Path, raw: &str, names: &[&str]) -> Result<()> {
    for name in ["double_failed", "double_limits", "double_cancel"] {
        let (body, _) = block(raw, &format!("ATTEMPTS_{name}"))?;
        require(
            body.lines().collect::<Vec<_>>()
                == if name == "double_cancel" {
                    COMMON[..1].to_vec()
                } else {
                    names.to_vec()
                },
            "actual double argv order",
        )?;
    }
    for name in [
        "initial",
        "guard_failed",
        "double_cancel",
        "double_failed",
        "double_limits",
        "real_first",
        "real_repeat",
    ] {
        let value = u8::from(!["initial", "guard_failed", "double_cancel"].contains(&name));
        let expected = format!("SCALARS_{name} all={value} default={value} lo={value} ");
        require(
            raw.lines().filter(|s| *s == expected).count() == 1,
            "independent sysctl readback",
        )?;
    }
    restoration(root, raw)?;
    for marker in [
        "SETUP_BEGIN",
        "SETUP_END",
        "MODULES_BEFORE_BEGIN",
        "MODULES_BEFORE_END",
        "MODULES_AFTER_BEGIN",
        "MODULES_AFTER_END",
        "EXTERNAL_SENTINEL_UNCHANGED",
        "NETWORK_GUEST_COMPLETE",
    ] {
        require(
            raw.lines().filter(|s| *s == marker).count() == 1,
            "complete guest marker",
        )?;
    }
    Ok(())
}
fn restoration(root: &Path, raw: &str) -> Result<()> {
    for name in ["modprobe", "iptables"] {
        for (suffix, pattern) in [
            ("", format!(r"ABSENT|[a-f0-9]{{64}}  /usr/sbin/{name}")),
            ("KIND_", r"ABSENT|REGULAR|LINK [^\r\n]+".into()),
            (
                "RESOLVED_",
                r"[a-f0-9]{64}  /(?:usr/)?s?bin/[a-z_-]+".into(),
            ),
        ] {
            let mut observations = Vec::new();
            for phase in ["ORIGINAL", "RESTORED"] {
                let (value, _) =
                    super::common::scalar(raw, &format!("{phase}_{suffix}{name}"), &pattern)?;
                observations.push(value);
            }
            require(
                observations[0] == observations[1],
                "original command type/link/resolution restored",
            )?;
        }
        let next = if name == "iptables" {
            "double_failed"
        } else {
            "real_first"
        };
        require(
            raw.find(&format!("RESTORED_{name} ")).ok_or("restored")?
                < raw.find(&format!("CASE_{next}_BEGIN")).ok_or("next case")?,
            "restore before genuine execution",
        )?;
        let expected = format!(
            "DOUBLE_{name} {}  /usr/sbin/{name}",
            digest(&root.join(format!("tools/node-network/{name}-double.sh")))?
        );
        require(
            raw.lines().filter(|s| *s == expected).count() == 1,
            "bound double bytes",
        )?;
    }
    Ok(())
}
