use super::{
    common::{Result, Value, block, hex, load, parse, read, require},
    network,
};
use std::{collections::BTreeSet, path::Path};
pub(super) const NETWORK_TESTS: [&str; 14] = [
    "complete_bounded_scalars_reject_prefixes_and_binary_data",
    "owner_launch_failure_has_no_child_and_is_settled",
    "cancellation_before_start_never_observes_or_mutates_network",
    "unjoined_module_owner_stops_all_further_effects",
    "fresh_root_backend_and_ipv4_unknown_guards_prevent_effects",
    "cancellation_after_ipv6_write_preserves_possible_effects_without_readback",
    "cancellation_between_ipv6_read_and_write_prevents_write",
    "cancellation_after_failed_write_retains_possible_effects",
    "ipv6_only_zero_writes_and_success_requires_readback",
    "write_failures_continue_to_all_controls_and_retain_possible_effects",
    "requested_unknown_ipv6_is_deferred_only_by_preparation",
    "fixed_backend_lists_and_external_runtime_keep_network_effects",
    "settled_module_failures_warn_and_continue_without_loaded_claim",
    "cancellation_during_module_waits_for_stop_acknowledgement",
];
pub(super) fn binaries(family: &str) -> Result<Vec<&'static str>> {
    match family {
        "network" => Ok(vec!["prepare_host_network", "host_network"]),
        "container" | "constrained" => {
            let mut names = vec![
                "prepare_node_host",
                "diorama",
                "host_preparation",
                "host_network",
            ];
            if family == "constrained" {
                names.push("constrained-guest");
            }
            Ok(names)
        },
        _ => Err("node build family".into()),
    }
}
fn tests(raw: &str, names: &BTreeSet<String>) -> Result<()> {
    let actual = raw
        .lines()
        .filter(|s| s.starts_with("test ") && !s.starts_with("test result:"))
        .collect::<Vec<_>>();
    let expected = names
        .iter()
        .map(|n| format!("test {n} ... ok"))
        .collect::<BTreeSet<_>>();
    require(
        actual.len() == names.len()
            && actual
                .into_iter()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
                == expected,
        "exact successful test inventory",
    )?;
    require(
        raw.matches(&format!(
            "test result: ok. {} passed; 0 failed; 0 ignored;",
            names.len()
        ))
        .count()
            == 1,
        "complete test summary",
    )
}
pub(super) fn builder_hashes(raw: &str, family: &str, nonce: &str) -> Result<Value> {
    require(hex(nonce, 32), "builder nonce")?;
    let prefix = regex::Regex::new(r"^#\d+ \d+(?:\.\d+)? (.*)$")?;
    let normalized = raw
        .lines()
        .filter_map(|line| prefix.captures(line).map(|c| c[1].to_owned()))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    if matches!(family, "container" | "constrained") {
        let (policy, _) = block(&normalized, "POLICY_TESTS")?;
        tests(
            policy,
            &[
                "tests::cancelled_result_publishes_once_and_is_terminal",
                "tests::uncertain_cleanup_is_quiet_terminal_even_when_observer_is_settled",
            ]
            .map(str::to_owned)
            .into_iter()
            .collect(),
        )?;
    }
    let begin = format!("DIORAMA_BUILD_BIND_BEGIN {nonce}\n");
    let end = format!("DIORAMA_BUILD_BIND_END {nonce}\n");
    require(
        normalized.matches(&begin).count() == 1 && normalized.matches(&end).count() == 1,
        "unique nonce frame",
    )?;
    let body = normalized
        .split_once(&begin)
        .ok_or("builder begin")?
        .1
        .split_once(&end)
        .ok_or("builder end")?
        .0;
    let names = if family == "assessment" {
        vec![
            "host_preflight",
            "iptables_probe",
            "assess_host",
            "node-fixture",
        ]
    } else if family == "probes" {
        vec!["diorama_platform", "preflight_probe"]
    } else {
        binaries(family)?
    };
    let rows = body.lines().collect::<Vec<_>>();
    require(rows.len() == names.len(), "builder binary inventory")?;
    let mut hashes = serde_json::Map::new();
    for (row, name) in rows.iter().zip(names) {
        let hash = if family == "probes" {
            let (hash, suffix) = row
                .split_once(&format!("  /out/{name}-"))
                .ok_or("ordered probe builder binary")?;
            require(
                !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_hexdigit()),
                "probe binary suffix",
            )?;
            hash
        } else {
            row.strip_suffix(&format!("  /out/{name}"))
                .ok_or("ordered builder binary")?
        };
        require(hex(hash, 64), "builder digest")?;
        hashes.insert(name.into(), hash.into());
    }
    Ok(hashes.into())
}
pub(super) fn verify_tests(root: &Path, raw: &str) -> Result<()> {
    let expected = load(&root.join("tools/node-container/test-inventory.json"))?;
    for (binary, names) in expected.as_object().ok_or("test inventory")? {
        let (body, _) = block(raw, &format!("TEST_{binary}"))?;
        let names = names
            .as_array()
            .ok_or("test array")?
            .iter()
            .map(|s| s.as_str().map(str::to_owned).ok_or("test name"))
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        tests(body, &names)?;
    }
    Ok(())
}
pub(super) fn verify_run(root: &Path, family: &str, raw: &str) -> Result<Value> {
    if family == "network" {
        tests(raw, &NETWORK_TESTS.map(str::to_owned).into_iter().collect())?;
    } else {
        verify_tests(root, raw)?;
    }
    for name in ["version", "help", "print-config"] {
        let (body, _) = block(raw, &format!("CLI_{name}"))?;
        match name {
            "version" => require(
                parse(body.as_bytes())?
                    == serde_json::json!({"level":"info","message":"kubesolo version","version":"0.1.0"}),
                "version output",
            )?,
            "help" => require(
                body.as_bytes() == read(&root.join("crates/diorama-kube/src/help.txt"), 65536)?,
                "complete help",
            )?,
            _ => network::config(body, matches!(family, "container" | "constrained"))?,
        }
    }
    let mut hashes = serde_json::Map::new();
    for name in binaries(family)? {
        let ending = format!("  /out/{name}");
        let rows = raw
            .lines()
            .filter_map(|s| s.strip_suffix(&ending))
            .collect::<Vec<_>>();
        require(
            rows.len() == 1 && hex(rows[0], 64),
            "actual runtime binary hash",
        )?;
        hashes.insert(name.into(), rows[0].into());
    }
    Ok(hashes.into())
}
