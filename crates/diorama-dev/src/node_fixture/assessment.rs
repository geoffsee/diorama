use super::common::{Result, Value, hex, parse, require};
pub(super) const EXPECTED: [(&str, &str); 11] = [
    ("nft", "None"),
    ("legacy", "None"),
    ("empty", "None"),
    ("invalid-utf8", "None"),
    ("nonzero", "Some(Command)"),
    ("missing", "Some(Command)"),
    ("denied", "Some(Command)"),
    ("overflow", "Some(Capture)"),
    ("deadline", "Some(Deadline)"),
    ("cancel", "Some(Cancelled)"),
    ("held", "Some(Capture)"),
];
pub(super) fn records(raw: &str) -> Result<(Value, Value)> {
    require(raw.len() < 1024 * 1024, "assessment log bound")?;
    let lines = raw.lines().collect::<Vec<_>>();
    for marker in [
        "DIORAMA_NODE_PROBE_COMPLETE cases=11 external_sentinel_preserved=true",
        "DIORAMA_NODE_ASSESSMENT external=true real_probe=true injected_host_facts=true",
    ] {
        require(
            lines.iter().filter(|s| **s == marker).count() == 1,
            "assessment completion",
        )?;
    }
    require(
        lines
            .iter()
            .filter(|s| s.starts_with("test result: ok. 9 passed; 0 failed;"))
            .count()
            == 1
            && lines
                .iter()
                .filter(|s| s.starts_with("test result: ok. 1 passed; 0 failed;"))
                .count()
                == 2,
        "policy/probe/configured consumer tests",
    )?;
    let mut hashes = serde_json::Map::new();
    for name in [
        "host_preflight",
        "iptables_probe",
        "assess_host",
        "node-fixture",
    ] {
        let suffix = format!("  /out/{name}");
        let rows = lines
            .iter()
            .filter_map(|s| s.strip_suffix(&suffix))
            .collect::<Vec<_>>();
        require(
            rows.len() == 1 && hex(rows[0], 64),
            "assessment binary inventory",
        )?;
        hashes.insert(name.into(), rows[0].into());
    }
    let mut rows = serde_json::Map::new();
    let pattern = regex::Regex::new(
        r"^DIORAMA_NODE_PROBE case=([a-z0-9-]+) result=(None|Some\([A-Za-z]+\)) joined=true reaped=(true|false) elapsed_ms=(\d+)$",
    )?;
    for line in &lines {
        if !line.starts_with("DIORAMA_NODE_PROBE ") {
            continue;
        }
        let record = pattern.captures(line).ok_or("probe shape")?;
        let name = &record[1];
        let (_, expected) = EXPECTED
            .iter()
            .find(|(n, _)| *n == name)
            .ok_or("probe identity")?;
        require(
            &record[2] == *expected
                && (&record[3] == "true") != ["missing", "denied"].contains(&name),
            "probe semantics",
        )?;
        let elapsed = record[4].parse::<u64>()?;
        require(
            elapsed < 5000 && (name != "deadline" || elapsed >= 2000),
            "probe deadline",
        )?;
        require(rows.insert(name.into(),serde_json::json!({"status":expected,"reaped":&record[3]=="true","elapsed_ms":elapsed})).is_none(),"duplicate probe case")?;
    }
    require(rows.len() == EXPECTED.len(), "complete probes")?;
    let expected =
        [("help", 0), ("version", 0), ("print", 0), ("blocked", 1)].map(|(name, code)| {
            format!("DIORAMA_NODE_CONSUMER case={name} exit={code} probe_absent=true")
        });
    let actual = lines
        .iter()
        .filter(|s| s.starts_with("DIORAMA_NODE_CONSUMER "))
        .copied()
        .collect::<Vec<_>>();
    require(
        actual.len() == 4 && expected.iter().all(|s| actual.contains(&s.as_str())),
        "consumer effect boundary",
    )?;
    namespace(raw)?;
    for line in lines {
        require(
            !line.starts_with("DIORAMA_")
                || [
                    "DIORAMA_NODE_PROBE ",
                    "DIORAMA_NODE_PROBE_COMPLETE ",
                    "DIORAMA_NODE_ASSESSMENT ",
                    "DIORAMA_NODE_CONSUMER ",
                    "DIORAMA_NAMESPACE ",
                ]
                .iter()
                .any(|p| line.starts_with(p)),
            "unexpected record",
        )?;
    }
    Ok((rows.into(), hashes.into()))
}
pub(super) fn namespace(raw: &str) -> Result<()> {
    let rows = raw
        .lines()
        .filter_map(|s| s.strip_prefix("DIORAMA_NAMESPACE "))
        .collect::<Vec<_>>();
    require(rows.len() == 1, "one namespace inventory")?;
    let value = parse(rows[0].as_bytes())?;
    super::common::fields(&value, &["init", "shell", "helper", "processes"])?;
    let mut identities = vec![
        value["init"].as_u64().ok_or("init PID")?,
        value["shell"].as_u64().ok_or("shell PID")?,
        value["helper"].as_u64().ok_or("helper PID")?,
    ];
    require(
        identities[0] == 1
            && identities[1] > 1
            && identities[2] > 1
            && identities[1] != identities[2]
            && identities.iter().all(|pid| u32::try_from(*pid).is_ok()),
        "namespace roles",
    )?;
    let mut pids = value["processes"]
        .as_array()
        .ok_or("PID array")?
        .iter()
        .map(|v| v.as_u64().ok_or("PID integer"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    pids.sort_unstable();
    identities.sort_unstable();
    require(pids == identities, "namespace cleanup")
}
