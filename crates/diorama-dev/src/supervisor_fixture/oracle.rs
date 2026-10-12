//! Source-reviewed expectations, independent of supervisor implementation.
use diorama_dev::{Result, json::parse};
use serde_json::{Value, json};
pub(super) fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}
fn fields(row: &Value, names: &[&str]) -> Result<()> {
    require(
        row.as_object()
            .is_some_and(|o| o.len() == names.len() && names.iter().all(|k| o.contains_key(*k))),
        "record fields",
    )
}
pub(super) fn namespace(raw: &str) -> Result<()> {
    let values = raw
        .lines()
        .filter_map(|line| line.strip_prefix("DIORAMA_NAMESPACE "))
        .map(|text| parse(text.as_bytes()))
        .collect::<Result<Vec<_>>>()?;
    require(values.len() == 1, "one namespace inventory")?;
    let row = &values[0];
    fields(row, &["init", "shell", "helper", "processes"])?;
    let shell = row["shell"].as_u64().ok_or("shell PID")?;
    let helper = row["helper"].as_u64().ok_or("helper PID")?;
    require(
        row["init"] == 1
            && shell > 1
            && helper > 1
            && shell != helper
            && u32::try_from(shell).is_ok()
            && u32::try_from(helper).is_ok(),
        "namespace identity",
    )?;
    let mut expected = vec![1, shell, helper];
    expected.sort_unstable();
    let mut pids = row["processes"]
        .as_array()
        .ok_or("PID array")?
        .iter()
        .map(|v| v.as_u64().ok_or("PID integer"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    pids.sort_unstable();
    require(pids == expected, "namespace residue")
}
pub(super) const PROCESS_CASES: [&str; 13] = [
    "delayed",
    "family",
    "ignore",
    "term-error",
    "early",
    "leader-exits-first",
    "oneshot",
    "probe-error",
    "worker-panic",
    "cancelled",
    "spawn-error",
    "startup-timeout",
    "sentinel-survived-external-stop",
];
pub(super) fn process(raw: &str) -> Result<Value> {
    let rows = raw
        .lines()
        .filter_map(|s| s.strip_prefix("DIORAMA_PROCESS "))
        .map(|s| parse(s.as_bytes()))
        .collect::<Result<Vec<_>>>()?;
    require(rows.len() == PROCESS_CASES.len(), "process case inventory")?;
    for (row, name) in rows.iter().zip(PROCESS_CASES) {
        fields(
            row,
            &[
                "case",
                "spawned",
                "term_attempted",
                "kill_attempted",
                "leader_reaped",
                "thread_joined",
                "complete",
                "exit_code",
                "signal",
                "elapsed_ms",
                "error",
            ],
        )?;
        require(row["case"] == name, "process case order")?;
        for key in [
            "spawned",
            "kill_attempted",
            "leader_reaped",
            "thread_joined",
            "complete",
        ] {
            require(
                row[key] == (name != "spawn-error" || key == "thread_joined"),
                "ownership fact",
            )?;
        }
        let elapsed = row["elapsed_ms"].as_u64().ok_or("elapsed integer")?;
        require(elapsed <= 35000, "35-second observed acceptance gate")?;
        let graceful = [
            "delayed",
            "family",
            "term-error",
            "startup-timeout",
            "sentinel-survived-external-stop",
        ]
        .contains(&name);
        require(
            row["term_attempted"] == (graceful || name == "ignore"),
            "TERM expectation",
        )?;
        let code = if ["early", "leader-exits-first", "term-error"].contains(&name) {
            json!(17)
        } else if graceful || name == "oneshot" {
            json!(0)
        } else {
            Value::Null
        };
        require(row["exit_code"] == code, "exit status")?;
        require(
            row["signal"]
                == if !code.is_null() || name == "spawn-error" {
                    Value::Null
                } else {
                    json!(9)
                },
            "termination signal",
        )?;
        require(
            row["error"]
                == if name == "spawn-error" {
                    json!("process_spawn_failed")
                } else {
                    Value::Null
                },
            "adapter error",
        )?;
        if name == "ignore" {
            require(elapsed >= 29000, "real TERM grace")?;
        } else if name == "startup-timeout" {
            require((1000..=5000).contains(&elapsed), "startup timeout")?;
        } else if !graceful {
            require(elapsed == 0, "untimed case")?;
        }
    }
    Ok(rows.into())
}
const OUTPUT: [(&str, &str, Option<u64>); 13] = [
    ("merged", "Complete", Some(8)),
    ("empty", "Complete", Some(0)),
    ("exact", "Complete", Some(64)),
    ("overflow", "LimitExceeded", Some(64)),
    ("simultaneous", "Complete", Some(2000)),
    ("flood", "LimitExceeded", Some(64)),
    ("missing", "SpawnFailed", Some(0)),
    ("stop", "Cancelled", None),
    ("timeout", "Cancelled", None),
    ("abort", "Cancelled", None),
    ("probe-failure", "Cancelled", None),
    ("descendant", "Complete", Some(6)),
    ("escaped", "IncompleteAfterExit", Some(6)),
];
pub(super) fn output(raw: &str) -> Result<Value> {
    require(
        raw.lines()
            .filter(|s| *s == "DIORAMA_OUTPUT_COMPLETE cases=13")
            .count()
            == 1,
        "output completion",
    )?;
    let pattern = regex::Regex::new(
        r"^DIORAMA_OUTPUT case=([a-z-]+) status=([A-Za-z]+) bytes=(\d+) reaped=(true|false) joined=(true|false) elapsed_ms=(\d+)$",
    )?;
    let mut rows = serde_json::Map::new();
    for line in raw.lines().filter(|s| s.starts_with("DIORAMA_OUTPUT ")) {
        let captures = pattern.captures(line).ok_or("output record shape")?;
        let case = &captures[1];
        let (_, status, size) = OUTPUT
            .iter()
            .find(|x| x.0 == case)
            .ok_or("unknown output case")?;
        let bytes = captures[3].parse::<u64>()?;
        let elapsed = captures[6].parse::<u64>()?;
        require(
            &captures[2] == *status && size.is_none_or(|n| bytes == n),
            "output status/size",
        )?;
        require(
            bytes <= if case == "simultaneous" { 2000 } else { 64 },
            "output byte budget",
        )?;
        require(
            &captures[5] == "true" && (&captures[4] == "true") == (case != "missing"),
            "output owner retired",
        )?;
        require(elapsed < 5000, "output deadline")?;
        require(rows.insert(case.into(),json!({"status":status,"bytes":bytes,"reaped":case!="missing","joined":true,"elapsed_ms":elapsed})).is_none(),"duplicate output case")?;
    }
    require(rows.len() == OUTPUT.len(), "output case inventory")?;
    Ok(rows.into())
}
pub(super) fn signals(raw: &str) -> Result<Value> {
    for summary in [
        "DIORAMA_QUALIFICATION repetitions=20 full_partial_signal_cases=160 worker_failure_cases=20 all_children_reaped=true",
        "DIORAMA_OWNED_QUALIFICATION repetitions=20 combined_cases=61 sentinel_survived=true all_owners_joined=true",
    ] {
        require(
            raw.lines().filter(|s| *s == summary).count() == 1,
            "signal completion",
        )?;
    }
    let rows = raw
        .lines()
        .filter(|s| s.starts_with("DIORAMA_OWNED_SIGNAL "))
        .collect::<Vec<_>>();
    let expected = (0..20)
        .flat_map(|i| ["full", "partial", "fatal"].map(move |mode| (mode, i)))
        .chain(std::iter::once(("force", 20)))
        .collect::<Vec<_>>();
    require(rows.len() == expected.len(), "signal case inventory")?;
    let mut result = Vec::new();
    for (line, (mode, iteration)) in rows.into_iter().zip(expected) {
        let prefix = format!(
            "DIORAMA_OWNED_SIGNAL case={mode} iteration={iteration} leader_reaped=true owner_joined=true dependent_started={} elapsed_ms=",
            ["full", "force"].contains(&mode)
        );
        let text = line.strip_prefix(&prefix).ok_or("signal case fields")?;
        require(
            !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()),
            "elapsed decimal",
        )?;
        let elapsed = text.parse::<u64>()?;
        require(
            elapsed <= 35000 && (mode != "force" || elapsed >= 29000),
            "signal observed acceptance deadline",
        )?;
        result.push(json!({"case":mode,"iteration":iteration,"elapsed_ms":elapsed}));
    }
    Ok(result.into())
}
pub(super) fn normalize(value: &Value) -> Value {
    match value {
        Value::Array(values) => values.iter().map(normalize).collect(),
        Value::Object(values) => values
            .iter()
            .filter(|(k, _)| {
                // Validated cancellation stops retention at a scheduling-dependent prefix.
                // Keep its exact bounded count in raw records, not repeat equality.
                *k != "elapsed_ms"
                    && !(*k == "bytes" && values.get("status") == Some(&json!("Cancelled")))
            })
            .map(|(k, v)| (k.clone(), normalize(v)))
            .collect(),
        _ => value.clone(),
    }
}
