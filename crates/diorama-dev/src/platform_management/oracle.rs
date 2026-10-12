use super::{load, require};
use crate::{Result, json};
use serde_json::{Value, json as value};
use std::path::Path;

pub fn record(raw: &[u8], prefix: &str) -> Result<Value> {
    let text = std::str::from_utf8(raw)?;
    let rows = text
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .collect::<Vec<_>>();
    require(rows.len() == 1, "exact executable record count")?;
    json::parse(rows[0].as_bytes())
}
pub fn classify(row: &Value) -> Result<Value> {
    let fields = row.as_object().ok_or("record schema")?;
    require(fields.len() == 4, "record schema")?;
    let name = row["name"].as_str().ok_or("record name")?;
    let out = row["stdout"].as_str().ok_or("record stdout")?;
    let err = row["stderr"].as_str().ok_or("record stderr")?;
    let code = row["exit"].as_i64().ok_or("record exit")?;
    let mut result = value!({"name":name});
    let outcome = match code {
        1 => {
            require(
                out.is_empty() && err.starts_with("error: "),
                "error channel",
            )?;
            if err.contains("unknown flag:") || err.contains("unknown shorthand flag:") {
                "unknown_flag"
            } else if err.contains("strconv.ParseBool:") {
                "invalid_boolean"
            } else if err.contains("unknown command ") {
                "unknown_command"
            } else {
                return Err("unrecognized parser error".into());
            }
        },
        0 if !err.is_empty() => {
            require(
                out.is_empty() && err.starts_with("Unknown help topic "),
                "unknown help channel",
            )?;
            "unknown_help"
        },
        0 if out.starts_with("CHECK ") => {
            let captures = regex::Regex::new(r"\ACHECK (true|false) (true|false)\n\z")?
                .captures(out)
                .ok_or("effect marker")?;
            result["install"] = (&captures[1] == "true").into();
            result["pprof"] = (&captures[2] == "true").into();
            "check"
        },
        0 if out == "kubesoloctl dev (commit unknown, built unknown)\n" => "version",
        0 if out.starts_with("Validates that this host meets all requirements for KubeSolo.") => {
            require(
                [
                    "  kubesoloctl check [flags]",
                    "--install-prereqs",
                    "--pprof-server",
                ]
                .iter()
                .all(|s| out.contains(s)),
                "check help",
            )?;
            "help_check"
        },
        0 if out.starts_with("Print kubesoloctl version information") => "help_version",
        0 if out.starts_with("kubesoloctl manages the lifecycle") => "help_root",
        _ => return Err("unrecognized command result".into()),
    };
    result["outcome"] = outcome.into();
    Ok(result)
}
pub fn go(family: &str, fixture: &Path, raw: &[u8]) -> Result<Value> {
    let actual = record(raw, "DIORAMA_CAPTURE ")?;
    if family == "platform" {
        let bytes = crate::read_bounded(&fixture.join("expected.tsv"), 1024 * 1024)?;
        let rows: Vec<_> = std::str::from_utf8(&bytes)?.lines().collect();
        require(actual == value!(rows), "independent platform records")?;
    } else {
        let classified = actual
            .as_array()
            .ok_or("management records")?
            .iter()
            .map(classify)
            .collect::<Result<Vec<_>>>()?;
        let expected = load(&fixture.join("expected.json"))?;
        require(
            value!(classified) == expected,
            "independent parser expectations",
        )?;
        let cases = load(&fixture.join("cases.json"))?;
        let names = |v: &Value| -> Result<Vec<Value>> {
            Ok(v.as_array()
                .ok_or("case inventory")?
                .iter()
                .map(|row| row["name"].clone())
                .collect())
        };
        require(
            names(&cases)? == names(&expected)?,
            "case identity and order",
        )?;
    }
    Ok(actual)
}
pub fn linux(family: &str, raw: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(raw)?;
    if family == "platform" {
        for count in [7, 1, 8, 6, 4] {
            require(
                text.matches(&format!("test result: ok. {count} passed;"))
                    .count()
                    == 1,
                "Linux completion",
            )?;
        }
        require(
            text.contains(
                "real_discovery_preserves_custom_paths_and_does_not_create_or_rewrite_them ... ok",
            ),
            "discovery completion",
        )?;
        let re = regex::Regex::new(
            r"(?m)^[0-9a-f]{64}  /out/(discovery|diorama_platform|preflight|constrained|preflight_probe)-[0-9a-f]+$",
        )?;
        let mut names = re
            .captures_iter(text)
            .map(|c| c[1].to_owned())
            .collect::<Vec<_>>();
        names.sort();
        require(
            names
                == [
                    "constrained",
                    "discovery",
                    "preflight",
                    "preflight_probe",
                    "diorama_platform",
                ],
            "exact binary inventory",
        )?;
    } else {
        require(
            text.matches("test result: ok. 7 passed;").count() == 1,
            "Rust test completion",
        )?;
        let re = regex::Regex::new(r"(?m)^[0-9a-f]{64}  /out/(dioramactl|check-tests)$")?;
        let mut names = re
            .captures_iter(text)
            .map(|c| c[1].to_owned())
            .collect::<Vec<_>>();
        names.sort();
        require(names == ["check-tests", "dioramactl"], "binary identity")?;
        management_record(&record(raw, "DIORAMA_CHECK ")?)?;
    }
    Ok(())
}
pub fn management_record(record: &Value) -> Result<()> {
    require(
        record.as_object().is_some_and(|v| v.len() == 4),
        "executable schema",
    )?;
    for field in ["listener_survived", "ports_released", "files_unchanged"] {
        require(record[field] == true, field)?;
    }
    let rows = record["cases"].as_array().ok_or("case inventory")?;
    let names = [
        "help",
        "version",
        "root_pass",
        "nonroot",
        "preparation",
        "pprof_off",
        "pprof_conflict",
        "repeat_0",
        "repeat_1",
    ];
    let exits = [0, 0, 0, 1, 0, 0, 1, 0, 0];
    require(rows.len() == names.len(), "case count")?;
    for ((row, name), exit) in rows.iter().zip(names).zip(exits) {
        require(
            row.as_object().is_some_and(|r| r.len() == 4)
                && row["name"] == name
                && row["exit"].as_i64() == Some(exit),
            "case identity and exit",
        )?;
        let out = row["stdout"].as_str().ok_or("stdout type")?;
        let err = row["stderr"].as_str().ok_or("stderr type")?;
        if matches!(name, "help" | "version") {
            require(out.contains("dioramactl") && err.is_empty(), "early output")?;
        } else {
            require(out.is_empty(), "check stdout")?;
            if exit == 0 {
                require(
                    err.contains("All 7 checks passed") && err.contains("ports are not reserved"),
                    "qualified success",
                )?;
            } else {
                require(!err.contains("All 7 checks passed"), "false success")?;
            }
        }
    }
    require(
        rows[3]["stderr"]
            .as_str()
            .is_some_and(|s| s.contains("root privileges required")),
        "root failure",
    )?;
    require(
        rows[6]["stderr"]
            .as_str()
            .is_some_and(|s| s.contains("TCP port 6060")),
        "pprof conflict",
    )
}
