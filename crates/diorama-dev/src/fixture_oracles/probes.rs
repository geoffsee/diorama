//! Independent filesystem and socket probe qualification records.
use crate::Result;
use serde_json::Value;
fn equal(actual: &Value, expected: &Value) -> Result<()> {
    if crate::json::changes(actual, expected).is_empty() {
        Ok(())
    } else {
        Err("probe observations differ".into())
    }
}
use serde_json::json;

const FILE_CASES: [&str; 17] = [
    "missing_version",
    "no_candidates",
    "exact",
    "exact.xz",
    "exact.zst",
    "exact.gz",
    "glob_broken_symlink",
    "glob_non_utf8_name",
    "not_recursive",
    "entry_limit",
    "byte_limit",
    "non_utf8_version",
    "unsafe_release",
    "permission_denied",
    "fifo_nonblocking",
    "rc_service_exact",
    "injected_ipv6_unsupported_real_ipv4",
];

pub fn records(raw: &[u8]) -> Result<(Value, Value)> {
    let binaries = verify(raw)?;
    Ok((
        json!({"files": FILE_CASES, "ports": [2379, 6443, 10443, 6060], "families": ["ipv4", "ipv6"], "pprof_disabled": "unprobed", "invocations": 4}),
        binaries,
    ))
}

/// Validate all ordered observable assertions and return the two executable identities.
pub fn verify(raw: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(raw)?;
    let files = text
        .lines()
        .filter(|line| line.starts_with("DIORAMA_PREFLIGHT_FILES "))
        .collect::<Vec<_>>();
    let expected = FILE_CASES.map(|name| format!("DIORAMA_PREFLIGHT_FILES {name} pass"));
    equal(&json!(files), &json!(expected))?;
    let mut ports = vec!["DIORAMA_PREFLIGHT_PORTS free_all available".to_owned()];
    for port in [2379, 6443, 10443, 6060] {
        if port == 6060 {
            ports.push("DIORAMA_PREFLIGHT_PORTS pprof_disabled unprobed".into());
        }
        for family in ["ipv4", "ipv6"] {
            ports.push(format!(
                "DIORAMA_PREFLIGHT_PORTS {family}_{port} conflict_then_rebind"
            ));
        }
    }
    equal(
        &json!(
            text.lines()
                .filter(|line| line.starts_with("DIORAMA_PREFLIGHT_PORTS "))
                .collect::<Vec<_>>()
        ),
        &json!(ports),
    )?;
    let completion = regex::Regex::new(
        r"^test result: ok\. ([1-9][0-9]*) passed; 0 failed; [0-9]+ ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s$",
    )?;
    let summaries = text
        .lines()
        .filter(|line| line.starts_with("test result:"))
        .collect::<Vec<_>>();
    if summaries.len() != 4 || summaries.iter().any(|line| !completion.is_match(line)) {
        return Err("all four nonempty successful test invocations required".into());
    }
    let pattern =
        regex::Regex::new(r"^([a-f0-9]{64})  /out/(diorama_platform|preflight_probe)-[a-f0-9]+$")?;
    let mut binaries = serde_json::Map::new();
    for line in text.lines() {
        if let Some(captures) = pattern.captures(line)
            && binaries
                .insert(captures[2].into(), json!(&captures[1]))
                .is_some()
        {
            return Err("duplicate probe executable".into());
        }
    }
    if binaries.len() != 2 {
        return Err("both probe executables required".into());
    }
    Ok(Value::Object(binaries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    fn directory() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../parity/fixtures/preflight-probes")
    }
    #[test]
    #[ignore = "receipt checks disabled"]
    fn historical_repeated_assertions_and_artifacts_retain_identity() -> Result<()> {
        let directory = directory();
        let first = crate::read_bounded(&directory.join("evidence/run0.log"), 1024 * 1024)?;
        let repeat = crate::read_bounded(&directory.join("evidence/run1.log"), 1024 * 1024)?;
        equal(&verify(&first)?, &verify(&repeat)?)?;
        let provenance = crate::json::parse(&crate::read_bounded(
            &directory.join("provenance.json"),
            1024 * 1024,
        )?)?;
        let files = provenance["files"]
            .as_object()
            .ok_or("historical artifact inventory")?;
        equal(
            &json!(files.keys().collect::<Vec<_>>()),
            &json!([
                "build.log",
                "receipt.json",
                "run0.log",
                "run1.log",
                "source-hashes.json"
            ]),
        )?;
        for (name, digest) in files {
            equal(
                &json!(crate::sha256(&crate::read_bounded(
                    &directory.join("evidence").join(name),
                    8 * 1024 * 1024
                )?)),
                digest,
            )?;
        }
        Ok(())
    }
    #[test]
    fn missing_duplicate_reordered_families_and_false_success_fail() -> Result<()> {
        let raw = String::from_utf8(crate::read_bounded(
            &directory().join("evidence/run0.log"),
            1024 * 1024,
        )?)?;
        for (from, to) in [
            (
                "DIORAMA_PREFLIGHT_PORTS ipv4_2379 conflict_then_rebind",
                "wrong",
            ),
            ("ipv6_6443", "ipv4_6443"),
            ("permission_denied pass", "permission_denied success"),
            ("test result: ok. 1 passed;", "test result: ok. 0 passed;"),
            ("0 failed;", "1 failed;"),
            (
                "DIORAMA_PREFLIGHT_FILES exact pass",
                "DIORAMA_PREFLIGHT_FILES exact pass\nDIORAMA_PREFLIGHT_FILES exact pass",
            ),
            ("missing_version pass", "no_candidates pass"),
            ("/out/diorama_platform-", "/out/foreign-"),
        ] {
            assert!(
                verify(raw.replace(from, to).as_bytes()).is_err(),
                "accepted {from}"
            );
        }
        assert!(
            verify(format!("{raw}\n{}\n", raw.lines().next().ok_or("binary line")?).as_bytes())
                .is_err()
        );
        Ok(())
    }
}
