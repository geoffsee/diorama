//! Immutable baseline observations and actual historical negative controls.
use super::{Result, contract, digest, read};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
};
const LIMIT: u64 = 8 * 1024 * 1024;
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../parity/fixtures")
}
fn load(name: &str) -> Result<Value> {
    diorama_dev::json::parse(&read(&root().join(name), LIMIT)?)
}
fn suite() -> Result<contract::Suite> {
    Ok(serde_json::from_value(load("config-command.json")?)?)
}
fn string(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(|| "text expected".into())
}
fn rows(value: &Value) -> Result<&Vec<Value>> {
    value.as_array().ok_or_else(|| "array expected".into())
}
fn cleanup(record: &Value) {
    assert_eq!(
        record["verified_cleanup"],
        json!({"container":true,"image":true,"volume":true})
    );
}
#[test]
#[ignore = "receipt checks disabled"]
fn frozen_reference_matches_complete_suite_provenance_and_raw_streams() -> Result<()> {
    let suite = suite()?;
    let capture = load("evidence/go-reference.json")?;
    let provenance = load("provenance.json")?;
    let hash = digest(&root().join("config-command.json"), false)?;
    assert_eq!(provenance["suite_sha256"], hash);
    assert_eq!(capture["result"]["suite_sha256"], hash);
    assert_eq!(
        read(&root().join("defaults.yaml"), LIMIT)?,
        string(&capture["observations"]["default-document"]["stdout"])?.as_bytes()
    );
    assert_eq!(
        capture["result"]["artifact"]["source"]["revision"],
        "2ef1c4787989f11f868f81bb84ae2afd4a49a81d"
    );
    let ids = suite
        .cases
        .iter()
        .map(|case| case.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for object in [&provenance["cases"], &capture["observations"]] {
        assert_eq!(
            object
                .as_object()
                .ok_or("case map")?
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            ids
        );
    }
    for case in &suite.cases {
        let observation = &capture["observations"][&case.id];
        assert!(
            contract::assess(
                case,
                i32::try_from(observation["exit_code"].as_i64().ok_or("exit")?)?,
                string(&observation["stdout"])?,
                string(&observation["stderr"])?
            )
            .is_empty()
        );
    }
    for case in rows(&capture["result"]["cases"])? {
        let observation = &capture["observations"][string(&case["id"])?];
        for stream in ["stdout", "stderr"] {
            assert_eq!(
                diorama_dev::sha256(string(&observation[stream])?.as_bytes()),
                string(&case[format!("{stream}_sha256")])?
            );
        }
    }
    cleanup(&capture);
    assert_eq!(capture["runner"]["exit_code"], 0);
    assert_eq!(capture["runner"]["errors"], json!([]));
    Ok(())
}
#[test]
#[ignore = "receipt checks disabled"]
fn historical_negative_controls_failed_with_owned_cleanup_and_preserved_identity() -> Result<()> {
    let controls = load("evidence/negative-controls.json")?;
    assert_eq!(
        digest(
            &root().join("evidence/deliberate-mismatch-suite.json"),
            false
        )?,
        string(&controls["deliberate_changed_expectation"]["result"]["suite_sha256"])?
    );
    for name in ["deliberate_changed_expectation", "actual_rust_placeholder"] {
        let record = &controls[name];
        assert_eq!(record["result"]["status"], "failed");
        assert!(!rows(&record["result"]["cases"])?.is_empty());
        assert!(
            rows(&record["result"]["cases"])?
                .iter()
                .all(|case| case["status"] == "failed")
        );
        assert_eq!(record["runner"]["exit_code"], 1);
        assert_eq!(record["runner"]["errors"], json!([]));
        cleanup(record);
    }
    assert_eq!(
        controls["actual_rust_placeholder"]["result"]["artifact"]["kind"],
        "rust"
    );
    Ok(())
}
#[test]
#[ignore = "receipt checks disabled"]
fn changed_inputs_produced_different_reference_output_without_changed_expectations() -> Result<()> {
    let controls = load("evidence/negative-controls.json")?;
    let negative = &controls["input_sensitivity"];
    let mutation = load("evidence/input-sensitivity-suite.json")?;
    assert_eq!(
        digest(&root().join("evidence/input-sensitivity-suite.json"), false)?,
        string(&negative["result"]["suite_sha256"])?
    );
    assert_eq!(rows(&mutation["cases"])?.len(), 3);
    assert_eq!(negative["runner"]["exit_code"], 1);
    assert_eq!(negative["runner"]["errors"], json!([]));
    cleanup(negative);
    let original = suite()?;
    let original_json = load("config-command.json")?;
    let capture = load("evidence/go-reference.json")?;
    for case in rows(&mutation["cases"])? {
        let id = string(&case["id"])?;
        let original = original
            .cases
            .iter()
            .find(|case| case.id == id)
            .ok_or("original case")?;
        assert_eq!(case["expect"], serde_json::to_value(&original.expect)?);
        let original_record = rows(&original_json["cases"])?
            .iter()
            .find(|row| row["id"] == id)
            .ok_or("original record")?;
        assert_ne!(case, original_record);
        let observation = &negative["observations"][id];
        assert_eq!(observation["exit_code"], 0);
        assert!(
            !contract::assess(
                original,
                0,
                string(&observation["stdout"])?,
                string(&observation["stderr"])?
            )
            .is_empty()
        );
        assert_ne!(observation["stdout"], capture["observations"][id]["stdout"]);
    }
    Ok(())
}
#[test]
#[ignore = "receipt checks disabled"]
fn storage_warning_and_environment_precedence_mutations_remain_visible() -> Result<()> {
    let suite = suite()?;
    let capture = load("evidence/go-reference.json")?;
    for (id, before, after) in [
        (
            "default-document",
            "  localPath:\n    enabled: true\n",
            "  localPath:\n    enabled: false\n",
        ),
        ("environment-over-file", "  mtu: 1450\n", "  mtu: 1400\n"),
    ] {
        let case = suite
            .cases
            .iter()
            .find(|case| case.id == id)
            .ok_or("case")?;
        let observation = &capture["observations"][id];
        let original = string(&observation["stdout"])?;
        let changed = original.replace(before, after);
        assert_ne!(changed, original);
        assert!(!contract::assess(case, 0, &changed, string(&observation["stderr"])?).is_empty());
    }
    let case = suite
        .cases
        .iter()
        .find(|case| case.id == "unknown-field-is-warning")
        .ok_or("warning case")?;
    assert!(
        !contract::assess(
            case,
            1,
            "",
            string(&capture["observations"][&case.id]["stderr"])?
        )
        .is_empty()
    );
    assert!(!contract::assess(&suite.cases[0], 0, "placeholder executable\n", "").is_empty());
    Ok(())
}
fn archive_streams(path: &Path) -> Result<BTreeMap<String, String>> {
    let raw = read(path, LIMIT)?;
    let gzip = flate2::read::GzDecoder::new(raw.as_slice());
    let mut archive = tar::Archive::new(gzip.take(64 * LIMIT));
    let mut hashes = BTreeMap::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = entry
            .path()?
            .to_string_lossy()
            .trim_start_matches("./")
            .to_owned();
        if !name.ends_with(".stdout") && !name.ends_with(".stderr") {
            continue;
        }
        let mut raw = Vec::new();
        (&mut entry).take(LIMIT + 1).read_to_end(&mut raw)?;
        assert!(raw.len() as u64 <= LIMIT);
        assert!(hashes.insert(name, diorama_dev::sha256(&raw)).is_none());
    }
    Ok(hashes)
}
#[test]
#[ignore = "receipt checks disabled"]
fn historical_vm_diagnostics_preserve_raw_hashes_and_complete_case_ownership() -> Result<()> {
    let hashes = load("evidence/vm/sha256.json")?;
    for (name, hash) in hashes.as_object().ok_or("hash inventory")? {
        assert_eq!(
            digest(&root().join("evidence/vm").join(name), false)?,
            string(hash)?
        );
    }
    let suite = suite()?;
    let expected_ids = suite
        .cases
        .iter()
        .map(|case| case.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for (kind, status) in [("go", "passed"), ("rust", "failed")] {
        let result = load(&format!("evidence/vm/{kind}/result.json"))?;
        assert_eq!(
            result["suite_sha256"],
            digest(&root().join("config-command.json"), false)?
        );
        assert_eq!(result["status"], status);
        assert_eq!(result["owned_process_group_absent"], true);
        assert_eq!(result["owned_temporary_directory_removed"], true);
        assert_eq!(result["errors"], json!([]));
        let cases = rows(&result["cases"])?;
        assert_eq!(
            cases
                .iter()
                .map(|case| string(&case["id"]).map(str::to_owned))
                .collect::<Result<std::collections::BTreeSet<_>>>()?,
            expected_ids
        );
        let streams =
            archive_streams(&root().join(format!("evidence/vm/{kind}/diagnostics.tar.gz")))?;
        for (index, case) in cases.iter().enumerate() {
            for stream in ["stdout", "stderr"] {
                assert_eq!(
                    streams
                        .get(&format!("case-{index:03}.{stream}"))
                        .ok_or("missing raw stream")?,
                    string(&case[format!("{stream}_sha256")])?
                );
            }
        }
    }
    Ok(())
}
