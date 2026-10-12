//! Read-only historical oracles and current disposable platform/management qualification.
pub mod capture;
pub mod linux;
pub mod oracle;
use crate::{Result, defaults::capture::digest};
use serde_json::Value;
use std::path::{Path, PathBuf};
pub fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}
pub fn load(path: &Path) -> Result<Value> {
    crate::json::parse(&crate::read_bounded(path, 8 * 1024 * 1024)?)
}
pub fn fixture(root: &Path, family: &str) -> Result<PathBuf> {
    Ok(root.join("tools/parity/fixtures").join(match family {
        "platform" => "platform-discovery",
        "management" => "management-check",
        _ => return Err("unknown qualification family".into()),
    }))
}
fn clean(receipt: &Value) -> Result<()> {
    for key in [
        "errors",
        "cleanup_errors",
        "remaining_containers",
        "remaining_images",
    ] {
        require(
            receipt[key] == serde_json::json!([]),
            "missing or unsuccessful cleanup",
        )?;
    }
    require(
        receipt["containers"]
            .as_array()
            .is_some_and(|v| !v.is_empty() && v.iter().all(Value::is_string)),
        "ownership inventory",
    )
}
fn frozen_files(base: &Path, provenance: &Value, expected: &[String]) -> Result<()> {
    let files = provenance["files"].as_object().ok_or("provenance files")?;
    require(
        files.len() == expected.len() && expected.iter().all(|name| files.contains_key(name)),
        "exact frozen inventory",
    )?;
    for (name, hash) in files {
        require(digest(&base.join(name))? == *hash, "frozen evidence digest")?;
    }
    Ok(())
}
pub fn verify_historical(root: &Path, family: &str) -> Result<()> {
    let here = fixture(root, family)?;
    let go = if family == "platform" {
        here.join("evidence/go")
    } else {
        here.join("evidence")
    };
    let linux = if family == "platform" {
        here.join("evidence/linux")
    } else {
        here.join("evidence-linux")
    };
    let go_names = [
        "build.log",
        "run0.log",
        "run1.log",
        "receipt.json",
        "source.sha256",
    ];
    let linux_names = ["build.log", "run.log", "receipt.json", "source-hashes.json"];
    if family == "platform" {
        let expected = go_names
            .iter()
            .map(|n| format!("go/{n}"))
            .chain(linux_names.iter().map(|n| format!("linux/{n}")))
            .collect::<Vec<_>>();
        frozen_files(
            &here.join("evidence"),
            &load(&here.join("provenance.json"))?,
            &expected,
        )?;
    } else {
        let expected = ["expected.json", "cases.json", "source-pins.json"]
            .iter()
            .map(|n| (*n).to_owned())
            .chain(go_names.iter().map(|n| format!("evidence/{n}")))
            .collect::<Vec<_>>();
        frozen_files(&here, &load(&here.join("provenance.json"))?, &expected)?;
        frozen_files(
            &linux,
            &load(&here.join("linux-provenance.json"))?,
            &linux_names.map(str::to_owned),
        )?;
    }
    let receipt = load(&go.join("receipt.json"))?;
    clean(&receipt)?;
    if family == "platform" {
        require(
            receipt["source_sha256"]["expected.tsv"] == digest(&here.join("expected.tsv"))?,
            "independent expected TSV unchanged",
        )?;
    }
    require(
        receipt["revision"] == "2ef1c4787989f11f868f81bb84ae2afd4a49a81d"
            && receipt["archive_sha256"]
                == "9d5f3ce1f3fbda971fb1e2fb6da18ae3880caeec677f0e5d928a3bbe7bb76aec"
            && receipt["identical_records"] == true,
        "baseline authority and repeats",
    )?;
    let first = oracle::go(
        family,
        &here,
        &crate::read_bounded(&go.join("run0.log"), 8 * 1024 * 1024)?,
    )?;
    require(
        first
            == oracle::go(
                family,
                &here,
                &crate::read_bounded(&go.join("run1.log"), 8 * 1024 * 1024)?,
            )?,
        "exact repeat",
    )?;
    verify_source_pins(
        family,
        &here,
        &crate::read_bounded(&go.join("source.sha256"), 1024 * 1024)?,
    )?;
    clean(&load(&linux.join("receipt.json"))?)?;
    oracle::linux(
        family,
        &crate::read_bounded(&linux.join("run.log"), 8 * 1024 * 1024)?,
    )
}
pub fn verify_source_pins(family: &str, here: &Path, raw: &[u8]) -> Result<()> {
    if family == "platform" {
        return require(
            raw == b"ed6900c2832745617930fdcdf77969a63a87a39b15fe8a318805ba077b84648a  detect.go\n",
            "unaltered actual Go source",
        );
    }
    let pins = load(&here.join("source-pins.json"))?;
    let mut actual = serde_json::Map::new();
    let re = regex::Regex::new(r"\A([a-f0-9]{64})  (.+)\z")?;
    for line in std::str::from_utf8(raw)?.lines() {
        let captures = re.captures(line).ok_or("source hash row")?;
        require(
            actual
                .insert(captures[2].into(), Value::from(&captures[1]))
                .is_none(),
            "duplicate source hash",
        )?;
    }
    require(
        actual.remove("/capture.test").is_some(),
        "actual binary identity",
    )?;
    require(Value::Object(actual) == pins, "baseline source pins")
}
#[cfg(test)]
mod tests {
    use super::*;
    fn root() -> PathBuf {
        crate::repository_root(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap()
    }
    #[test]
    #[ignore = "receipt checks disabled"]
    fn historical_go_and_linux_oracles_remain_independent() {
        for family in ["platform", "management"] {
            verify_historical(&root(), family).unwrap();
        }
    }
    #[test]
    fn management_effect_boolean_and_exit_types_cannot_be_rewritten() {
        let row = serde_json::json!({"name":"check","stdout":"CHECK false false\n","stderr":"","exit":false});
        assert!(oracle::classify(&row).is_err());
        let fixture = fixture(&root(), "management").unwrap();
        let raw = crate::read_bounded(&fixture.join("evidence/run0.log"), 1024 * 1024).unwrap();
        let changed = String::from_utf8(raw)
            .unwrap()
            .replace("CHECK false false", "CHECK true false");
        assert!(oracle::go("management", &fixture, changed.as_bytes()).is_err());
    }
    #[test]
    fn linux_semantics_cannot_be_rehashed_into_success() {
        for family in ["platform", "management"] {
            let here = fixture(&root(), family).unwrap();
            let path = here.join(if family == "platform" {
                "evidence/linux/run.log"
            } else {
                "evidence-linux/run.log"
            });
            let raw = crate::read_bounded(&path, 8 * 1024 * 1024).unwrap();
            let text = std::str::from_utf8(&raw).unwrap();
            assert!(
                oracle::linux(
                    family,
                    text.replace("test result: ok. 7 passed;", "test result: FAILED;")
                        .as_bytes()
                )
                .is_err()
            );
            if family == "management" {
                let original = oracle::record(&raw, "DIORAMA_CHECK ").unwrap();
                for field in ["listener_survived", "ports_released", "files_unchanged"] {
                    let mut changed = original.clone();
                    changed[field] = false.into();
                    assert!(oracle::management_record(&changed).is_err());
                }
                let mut changed = original;
                changed["cases"][6]["exit"] = 0.into();
                assert!(oracle::management_record(&changed).is_err());
            }
        }
    }
}
