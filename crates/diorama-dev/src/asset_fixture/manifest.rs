//! Declared manifest qualification; input identities do not approve a publisher.
use super::{
    archive,
    common::{Result, bounded, check, json, read, save, sha256, strict, string},
    manifest_oracle as oracle, native,
};
use serde_json::{Map, Value};
use std::{io::Write as _, path::Path, process::Command};
const RAW: &str = include_str!("../../../assets-manifest/arm64-manifest.json");
const PRODUCER: &str = "DIORAMA_PRODUCER go1.26.2 github.com/google/go-containerregistry v0.21.5 h1:KTJG9Pn/jC0VdZR6ctV3/jcN+q6/Iqlx0sTVz3ywZlM=";
const CONSUMER: [&str; 6] = [
    "/manifest-tests",
    "--ignored",
    "--exact",
    "verify_pinned_crane_manifest",
    "--show-output",
    "--test-threads=1",
];

pub(super) fn copy_inputs(cache: &Path, target: &Path) -> Result<()> {
    let observed = oracle::verify_inputs(cache)?;
    std::fs::create_dir(target)?;
    std::fs::create_dir(target.join("blobs"))?;
    for (name, pin) in observed["files"].as_object().ok_or("input inventory")? {
        let raw = read(
            &cache.join(name),
            pin["bytes"].as_u64().ok_or("input bytes")?,
        )?;
        check(
            sha256(&raw) == string(&pin["sha256"])?,
            "cache changed during copy",
        )?;
        std::fs::write(target.join(name), raw)?;
    }
    check(
        oracle::verify_inputs(target)? == observed,
        "copied retained inputs",
    )
}

fn case(name: &str, raw: &str, status: &str) -> Value {
    json!({"name":name,"raw":raw,"manifest_sha256":sha256(raw.as_bytes()),"manifest_bytes":raw.len(),"mode":"normal","expected":status})
}
fn cases() -> Result<Vec<Value>> {
    let original = strict(RAW.as_bytes())?;
    let mut out = vec![case("coredns", RAW, "ok")];
    for (name, field, config, status) in [
        ("config-digest", "digest", true, "Config"),
        ("config-size", "size", true, "Config"),
        ("layer-digest", "digest", false, "Layers"),
        ("layer-size", "size", false, "Layers"),
    ] {
        let mut value = original.clone();
        let target = if config {
            &mut value["config"]
        } else {
            &mut value["layers"][0]
        };
        target[field] = if field == "size" {
            json!(1)
        } else {
            json!(format!("sha256:{}", "0".repeat(64)))
        };
        out.push(case(name, &serde_json::to_string(&value)?, status));
    }
    for name in [
        "reordered",
        "omitted",
        "duplicated",
        "codec",
        "index",
        "external-url",
        "duplicate-json",
        "fraction",
        "depth",
        "bytes",
        "references",
        "raw-identity",
        "archive-identity",
        "asset",
        "platform",
    ] {
        out.push(mutated_case(name, &original)?);
    }
    Ok(out)
}
fn mutated_case(name: &str, original: &Value) -> Result<Value> {
    let mut value = original.clone();
    let status = match name {
        "reordered" => {
            value["layers"].as_array_mut().ok_or("layers")?.swap(0, 1);
            "Layers"
        },
        "omitted" => {
            value["layers"].as_array_mut().ok_or("layers")?.pop();
            "Layers"
        },
        "duplicated" => {
            let row = value["layers"][0].clone();
            value["layers"].as_array_mut().ok_or("layers")?.push(row);
            "Layers"
        },
        "codec" => {
            value["layers"][0]["mediaType"] = json!("application/vnd.oci.image.layer.v1.tar+zstd");
            "Codec"
        },
        "index" => {
            value["mediaType"] = json!("application/vnd.oci.image.index.v1+json");
            "Profile"
        },
        "external-url" => {
            value["layers"][0]["urls"] = json!(["https://invalid.example/blob"]);
            "Profile"
        },
        "duplicate-json" | "depth" => "Json",
        "fraction" => "Profile",
        "bytes" | "references" => "Limit",
        "raw-identity" => "ManifestIdentity",
        "archive-identity" => "ArchiveIdentity",
        "asset" => "Asset",
        "platform" => "Platform",
        _ => return Err("unknown fixture case".into()),
    };
    let mut raw = serde_json::to_string(&value)?;
    if name == "duplicate-json" {
        raw = raw.replacen(
            "\"schemaVersion\":2",
            "\"schemaVersion\":2,\"schemaVersion\":2",
            1,
        );
    }
    if name == "fraction" {
        raw = raw.replacen("\"schemaVersion\":2", "\"schemaVersion\":2.0", 1);
    }
    let mut row = case(name, &raw, status);
    if [
        "depth",
        "bytes",
        "references",
        "archive-identity",
        "asset",
        "platform",
    ]
    .contains(&name)
    {
        row["mode"] = name.into();
    }
    if name == "raw-identity" {
        row["manifest_sha256"] = "0".repeat(64).into();
    }
    Ok(row)
}
fn expected_cases(cases: &[Value]) -> Result<Value> {
    let mut result = Map::new();
    for case in cases {
        result.insert(string(&case["name"])?.into(),json!({"case":case["name"],"manifest_sha256":sha256(string(&case["raw"])?.as_bytes()),"status":case["expected"],"budget_unchanged":true}));
    }
    Ok(result.into())
}
fn consumer_records(raw: &str) -> Result<Value> {
    let observed = oracle::pinned_observation()?;
    let expected = json!({"outer_sha256":observed["outer_sha256"],"outer_bytes":observed["outer_bytes"],"config_sha256":observed["config_sha256"],"config_bytes":observed["config_bytes"],"layers":observed["layers"]});
    let bindings = raw
        .lines()
        .filter_map(|line| line.strip_prefix("DIORAMA_BOUND "))
        .collect::<Vec<_>>();
    check(
        bindings.len() == 1 && strict(bindings[0].as_bytes())? == expected,
        "consumer independently bound raw observations",
    )?;
    let wanted = cases()?;
    let rows = raw
        .lines()
        .filter_map(|line| line.strip_prefix("DIORAMA_MANIFEST "))
        .map(|row| strict(row.as_bytes()))
        .collect::<Result<Vec<_>>>()?;
    check(
        rows.iter()
            .map(|row| row["case"].as_str())
            .eq(wanted.iter().map(|row| row["name"].as_str())),
        "exact manifest case order",
    )?;
    let mut result = Map::new();
    for row in rows {
        result.insert(string(&row["case"])?.into(), row);
    }
    let result = Value::Object(result);
    check(
        result == expected_cases(&wanted)?,
        "independent manifest case observations",
    )?;
    let tests = raw
        .lines()
        .filter(|line| line.starts_with("test ") && !line.starts_with("test result:"))
        .collect::<Vec<_>>();
    check(
        tests == ["test verify_pinned_crane_manifest ... ok"],
        "exact consumer test",
    )?;
    let summaries = raw
        .lines()
        .filter(|line| line.starts_with("test result:"))
        .collect::<Vec<_>>();
    check(summaries.len() == 1, "one consumer summary")?;
    let seconds=summaries[0].strip_prefix("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in ").and_then(|value|value.strip_suffix('s')).ok_or("consumer completion")?;
    check(
        !seconds.is_empty()
            && seconds
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.'),
        "consumer duration",
    )?;

    check(
        raw.lines()
            .filter(|line| *line == "DIORAMA_SYNTHETIC 8")
            .count()
            == 1,
        "synthetic profile assertions",
    )?;
    Ok(result)
}
pub(super) fn runtime() -> Result<()> {
    let directory = tempfile::Builder::new()
        .prefix("diorama-manifest-")
        .tempdir_in("/tmp")?;
    let result = runtime_in(directory.path());
    super::common::retain(directory, result)
}
fn runtime_in(directory: &Path) -> Result<()> {
    let input = Path::new("/inputs");
    oracle::verify_inputs(input)?;
    let packaged = directory.join("packaged");
    let log = directory.join("producer.log");
    let status = bounded(
        Command::new("/producer").arg(input).arg(&packaged),
        &log,
        30,
        65536,
    );
    archive::emit_log(status, &log, &mut std::io::stdout().lock())?;
    let bytes = read(&packaged.join("coredns.tar.gz"), 32 * 1024 * 1024)?;
    let observed = oracle::verify_archive(input, &bytes)?;
    check(
        observed == oracle::pinned_observation()?,
        "audited archive pin",
    )?;
    let cases = cases()?;
    let mut requests = cases.clone();
    for row in &mut requests {
        row.as_object_mut().ok_or("case")?.remove("expected");
    }
    save(&packaged.join("cases.json"), &json!(requests))?;
    {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "DIORAMA_ORACLE {observed}")?;
        stdout.flush()?;
    }
    let log = directory.join("consumer.log");
    let status = bounded(
        Command::new(CONSUMER[0])
            .args(&CONSUMER[1..])
            .env("DIORAMA_MANIFEST_FIXTURE", &packaged),
        &log,
        60,
        256 * 1024,
    );
    let raw = String::from_utf8(archive::emit_log(
        status,
        &log,
        &mut std::io::stdout().lock(),
    )?)?;
    consumer_records(&raw)?;
    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "DIORAMA_COMPLETE {}",
        json!({"cases":cases.iter().map(|v|&v["name"]).collect::<Vec<_>>(),"consumer_command":CONSUMER})
    )?;
    stdout.flush()?;
    Ok(())
}
pub(super) fn records(path: &Path) -> Result<(Value, Value)> {
    let raw = String::from_utf8(read(path, 1024 * 1024)?)?;
    let lines = raw.lines().collect::<Vec<_>>();
    let binaries = native::runtime_binaries(&lines, &["producer", "manifest-tests", "fixture"])?;
    check(lines.get(3) == Some(&PRODUCER), "producer provenance/order")?;
    let observed = strict(
        lines
            .get(4)
            .and_then(|line| line.strip_prefix("DIORAMA_ORACLE "))
            .ok_or("oracle record order")?
            .as_bytes(),
    )?;
    check(
        observed == oracle::pinned_observation()?,
        "pinned independent byte observations",
    )?;
    for (prefix, count) in [
        ("DIORAMA_PRODUCER ", 1),
        ("DIORAMA_ORACLE ", 1),
        ("DIORAMA_COMPLETE ", 1),
        ("DIORAMA_SYNTHETIC ", 1),
    ] {
        check(
            lines.iter().filter(|line| line.starts_with(prefix)).count() == count,
            "exact record count",
        )?;
    }
    check(
        lines
            .iter()
            .filter(|line| line.starts_with("DIORAMA_"))
            .all(|line| {
                [
                    "DIORAMA_PRODUCER ",
                    "DIORAMA_ORACLE ",
                    "DIORAMA_COMPLETE ",
                    "DIORAMA_SYNTHETIC ",
                    "DIORAMA_MANIFEST ",
                    "DIORAMA_BOUND ",
                    "DIORAMA_NAMESPACE ",
                ]
                .iter()
                .any(|prefix| line.starts_with(prefix))
            }),
        "unknown manifest record",
    )?;
    let cases = cases()?;
    let complete = lines
        .get(lines.len().checked_sub(2).ok_or("runtime boundary")?)
        .and_then(|line| line.strip_prefix("DIORAMA_COMPLETE "))
        .ok_or("completion order")?;
    check(
        strict(complete.as_bytes())?
            == json!({"cases":cases.iter().map(|v|&v["name"]).collect::<Vec<_>>(),"consumer_command":CONSUMER}),
        "completion binding",
    )?;
    native::namespace(&lines)?;
    Ok((
        json!({"oracle":observed,"cases":consumer_records(&raw)?}),
        binaries,
    ))
}
#[cfg(test)]
#[path = "manifest_tests.rs"]
mod tests;
