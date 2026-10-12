//! Runtime orchestration and raw evidence parsing, independent of the layer consumer.
use super::{
    archive,
    common::{Result, b64, bounded, check, fields, json, read, strict, string, unb64},
    layer_oracle as oracle, native,
};
use serde_json::{Map, Value};
use std::{io::Write as _, path::Path, process::Command};

pub(super) const CONSUMER: [&str; 6] = [
    "/layer-tests",
    "--ignored",
    "--exact",
    "verify_pinned_crane_layers",
    "--show-output",
    "--test-threads=1",
];
const PRODUCER: &str = "DIORAMA_PRODUCER go1.26.2 github.com/google/go-containerregistry v0.21.5 h1:KTJG9Pn/jC0VdZR6ctV3/jcN+q6/Iqlx0sTVz3ywZlM=";

pub(super) fn parse_consumer(raw: &str) -> Result<Value> {
    let rows = raw
        .lines()
        .filter_map(|line| line.strip_prefix("DIORAMA_LAYER "))
        .map(|line| strict(line.as_bytes()))
        .collect::<Result<Vec<_>>>()?;
    for row in &rows {
        oracle::observation_schema(row)?;
    }
    check(
        rows.iter()
            .map(|row| row["case"].as_str().unwrap_or(""))
            .eq(oracle::NAMES),
        "exact layer consumer case order",
    )?;
    let tests = raw
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("test ") && !line.starts_with("test result:"))
        .collect::<Vec<_>>();
    check(
        tests == ["test verify_pinned_crane_layers ... ok"],
        "exact layer consumer test inventory",
    )?;
    native::summary(raw, 1)?;
    let mut observations = Map::new();
    for row in rows {
        observations.insert(string(&row["case"])?.into(), row);
    }
    Ok(observations.into())
}

pub(super) fn runtime() -> Result<()> {
    let directory = tempfile::Builder::new()
        .prefix("diorama-layer-")
        .tempdir_in("/tmp")?;
    let result = runtime_in(directory.path());
    super::common::retain(directory, result)
}

fn runtime_in(directory: &Path) -> Result<()> {
    let producer_log = directory.join("producer.log");
    let status = bounded(
        Command::new("/producer").arg(directory),
        &producer_log,
        20,
        65536,
    );
    archive::emit_log(status, &producer_log, &mut std::io::stdout().lock())?;
    let upstream = strict(&read(
        &directory.join("upstream.json"),
        oracle::LIMIT as u64,
    )?)?;
    let positives = oracle::POSITIVES
        .iter()
        .map(|name| {
            Ok((
                (*name).into(),
                read(
                    &directory.join(format!("{name}.tar.gz")),
                    oracle::LIMIT as u64,
                )?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let inputs = oracle::cases(&positives, &upstream)?;
    let expected = oracle::observations(&inputs, &upstream)?;
    {
        let mut output = std::io::stdout().lock();
        writeln!(output, "DIORAMA_UPSTREAM {upstream}")?;
        for (name, raw) in &inputs {
            std::fs::write(directory.join(format!("{name}.tar.gz")), raw)?;
            writeln!(
                output,
                "DIORAMA_INPUT {}",
                json!({"case":name,"gzip_base64":b64(raw)})
            )?;
        }
        output.flush()?;
    }
    let log = directory.join("consumer.log");
    let status = bounded(
        Command::new(CONSUMER[0])
            .args(&CONSUMER[1..])
            .env("DIORAMA_LAYER_FIXTURE", directory),
        &log,
        20,
        65536,
    );
    let raw = String::from_utf8(archive::emit_log(
        status,
        &log,
        &mut std::io::stdout().lock(),
    )?)?;
    check(
        parse_consumer(&raw)? == expected,
        "independent layer consumer equality",
    )?;
    let mut output = std::io::stdout().lock();
    writeln!(
        output,
        "DIORAMA_COMPLETE {}",
        json!({"cases":oracle::NAMES,"consumer_command":CONSUMER})
    )?;
    output.flush()?;
    Ok(())
}

pub(super) fn records(path: &Path) -> Result<(Value, Value)> {
    let raw = String::from_utf8(read(path, 2 * 1024 * 1024)?)?;
    let lines = raw.lines().collect::<Vec<_>>();
    let binaries = native::runtime_binaries(&lines, &["producer", "layer-tests", "fixture"])?;
    check(
        lines.get(3) == Some(&PRODUCER),
        "layer producer provenance/order",
    )?;
    let upstream = strict(
        lines
            .get(4)
            .and_then(|line| line.strip_prefix("DIORAMA_UPSTREAM "))
            .ok_or("layer upstream order")?
            .as_bytes(),
    )?;
    let mut inputs = Vec::new();
    for (index, name) in oracle::NAMES.iter().enumerate() {
        let row = strict(
            lines
                .get(index + 5)
                .and_then(|line| line.strip_prefix("DIORAMA_INPUT "))
                .ok_or("layer input order")?
                .as_bytes(),
        )?;
        fields(&row, &["case", "gzip_base64"])?;
        check(row["case"] == *name, "layer input case")?;
        let bytes = unb64(string(&row["gzip_base64"])?)?;
        check(bytes.len() <= oracle::LIMIT, "encoded layer fixture cap")?;
        inputs.push(((*name).into(), bytes));
    }
    for (prefix, count) in [
        ("DIORAMA_PRODUCER ", 1),
        ("DIORAMA_UPSTREAM ", 1),
        ("DIORAMA_INPUT ", 12),
        ("DIORAMA_COMPLETE ", 1),
    ] {
        check(
            lines.iter().filter(|line| line.starts_with(prefix)).count() == count,
            "exact layer runtime record count",
        )?;
    }
    check(
        lines
            .iter()
            .filter(|line| line.starts_with("DIORAMA_"))
            .all(|line| {
                [
                    "DIORAMA_PRODUCER ",
                    "DIORAMA_UPSTREAM ",
                    "DIORAMA_INPUT ",
                    "DIORAMA_LAYER ",
                    "DIORAMA_COMPLETE ",
                    "DIORAMA_NAMESPACE ",
                ]
                .iter()
                .any(|prefix| line.starts_with(prefix))
            }),
        "unknown layer runtime record",
    )?;
    let expected = oracle::observations(&inputs, &upstream)?;
    check(
        parse_consumer(&raw)? == expected,
        "independent layer observations",
    )?;
    let complete = lines
        .get(lines.len().checked_sub(2).ok_or("runtime boundary")?)
        .and_then(|line| line.strip_prefix("DIORAMA_COMPLETE "))
        .ok_or("final layer completion order")?;
    check(
        strict(complete.as_bytes())? == json!({"cases":oracle::NAMES,"consumer_command":CONSUMER}),
        "exact layer completion",
    )?;
    native::namespace(&lines)?;
    Ok((expected, binaries))
}

#[cfg(test)]
#[path = "layer_tests.rs"]
mod tests;
