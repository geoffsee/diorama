//! Independent semantic inventories of pinned source inputs.
use crate::upstream::{
    self, Result, array, atomic_write, blob_name, compiler_record, fail, read_verified,
    strict_json, text,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::Path,
    process::Command,
};
mod descriptor;
mod report;
pub(crate) fn source_authority(record: &Value, architecture: &Value) -> Result<Value> {
    let mut matches = Vec::new();
    for source in array(architecture, "sources")? {
        if let Some(files) = source.get("files") {
            for entry in files.as_array().ok_or("invalid authority files")? {
                if entry.get("url") == record.get("url") {
                    matches.push((source, entry));
                }
            }
        }
    }
    if matches.len() != 1 {
        return fail("source missing/ambiguous in architecture contract");
    }
    let (authority, entry) = matches[0];
    for key in ["sha256", "bytes", "url"] {
        if record.get(key) != entry.get(key) {
            return fail("architecture and prepared-input contracts disagree");
        }
    }
    Ok(json!({"repository":text(authority,"repository")?,"commit":text(authority,"commit")?}))
}
fn containerd(
    inputs: &Value,
    cache: &Path,
    platform: &str,
    compiler: &Path,
) -> Result<(Value, Vec<Value>, Vec<Value>)> {
    let records: Vec<_> = array(inputs, "sources")?
        .iter()
        .filter(|r| r["target"] == "containerd")
        .cloned()
        .collect();
    if records.is_empty() {
        return fail("missing containerd schema inputs");
    }
    let work = tempfile::tempdir()?;
    let mut names = BTreeSet::new();
    for r in &records {
        let name = text(r, "proto_path")?;
        if !names.insert(name.to_owned()) {
            return fail("duplicate protobuf source");
        }
        atomic_write(
            work.path(),
            name,
            &read_verified(cache, &blob_name(r)?, r)?,
            false,
        )?;
    }
    let mut imports = Vec::new();
    for r in array(compiler_record(inputs, platform)?, "files")? {
        if let Some(name) = text(r, "path")?.strip_prefix("include/") {
            if !names.insert(name.to_owned()) {
                return fail("protobuf import shadows source");
            }
            imports.push(r.clone());
            atomic_write(
                work.path(),
                name,
                &read_verified(cache, &format!("protoc/{platform}/{}", text(r, "path")?), r)?,
                false,
            )?;
        }
    }
    let output = work.path().join("containerd.pb");
    let mut cmd = Command::new(compiler);
    cmd.arg(format!("--proto_path={}", work.path().display()))
        .arg("--include_imports")
        .arg(format!("--descriptor_set_out={}", output.display()));
    for r in &records {
        cmd.arg(text(r, "proto_path")?);
    }
    let _work = upstream::run_in(&mut cmd, 30, work)?;
    let result = descriptor::descriptor(&fs::read(output)?, "set", 0)?;
    let actual = array(&result, "files")?
        .iter()
        .map(|f| {
            f["name"][0]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "invalid descriptor name".into())
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if !actual.is_subset(&names)
        || records
            .iter()
            .any(|r| !actual.contains(r["proto_path"].as_str().unwrap_or("")))
    {
        return fail("unexpected descriptor source inventory");
    }
    Ok((result, records, imports))
}
pub(crate) fn extract(
    cache: &Path,
    input_manifest: &Path,
    architecture_manifest: &Path,
) -> Result<Value> {
    let inputs = upstream::manifest(input_manifest)?;
    let platform = upstream::host_platform();
    let compiler = upstream::verify(&inputs, cache, &platform, None)?;
    let architecture = strict_json(&fs::read(architecture_manifest)?)?;
    let records = array(&inputs, "sources")?
        .iter()
        .map(|r| Ok((text(r, "id")?.to_owned(), r.clone())))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let cri = records.get("cri").ok_or("missing CRI source")?;
    let openapi = records.get("openapi").ok_or("missing OpenAPI source")?;
    source_authority(cri, &architecture)?;
    source_authority(openapi, &architecture)?;
    let work = tempfile::tempdir()?;
    fs::write(
        work.path().join("api.proto"),
        read_verified(cache, &blob_name(cri)?, cri)?,
    )?;
    let output = work.path().join("api.pb");
    let _work = upstream::run_in(
        Command::new(&compiler)
            .arg(format!("--proto_path={}", work.path().display()))
            .arg(format!("--descriptor_set_out={}", output.display()))
            .arg("api.proto"),
        30,
        work,
    )?;
    let protocol = descriptor::descriptor(&fs::read(output)?, "set", 0)?;
    let document = strict_json(&read_verified(cache, &blob_name(openapi)?, openapi)?)?;
    if document["swagger"] != "2.0" || !document["definitions"].is_object() {
        return fail("unsupported OpenAPI format");
    }
    let (containerd, rows, imports) = containerd(&inputs, cache, &platform, &compiler)?;
    let authorities = rows
        .iter()
        .map(|r| {
            Ok((
                text(r, "id")?.to_owned(),
                source_authority(r, &architecture)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(
        json!({"schema_version":2,"authority":source_authority(cri,&architecture)?,"inputs":{"cri":cri,"openapi":openapi},"protoc_version":inputs["protoc_version"],"cri":protocol,"openapi_definitions":document["definitions"],"containerd":containerd,"containerd_authorities":authorities,"containerd_inputs":rows,"well_known_imports":imports}),
    )
}
pub(crate) fn pointer(path: &str, key: &str) -> String {
    format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"))
}
pub(crate) fn changes(before: &Value, after: &Value, path: &str) -> Vec<Value> {
    let mut out = Vec::new();
    match (before, after) {
        (Value::Object(a), Value::Object(b)) => {
            let keys: BTreeSet<_> = a.keys().chain(b.keys()).collect();
            for key in keys {
                let p = pointer(path, key);
                match (a.get(key), b.get(key)) {
                    (Some(a), Some(b)) => out.extend(changes(a, b, &p)),
                    (None, Some(b)) => out.push(json!({"path":p,"added":b})),
                    (Some(a), None) => out.push(json!({"path":p,"removed":a})),
                    _ => {},
                }
            }
        },
        (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
            for (i, (a, b)) in a.iter().zip(b).enumerate() {
                out.extend(changes(a, b, &pointer(path, &i.to_string())));
            }
        },
        _ => {
            if before != after {
                out.push(json!({"path":path,"before":before,"after":after}));
            }
        },
    }
    out
}
pub fn cli(args: &[String]) -> Result<i32> {
    upstream::with_execution(|| cli_inner(args))
}
fn cli_inner(args: &[String]) -> Result<i32> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        println!(
            "diorama-drift <check|extract> [--cache-dir PATH] [--inventory PATH] [--input-manifest PATH] [--architecture-manifest PATH]\ndiorama-drift report --before PATH --after PATH [--format json|markdown] [--before-resolved PATH --after-resolved PATH]"
        );
        return Ok(0);
    }
    let command = args.first().ok_or("expected check, extract, or report")?;
    if command == "report" {
        return report::cli(&args[1..]);
    }
    if !["check", "extract"].contains(&command.as_str()) {
        return fail("unknown drift command");
    }
    let mut opts = BTreeMap::new();
    let mut it = args[1..].iter();
    while let Some(k) = it.next() {
        if ![
            "--cache-dir",
            "--inventory",
            "--input-manifest",
            "--architecture-manifest",
        ]
        .contains(&k.as_str())
            || opts
                .insert(
                    k.as_str(),
                    it.next().ok_or("missing option value")?.as_str(),
                )
                .is_some()
        {
            return fail("unknown or duplicate option");
        }
    }
    let root = upstream::root();
    let path = |key, default: &str| {
        opts.get(key)
            .map_or_else(|| root.join(default), std::path::PathBuf::from)
    };
    let inventory = path("--inventory", "tools/drift/inventory.json.gz");
    let current = extract(
        &path("--cache-dir", "target/upstream"),
        &path("--input-manifest", "tools/upstream/inputs.json"),
        &path(
            "--architecture-manifest",
            "docs/architecture/upstream-inputs.json",
        ),
    )?;
    if command == "extract" {
        let mut gzip = flate2::GzBuilder::new()
            .mtime(0)
            .write(Vec::new(), flate2::Compression::default());
        gzip.write_all(&serde_json::to_vec(&current)?)?;
        atomic_write(
            inventory.parent().ok_or("inventory has no parent")?,
            inventory
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or("invalid inventory filename")?,
            &gzip.finish()?,
            false,
        )?;
        return Ok(0);
    }
    let mut raw = Vec::new();
    flate2::read::MultiGzDecoder::new(fs::File::open(inventory)?)
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() > 32 * 1024 * 1024 {
        return fail("inventory exceeds limit");
    }
    let diff = changes(&strict_json(&raw)?, &current, "");
    upstream::check_cancelled()?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"status":if diff.is_empty(){"unchanged"}else{"drift"},"changes":diff})
        )?
    );
    Ok(i32::from(!diff.is_empty()))
}
#[cfg(test)]
mod tests;
