use super::{
    Result, array, atomic_write, blob_name, compiler_record, digest, fail, host_platform,
    owned_path, read_verified, root, run, text, verify,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Command,
};
pub(crate) fn protocol_routes(proto: &[u8]) -> Result<Vec<Vec<u8>>> {
    let source = std::str::from_utf8(proto)?;
    let comments = regex::Regex::new(r"(?s)/\*.*?\*/|//[^\n]*")?;
    let source = comments.replace_all(source, "");
    let package = regex::Regex::new(r"(?m)^\s*package\s+([^;]+);")?;
    let package = package.captures(&source);
    let services = regex::Regex::new(r"(?ms)^\s*service\s+(\w+)\s*\{(.*?)^\}")?;
    let methods = regex::Regex::new(r"\brpc\s+(\w+)\s*\(")?;
    let mut routes = Vec::new();
    for service in services.captures_iter(&source) {
        let package = package
            .as_ref()
            .ok_or("service definition has no protobuf package")?;
        for method in methods.captures_iter(&service[2]) {
            routes.push(format!("/{}.{}/{}", &package[1], &service[1], &method[1]).into_bytes());
        }
    }
    Ok(routes)
}
pub(crate) fn prepare_containerd(
    inputs: &Value,
    cache: &Path,
    selected: &str,
    directory: &Path,
) -> Result<(Vec<Value>, Vec<Vec<u8>>)> {
    let records: Vec<_> = array(inputs, "sources")?
        .iter()
        .filter(|r| r["target"] == "containerd")
        .cloned()
        .collect();
    if records.is_empty() {
        return fail("no locked containerd protocols");
    }
    let mut prepared = BTreeMap::new();
    for r in &records {
        if prepared
            .insert(
                text(r, "proto_path")?.to_owned(),
                read_verified(cache, &blob_name(r)?, r)?,
            )
            .is_some()
        {
            return fail("duplicate protobuf import name");
        }
    }
    for r in array(compiler_record(inputs, selected)?, "files")? {
        if let Some(name) = text(r, "path")?.strip_prefix("include/")
            && prepared
                .insert(
                    name.to_owned(),
                    read_verified(cache, &format!("protoc/{selected}/{}", text(r, "path")?), r)?,
                )
                .is_some()
        {
            return fail("duplicate protobuf import name");
        }
    }
    let imports = regex::Regex::new(r#"(?m)^\s*import\s+"([^"]+)";"#)?;
    for content in prepared.values() {
        for imported in imports.captures_iter(std::str::from_utf8(content)?) {
            if !prepared.contains_key(&imported[1]) {
                return fail(format!("missing locked protobuf import: {}", &imported[1]));
            }
        }
    }
    for (name, content) in &prepared {
        atomic_write(directory, name, content, false)?;
    }
    let protocols = records
        .iter()
        .map(|r| {
            Ok(prepared
                .get(text(r, "proto_path")?)
                .ok_or("missing prepared source")?
                .clone())
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((records, protocols))
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn generate(
    inputs: &Value,
    cache: &Path,
    selected: &str,
    generator: &Path,
    output: &Path,
    check: bool,
    alternate: Option<&Path>,
    target: &str,
) -> Result<Value> {
    if selected != host_platform() {
        return fail("generation requires the locked compiler for the current host platform");
    }
    let protoc = verify(inputs, cache, selected, alternate)?;
    let version = run(Command::new(&protoc).arg("--version"), 10)?;
    if std::str::from_utf8(&version)?.trim()
        != format!("libprotoc {}", text(inputs, "protoc_version")?)
    {
        return fail("unexpected verified compiler version");
    }
    if !generator.is_file() {
        return fail("generator missing; build diorama-upstream-codegen explicitly");
    }
    let work = tempfile::tempdir()?;
    let generated = work.path().join("generated");
    let mut command = Command::new(generator);
    let (records, protocols, expected) = match target {
        "containerd" => {
            let path = work.path().join("inputs");
            let (r, p) = prepare_containerd(inputs, cache, selected, &path)?;
            command
                .arg("--containerd")
                .arg(path)
                .arg(&protoc)
                .arg(&generated);
            let e = array(inputs, "containerd_output_files")?
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| "invalid output file".into())
                })
                .collect::<Result<BTreeSet<_>>>()?;
            (r, p, e)
        },
        "cri" => {
            let r = array(inputs, "sources")?
                .iter()
                .find(|r| r["id"] == "cri")
                .ok_or("missing CRI source")?
                .clone();
            let data = read_verified(cache, &blob_name(&r)?, &r)?;
            let path = work.path().join("api.proto");
            fs::write(&path, &data)?;
            command.arg(path).arg(&protoc).arg(&generated);
            (
                vec![r],
                vec![data],
                BTreeSet::from(["runtime.v1.rs".to_owned()]),
            )
        },
        _ => return fail("unsupported generation target"),
    };
    let _work = super::run_in(&mut command, 120, work)?;
    if inventory(&generated)? != expected {
        return fail("generator returned an unexpected output inventory");
    }
    let contents = expected
        .iter()
        .map(|n| Ok((n.clone(), fs::read(generated.join(n))?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let routes = protocols
        .iter()
        .map(|p| protocol_routes(p))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    for route in &routes {
        if !contents
            .values()
            .any(|c| c.windows(route.len()).any(|w| w == route))
        {
            return fail("generated client is missing RPC");
        }
    }
    publish_outputs(output, check, &expected, &contents)?;
    let sources = records
        .iter()
        .map(|r| Ok((text(r, "id")?.to_owned(), r["sha256"].clone())))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let outputs = contents
        .iter()
        .map(|(n, d)| (n.clone(), json!({"sha256":digest(d),"bytes":d.len()})))
        .collect::<BTreeMap<_, _>>();
    let mut receipt = json!({"schema_version":1,"mode":if check{"check"}else{"generate"},"target":target,"platform":selected,"source_hashes":sources,"compiler_sha256":digest(&fs::read(protoc)?),"generator_sha256":digest(&fs::read(generator)?),"cargo_lock_sha256":digest(&fs::read(root().join("Cargo.lock"))?),"outputs":outputs,"rpc_count":routes.len()});
    if target == "cri" {
        receipt["source_sha256"] = records[0]["sha256"].clone();
        receipt["output_sha256"] = digest(&contents["runtime.v1.rs"]).into();
        receipt["output_bytes"] = contents["runtime.v1.rs"].len().into();
    }
    Ok(receipt)
}
fn inventory(path: &Path) -> Result<BTreeSet<String>> {
    fs::read_dir(path)?
        .map(|e| {
            Ok(e?
                .file_name()
                .into_string()
                .map_err(|_| "non UTF-8 output name")?)
        })
        .collect()
}

fn publish_outputs(
    output: &Path,
    check: bool,
    expected: &BTreeSet<String>,
    contents: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let destinations = expected
        .iter()
        .map(|n| Ok((n.clone(), owned_path(output, n)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    if output.exists() && !inventory(output)?.is_subset(expected) {
        return fail("unexpected files in generated output");
    }
    for p in destinations.values() {
        if p.exists() && !p.is_file() {
            return fail("generated output destination is not a regular file");
        }
    }
    for (name, content) in contents {
        if check {
            let p = &destinations[name];
            if !p.is_file() || fs::read(p)? != *content {
                return fail(format!("generated output drift: {}", p.display()));
            }
        } else {
            atomic_write(output, name, content, false)?;
        }
    }
    Ok(())
}
