use super::pointer;
use crate::upstream::{Result, array, digest, fail, strict_json, text};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::Path,
};
const CATEGORIES: [&str; 7] = [
    "api_schema",
    "protobuf_fields",
    "protobuf_rpcs",
    "component_defaults",
    "apiserver_defaults",
    "feature_gates",
    "snapshot_metadata",
];
const NAMED: [&str; 10] = [
    "files",
    "messages",
    "nested",
    "fields",
    "enums",
    "values",
    "services",
    "methods",
    "extensions",
    "oneofs",
];
pub(crate) fn changes(before: Option<&Value>, after: Option<&Value>, path: &str) -> Vec<Value> {
    match (before, after) {
        (None, Some(b)) => vec![json!({"path":path,"kind":"added","after":b})],
        (Some(a), None) => vec![json!({"path":path,"kind":"removed","before":a})],
        (Some(a), Some(b)) => {
            if std::mem::discriminant(a) != std::mem::discriminant(b)
                || a.is_number() && b.is_number() && a.is_f64() != b.is_f64()
            {
                return vec![json!({"path":path,"kind":"type_changed","before":a,"after":b})];
            }
            match (a, b) {
                (Value::Object(a), Value::Object(b)) => a
                    .keys()
                    .chain(b.keys())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .flat_map(|k| changes(a.get(k), b.get(k), &pointer(path, k)))
                    .collect(),
                (Value::Array(a), Value::Array(b)) => (0..a.len().max(b.len()))
                    .flat_map(|i| changes(a.get(i), b.get(i), &pointer(path, &i.to_string())))
                    .collect(),
                _ => {
                    if a == b {
                        Vec::new()
                    } else {
                        vec![json!({"path":path,"kind":"changed","before":a,"after":b})]
                    }
                },
            }
        },
        _ => Vec::new(),
    }
}
pub(crate) fn named(value: &Value, collection: Option<&str>) -> Result<Value> {
    let is_named = collection.is_some_and(|c| NAMED.contains(&c));
    if is_named && !value.is_array() {
        return fail("invalid descriptor array");
    }
    match value {
        Value::Object(map) => Ok(Value::Object(
            map.iter()
                .map(|(k, v)| Ok((k.clone(), self::named(v, Some(k))?)))
                .collect::<Result<_>>()?,
        )),
        Value::Array(items) if is_named => {
            let mut out = serde_json::Map::new();
            for item in items {
                let names = array(item, "name")?;
                if names.len() != 1 {
                    return fail("invalid named descriptor identity");
                }
                let name = names[0].as_str().ok_or("invalid descriptor name")?;
                if out
                    .insert(name.to_owned(), self::named(item, None)?)
                    .is_some()
                {
                    return fail("duplicate named descriptor");
                }
            }
            Ok(out.into())
        },
        Value::Array(items) => Ok(items
            .iter()
            .map(|v| self::named(v, None))
            .collect::<Result<Vec<_>>>()?
            .into()),
        _ => Ok(value.clone()),
    }
}
fn mapping(value: &Value, key: &str) -> Result<()> {
    if !value.get(key).is_some_and(Value::is_object) {
        return fail(format!("missing or invalid object: {key}"));
    }
    Ok(())
}
pub(crate) fn validate(snapshot: &Value) -> Result<()> {
    for (kind, version) in [("source", 2), ("defaults", 1), ("apiserver", 1)] {
        if snapshot[kind]["schema_version"].as_u64() != Some(version) {
            return fail("unsupported snapshot schema");
        }
    }
    let source = &snapshot["source"];
    for key in [
        "authority",
        "inputs",
        "openapi_definitions",
        "cri",
        "containerd",
    ] {
        mapping(source, key)?;
    }
    for key in ["repository", "commit"] {
        if text(&source["authority"], key)?.is_empty() {
            return fail("missing official source authority");
        }
    }
    for key in ["cri", "containerd"] {
        for file in array(&source[key], "files")? {
            let names = array(file, "name")?;
            if names.len() != 1 || !names[0].is_string() {
                return fail("invalid descriptor file identity");
            }
        }
    }
    for kind in ["defaults", "apiserver"] {
        let document = &snapshot[kind];
        for key in ["cases", "registered_feature_gates"] {
            mapping(document, key)?;
        }
        for key in [
            "source_revision",
            "go_version",
            "platform",
            "emulation_version",
            "minimum_compatibility_version",
        ] {
            if text(document, key)?.is_empty() {
                return fail("missing default source pin");
            }
        }
    }
    mapping(&snapshot["apiserver"], "apiserver_options")
}
pub(crate) fn load_snapshot(directory: &Path) -> Result<(Value, Value)> {
    let mut documents = serde_json::Map::new();
    let mut hashes = serde_json::Map::new();
    for (kind, name) in [
        ("source", "inventory.json.gz"),
        ("defaults", "defaults.json"),
        ("apiserver", "apiserver-defaults.json"),
    ] {
        let mut raw = Vec::new();
        fs::File::open(directory.join(name))?
            .take(32 * 1024 * 1024 + 1)
            .read_to_end(&mut raw)?;
        if raw.len() > 32 * 1024 * 1024 {
            return fail("snapshot exceeds 32MiB input limit");
        }
        hashes.insert(name.to_owned(), digest(&raw).into());
        if kind == "source" {
            let mut decoded = Vec::new();
            flate2::read::MultiGzDecoder::new(raw.as_slice())
                .take(32 * 1024 * 1024 + 1)
                .read_to_end(&mut decoded)?;
            if decoded.len() > 32 * 1024 * 1024 {
                return fail("snapshot exceeds 32MiB limit");
            }
            raw = decoded;
        }
        documents.insert(kind.to_owned(), strict_json(&raw)?);
    }
    let documents = Value::Object(documents);
    validate(&documents)?;
    Ok((documents, hashes.into()))
}
pub(crate) fn domains(snapshot: &Value) -> Result<Value> {
    let mut result = json!({});
    for c in CATEGORIES {
        result[c] = json!({});
    }
    let source = &snapshot["source"];
    result["api_schema"] = source["openapi_definitions"].clone();
    for protocol in ["cri", "containerd"] {
        let mut descriptor = named(&source[protocol], None)?;
        let mut rpc = serde_json::Map::new();
        let files = descriptor["files"]
            .as_object_mut()
            .ok_or("invalid descriptor files")?;
        for (name, file) in files {
            if let Some(services) = file
                .as_object_mut()
                .ok_or("invalid descriptor file")?
                .remove("services")
            {
                rpc.insert(name.clone(), services);
            }
        }
        result["protobuf_fields"][protocol] = descriptor;
        result["protobuf_rpcs"][protocol] = rpc.into();
    }
    for kind in ["defaults", "apiserver"] {
        let document = &snapshot[kind];
        result["component_defaults"][kind] = document["cases"].clone();
        result["feature_gates"][kind] = document["registered_feature_gates"].clone();
        let metadata = document
            .as_object()
            .ok_or("invalid snapshot")?
            .iter()
            .filter(|(key, _)| {
                !(matches!(key.as_str(), "cases" | "registered_feature_gates")
                    || kind == "apiserver" && key.as_str() == "apiserver_options")
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<serde_json::Map<_, _>>();
        result["snapshot_metadata"][kind] = metadata.into();
    }
    result["apiserver_defaults"] = snapshot["apiserver"]["apiserver_options"].clone();
    result["snapshot_metadata"]["source"] = source
        .as_object()
        .ok_or("invalid source")?
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), "cri" | "containerd" | "openapi_definitions"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<serde_json::Map<_, _>>()
        .into();
    Ok(result)
}
pub(crate) fn build_report(
    before: &Value,
    after: &Value,
    old_hashes: &Value,
    new_hashes: &Value,
) -> Result<Value> {
    validate(before)?;
    validate(after)?;
    let old = domains(before)?;
    let new = domains(after)?;
    let mut categorized = serde_json::Map::new();
    let mut count = 0;
    let mut removals = 0;
    for category in CATEGORIES {
        let diff = changes(Some(&old[category]), Some(&new[category]), "");
        count += diff.len();
        removals += diff.iter().filter(|v| v["kind"] == "removed").count();
        categorized.insert(category.to_owned(), diff.into());
    }
    Ok(
        json!({"schema_version":1,"status":if count==0{"unchanged"}else{"changed"},"change_count":count,"removal_count":removals,"snapshot_sha256":{"before":old_hashes,"after":new_hashes},"source_pins":{"before":old["snapshot_metadata"],"after":new["snapshot_metadata"]},"changes":categorized}),
    )
}
pub(crate) fn merge_resolved(report: &mut Value, resolved: &Value) -> Result<()> {
    let changes = resolved["changes"]
        .as_object()
        .ok_or("missing resolved changes")?;
    report["changes"]
        .as_object_mut()
        .ok_or("invalid report")?
        .extend(changes.clone());
    for side in ["before", "after"] {
        report["source_pins"][side]["resolved"] = resolved["source_pins"][side].clone();
        for (name, hash) in resolved["snapshot_sha256"][side]
            .as_object()
            .ok_or("missing resolved hashes")?
        {
            report["snapshot_sha256"][side][format!("resolved/{name}")] = hash.clone();
        }
    }
    for key in ["change_count", "removal_count"] {
        report[key] = report[key]
            .as_u64()
            .ok_or("invalid count")?
            .checked_add(resolved[key].as_u64().ok_or("invalid resolved count")?)
            .ok_or("count overflow")?
            .into();
    }
    report["status"] = if report["change_count"] == 0 {
        "unchanged"
    } else {
        "changed"
    }
    .into();
    Ok(())
}
pub(crate) fn markdown(report: &Value) -> Result<String> {
    let mut lines = vec![
        "# Upstream adoption review".to_owned(),
        String::new(),
        format!(
            "Status: **{}**; {} changes; {} removals.",
            text(report, "status")?,
            report["change_count"],
            report["removal_count"]
        ),
        String::new(),
        "## Source pins".to_owned(),
        String::new(),
        "```json".to_owned(),
        serde_json::to_string_pretty(&report["source_pins"])?,
        "```".to_owned(),
    ];
    let categories = report["changes"].as_object().ok_or("invalid changes")?;
    for category in CATEGORIES
        .into_iter()
        .chain(crate::resolved_report::CATEGORIES)
    {
        let Some(items) = categories.get(category) else {
            continue;
        };
        let mut title = category.replace('_', " ");
        if let Some(first) = title.get_mut(..1) {
            first.make_ascii_uppercase();
        }
        lines.extend([String::new(), format!("## {title}"), String::new()]);
        let items = items.as_array().ok_or("invalid category")?;
        if items.is_empty() {
            lines.push("No changes.".to_owned());
        }
        for item in items {
            let escaped = ascii_json(item)?;
            lines.extend([format!("    {escaped}"), String::new()]);
        }
    }
    Ok(format!("{}\n", lines.join("\n").trim_end()))
}
pub(crate) fn cli(args: &[String]) -> Result<i32> {
    let mut opts = BTreeMap::new();
    let mut it = args.iter();
    while let Some(k) = it.next() {
        if ![
            "--before",
            "--after",
            "--format",
            "--before-resolved",
            "--after-resolved",
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
    let before = Path::new(opts.get("--before").ok_or("--before is required")?);
    let after = Path::new(opts.get("--after").ok_or("--after is required")?);
    let (old, old_hashes) = load_snapshot(before)?;
    let (new, new_hashes) = load_snapshot(after)?;
    let mut report = build_report(&old, &new, &old_hashes, &new_hashes)?;
    match (opts.get("--before-resolved"), opts.get("--after-resolved")) {
        (Some(before), Some(after)) => {
            let old = crate::resolved_report::load_snapshot(Path::new(before))?;
            let new = crate::resolved_report::load_snapshot(Path::new(after))?;
            let resolved = crate::resolved_report::build_report(&old, &new)?;
            merge_resolved(&mut report, &resolved)?;
        },
        (None, None) => {},
        _ => return fail("both resolved snapshot directories are required"),
    }
    match opts.get("--format").copied().unwrap_or("json") {
        "json" => {
            let text = serde_json::to_string_pretty(&report)?;
            crate::upstream::check_cancelled()?;
            println!("{text}");
        },
        "markdown" => {
            let text = markdown(&report)?;
            crate::upstream::check_cancelled()?;
            print!("{text}");
        },
        _ => return fail("format must be json or markdown"),
    }
    Ok(i32::from(report["change_count"] != 0))
}

fn ascii_json(value: &Value) -> Result<String> {
    use std::fmt::Write as _;
    let mut escaped = String::new();
    for ch in serde_json::to_string(value)?.chars() {
        if ch.is_ascii() {
            escaped.push(ch);
        } else {
            for unit in ch.encode_utf16(&mut [0; 2]) {
                write!(escaped, "\\u{unit:04x}")?;
            }
        }
    }
    Ok(escaped)
}
