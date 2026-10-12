//! Independent official API JSON expectations and evidence validation.
use crate::{Result, json, read_bounded, sha256};
use serde_json::{Value, json as value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
pub(crate) mod scenario;
#[cfg(test)]
mod tests;
pub fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../api-json")
}
pub fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
pub fn load(path: &Path) -> Result<Value> {
    json::parse(&read_bounded(path, 8 * 1024 * 1024)?)
}
/// Only four server-owned, top-level metadata fields are volatile.
pub fn normalize(resource: &Value) -> Value {
    let mut result = resource.clone();
    if let Some(metadata) = result.get_mut("metadata").and_then(Value::as_object_mut) {
        for key in [
            "uid",
            "resourceVersion",
            "creationTimestamp",
            "managedFields",
        ] {
            metadata.remove(key);
        }
    }
    result
}
pub fn verify(fixture: &Value) -> Result<()> {
    let cases = fixture["cases"].as_object().ok_or("API cases missing")?;
    require(
        cases.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == BTreeSet::from([
                "pod-create",
                "pod-read",
                "service-create",
                "service-read",
                "custom-create",
                "custom-read",
            ]),
        "API case inventory",
    )?;
    require(fixture["schema_version"] == 1, "API fixture schema")?;
    for kind in ["pod", "service", "custom"] {
        require(
            cases[&format!("{kind}-create")] == cases[&format!("{kind}-read")],
            "create/read typed equality",
        )?;
    }
    let pod = &cases["pod-read"];
    let metadata = pod["metadata"].as_object().ok_or("pod metadata")?;
    require(
        metadata.get("name") == Some(&value!("quantities"))
            && metadata.get("namespace") == Some(&value!("serialization-fixture")),
        "pod identity",
    )?;
    require(
        pod["metadata"]["labels"] == value!({"fixture":"json"})
            && pod["metadata"]["annotations"] == value!({"example.test/text":"literal: null"}),
        "pod metadata values",
    )?;
    require(
        !metadata.contains_key("finalizers") && !metadata.contains_key("ownerReferences"),
        "omitted pod metadata",
    )?;
    let spec = pod["spec"].as_object().ok_or("pod spec")?;
    require(
        !spec.contains_key("nodeSelector")
            && !spec.contains_key("volumes")
            && pod["spec"]["automountServiceAccountToken"] == false,
        "pod omitted fields and token automount",
    )?;
    require(
        pod["spec"]["containers"][0]["resources"]
            == value!({"requests":{"cpu":"500m","memory":"1536Mi","ephemeral-storage":"1e3"},"limits":{"cpu":"1","memory":"2Gi"}}),
        "canonical quantities",
    )?;
    let service = &cases["service-read"];
    require(
        service["spec"]["ports"][0]["targetPort"] == "http"
            && service["spec"]["ports"][1]["targetPort"] == 8080,
        "typed service target ports",
    )?;
    require(
        !service["metadata"]
            .as_object()
            .ok_or("service metadata")?
            .contains_key("annotations"),
        "omitted service annotations",
    )?;
    require(
        cases["custom-read"]["spec"]
            == value!({"unknown":{"metadata":{"uid":"user-value"},"null":null,"bool":false,"integer":17,"decimal":1.25,"list":[null,true,"7",7,{"nested":"value"}]}}),
        "arbitrary CRD typed values",
    )?;
    let watch = fixture["watch"].as_array().ok_or("watch events")?;
    require(watch.len() == 3, "watch inventory")?;
    for (event, (kind, data)) in watch.iter().zip([
        ("ADDED", "first"),
        ("MODIFIED", "second"),
        ("DELETED", "second"),
    ]) {
        require(
            event["type"] == kind
                && event["object"]["kind"] == "ConfigMap"
                && event["object"]["apiVersion"] == "v1"
                && event["object"]["metadata"]["name"] == "watched"
                && event["object"]["data"] == value!({"value":data}),
            "watch event type and latest value",
        )?;
    }
    Ok(())
}
pub fn reviewed() -> Result<Value> {
    let dir = directory();
    let raw = read_bounded(&dir.join("fixtures.json"), 8 * 1024 * 1024)?;
    require(
        load(&dir.join("provenance.json"))?["durable_sha256"]["fixtures.json"] == sha256(&raw),
        "reviewed frozen fixture hash mismatch",
    )?;
    let fixture = json::parse(&raw)?;
    verify(&fixture)?;
    Ok(fixture)
}
pub fn verify_raw(fixture: &Value, result: &Value) -> Result<()> {
    verify(fixture)?;
    require(
        result["status"] == "passed"
            && result.get("error").is_none()
            && result.get("cleanup_error").is_none(),
        "component capture failed",
    )?;
    require(
        result["fixture"] == *fixture,
        "recorded fixture disagreement",
    )?;
    verify_shutdown_and_tls(result)?;
    let expected = BTreeMap::from([
        ("anonymous-denied", 401),
        ("rbac-denied", 403),
        ("namespace", 201),
        ("service-account", 201),
        ("pod-create", 201),
        ("pod-read", 200),
        ("service-create", 201),
        ("service-read", 200),
        ("crd-create", 201),
        ("crd-ready", 200),
        ("custom-create", 201),
        ("custom-read", 200),
        ("watch-before", 200),
        ("watch-create", 201),
        ("watch-update", 200),
        ("watch-delete", 200),
    ]);
    let mut records = BTreeMap::new();
    for row in result["http"].as_array().ok_or("raw HTTP observations")? {
        let name = row["name"].as_str().ok_or("HTTP name")?;
        require(
            expected.get(name).copied() == row["status"].as_i64(),
            "unexpected HTTP status",
        )?;
        require(
            !records.contains_key(name) || name == "crd-ready",
            "duplicate HTTP scenario",
        )?;
        require(
            json::parse(
                row["raw_response"]
                    .as_str()
                    .ok_or("raw HTTP response")?
                    .as_bytes(),
            )? == row["response"],
            "raw HTTP and parsed observation disagree",
        )?;
        records.insert(name, row);
    }
    require(
        records.keys().eq(expected.keys()),
        "HTTP scenario inventory",
    )?;
    for (name, expected) in fixture["cases"].as_object().ok_or("fixture cases")? {
        require(
            normalize(&records[name.as_str()]["response"]) == *expected,
            "raw resource does not reproduce fixture",
        )?;
    }
    let lines = result["raw_watch_lines"]
        .as_array()
        .ok_or("raw watch lines")?;
    require(lines.len() == 3, "raw watch inventory")?;
    let events = lines
        .iter()
        .map(|line| {
            let event = json::parse(line.as_str().ok_or("watch line type")?.as_bytes())?;
            Ok(value!({"type":event["type"],"object":normalize(&event["object"])}))
        })
        .collect::<Result<Vec<_>>>()?;
    require(
        value!(events) == fixture["watch"],
        "raw watch does not reproduce fixture",
    )
}
pub fn check_capture(directory: &Path) -> Result<Value> {
    let fixture = load(&directory.join("fixtures.json"))?;
    let result = load(&directory.join("result.json"))?;
    let runner = load(&directory.join("runner-result.json"))?;
    let expected = reviewed()?;
    require(
        fixture == expected,
        "fresh fixture differs from reviewed complete fixture",
    )?;
    verify_raw(&fixture, &result)?;
    require(
        runner["schema_version"] == 2 && result["schema_version"] == 2,
        "current Rust capture receipt required",
    )?;
    require(result["cancelled"] == false, "runtime cancelled")?;
    crate::component_boundary::verify_runner_commands(directory, &runner)?;
    require(
        runner["exit_code"].as_i64() == Some(0)
            && runner["errors"] == value!([])
            && runner["cancelled"] == false,
        "runner execution or cleanup failed",
    )?;
    require(
        runner["remaining_containers"] == value!([])
            && runner["remaining_images"] == value!([])
            && runner["process_cleanup_complete"] == true,
        "owned cleanup unconfirmed",
    )?;
    let root = crate::repository_root(&self::directory())?;
    let sources = crate::component_boundary::source_inventory(&root, "api-json")?;
    require(
        runner["source_sha256"] == sources && result["source_sha256"] == sources,
        "runner or executed source hashes differ from current source",
    )?;
    require(
        result["inputs"] == load(&self::directory().join("inputs.json"))?,
        "component input pins differ",
    )?;
    require(
        matches!(result["architecture"].as_str(), Some("arm64" | "amd64")),
        "unknown architecture",
    )?;
    require(
        result["kernel"].as_str().is_some_and(|s| !s.is_empty()),
        "missing environment kernel",
    )?;
    let checks = result["checks"]
        .as_array()
        .ok_or("missing runtime checks")?;
    for name in ["kube-apiserver", "kine"] {
        require(
            checks.contains(&value!(format!("runtime digest {name}"))),
            "runtime digest check absent",
        )?;
    }
    Ok(
        value!({"status":"verified","architecture":result["architecture"],"resource_documents":6,"watch_events":3,"fixture_sha256":sha256(&read_bounded(&directory.join("fixtures.json"), 8 * 1024 * 1024)?)}),
    )
}

fn verify_shutdown_and_tls(result: &Value) -> Result<()> {
    let shutdowns = result["shutdowns"].as_array().ok_or("shutdown records")?;
    require(
        shutdowns.len() == 2
            && shutdowns
                .iter()
                .filter_map(|s| s["component"].as_str())
                .collect::<BTreeSet<_>>()
                == BTreeSet::from(["kube-apiserver", "kine"]),
        "component shutdown inventory",
    )?;
    for row in shutdowns {
        require(
            row["exit_code"].as_i64() == Some(0)
                && row["forced"] == false
                && row["owned_group_remained"] == false
                && row.get("error") == Some(&Value::Null),
            "unclean component shutdown",
        )?;
    }
    let tls = result["datastore_tls"]
        .as_array()
        .ok_or("datastore TLS probes")?;
    require(
        tls.len() == 2
            && tls
                .iter()
                .filter_map(|s| s["identity"].as_str())
                .collect::<BTreeSet<_>>()
                == BTreeSet::from(["absent", "admin"]),
        "dedicated datastore TLS negatives",
    )?;
    for row in tls {
        let expected = if row["identity"] == "absent" {
            "alert handshake failure"
        } else {
            "alert unknown ca"
        };
        require(
            row["exit_code"].as_i64() == Some(1)
                && row["diagnostic"]
                    .as_str()
                    .is_some_and(|s| s.to_lowercase().contains(expected)),
            "TLS negative failed for unexpected reason",
        )?;
    }
    Ok(())
}
