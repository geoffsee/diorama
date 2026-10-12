//! Independent configuration writer, HTTP policy, concurrency and socket expectations.
use super::{equal, load};
use crate::Result;
use serde_json::{Value, json};
use std::path::Path;

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}
fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or_else(|| "string missing".into())
}
fn keys(value: &Value, expected: &[&str]) -> Result<()> {
    let actual = value
        .as_object()
        .ok_or("object missing")?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    require(
        actual == expected.iter().copied().collect(),
        "field inventory differs",
    )
}
fn default_config() -> Value {
    json!({"apiVersion":"kubesolo.io/v1alpha1","kind":"Config","path":"/var/lib/kubesolo",
        "logging":{"debug":false,"pprof":false},"network":{"nodeIP":"","mtu":0,"disableIPv6":false,"loadBalancer":{"enabled":true,"ip":""}},
        "runtime":{"endpoint":""},"kubernetes":{"apiServer":{"startupTimeoutSeconds":600},"kubelet":{"cpuManager":{"policy":"none","reservedCPUs":""}}},
        "storage":{"dbWALRepair":false,"localPath":{"enabled":true,"sharedPath":""}},"portainer":{"async":false,"edgeID":"","edgeKey":"","image":"docker.io/portainer/agent:lts"},
        "d2k":{"enabled":false,"namespace":"d2k"},"metrics":{"enabled":false,"bindAddress":"127.0.0.1:9105"},"api":{"enabled":false,"socketPath":""}})
}
pub fn verify_file(records: &Value) -> Result<()> {
    require(
        records.as_array().is_some_and(|records| records.len() == 1),
        "one file record required",
    )?;
    let record = &records[0];
    for (key, value) in [
        ("target_mode", json!("0600")),
        ("ordinary_backup_mode", json!("0600")),
        ("backup_mode", json!("0400")),
        ("preexisting_backup_mode", json!("0644")),
        (
            "remaining_entries",
            json!(["config.yaml", "config.yaml.bak"]),
        ),
        ("backup_matches_first", json!(true)),
        ("failed_write_rejected", json!(true)),
        ("failed_write_preserves_original", json!(true)),
    ] {
        equal(&record[key], &value)?;
    }
    let first = text(&record["first"])?;
    require(
        first.contains("mtu: 0\n") && first.contains("edgeKey: fixture-synthetic-key"),
        "first config content differs",
    )?;
    equal(
        &record["second"],
        &json!(first.replace("mtu: 0\n", "mtu: 1400\n")),
    )
}
const SUCCESS: &[&str] = &[
    "get",
    "show-secrets",
    "schema",
    "patch-current-etag",
    "patch-null",
    "validate",
    "put-replacement",
    "delete-defaults",
    "after-concurrent-patches",
    "health",
    "no-op-patch",
];
const FAILURES: &[(&str, u16)] = &[
    ("patch-stale-etag", 412),
    ("immutable", 409),
    ("invalid", 422),
    ("malformed-patch", 400),
    ("malformed-put", 400),
    ("wrong-type", 400),
    ("wrong-content", 415),
    ("redacted-write", 400),
    ("oversized", 400),
    ("validate-invalid", 422),
];
fn verify_requests(requests: &Value) -> Result<()> {
    keys(
        requests,
        &SUCCESS
            .iter()
            .copied()
            .chain(FAILURES.iter().map(|(name, _)| *name))
            .collect::<Vec<_>>(),
    )?;
    for (name, status) in SUCCESS
        .iter()
        .map(|name| (*name, 200))
        .chain(FAILURES.iter().copied())
    {
        let request = &requests[name];
        equal(&request["status"], &json!(status))?;
        if name == "health" {
            equal(&request["body"], &json!("ok\n"))?;
            equal(&request["raw_body"], &json!("ok\n"))?;
        } else {
            equal(
                &crate::json::parse(text(&request["raw_body"])?.as_bytes())?,
                &request["body"],
            )?;
        }
    }
    Ok(())
}
fn verify_schema(settings: &Value) -> Result<()> {
    let settings = settings.as_array().ok_or("settings array")?;
    let expected = "api.enabled api.socketPath d2k.enabled d2k.namespace kubernetes.apiServer.extraSANs kubernetes.apiServer.startupTimeoutSeconds kubernetes.kubelet.cpuManager.policy kubernetes.kubelet.cpuManager.policyOptions kubernetes.kubelet.cpuManager.reservedCPUs kubernetes.kubelet.systemReserved kubernetes.nodeName logging.debug logging.pprof metrics.bindAddress metrics.enabled network.disableIPv6 network.loadBalancer.enabled network.loadBalancer.ip network.mtu network.nodeIP path portainer.async portainer.edgeID portainer.edgeKey portainer.image runtime.containerMode runtime.endpoint storage.dbWALRepair storage.localPath.enabled storage.localPath.sharedPath".split_whitespace().collect::<std::collections::BTreeSet<_>>();
    let actual = settings
        .iter()
        .map(|setting| text(&setting["path"]))
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    require(
        settings.len() == 30 && actual == expected,
        "settings inventory differs",
    )?;
    for setting in settings {
        if setting["path"] == "path" {
            equal(&setting["mutability"], &json!("immutable"))?;
        }
        if setting["path"] == "portainer.edgeKey" {
            equal(&setting["secret"], &json!(true))?;
        }
    }
    Ok(())
}
fn config_etag(raw: &str) -> Result<String> {
    // Go emits the config field first in compact struct order. Parse its exact
    // object boundary while hashing the original bytes, never sorted map keys.
    let config = raw
        .strip_prefix("{\"config\":")
        .ok_or("raw config prefix")?;
    let mut stream = serde_json::Deserializer::from_str(config).into_iter::<Value>();
    let value = stream.next().ok_or("config missing")??;
    require(value.is_object(), "config object missing")?;
    let end = stream.byte_offset();
    Ok(format!("\"{}\"", crate::sha256(&config.as_bytes()[..end])))
}
pub fn verify_api(records: &Value) -> Result<()> {
    require(
        records.as_array().is_some_and(|records| records.len() == 1),
        "one API record required",
    )?;
    let api = &records[0];
    equal(&api["socket_mode"], &json!("0600"))?;
    equal(&api["effective_node_ip"], &json!("192.0.2.99"))?;
    let checks = [
        "validate_does_not_write",
        "rejected_requests_do_not_write",
        "live_socket_refused",
        "shutdown_removes_socket",
        "stale_socket_reclaimed",
        "stale_socket_removed",
        "regular_file_refused",
        "regular_file_preserved",
    ];
    keys(&api["checks"], &checks)?;
    for key in checks {
        equal(&api["checks"][key], &json!(true))?;
    }
    let requests = &api["requests"];
    verify_requests(requests)?;
    verify_transitions(requests)?;
    verify_schema(&requests["schema"]["body"]["settings"])
}
fn verify_transitions(requests: &Value) -> Result<()> {
    let mut current = default_config();
    current["network"]["nodeIP"] = json!("192.0.2.10");
    current["d2k"]["namespace"] = json!("workloads");
    current["portainer"]["edgeKey"] = json!("***");
    equal(
        &requests["get"]["body"],
        &json!({"config":current,"restartRequired":false}),
    )?;
    let mut revealed = current.clone();
    revealed["portainer"]["edgeKey"] = json!("fixture-synthetic-key");
    equal(&requests["show-secrets"]["body"]["config"], &revealed)?;
    let tag = config_etag(text(&requests["show-secrets"]["raw_body"])?)?;
    equal(&requests["get"]["etag"], &json!(tag))?;
    equal(&requests["show-secrets"]["etag"], &json!(tag))?;
    current["network"]["mtu"] = json!(1400);
    let patch = &requests["patch-current-etag"];
    equal(&patch["body"]["config"], &current)?;
    require(
        patch["etag"].is_string() && patch["etag"] != tag,
        "patch ETag must change",
    )?;
    equal(&patch["body"]["changed"], &json!(["network.mtu"]))?;
    equal(&patch["body"]["requiresRestart"], &json!(["network.mtu"]))?;
    equal(&patch["body"]["restartRequired"], &json!(true))?;
    current["d2k"]["namespace"] = json!("d2k");
    equal(&requests["patch-null"]["body"]["config"], &current)?;
    equal(&requests["immutable"]["body"]["field"], &json!("path"))?;
    require(
        text(&requests["redacted-write"]["body"]["error"])?.contains("portainer.edgeKey"),
        "redacted error differs",
    )?;
    require(
        text(&requests["oversized"]["body"]["error"])?.contains("request body too large"),
        "oversize error differs",
    )?;
    let mut replacement = default_config();
    replacement["network"]["mtu"] = json!(1450);
    equal(&requests["put-replacement"]["body"]["config"], &replacement)?;
    equal(
        &requests["delete-defaults"]["body"]["config"],
        &default_config(),
    )?;
    let mut concurrent = default_config();
    concurrent["network"]["mtu"] = json!(1400);
    concurrent["logging"]["debug"] = json!(true);
    equal(
        &requests["after-concurrent-patches"]["body"]["config"],
        &concurrent,
    )?;
    equal(
        &requests["no-op-patch"]["body"],
        &json!({"config":concurrent,"restartRequired":false}),
    )
}
pub fn expected(component: &str) -> Result<Value> {
    require(
        ["config", "configapi"].contains(&component),
        "unknown config component",
    )?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../parity/fixtures/config-api");
    let filename = format!("{component}.json");
    let bytes = crate::read_bounded(&root.join(&filename), super::LIMIT)?;
    let provenance = load(&root.join("provenance.json"))?;
    equal(
        &json!(crate::sha256(&bytes)),
        &provenance["durable_sha256"][&filename],
    )?;
    let records = crate::json::parse(&bytes)?;
    if component == "config" {
        verify_file(&records)?;
    } else {
        verify_api(&records)?;
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn historical_file_and_http_records_match_independent_policy() -> Result<()> {
        expected("config")?;
        expected("configapi")?;
        Ok(())
    }
    #[test]
    fn historical_raw_records_and_surviving_inputs_match_provenance() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../parity/fixtures/config-api");
        let provenance = load(&root.join("provenance.json"))?;
        for name in [
            "Capture.Dockerfile",
            "api_capture_test.go",
            "file_capture_test.go",
            "capture-receipt.json",
            "config.json",
            "configapi.json",
            "evidence/config.log",
            "evidence/configapi.log",
        ] {
            equal(
                &json!(crate::sha256(&crate::read_bounded(
                    &root.join(name),
                    super::super::LIMIT
                )?)),
                &provenance["durable_sha256"][name],
            )?;
        }
        for component in ["config", "configapi"] {
            let raw = crate::read_bounded(
                &root.join(format!("evidence/{component}.log")),
                super::super::LIMIT,
            )?;
            let records = std::str::from_utf8(&raw)?
                .lines()
                .filter_map(|line| line.strip_prefix("DIORAMA_CAPTURE "))
                .map(|line| crate::json::parse(line.as_bytes()))
                .collect::<Result<Vec<_>>>()?;
            equal(&json!(records), &expected(component)?)?;
        }
        Ok(())
    }
    #[test]
    fn rejects_numeric_boolean_raw_drift_secrets_lost_updates_etags_and_socket_leaks() -> Result<()>
    {
        for (pointer, replacement) in [
            ("/0/requests/get/body/config/logging/debug", json!(0)),
            ("/0/requests/patch-stale-etag/status", json!(200)),
            (
                "/0/requests/get/body/config/portainer/edgeKey",
                json!("fixture-synthetic-key"),
            ),
            (
                "/0/requests/after-concurrent-patches/body/config/logging/debug",
                json!(false),
            ),
            ("/0/checks/shutdown_removes_socket", json!(false)),
            ("/0/requests/get/etag", json!("wrong")),
        ] {
            let mut changed = expected("configapi")?;
            *changed.pointer_mut(pointer).ok_or("mutation path")? = replacement;
            for name in ["get", "after-concurrent-patches"] {
                changed[0]["requests"][name]["raw_body"] = json!(serde_json::to_string(
                    &changed[0]["requests"][name]["body"]
                )?);
            }
            assert!(verify_api(&changed).is_err(), "accepted {pointer}");
        }
        let mut changed = expected("configapi")?;
        changed[0]["requests"]["get"]["raw_body"] = json!(
            text(&changed[0]["requests"]["get"]["raw_body"])?
                .replace("\"debug\":false", "\"debug\":0")
        );
        assert!(verify_api(&changed).is_err());
        let mut changed = expected("config")?;
        changed[0]["failed_write_preserves_original"] = json!(false);
        assert!(verify_file(&changed).is_err());
        Ok(())
    }
}
