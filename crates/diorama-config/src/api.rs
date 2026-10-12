//! Configuration API serialization, RFC 7386 merge-patch, diffing, and redaction.

use sha2::{Digest, Sha256};

use crate::{Config, ConfigError, ErrorKind};

/// Exact traversal order of fields matching the Go struct field definitions.
pub const STRUCT_FIELD_PATHS: &[&str] = &[
    "path",
    "logging.debug",
    "logging.pprof",
    "network.nodeIP",
    "network.mtu",
    "network.disableIPv6",
    "network.loadBalancer.enabled",
    "network.loadBalancer.ip",
    "runtime.endpoint",
    "runtime.containerMode",
    "kubernetes.nodeName",
    "kubernetes.apiServer.extraSANs",
    "kubernetes.apiServer.startupTimeoutSeconds",
    "kubernetes.kubelet.cpuManager.policy",
    "kubernetes.kubelet.cpuManager.policyOptions",
    "kubernetes.kubelet.cpuManager.reservedCPUs",
    "kubernetes.kubelet.systemReserved",
    "storage.localPath.enabled",
    "storage.localPath.sharedPath",
    "storage.dbWALRepair",
    "portainer.edgeID",
    "portainer.edgeKey",
    "portainer.async",
    "portainer.image",
    "d2k.enabled",
    "d2k.namespace",
    "metrics.enabled",
    "metrics.bindAddress",
    "api.enabled",
    "api.socketPath",
];

/// Computes the list of modified fields between two configurations in struct field order.
#[must_use]
pub fn diff_configs(old: &Config, new: &Config) -> Vec<String> {
    let old_val = serde_json::to_value(old).unwrap_or(serde_json::Value::Null);
    let new_val = serde_json::to_value(new).unwrap_or(serde_json::Value::Null);

    let mut changed = Vec::new();
    for &path in STRUCT_FIELD_PATHS {
        let pointer = format!("/{}", path.replace('.', "/"));
        let old_field = old_val.pointer(&pointer);
        let new_field = new_val.pointer(&pointer);
        if old_field != new_field {
            changed.push(path.to_string());
        }
    }
    changed
}

/// Applies an RFC 7386 JSON Merge Patch to `current`, where `null` values restore field defaults.
pub fn apply_merge_patch(
    current: &Config,
    patch: &serde_json::Value,
) -> Result<Config, ConfigError> {
    if !patch.is_object() {
        return Err(ConfigError {
            kind: ErrorKind::Syntax,
            path: String::new(),
            message: "patch is not valid JSON".to_string(),
        });
    }

    let mut current_val = serde_json::to_value(current).map_err(|e| ConfigError {
        kind: ErrorKind::Type,
        path: String::new(),
        message: e.to_string(),
    })?;

    let default_val = serde_json::to_value(Config::default()).map_err(|e| ConfigError {
        kind: ErrorKind::Type,
        path: String::new(),
        message: e.to_string(),
    })?;

    merge_patch_values(&mut current_val, patch, &default_val);

    serde_json::from_value::<Config>(current_val).map_err(|e| ConfigError {
        kind: ErrorKind::Type,
        path: String::new(),
        message: format!("body is not a valid configuration document: {e}"),
    })
}

/// Applies a full PUT document replacement starting from defaults, preserving `stored.path` if omitted.
pub fn apply_put_replacement(
    stored: &Config,
    put: &serde_json::Value,
) -> Result<Config, ConfigError> {
    if !put.is_object() {
        return Err(ConfigError {
            kind: ErrorKind::Syntax,
            path: String::new(),
            message: "body is not a valid configuration document".to_string(),
        });
    }

    let mut candidate_val = serde_json::to_value(Config::default()).map_err(|e| ConfigError {
        kind: ErrorKind::Type,
        path: String::new(),
        message: e.to_string(),
    })?;

    // If path was omitted from the PUT document, retain stored.path
    if put.get("path").is_none()
        && let Some(map) = candidate_val.as_object_mut()
    {
        map.insert(
            "path".to_string(),
            serde_json::Value::String(stored.path.clone()),
        );
    }

    merge_patch_values(&mut candidate_val, put, &serde_json::Value::Null);

    serde_json::from_value::<Config>(candidate_val).map_err(|e| ConfigError {
        kind: ErrorKind::Type,
        path: String::new(),
        message: format!("body is not a valid configuration document: {e}"),
    })
}

fn merge_patch_values(
    target: &mut serde_json::Value,
    patch: &serde_json::Value,
    defaults: &serde_json::Value,
) {
    if let serde_json::Value::Object(patch_map) = patch {
        // RFC 7386: an object patch first replaces a non-object target with an
        // empty object. Optional configuration maps initially serialize as null.
        if !target.is_object() {
            *target = serde_json::Value::Object(serde_json::Map::new());
        }
        let target_map = target
            .as_object_mut()
            .expect("object target established above");
        let default_map = defaults.as_object();
        for (key, patch_v) in patch_map {
            if patch_v.is_null() {
                if let Some(def_v) = default_map.and_then(|d| d.get(key)) {
                    target_map.insert(key.clone(), def_v.clone());
                } else {
                    target_map.remove(key);
                }
            } else if patch_v.is_object() {
                let def_sub = default_map
                    .and_then(|d| d.get(key))
                    .unwrap_or(&serde_json::Value::Null);
                let target_entry = target_map
                    .entry(key.clone())
                    .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
                merge_patch_values(target_entry, patch_v, def_sub);
            } else {
                target_map.insert(key.clone(), patch_v.clone());
            }
        }
    }
}

/// Checks if any secret field (such as `portainer.edgeKey`) is sent back as `"***"`.
#[must_use]
pub fn has_redacted_secrets(value: &serde_json::Value) -> bool {
    value
        .pointer("/portainer/edgeKey")
        .is_some_and(|v| v == "***")
}

/// Redacts non-empty sensitive fields in `config` in-place.
pub fn redact_secrets(config: &mut Config) {
    if !config.portainer.edge_key.is_empty() {
        config.portainer.edge_key = "***".to_string();
    }
}

/// Serializes `Config` to JSON in Go struct order with omitted optional empty fields.
#[must_use]
pub fn serialize_api_config(config: &Config) -> String {
    let mut out = String::new();
    out.push_str("{\"apiVersion\":");
    out.push_str(&serde_json::to_string(&config.api_version).unwrap());
    out.push_str(",\"kind\":");
    out.push_str(&serde_json::to_string(&config.kind).unwrap());
    out.push_str(",\"path\":");
    out.push_str(&serde_json::to_string(&config.path).unwrap());
    out.push_str(",\"logging\":{\"debug\":");
    out.push_str(if config.logging.debug {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"pprof\":");
    out.push_str(if config.logging.pprof {
        "true"
    } else {
        "false"
    });
    out.push_str("},\"network\":{\"nodeIP\":");
    out.push_str(&serde_json::to_string(&config.network.node_ip).unwrap());
    out.push_str(",\"mtu\":");
    out.push_str(&config.network.mtu.to_string());
    out.push_str(",\"disableIPv6\":");
    out.push_str(if config.network.disable_ipv6 {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"loadBalancer\":{\"enabled\":");
    out.push_str(if config.network.load_balancer.enabled {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"ip\":");
    out.push_str(&serde_json::to_string(&config.network.load_balancer.ip).unwrap());
    out.push_str("}},\"runtime\":{\"endpoint\":");
    out.push_str(&serde_json::to_string(&config.runtime.endpoint).unwrap());
    if let Some(cm) = config.runtime.container_mode {
        out.push_str(",\"containerMode\":");
        out.push_str(if cm { "true" } else { "false" });
    }
    out.push_str("},\"kubernetes\":{");
    out.push_str(&serialize_kubernetes(config));
    out.push('}');
    out.push_str(&serialize_storage_and_addons(config));
    out
}

fn serialize_kubernetes(config: &Config) -> String {
    let mut k_parts = Vec::new();
    if !config.kubernetes.node_name.is_empty() {
        k_parts.push(format!(
            "\"nodeName\":{}",
            serde_json::to_string(&config.kubernetes.node_name).unwrap()
        ));
    }
    let mut api_parts = Vec::new();
    if let Some(ref sans) = config.kubernetes.api_server.extra_sans
        && !sans.is_empty()
    {
        api_parts.push(format!(
            "\"extraSANs\":{}",
            serde_json::to_string(sans).unwrap()
        ));
    }
    api_parts.push(format!(
        "\"startupTimeoutSeconds\":{}",
        config.kubernetes.api_server.startup_timeout_seconds
    ));
    k_parts.push(format!("\"apiServer\":{{{}}}", api_parts.join(",")));

    let mut cpu_parts = Vec::new();
    cpu_parts.push(format!(
        "\"policy\":{}",
        serde_json::to_string(&config.kubernetes.kubelet.cpu_manager.policy).unwrap()
    ));
    if let Some(ref opts) = config.kubernetes.kubelet.cpu_manager.policy_options
        && !opts.is_empty()
    {
        cpu_parts.push(format!(
            "\"policyOptions\":{}",
            serde_json::to_string(opts).unwrap()
        ));
    }
    cpu_parts.push(format!(
        "\"reservedCPUs\":{}",
        serde_json::to_string(&config.kubernetes.kubelet.cpu_manager.reserved_cpus).unwrap()
    ));
    let mut kubelet_parts = Vec::new();
    kubelet_parts.push(format!("\"cpuManager\":{{{}}}", cpu_parts.join(",")));
    if let Some(ref sys) = config.kubernetes.kubelet.system_reserved
        && !sys.is_empty()
    {
        kubelet_parts.push(format!(
            "\"systemReserved\":{}",
            serde_json::to_string(sys).unwrap()
        ));
    }
    k_parts.push(format!("\"kubelet\":{{{}}}", kubelet_parts.join(",")));
    k_parts.join(",")
}

fn serialize_storage_and_addons(config: &Config) -> String {
    let mut out = String::new();
    out.push_str(",\"storage\":{\"localPath\":{\"enabled\":");
    out.push_str(if config.storage.local_path.enabled {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"sharedPath\":");
    out.push_str(&serde_json::to_string(&config.storage.local_path.shared_path).unwrap());
    out.push_str("},\"dbWALRepair\":");
    out.push_str(if config.storage.db_wal_repair {
        "true"
    } else {
        "false"
    });
    out.push_str("},\"portainer\":{\"edgeID\":");
    out.push_str(&serde_json::to_string(&config.portainer.edge_id).unwrap());
    out.push_str(",\"edgeKey\":");
    out.push_str(&serde_json::to_string(&config.portainer.edge_key).unwrap());
    out.push_str(",\"async\":");
    out.push_str(if config.portainer.asynchronous {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"image\":");
    out.push_str(&serde_json::to_string(&config.portainer.image).unwrap());
    out.push_str("},\"d2k\":{\"enabled\":");
    out.push_str(if config.d2k.enabled { "true" } else { "false" });
    out.push_str(",\"namespace\":");
    out.push_str(&serde_json::to_string(&config.d2k.namespace).unwrap());
    out.push_str("},\"metrics\":{\"enabled\":");
    out.push_str(if config.metrics.enabled {
        "true"
    } else {
        "false"
    });
    out.push_str(",\"bindAddress\":");
    out.push_str(&serde_json::to_string(&config.metrics.bind_address).unwrap());
    out.push_str("},\"api\":{\"enabled\":");
    out.push_str(if config.api.enabled { "true" } else { "false" });
    out.push_str(",\"socketPath\":");
    out.push_str(&serde_json::to_string(&config.api.socket_path).unwrap());
    out.push_str("}}");
    out
}

/// Computes the unredacted configuration `ETag` as `"<sha256>"`.
#[must_use]
pub fn compute_etag(config: &Config) -> String {
    let json = serialize_api_config(config);
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let hash = hasher.finalize();
    let mut hex = String::with_capacity(66);
    hex.push('"');
    for byte in hash {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex.push('"');
    hex
}

/// Formats the JSON response body with `config` leading, followed by `changed`, `requiresRestart`, and `restartRequired`.
#[must_use]
pub fn format_api_response(config: &Config, changed: &[String]) -> String {
    let config_json = serialize_api_config(config);
    let mut out = String::from("{\"config\":");
    out.push_str(&config_json);
    if changed.is_empty() {
        out.push_str(",\"restartRequired\":false}\n");
    } else {
        out.push_str(",\"changed\":");
        out.push_str(&serde_json::to_string(changed).unwrap());
        out.push_str(",\"requiresRestart\":");
        out.push_str(&serde_json::to_string(changed).unwrap());
        out.push_str(",\"restartRequired\":true}\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_patch_restores_defaults_on_null() {
        let mut initial = Config::default();
        initial.network.node_ip = "192.0.2.10".into();
        initial.d2k.namespace = "workloads".into();

        let patch = serde_json::json!({
            "d2k": { "namespace": null },
            "network": { "mtu": 1400 }
        });

        let updated = apply_merge_patch(&initial, &patch).unwrap();
        assert_eq!(updated.d2k.namespace, "d2k");
        assert_eq!(updated.network.mtu, 1400);
        assert_eq!(updated.network.node_ip, "192.0.2.10");

        let changed = diff_configs(&initial, &updated);
        assert_eq!(changed, vec!["network.mtu", "d2k.namespace"]);
    }

    #[test]
    fn detects_redacted_secrets() {
        let patch = serde_json::json!({
            "portainer": { "edgeKey": "***" }
        });
        assert!(has_redacted_secrets(&patch));

        let ok_patch = serde_json::json!({
            "portainer": { "edgeKey": "real-key" }
        });
        assert!(!has_redacted_secrets(&ok_patch));
    }
}

#[cfg(test)]
mod merge_regressions {
    use super::*;

    #[test]
    fn object_patches_populate_null_maps_for_patch_and_put() {
        let initial = Config::default();
        let value = serde_json::json!({"kubernetes":{"kubelet":{
            "systemReserved":{"cpu":"100m"},
            "cpuManager":{"policyOptions":{"full-pcpus-only":"true"}}
        }}});
        for candidate in [
            apply_merge_patch(&initial, &value),
            apply_put_replacement(&initial, &value),
        ] {
            let candidate = candidate.unwrap();
            assert_eq!(
                candidate.kubernetes.kubelet.system_reserved.unwrap()["cpu"],
                "100m"
            );
            assert_eq!(
                candidate
                    .kubernetes
                    .kubelet
                    .cpu_manager
                    .policy_options
                    .unwrap()["full-pcpus-only"],
                "true"
            );
        }
    }

    #[test]
    fn patch_removes_map_members_and_rejects_object_for_scalar_fields() {
        let populated = apply_merge_patch(
            &Config::default(),
            &serde_json::json!({
                "kubernetes":{"kubelet":{"systemReserved":{"cpu":"100m","memory":"64Mi"}}}
            }),
        )
        .unwrap();
        let patched = apply_merge_patch(
            &populated,
            &serde_json::json!({
                "kubernetes":{"kubelet":{"systemReserved":{"cpu":null}}}
            }),
        )
        .unwrap();
        let map = patched.kubernetes.kubelet.system_reserved.unwrap();
        assert!(!map.contains_key("cpu"));
        assert_eq!(map["memory"], "64Mi");
        assert!(
            apply_merge_patch(
                &Config::default(),
                &serde_json::json!({"logging":{"debug":{}}})
            )
            .is_err()
        );
    }
}
