//! `ResourceQuota` accounting shared by the quota controller and admission.
//!
//! Quantities are handled in milli-units so CPU (`500m`) and byte counts
//! (`1Gi`) share one integer representation.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

/// Parses a Kubernetes quantity into milli-units (`1` -> 1000, `500m` -> 500).
#[must_use]
pub fn parse_quantity_milli(raw: &str) -> Option<i128> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '+' || c == '-'))
        .unwrap_or(s.len());
    let (num, suffix) = s.split_at(split);
    let (mantissa, scale_num, scale_den): (&str, i128, i128) = match suffix {
        "" => (num, 1000, 1),
        "m" => (num, 1, 1),
        "u" => (num, 1, 1000),
        "n" => (num, 1, 1_000_000),
        "k" => (num, 1_000_000, 1),
        "M" => (num, 1_000_000_000, 1),
        "G" => (num, 1_000_000_000_000, 1),
        "T" => (num, 1_000_000_000_000_000, 1),
        "P" => (num, 1_000_000_000_000_000_000, 1),
        "E" => (num, 1_000_000_000_000_000_000_000, 1),
        "Ki" => (num, 1000 << 10, 1),
        "Mi" => (num, 1000 << 20, 1),
        "Gi" => (num, 1000 << 30, 1),
        "Ti" => (num, 1000 << 40, 1),
        "Pi" => (num, 1000 << 50, 1),
        "Ei" => (num, 1000 << 60, 1),
        other => {
            // Decimal exponent form, e.g. `1e3`.
            let exp: u32 = other
                .strip_prefix('e')
                .or_else(|| other.strip_prefix('E'))?
                .parse()
                .ok()?;
            (num, 1000 * 10_i128.checked_pow(exp)?, 1)
        },
    };
    let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let negative = int_part.starts_with('-');
    let int_digits = int_part.trim_start_matches(['+', '-']);
    let int_val: i128 = if int_digits.is_empty() {
        0
    } else {
        int_digits.parse().ok()?
    };
    let mut value = int_val.checked_mul(scale_num)?;
    if !frac_part.is_empty() {
        let frac: i128 = frac_part.parse().ok()?;
        let denom = 10_i128.checked_pow(u32::try_from(frac_part.len()).ok()?)?;
        // Round fractional milli-units up, like upstream's ceiling on scale.
        value += (frac * scale_num + denom - 1) / denom;
    }
    value = (value + scale_den - 1) / scale_den;
    Some(if negative { -value } else { value })
}

/// Formats milli-units back into a canonical quantity string.
#[must_use]
pub fn format_milli(value: i128) -> String {
    if value % 1000 == 0 {
        (value / 1000).to_string()
    } else {
        format!("{value}m")
    }
}

fn quantity(v: &Value) -> Option<i128> {
    match v {
        Value::String(s) => parse_quantity_milli(s),
        Value::Number(n) => n.as_i64().map(|n| i128::from(n) * 1000),
        _ => None,
    }
}

fn is_terminal(pod: &Value) -> bool {
    matches!(
        pod.pointer("/status/phase").and_then(Value::as_str),
        Some("Succeeded" | "Failed")
    )
}

fn container_resources(pod: &Value, kind: &str) -> BTreeMap<String, i128> {
    let mut sum: BTreeMap<String, i128> = BTreeMap::new();
    let mut init_max: BTreeMap<String, i128> = BTreeMap::new();
    let collect = |list: Option<&Value>, out: &mut BTreeMap<String, i128>, add: bool| {
        for c in list.and_then(Value::as_array).into_iter().flatten() {
            let Some(map) = c
                .pointer(&format!("/resources/{kind}"))
                .and_then(Value::as_object)
            else {
                continue;
            };
            for (k, v) in map {
                let Some(q) = quantity(v) else { continue };
                let e = out.entry(k.clone()).or_insert(0);
                if add {
                    *e += q;
                } else {
                    *e = (*e).max(q);
                }
            }
        }
    };
    collect(pod.pointer("/spec/containers"), &mut sum, true);
    collect(pod.pointer("/spec/initContainers"), &mut init_max, false);
    for (k, v) in init_max {
        let e = sum.entry(k).or_insert(0);
        *e = (*e).max(v);
    }
    if let Some(overhead) = pod.pointer("/spec/overhead").and_then(Value::as_object) {
        for (k, v) in overhead {
            if let Some(q) = quantity(v) {
                *sum.entry(k.clone()).or_insert(0) += q;
            }
        }
    }
    sum
}

/// Returns true when a pod declares no requests or limits at all.
#[must_use]
pub fn is_best_effort(pod: &Value) -> bool {
    ["/spec/containers", "/spec/initContainers"]
        .iter()
        .all(|ptr| {
            pod.pointer(ptr)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .all(|c| {
                    ["requests", "limits"].iter().all(|k| {
                        c.pointer(&format!("/resources/{k}"))
                            .and_then(Value::as_object)
                            .is_none_or(Map::is_empty)
                    })
                })
        })
}

/// Evaluates `spec.scopes` for a pod.
#[must_use]
pub fn pod_matches_scopes(pod: &Value, scopes: &[&str]) -> bool {
    let terminating = pod.pointer("/spec/activeDeadlineSeconds").is_some();
    scopes.iter().all(|scope| match *scope {
        "BestEffort" => is_best_effort(pod),
        "NotBestEffort" => !is_best_effort(pod),
        "Terminating" => terminating,
        "NotTerminating" => !terminating,
        _ => true,
    })
}

/// Per-resource usage a live pod charges against a quota.
#[must_use]
pub fn pod_usage(pod: &Value) -> BTreeMap<String, i128> {
    let mut usage = BTreeMap::new();
    if is_terminal(pod) {
        return usage;
    }
    usage.insert("pods".to_string(), 1000);
    usage.insert("count/pods".to_string(), 1000);
    for (k, v) in container_resources(pod, "requests") {
        if matches!(k.as_str(), "cpu" | "memory" | "ephemeral-storage") {
            usage.insert(k.clone(), v);
        }
        usage.insert(format!("requests.{k}"), v);
    }
    for (k, v) in container_resources(pod, "limits") {
        usage.insert(format!("limits.{k}"), v);
    }
    usage
}

/// Usage charged by a `PersistentVolumeClaim`.
#[must_use]
pub fn pvc_usage(pvc: &Value) -> BTreeMap<String, i128> {
    let mut usage = BTreeMap::new();
    usage.insert("persistentvolumeclaims".to_string(), 1000);
    usage.insert("count/persistentvolumeclaims".to_string(), 1000);
    let storage = pvc
        .pointer("/spec/resources/requests/storage")
        .and_then(quantity)
        .unwrap_or(0);
    usage.insert("requests.storage".to_string(), storage);
    if let Some(class) = pvc
        .pointer("/spec/storageClassName")
        .and_then(Value::as_str)
    {
        usage.insert(
            format!("{class}.storageclass.storage.k8s.io/persistentvolumeclaims"),
            1000,
        );
        usage.insert(
            format!("{class}.storageclass.storage.k8s.io/requests.storage"),
            storage,
        );
    }
    usage
}

/// Usage charged by a `Service`.
#[must_use]
pub fn service_usage(svc: &Value) -> BTreeMap<String, i128> {
    let mut usage = BTreeMap::new();
    usage.insert("services".to_string(), 1000);
    usage.insert("count/services".to_string(), 1000);
    let svc_type = svc
        .pointer("/spec/type")
        .and_then(Value::as_str)
        .unwrap_or("ClusterIP");
    let ports = svc
        .pointer("/spec/ports")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let ports = i128::try_from(ports).unwrap_or(0) * 1000;
    match svc_type {
        "NodePort" => {
            usage.insert("services.nodeports".to_string(), ports);
        },
        "LoadBalancer" => {
            usage.insert("services.loadbalancers".to_string(), 1000);
            usage.insert("services.nodeports".to_string(), ports);
        },
        _ => {},
    }
    usage
}

/// Usage charged by any other counted object (`configmaps`, `secrets`, ...).
#[must_use]
pub fn object_count_usage(group: &str, plural: &str) -> BTreeMap<String, i128> {
    let mut usage = BTreeMap::new();
    if group.is_empty() {
        usage.insert(plural.to_string(), 1000);
        usage.insert(format!("count/{plural}"), 1000);
    } else {
        usage.insert(format!("count/{plural}.{group}"), 1000);
    }
    usage
}

/// Usage of one object of `group/plural`.
#[must_use]
pub fn usage_for(group: &str, plural: &str, obj: &Value) -> BTreeMap<String, i128> {
    match (group, plural) {
        ("", "pods") => pod_usage(obj),
        ("", "services") => service_usage(obj),
        ("", "persistentvolumeclaims") => pvc_usage(obj),
        _ => object_count_usage(group, plural),
    }
}

/// Returns the quota's scopes as string slices.
#[must_use]
pub fn quota_scopes(quota: &Value) -> Vec<&str> {
    quota
        .pointer("/spec/scopes")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// True when the quota tracks objects of this resource.
#[must_use]
pub fn object_in_scope(quota: &Value, group: &str, plural: &str, obj: &Value) -> bool {
    let scopes = quota_scopes(quota);
    if scopes.is_empty() {
        return true;
    }
    group.is_empty() && plural == "pods" && pod_matches_scopes(obj, &scopes)
}

/// Builds `status` (`hard` + `used`) from per-object usages.
#[must_use]
pub fn status_from_usage(quota: &Value, totals: &BTreeMap<String, i128>) -> Value {
    let hard = quota
        .pointer("/spec/hard")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut used = Map::new();
    for key in hard.keys() {
        let v = totals.get(key).copied().unwrap_or(0);
        used.insert(key.clone(), json!(format_milli(v)));
    }
    json!({ "hard": hard, "used": used })
}

/// Explains which hard limits `delta` would exceed given current `totals`.
#[must_use]
pub fn exceeded(
    quota: &Value,
    totals: &BTreeMap<String, i128>,
    delta: &BTreeMap<String, i128>,
) -> Option<String> {
    let hard = quota.pointer("/spec/hard").and_then(Value::as_object)?;
    let mut requested = Vec::new();
    let mut used = Vec::new();
    let mut limited = Vec::new();
    for (key, limit) in hard {
        let Some(add) = delta.get(key).copied().filter(|v| *v > 0) else {
            continue;
        };
        let Some(limit_v) = quantity(limit) else {
            continue;
        };
        let current = totals.get(key).copied().unwrap_or(0);
        if current + add > limit_v {
            requested.push(format!("{key}={}", format_milli(add)));
            used.push(format!("{key}={}", format_milli(current)));
            limited.push(format!("{key}={}", format_milli(limit_v)));
        }
    }
    if requested.is_empty() {
        return None;
    }
    let name = quota
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    Some(format!(
        "exceeded quota: {name}, requested: {}, used: {}, limited: {}",
        requested.join(","),
        used.join(","),
        limited.join(",")
    ))
}

/// Lists `group/plural` in a namespace through the typed client paths.
pub async fn list_counted(
    client: &crate::client::KubernetesApiClient,
    group: &str,
    list_kind: &str,
    plural: &str,
    namespace: &str,
) -> Vec<Value> {
    let listed = match (group, plural) {
        ("", "pods") => client.list_pods(namespace).await,
        ("", "replicationcontrollers") => client.list_replicationcontrollers(namespace).await,
        ("", "configmaps") => client.list_configmaps(namespace).await,
        ("", "secrets") => client.list_secrets(namespace).await,
        ("", "services") => client.list_services(namespace).await,
        ("", "persistentvolumeclaims") => client.list_pvcs(namespace).await,
        ("apps", "deployments") => client.list_deployments(namespace).await,
        ("apps", "replicasets") => client.list_replicasets(namespace).await,
        ("apps", "statefulsets") => client.list_statefulsets(namespace).await,
        ("apps", "daemonsets") => client.list_daemonsets(namespace).await,
        ("batch", "jobs") => client.list_jobs(namespace).await,
        ("batch", "cronjobs") => client.list_cronjobs(namespace).await,
        _ => {
            client
                .list_namespaced_objects(group, list_kind, plural, namespace)
                .await
        },
    };
    listed
        .ok()
        .and_then(|l| l.get("items").and_then(Value::as_array).cloned())
        .unwrap_or_default()
}

/// Totals the usage a quota currently observes in its namespace.
pub async fn compute_totals(
    client: &crate::client::KubernetesApiClient,
    quota: &Value,
    namespace: &str,
) -> BTreeMap<String, i128> {
    let mut totals = BTreeMap::new();
    for (group, list_kind, plural) in COUNTED_RESOURCES {
        if !quota_tracks(quota, group, plural) {
            continue;
        }
        for obj in list_counted(client, group, list_kind, plural, namespace).await {
            if obj
                .pointer("/metadata/deletionTimestamp")
                .and_then(Value::as_str)
                .is_some()
                && *plural == "pods"
            {
                continue;
            }
            if !object_in_scope(quota, group, plural, &obj) {
                continue;
            }
            for (k, v) in usage_for(group, plural, &obj) {
                *totals.entry(k).or_insert(0) += v;
            }
        }
    }
    totals
}

/// Resource collections a quota may count, as `(group, list kind, plural)`.
pub const COUNTED_RESOURCES: &[(&str, &str, &str)] = &[
    ("", "PodList", "pods"),
    ("", "ServiceList", "services"),
    ("", "PersistentVolumeClaimList", "persistentvolumeclaims"),
    ("", "ConfigMapList", "configmaps"),
    ("", "SecretList", "secrets"),
    ("", "ReplicationControllerList", "replicationcontrollers"),
    ("", "ResourceQuotaList", "resourcequotas"),
    ("apps", "ReplicaSetList", "replicasets"),
    ("apps", "DeploymentList", "deployments"),
    ("apps", "StatefulSetList", "statefulsets"),
    ("apps", "DaemonSetList", "daemonsets"),
    ("batch", "JobList", "jobs"),
    ("batch", "CronJobList", "cronjobs"),
];

/// True when any hard key of the quota could be charged by `group/plural`.
#[must_use]
pub fn quota_tracks(quota: &Value, group: &str, plural: &str) -> bool {
    let Some(hard) = quota.pointer("/spec/hard").and_then(Value::as_object) else {
        return false;
    };
    let compute = group.is_empty() && plural == "pods";
    let pvc = group.is_empty() && plural == "persistentvolumeclaims";
    let svc = group.is_empty() && plural == "services";
    let count_key = if group.is_empty() {
        format!("count/{plural}")
    } else {
        format!("count/{plural}.{group}")
    };
    hard.keys().any(|k| {
        let compute_key = matches!(k.as_str(), "cpu" | "memory" | "ephemeral-storage")
            || ((k.starts_with("requests.") || k.starts_with("limits."))
                && k != "requests.storage");
        (group.is_empty() && k == plural)
            || *k == count_key
            || (compute && compute_key)
            || (pvc && (k == "requests.storage" || k.contains(".storageclass.storage.k8s.io/")))
            || (svc && k.starts_with("services."))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quantities() {
        assert_eq!(parse_quantity_milli("1"), Some(1000));
        assert_eq!(parse_quantity_milli("500m"), Some(500));
        assert_eq!(parse_quantity_milli("1Gi"), Some(1000 << 30));
        assert_eq!(parse_quantity_milli("0.5"), Some(500));
        assert_eq!(parse_quantity_milli("1e3"), Some(1_000_000));
        assert_eq!(format_milli(500), "500m");
        assert_eq!(format_milli(2000), "2");
    }

    #[test]
    fn pod_usage_sums_requests() {
        let pod = json!({ "spec": { "containers": [
            { "resources": { "requests": { "cpu": "500m", "memory": "252Mi" }, "limits": { "cpu": "1" } } }
        ] } });
        let u = pod_usage(&pod);
        assert_eq!(u["requests.cpu"], 500);
        assert_eq!(u["cpu"], 500);
        assert_eq!(u["limits.cpu"], 1000);
        assert_eq!(u["pods"], 1000);
    }

    #[test]
    fn detects_exceeded_quota() {
        let quota = json!({ "metadata": { "name": "q" }, "spec": { "hard": { "pods": "1" } } });
        let totals = BTreeMap::from([("pods".to_string(), 1000)]);
        let delta = BTreeMap::from([("pods".to_string(), 1000)]);
        assert!(
            exceeded(&quota, &totals, &delta)
                .unwrap()
                .contains("exceeded quota: q")
        );
    }
}
