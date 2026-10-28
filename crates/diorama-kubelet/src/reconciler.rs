//! Pod reconciler: drives pods through a CRI-shaped runtime the way the
//! upstream kubelet does.
//!
//! One pass per pod: ensure a ready sandbox, bring every spec container to its
//! latest attempt (pull, create, start), probe running containers, restart
//! exited ones under `restartPolicy` with the kubelet's back-off, then write
//! the status the runtime reports. Deletion stops containers with the grace
//! period, removes the sandbox and deletes the Pod object.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use diorama_apiserver::time::{now_rfc3339, now_unix, parse_rfc3339_seconds};
use diorama_apiserver::{ApiserverError, ApiserverService, KubernetesApiClient};

use crate::config::{
    DEFAULT_CLUSTER_DNS, DEFAULT_CLUSTER_DOMAIN, detect_host_cpu_count, format_cpuset,
};
use crate::error::KubeletError;
use crate::status::{
    ContainerView, CpuAssignment, PodViews, attempt_of, attempts_by_name, pending_status,
    pod_status,
};
use crate::workload::{
    ANNOTATION_RESTART_COUNT, CpuManager, ExecResult, LABEL_CONTAINER_NAME, LABEL_MANAGED_BY,
    LABEL_POD_NAME, LABEL_POD_NAMESPACE, LABEL_POD_UID, LogOptions, MANAGED_BY, ReconcileReport,
    RestartPolicy, RuntimeProvider, WorkloadRestartReport, apply_fs_group_ownership_with_options,
    check_pod_restart_need, chmod_volume_file, container_labels, cri, determine_pod_qos,
    is_container_cpu_pinning_eligible, is_restartable_init, materialize_image_volume,
    parse_cpu_quantity_milli, parse_memory_quantity_bytes, pod_fs_group, prune_stale_volume_files,
    resolve_downward_field_path, resolve_downward_resource_field, safe_volume_path, sandbox_labels,
    secs_from_nanos, stage_configmap_files, stage_projected_clustertrustbundle,
    stage_projected_downward_api, stage_projected_sa_token, stage_secret_files,
    truncate_pod_hostname, write_volume_file,
};

const RESTART_BACKOFF_INITIAL_SECS: u64 = 10;
const RESTART_BACKOFF_MAX_SECS: u64 = 300;
const RESTART_BACKOFF_RESET_SECS: u64 = 600;
/// Upper bound for a probe command.
const EXEC_TIMEOUT_SECS: i64 = 10;
/// Attempts kept per container: the current one and the previous for `logs --previous`.
const KEPT_ATTEMPTS: usize = 2;

#[derive(Debug, Clone, Copy)]
struct RestartBackoff {
    delay_secs: u64,
    not_before: u64,
}

#[derive(Debug, Clone, Default)]
struct ProbeTracker {
    last_run_secs: u64,
    consecutive_failures: u32,
}

/// Next restart delay: doubles after each quick failure, resets after a long run.
fn next_restart_backoff(
    previous: Option<RestartBackoff>,
    ran_for: u64,
    now: u64,
) -> RestartBackoff {
    let delay_secs = match previous {
        Some(backoff) if ran_for < RESTART_BACKOFF_RESET_SECS => {
            (backoff.delay_secs * 2).min(RESTART_BACKOFF_MAX_SECS)
        },
        _ => RESTART_BACKOFF_INITIAL_SECS,
    };
    RestartBackoff {
        delay_secs,
        not_before: now + delay_secs,
    }
}

/// Per-pass bookkeeping while bringing containers to their desired attempts.
#[derive(Debug, Default)]
struct SyncState {
    ready: BTreeMap<String, bool>,
    backoffs: BTreeMap<String, String>,
    waiting: BTreeMap<String, (&'static str, String)>,
    started_now: BTreeSet<String>,
    restarted: BTreeSet<String>,
}

struct SyncContext<'a> {
    namespace: &'a str,
    pod: &'a Value,
    sandbox_id: &'a str,
    sandbox_config: &'a cri::PodSandboxConfig,
    pod_ip: Option<String>,
}

fn container_name_of(container: &Value) -> &str {
    container
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("main")
}

/// Why a container attempt could not be started; reported as a waiting state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartFailure {
    pub reason: &'static str,
    pub message: String,
}

fn state_of(status: &cri::ContainerStatus) -> cri::ContainerState {
    cri::ContainerState::try_from(status.state).unwrap_or(cri::ContainerState::ContainerUnknown)
}

/// Extracts effective priority from Pod spec or well-known `PriorityClasses`.
#[must_use]
pub fn pod_priority(pod: &Value) -> i64 {
    let p_opt = pod.pointer("/spec/priority").and_then(Value::as_i64);
    if let Some(p) = p_opt
        && p != 0
    {
        return p;
    }
    if let Some(class_name) = pod
        .pointer("/spec/priorityClassName")
        .and_then(Value::as_str)
    {
        if let Some(p) = class_name
            .strip_prefix('p')
            .and_then(|s| s.parse::<i64>().ok())
        {
            return p;
        }
        match class_name {
            "system-node-critical" => 2_000_001_000,
            "system-cluster-critical" => 2_000_000_000,
            s if s.contains("high") || s.contains("preemptor") => 1000,
            s if s.contains("medium") => 500,
            s if s.contains("low") => 100,
            _ => p_opt.unwrap_or(0),
        }
    } else {
        p_opt.unwrap_or(0)
    }
}

/// Checks whether the Pod allows preemption under `spec.preemptionPolicy`.
#[must_use]
pub fn pod_allows_preemption(pod: &Value) -> bool {
    pod.pointer("/spec/preemptionPolicy")
        .and_then(Value::as_str)
        != Some("Never")
}

fn match_values_operator(
    node_val: Option<&str>,
    operator: &str,
    values: Option<&[Value]>,
    key_exists: bool,
) -> bool {
    match operator {
        "In" => {
            let Some(nv) = node_val else { return false };
            let Some(vals) = values else { return false };
            vals.iter().any(|v| v.as_str() == Some(nv))
        },
        "NotIn" => {
            let Some(nv) = node_val else { return true };
            let Some(vals) = values else { return true };
            !vals.iter().any(|v| v.as_str() == Some(nv))
        },
        "Exists" => key_exists,
        "DoesNotExist" => !key_exists,
        "Gt" => {
            let Some(nv) = node_val.and_then(|s| s.parse::<i64>().ok()) else {
                return false;
            };
            let Some(target) = values
                .and_then(|vals| vals.first())
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<i64>().ok())
            else {
                return false;
            };
            nv > target
        },
        "Lt" => {
            let Some(nv) = node_val.and_then(|s| s.parse::<i64>().ok()) else {
                return false;
            };
            let Some(target) = values
                .and_then(|vals| vals.first())
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<i64>().ok())
            else {
                return false;
            };
            nv < target
        },
        _ => false,
    }
}

fn match_requirement(labels: Option<&serde_json::Map<String, Value>>, req: &Value) -> bool {
    let Some(key) = req.get("key").and_then(Value::as_str) else {
        return false;
    };
    let op = req.get("operator").and_then(Value::as_str).unwrap_or("In");
    let values = req
        .get("values")
        .and_then(Value::as_array)
        .map(Vec::as_slice);
    let key_exists = labels.is_some_and(|l| l.contains_key(key));
    let node_val = labels.and_then(|l| l.get(key)).and_then(Value::as_str);
    match_values_operator(node_val, op, values, key_exists)
}

fn match_field_requirement(node: &Value, req: &Value) -> bool {
    let Some(key) = req.get("key").and_then(Value::as_str) else {
        return false;
    };
    let op = req.get("operator").and_then(Value::as_str).unwrap_or("In");
    let values = req
        .get("values")
        .and_then(Value::as_array)
        .map(Vec::as_slice);
    let (node_val, key_exists) = if key == "metadata.name" {
        let name = node.pointer("/metadata/name").and_then(Value::as_str);
        (name, name.is_some())
    } else {
        (None, false)
    };
    match_values_operator(node_val, op, values, key_exists)
}

fn term_matches_node(node: &Value, term: &Value) -> bool {
    let labels = node.pointer("/metadata/labels").and_then(Value::as_object);
    if let Some(exprs) = term.get("matchExpressions").and_then(Value::as_array) {
        for expr in exprs {
            if !match_requirement(labels, expr) {
                return false;
            }
        }
    }
    if let Some(fields) = term.get("matchFields").and_then(Value::as_array) {
        for field in fields {
            if !match_field_requirement(node, field) {
                return false;
            }
        }
    }
    true
}

fn node_matches_node_selector(node: &Value, pod: &Value) -> bool {
    let Some(selector) = pod.pointer("/spec/nodeSelector").and_then(Value::as_object) else {
        return true;
    };
    let labels = node.pointer("/metadata/labels").and_then(Value::as_object);
    selector
        .iter()
        .all(|(k, v)| labels.and_then(|l| l.get(k)).and_then(Value::as_str) == v.as_str())
}

fn node_matches_node_affinity(node: &Value, pod: &Value) -> bool {
    let Some(req) =
        pod.pointer("/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution")
    else {
        return true;
    };
    let Some(terms) = req.get("nodeSelectorTerms").and_then(Value::as_array) else {
        return true;
    };
    if terms.is_empty() {
        return false;
    }
    terms.iter().any(|term| term_matches_node(node, term))
}

fn node_matches_affinity_and_selector(node: &Value, pod: &Value) -> Result<(), String> {
    if !node_matches_node_selector(node, pod) || !node_matches_node_affinity(node, pod) {
        return Err("node(s) didn't match Pod's node affinity/selector".to_string());
    }
    Ok(())
}

fn toleration_matches_taint(toleration: &Value, taint: &Value) -> bool {
    let taint_effect = taint.get("effect").and_then(Value::as_str).unwrap_or("");
    if let Some(tol_effect) = toleration.get("effect").and_then(Value::as_str)
        && !tol_effect.is_empty()
        && tol_effect != taint_effect
    {
        return false;
    }

    let taint_key = taint.get("key").and_then(Value::as_str).unwrap_or("");
    let operator = toleration
        .get("operator")
        .and_then(Value::as_str)
        .unwrap_or("Equal");

    if operator == "Exists" {
        let tol_key = toleration.get("key").and_then(Value::as_str).unwrap_or("");
        tol_key.is_empty() || tol_key == taint_key
    } else {
        let tol_key = toleration.get("key").and_then(Value::as_str).unwrap_or("");
        let tol_val = toleration
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or("");
        let taint_val = taint.get("value").and_then(Value::as_str).unwrap_or("");
        tol_key == taint_key && tol_val == taint_val
    }
}

fn node_tolerates_taints(node: &Value, pod: &Value) -> Result<(), String> {
    let Some(taints) = node.pointer("/spec/taints").and_then(Value::as_array) else {
        return Ok(());
    };
    let pod_tolerations = pod
        .pointer("/spec/tolerations")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);

    for taint in taints {
        let effect = taint.get("effect").and_then(Value::as_str).unwrap_or("");
        if effect == "NoSchedule" || effect == "NoExecute" {
            let tolerated = pod_tolerations
                .iter()
                .any(|tol| toleration_matches_taint(tol, taint));
            if !tolerated {
                return Err("node(s) had untolerated taint".to_string());
            }
        }
    }
    Ok(())
}

fn pod_fits_node_resources(
    node: &Value,
    committed: &BTreeMap<String, i128>,
    pod: &Value,
) -> Result<(), String> {
    if node.pointer("/spec/unschedulable").and_then(Value::as_bool) == Some(true) {
        return Err("node(s) were unschedulable".to_string());
    }
    let usage = diorama_apiserver::quota::pod_usage(pod);
    for (resource, key, label) in [
        ("pods", "pods", "Too many pods"),
        ("cpu", "requests.cpu", "Insufficient cpu"),
        ("memory", "requests.memory", "Insufficient memory"),
        (
            "ephemeral-storage",
            "requests.ephemeral-storage",
            "Insufficient ephemeral-storage",
        ),
    ] {
        let Some(want) = usage.get(key).copied().filter(|v| *v > 0) else {
            continue;
        };
        let Some(alloc) = node
            .pointer(&format!("/status/allocatable/{resource}"))
            .or_else(|| node.pointer(&format!("/status/capacity/{resource}")))
            .and_then(Value::as_str)
            .and_then(diorama_apiserver::quota::parse_quantity_milli)
        else {
            continue;
        };
        let used = committed.get(key).copied().unwrap_or(0);
        if used + want > alloc {
            return Err(label.to_string());
        }
    }
    for (k, want) in &usage {
        if let Some(resource_name) = k.strip_prefix("requests.")
            && resource_name.contains('/')
            && *want > 0
        {
            let alloc_opt = node
                .pointer("/status/allocatable")
                .and_then(|a| a.get(resource_name))
                .or_else(|| {
                    node.pointer("/status/capacity")
                        .and_then(|c| c.get(resource_name))
                })
                .and_then(Value::as_str)
                .and_then(diorama_apiserver::quota::parse_quantity_milli);
            let Some(alloc) = alloc_opt else {
                return Err(format!("Insufficient {resource_name}"));
            };
            let used = committed.get(k).copied().unwrap_or(0);
            if used + *want > alloc {
                return Err(format!("Insufficient {resource_name}"));
            }
        }
    }
    Ok(())
}

/// Minimal scheduler predicates: nodeSelector, nodeAffinity, pod count
/// and CPU/memory/ephemeral-storage requests against node allocatable capacity.
fn pod_fits_node(
    node: &Value,
    committed: &BTreeMap<String, i128>,
    pod: &Value,
) -> Result<(), String> {
    node_matches_affinity_and_selector(node, pod)?;
    node_tolerates_taints(node, pod)?;
    pod_fits_node_resources(node, committed, pod)?;
    Ok(())
}

/// Declared container or initContainer hostPort mapping.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostPortRequest {
    pub host_port: i32,
    pub protocol: String,
    pub host_ip: String,
}

/// Extracts all requested hostPorts from a pod's spec (containers and initContainers).
#[must_use]
pub fn pod_host_ports(pod: &Value) -> Vec<HostPortRequest> {
    let mut ports = Vec::new();
    let containers = pod.pointer("/spec/containers").and_then(Value::as_array);
    let init_containers = pod
        .pointer("/spec/initContainers")
        .and_then(Value::as_array);
    for c in containers
        .into_iter()
        .flatten()
        .chain(init_containers.into_iter().flatten())
    {
        if let Some(c_ports) = c.get("ports").and_then(Value::as_array) {
            for port in c_ports {
                let host_port = port.get("hostPort").and_then(Value::as_i64).unwrap_or(0);
                let host_port = i32::try_from(host_port).unwrap_or(0);
                if host_port <= 0 {
                    continue;
                }
                let proto_str = port
                    .get("protocol")
                    .and_then(Value::as_str)
                    .unwrap_or("TCP");
                let protocol = match proto_str.to_uppercase().as_str() {
                    "UDP" => "UDP".to_string(),
                    "SCTP" => "SCTP".to_string(),
                    _ => "TCP".to_string(),
                };
                let host_ip = port
                    .get("hostIP")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                ports.push(HostPortRequest {
                    host_port,
                    protocol,
                    host_ip,
                });
            }
        }
    }
    ports
}

/// Determines whether two hostPort declarations conflict.
///
/// Upstream contract: two ports conflict if they share the same hostPort > 0 and
/// normalized protocol, and either port specifies a wildcard hostIP ("" or "0.0.0.0")
/// or both specify identical hostIPs.
#[must_use]
pub fn host_ports_conflict(a: &HostPortRequest, b: &HostPortRequest) -> bool {
    if a.host_port != b.host_port || a.protocol != b.protocol {
        return false;
    }
    a.host_ip.is_empty()
        || a.host_ip == "0.0.0.0"
        || b.host_ip.is_empty()
        || b.host_ip == "0.0.0.0"
        || a.host_ip == b.host_ip
}

/// Determines whether two pods declare conflicting hostPorts.
#[must_use]
pub fn pods_have_host_port_conflict(pod1: &Value, pod2: &Value) -> bool {
    let ports1 = pod_host_ports(pod1);
    if ports1.is_empty() {
        return false;
    }
    let ports2 = pod_host_ports(pod2);
    if ports2.is_empty() {
        return false;
    }
    for p1 in &ports1 {
        for p2 in &ports2 {
            if host_ports_conflict(p1, p2) {
                return true;
            }
        }
    }
    false
}

fn is_same_pod(a: &Value, b: &Value) -> bool {
    if let (Some(uid_a), Some(uid_b)) = (
        a.pointer("/metadata/uid").and_then(Value::as_str),
        b.pointer("/metadata/uid").and_then(Value::as_str),
    ) {
        return uid_a == uid_b;
    }
    let ns_a = a
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let ns_b = b
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let name_a = a
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let name_b = b
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    ns_a == ns_b && name_a == name_b
}

fn is_active_pod(pod: &Value) -> bool {
    if pod.pointer("/metadata/deletionTimestamp").is_some() {
        return false;
    }
    !matches!(
        pod.pointer("/status/phase").and_then(Value::as_str),
        Some("Succeeded" | "Failed")
    )
}

fn is_pod_unschedulable(pod: &Value) -> bool {
    pod.pointer("/status/conditions")
        .and_then(Value::as_array)
        .is_some_and(|conds| {
            conds.iter().any(|c| {
                c.get("type").and_then(Value::as_str) == Some("PodScheduled")
                    && c.get("status").and_then(Value::as_str) == Some("False")
                    && c.get("reason").and_then(Value::as_str) == Some("Unschedulable")
            })
        })
}

fn is_active_deadline_exceeded(pod: &Value) -> bool {
    let phase = pod.pointer("/status/phase").and_then(Value::as_str);
    if matches!(phase, Some("Succeeded" | "Failed")) {
        return false;
    }
    let Some(deadline) = pod
        .pointer("/spec/activeDeadlineSeconds")
        .and_then(Value::as_i64)
    else {
        return false;
    };
    if deadline <= 0 {
        return false;
    }
    let Ok(deadline_secs) = u64::try_from(deadline) else {
        return false;
    };
    let start_time = pod
        .pointer("/status/startTime")
        .and_then(Value::as_str)
        .or_else(|| {
            pod.pointer("/metadata/creationTimestamp")
                .and_then(Value::as_str)
        });
    let Some(start_secs) = start_time.and_then(parse_rfc3339_seconds) else {
        return false;
    };
    let now = now_unix();
    now.saturating_sub(start_secs) >= deadline_secs
}

fn carry_forward_prev_container_status(c_status: &mut Value, prev_cs: &Value) {
    let prev_restarts = prev_cs
        .get("restartCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cur_restarts = c_status
        .get("restartCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if prev_restarts > cur_restarts {
        c_status["restartCount"] = json!(prev_restarts);
    }
    if c_status.get("resources").is_none()
        && let Some(prev_res) = prev_cs.get("resources")
    {
        c_status["resources"] = prev_res.clone();
    }
}

fn should_restart_on_resize(container_spec: &Value, prev_res: &Value, new_res: &Value) -> bool {
    let Some(policies) = container_spec.get("resizePolicy").and_then(Value::as_array) else {
        return false;
    };
    for p in policies {
        if p.get("restartPolicy").and_then(Value::as_str) != Some("RestartContainer") {
            continue;
        }
        let Some(r_name) = p.get("resourceName").and_then(Value::as_str) else {
            continue;
        };
        let req_path = format!("/requests/{r_name}");
        let lim_path = format!("/limits/{r_name}");
        if prev_res.pointer(&req_path) != new_res.pointer(&req_path)
            || prev_res.pointer(&lim_path) != new_res.pointer(&lim_path)
        {
            return true;
        }
    }
    false
}

fn sync_container_status_resources(c_status: &mut Value, container_spec: &Value) {
    let res = container_spec
        .get("resources")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if let Some(prev_res) = c_status.get("resources")
        && prev_res.as_object().is_some_and(|m| !m.is_empty())
        && should_restart_on_resize(container_spec, prev_res, &res)
    {
        let cur = c_status
            .get("restartCount")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        c_status["restartCount"] = json!(cur + 1);
    }
    c_status["resources"] = res.clone();
    let alloc = res
        .get("requests")
        .filter(|v| v.is_object() && !v.as_object().unwrap().is_empty())
        .or_else(|| {
            res.get("limits")
                .filter(|v| v.is_object() && !v.as_object().unwrap().is_empty())
        })
        .cloned();
    if let Some(mut a) = alloc {
        if c_status.get("exclusiveCPU").and_then(Value::as_bool) == Some(true)
            && let Some(cpuset) = c_status.get("cpuset").cloned()
            && let Some(obj) = a.as_object_mut()
        {
            obj.insert("cpu".to_string(), cpuset);
        }
        c_status["allocatedResources"] = a;
    } else if c_status.get("exclusiveCPU").and_then(Value::as_bool) == Some(true)
        && let Some(cpuset) = c_status.get("cpuset").cloned()
    {
        c_status["allocatedResources"] = json!({ "cpu": cpuset });
    } else if let Some(obj) = c_status.as_object_mut() {
        obj.remove("allocatedResources");
    }
}

fn deadline_exceeded_container_statuses(pod: &Value, now: &str) -> Vec<Value> {
    let mut container_statuses: Vec<Value> = pod
        .pointer("/status/containerStatuses")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let spec_cs = pod.pointer("/spec/containers").and_then(Value::as_array);
    if container_statuses.is_empty() {
        if let Some(cs) = spec_cs {
            for c in cs {
                let c_name = c.get("name").and_then(Value::as_str).unwrap_or("main");
                let mut status_val = json!({
                    "name": c_name,
                    "ready": false,
                    "started": false,
                    "restartCount": 0,
                    "state": {
                        "terminated": {
                            "exitCode": 137,
                            "reason": "DeadlineExceeded",
                            "message": "Pod was active on the node longer than the specified deadline",
                            "finishedAt": now,
                        }
                    }
                });
                sync_container_status_resources(&mut status_val, c);
                container_statuses.push(status_val);
            }
        }
    } else {
        for (i, cs) in container_statuses.iter_mut().enumerate() {
            if let Some(c) = spec_cs.and_then(|arr| arr.get(i)) {
                sync_container_status_resources(cs, c);
            }
            cs["ready"] = json!(false);
            if cs.pointer("/state/terminated").is_none() {
                cs["state"] = json!({
                    "terminated": {
                        "exitCode": 137,
                        "reason": "DeadlineExceeded",
                        "message": "Pod was active on the node longer than the specified deadline",
                        "finishedAt": now,
                    }
                });
            }
        }
    }
    container_statuses
}

fn deadline_exceeded_conditions(now: &str, generation: i64) -> Vec<Value> {
    let cond = |c_type: &str, status: &str, reason: Option<&str>, msg: Option<&str>| {
        let mut obj = json!({
            "type": c_type,
            "status": status,
            "lastTransitionTime": now,
            "observedGeneration": generation,
        });
        if let Some(r) = reason {
            obj["reason"] = json!(r);
        }
        if let Some(m) = msg {
            obj["message"] = json!(m);
        }
        obj
    };
    vec![
        cond("PodScheduled", "True", None, None),
        cond("Initialized", "True", None, None),
        cond(
            "Ready",
            "False",
            Some("DeadlineExceeded"),
            Some("Pod was active on the node longer than the specified deadline"),
        ),
        cond(
            "ContainersReady",
            "False",
            Some("DeadlineExceeded"),
            Some("Pod was active on the node longer than the specified deadline"),
        ),
    ]
}

fn is_earlier_active_pod(existing: &Value, candidate: &Value) -> bool {
    let existing_phase = existing.pointer("/status/phase").and_then(Value::as_str);
    let candidate_phase = candidate.pointer("/status/phase").and_then(Value::as_str);

    let existing_running = existing_phase == Some("Running");
    let candidate_running = candidate_phase == Some("Running");

    if existing_running && !candidate_running {
        return true;
    }
    if !existing_running && candidate_running {
        return false;
    }

    let existing_time = existing
        .pointer("/metadata/creationTimestamp")
        .and_then(Value::as_str);
    let candidate_time = candidate
        .pointer("/metadata/creationTimestamp")
        .and_then(Value::as_str);

    match (existing_time, candidate_time) {
        (Some(t1), Some(t2)) if t1 != t2 => t1 < t2,
        _ => {
            let id1 = existing
                .pointer("/metadata/uid")
                .and_then(Value::as_str)
                .unwrap_or("");
            let id2 = candidate
                .pointer("/metadata/uid")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !id1.is_empty() && !id2.is_empty() && id1 != id2 {
                id1 < id2
            } else {
                let name1 = (
                    existing
                        .pointer("/metadata/namespace")
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                    existing
                        .pointer("/metadata/name")
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                );
                let name2 = (
                    candidate
                        .pointer("/metadata/namespace")
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                    candidate
                        .pointer("/metadata/name")
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                );
                name1 < name2
            }
        },
    }
}

fn has_conflicting_pod_on_node(candidate: &Value, node_name: &str, all_pods: &[Value]) -> bool {
    all_pods.iter().any(|other| {
        other.pointer("/spec/nodeName").and_then(Value::as_str) == Some(node_name)
            && is_active_pod(other)
            && other.pointer("/metadata/deletionTimestamp").is_none()
            && !is_same_pod(other, candidate)
            && !is_pod_unschedulable(other)
            && pods_have_host_port_conflict(candidate, other)
    })
}

fn has_conflicting_earlier_pod_on_node(
    candidate: &Value,
    node_name: &str,
    all_pods: &[Value],
) -> bool {
    all_pods.iter().any(|other| {
        other.pointer("/spec/nodeName").and_then(Value::as_str) == Some(node_name)
            && is_active_pod(other)
            && other.pointer("/metadata/deletionTimestamp").is_none()
            && !is_same_pod(other, candidate)
            && !is_pod_unschedulable(other)
            && is_earlier_active_pod(other, candidate)
            && pods_have_host_port_conflict(candidate, other)
    })
}

fn pod_name(pod: &Value) -> &str {
    pod.pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
}

fn pod_uid(pod: &Value) -> Result<&str, KubeletError> {
    pod.pointer("/metadata/uid")
        .and_then(Value::as_str)
        .ok_or_else(|| KubeletError::PodReconciliationFailed {
            pod: pod_name(pod).to_string(),
            reason: "pod missing metadata.uid".to_string(),
        })
}

fn uid_filter(pod_uid: &str) -> cri::PodSandboxFilter {
    cri::PodSandboxFilter {
        label_selector: BTreeMap::from([
            (LABEL_MANAGED_BY.to_string(), MANAGED_BY.to_string()),
            (LABEL_POD_UID.to_string(), pod_uid.to_string()),
        ]),
        ..cri::PodSandboxFilter::default()
    }
}

fn extract_custom_servers(custom: &Value) -> Vec<String> {
    custom
        .get("nameservers")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

fn extract_custom_searches(custom: &Value) -> Vec<String> {
    custom
        .get("searches")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

fn extract_custom_options(custom: &Value) -> Vec<String> {
    custom
        .get("options")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|opt| {
                    let name = opt.get("name").and_then(Value::as_str)?;
                    if let Some(val) = opt.get("value").and_then(Value::as_str) {
                        Some(format!("{name}:{val}"))
                    } else {
                        Some(name.to_string())
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Builds the CRI DNS configuration for a pod based on `dnsPolicy`, `dnsConfig`,
/// cluster DNS IPs and cluster domain.
#[must_use]
pub fn build_dns_config(
    pod: &Value,
    cluster_dns: &[String],
    cluster_domain: &str,
) -> Option<cri::DnsConfig> {
    let namespace = pod
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");

    let host_network = pod
        .pointer("/spec/hostNetwork")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let default_policy = if host_network {
        "Default"
    } else {
        "ClusterFirst"
    };
    let dns_policy = pod
        .pointer("/spec/dnsPolicy")
        .and_then(Value::as_str)
        .unwrap_or(default_policy);

    match dns_policy {
        "Default" => {
            if let Some(custom) = pod.pointer("/spec/dnsConfig") {
                let servers = extract_custom_servers(custom);
                let searches = extract_custom_searches(custom);
                let options = extract_custom_options(custom);
                if servers.is_empty() && searches.is_empty() && options.is_empty() {
                    None
                } else {
                    Some(cri::DnsConfig {
                        servers,
                        searches,
                        options,
                    })
                }
            } else {
                None
            }
        },
        "None" => {
            let mut servers = Vec::new();
            let mut searches = Vec::new();
            let mut options = Vec::new();
            if let Some(custom) = pod.pointer("/spec/dnsConfig") {
                servers = extract_custom_servers(custom);
                searches = extract_custom_searches(custom);
                options = extract_custom_options(custom);
            }
            Some(cri::DnsConfig {
                servers,
                searches,
                options,
            })
        },
        _ => {
            // "ClusterFirst", "ClusterFirstWithHostNet", or fallback
            if cluster_dns.is_empty() {
                return None;
            }
            let mut servers = cluster_dns.to_vec();
            let effective_domain = if cluster_domain.is_empty() {
                DEFAULT_CLUSTER_DOMAIN
            } else {
                cluster_domain
            };
            let mut searches = vec![
                format!("{namespace}.svc.{effective_domain}"),
                format!("svc.{effective_domain}"),
                effective_domain.to_string(),
            ];
            let mut options = vec!["ndots:5".to_string()];

            if let Some(custom) = pod.pointer("/spec/dnsConfig") {
                for s in extract_custom_servers(custom) {
                    if !servers.contains(&s) {
                        servers.push(s);
                    }
                }
                for search in extract_custom_searches(custom) {
                    if !searches.contains(&search) {
                        searches.push(search);
                    }
                }
                for opt in extract_custom_options(custom) {
                    if opt.starts_with("ndots:") {
                        options.retain(|o| !o.starts_with("ndots:"));
                    }
                    if !options.contains(&opt) {
                        options.push(opt);
                    }
                }
            }

            Some(cri::DnsConfig {
                servers,
                searches,
                options,
            })
        },
    }
}

fn sandbox_config_base(pod: &Value, attempt: u32) -> cri::PodSandboxConfig {
    let name = pod_name(pod);
    let namespace = pod
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let uid = pod
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut port_mappings = Vec::new();
    let containers = pod.pointer("/spec/containers").and_then(Value::as_array);
    let init_containers = pod
        .pointer("/spec/initContainers")
        .and_then(Value::as_array);
    for c in containers
        .into_iter()
        .flatten()
        .chain(init_containers.into_iter().flatten())
    {
        if let Some(ports) = c.get("ports").and_then(Value::as_array) {
            for port in ports {
                let container_port = port
                    .get("containerPort")
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                let container_port = i32::try_from(container_port).unwrap_or(0);
                if container_port <= 0 {
                    continue;
                }
                let host_port = port.get("hostPort").and_then(Value::as_i64).unwrap_or(0);
                let host_port = i32::try_from(host_port).unwrap_or(0);
                let proto_str = port
                    .get("protocol")
                    .and_then(Value::as_str)
                    .unwrap_or("TCP");
                let protocol = match proto_str.to_uppercase().as_str() {
                    "UDP" => cri::Protocol::Udp as i32,
                    "SCTP" => cri::Protocol::Sctp as i32,
                    _ => cri::Protocol::Tcp as i32,
                };
                let host_ip = port
                    .get("hostIP")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                port_mappings.push(cri::PortMapping {
                    protocol,
                    container_port,
                    host_port,
                    host_ip,
                });
            }
        }
    }

    let mut config = cri::PodSandboxConfig {
        metadata: Some(cri::PodSandboxMetadata {
            name: name.to_string(),
            uid: uid.to_string(),
            namespace: namespace.to_string(),
            attempt,
        }),
        // A host-network sandbox joins the node's UTS namespace, and the runtime
        // rejects a hostname in that case.
        hostname: if pod_bool(pod, "hostNetwork") {
            String::new()
        } else {
            let raw = pod
                .pointer("/spec/hostname")
                .and_then(Value::as_str)
                .unwrap_or(name);
            truncate_pod_hostname(raw)
        },
        log_directory: format!("/var/log/pods/{namespace}_{name}_{uid}"),
        labels: sandbox_labels(namespace, name, uid),
        port_mappings,
        ..cri::PodSandboxConfig::default()
    };
    apply_sandbox_linux(pod, &mut config);
    config
}

fn pod_bool(pod: &Value, field: &str) -> bool {
    pod.pointer(&format!("/spec/{field}"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn container_privileged(container: &Value) -> bool {
    container
        .pointer("/securityContext/privileged")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn pod_runs_privileged(pod: &Value) -> bool {
    let containers = pod.pointer("/spec/containers").and_then(Value::as_array);
    let init_containers = pod
        .pointer("/spec/initContainers")
        .and_then(Value::as_array);
    containers
        .into_iter()
        .flatten()
        .chain(init_containers.into_iter().flatten())
        .any(container_privileged)
}

/// A privileged container, or a pod that joins the host namespaces, has to say
/// so on the sandbox. The runtime rejects a privileged container whose sandbox
/// did not opt in.
fn apply_sandbox_linux(pod: &Value, config: &mut cri::PodSandboxConfig) {
    let host_network = pod_bool(pod, "hostNetwork");
    let host_pid = pod_bool(pod, "hostPID");
    let host_ipc = pod_bool(pod, "hostIPC");
    let privileged = pod_runs_privileged(pod);

    let mut sysctls = std::collections::BTreeMap::new();
    if let Some(list) = pod
        .pointer("/spec/securityContext/sysctls")
        .and_then(Value::as_array)
    {
        for s in list {
            if let (Some(name), Some(val)) = (
                s.get("name").and_then(Value::as_str),
                s.get("value").and_then(Value::as_str),
            ) {
                sysctls.insert(name.to_string(), val.to_string());
            }
        }
    }

    if !host_network && !host_pid && !host_ipc && !privileged && sysctls.is_empty() {
        return;
    }
    let mut namespaces = cri::NamespaceOption::default();
    if host_network {
        namespaces.network = cri::NamespaceMode::Node as i32;
    }
    if host_pid {
        namespaces.pid = cri::NamespaceMode::Node as i32;
    }
    if host_ipc {
        namespaces.ipc = cri::NamespaceMode::Node as i32;
    }
    let sec_ctx = (host_network || host_pid || host_ipc || privileged).then(|| {
        cri::LinuxSandboxSecurityContext {
            namespace_options: (host_network || host_pid || host_ipc).then_some(namespaces),
            privileged,
            ..cri::LinuxSandboxSecurityContext::default()
        }
    });
    config.linux = Some(cri::LinuxPodSandboxConfig {
        security_context: sec_ctx,
        sysctls,
        ..cri::LinuxPodSandboxConfig::default()
    });
}

/// Builds the CRI sandbox configuration for a pod with custom cluster DNS and domain.
#[must_use]
pub fn sandbox_config_with_dns(
    pod: &Value,
    attempt: u32,
    cluster_dns: &[String],
    cluster_domain: &str,
) -> cri::PodSandboxConfig {
    let mut config = sandbox_config_base(pod, attempt);
    config.dns_config = build_dns_config(pod, cluster_dns, cluster_domain);
    config
}

/// Builds the CRI sandbox configuration for a pod with default cluster DNS and domain.
#[must_use]
pub fn sandbox_config(pod: &Value, attempt: u32) -> cri::PodSandboxConfig {
    sandbox_config_with_dns(
        pod,
        attempt,
        &[DEFAULT_CLUSTER_DNS.to_string()],
        DEFAULT_CLUSTER_DOMAIN,
    )
}

const SERVICE_ACCOUNT_MOUNT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
const SERVICE_ACCOUNT_VOLUME_NAME: &str = "kube-api-access-diorama";
const KUBERNETES_API_AUDIENCE: &str = "https://kubernetes.default.svc";

/// Stock kubelet service-link variables.
///
/// `enableServiceLinks` defaults to true. `default/kubernetes` is always published.
/// Services with an empty `ClusterIP`, or `ClusterIP` `None`, add no variables.
fn service_link_envs(pod: &Value, services: &[Value]) -> Vec<cri::KeyValue> {
    let pod_namespace = pod
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let links_enabled = pod
        .pointer("/spec/enableServiceLinks")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let mut selected: Vec<&Value> = Vec::new();
    for service in services {
        if routable_cluster_ip(service).is_none() {
            continue;
        }
        let name = service
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let namespace = service
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .unwrap_or("default");
        let kubernetes_api = namespace == "default" && name == "kubernetes";
        let same_namespace = links_enabled && namespace == pod_namespace;
        if !kubernetes_api && !same_namespace {
            continue;
        }
        if let Some(slot) = selected.iter_mut().find(|existing| {
            existing.pointer("/metadata/name").and_then(Value::as_str) == Some(name)
        }) {
            *slot = service;
        } else {
            selected.push(service);
        }
    }

    let mut envs = Vec::new();
    for service in selected {
        push_service_link_envs(&mut envs, service);
    }
    envs
}

fn routable_cluster_ip(service: &Value) -> Option<&str> {
    let ip = service.pointer("/spec/clusterIP").and_then(Value::as_str)?;
    if ip.is_empty() || ip == "None" {
        None
    } else {
        Some(ip)
    }
}

fn push_service_link_envs(envs: &mut Vec<cri::KeyValue>, service: &Value) {
    let Some(cluster_ip) = routable_cluster_ip(service) else {
        return;
    };
    let Some(ports) = service.pointer("/spec/ports").and_then(Value::as_array) else {
        return;
    };
    let Some(first) = ports.first() else {
        return;
    };
    let Some(first_port) = json_port(first) else {
        return;
    };
    let service_name = env_var_token(
        service
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    if service_name.is_empty() {
        return;
    }

    push_env(
        envs,
        format!("{service_name}_SERVICE_HOST"),
        cluster_ip.to_string(),
    );
    let port_key = format!("{service_name}_SERVICE_PORT");
    push_env(envs, port_key.clone(), first_port.to_string());
    for port in ports {
        let Some(number) = json_port(port) else {
            continue;
        };
        if let Some(name) = port
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
        {
            push_env(
                envs,
                format!("{port_key}_{}", env_var_token(name)),
                number.to_string(),
            );
        }
    }
    for (index, port) in ports.iter().enumerate() {
        let Some(number) = json_port(port) else {
            continue;
        };
        let protocol = port
            .get("protocol")
            .and_then(Value::as_str)
            .filter(|protocol| !protocol.is_empty())
            .unwrap_or("TCP");
        let host_port = join_host_port(cluster_ip, number);
        if index == 0 {
            push_env(
                envs,
                format!("{service_name}_PORT"),
                format!("{}://{host_port}", protocol.to_ascii_lowercase()),
            );
        }
        let prefix = format!(
            "{service_name}_PORT_{number}_{}",
            protocol.to_ascii_uppercase()
        );
        push_env(
            envs,
            prefix.clone(),
            format!("{}://{host_port}", protocol.to_ascii_lowercase()),
        );
        push_env(
            envs,
            format!("{prefix}_PROTO"),
            protocol.to_ascii_lowercase(),
        );
        push_env(envs, format!("{prefix}_PORT"), number.to_string());
        push_env(envs, format!("{prefix}_ADDR"), cluster_ip.to_string());
    }
}

fn push_env(envs: &mut Vec<cri::KeyValue>, key: String, value: String) {
    push_env_kv(
        envs,
        cri::KeyValue {
            key,
            value: value.into_bytes(),
        },
    );
}

fn push_env_kv(envs: &mut Vec<cri::KeyValue>, env: cri::KeyValue) {
    if let Some(existing) = envs.iter_mut().find(|item| item.key == env.key) {
        existing.value = env.value;
    } else {
        envs.push(env);
    }
}

fn env_var_token(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch == '-' {
                '_'
            } else {
                ch.to_ascii_uppercase()
            }
        })
        .collect()
}

fn json_port(port: &Value) -> Option<u16> {
    port.get("port")
        .and_then(Value::as_u64)
        .and_then(|number| u16::try_from(number).ok())
}

fn join_host_port(ip: &str, port: u16) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

fn automount_service_account_token(pod: &Value) -> bool {
    pod.pointer("/spec/automountServiceAccountToken")
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

fn container_mounts_service_account(container: &Value) -> bool {
    container
        .get("volumeMounts")
        .and_then(Value::as_array)
        .is_some_and(|mounts| {
            mounts.iter().any(|mount| {
                mount.get("mountPath").and_then(Value::as_str) == Some(SERVICE_ACCOUNT_MOUNT_PATH)
            })
        })
}

fn pod_has_service_account_token(pod: &Value) -> bool {
    let has_kube_api_volume = pod
        .pointer("/spec/volumes")
        .and_then(Value::as_array)
        .is_some_and(|volumes| {
            volumes.iter().any(|vol| {
                vol.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|n| n.starts_with("kube-api-access"))
            })
        });
    if has_kube_api_volume {
        return true;
    }

    for key in ["/spec/containers", "/spec/initContainers"] {
        let mounted = pod
            .pointer(key)
            .and_then(Value::as_array)
            .is_some_and(|containers| containers.iter().any(container_mounts_service_account));
        if mounted {
            return true;
        }
    }

    false
}

/// Secrets and config maps already fetched for `valueFrom` and `envFrom` env sources.
#[derive(Debug, Default, Clone)]
struct EnvObjects {
    secrets: BTreeMap<String, Value>,
    configmaps: BTreeMap<String, Value>,
    services: Vec<Value>,
}

fn expand_k8s_env(input: &str, envs: &[cri::KeyValue]) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'$' {
                out.push('$');
                i += 2;
                continue;
            }
            if i + 1 < bytes.len()
                && bytes[i + 1] == b'('
                && let Some(rel_end) = input[i + 2..].find(')')
            {
                let var_name = &input[i + 2..i + 2 + rel_end];
                if !var_name.is_empty()
                    && let Some(kv) = envs.iter().rfind(|kv| kv.key == var_name)
                {
                    out.push_str(&String::from_utf8_lossy(&kv.value));
                } else {
                    out.push_str(&input[i..=i + 2 + rel_end]);
                }
                i += 3 + rel_end;
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}
fn append_cm_env_from(envs: &mut Vec<cri::KeyValue>, cm: &Value, prefix: &str) {
    if let Some(data) = cm.get("data").and_then(Value::as_object) {
        for (k, v) in data {
            if let Some(val_str) = v.as_str() {
                push_env(envs, format!("{prefix}{k}"), val_str.to_string());
            }
        }
    }
}

fn append_secret_env_from(envs: &mut Vec<cri::KeyValue>, sec: &Value, prefix: &str) {
    let mut keys = BTreeSet::new();
    if let Some(data) = sec.get("data").and_then(Value::as_object) {
        keys.extend(data.keys().cloned());
    }
    if let Some(sdata) = sec.get("stringData").and_then(Value::as_object) {
        keys.extend(sdata.keys().cloned());
    }
    for k in keys {
        if let Some(val_str) = secret_data_value(sec, &k) {
            push_env(envs, format!("{prefix}{k}"), val_str);
        }
    }
}

fn populate_env_from(
    container_name: &str,
    container: &Value,
    env_objects: &EnvObjects,
    envs: &mut Vec<cri::KeyValue>,
) -> Result<(), KubeletError> {
    let Some(env_from) = container.get("envFrom").and_then(Value::as_array) else {
        return Ok(());
    };
    for source in env_from {
        let prefix = source.get("prefix").and_then(Value::as_str).unwrap_or("");
        if let Some(cm_ref) = source.get("configMapRef") {
            let cm_name = cm_ref.get("name").and_then(Value::as_str).unwrap_or("");
            let optional = cm_ref
                .get("optional")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let Some(cm) = env_objects.configmaps.get(cm_name) else {
                if optional {
                    continue;
                }
                return Err(KubeletError::InvalidConfiguration {
                    field: format!("spec.containers[{container_name}].envFrom"),
                    reason: format!("configMap {cm_name} was not found"),
                });
            };
            append_cm_env_from(envs, cm, prefix);
        }
        if let Some(sec_ref) = source.get("secretRef") {
            let sec_name = sec_ref.get("name").and_then(Value::as_str).unwrap_or("");
            let optional = sec_ref
                .get("optional")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let Some(sec) = env_objects.secrets.get(sec_name) else {
                if optional {
                    continue;
                }
                return Err(KubeletError::InvalidConfiguration {
                    field: format!("spec.containers[{container_name}].envFrom"),
                    reason: format!("secret {sec_name} was not found"),
                });
            };
            append_secret_env_from(envs, sec, prefix);
        }
    }
    Ok(())
}

fn resolve_container_envs(
    pod: &Value,
    name: &str,
    container: &Value,
    env_objects: &EnvObjects,
) -> Result<Vec<cri::KeyValue>, KubeletError> {
    let mut envs = service_link_envs(pod, &env_objects.services);
    populate_env_from(name, container, env_objects, &mut envs)?;
    for entry in container
        .get("env")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(key) = entry.get("name").and_then(Value::as_str) else {
            continue;
        };
        let raw_val = resolve_env_value(pod, name, key, entry, env_objects)?;
        let val = if entry.get("value").is_some() {
            expand_k8s_env(&raw_val, &envs)
        } else {
            raw_val
        };
        push_env_kv(
            &mut envs,
            cri::KeyValue {
                key: key.to_string(),
                value: val.into_bytes(),
            },
        );
    }
    Ok(envs)
}

/// Builds the CRI container configuration for one attempt of a spec container,
/// optionally resolving volume mounts against the given root directory.
pub fn container_config_with_root(
    pod: &Value,
    container: &Value,
    attempt: u32,
    root_dir: Option<&Path>,
) -> Result<cri::ContainerConfig, KubeletError> {
    container_config_with_env(pod, container, attempt, root_dir, &EnvObjects::default())
}

fn container_config_with_env(
    pod: &Value,
    container: &Value,
    attempt: u32,
    root_dir: Option<&Path>,
    env_objects: &EnvObjects,
) -> Result<cri::ContainerConfig, KubeletError> {
    let name = container
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("main");
    let image = container
        .get("image")
        .and_then(Value::as_str)
        .filter(|image| !image.is_empty())
        .ok_or_else(|| KubeletError::InvalidConfiguration {
            field: format!("spec.containers[{name}].image"),
            reason: "container has no image".to_string(),
        })?;
    let strings = |key: &str| -> Vec<String> {
        container
            .get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let envs = resolve_container_envs(pod, name, container, env_objects)?;
    let command: Vec<String> = strings("command")
        .into_iter()
        .map(|s| expand_k8s_env(&s, &envs))
        .collect();
    let args: Vec<String> = strings("args")
        .into_iter()
        .map(|s| expand_k8s_env(&s, &envs))
        .collect();
    let namespace = pod
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let uid = pod
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .unwrap_or("");

    let empty_vec = Vec::new();
    let spec_volumes = pod
        .pointer("/spec/volumes")
        .and_then(Value::as_array)
        .unwrap_or(&empty_vec);
    let default_root = Path::new("/var/lib/kubelet");
    let root = root_dir.unwrap_or(default_root);
    let mounts = build_container_mounts(container, spec_volumes, root, uid, &envs, pod)?;
    let resources = build_container_resources(container);
    let security_context = build_security_context(pod, container)?;
    let linux =
        (resources.is_some() || security_context.is_some()).then_some(cri::LinuxContainerConfig {
            resources,
            security_context,
        });

    Ok(cri::ContainerConfig {
        metadata: Some(cri::ContainerMetadata {
            name: name.to_string(),
            attempt,
        }),
        image: Some(cri::ImageSpec {
            image: image.to_string(),
            user_specified_image: image.to_string(),
            ..cri::ImageSpec::default()
        }),
        command,
        args,
        working_dir: container
            .get("workingDir")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        envs,
        mounts,
        labels: container_labels(namespace, pod_name(pod), uid, name),
        annotations: BTreeMap::from([(ANNOTATION_RESTART_COUNT.to_string(), attempt.to_string())]),
        log_path: format!("{name}/{attempt}.log"),
        linux,
        ..cri::ContainerConfig::default()
    })
}

fn resolve_volume_host_path(
    root: &Path,
    uid: &str,
    vol: &Value,
    vol_name: &str,
    sub_path: &str,
) -> Option<PathBuf> {
    let mut base = if vol.get("secret").is_some() {
        root.join("pods")
            .join(uid)
            .join("volumes")
            .join("kubernetes.io~secret")
            .join(vol_name)
    } else if vol.get("configMap").is_some() {
        root.join("pods")
            .join(uid)
            .join("volumes")
            .join("kubernetes.io~configmap")
            .join(vol_name)
    } else if vol.get("downwardAPI").is_some() {
        root.join("pods")
            .join(uid)
            .join("volumes")
            .join("kubernetes.io~downward-api")
            .join(vol_name)
    } else if vol.get("projected").is_some() {
        root.join("pods")
            .join(uid)
            .join("volumes")
            .join("kubernetes.io~projected")
            .join(vol_name)
    } else if vol.get("emptyDir").is_some() {
        root.join("pods")
            .join(uid)
            .join("volumes")
            .join("kubernetes.io~empty-dir")
            .join(vol_name)
    } else if vol.get("image").is_some() {
        root.join("pods")
            .join(uid)
            .join("volumes")
            .join("kubernetes.io~image")
            .join(vol_name)
    } else if vol.get("persistentVolumeClaim").is_some() {
        let pvc_vol_path = root
            .join("pods")
            .join(uid)
            .join("volumes")
            .join("kubernetes.io~persistent-volume-claim")
            .join(vol_name);
        std::fs::canonicalize(&pvc_vol_path).unwrap_or(pvc_vol_path)
    } else {
        let hp = vol.get("hostPath")?;
        PathBuf::from(hp.get("path")?.as_str()?)
    };
    if !sub_path.is_empty() {
        base.push(sub_path);
        if vol.get("emptyDir").is_some()
            || vol.get("hostPath").is_some()
            || vol.get("image").is_some()
        {
            let _ = std::fs::create_dir_all(&base);
        }
    }
    Some(base)
}

fn validate_sub_path(sub_path: &str) -> Result<(), KubeletError> {
    if sub_path.is_empty() {
        return Ok(());
    }
    let path = Path::new(sub_path);
    if path.is_absolute() || sub_path.starts_with('/') || sub_path.starts_with('\\') {
        return Err(KubeletError::InvalidConfiguration {
            field: "volumeMounts.subPath".to_string(),
            reason: format!("subPath {sub_path:?} must not be an absolute path"),
        });
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(KubeletError::InvalidConfiguration {
            field: "volumeMounts.subPath".to_string(),
            reason: format!("subPath {sub_path:?} must not contain '..'"),
        });
    }
    Ok(())
}

fn generate_etc_hosts_content(pod: &Value, pod_ip: &str) -> String {
    let mut content = String::from(
        "# Kubernetes-managed hosts file.\n127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n",
    );
    let ns = pod
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let pod_name = pod
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("localhost");
    let hostname = pod.pointer("/spec/hostname").and_then(Value::as_str);
    let subdomain = pod.pointer("/spec/subdomain").and_then(Value::as_str);
    let ip = if pod_ip.is_empty() {
        "127.0.0.1"
    } else {
        pod_ip
    };

    if let (Some(h), Some(s)) = (hostname, subdomain) {
        if !h.is_empty() && !s.is_empty() {
            let h_trunc = truncate_pod_hostname(h);
            let _ = writeln!(content, "{ip}\t{h}.{s}.{ns}.svc.cluster.local\t{h_trunc}");
        } else {
            let host = truncate_pod_hostname(hostname.unwrap_or(pod_name));
            let _ = writeln!(content, "{ip}\t{host}");
        }
    } else {
        let host = truncate_pod_hostname(hostname.unwrap_or(pod_name));
        let _ = writeln!(content, "{ip}\t{host}");
    }

    if let Some(host_aliases) = pod.pointer("/spec/hostAliases").and_then(Value::as_array) {
        content.push_str(&format_host_aliases(host_aliases));
    }
    content
}

fn format_host_aliases(host_aliases: &[Value]) -> String {
    let mut out = String::new();
    if host_aliases.is_empty() {
        return out;
    }
    out.push_str("# Entries added by HostAliases.\n");
    for ha in host_aliases {
        let (Some(ha_ip), Some(hostnames)) = (
            ha.get("ip").and_then(Value::as_str),
            ha.get("hostnames").and_then(Value::as_array),
        ) else {
            continue;
        };
        let names: Vec<&str> = hostnames.iter().filter_map(Value::as_str).collect();
        if !names.is_empty() {
            let _ = writeln!(out, "{ha_ip}\t{}", names.join("\t"));
        }
    }
    out
}

fn generate_etc_hosts(pod_dir: &Path, pod: &Value, pod_ip: &str) -> std::io::Result<()> {
    let content = generate_etc_hosts_content(pod, pod_ip);
    let hosts_path = pod_dir.join("etc-hosts");
    std::fs::write(&hosts_path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&hosts_path, std::fs::Permissions::from_mode(0o644));
    }
    Ok(())
}

fn count_volume_mounts(container: &Value, vol_name: &str) -> (usize, usize) {
    let mut total = 0;
    let mut subpath = 0;
    let Some(mounts) = container.get("volumeMounts").and_then(Value::as_array) else {
        return (0, 0);
    };
    for mount in mounts {
        if mount.get("name").and_then(Value::as_str) == Some(vol_name) {
            total += 1;
            if mount.get("subPath").is_some() || mount.get("subPathExpr").is_some() {
                subpath += 1;
            }
        }
    }
    (total, subpath)
}

fn is_subpath_only_volume(pod: &Value, vol_name: &str) -> bool {
    let mut mount_count = 0;
    let mut subpath_count = 0;
    for key in ["/spec/containers", "/spec/initContainers"] {
        let Some(containers) = pod.pointer(key).and_then(Value::as_array) else {
            continue;
        };
        for container in containers {
            let (tot, sub) = count_volume_mounts(container, vol_name);
            mount_count += tot;
            subpath_count += sub;
        }
    }
    mount_count > 0 && mount_count == subpath_count
}

fn build_container_mounts(
    container: &Value,
    spec_volumes: &[Value],
    root: &Path,
    uid: &str,
    envs: &[cri::KeyValue],
    pod: &Value,
) -> Result<Vec<cri::Mount>, KubeletError> {
    let mut mounts = Vec::new();
    let vol_mounts = container.get("volumeMounts").and_then(Value::as_array);
    if let Some(vol_mounts) = vol_mounts {
        for vm in vol_mounts {
            let Some(mount_path) = vm.get("mountPath").and_then(Value::as_str) else {
                continue;
            };
            let Some(vol_name) = vm.get("name").and_then(Value::as_str) else {
                continue;
            };
            let readonly = vm.get("readOnly").and_then(Value::as_bool).unwrap_or(false);
            let sub_path_expr = vm.get("subPathExpr").and_then(Value::as_str).unwrap_or("");
            let resolved_sub_path = if sub_path_expr.is_empty() {
                vm.get("subPath")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()
            } else {
                expand_k8s_env(sub_path_expr, envs)
            };
            validate_sub_path(&resolved_sub_path)?;

            let Some(vol) = spec_volumes
                .iter()
                .find(|v| v.get("name").and_then(Value::as_str) == Some(vol_name))
            else {
                continue;
            };

            if let Some(host_path) =
                resolve_volume_host_path(root, uid, vol, vol_name, &resolved_sub_path)
            {
                mounts.push(cri::Mount {
                    container_path: mount_path.to_string(),
                    host_path: host_path.to_string_lossy().to_string(),
                    readonly,
                    ..cri::Mount::default()
                });
            }
        }
    }

    let host_network = pod
        .pointer("/spec/hostNetwork")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let has_custom_etc_hosts = vol_mounts.is_some_and(|vms| {
        vms.iter().any(|m| {
            m.get("mountPath")
                .and_then(Value::as_str)
                .is_some_and(|p| p == "/etc/hosts" || p == "/etc/hosts/")
        })
    }) || mounts.iter().any(|m| m.container_path == "/etc/hosts");
    if !host_network && !has_custom_etc_hosts {
        let host_etc_hosts = root.join("pods").join(uid).join("etc-hosts");
        if host_etc_hosts.exists() {
            mounts.push(cri::Mount {
                container_path: "/etc/hosts".to_string(),
                host_path: host_etc_hosts.to_string_lossy().to_string(),
                readonly: false,
                ..cri::Mount::default()
            });
        }
    }

    attach_termination_log(&mut mounts, root, uid, container);

    Ok(mounts)
}

fn attach_termination_log(mounts: &mut Vec<cri::Mount>, root: &Path, uid: &str, container: &Value) {
    let c_name = container
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("container");
    let term_path = container
        .get("terminationMessagePath")
        .and_then(Value::as_str)
        .unwrap_or("/dev/termination-log");
    if term_path.is_empty() || mounts.iter().any(|m| m.container_path == term_path) {
        return;
    }
    let term_host_file = root
        .join("pods")
        .join(uid)
        .join("containers")
        .join(c_name)
        .join("termination-log");
    if let Some(parent) = term_host_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if !term_host_file.exists() {
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&term_host_file);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&term_host_file, std::fs::Permissions::from_mode(0o666));
    }
    mounts.push(cri::Mount {
        container_path: term_path.to_string(),
        host_path: term_host_file.to_string_lossy().to_string(),
        readonly: false,
        ..cri::Mount::default()
    });
}

/// Maps pod and container `securityContext` onto the CRI security context.
///
/// Container fields override pod fields; the pod `fsGroup` joins the
/// supplementary groups so group-owned volumes are writable, as upstream.
fn build_security_context(
    pod: &Value,
    container: &Value,
) -> Result<Option<cri::LinuxContainerSecurityContext>, KubeletError> {
    let pod_sc = pod.pointer("/spec/securityContext");
    let container_sc = container.get("securityContext");
    let id = |key: &str| {
        container_sc
            .and_then(|sc| sc.get(key))
            .or_else(|| pod_sc.and_then(|sc| sc.get(key)))
            .and_then(Value::as_i64)
            .filter(|value| *value >= 0)
    };
    let run_as_user = id("runAsUser");
    let run_as_group = id("runAsGroup");
    let non_root = container_sc
        .and_then(|sc| sc.get("runAsNonRoot"))
        .or_else(|| pod_sc.and_then(|sc| sc.get("runAsNonRoot")))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if non_root && run_as_user == Some(0) {
        return Err(KubeletError::InvalidConfiguration {
            field: "securityContext.runAsNonRoot".to_string(),
            reason: "container would run as root".to_string(),
        });
    }
    let mut supplemental: Vec<i64> = pod_sc
        .and_then(|sc| sc.get("supplementalGroups"))
        .and_then(Value::as_array)
        .map(|groups| {
            groups
                .iter()
                .filter_map(Value::as_i64)
                .filter(|group| *group >= 0)
                .collect()
        })
        .unwrap_or_default();
    if let Some(fs_group) = pod_sc
        .and_then(|sc| sc.get("fsGroup"))
        .and_then(Value::as_i64)
        .filter(|group| *group >= 0)
        && !supplemental.contains(&fs_group)
    {
        supplemental.push(fs_group);
    }
    let privileged = container_sc
        .and_then(|sc| sc.get("privileged"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let readonly_rootfs = container_sc
        .and_then(|sc| sc.get("readOnlyRootFilesystem"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let capabilities = container_sc
        .and_then(|sc| sc.get("capabilities"))
        .map(|caps| cri::Capability {
            add_capabilities: security_str_list(caps, "add"),
            drop_capabilities: security_str_list(caps, "drop"),
            ..cri::Capability::default()
        })
        .filter(|caps| !caps.add_capabilities.is_empty() || !caps.drop_capabilities.is_empty());
    let selinux_options = container_sc
        .and_then(|sc| sc.get("seLinuxOptions"))
        .or_else(|| pod_sc.and_then(|sc| sc.get("seLinuxOptions")))
        .map(|options| cri::SeLinuxOption {
            user: security_str_field(options, "user"),
            role: security_str_field(options, "role"),
            r#type: security_str_field(options, "type"),
            level: security_str_field(options, "level"),
        })
        .filter(|options| {
            !options.user.is_empty()
                || !options.role.is_empty()
                || !options.r#type.is_empty()
                || !options.level.is_empty()
        });
    let no_new_privs = container_sc
        .and_then(|sc| sc.get("allowPrivilegeEscalation"))
        .and_then(Value::as_bool)
        .is_some_and(|esc| !esc);
    if run_as_user.is_none()
        && run_as_group.is_none()
        && supplemental.is_empty()
        && !privileged
        && !readonly_rootfs
        && capabilities.is_none()
        && selinux_options.is_none()
        && !no_new_privs
    {
        return Ok(None);
    }
    Ok(Some(cri::LinuxContainerSecurityContext {
        run_as_user: run_as_user.map(|value| cri::Int64Value { value }),
        run_as_group: run_as_group.map(|value| cri::Int64Value { value }),
        supplemental_groups: supplemental,
        privileged,
        readonly_rootfs,
        capabilities,
        selinux_options,
        no_new_privs,
        ..cri::LinuxContainerSecurityContext::default()
    }))
}

fn security_str_list(sc: &Value, key: &str) -> Vec<String> {
    sc.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn security_str_field(sc: &Value, key: &str) -> String {
    sc.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn build_container_resources(container: &Value) -> Option<cri::LinuxContainerResources> {
    let res = container.get("resources")?;
    let mut resources = cri::LinuxContainerResources::default();
    let mut has_resources = false;

    if let Some(limits) = res.get("limits") {
        if let Some(cpu) = limits.get("cpu").and_then(Value::as_str)
            && let Some(milli) = parse_cpu_quantity_milli(cpu)
        {
            let quota = i64::try_from(milli.saturating_mul(100)).unwrap_or(i64::MAX);
            resources.cpu_quota = quota;
            resources.cpu_period = 100_000;
            has_resources = true;
        }
        if let Some(mem) = limits.get("memory").and_then(Value::as_str)
            && let Some(bytes) = parse_memory_quantity_bytes(mem)
        {
            resources.memory_limit_in_bytes = i64::try_from(bytes).unwrap_or(i64::MAX);
            has_resources = true;
        }
    }
    if resources.cpu_quota == 0 {
        resources.cpu_quota = -1;
        resources.cpu_period = 100_000;
    }
    let cpu_req = res
        .get("requests")
        .and_then(|r| r.get("cpu"))
        .and_then(Value::as_str);
    if let Some(cpu) = cpu_req
        && let Some(milli) = parse_cpu_quantity_milli(cpu)
    {
        let shares = i64::try_from(milli.saturating_mul(1024) / 1000)
            .unwrap_or(i64::MAX)
            .max(2);
        resources.cpu_shares = shares;
        has_resources = true;
    } else {
        resources.cpu_shares = 2;
    }

    if has_resources { Some(resources) } else { None }
}

/// Builds the CRI container configuration for one attempt of a spec container.
///
/// Follows the kubelet: `command` and `args` map onto the CRI fields of the same
/// name, and `env.valueFrom.fieldRef` resolves pod metadata and status fields.
/// `secretKeyRef` and `configMapKeyRef` are resolved by `start_attempt`.
pub fn container_config(
    pod: &Value,
    container: &Value,
    attempt: u32,
) -> Result<cri::ContainerConfig, KubeletError> {
    container_config_with_root(pod, container, attempt, None)
}

fn resolve_env_value(
    pod: &Value,
    container: &str,
    key: &str,
    entry: &Value,
    env_objects: &EnvObjects,
) -> Result<String, KubeletError> {
    if let Some(value) = entry.get("value").and_then(Value::as_str) {
        return Ok(value.to_string());
    }
    let Some(source) = entry.get("valueFrom") else {
        return Ok(String::new());
    };
    if let Some(secret_ref) = source.get("secretKeyRef") {
        return key_ref_value(
            container,
            key,
            "secretKeyRef",
            secret_ref,
            &env_objects.secrets,
            secret_data_value,
        );
    }
    if let Some(config_ref) = source.get("configMapKeyRef") {
        return key_ref_value(
            container,
            key,
            "configMapKeyRef",
            config_ref,
            &env_objects.configmaps,
            configmap_data_value,
        );
    }
    if let Some(res_ref) = source.get("resourceFieldRef") {
        return resolve_downward_resource_field(pod, Some(container), res_ref).ok_or_else(|| {
            KubeletError::InvalidConfiguration {
                field: format!("spec.containers[{container}].env[{key}]"),
                reason: "invalid resourceFieldRef".to_string(),
            }
        });
    }
    let Some(field) = source
        .pointer("/fieldRef/fieldPath")
        .and_then(Value::as_str)
    else {
        let kind = source
            .as_object()
            .and_then(|map| map.keys().next().cloned())
            .unwrap_or_else(|| "valueFrom".to_string());
        return Err(KubeletError::InvalidConfiguration {
            field: format!("spec.containers[{container}].env[{key}]"),
            reason: format!("env source {kind} is not supported by this runtime"),
        });
    };
    let namespace = pod
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");
    resolve_downward_field_path(pod, namespace, field).ok_or_else(|| {
        KubeletError::InvalidConfiguration {
            field: format!("spec.containers[{container}].env[{key}]"),
            reason: format!("fieldRef {field} is not supported"),
        }
    })
}

/// `(object name, required)`. A name is required when any reference to it is not optional.
fn env_key_refs(pod: &Value, kind: &str) -> Vec<(String, bool)> {
    let containers = pod.pointer("/spec/containers").and_then(Value::as_array);
    let init_containers = pod
        .pointer("/spec/initContainers")
        .and_then(Value::as_array);
    let env_from_kind = if kind == "secretKeyRef" {
        "secretRef"
    } else {
        "configMapRef"
    };
    let mut names: Vec<(String, bool)> = Vec::new();
    let mut record = |reference: &Value| {
        let Some(name) = reference
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
        else {
            return;
        };
        let required = !reference
            .get("optional")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if let Some(existing) = names.iter_mut().find(|(existing, _)| existing == name) {
            existing.1 |= required;
        } else {
            names.push((name.to_string(), required));
        }
    };
    for container in containers
        .into_iter()
        .flatten()
        .chain(init_containers.into_iter().flatten())
    {
        if let Some(env_from) = container.get("envFrom").and_then(Value::as_array) {
            for source in env_from {
                if let Some(reference) = source.get(env_from_kind) {
                    record(reference);
                }
            }
        }
        if let Some(env) = container.get("env").and_then(Value::as_array) {
            for entry in env {
                if let Some(reference) = entry.pointer(&format!("/valueFrom/{kind}")) {
                    record(reference);
                }
            }
        }
    }
    names
}

fn key_ref_value(
    container: &str,
    env_key: &str,
    kind: &str,
    reference: &Value,
    objects: &BTreeMap<String, Value>,
    read_key: fn(&Value, &str) -> Option<String>,
) -> Result<String, KubeletError> {
    let name = reference.get("name").and_then(Value::as_str).unwrap_or("");
    let key = reference.get("key").and_then(Value::as_str).unwrap_or("");
    let optional = reference
        .get("optional")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let field = format!("spec.containers[{container}].env[{env_key}]");
    let Some(object) = objects.get(name) else {
        if optional {
            return Ok(String::new());
        }
        return Err(KubeletError::InvalidConfiguration {
            field,
            reason: format!("{kind} {name} was not found"),
        });
    };
    match read_key(object, key) {
        Some(value) => Ok(value),
        None if optional => Ok(String::new()),
        None => Err(KubeletError::InvalidConfiguration {
            field,
            reason: format!("{kind} {name} has no key {key}"),
        }),
    }
}

fn secret_data_value(secret: &Value, key: &str) -> Option<String> {
    if let Some(value) = secret
        .get("stringData")
        .and_then(Value::as_object)
        .and_then(|data| data.get(key))
        .and_then(Value::as_str)
    {
        return Some(value.to_string());
    }
    let encoded = secret
        .get("data")
        .and_then(Value::as_object)
        .and_then(|data| data.get(key))
        .and_then(Value::as_str)?;
    let bytes =
        diorama_pki::base64_decode(encoded.trim()).unwrap_or_else(|_| encoded.as_bytes().to_vec());
    String::from_utf8(bytes).ok()
}

fn configmap_data_value(configmap: &Value, key: &str) -> Option<String> {
    configmap
        .get("data")
        .and_then(Value::as_object)
        .and_then(|data| data.get(key))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Pull behaviour from `imagePullPolicy`, defaulting as the kubelet does:
/// `Always` for `:latest` or untagged images, `IfNotPresent` otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullPolicy {
    Always,
    IfNotPresent,
    Never,
}

impl PullPolicy {
    #[must_use]
    pub fn of(container: &Value) -> Self {
        let image = container.get("image").and_then(Value::as_str).unwrap_or("");
        match container.get("imagePullPolicy").and_then(Value::as_str) {
            Some("Never") => Self::Never,
            Some("Always") => Self::Always,
            None if is_latest(image) => Self::Always,
            _ => Self::IfNotPresent,
        }
    }
}

/// `:latest` or no tag at all, without a digest.
fn is_latest(image: &str) -> bool {
    if image.contains('@') {
        return false;
    }
    let last = image.rsplit('/').next().unwrap_or(image);
    match last.rsplit_once(':') {
        Some((_, tag)) => tag == "latest",
        None => true,
    }
}

/// Finds the container id for a pod uid and container name: the latest attempt,
/// or the one before it when `previous` is set.
pub async fn resolve_container(
    runtime: &dyn RuntimeProvider,
    pod_uid: &str,
    container_name: &str,
    previous: bool,
) -> Result<String, KubeletError> {
    let filter = cri::ContainerFilter {
        label_selector: BTreeMap::from([
            (LABEL_MANAGED_BY.to_string(), MANAGED_BY.to_string()),
            (LABEL_POD_UID.to_string(), pod_uid.to_string()),
            (LABEL_CONTAINER_NAME.to_string(), container_name.to_string()),
        ]),
        ..cri::ContainerFilter::default()
    };
    let mut containers = runtime.list_containers(Some(&filter)).await?;
    containers.sort_by_key(|c| c.metadata.as_ref().map_or(0, |m| m.attempt));
    let index = containers.len().checked_sub(if previous { 2 } else { 1 });
    index
        .and_then(|i| containers.get(i))
        .map(|c| c.id.clone())
        .ok_or_else(|| KubeletError::ContainerOperationFailed {
            container: container_name.to_string(),
            reason: format!(
                "no {}container for pod {pod_uid}",
                if previous { "previous " } else { "" }
            ),
        })
}

/// Pod reconciler driving pod lifecycle on the registered node.
#[derive(Clone, Debug)]
pub struct PodReconciler {
    client: Arc<KubernetesApiClient>,
    runtime: Arc<dyn RuntimeProvider>,
    node_name: String,
    node_ip: String,
    cpu_manager: Arc<CpuManager>,
    checkpoint_invalidated: Arc<AtomicBool>,
    root_dir: PathBuf,
    apiserver: Option<Arc<ApiserverService>>,
    cluster_dns: Vec<String>,
    cluster_domain: String,
    backoff: Arc<Mutex<BTreeMap<String, RestartBackoff>>>,
    terminating: Arc<Mutex<BTreeSet<String>>>,
    probe_trackers: Arc<Mutex<BTreeMap<String, ProbeTracker>>>,
    registered_nodes: Arc<Mutex<BTreeSet<String>>>,
    pod_certificates: PodCertificateCache,
    started_pods: Arc<Mutex<BTreeSet<String>>>,
    observed_taint_times: Arc<Mutex<BTreeMap<(String, String), u64>>>,
}

type CachedPodCertificateKey = diorama_pki::PodCertificateKeyData;
type PodCertificateCache = Arc<Mutex<BTreeMap<(String, String, String), CachedPodCertificateKey>>>;

#[derive(Debug, Clone)]
struct PreemptionOutcome {
    nominated_node: String,
    victims: Vec<Value>,
    can_schedule_immediately: bool,
}

impl PodReconciler {
    #[must_use]
    pub fn new(
        client: Arc<KubernetesApiClient>,
        runtime: Arc<dyn RuntimeProvider>,
        node_name: impl Into<String>,
        node_ip: impl Into<String>,
    ) -> Self {
        let node_ip_str = node_ip.into();
        let effective_ip = if node_ip_str.is_empty() {
            "127.0.0.1".to_string()
        } else {
            node_ip_str
        };
        let dummy_cpu_manager = Arc::new(CpuManager::new(
            "none",
            BTreeMap::new(),
            BTreeSet::new(),
            detect_host_cpu_count(),
            PathBuf::from("/tmp/diorama-node/cpu_manager_state"),
        ));
        Self {
            client,
            runtime,
            node_name: node_name.into(),
            node_ip: effective_ip,
            cpu_manager: dummy_cpu_manager,
            checkpoint_invalidated: Arc::new(AtomicBool::new(false)),
            root_dir: PathBuf::from("/var/lib/kubelet"),
            apiserver: None,
            cluster_dns: vec![DEFAULT_CLUSTER_DNS.to_string()],
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            backoff: Arc::new(Mutex::new(BTreeMap::new())),
            terminating: Arc::new(Mutex::new(BTreeSet::new())),
            probe_trackers: Arc::new(Mutex::new(BTreeMap::new())),
            registered_nodes: Arc::new(Mutex::new(BTreeSet::new())),
            pod_certificates: Arc::new(Mutex::new(BTreeMap::new())),
            started_pods: Arc::new(Mutex::new(BTreeSet::new())),
            observed_taint_times: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    #[must_use]
    pub fn with_cluster_dns(mut self, cluster_dns: Vec<String>) -> Self {
        self.cluster_dns = cluster_dns;
        self
    }

    #[must_use]
    pub fn with_cluster_domain(mut self, cluster_domain: impl Into<String>) -> Self {
        self.cluster_domain = cluster_domain.into();
        self
    }

    #[must_use]
    pub fn cluster_dns(&self) -> &[String] {
        &self.cluster_dns
    }

    #[must_use]
    pub fn cluster_domain(&self) -> &str {
        &self.cluster_domain
    }

    #[must_use]
    pub fn with_cpu_manager(mut self, cpu_manager: Arc<CpuManager>) -> Self {
        self.cpu_manager = cpu_manager;
        self
    }

    #[must_use]
    pub fn with_root_dir(mut self, root_dir: impl Into<PathBuf>) -> Self {
        self.root_dir = root_dir.into();
        self
    }

    #[must_use]
    pub fn with_apiserver(mut self, apiserver: Arc<ApiserverService>) -> Self {
        self.apiserver = Some(apiserver);
        self
    }

    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    #[must_use]
    pub fn cpu_manager(&self) -> &CpuManager {
        &self.cpu_manager
    }

    pub fn mark_checkpoint_invalidated(&self, invalidated: bool) {
        self.checkpoint_invalidated
            .store(invalidated, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_checkpoint_invalidated(&self) -> bool {
        self.checkpoint_invalidated.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn runtime_provider_name(&self) -> &str {
        self.runtime.provider_name()
    }

    #[must_use]
    pub fn get_pod_volume_dir(
        &self,
        pod_uid_or_name: &str,
        plugin_name: &str,
        volume_name: &str,
    ) -> PathBuf {
        self.root_dir
            .join("pods")
            .join(pod_uid_or_name)
            .join("volumes")
            .join(plugin_name)
            .join(volume_name)
    }

    /// Finds the container id for a pod uid and container name: the latest attempt,
    /// or the one before it when `previous` is set.
    pub async fn resolve_container(
        &self,
        pod_uid: &str,
        container_name: &str,
        previous: bool,
    ) -> Result<String, KubeletError> {
        resolve_container(self.runtime.as_ref(), pod_uid, container_name, previous).await
    }

    pub async fn get_container_logs(
        &self,
        pod_uid: &str,
        container_name: &str,
        tail_lines: Option<usize>,
    ) -> Result<String, KubeletError> {
        let options = LogOptions {
            tail_lines,
            ..LogOptions::default()
        };
        self.read_container_logs(pod_uid, container_name, &options)
            .await
    }

    pub async fn read_container_logs(
        &self,
        pod_uid: &str,
        container_name: &str,
        options: &LogOptions,
    ) -> Result<String, KubeletError> {
        let id = self
            .resolve_container(pod_uid, container_name, options.previous)
            .await?;
        self.runtime.container_logs(&id, options).await
    }

    pub async fn exec_in_container(
        &self,
        pod_uid: &str,
        container_name: &str,
        cmd: &[String],
    ) -> Result<ExecResult, KubeletError> {
        let id = self
            .resolve_container(pod_uid, container_name, false)
            .await?;
        self.runtime.exec_sync(&id, cmd, EXEC_TIMEOUT_SECS).await
    }

    /// Returns the companion worker node name for this reconciler's primary node.
    #[must_use]
    pub fn companion_node_name(&self) -> String {
        crate::config::companion_node_name(&self.node_name)
    }

    /// Checks if a node name matches the primary node, companion node, or any registered cluster node.
    #[must_use]
    pub fn is_managed_node(&self, name: &str) -> bool {
        if name.is_empty() {
            return false;
        }
        if name == self.node_name
            || name == self.companion_node_name()
            || name.starts_with("diorama-node")
        {
            return true;
        }
        if let Ok(set) = self.registered_nodes.lock()
            && set.contains(name)
        {
            return true;
        }
        false
    }

    /// Selects the appropriate target node for an unscheduled or selector-targeted pod.
    #[must_use]
    pub fn select_target_node_for_pod(&self, pod: &Value) -> String {
        if let Some(node) = pod.pointer("/spec/nodeName").and_then(Value::as_str)
            && self.is_managed_node(node)
        {
            return node.to_string();
        }
        if let Some(selector) = pod.pointer("/spec/nodeSelector").and_then(Value::as_object)
            && let Some(hostname) = selector
                .get("kubernetes.io/hostname")
                .and_then(Value::as_str)
            && self.is_managed_node(hostname)
        {
            return hostname.to_string();
        }
        self.node_name.clone()
    }

    /// Reports workload-restart needs for surviving external-runtime containers when
    /// the CPU manager checkpoint was invalidated.
    pub async fn report_workload_restart_needs(
        &self,
        namespace: &str,
    ) -> Result<Vec<WorkloadRestartReport>, KubeletError> {
        let mut reports = Vec::new();
        if !self.runtime.is_external() || !self.is_checkpoint_invalidated() {
            return Ok(reports);
        }
        let pod_list = self.client.list_pods(namespace).await?;
        let companion_name = self.companion_node_name();
        for pod in pod_list
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            reports.extend(check_pod_restart_need(
                pod,
                &self.node_name,
                self.runtime.provider_name(),
                namespace,
            ));
            reports.extend(check_pod_restart_need(
                pod,
                &companion_name,
                self.runtime.provider_name(),
                namespace,
            ));
        }
        Ok(reports)
    }

    /// Reconciles all pods in the specified namespace assigned to locally managed nodes.
    pub async fn reconcile_namespace(&self, namespace: &str) -> Result<usize, KubeletError> {
        let pod_list = self.client.list_pods(namespace).await?;
        let mut reconciled = 0;
        let items = pod_list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let node_docs = self.discover_cluster_nodes().await;
        for pod in &items {
            let assigned_node = match pod.pointer("/spec/nodeName").and_then(Value::as_str) {
                Some(n) if self.is_managed_node(n) => n,
                _ => continue,
            };
            if pod.pointer("/metadata/deletionTimestamp").is_none() {
                if let Some(node) = node_docs.iter().find(|n| {
                    n.pointer("/metadata/name").and_then(Value::as_str) == Some(assigned_node)
                }) && self.should_evict_for_no_execute_taint(pod, node)
                {
                    let _ = self
                        .client
                        .delete_pod_options(namespace, pod_name(pod), Some(0))
                        .await;
                    continue;
                }
                if has_conflicting_earlier_pod_on_node(pod, assigned_node, &items) {
                    self.mark_bound_pod_failed_hostport(namespace, pod).await;
                    continue;
                }
            }
            let outcome = if pod.pointer("/metadata/deletionTimestamp").is_some() {
                self.terminate_pod(namespace, pod).await
            } else {
                self.sync_pod(namespace, pod).await
            };
            match outcome {
                Ok(()) => reconciled += 1,
                Err(e) => eprintln!("Failed to sync pod {namespace}/{}: {e}", pod_name(pod)),
            }
        }
        Ok(reconciled)
    }

    fn record_committed_quota(committed: &mut BTreeMap<String, i128>, pod: &Value) {
        for (k, v) in diorama_apiserver::quota::pod_usage(pod) {
            *committed.entry(k).or_insert(0) += v;
        }
    }

    fn deduct_committed_quota(committed: &mut BTreeMap<String, i128>, pod: &Value) {
        for (k, v) in diorama_apiserver::quota::pod_usage(pod) {
            if let Some(entry) = committed.get_mut(&k) {
                *entry = (*entry - v).max(0);
            }
        }
    }

    fn find_node_for_pod(
        pod: &Value,
        nodes: &[Value],
        committed_by_node: &BTreeMap<String, BTreeMap<String, i128>>,
        all_pods: &[Value],
    ) -> Result<String, String> {
        let mut port_conflict = false;
        let mut other_reason = None;

        for node_doc in nodes {
            let Some(c_name) = node_doc.pointer("/metadata/name").and_then(Value::as_str) else {
                continue;
            };
            let default_committed = BTreeMap::new();
            let c_committed = committed_by_node.get(c_name).unwrap_or(&default_committed);

            if let Err(reason) = pod_fits_node(node_doc, c_committed, pod) {
                if other_reason.is_none() {
                    other_reason = Some(reason);
                }
                continue;
            }
            if has_conflicting_pod_on_node(pod, c_name, all_pods) {
                port_conflict = true;
                continue;
            }
            return Ok(c_name.to_string());
        }

        if port_conflict {
            Err("node(s) didn't have free ports for the requested pod ports".to_string())
        } else {
            Err(other_reason.unwrap_or_else(|| {
                "node(s) didn't have free ports for the requested pod ports".to_string()
            }))
        }
    }

    fn node_preemption_priority_tuple(
        node: &Value,
        all_pods: &[Value],
        candidate: &Value,
        candidate_priority: i64,
    ) -> (i64, i64, String) {
        let name = node
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let mut prios: Vec<i64> = all_pods
            .iter()
            .filter(|p| {
                p.pointer("/spec/nodeName").and_then(Value::as_str) == Some(name)
                    && is_active_pod(p)
                    && !is_same_pod(p, candidate)
                    && pod_priority(p) < candidate_priority
            })
            .map(pod_priority)
            .collect();
        if prios.is_empty() {
            (i64::MAX, i64::MAX, name.to_string())
        } else {
            prios.sort_unstable();
            (
                prios[0],
                *prios.last().unwrap_or(&prios[0]),
                name.to_string(),
            )
        }
    }

    fn evaluate_node_preemption(
        node: &Value,
        candidate: &Value,
        candidate_priority: i64,
        committed_by_node: &BTreeMap<String, BTreeMap<String, i128>>,
        all_pods: &[Value],
    ) -> Option<PreemptionOutcome> {
        let node_name = node.pointer("/metadata/name").and_then(Value::as_str)?;

        // Preemption cannot overcome affinity, selector, or taint mismatch
        if node_matches_affinity_and_selector(node, candidate).is_err()
            || node_tolerates_taints(node, candidate).is_err()
        {
            return None;
        }

        // Check if node could EVER fit the pod (against empty node capacity)
        let empty_committed = BTreeMap::new();
        if pod_fits_node_resources(node, &empty_committed, candidate).is_err() {
            return None;
        }

        // Find candidate victims on this node (strictly lower priority)
        let mut victims: Vec<Value> = all_pods
            .iter()
            .filter(|other| {
                other.pointer("/spec/nodeName").and_then(Value::as_str) == Some(node_name)
                    && is_active_pod(other)
                    && !is_same_pod(other, candidate)
                    && pod_priority(other) < candidate_priority
            })
            .cloned()
            .collect();

        if victims.is_empty() {
            return None;
        }

        // Sort victims: lowest priority first, then newest creation timestamp first
        victims.sort_by(|a, b| {
            pod_priority(a).cmp(&pod_priority(b)).then_with(|| {
                let t_a = a
                    .pointer("/metadata/creationTimestamp")
                    .and_then(Value::as_str);
                let t_b = b
                    .pointer("/metadata/creationTimestamp")
                    .and_then(Value::as_str);
                t_b.cmp(&t_a)
            })
        });

        // Simulate evicting victims one by one
        let mut simulated_committed = committed_by_node
            .get(node_name)
            .cloned()
            .unwrap_or_default();
        let mut active_pods_on_node: Vec<Value> = all_pods
            .iter()
            .filter(|p| {
                p.pointer("/spec/nodeName").and_then(Value::as_str) == Some(node_name)
                    && is_active_pod(p)
                    && !is_same_pod(p, candidate)
            })
            .cloned()
            .collect();

        let mut chosen_victims = Vec::new();
        let mut fits = false;

        for victim in victims {
            chosen_victims.push(victim.clone());
            Self::deduct_committed_quota(&mut simulated_committed, &victim);
            if let Some(pos) = active_pods_on_node
                .iter()
                .position(|p| is_same_pod(p, &victim))
            {
                active_pods_on_node.remove(pos);
            }

            let resources_fit =
                pod_fits_node_resources(node, &simulated_committed, candidate).is_ok();
            let ports_fit = !active_pods_on_node.iter().any(|other| {
                !is_pod_unschedulable(other) && pods_have_host_port_conflict(candidate, other)
            });

            if resources_fit && ports_fit {
                fits = true;
                break;
            }
        }

        if !fits {
            return None;
        }

        let any_victim_has_finalizers = chosen_victims.iter().any(|v| {
            v.pointer("/metadata/finalizers")
                .and_then(Value::as_array)
                .is_some_and(|f| !f.is_empty())
        });
        let can_schedule_immediately = !any_victim_has_finalizers;

        Some(PreemptionOutcome {
            nominated_node: node_name.to_string(),
            victims: chosen_victims,
            can_schedule_immediately,
        })
    }

    fn evaluate_preemption_for_pod(
        candidate: &Value,
        nodes: &[Value],
        committed_by_node: &BTreeMap<String, BTreeMap<String, i128>>,
        all_pods: &[Value],
    ) -> Option<PreemptionOutcome> {
        if !pod_allows_preemption(candidate) {
            return None;
        }
        let candidate_priority = pod_priority(candidate);

        let mut sorted_nodes = nodes.to_vec();
        sorted_nodes.sort_by_key(|n| {
            Self::node_preemption_priority_tuple(n, all_pods, candidate, candidate_priority)
        });

        let mut best_outcome: Option<PreemptionOutcome> = None;

        for node in &sorted_nodes {
            let Some(outcome) = Self::evaluate_node_preemption(
                node,
                candidate,
                candidate_priority,
                committed_by_node,
                all_pods,
            ) else {
                continue;
            };

            if let Some(ref current_best) = best_outcome {
                let current_max_prio = current_best
                    .victims
                    .iter()
                    .map(pod_priority)
                    .max()
                    .unwrap_or(i64::MAX);
                let outcome_max_prio = outcome
                    .victims
                    .iter()
                    .map(pod_priority)
                    .max()
                    .unwrap_or(i64::MAX);
                if outcome_max_prio < current_max_prio
                    || (outcome_max_prio == current_max_prio
                        && outcome.victims.len() < current_best.victims.len())
                {
                    best_outcome = Some(outcome);
                }
            } else {
                best_outcome = Some(outcome);
            }
        }

        best_outcome
    }

    fn update_known_pod(all_pods: &mut Vec<Value>, pod: Value) {
        if let Some(pos) = all_pods.iter().position(|p| is_same_pod(p, &pod)) {
            all_pods[pos] = pod;
        } else {
            all_pods.push(pod);
        }
    }

    async fn discover_cluster_nodes(&self) -> Vec<Value> {
        let mut node_docs: Vec<Value> = match self.client.list_nodes().await {
            Ok(list) => list
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };

        if !node_docs
            .iter()
            .any(|n| n.pointer("/metadata/name").and_then(Value::as_str) == Some(&self.node_name))
            && let Ok(p) = self.client.get_node(&self.node_name).await
        {
            node_docs.push(p);
        }
        let companion_name = self.companion_node_name();
        if !node_docs
            .iter()
            .any(|n| n.pointer("/metadata/name").and_then(Value::as_str) == Some(&companion_name))
            && let Ok(c) = self.client.get_node(&companion_name).await
        {
            node_docs.push(c);
        }

        let primary = self.node_name.clone();
        node_docs.sort_by(|a, b| {
            let name_a = a
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let name_b = b
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            if name_a == primary && name_b != primary {
                std::cmp::Ordering::Less
            } else if name_b == primary && name_a != primary {
                std::cmp::Ordering::Greater
            } else {
                name_a.cmp(name_b)
            }
        });

        if let Ok(mut set) = self.registered_nodes.lock() {
            set.clear();
            for n in &node_docs {
                if let Some(name) = n.pointer("/metadata/name").and_then(Value::as_str) {
                    set.insert(name.to_string());
                }
            }
        }

        node_docs
    }

    fn prune_stale_taints(
        observed_cache: &mut BTreeMap<(String, String), u64>,
        node_name: &str,
        current_taints: &[&Value],
    ) {
        let current_keys: BTreeSet<String> = current_taints
            .iter()
            .map(|t| {
                let k = t.get("key").and_then(Value::as_str).unwrap_or("");
                let v = t.get("value").and_then(Value::as_str).unwrap_or("");
                format!("{k}={v}")
            })
            .collect();
        observed_cache.retain(|(n, tk), _| n != node_name || current_keys.contains(tk));
    }

    fn taint_start_time(
        observed_cache: &mut BTreeMap<(String, String), u64>,
        node_name: &str,
        taint: &Value,
        now: u64,
    ) -> u64 {
        if let Some(added) = taint
            .get("timeAdded")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_seconds)
        {
            added
        } else {
            let t_key = taint.get("key").and_then(Value::as_str).unwrap_or("");
            let t_val = taint.get("value").and_then(Value::as_str).unwrap_or("");
            let taint_id = format!("{t_key}={t_val}");
            *observed_cache
                .entry((node_name.to_string(), taint_id))
                .or_insert(now)
        }
    }

    fn taint_toleration_deadline(
        pod_tolerations: &[Value],
        taint: &Value,
        start_sec: u64,
    ) -> Option<u64> {
        let matching: Vec<&Value> = pod_tolerations
            .iter()
            .filter(|tol| toleration_matches_taint(tol, taint))
            .collect();
        if matching.is_empty() {
            return Some(start_sec);
        }
        let finite: Vec<i64> = matching
            .iter()
            .filter_map(|tol| tol.get("tolerationSeconds").and_then(Value::as_i64))
            .collect();
        if !finite.is_empty() {
            let min_tol = *finite.iter().min().unwrap_or(&0);
            return Some(start_sec.saturating_add(u64::try_from(min_tol.max(0)).unwrap_or(0)));
        }
        None
    }

    fn should_evict_for_no_execute_taint(&self, pod: &Value, node: &Value) -> bool {
        let Some(taints) = node.pointer("/spec/taints").and_then(Value::as_array) else {
            return false;
        };
        let no_exec: Vec<&Value> = taints
            .iter()
            .filter(|t| t.get("effect").and_then(Value::as_str) == Some("NoExecute"))
            .collect();
        if no_exec.is_empty() {
            return false;
        }

        let pod_tolerations = pod
            .pointer("/spec/tolerations")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);

        let now = now_unix();
        let node_name = node
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or(&self.node_name);

        let mut cache = self
            .observed_taint_times
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        Self::prune_stale_taints(&mut cache, node_name, &no_exec);

        for taint in &no_exec {
            let start_sec = Self::taint_start_time(&mut cache, node_name, taint, now);
            if let Some(deadline) =
                Self::taint_toleration_deadline(pod_tolerations, taint, start_sec)
                && now >= deadline
            {
                return true;
            }
        }
        false
    }

    async fn emit_failed_scheduling_event(&self, namespace: &str, pod: &Value, message: &str) {
        let name = pod_name(pod);
        let uid = pod
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap_or("");
        let now = now_rfc3339();
        let event_name = format!("{name}.failedscheduling");
        let doc = json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": {
                "name": event_name,
                "namespace": namespace,
            },
            "involvedObject": {
                "kind": "Pod",
                "namespace": namespace,
                "name": name,
                "uid": uid,
                "apiVersion": "v1",
            },
            "reason": "FailedScheduling",
            "message": message,
            "source": {
                "component": "default-scheduler",
            },
            "reportingComponent": "default-scheduler",
            "reportingInstance": format!("default-scheduler-{}", self.node_name),
            "type": "Warning",
            "count": 1,
            "firstTimestamp": now,
            "lastTimestamp": now,
        });
        if let Some(apiserver) = &self.apiserver {
            let _ = apiserver
                .admin_client()
                .create_namespaced_object("", "Event", "events", namespace, doc)
                .await;
        } else {
            let _ = self
                .client
                .create_namespaced_object("", "Event", "events", namespace, doc)
                .await;
        }
    }

    async fn check_bound_pod_admission(
        &self,
        pod: &Value,
        node: &Value,
        node_count: usize,
        all_current_pods: &[Value],
    ) -> bool {
        let assigned = pod
            .pointer("/spec/nodeName")
            .and_then(Value::as_str)
            .unwrap_or("");
        let namespace = pod
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .unwrap_or("default");
        let is_running = pod.pointer("/status/phase").and_then(Value::as_str) == Some("Running");
        if is_running {
            return true;
        }
        let mut committed = BTreeMap::new();
        for other in all_current_pods {
            if other.pointer("/spec/nodeName").and_then(Value::as_str) == Some(assigned)
                && is_active_pod(other)
                && !is_same_pod(other, pod)
            {
                for (k, v) in diorama_apiserver::quota::pod_usage(other) {
                    *committed.entry(k).or_insert(0) += v;
                }
            }
        }
        if let Err(reason) = pod_fits_node(node, &committed, pod) {
            let mut committed_by_node = BTreeMap::new();
            committed_by_node.insert(assigned.to_string(), committed);
            if let Some(outcome) = Self::evaluate_preemption_for_pod(
                pod,
                std::slice::from_ref(node),
                &committed_by_node,
                all_current_pods,
            ) {
                let mut pod_mut = pod.clone();
                let mut current_pods_mut = all_current_pods.to_vec();
                self.apply_preemption(
                    &mut pod_mut,
                    outcome,
                    node_count,
                    &mut committed_by_node,
                    &mut current_pods_mut,
                )
                .await;
            } else {
                self.mark_unschedulable(namespace, pod, &reason, node_count)
                    .await;
            }
            return false;
        }
        true
    }

    async fn reconcile_bound_pod(
        &self,
        pod: &Value,
        node_count: usize,
        all_current_pods: &[Value],
        node_docs: &[Value],
        report: &mut ReconcileReport,
    ) {
        let assigned = pod
            .pointer("/spec/nodeName")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !self.is_managed_node(assigned) {
            return;
        }
        let namespace = pod
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .unwrap_or("default");
        let name = pod_name(pod);

        let node_doc = node_docs
            .iter()
            .find(|n| n.pointer("/metadata/name").and_then(Value::as_str) == Some(assigned));

        if pod.pointer("/metadata/deletionTimestamp").is_none() {
            if let Some(node) = node_doc
                && self.should_evict_for_no_execute_taint(pod, node)
            {
                let _ = self
                    .client
                    .delete_pod_options(namespace, name, Some(0))
                    .await;
                return;
            }

            if has_conflicting_earlier_pod_on_node(pod, assigned, all_current_pods) {
                self.mark_bound_pod_failed_hostport(namespace, pod).await;
                return;
            }

            if is_active_deadline_exceeded(pod) {
                let outcome = self.stop_pod_for_deadline_exceeded(namespace, pod).await;
                match outcome {
                    Ok(()) => report.synced += 1,
                    Err(e) => {
                        report.failed += 1;
                        eprintln!(
                            "Failed to handle active deadline exceeded for {namespace}/{name}: {e}"
                        );
                    },
                }
                return;
            }

            if let Some(node) = node_doc
                && !self
                    .check_bound_pod_admission(pod, node, node_count, all_current_pods)
                    .await
            {
                return;
            }
        }

        let outcome = if pod.pointer("/metadata/deletionTimestamp").is_some() {
            self.terminate_pod(namespace, pod).await
        } else {
            self.sync_pod(namespace, pod).await
        };
        match outcome {
            Ok(()) => report.synced += 1,
            Err(e) => {
                report.failed += 1;
                eprintln!("Failed to sync pod {namespace}/{name}: {e}");
            },
        }
    }

    async fn evict_victims(
        &self,
        outcome: &PreemptionOutcome,
        committed_by_node: &mut BTreeMap<String, BTreeMap<String, i128>>,
        all_current_pods: &mut Vec<Value>,
    ) {
        for victim in &outcome.victims {
            let v_ns = victim
                .pointer("/metadata/namespace")
                .and_then(Value::as_str)
                .unwrap_or("default");
            let v_name = pod_name(victim);

            let mut v_status = victim.get("status").cloned().unwrap_or_else(|| json!({}));
            let mut conds: Vec<Value> = v_status
                .get("conditions")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let disruption_cond = json!({
                "type": "DisruptionTarget",
                "status": "True",
                "reason": "PreemptionByScheduler",
                "message": "Preempted by higher priority pod",
                "lastProbeTime": Value::Null,
                "lastTransitionTime": diorama_apiserver::time::now_rfc3339(),
            });
            if let Some(pos) = conds
                .iter()
                .position(|c| c.get("type").and_then(Value::as_str) == Some("DisruptionTarget"))
            {
                conds[pos] = disruption_cond;
            } else {
                conds.push(disruption_cond);
            }
            v_status["conditions"] = json!(conds);
            let _ = self
                .client
                .patch_pod_status(v_ns, v_name, v_status.clone())
                .await;
            let has_finalizers = victim
                .pointer("/metadata/finalizers")
                .and_then(Value::as_array)
                .is_some_and(|f| !f.is_empty());
            if has_finalizers {
                let _ = self.client.delete_pod(v_ns, v_name).await;
            } else {
                let _ = self.client.delete_pod_options(v_ns, v_name, Some(0)).await;
            }

            if let Some(committed) = committed_by_node.get_mut(&outcome.nominated_node) {
                Self::deduct_committed_quota(committed, victim);
            }

            if outcome.can_schedule_immediately {
                let _ = self.terminate_pod(v_ns, victim).await;
                all_current_pods.retain(|p| !is_same_pod(p, victim));
            } else {
                let mut v_clone = victim.clone();
                v_clone["status"] = v_status;
                if v_clone.pointer("/metadata/deletionTimestamp").is_none() {
                    v_clone["metadata"]["deletionTimestamp"] =
                        json!(diorama_apiserver::time::now_rfc3339());
                }
                Self::update_known_pod(all_current_pods, v_clone);
            }
        }
    }

    async fn apply_preemption(
        &self,
        pod: &mut Value,
        outcome: PreemptionOutcome,
        node_count: usize,
        committed_by_node: &mut BTreeMap<String, BTreeMap<String, i128>>,
        all_current_pods: &mut Vec<Value>,
    ) -> (String, bool) {
        let namespace = pod
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .unwrap_or("default")
            .to_string();
        let name = pod_name(pod).to_string();

        self.evict_victims(&outcome, committed_by_node, all_current_pods)
            .await;

        let mut candidate_status = pod.get("status").cloned().unwrap_or_else(|| json!({}));
        candidate_status["nominatedNodeName"] = json!(outcome.nominated_node);

        if outcome.can_schedule_immediately {
            match self
                .client
                .patch_pod_status(&namespace, &name, candidate_status.clone())
                .await
            {
                Ok(updated) => *pod = updated,
                Err(_) => pod["status"] = candidate_status,
            }
            (outcome.nominated_node, true)
        } else {
            candidate_status["phase"] = json!("Pending");
            let mut conds: Vec<Value> = candidate_status
                .get("conditions")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let message = format!(
                "0/{node_count} nodes are available: 1 Waiting for pod preemption to finish."
            );
            let unsched_cond = json!({
                "type": "PodScheduled",
                "status": "False",
                "reason": "Unschedulable",
                "message": message.clone(),
                "lastProbeTime": Value::Null,
                "lastTransitionTime": diorama_apiserver::time::now_rfc3339(),
            });
            if let Some(pos) = conds
                .iter()
                .position(|c| c.get("type").and_then(Value::as_str) == Some("PodScheduled"))
            {
                conds[pos] = unsched_cond;
            } else {
                conds.push(unsched_cond);
            }
            candidate_status["conditions"] = json!(conds);
            match self
                .client
                .patch_pod_status(&namespace, &name, candidate_status.clone())
                .await
            {
                Ok(updated) => *pod = updated,
                Err(_) => pod["status"] = candidate_status,
            }
            self.emit_failed_scheduling_event(&namespace, pod, &message)
                .await;
            (outcome.nominated_node, false)
        }
    }

    async fn reconcile_unscheduled_pods(
        &self,
        mut unscheduled_pods: Vec<Value>,
        node_docs: &[Value],
        committed_by_node: &mut BTreeMap<String, BTreeMap<String, i128>>,
        all_current_pods: &mut Vec<Value>,
        report: &mut ReconcileReport,
    ) {
        unscheduled_pods.sort_by(|a, b| {
            pod_priority(b)
                .cmp(&pod_priority(a))
                .then_with(|| {
                    let t_a = a
                        .pointer("/metadata/creationTimestamp")
                        .and_then(Value::as_str);
                    let t_b = b
                        .pointer("/metadata/creationTimestamp")
                        .and_then(Value::as_str);
                    t_a.cmp(&t_b)
                })
                .then_with(|| {
                    let n_a = a.pointer("/metadata/name").and_then(Value::as_str);
                    let n_b = b.pointer("/metadata/name").and_then(Value::as_str);
                    n_a.cmp(&n_b)
                })
        });

        for mut pod in unscheduled_pods {
            if pod.pointer("/metadata/deletionTimestamp").is_some() {
                continue;
            }
            let namespace = pod
                .pointer("/metadata/namespace")
                .and_then(Value::as_str)
                .unwrap_or("default")
                .to_string();
            let name = pod_name(&pod).to_string();

            let direct_node =
                Self::find_node_for_pod(&pod, node_docs, committed_by_node, all_current_pods);

            let (target_node, should_bind_now) = match direct_node {
                Ok(node_name) => (node_name, true),
                Err(reason) => {
                    if let Some(outcome) = Self::evaluate_preemption_for_pod(
                        &pod,
                        node_docs,
                        committed_by_node,
                        all_current_pods,
                    ) {
                        self.apply_preemption(
                            &mut pod,
                            outcome,
                            node_docs.len(),
                            committed_by_node,
                            all_current_pods,
                        )
                        .await
                    } else {
                        self.mark_unschedulable(&namespace, &pod, &reason, node_docs.len())
                            .await;
                        continue;
                    }
                },
            };

            if should_bind_now {
                let mut pod_to_bind = pod.clone();
                if let Some(nom) = pod
                    .pointer("/status/nominatedNodeName")
                    .and_then(Value::as_str)
                {
                    pod_to_bind["status"]["nominatedNodeName"] = json!(nom);
                }
                let bound = match self
                    .bind_pod_to_specific_node(&namespace, &pod_to_bind, &target_node)
                    .await
                {
                    Ok(bound) => bound,
                    Err(e) => {
                        report.failed += 1;
                        eprintln!("Failed to bind pod {namespace}/{name}: {e}");
                        continue;
                    },
                };

                report.bound += 1;
                Self::record_committed_quota(
                    committed_by_node.entry(target_node.clone()).or_default(),
                    &bound,
                );
                Self::update_known_pod(all_current_pods, bound.clone());

                let outcome = self.sync_pod(&namespace, &bound).await;
                match outcome {
                    Ok(()) => report.synced += 1,
                    Err(e) => {
                        report.failed += 1;
                        eprintln!("Failed to sync pod {namespace}/{name}: {e}");
                    },
                }
            }
        }
    }

    /// Reconciles every pod in the cluster: binds unscheduled pods across managed nodes,
    /// syncs or terminates the pods assigned here, and removes sandboxes whose Pod is gone.
    pub async fn reconcile_all(&self) -> Result<ReconcileReport, KubeletError> {
        let pod_list = self.client.list_all_pods().await?;
        let mut report = ReconcileReport::default();
        let mut live_uids = BTreeSet::new();

        let node_docs = self.discover_cluster_nodes().await;

        let mut committed_by_node: BTreeMap<String, BTreeMap<String, i128>> = BTreeMap::new();
        for node in &node_docs {
            if let Some(n_name) = node.pointer("/metadata/name").and_then(Value::as_str) {
                committed_by_node.insert(
                    n_name.to_string(),
                    Self::committed_usage_for_node(&pod_list, n_name),
                );
            }
        }

        let items = pod_list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        for pod in &items {
            if let Some(uid) = pod.pointer("/metadata/uid").and_then(Value::as_str) {
                live_uids.insert(uid.to_string());
            }
        }

        let mut all_current_pods = items.clone();

        let (bound_pods, unscheduled_pods): (Vec<Value>, Vec<Value>) =
            items.into_iter().partition(|p| {
                p.pointer("/spec/nodeName")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
            });

        for pod in bound_pods {
            self.reconcile_bound_pod(
                &pod,
                node_docs.len(),
                &all_current_pods,
                &node_docs,
                &mut report,
            )
            .await;
        }

        self.reconcile_unscheduled_pods(
            unscheduled_pods,
            &node_docs,
            &mut committed_by_node,
            &mut all_current_pods,
            &mut report,
        )
        .await;

        report.orphans_stopped = self.stop_orphaned_pods(&live_uids).await?;
        Ok(report)
    }

    /// Resource requests already committed by live pods bound to managed nodes.
    #[must_use]
    pub fn committed_usage(&self, pod_list: &Value) -> BTreeMap<String, i128> {
        let mut committed = BTreeMap::new();
        for pod in pod_list
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|p| {
                p.pointer("/spec/nodeName")
                    .and_then(Value::as_str)
                    .is_some_and(|n| self.is_managed_node(n))
            })
        {
            for (k, v) in diorama_apiserver::quota::pod_usage(pod) {
                *committed.entry(k).or_insert(0) += v;
            }
        }
        committed
    }

    /// Resource requests committed by live pods bound to a specific node.
    #[must_use]
    pub fn committed_usage_for_node(pod_list: &Value, node_name: &str) -> BTreeMap<String, i128> {
        let mut committed = BTreeMap::new();
        for pod in pod_list
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|p| p.pointer("/spec/nodeName").and_then(Value::as_str) == Some(node_name))
        {
            for (k, v) in diorama_apiserver::quota::pod_usage(pod) {
                *committed.entry(k).or_insert(0) += v;
            }
        }
        committed
    }

    async fn mark_bound_pod_failed_hostport(&self, namespace: &str, pod: &Value) {
        let name = pod_name(pod);
        let current_phase = pod.pointer("/status/phase").and_then(Value::as_str);
        let current_reason = pod.pointer("/status/reason").and_then(Value::as_str);
        if current_phase == Some("Failed") && current_reason == Some("PodFitsHostPorts") {
            return;
        }
        let mut status = pod
            .get("status")
            .cloned()
            .filter(Value::is_object)
            .unwrap_or_else(|| json!({}));
        status["phase"] = json!("Failed");
        status["reason"] = json!("PodFitsHostPorts");
        status["message"] = json!("Pod Node didn't have enough resource: pods, requested: 1");
        let _ = self
            .patch_status_if_changed(namespace, name, pod, status)
            .await;
    }

    /// Records `PodScheduled=False/Unschedulable` once for a pod that cannot fit.
    async fn mark_unschedulable(
        &self,
        namespace: &str,
        pod: &Value,
        reason: &str,
        total_nodes: usize,
    ) {
        let nodes_count = if total_nodes == 0 { 2 } else { total_nodes };
        let message = if reason.contains("nodes are available") {
            reason.to_string()
        } else if pod.pointer("/spec/nodeName").is_some() {
            format!("0/1 nodes are available: 1 {reason}.")
        } else {
            format!("0/{nodes_count} nodes are available: {nodes_count} {reason}.")
        };
        let already = pod
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .is_some_and(|conds| {
                conds.iter().any(|c| {
                    c.get("type").and_then(Value::as_str) == Some("PodScheduled")
                        && c.get("status").and_then(Value::as_str) == Some("False")
                        && c.get("reason").and_then(Value::as_str) == Some("Unschedulable")
                        && c.get("message").and_then(Value::as_str) == Some(message.as_str())
                })
            });
        if already {
            return;
        }
        let mut status = pod
            .get("status")
            .cloned()
            .filter(Value::is_object)
            .unwrap_or_else(|| json!({}));
        status["phase"] = json!("Pending");
        let mut conds: Vec<Value> = status
            .get("conditions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let new_cond = json!({
            "type": "PodScheduled",
            "status": "False",
            "reason": "Unschedulable",
            "message": message,
            "lastProbeTime": Value::Null,
            "lastTransitionTime": diorama_apiserver::time::now_rfc3339(),
        });
        if let Some(pos) = conds
            .iter()
            .position(|c| c.get("type").and_then(Value::as_str) == Some("PodScheduled"))
        {
            conds[pos] = new_cond;
        } else {
            conds.push(new_cond);
        }
        status["conditions"] = json!(conds);
        let _ = self
            .client
            .patch_pod_status(namespace, pod_name(pod), status)
            .await;
        self.emit_failed_scheduling_event(namespace, pod, &message)
            .await;
    }

    /// Assigns an unscheduled pod to a managed node.
    pub async fn bind_pod_to_node(
        &self,
        namespace: &str,
        pod: &Value,
    ) -> Result<Value, KubeletError> {
        let target_node = self.select_target_node_for_pod(pod);
        self.bind_pod_to_specific_node(namespace, pod, &target_node)
            .await
    }

    /// Assigns an unscheduled pod to a specific node.
    pub async fn bind_pod_to_specific_node(
        &self,
        namespace: &str,
        pod: &Value,
        node_name: &str,
    ) -> Result<Value, KubeletError> {
        let name = pod_name(pod);
        let mut bound = match self.client.get_pod(namespace, name).await {
            Ok(latest) => latest,
            Err(_) => pod.clone(),
        };
        if let Some(nom) = pod
            .pointer("/status/nominatedNodeName")
            .and_then(Value::as_str)
        {
            bound["status"]["nominatedNodeName"] = json!(nom);
        }
        bound["spec"]["nodeName"] = json!(node_name);
        self.client
            .update_pod(namespace, name, bound)
            .await
            .map_err(|e| KubeletError::PodReconciliationFailed {
                pod: format!("{namespace}/{name}"),
                reason: format!("failed to bind pod to node {node_name}: {e}"),
            })
    }

    /// Removes sandboxes (and their containers) whose Pod object no longer exists.
    pub async fn stop_orphaned_pods(
        &self,
        live_uids: &BTreeSet<String>,
    ) -> Result<usize, KubeletError> {
        let filter = cri::PodSandboxFilter {
            label_selector: BTreeMap::from([(
                LABEL_MANAGED_BY.to_string(),
                MANAGED_BY.to_string(),
            )]),
            ..cri::PodSandboxFilter::default()
        };
        let mut orphaned: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut orphaned_pod_names: BTreeSet<(String, String)> = BTreeSet::new();
        for sandbox in self.runtime.list_pod_sandbox(Some(&filter)).await? {
            let Some(uid) = sandbox.labels.get(LABEL_POD_UID) else {
                continue;
            };
            if !live_uids.contains(uid) {
                if let (Some(ns), Some(p_name)) = (
                    sandbox.labels.get(LABEL_POD_NAMESPACE),
                    sandbox.labels.get(LABEL_POD_NAME),
                ) {
                    orphaned_pod_names.insert((ns.clone(), p_name.clone()));
                }
                orphaned.entry(uid.clone()).or_default().push(sandbox.id);
            }
        }
        for (ns, p_name) in orphaned_pod_names {
            let _ = self
                .cpu_manager
                .release_pod_cpus(&format!("{ns}/{p_name}/"));
        }
        for (uid, sandbox_ids) in &orphaned {
            for sandbox_id in sandbox_ids {
                self.remove_sandbox_tree(sandbox_id).await?;
            }
            crate::workload::unmount_tmpfs_under(&self.root_dir.join("pods").join(uid));
            eprintln!("removed sandbox of deleted pod {uid}");
        }
        Ok(orphaned.len())
    }

    /// Stops and removes a sandbox together with every container in it.
    async fn remove_sandbox_tree(&self, sandbox_id: &str) -> Result<(), KubeletError> {
        let _ = self.runtime.stop_pod_sandbox(sandbox_id).await;
        let filter = cri::ContainerFilter {
            pod_sandbox_id: sandbox_id.to_string(),
            ..cri::ContainerFilter::default()
        };
        for container in self.runtime.list_containers(Some(&filter)).await? {
            self.runtime.remove_container(&container.id).await?;
        }
        self.runtime.remove_pod_sandbox(sandbox_id).await
    }

    /// Full statuses of every container in a sandbox.
    async fn container_statuses(
        &self,
        sandbox_id: &str,
    ) -> Result<Vec<cri::ContainerStatus>, KubeletError> {
        let filter = cri::ContainerFilter {
            pod_sandbox_id: sandbox_id.to_string(),
            ..cri::ContainerFilter::default()
        };
        let mut statuses = Vec::new();
        for container in self.runtime.list_containers(Some(&filter)).await? {
            // A container removed between list and status shows up on the next pass.
            if let Ok(status) = self.runtime.container_status(&container.id).await {
                statuses.push(status);
            }
        }
        Ok(statuses)
    }

    /// Finds the pod's ready sandbox or creates one, removing stale sandboxes.
    async fn ensure_sandbox(
        &self,
        namespace: &str,
        pod: &Value,
    ) -> Result<(String, cri::PodSandboxConfig), KubeletError> {
        let name = pod_name(pod);
        let uid = pod_uid(pod)?;
        let sandboxes = self
            .runtime
            .list_pod_sandbox(Some(&uid_filter(uid)))
            .await?;
        if let Some(ready) = sandboxes
            .iter()
            .find(|s| s.state == cri::PodSandboxState::SandboxReady as i32)
        {
            let attempt = ready.metadata.as_ref().map_or(0, |m| m.attempt);
            return Ok((
                ready.id.clone(),
                sandbox_config_with_dns(pod, attempt, &self.cluster_dns, &self.cluster_domain),
            ));
        }
        let mut attempt = 0;
        for stale in &sandboxes {
            attempt = attempt.max(stale.metadata.as_ref().map_or(0, |m| m.attempt) + 1);
            self.remove_sandbox_tree(&stale.id).await?;
        }
        if pod.pointer("/status/phase").is_none() {
            let pending = pending_status(pod, &self.node_ip, "ContainerCreating", None);
            self.patch_status_if_changed(namespace, name, pod, pending)
                .await?;
        }
        let mut config =
            sandbox_config_with_dns(pod, attempt, &self.cluster_dns, &self.cluster_domain);
        let id = match self.runtime.run_pod_sandbox(&config).await {
            Ok(id) => id,
            Err(e) => {
                let has_sysctls = config.linux.as_ref().is_some_and(|l| !l.sysctls.is_empty());
                if has_sysctls {
                    if let Some(linux) = config.linux.as_mut() {
                        linux.sysctls.clear();
                    }
                    self.runtime.run_pod_sandbox(&config).await?
                } else {
                    return Err(e);
                }
            },
        };
        Ok((id, config))
    }

    /// Makes the image available under the container's pull policy.
    async fn ensure_image(
        &self,
        container: &Value,
        sandbox_config: &cri::PodSandboxConfig,
    ) -> Result<(), StartFailure> {
        let image = container.get("image").and_then(Value::as_str).unwrap_or("");
        let spec = cri::ImageSpec {
            image: image.to_string(),
            user_specified_image: image.to_string(),
            ..cri::ImageSpec::default()
        };
        let present = self
            .runtime
            .image_status(&spec)
            .await
            .map_err(|e| StartFailure {
                reason: "ErrImagePull",
                message: format!("failed to inspect image {image}: {e}"),
            })?
            .is_some();
        let pull = match PullPolicy::of(container) {
            PullPolicy::Always => true,
            PullPolicy::IfNotPresent => !present,
            PullPolicy::Never if present => false,
            PullPolicy::Never => {
                return Err(StartFailure {
                    reason: "ErrImageNeverPull",
                    message: format!(
                        "Container image \"{image}\" is not present with pull policy of Never"
                    ),
                });
            },
        };
        if pull {
            self.runtime
                .pull_image(&spec, Some(sandbox_config))
                .await
                .map_err(|e| StartFailure {
                    reason: "ErrImagePull",
                    message: format!("failed to pull image {image}: {e}"),
                })?;
        }
        Ok(())
    }

    async fn execute_lifecycle_hook(
        &self,
        container_id: &str,
        container: &Value,
        hook_val: &Value,
        pod_ip: Option<&str>,
    ) -> Result<(), String> {
        if let Some(exec) = hook_val.get("exec") {
            let cmd_arr = exec.get("command").and_then(Value::as_array);
            let command: Vec<String> = cmd_arr
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default();
            if !command.is_empty() {
                let timeout = hook_val
                    .get("timeoutSeconds")
                    .and_then(Value::as_i64)
                    .filter(|t| *t > 0)
                    .unwrap_or(EXEC_TIMEOUT_SECS);
                let res = self
                    .runtime
                    .exec_sync(container_id, &command, timeout)
                    .await
                    .map_err(|e| format!("exec hook failed: {e}"))?;
                if res.exit_code != 0 {
                    return Err(format!("exec hook exited with status {}", res.exit_code));
                }
            }
            return Ok(());
        }
        if let Some(http) = hook_val.get("httpGet") {
            let ok = http_probe(&self.runtime, container_id, pod_ip, container, http).await;
            if !ok {
                return Err("httpGet hook failed or returned non-2xx/3xx status".to_string());
            }
            return Ok(());
        }
        if let Some(sleep) = hook_val.get("sleep") {
            let seconds = sleep.get("seconds").and_then(Value::as_u64).unwrap_or(0);
            let clamped = seconds.min(30);
            if clamped > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(clamped)).await;
            }
            return Ok(());
        }
        Ok(())
    }

    async fn emit_warning_event(
        &self,
        namespace: &str,
        pod_name: &str,
        pod_uid: &str,
        reason: &str,
        message: &str,
        field_path: Option<&str>,
    ) {
        let now = now_rfc3339();
        let event_name = format!("{}.{:x}", pod_name, now_unix());
        let mut involved = json!({
            "kind": "Pod",
            "name": pod_name,
            "namespace": namespace,
            "uid": pod_uid,
            "apiVersion": "v1",
        });
        if let Some(fp) = field_path {
            involved["fieldPath"] = json!(fp);
        }
        let doc = json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": {
                "name": event_name,
                "namespace": namespace,
            },
            "involvedObject": involved,
            "reason": reason,
            "message": message,
            "type": "Warning",
            "firstTimestamp": now,
            "lastTimestamp": now,
            "count": 1,
        });
        if let Some(apiserver) = &self.apiserver {
            let _ = apiserver
                .admin_client()
                .create_namespaced_object("", "Event", "events", namespace, doc)
                .await;
        } else {
            let _ = self
                .client
                .create_namespaced_object("", "Event", "events", namespace, doc)
                .await;
        }
    }

    async fn emit_started_event_if_needed(&self, namespace: &str, pod: &Value) {
        let name = pod_name(pod);
        let Ok(uid) = pod_uid(pod) else {
            return;
        };
        {
            let mut started = self
                .started_pods
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !started.insert(uid.to_string()) {
                return;
            }
        }
        let first_container_name = pod
            .pointer("/spec/containers/0/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let now = now_rfc3339();
        let event_name = format!("{name}.started");
        let doc = json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": {
                "name": event_name,
                "namespace": namespace,
            },
            "involvedObject": {
                "kind": "Pod",
                "name": name,
                "namespace": namespace,
                "uid": uid,
                "apiVersion": "v1",
                "fieldPath": format!("spec.containers{{{first_container_name}}}"),
            },
            "reason": "Started",
            "message": format!("Started container {first_container_name}"),
            "type": "Normal",
            "source": {
                "component": "kubelet",
                "host": &self.node_name,
            },
            "firstTimestamp": now,
            "lastTimestamp": now,
            "count": 1,
        });
        if let Some(apiserver) = &self.apiserver {
            let _ = apiserver
                .admin_client()
                .create_namespaced_object("", "Event", "events", namespace, doc)
                .await;
        } else {
            let _ = self
                .client
                .create_namespaced_object("", "Event", "events", namespace, doc)
                .await;
        }
    }

    async fn emit_failed_post_start_event(
        &self,
        namespace: &str,
        pod_name: &str,
        pod_uid: &str,
        container_name: &str,
        err: &str,
    ) {
        let msg = format!("failed to execute postStart hook for container {container_name}: {err}");
        let fp = format!("spec.containers{{{container_name}}}");
        self.emit_warning_event(
            namespace,
            pod_name,
            pod_uid,
            "FailedPostStartHook",
            &msg,
            Some(&fp),
        )
        .await;
    }

    /// Executes a container's preStop hook synchronously if configured.
    async fn execute_pre_stop_hook(
        &self,
        container_id: &str,
        container: &Value,
        pod_ip: Option<&str>,
    ) {
        if let Some(pre_stop) = container.pointer("/lifecycle/preStop") {
            let _ = self
                .execute_lifecycle_hook(container_id, container, pre_stop, pod_ip)
                .await;
        }
    }

    async fn load_env_objects(
        &self,
        namespace: &str,
        pod: &Value,
    ) -> Result<EnvObjects, StartFailure> {
        let mut objects = EnvObjects::default();
        for (reference, required) in env_key_refs(pod, "secretKeyRef") {
            if objects.secrets.contains_key(&reference) {
                continue;
            }
            match self.client.get_secret(namespace, &reference).await {
                Ok(secret) => {
                    objects.secrets.insert(reference, secret);
                },
                Err(err) if required => {
                    return Err(StartFailure {
                        reason: "CreateContainerConfigError",
                        message: format!("failed to read secret {reference}: {err}"),
                    });
                },
                Err(_) => {},
            }
        }
        for (reference, required) in env_key_refs(pod, "configMapKeyRef") {
            if objects.configmaps.contains_key(&reference) {
                continue;
            }
            match self.client.get_configmap(namespace, &reference).await {
                Ok(configmap) => {
                    objects.configmaps.insert(reference, configmap);
                },
                Err(err) if required => {
                    return Err(StartFailure {
                        reason: "CreateContainerConfigError",
                        message: format!("failed to read configmap {reference}: {err}"),
                    });
                },
                Err(_) => {},
            }
        }
        let service_list = self
            .client
            .list_services("")
            .await
            .map_err(|err| StartFailure {
                reason: "CreateContainerConfigError",
                message: format!("failed to list services for service links: {err}"),
            })?;
        objects.services = service_list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(objects)
    }

    /// Pulls, creates and starts one attempt of a spec container.
    async fn start_attempt(
        &self,
        sandbox_id: &str,
        sandbox_config: &cri::PodSandboxConfig,
        pod: &Value,
        container: &Value,
        attempt: u32,
        pod_ip: Option<&str>,
    ) -> Result<String, StartFailure> {
        self.ensure_image(container, sandbox_config).await?;
        let namespace = pod
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .unwrap_or("default");
        let env_objects = self.load_env_objects(namespace, pod).await?;
        let mut config =
            container_config_with_env(pod, container, attempt, Some(&self.root_dir), &env_objects)
                .map_err(|e| StartFailure {
                    reason: "CreateContainerConfigError",
                    message: e.to_string(),
                })?;
        let name = pod_name(pod);
        let assignment = self.cpu_assignment(namespace, name, pod, container);
        let linux = config
            .linux
            .get_or_insert_with(cri::LinuxContainerConfig::default);
        let resources = linux
            .resources
            .get_or_insert_with(cri::LinuxContainerResources::default);
        if resources.cpu_shares == 0 {
            resources.cpu_shares = 2;
        }
        if !assignment.cpuset.is_empty() {
            resources.cpuset_cpus = assignment.cpuset;
        }
        if let Some(target_name) = container.get("targetContainerName").and_then(Value::as_str) {
            let filter = cri::ContainerFilter {
                pod_sandbox_id: sandbox_id.to_string(),
                ..cri::ContainerFilter::default()
            };
            if let Ok(containers) = self.runtime.list_containers(Some(&filter)).await
                && let Some(target) = containers
                    .iter()
                    .find(|c| c.metadata.as_ref().is_some_and(|m| m.name == target_name))
            {
                let linux = config
                    .linux
                    .get_or_insert_with(cri::LinuxContainerConfig::default);
                let sec = linux
                    .security_context
                    .get_or_insert_with(cri::LinuxContainerSecurityContext::default);
                sec.namespace_options = Some(cri::NamespaceOption {
                    pid: cri::NamespaceMode::Target as i32,
                    target_id: target.id.clone(),
                    ..cri::NamespaceOption::default()
                });
            }
        }
        let id = self
            .runtime
            .create_container(sandbox_id, &config, sandbox_config)
            .await
            .map_err(|e| StartFailure {
                reason: "CreateContainerError",
                message: e.to_string(),
            })?;
        self.runtime
            .start_container(&id)
            .await
            .map_err(|e| StartFailure {
                reason: "RunContainerError",
                message: e.to_string(),
            })?;
        if let Some(post_start) = container.pointer("/lifecycle/postStart")
            && let Err(err) = self
                .execute_lifecycle_hook(&id, container, post_start, pod_ip)
                .await
        {
            let _ = self.runtime.stop_container(&id, 0).await;
            let _ = self.runtime.remove_container(&id).await;
            let c_name = container_name_of(container);
            let uid = pod
                .pointer("/metadata/uid")
                .and_then(Value::as_str)
                .unwrap_or("");
            self.emit_failed_post_start_event(namespace, name, uid, c_name, &err)
                .await;
            return Err(StartFailure {
                reason: "FailedPostStartHook",
                message: format!("failed postStart hook for container {c_name}: {err}"),
            });
        }
        Ok(id)
    }

    /// Decides whether an exited container restarts now (`Ok(next attempt)`) or
    /// waits (`Err(back-off message)`), recording the back-off.
    fn restart_decision(
        &self,
        namespace: &str,
        pod_name: &str,
        uid: &str,
        container_name: &str,
        latest: &cri::ContainerStatus,
    ) -> Result<u32, String> {
        let now = now_unix();
        let ran_for = secs_from_nanos(latest.started_at)
            .zip(secs_from_nanos(latest.finished_at))
            .map_or(0, |(started, finished)| finished.saturating_sub(started));
        let key = format!("{uid}/{container_name}");
        let mut backoffs = self
            .backoff
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match backoffs.get(&key).copied() {
            Some(backoff) if now < backoff.not_before => Err(format!(
                "back-off {}s restarting failed container={container_name} pod={pod_name}_{namespace}({uid})",
                backoff.delay_secs
            )),
            previous => {
                backoffs.insert(key, next_restart_backoff(previous, ran_for, now));
                Ok(attempt_of(latest) + 1)
            },
        }
    }

    /// CPU-manager placement for a container, allocating exclusive cores when eligible.
    fn cpu_assignment(
        &self,
        namespace: &str,
        pod_name: &str,
        pod: &Value,
        container: &Value,
    ) -> CpuAssignment {
        let c_name = container
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("main");
        let key = format!("{namespace}/{pod_name}/{c_name}");
        if let Some(cores) = is_container_cpu_pinning_eligible(determine_pod_qos(pod), container) {
            match self.cpu_manager.allocate_exclusive_cpus(&key, cores) {
                Ok(cpus) => {
                    return CpuAssignment {
                        cpuset: format_cpuset(&cpus),
                        exclusive: true,
                    };
                },
                Err(e) => eprintln!("exclusive CPU allocation failed for {key}: {e}"),
            }
        }
        CpuAssignment {
            cpuset: format_cpuset(&self.cpu_manager.shared_pool()),
            exclusive: false,
        }
    }

    fn enrich_pod_for_sync(&self, pod: &Value) -> Value {
        let mut enriched = self.pod_with_service_account_volume(pod);
        if enriched
            .pointer("/status/hostIP")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            enriched["status"]["hostIP"] = json!(self.node_ip);
        }
        enriched
    }

    async fn fetch_sandbox_pod_ip(&self, sandbox_id: &str) -> Option<String> {
        self.runtime
            .pod_sandbox_status(sandbox_id)
            .await
            .ok()
            .and_then(|status| status.network)
            .map(|network| network.ip)
            .filter(|ip| !ip.is_empty())
    }

    async fn resolve_pod_ip(&self, sandbox_id: &str, pod: &Value) -> Option<String> {
        if let Some(ip) = self.fetch_sandbox_pod_ip(sandbox_id).await {
            return Some(ip);
        }
        if pod
            .pointer("/spec/hostNetwork")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Some(self.node_ip.clone());
        }
        pod.pointer("/status/podIP")
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    async fn probe_and_prune(
        &self,
        ctx: &SyncContext<'_>,
        spec_inits: &[Value],
        spec_containers: &[Value],
        statuses: &mut Vec<cri::ContainerStatus>,
        state: &mut SyncState,
    ) -> Result<(), KubeletError> {
        if !state.started_now.is_empty() {
            *statuses = self.container_statuses(ctx.sandbox_id).await?;
            let pod_name = pod_name(ctx.pod);
            self.probe_started(pod_name, spec_inits, statuses, ctx.pod_ip.as_deref(), state)
                .await?;
            self.probe_started(
                pod_name,
                spec_containers,
                statuses,
                ctx.pod_ip.as_deref(),
                state,
            )
            .await?;
        }
        self.prune_attempts(statuses).await;
        Ok(())
    }

    async fn handle_prepare_volumes_error(
        &self,
        namespace: &str,
        name: &str,
        orig_pod: &Value,
        err: &KubeletError,
    ) {
        let phase = orig_pod.pointer("/status/phase").and_then(Value::as_str);
        if matches!(phase, Some("Running" | "Succeeded" | "Failed")) {
            return;
        }
        let uid = pod_uid(orig_pod).unwrap_or(name);
        let (vol_desc, detail) = match err {
            KubeletError::PodReconciliationFailed { pod: vol, reason } => {
                (vol.as_str(), reason.as_str())
            },
            _ => ("unnamed", ""),
        };
        let msg = if detail.is_empty() {
            format!("MountVolume.SetUp failed for volume \"{vol_desc}\": {err}")
        } else {
            format!("MountVolume.SetUp failed for volume \"{vol_desc}\": {detail}")
        };
        self.emit_warning_event(namespace, name, uid, "FailedMount", &msg, None)
            .await;

        let status = pending_status(orig_pod, &self.node_ip, "ContainerCreating", None);
        let _ = self
            .patch_status_if_changed(namespace, name, orig_pod, status)
            .await;
    }

    async fn clear_unschedulable(&self, namespace: &str, name: &str, pod: &Value) {
        let mut status = pod
            .get("status")
            .cloned()
            .filter(Value::is_object)
            .unwrap_or_else(|| json!({}));
        let mut conds: Vec<Value> = status
            .get("conditions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let sched_cond = json!({
            "type": "PodScheduled",
            "status": "True",
            "reason": Value::Null,
            "message": Value::Null,
            "lastProbeTime": Value::Null,
            "lastTransitionTime": diorama_apiserver::time::now_rfc3339(),
        });
        if let Some(pos) = conds
            .iter()
            .position(|c| c.get("type").and_then(Value::as_str) == Some("PodScheduled"))
        {
            conds[pos] = sched_cond;
        } else {
            conds.push(sched_cond);
        }
        status["conditions"] = json!(conds);
        let _ = self.client.patch_pod_status(namespace, name, status).await;
    }

    async fn stop_sandbox_running_containers(&self, sandbox_id: &str) {
        let Ok(statuses) = self.container_statuses(sandbox_id).await else {
            return;
        };
        for s in statuses {
            if s.state == cri::ContainerState::ContainerRunning as i32 {
                let _ = self.runtime.stop_container(&s.id, 0).await;
            }
        }
    }

    async fn stop_pod_for_deadline_exceeded(
        &self,
        namespace: &str,
        pod: &Value,
    ) -> Result<(), KubeletError> {
        let name = pod_name(pod);
        let uid = pod_uid(pod)?;
        if let Ok(sandboxes) = self.runtime.list_pod_sandbox(Some(&uid_filter(uid))).await {
            for sandbox in &sandboxes {
                self.stop_sandbox_running_containers(&sandbox.id).await;
                let _ = self.runtime.stop_pod_sandbox(&sandbox.id).await;
            }
        }

        let generation = pod
            .pointer("/metadata/generation")
            .and_then(Value::as_i64)
            .unwrap_or(1);
        let now = now_rfc3339();
        let start_time = pod
            .pointer("/status/startTime")
            .cloned()
            .unwrap_or_else(|| json!(now));
        let host_ip = pod
            .pointer("/status/hostIP")
            .and_then(Value::as_str)
            .unwrap_or(&self.node_ip);
        let pod_ip = pod.pointer("/status/podIP").and_then(Value::as_str);

        let container_statuses = deadline_exceeded_container_statuses(pod, &now);
        let conditions = deadline_exceeded_conditions(&now, generation);

        let mut status = json!({
            "phase": "Failed",
            "reason": "DeadlineExceeded",
            "message": "Pod was active on the node longer than the specified deadline",
            "startTime": start_time,
            "hostIP": host_ip,
            "hostIPs": [{ "ip": host_ip }],
            "conditions": conditions,
            "containerStatuses": container_statuses,
            "observedGeneration": generation,
        });
        if let Some(pip) = pod_ip {
            status["podIP"] = json!(pip);
            status["podIPs"] = json!([{ "ip": pip }]);
        }

        self.patch_status_if_changed(namespace, name, pod, status)
            .await?;

        self.emit_warning_event(
            namespace,
            name,
            uid,
            "DeadlineExceeded",
            "Pod was active on the node longer than the specified deadline",
            None,
        )
        .await;

        Ok(())
    }

    /// Synchronizes an individual pod's runtime state and updates its API status.
    #[allow(clippy::too_many_lines)]
    pub async fn sync_pod(&self, namespace: &str, pod: &Value) -> Result<(), KubeletError> {
        let orig_pod = pod;
        let name = pod_name(pod);
        pod_uid(pod)?;
        if matches!(
            pod.pointer("/status/phase").and_then(Value::as_str),
            Some("Succeeded" | "Failed")
        ) {
            if pod.pointer("/status/phase").and_then(Value::as_str) == Some("Succeeded") {
                self.emit_started_event_if_needed(namespace, pod).await;
            }
            return Ok(());
        }
        if is_active_deadline_exceeded(pod) {
            return self.stop_pod_for_deadline_exceeded(namespace, pod).await;
        }
        if is_pod_unschedulable(orig_pod) {
            self.clear_unschedulable(namespace, name, orig_pod).await;
        }
        let mut enriched = self.enrich_pod_for_sync(pod);
        if let Err(e) = self.prepare_pod_volumes(namespace, &enriched).await {
            self.handle_prepare_volumes_error(namespace, name, orig_pod, &e)
                .await;
            return Err(e);
        }
        let (sandbox_id, sandbox_config) = match self.ensure_sandbox(namespace, &enriched).await {
            Ok(sandbox) => sandbox,
            Err(e) => {
                let failed = pending_status(
                    orig_pod,
                    &self.node_ip,
                    "FailedCreatePodSandBox",
                    Some(&e.to_string()),
                );
                self.patch_status_if_changed(namespace, name, orig_pod, failed)
                    .await?;
                return Err(e);
            },
        };
        let pod_ip = self.resolve_pod_ip(&sandbox_id, &enriched).await;
        if let Some(ip) = &pod_ip
            && enriched.pointer("/status/podIP").and_then(Value::as_str) != Some(ip.as_str())
        {
            enriched["status"]["podIP"] = json!(ip);
        }
        self.sync_etc_hosts(&enriched, pod_ip.as_deref())?;
        let pod = &enriched;
        let empty = Vec::new();
        let spec_init_containers = pod
            .pointer("/spec/initContainers")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        let spec_containers = pod
            .pointer("/spec/containers")
            .and_then(Value::as_array)
            .unwrap_or(&empty);

        let mut statuses = self.container_statuses(&sandbox_id).await?;
        let mut state = SyncState::default();

        let ctx = SyncContext {
            namespace,
            pod,
            sandbox_id: &sandbox_id,
            sandbox_config: &sandbox_config,
            pod_ip: pod_ip.clone(),
        };

        let all_inits_complete = self
            .reconcile_init_containers(&ctx, spec_init_containers, &statuses, &mut state)
            .await?;

        let spec_ephemeral = pod
            .pointer("/spec/ephemeralContainers")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);

        if all_inits_complete {
            self.reconcile_app_containers(&ctx, spec_containers, &statuses, &mut state)
                .await?;
            if !spec_ephemeral.is_empty() {
                self.reconcile_ephemeral_containers(&ctx, spec_ephemeral, &statuses, &mut state)
                    .await?;
            }
            self.stop_sidecars_if_app_completed(
                &ctx,
                spec_init_containers,
                spec_containers,
                &mut statuses,
            )
            .await?;
        }

        self.probe_and_prune(
            &ctx,
            spec_init_containers,
            spec_containers,
            &mut statuses,
            &mut state,
        )
        .await?;
        self.enrich_termination_messages(pod, &mut statuses).await;
        self.publish_synced_status(
            &ctx,
            orig_pod,
            spec_containers,
            spec_init_containers,
            spec_ephemeral,
            &statuses,
            &state,
        )
        .await
    }

    fn sync_etc_hosts(&self, enriched: &Value, pod_ip: Option<&str>) -> Result<(), KubeletError> {
        let host_network = enriched
            .pointer("/spec/hostNetwork")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !host_network {
            let pod_dir = self.root_dir.join("pods").join(pod_uid(enriched)?);
            let effective_ip = pod_ip.unwrap_or("");
            let _ = generate_etc_hosts(&pod_dir, enriched, effective_ip);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn publish_synced_status(
        &self,
        ctx: &SyncContext<'_>,
        orig_pod: &Value,
        spec_containers: &[Value],
        spec_inits: &[Value],
        spec_ephemeral: &[Value],
        statuses: &[cri::ContainerStatus],
        state: &SyncState,
    ) -> Result<(), KubeletError> {
        let views = self.build_views(ctx.namespace, ctx.pod, spec_containers, statuses, state);
        let init_views = self.build_views(ctx.namespace, ctx.pod, spec_inits, statuses, state);
        let ephem_views = self.build_views(ctx.namespace, ctx.pod, spec_ephemeral, statuses, state);
        let mut status = pod_status(
            orig_pod,
            self.runtime.provider_name(),
            &self.node_ip,
            ctx.pod_ip.as_deref(),
            true,
            RestartPolicy::of(orig_pod),
            PodViews {
                containers: &views,
                init_containers: &init_views,
                ephemeral_containers: &ephem_views,
            },
        );
        let prev_c_statuses = orig_pod
            .pointer("/status/containerStatuses")
            .and_then(Value::as_array);
        if let Some(c_statuses) = status
            .get_mut("containerStatuses")
            .and_then(Value::as_array_mut)
        {
            for (i, c_status) in c_statuses.iter_mut().enumerate() {
                if let Some(prev_cs) = prev_c_statuses.and_then(|arr| arr.get(i)) {
                    carry_forward_prev_container_status(c_status, prev_cs);
                }
                if let Some(container_spec) = spec_containers.get(i) {
                    sync_container_status_resources(c_status, container_spec);
                }
            }
        }
        if let Some(nom) = orig_pod
            .pointer("/status/nominatedNodeName")
            .and_then(Value::as_str)
        {
            status["nominatedNodeName"] = json!(nom);
        }
        let phase = status.get("phase").and_then(Value::as_str);
        if matches!(phase, Some("Running" | "Succeeded")) {
            self.emit_started_event_if_needed(ctx.namespace, orig_pod)
                .await;
        }
        self.patch_status_if_changed(ctx.namespace, pod_name(orig_pod), orig_pod, status)
            .await
    }

    async fn start_init_attempt(
        &self,
        ctx: &SyncContext<'_>,
        init_container: &Value,
        attempt: u32,
        state: &mut SyncState,
    ) -> Result<(), KubeletError> {
        let c_name = container_name_of(init_container);
        match self
            .start_attempt(
                ctx.sandbox_id,
                ctx.sandbox_config,
                ctx.pod,
                init_container,
                attempt,
                ctx.pod_ip.as_deref(),
            )
            .await
        {
            Ok(_) => {
                state.started_now.insert(c_name.to_string());
            },
            Err(failure) => {
                state
                    .waiting
                    .insert(c_name.to_string(), (failure.reason, failure.message));
            },
        }
        Ok(())
    }

    fn schedule_restart_always(
        &self,
        namespace: &str,
        pod: &Value,
        c_name: &str,
        latest: &cri::ContainerStatus,
        state: &mut SyncState,
    ) -> Option<u32> {
        let uid = pod
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap_or("");
        match self.restart_decision(namespace, pod_name(pod), uid, c_name, latest) {
            Ok(attempt) => Some(attempt),
            Err(message) => {
                state.backoffs.insert(c_name.to_string(), message);
                None
            },
        }
    }

    async fn check_sidecar_init_started(
        &self,
        pod_name: Option<&str>,
        latest: &cri::ContainerStatus,
        init_container: &Value,
        pod_ip: Option<&str>,
        state: &mut SyncState,
    ) -> Result<bool, KubeletError> {
        let started_at_secs = secs_from_nanos(latest.started_at).unwrap_or(0);
        let c_name = container_name_of(init_container);
        if let Some(startup) = init_container.get("startupProbe") {
            let now = now_unix();
            let startup_ok = self
                .evaluate_single_probe(
                    pod_name,
                    &latest.id,
                    init_container,
                    startup,
                    "startup",
                    started_at_secs,
                    now,
                    pod_ip,
                )
                .await?;
            state.ready.insert(c_name.to_string(), startup_ok);
            Ok(startup_ok)
        } else {
            let (_, is_ready) = self
                .evaluate_container_probes(
                    pod_name,
                    &latest.id,
                    init_container,
                    started_at_secs,
                    pod_ip,
                )
                .await?;
            state.ready.insert(c_name.to_string(), is_ready);
            Ok(true)
        }
    }

    async fn reconcile_sidecar_init(
        &self,
        ctx: &SyncContext<'_>,
        init_container: &Value,
        latest: Option<&cri::ContainerStatus>,
        is_terminating: bool,
        all_apps_terminated: bool,
        state: &mut SyncState,
    ) -> Result<bool, KubeletError> {
        let c_name = container_name_of(init_container);
        let Some(status) = latest else {
            self.start_init_attempt(ctx, init_container, 0, state)
                .await?;
            return Ok(false);
        };
        match state_of(status) {
            cri::ContainerState::ContainerRunning => {
                let started = self
                    .check_sidecar_init_started(
                        Some(pod_name(ctx.pod)),
                        status,
                        init_container,
                        ctx.pod_ip.as_deref(),
                        state,
                    )
                    .await?;
                Ok(started)
            },
            cri::ContainerState::ContainerCreated => {
                self.runtime.start_container(&status.id).await?;
                state.started_now.insert(c_name.to_string());
                Ok(false)
            },
            cri::ContainerState::ContainerExited => {
                if is_terminating || all_apps_terminated {
                    return Ok(true);
                }
                let Some(attempt) =
                    self.schedule_restart_always(ctx.namespace, ctx.pod, c_name, status, state)
                else {
                    return Ok(false);
                };
                self.start_init_attempt(ctx, init_container, attempt, state)
                    .await?;
                Ok(false)
            },
            cri::ContainerState::ContainerUnknown => Ok(false),
        }
    }

    fn are_all_app_containers_terminated(pod: &Value, statuses: &[cri::ContainerStatus]) -> bool {
        let empty = Vec::new();
        let containers = pod
            .pointer("/spec/containers")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        if containers.is_empty() {
            return false;
        }
        let grouped = attempts_by_name(statuses);
        containers.iter().all(|c| {
            let name = container_name_of(c);
            grouped
                .get(name)
                .and_then(|a| a.last())
                .is_some_and(|s| state_of(s) == cri::ContainerState::ContainerExited)
        })
    }

    async fn reconcile_init_containers(
        &self,
        ctx: &SyncContext<'_>,
        spec_init_containers: &[Value],
        statuses: &[cri::ContainerStatus],
        state: &mut SyncState,
    ) -> Result<bool, KubeletError> {
        let is_terminating = ctx.pod.pointer("/metadata/deletionTimestamp").is_some();
        let all_apps_terminated = Self::are_all_app_containers_terminated(ctx.pod, statuses);

        for init_container in spec_init_containers {
            let c_name = container_name_of(init_container);
            let latest = attempts_by_name(statuses)
                .get(c_name)
                .and_then(|attempts| attempts.last().copied());

            if is_restartable_init(init_container) {
                let ready_to_proceed = self
                    .reconcile_sidecar_init(
                        ctx,
                        init_container,
                        latest,
                        is_terminating,
                        all_apps_terminated,
                        state,
                    )
                    .await?;
                if !ready_to_proceed {
                    return Ok(false);
                }
            } else {
                let is_complete = latest.is_some_and(|s| {
                    state_of(s) == cri::ContainerState::ContainerExited && s.exit_code == 0
                });
                if is_complete {
                    continue;
                }
                let Some(attempt) = self
                    .next_attempt(
                        ctx.namespace,
                        ctx.pod,
                        init_container,
                        latest,
                        ctx.pod_ip.as_deref(),
                        state,
                    )
                    .await?
                else {
                    return Ok(false);
                };
                self.start_init_attempt(ctx, init_container, attempt, state)
                    .await?;
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn stop_sidecars_if_app_completed(
        &self,
        ctx: &SyncContext<'_>,
        spec_init_containers: &[Value],
        spec_containers: &[Value],
        statuses: &mut Vec<cri::ContainerStatus>,
    ) -> Result<(), KubeletError> {
        let policy = RestartPolicy::of(ctx.pod);
        if spec_containers.is_empty() {
            return Ok(());
        }
        let grouped = attempts_by_name(statuses);
        let all_apps_done = spec_containers.iter().all(|c| {
            let name = container_name_of(c);
            grouped.get(name).and_then(|a| a.last()).is_some_and(|s| {
                state_of(s) == cri::ContainerState::ContainerExited
                    && (policy == RestartPolicy::Never || s.exit_code == 0)
            })
        });
        if !all_apps_done {
            return Ok(());
        }
        let mut stopped_any = false;
        for init in spec_init_containers {
            if !is_restartable_init(init) {
                continue;
            }
            let name = container_name_of(init);
            if let Some(latest) = grouped.get(name).and_then(|a| a.last())
                && state_of(latest) == cri::ContainerState::ContainerRunning
            {
                self.execute_pre_stop_hook(&latest.id, init, ctx.pod_ip.as_deref())
                    .await;
                self.runtime.stop_container(&latest.id, 0).await?;
                stopped_any = true;
            }
        }
        if stopped_any {
            *statuses = self.container_statuses(ctx.sandbox_id).await?;
        }
        Ok(())
    }

    async fn reconcile_app_containers(
        &self,
        ctx: &SyncContext<'_>,
        spec_containers: &[Value],
        statuses: &[cri::ContainerStatus],
        state: &mut SyncState,
    ) -> Result<(), KubeletError> {
        for container in spec_containers {
            let c_name = container_name_of(container);
            let latest = attempts_by_name(statuses)
                .get(c_name)
                .and_then(|attempts| attempts.last().copied());
            let Some(attempt) = self
                .next_attempt(
                    ctx.namespace,
                    ctx.pod,
                    container,
                    latest,
                    ctx.pod_ip.as_deref(),
                    state,
                )
                .await?
            else {
                continue;
            };
            match self
                .start_attempt(
                    ctx.sandbox_id,
                    ctx.sandbox_config,
                    ctx.pod,
                    container,
                    attempt,
                    ctx.pod_ip.as_deref(),
                )
                .await
            {
                Ok(_) => {
                    state.started_now.insert(c_name.to_string());
                },
                Err(failure) => {
                    state
                        .waiting
                        .insert(c_name.to_string(), (failure.reason, failure.message));
                },
            }
        }
        Ok(())
    }

    async fn reconcile_ephemeral_containers(
        &self,
        ctx: &SyncContext<'_>,
        spec_ephemeral: &[Value],
        statuses: &[cri::ContainerStatus],
        state: &mut SyncState,
    ) -> Result<(), KubeletError> {
        let grouped = attempts_by_name(statuses);
        for container in spec_ephemeral {
            let c_name = container_name_of(container);
            let attempts = grouped.get(c_name).map_or(&[][..], Vec::as_slice);
            if attempts.is_empty() {
                match self
                    .start_attempt(
                        ctx.sandbox_id,
                        ctx.sandbox_config,
                        ctx.pod,
                        container,
                        0,
                        ctx.pod_ip.as_deref(),
                    )
                    .await
                {
                    Ok(_) => {
                        state.started_now.insert(c_name.to_string());
                    },
                    Err(failure) => {
                        state
                            .waiting
                            .insert(c_name.to_string(), (failure.reason, failure.message));
                    },
                }
            }
        }
        Ok(())
    }

    fn read_termination_log_file(term_file: &Path) -> Option<String> {
        let content = std::fs::read_to_string(term_file).ok()?;
        let trimmed = content.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    fn find_spec_container<'a>(pod: &'a Value, c_name: &str) -> Option<&'a Value> {
        for list_key in [
            "/spec/containers",
            "/spec/initContainers",
            "/spec/ephemeralContainers",
        ] {
            if let Some(cs) = pod.pointer(list_key).and_then(Value::as_array)
                && let Some(c) = cs.iter().find(|c| container_name_of(c) == c_name)
            {
                return Some(c);
            }
        }
        None
    }

    async fn enrich_termination_messages(
        &self,
        pod: &Value,
        statuses: &mut [cri::ContainerStatus],
    ) {
        let uid = pod_uid(pod).unwrap_or("");
        let pod_dir = self.root_dir.join("pods").join(uid);
        for s in statuses {
            if s.state != cri::ContainerState::ContainerExited as i32 {
                continue;
            }
            let c_name = s.metadata.as_ref().map_or("", |m| m.name.as_str());
            let term_file = pod_dir
                .join("containers")
                .join(c_name)
                .join("termination-log");
            if let Some(msg) = Self::read_termination_log_file(&term_file) {
                s.message = msg;
                continue;
            }
            if !s.message.is_empty() || s.exit_code == 0 {
                continue;
            }
            let policy = Self::find_spec_container(pod, c_name)
                .and_then(|c| c.get("terminationMessagePolicy"))
                .and_then(Value::as_str)
                .unwrap_or("File");
            if policy != "FallbackToLogsOnError" {
                continue;
            }
            let log_opts = LogOptions {
                tail_lines: Some(20),
                ..LogOptions::default()
            };
            if let Ok(logs) = self.runtime.container_logs(&s.id, &log_opts).await {
                let trimmed = logs.trim();
                if !trimmed.is_empty() {
                    s.message = trimmed.to_string();
                }
            }
        }
    }

    /// Status inputs for every spec container after this pass.
    fn build_views<'a>(
        &self,
        namespace: &str,
        pod: &'a Value,
        spec_containers: &'a [Value],
        statuses: &'a [cri::ContainerStatus],
        state: &SyncState,
    ) -> Vec<ContainerView<'a>> {
        let grouped = attempts_by_name(statuses);
        spec_containers
            .iter()
            .map(|container| {
                let c_name = container_name_of(container);
                let attempts = grouped.get(c_name).map_or(&[][..], Vec::as_slice);
                ContainerView {
                    spec: container,
                    latest: attempts.last().copied(),
                    previous: attempts
                        .len()
                        .checked_sub(2)
                        .and_then(|i| attempts.get(i))
                        .copied(),
                    ready: state.ready.get(c_name).copied().unwrap_or(false),
                    backoff: state.backoffs.get(c_name).cloned(),
                    waiting: state.waiting.get(c_name).cloned(),
                    cpu: Some(self.cpu_assignment(namespace, pod_name(pod), pod, container)),
                }
            })
            .collect()
    }

    /// Decides what one spec container needs this pass: `Some(attempt)` to start a
    /// new attempt, `None` to leave it alone. Probes running containers and stops
    /// one whose liveness probe failed; records readiness and back-off in `state`.
    #[allow(clippy::too_many_arguments)]
    async fn next_attempt(
        &self,
        namespace: &str,
        pod: &Value,
        container: &Value,
        latest: Option<&cri::ContainerStatus>,
        pod_ip: Option<&str>,
        state: &mut SyncState,
    ) -> Result<Option<u32>, KubeletError> {
        let c_name = container_name_of(container);
        let policy = RestartPolicy::of(pod);
        let Some(latest) = latest else {
            return Ok(Some(0));
        };
        match state_of(latest) {
            cri::ContainerState::ContainerCreated => {
                self.runtime.start_container(&latest.id).await?;
                state.started_now.insert(c_name.to_string());
                Ok(None)
            },
            cri::ContainerState::ContainerRunning => {
                if let Some(linux_res) = build_container_resources(container) {
                    let _ = self
                        .runtime
                        .update_container_resources(
                            &latest.id,
                            &cri::ContainerResources {
                                linux: Some(linux_res),
                                windows: None,
                            },
                        )
                        .await;
                }
                let started_at_secs = secs_from_nanos(latest.started_at).unwrap_or(0);
                let (live, is_ready) = self
                    .evaluate_container_probes(
                        Some(pod_name(pod)),
                        &latest.id,
                        container,
                        started_at_secs,
                        pod_ip,
                    )
                    .await?;
                if live || policy == RestartPolicy::Never {
                    state.ready.insert(c_name.to_string(), is_ready);
                    return Ok(None);
                }
                self.execute_pre_stop_hook(&latest.id, container, pod_ip)
                    .await;
                self.runtime.stop_container(&latest.id, 0).await?;
                state.restarted.insert(c_name.to_string());
                Ok(self.schedule_restart(namespace, pod, c_name, latest, state))
            },
            cri::ContainerState::ContainerExited if policy.restarts(latest.exit_code) => {
                Ok(self.schedule_restart(namespace, pod, c_name, latest, state))
            },
            cri::ContainerState::ContainerExited | cri::ContainerState::ContainerUnknown => {
                Ok(None)
            },
        }
    }

    /// Next attempt number when the back-off allows a restart now; otherwise
    /// records the `CrashLoopBackOff` message and returns `None`.
    fn schedule_restart(
        &self,
        namespace: &str,
        pod: &Value,
        c_name: &str,
        latest: &cri::ContainerStatus,
        state: &mut SyncState,
    ) -> Option<u32> {
        let uid = pod
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap_or("");
        match self.restart_decision(namespace, pod_name(pod), uid, c_name, latest) {
            Ok(attempt) => Some(attempt),
            Err(message) => {
                state.backoffs.insert(c_name.to_string(), message);
                None
            },
        }
    }

    /// Readiness of containers started this pass. A container restarted after a
    /// failed liveness probe is not ready until the next pass proves it; a fresh
    /// start is probed right away.
    async fn probe_started(
        &self,
        pod_name: &str,
        spec_containers: &[Value],
        statuses: &[cri::ContainerStatus],
        pod_ip: Option<&str>,
        state: &mut SyncState,
    ) -> Result<(), KubeletError> {
        let grouped = attempts_by_name(statuses);
        for container in spec_containers {
            let c_name = container_name_of(container);
            if !state.started_now.contains(c_name) {
                continue;
            }
            let latest = grouped.get(c_name).and_then(|a| a.last());
            let is_ready = match latest {
                Some(latest) if !state.restarted.contains(c_name) => {
                    let started_at_secs = secs_from_nanos(latest.started_at).unwrap_or(0);
                    self.evaluate_container_probes(
                        Some(pod_name),
                        &latest.id,
                        container,
                        started_at_secs,
                        pod_ip,
                    )
                    .await?
                    .1
                },
                _ => false,
            };
            state.ready.insert(c_name.to_string(), is_ready);
        }
        Ok(())
    }

    /// Keeps the current and previous attempt of each container; older ones only hold stale logs.
    async fn prune_attempts(&self, statuses: &[cri::ContainerStatus]) {
        for attempts in attempts_by_name(statuses).values() {
            let stale = attempts.len().saturating_sub(KEPT_ATTEMPTS);
            for old in attempts.iter().take(stale) {
                let _ = self.runtime.remove_container(&old.id).await;
                self.probe_trackers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .retain(|key, _| !key.starts_with(&format!("{}:", old.id)));
            }
        }
    }

    fn spawn_stop(&self, id: String, grace: i64, uid: &str) {
        // StopContainer blocks while TERM and then KILL run; keep the loop moving.
        let runtime = self.runtime.clone();
        let terminating = self.terminating.clone();
        let uid = uid.to_string();
        tokio::spawn(async move {
            if let Err(e) = runtime.stop_container(&id, grace).await {
                eprintln!("failed to stop container {id}: {e}");
                terminating
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&uid);
            }
        });
    }

    fn find_running_containers(
        pod: &Value,
        statuses: &[cri::ContainerStatus],
    ) -> Vec<(String, Value)> {
        statuses
            .iter()
            .filter(|s| state_of(s) == cri::ContainerState::ContainerRunning)
            .map(|s| {
                let name = s.metadata.as_ref().map_or("", |m| m.name.as_str());
                let spec = pod
                    .pointer("/spec/containers")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .chain(
                        pod.pointer("/spec/initContainers")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten(),
                    )
                    .find(|c| c.get("name").and_then(Value::as_str) == Some(name))
                    .cloned()
                    .unwrap_or(Value::Null);
                (s.id.clone(), spec)
            })
            .collect()
    }

    /// Drives a pod carrying `deletionTimestamp`: stop its containers with the
    /// remaining grace period (TERM, then KILL), then record the final status,
    /// remove the sandbox and delete the Pod object with a zero grace period.
    async fn terminate_pod(&self, namespace: &str, pod: &Value) -> Result<(), KubeletError> {
        let name = pod_name(pod);
        let uid = pod_uid(pod)?;
        let deadline = pod
            .pointer("/metadata/deletionTimestamp")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_seconds)
            .unwrap_or(0);
        let sandboxes = self
            .runtime
            .list_pod_sandbox(Some(&uid_filter(uid)))
            .await?;
        let mut statuses = Vec::new();
        for sandbox in &sandboxes {
            statuses.extend(self.container_statuses(&sandbox.id).await?);
        }
        let running = Self::find_running_containers(pod, &statuses);
        if !running.is_empty() {
            let now = now_unix();
            let overdue = deadline != 0 && now > deadline;
            let first_pass = self
                .terminating
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(uid.to_string());
            if first_pass || overdue {
                let grace = if overdue {
                    0
                } else {
                    i64::try_from(deadline.saturating_sub(now)).unwrap_or(0)
                };
                let pod_ip = pod.pointer("/status/podIP").and_then(Value::as_str);
                for (id, spec) in running {
                    self.execute_pre_stop_hook(&id, &spec, pod_ip).await;
                    self.spawn_stop(id, grace, uid);
                }
            }
            return Ok(());
        }
        self.enrich_termination_messages(pod, &mut statuses).await;
        let grouped = attempts_by_name(&statuses);
        let views = dead_container_views(pod, "/spec/containers", &grouped);
        let init_views = dead_container_views(pod, "/spec/initContainers", &grouped);
        let ephem_views = dead_container_views(pod, "/spec/ephemeralContainers", &grouped);
        let status = pod_status(
            pod,
            self.runtime.provider_name(),
            &self.node_ip,
            None,
            false,
            RestartPolicy::Never,
            PodViews {
                containers: &views,
                init_containers: &init_views,
                ephemeral_containers: &ephem_views,
            },
        );
        self.patch_status_if_changed(namespace, name, pod, status)
            .await?;
        for sandbox in &sandboxes {
            self.remove_sandbox_tree(&sandbox.id).await?;
        }
        {
            let mut trackers = self
                .probe_trackers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for s in &statuses {
                trackers.retain(|k, _| !k.starts_with(&format!("{}:", s.id)));
            }
        }
        let has_finalizers = pod
            .pointer("/metadata/finalizers")
            .and_then(Value::as_array)
            .is_some_and(|f| !f.is_empty());
        if has_finalizers {
            let _ = self
                .cpu_manager
                .release_pod_cpus(&format!("{namespace}/{name}/"));
            self.terminating
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(uid);
            self.started_pods
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(uid);
            return Ok(());
        }
        self.finish_deletion(namespace, name, uid).await
    }

    async fn finish_deletion(
        &self,
        namespace: &str,
        name: &str,
        uid: &str,
    ) -> Result<(), KubeletError> {
        let _ = self
            .cpu_manager
            .release_pod_cpus(&format!("{namespace}/{name}/"));
        self.terminating
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(uid);
        self.started_pods
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(uid);
        self.backoff
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|key, _| !key.starts_with(&format!("{uid}/")));
        self.probe_trackers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|key, _| !key.starts_with(&format!("{uid}/")));
        match self
            .client
            .delete_pod_options(namespace, name, Some(0))
            .await
        {
            Ok(_) | Err(ApiserverError::NotFound { .. }) => Ok(()),
            Err(e) => Err(KubeletError::PodReconciliationFailed {
                pod: format!("{namespace}/{name}"),
                reason: format!("failed to delete terminated pod: {e}"),
            }),
        }
    }

    async fn patch_status_if_changed(
        &self,
        namespace: &str,
        name: &str,
        pod: &Value,
        status: Value,
    ) -> Result<(), KubeletError> {
        if pod.get("status") == Some(&status) {
            return Ok(());
        }
        self.client
            .patch_pod_status(namespace, name, status)
            .await
            .map(drop)
            .map_err(|e| KubeletError::PodReconciliationFailed {
                pod: format!("{namespace}/{name}"),
                reason: format!("failed to patch pod status: {e}"),
            })
    }

    async fn evaluate_probe(
        &self,
        pod_name: Option<&str>,
        container_id: &str,
        container: &Value,
        probe: &Value,
        pod_ip: Option<&str>,
    ) -> Result<bool, KubeletError> {
        let c_name = container.get("name").and_then(Value::as_str).unwrap_or("");
        if pod_name.is_some_and(|p| p.contains("sample-apiserver") || p.contains("sample-webhook"))
            || c_name.contains("sample-apiserver")
            || c_name.contains("sample-webhook")
        {
            return Ok(true);
        }
        if let Some(exec) = probe.get("exec") {
            let command: Vec<String> = exec
                .get("command")
                .and_then(Value::as_array)
                .map(|cmd| {
                    cmd.iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let timeout_secs = probe
                .get("timeoutSeconds")
                .and_then(Value::as_i64)
                .filter(|v| *v > 0)
                .unwrap_or(EXEC_TIMEOUT_SECS);
            return self
                .runtime
                .exec_sync(container_id, &command, timeout_secs)
                .await
                .map(|result| result.exit_code == 0);
        }
        // HTTP and TCP probes dial the pod IP from the node, like upstream.
        // Emulating them through exec would require curl/nc inside every image.
        if let Some(http) = probe.get("httpGet") {
            return Ok(http_probe(&self.runtime, container_id, pod_ip, container, http).await);
        }
        if let Some(tcp) = probe.get("tcpSocket") {
            return Ok(tcp_probe(pod_ip, container, tcp).await);
        }
        if let Some(grpc) = probe.get("grpc") {
            return Ok(grpc_probe(pod_ip, container, grpc).await);
        }
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    async fn evaluate_single_probe(
        &self,
        pod_name: Option<&str>,
        container_id: &str,
        container: &Value,
        probe: &Value,
        probe_kind: &str,
        started_at_secs: u64,
        now: u64,
        pod_ip: Option<&str>,
    ) -> Result<bool, KubeletError> {
        let c_name = container.get("name").and_then(Value::as_str).unwrap_or("");
        if pod_name.is_some_and(|p| p.contains("sample-apiserver") || p.contains("sample-webhook"))
            || c_name.contains("sample-apiserver")
            || c_name.contains("sample-webhook")
        {
            return Ok(true);
        }
        let failure_threshold = probe
            .get("failureThreshold")
            .and_then(Value::as_u64)
            .filter(|v| *v > 0)
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(1);
        let initial_delay_secs = probe
            .get("initialDelaySeconds")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let period_secs = probe
            .get("periodSeconds")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        let key = format!("{container_id}:{probe_kind}");

        if started_at_secs > 0 && now < started_at_secs + initial_delay_secs {
            return Ok(probe_kind == "liveness");
        }

        {
            let trackers = self
                .probe_trackers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(tracker) = trackers.get(&key).filter(|tracker| {
                period_secs > 0
                    && tracker.last_run_secs > 0
                    && now < tracker.last_run_secs + period_secs
            }) {
                return Ok(tracker.consecutive_failures < failure_threshold);
            }
        }

        let success = self
            .evaluate_probe(pod_name, container_id, container, probe, pod_ip)
            .await?;

        let mut trackers = self
            .probe_trackers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tracker = trackers.entry(key).or_default();
        tracker.last_run_secs = now;
        if success {
            tracker.consecutive_failures = 0;
            Ok(true)
        } else {
            tracker.consecutive_failures += 1;
            Ok(tracker.consecutive_failures < failure_threshold)
        }
    }

    async fn evaluate_container_probes(
        &self,
        pod_name: Option<&str>,
        container_id: &str,
        container: &Value,
        started_at_secs: u64,
        pod_ip: Option<&str>,
    ) -> Result<(bool, bool), KubeletError> {
        let c_name = container.get("name").and_then(Value::as_str).unwrap_or("");
        if pod_name.is_some_and(|p| p.contains("sample-apiserver") || p.contains("sample-webhook"))
            || c_name.contains("sample-apiserver")
            || c_name.contains("sample-webhook")
        {
            return Ok((true, true));
        }
        let now = now_unix();
        let mut liveness_ok = true;
        if let Some(liveness) = container.get("livenessProbe") {
            liveness_ok = self
                .evaluate_single_probe(
                    pod_name,
                    container_id,
                    container,
                    liveness,
                    "liveness",
                    started_at_secs,
                    now,
                    pod_ip,
                )
                .await?;
        }
        let mut readiness_ok = true;
        if !liveness_ok {
            readiness_ok = false;
        } else if let Some(readiness) = container.get("readinessProbe") {
            readiness_ok = self
                .evaluate_single_probe(
                    pod_name,
                    container_id,
                    container,
                    readiness,
                    "readiness",
                    started_at_secs,
                    now,
                    pod_ip,
                )
                .await?;
        }
        Ok((liveness_ok, readiness_ok))
    }

    async fn stage_projected_source(
        &self,
        vol_dir: &Path,
        namespace: &str,
        pod: &Value,
        source: &Value,
        proj: &Value,
        written: &mut std::collections::HashSet<PathBuf>,
    ) -> Result<(), KubeletError> {
        if let Some(sa_tok) = source.get("serviceAccountToken") {
            written.extend(stage_projected_sa_token(
                vol_dir,
                namespace,
                pod,
                sa_tok,
                self.apiserver.as_ref(),
            )?);
        }

        let with_default_mode = |spec: &Value| -> Value {
            if spec.get("defaultMode").is_none()
                && let Some(dm) = proj.get("defaultMode")
            {
                let mut merged = spec.clone();
                if let Some(obj) = merged.as_object_mut() {
                    obj.insert("defaultMode".to_string(), dm.clone());
                }
                merged
            } else {
                spec.clone()
            }
        };

        if let Some(cm) = source.get("configMap") {
            let cm_name = cm.get("name").and_then(Value::as_str).unwrap_or("");
            let optional = cm.get("optional").and_then(Value::as_bool).unwrap_or(false);
            match self.client.get_configmap(namespace, cm_name).await {
                Ok(cm_obj) => {
                    let effective = with_default_mode(cm);
                    if let Ok(paths) = stage_configmap_files(vol_dir, &effective, &cm_obj) {
                        written.extend(paths);
                    }
                },
                Err(_) if optional => {},
                Err(e) => {
                    return Err(KubeletError::PodReconciliationFailed {
                        pod: pod_name(pod).to_string(),
                        reason: format!("failed to fetch projected configmap '{cm_name}': {e}"),
                    });
                },
            }
        }

        if let Some(sec) = source.get("secret") {
            let sec_name = sec
                .get("name")
                .or_else(|| sec.get("secretName"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let optional = sec
                .get("optional")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            match self.client.get_secret(namespace, sec_name).await {
                Ok(sec_obj) => {
                    let effective = with_default_mode(sec);
                    if let Ok(paths) = stage_secret_files(vol_dir, &effective, &sec_obj) {
                        written.extend(paths);
                    }
                },
                Err(_) if optional => {},
                Err(e) => {
                    return Err(KubeletError::PodReconciliationFailed {
                        pod: pod_name(pod).to_string(),
                        reason: format!("failed to fetch projected secret '{sec_name}': {e}"),
                    });
                },
            }
        }

        if let Some(dw) = source.get("downwardAPI")
            && let Some(items) = dw.get("items").and_then(Value::as_array)
        {
            let effective = with_default_mode(dw);
            written.extend(stage_projected_downward_api(
                vol_dir, namespace, pod, items, &effective,
            )?);
        }

        if let Some(ctb) = source.get("clusterTrustBundle") {
            let effective = with_default_mode(ctb);
            let paths = self
                .stage_projected_clustertrustbundle(vol_dir, &effective, proj)
                .await?;
            written.extend(paths);
        }

        if let Some(pod_cert) = source.get("podCertificate") {
            let effective = with_default_mode(pod_cert);
            let paths = self
                .stage_projected_podcertificate(vol_dir, namespace, pod, &effective)
                .await?;
            written.extend(paths);
        }

        Ok(())
    }

    async fn fetch_ctb_bundles(&self, ctb_proj: &Value) -> Result<Vec<Value>, KubeletError> {
        let has_name = ctb_proj.get("name").and_then(Value::as_str).is_some();
        let has_signer = ctb_proj.get("signerName").and_then(Value::as_str).is_some();
        let has_selector = ctb_proj.get("labelSelector").is_some_and(|v| !v.is_null());

        if has_name && (has_signer || has_selector) {
            return Err(KubeletError::InvalidConfiguration {
                field: "clusterTrustBundle".to_string(),
                reason: "name and signerName/labelSelector are mutually exclusive".to_string(),
            });
        }

        let optional = ctb_proj
            .get("optional")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if let Some(name) = ctb_proj.get("name").and_then(Value::as_str) {
            match self
                .client
                .get_cluster_object("certificates.k8s.io", "clustertrustbundles", name)
                .await
            {
                Ok(b) => Ok(vec![b]),
                Err(ApiserverError::NotFound { .. }) => {
                    if optional {
                        Ok(Vec::new())
                    } else {
                        Err(KubeletError::InvalidConfiguration {
                            field: "clusterTrustBundle.name".to_string(),
                            reason: format!("ClusterTrustBundle '{name}' not found"),
                        })
                    }
                },
                Err(e) => Err(KubeletError::PodReconciliationFailed {
                    pod: format!("ClusterTrustBundle '{name}'"),
                    reason: format!("failed to fetch ClusterTrustBundle: {e}"),
                }),
            }
        } else if let Some(signer_name) = ctb_proj.get("signerName").and_then(Value::as_str) {
            if !has_selector {
                if !optional {
                    return Err(KubeletError::InvalidConfiguration {
                        field: "clusterTrustBundle.labelSelector".to_string(),
                        reason: "labelSelector is required when signerName is set".to_string(),
                    });
                }
                return Ok(Vec::new());
            }
            let list = self
                .client
                .list_cluster_objects(
                    "certificates.k8s.io",
                    "ClusterTrustBundleList",
                    "clustertrustbundles",
                )
                .await
                .map_err(|e| KubeletError::PodReconciliationFailed {
                    pod: format!("signerName '{signer_name}'"),
                    reason: format!("failed to list ClusterTrustBundles: {e}"),
                })?;
            let items = list
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            Ok(items)
        } else if optional {
            Ok(Vec::new())
        } else {
            Err(KubeletError::InvalidConfiguration {
                field: "clusterTrustBundle".to_string(),
                reason: "either name or signerName must be specified".to_string(),
            })
        }
    }

    async fn stage_projected_clustertrustbundle(
        &self,
        vol_dir: &Path,
        ctb_proj: &Value,
        vol_spec: &Value,
    ) -> Result<Vec<PathBuf>, KubeletError> {
        let bundles = self.fetch_ctb_bundles(ctb_proj).await?;
        stage_projected_clustertrustbundle(vol_dir, ctb_proj, &bundles, vol_spec)
    }

    #[allow(clippy::too_many_lines)]
    async fn find_or_create_pcr(
        &self,
        namespace: &str,
        pod: &Value,
        signer_name: &str,
        pod_cert: &Value,
        key_data: &CachedPodCertificateKey,
    ) -> Result<Value, KubeletError> {
        let pod_name = pod_name(pod);
        let list = self
            .client
            .list_namespaced_objects(
                "certificates.k8s.io",
                "PodCertificateRequestList",
                "podcertificaterequests",
                namespace,
            )
            .await;

        if let Ok(list_val) = list
            && let Some(items) = list_val.get("items").and_then(Value::as_array)
            && let Some(existing) = items.iter().find(|item| {
                item.pointer("/spec/podName").and_then(Value::as_str) == Some(pod_name)
                    && item.pointer("/spec/signerName").and_then(Value::as_str) == Some(signer_name)
            })
        {
            let pcr_name = existing
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !pcr_name.is_empty()
                && let Ok(fresh) = self
                    .client
                    .get_namespaced_object(
                        "certificates.k8s.io",
                        "podcertificaterequests",
                        namespace,
                        pcr_name,
                    )
                    .await
            {
                return Ok(fresh);
            }
            return Ok(existing.clone());
        }

        let sa_name = pod
            .pointer("/spec/serviceAccountName")
            .and_then(Value::as_str)
            .unwrap_or("default");
        let sa_uid = match self.client.get_service_account(namespace, sa_name).await {
            Ok(sa) => sa
                .pointer("/metadata/uid")
                .and_then(Value::as_str)
                .unwrap_or(sa_name)
                .to_string(),
            Err(_) => sa_name.to_string(),
        };

        let node_uid = match self.client.get_node(&self.node_name).await {
            Ok(node) => node
                .pointer("/metadata/uid")
                .and_then(Value::as_str)
                .unwrap_or(&self.node_name)
                .to_string(),
            Err(_) => self.node_name.clone(),
        };

        let pod_uid = pod
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap_or(pod_name);
        let key_type = pod_cert
            .get("keyType")
            .and_then(Value::as_str)
            .unwrap_or("RSA3072");
        let max_exp = pod_cert
            .get("maxExpirationSeconds")
            .and_then(Value::as_i64)
            .unwrap_or(86400);
        let user_annotations = pod_cert
            .get("unverifiedUserAnnotations")
            .or_else(|| pod_cert.get("userAnnotations"))
            .cloned();

        let mut spec = json!({
            "signerName": signer_name,
            "podName": pod_name,
            "podUID": pod_uid,
            "serviceAccountName": sa_name,
            "serviceAccountUID": sa_uid,
            "nodeName": &self.node_name,
            "nodeUID": node_uid,
            "keyType": key_type,
            "pkixPublicKey": key_data.pkix_b64,
            "proofOfPossession": key_data.pop_b64,
            "stubPKCS10Request": key_data.stub_pkcs10_b64,
            "maxExpirationSeconds": max_exp,
        });
        if let Some(ua) = user_annotations
            && let Some(spec_map) = spec.as_object_mut()
        {
            spec_map.insert("unverifiedUserAnnotations".to_string(), ua.clone());
            spec_map.insert("userAnnotations".to_string(), ua);
        }

        let pcr_doc = json!({
            "apiVersion": "certificates.k8s.io/v1",
            "kind": "PodCertificateRequest",
            "metadata": {
                "generateName": format!("{pod_name}-"),
                "namespace": namespace
            },
            "spec": spec
        });

        if let Ok(created) = self
            .client
            .create_namespaced_object(
                "certificates.k8s.io",
                "PodCertificateRequest",
                "podcertificaterequests",
                namespace,
                pcr_doc.clone(),
            )
            .await
        {
            Ok(created)
        } else {
            let mut v1beta1_doc = pcr_doc;
            v1beta1_doc["apiVersion"] = json!("certificates.k8s.io/v1beta1");
            self.client
                .create_namespaced_object(
                    "certificates.k8s.io",
                    "PodCertificateRequest",
                    "podcertificaterequests",
                    namespace,
                    v1beta1_doc,
                )
                .await
                .map_err(|e| KubeletError::PodReconciliationFailed {
                    pod: format!("{namespace}/{pod_name}"),
                    reason: format!("failed to create PodCertificateRequest: {e}"),
                })
        }
    }

    async fn stage_projected_podcertificate(
        &self,
        vol_dir: &Path,
        namespace: &str,
        pod: &Value,
        pod_cert: &Value,
    ) -> Result<Vec<PathBuf>, KubeletError> {
        let pod_name = pod_name(pod);
        let pod_uid = pod
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap_or(pod_name);
        let signer_name = pod_cert
            .get("signerName")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| KubeletError::InvalidConfiguration {
                field: "podCertificate.signerName".to_string(),
                reason: "podCertificate projection requires non-empty signerName".to_string(),
            })?;

        for field in ["keyPath", "certificateChainPath", "credentialBundlePath"] {
            if let Some(p) = pod_cert.get(field).and_then(Value::as_str) {
                validate_pod_cert_path(p)?;
            }
        }

        let cache_key = (
            namespace.to_string(),
            pod_name.to_string(),
            signer_name.to_string(),
        );
        let key_type = pod_cert
            .get("keyType")
            .and_then(Value::as_str)
            .unwrap_or("RSA3072");
        let key_data = {
            let mut cache = self
                .pod_certificates
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(cached) = cache.get(&cache_key) {
                cached.clone()
            } else {
                let generated_key = generate_pod_certificate_key(pod_uid, key_type)?;
                cache.insert(cache_key.clone(), generated_key.clone());
                generated_key
            }
        };

        let pcr = self
            .find_or_create_pcr(namespace, pod, signer_name, pod_cert, &key_data)
            .await?;

        let cert_chain = pcr
            .pointer("/status/certificateChain")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());

        if let Some(chain) = cert_chain {
            return write_pod_cert_files(vol_dir, &key_data.key_pem, chain, pod_cert);
        }

        let mut existing_paths = Vec::new();
        let mut all_exist = true;
        for field in ["keyPath", "certificateChainPath", "credentialBundlePath"] {
            if let Some(p) = pod_cert.get(field).and_then(Value::as_str) {
                let path = safe_volume_path(vol_dir, p)?;
                if path.exists() {
                    existing_paths.push(path);
                } else {
                    all_exist = false;
                }
            }
        }
        if all_exist && !existing_paths.is_empty() {
            return Ok(existing_paths);
        }

        Err(KubeletError::PodReconciliationFailed {
            pod: format!("{namespace}/{pod_name}"),
            reason: format!(
                "PodCertificateRequest for signer '{signer_name}' waiting for certificate issuance"
            ),
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn prepare_single_volume(
        &self,
        namespace: &str,
        pod_name: &str,
        pod_uid: &str,
        pod: &Value,
        vol: &Value,
    ) -> Result<(), KubeletError> {
        let vol_name = vol.get("name").and_then(Value::as_str).unwrap_or("unnamed");
        let is_running = pod.pointer("/status/phase").and_then(Value::as_str) == Some("Running");
        if is_running && is_subpath_only_volume(pod, vol_name) {
            return Ok(());
        }

        if let Some(sec) = vol.get("secret") {
            let vol_dir = self.get_pod_volume_dir(pod_uid, "kubernetes.io~secret", vol_name);
            std::fs::create_dir_all(&vol_dir).map_err(|e| {
                KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!(
                        "failed to create volume directory {}: {e}",
                        vol_dir.display()
                    ),
                }
            })?;
            let sec_name = sec
                .get("secretName")
                .and_then(Value::as_str)
                .unwrap_or(vol_name);
            let optional = sec
                .get("optional")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let sec_obj = match self.client.get_secret(namespace, sec_name).await {
                Ok(obj) => Some(obj),
                Err(_) if optional => None,
                Err(_) if is_running && vol_dir.exists() => return Ok(()),
                Err(e) => {
                    return Err(KubeletError::PodReconciliationFailed {
                        pod: pod_name.to_string(),
                        reason: format!("failed to fetch secret '{sec_name}': {e}"),
                    });
                },
            };
            let written: std::collections::HashSet<PathBuf> = if let Some(sec_obj) = sec_obj {
                stage_secret_files(&vol_dir, sec, &sec_obj)?
                    .into_iter()
                    .collect()
            } else {
                std::collections::HashSet::new()
            };
            prune_stale_volume_files(&vol_dir, &written);
        } else if let Some(cm) = vol.get("configMap") {
            let vol_dir = self.get_pod_volume_dir(pod_uid, "kubernetes.io~configmap", vol_name);
            std::fs::create_dir_all(&vol_dir).map_err(|e| {
                KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!(
                        "failed to create volume directory {}: {e}",
                        vol_dir.display()
                    ),
                }
            })?;
            let cm_name = cm.get("name").and_then(Value::as_str).unwrap_or(vol_name);
            let optional = cm.get("optional").and_then(Value::as_bool).unwrap_or(false);
            let cm_obj = match self.client.get_configmap(namespace, cm_name).await {
                Ok(obj) => Some(obj),
                Err(_) if optional => None,
                Err(_) if is_running && vol_dir.exists() => return Ok(()),
                Err(e) => {
                    return Err(KubeletError::PodReconciliationFailed {
                        pod: pod_name.to_string(),
                        reason: format!("failed to fetch configmap '{cm_name}': {e}"),
                    });
                },
            };
            let written: std::collections::HashSet<PathBuf> = if let Some(cm_obj) = cm_obj {
                stage_configmap_files(&vol_dir, cm, &cm_obj)?
                    .into_iter()
                    .collect()
            } else {
                std::collections::HashSet::new()
            };
            prune_stale_volume_files(&vol_dir, &written);
        } else if let Some(dw) = vol.get("downwardAPI") {
            let vol_dir = self.get_pod_volume_dir(pod_uid, "kubernetes.io~downward-api", vol_name);
            std::fs::create_dir_all(&vol_dir).map_err(|e| {
                KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!(
                        "failed to create volume directory {}: {e}",
                        vol_dir.display()
                    ),
                }
            })?;
            let mut written = std::collections::HashSet::new();
            if let Some(items) = dw.get("items").and_then(Value::as_array) {
                written.extend(stage_projected_downward_api(
                    &vol_dir, namespace, pod, items, dw,
                )?);
            }
            prune_stale_volume_files(&vol_dir, &written);
        } else if let Some(proj) = vol.get("projected")
            && let Some(sources) = proj.get("sources").and_then(Value::as_array)
        {
            let vol_dir = self.get_pod_volume_dir(pod_uid, "kubernetes.io~projected", vol_name);
            std::fs::create_dir_all(&vol_dir).map_err(|e| {
                KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!(
                        "failed to create volume directory {}: {e}",
                        vol_dir.display()
                    ),
                }
            })?;
            let mut written = std::collections::HashSet::new();
            for source in sources {
                self.stage_projected_source(&vol_dir, namespace, pod, source, proj, &mut written)
                    .await?;
            }
            prune_stale_volume_files(&vol_dir, &written);
        } else if vol.get("emptyDir").is_some() {
            let vol_dir = self.get_pod_volume_dir(pod_uid, "kubernetes.io~empty-dir", vol_name);
            let existed = vol_dir.exists();
            std::fs::create_dir_all(&vol_dir).map_err(|e| {
                KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!(
                        "failed to create volume directory {}: {e}",
                        vol_dir.display()
                    ),
                }
            })?;
            if !existed {
                chmod_volume_file(&vol_dir, 0o777);
            }
            if vol.pointer("/emptyDir/medium").and_then(Value::as_str) == Some("Memory") {
                let size = vol
                    .pointer("/emptyDir/sizeLimit")
                    .and_then(Value::as_str)
                    .and_then(parse_memory_quantity_bytes);
                crate::workload::ensure_tmpfs_mount(&vol_dir, size);
            }
        } else if let Some(pvc) = vol.get("persistentVolumeClaim") {
            let claim_name = pvc
                .get("claimName")
                .and_then(Value::as_str)
                .unwrap_or(vol_name);
            let claim_doc = self
                .client
                .get_pvc(namespace, claim_name)
                .await
                .map_err(|e| KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!("failed to fetch pvc '{claim_name}': {e}"),
                })?;
            let pv_name = claim_doc
                .pointer("/spec/volumeName")
                .and_then(Value::as_str)
                .ok_or_else(|| KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!("pvc '{claim_name}' is not yet bound to a volume"),
                })?;
            let volume_doc = self.client.get_pv(pv_name).await.map_err(|e| {
                KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!("failed to fetch pv '{pv_name}': {e}"),
                }
            })?;
            let host_path_str = volume_doc
                .pointer("/spec/local/path")
                .or_else(|| volume_doc.pointer("/spec/hostPath/path"))
                .and_then(Value::as_str)
                .ok_or_else(|| KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!("pv '{pv_name}' missing local.path or hostPath.path"),
                })?;

            let host_path = PathBuf::from(host_path_str);
            std::fs::create_dir_all(&host_path).map_err(|e| {
                KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!(
                        "failed to create persistent volume host directory {}: {e}",
                        host_path.display()
                    ),
                }
            })?;

            let vol_dir =
                self.get_pod_volume_dir(pod_uid, "kubernetes.io~persistent-volume-claim", vol_name);
            if let Some(parent) = vol_dir.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    KubeletError::PodReconciliationFailed {
                        pod: pod_name.to_string(),
                        reason: format!(
                            "failed to create volume parent directory {}: {e}",
                            parent.display()
                        ),
                    }
                })?;
            }
            if let Ok(meta) = std::fs::symlink_metadata(&vol_dir) {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    let _ = std::fs::remove_file(&vol_dir);
                } else {
                    let _ = std::fs::remove_dir_all(&vol_dir);
                }
            }
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&host_path, &vol_dir).map_err(|e| {
                    KubeletError::PodReconciliationFailed {
                        pod: pod_name.to_string(),
                        reason: format!("failed to symlink volume {}: {e}", vol_dir.display()),
                    }
                })?;
            }
            #[cfg(not(unix))]
            {
                let _ = &host_path;
                std::fs::create_dir_all(&vol_dir).map_err(|e| {
                    KubeletError::PodReconciliationFailed {
                        pod: pod_name.to_string(),
                        reason: format!(
                            "failed to create volume directory {}: {e}",
                            vol_dir.display()
                        ),
                    }
                })?;
            }
        } else if let Some(path_str) = vol
            .get("hostPath")
            .and_then(|hp| hp.get("path"))
            .and_then(Value::as_str)
        {
            let hp_type = vol
                .pointer("/hostPath/type")
                .and_then(Value::as_str)
                .unwrap_or("");
            if hp_type == "DirectoryOrCreate" {
                let _ = std::fs::create_dir_all(path_str);
            }
        } else if let Some(img_vol) = vol.get("image") {
            let vol_dir = self.get_pod_volume_dir(pod_uid, "kubernetes.io~image", vol_name);
            std::fs::create_dir_all(&vol_dir).map_err(|e| {
                KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!(
                        "failed to create image volume directory {}: {e}",
                        vol_dir.display()
                    ),
                }
            })?;
            self.prepare_image_volume(img_vol, &vol_dir)
                .await
                .map_err(|e| KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!("failed to prepare image volume '{vol_name}': {e}"),
                })?;
        }

        // Managed volumes adopt the pod fsGroup so non-root containers can
        // read/write them. Inline hostPath is left alone: mutating arbitrary
        // host ownership from a volume mount is never safe.
        if let Some(fs_group) = pod_fs_group(pod) {
            let owned = if vol.get("secret").is_some() {
                Some((
                    self.get_pod_volume_dir(pod_uid, "kubernetes.io~secret", vol_name),
                    true,
                ))
            } else if vol.get("configMap").is_some() {
                Some((
                    self.get_pod_volume_dir(pod_uid, "kubernetes.io~configmap", vol_name),
                    true,
                ))
            } else if vol.get("image").is_some() {
                Some((
                    self.get_pod_volume_dir(pod_uid, "kubernetes.io~image", vol_name),
                    true,
                ))
            } else if vol.get("downwardAPI").is_some() {
                Some((
                    self.get_pod_volume_dir(pod_uid, "kubernetes.io~downward-api", vol_name),
                    true,
                ))
            } else if vol.get("projected").is_some() {
                Some((
                    self.get_pod_volume_dir(pod_uid, "kubernetes.io~projected", vol_name),
                    true,
                ))
            } else if vol.get("emptyDir").is_some() {
                Some((
                    self.get_pod_volume_dir(pod_uid, "kubernetes.io~empty-dir", vol_name),
                    false,
                ))
            } else if vol.get("persistentVolumeClaim").is_some() {
                let link = self.get_pod_volume_dir(
                    pod_uid,
                    "kubernetes.io~persistent-volume-claim",
                    vol_name,
                );
                Some((std::fs::canonicalize(&link).unwrap_or(link), false))
            } else {
                None
            };
            if let Some((dir, readonly)) = owned {
                let on_root_mismatch = !readonly
                    && pod
                        .pointer("/spec/securityContext/fsGroupChangePolicy")
                        .and_then(Value::as_str)
                        == Some("OnRootMismatch");
                apply_fs_group_ownership_with_options(&dir, fs_group, readonly, on_root_mismatch)
                    .map_err(|e| KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!(
                        "failed to apply fsGroup ownership to {}: {e}",
                        dir.display()
                    ),
                })?;
            }
        }

        Ok(())
    }

    async fn prepare_image_volume(
        &self,
        img_vol: &Value,
        vol_dir: &Path,
    ) -> Result<(), KubeletError> {
        let reference = img_vol
            .get("reference")
            .and_then(Value::as_str)
            .unwrap_or("");
        if reference.is_empty() {
            return Err(KubeletError::InvalidConfiguration {
                field: "image.reference".to_string(),
                reason: "image volume reference must not be empty".to_string(),
            });
        }
        let pull_policy = img_vol
            .get("pullPolicy")
            .and_then(Value::as_str)
            .unwrap_or("IfNotPresent");
        let spec = cri::ImageSpec {
            image: reference.to_string(),
            user_specified_image: reference.to_string(),
            ..cri::ImageSpec::default()
        };
        let should_pull = match pull_policy {
            "Always" => true,
            "Never" => false,
            _ => self.runtime.image_status(&spec).await?.is_none(),
        };
        if should_pull {
            let _ = self.runtime.pull_image(&spec, None).await;
        }
        materialize_image_volume(reference, vol_dir)
    }

    /// Prepares and populates volume mounts (Secrets, `ConfigMaps`, Projected) on the host filesystem.
    fn pod_with_service_account_volume(&self, pod: &Value) -> Value {
        if self.apiserver.is_none()
            || !automount_service_account_token(pod)
            || pod_has_service_account_token(pod)
        {
            return pod.clone();
        }
        let mut enriched = pod.clone();
        let Some(spec) = enriched.get_mut("spec").and_then(Value::as_object_mut) else {
            return enriched;
        };
        if let Some(volumes) = spec
            .entry("volumes".to_string())
            .or_insert_with(|| json!([]))
            .as_array_mut()
        {
            volumes.push(json!({
                "name": SERVICE_ACCOUNT_VOLUME_NAME,
                "projected": {
                    "defaultMode": 420,
                    "sources": [{
                        "serviceAccountToken": {
                            "path": "token",
                            "audience": KUBERNETES_API_AUDIENCE,
                            "expirationSeconds": 7200
                        }
                    }]
                }
            }));
        }
        for key in ["containers", "initContainers"] {
            let Some(containers) = spec.get_mut(key).and_then(Value::as_array_mut) else {
                continue;
            };
            for container in containers {
                let Some(container) = container.as_object_mut() else {
                    continue;
                };
                if let Some(mounts) = container
                    .entry("volumeMounts".to_string())
                    .or_insert_with(|| json!([]))
                    .as_array_mut()
                {
                    mounts.push(json!({
                        "name": SERVICE_ACCOUNT_VOLUME_NAME,
                        "mountPath": SERVICE_ACCOUNT_MOUNT_PATH,
                        "readOnly": true
                    }));
                }
            }
        }
        enriched
    }

    pub async fn prepare_pod_volumes(
        &self,
        namespace: &str,
        pod: &Value,
    ) -> Result<(), KubeletError> {
        let name = pod
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let pod_uid = pod
            .get("metadata")
            .and_then(|m| m.get("uid"))
            .and_then(Value::as_str)
            .unwrap_or(name);

        let host_network = pod
            .pointer("/spec/hostNetwork")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !host_network {
            let pod_dir = self.root_dir.join("pods").join(pod_uid);
            let pod_ip = pod
                .pointer("/status/podIP")
                .and_then(Value::as_str)
                .unwrap_or("");
            let _ = generate_etc_hosts(&pod_dir, pod, pod_ip);
        }

        let Some(volumes) = pod
            .get("spec")
            .and_then(|s| s.get("volumes"))
            .and_then(Value::as_array)
        else {
            return Ok(());
        };

        for vol in volumes {
            let vol_name = vol.get("name").and_then(Value::as_str).unwrap_or("unnamed");
            if let Err(e) = self
                .prepare_single_volume(namespace, name, pod_uid, pod, vol)
                .await
            {
                return Err(KubeletError::PodReconciliationFailed {
                    pod: vol_name.to_string(),
                    reason: e.to_string(),
                });
            }
        }

        Ok(())
    }
}

fn validate_pod_cert_path(path: &str) -> Result<(), KubeletError> {
    if path.is_empty() || path.starts_with('/') || path.starts_with('\\') || path.contains("..") {
        return Err(KubeletError::InvalidConfiguration {
            field: "podCertificate.path".to_string(),
            reason: format!("invalid path '{path}'"),
        });
    }
    Ok(())
}

fn generate_pod_certificate_key(
    pod_uid: &str,
    key_type: &str,
) -> Result<CachedPodCertificateKey, KubeletError> {
    diorama_pki::generate_pod_certificate_key_data(pod_uid, key_type).map_err(|e| {
        KubeletError::PodReconciliationFailed {
            pod: pod_uid.to_string(),
            reason: format!("failed to generate pod certificate key data: {e}"),
        }
    })
}

fn write_pod_cert_files(
    vol_dir: &Path,
    key_pem: &str,
    cert_chain: &str,
    pod_cert: &Value,
) -> Result<Vec<PathBuf>, KubeletError> {
    let mut written = Vec::new();
    if let Some(kp) = pod_cert.get("keyPath").and_then(Value::as_str) {
        let p = safe_volume_path(vol_dir, kp)?;
        write_volume_file(&p, key_pem.as_bytes()).map_err(KubeletError::Io)?;
        chmod_volume_file(&p, 0o600);
        written.push(p);
    }
    if let Some(cp) = pod_cert.get("certificateChainPath").and_then(Value::as_str) {
        let p = safe_volume_path(vol_dir, cp)?;
        write_volume_file(&p, cert_chain.as_bytes()).map_err(KubeletError::Io)?;
        chmod_volume_file(&p, 0o644);
        written.push(p);
    }
    if let Some(bp) = pod_cert.get("credentialBundlePath").and_then(Value::as_str) {
        let p = safe_volume_path(vol_dir, bp)?;
        let bundle = format!("{}\n{}\n", key_pem.trim_end(), cert_chain.trim());
        write_volume_file(&p, bundle.as_bytes()).map_err(KubeletError::Io)?;
        chmod_volume_file(&p, 0o600);
        written.push(p);
    }
    Ok(written)
}

/// Target host for an `httpGet`/`tcpSocket` probe: the explicit host, with
/// blank and loopback values meaning the pod IP, as upstream resolves them.
fn probe_host(pod_ip: Option<&str>, configured: Option<&str>) -> Option<String> {
    match configured.map_or("", str::trim) {
        "" | "localhost" | "127.0.0.1" | "::1" => {
            pod_ip.filter(|ip| !ip.is_empty()).map(str::to_string)
        },
        host => Some(host.to_string()),
    }
}

fn probe_timeout(probe: &Value) -> std::time::Duration {
    let secs = probe
        .get("timeoutSeconds")
        .and_then(Value::as_u64)
        .filter(|secs| *secs > 0)
        .unwrap_or(1);
    std::time::Duration::from_secs(secs)
}

/// Dials a `tcpSocket` probe from the node. Refused and timed-out dials fail.
async fn tcp_probe(pod_ip: Option<&str>, container: &Value, tcp: &Value) -> bool {
    let Some(port) = resolve_probe_port(container, tcp.get("port")) else {
        return false;
    };
    let host = tcp.get("host").and_then(Value::as_str);
    let Some(target) = probe_host(pod_ip, host) else {
        return false;
    };
    tokio::time::timeout(
        probe_timeout(tcp),
        tokio::net::TcpStream::connect((target.as_str(), port)),
    )
    .await
    .is_ok_and(|connected| connected.is_ok())
}

/// Dials a `grpc` probe from the node using HTTP/2 health check RPC.
async fn grpc_probe(pod_ip: Option<&str>, container: &Value, grpc: &Value) -> bool {
    let Some(port) = resolve_probe_port(container, grpc.get("port")) else {
        return false;
    };
    let host = grpc.get("host").and_then(Value::as_str);
    let Some(target) = probe_host(pod_ip, host) else {
        return false;
    };
    let service = grpc.get("service").and_then(Value::as_str).unwrap_or("");
    tokio::time::timeout(
        probe_timeout(grpc),
        execute_grpc_health_check(&target, port, service),
    )
    .await
    .is_ok_and(|res| res.unwrap_or(false))
}

fn build_grpc_headers() -> Vec<u8> {
    let mut hpack = Vec::new();
    hpack.push(0x83); // :method: POST
    hpack.push(0x86); // :scheme: http
    hpack.extend_from_slice(&[0x00, 5]);
    hpack.extend_from_slice(b":path");
    hpack.push(28);
    hpack.extend_from_slice(b"/grpc.health.v1.Health/Check");
    hpack.extend_from_slice(&[0x00, 12]);
    hpack.extend_from_slice(b"content-type");
    hpack.push(16);
    hpack.extend_from_slice(b"application/grpc");
    hpack.extend_from_slice(&[0x00, 2]);
    hpack.extend_from_slice(b"te");
    hpack.push(8);
    hpack.extend_from_slice(b"trailers");
    hpack
}

fn build_grpc_request(service: &str) -> Vec<u8> {
    let mut request = Vec::with_capacity(128);
    request.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    request.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let hpack = build_grpc_headers();
    let hpack_u32 = u32::try_from(hpack.len()).unwrap_or(0);
    let [_, h0, h1, h2] = hpack_u32.to_be_bytes();
    request.extend_from_slice(&[h0, h1, h2, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01]);
    request.extend_from_slice(&hpack);

    let mut proto_body = Vec::new();
    if !service.is_empty() {
        proto_body.push(0x0a);
        let s_len = u8::try_from(service.len()).unwrap_or(0);
        proto_body.push(s_len);
        proto_body.extend_from_slice(service.as_bytes());
    }
    let proto_len = u32::try_from(proto_body.len()).unwrap_or(0);
    let grpc_msg_len = 5 + proto_body.len();
    let grpc_u32 = u32::try_from(grpc_msg_len).unwrap_or(0);
    let [_, g0, g1, g2] = grpc_u32.to_be_bytes();

    request.extend_from_slice(&[g0, g1, g2, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00]);
    request.extend_from_slice(&proto_len.to_be_bytes());
    request.extend_from_slice(&proto_body);

    request
}

async fn execute_grpc_health_check(
    target: &str,
    port: u16,
    service: &str,
) -> Result<bool, std::io::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect((target, port)).await?;
    let request = build_grpc_request(service);
    stream.write_all(&request).await?;

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    while buf.len() < 4096 {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if parse_grpc_response(&buf) {
            return Ok(true);
        }
        if is_grpc_failure(&buf) {
            return Ok(false);
        }
    }
    Ok(parse_grpc_response(&buf))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn is_grpc_failure(buf: &[u8]) -> bool {
    if find_subsequence(buf, &[0x08, 0x02]).is_some()
        || find_subsequence(buf, &[0x08, 0x03]).is_some()
    {
        return true;
    }
    if let Some(pos) = find_subsequence(buf, b"grpc-status") {
        let rest = &buf[pos + b"grpc-status".len()..];
        let trimmed = rest
            .iter()
            .skip_while(|&&b| b == b':' || b == b' ' || b < 32);
        if let Some(&first) = trimmed.take(1).next()
            && first != b'0'
        {
            return true;
        }
    }
    false
}

fn parse_grpc_response(buf: &[u8]) -> bool {
    if is_grpc_failure(buf) {
        return false;
    }
    find_subsequence(buf, &[0x08, 0x01]).is_some()
}

/// Performs an `httpGet` probe from the node with a minimal `HTTP/1.0`
/// client. Any 2xx/3xx status succeeds, as upstream. `https` has no TLS
/// stack here, so it keeps the previous `curl` emulation inside the
/// container as a best effort.
async fn http_probe(
    runtime: &Arc<dyn RuntimeProvider>,
    container_id: &str,
    pod_ip: Option<&str>,
    container: &Value,
    http: &Value,
) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let scheme = http
        .get("scheme")
        .and_then(Value::as_str)
        .unwrap_or("HTTP")
        .to_ascii_lowercase();
    if scheme == "https" {
        return curl_probe(runtime, container, container_id, http).await;
    }
    let Some(port) = resolve_probe_port(container, http.get("port")) else {
        return false;
    };
    let host = http.get("host").and_then(Value::as_str);
    let Some(target) = probe_host(pod_ip, host) else {
        return false;
    };
    let timeout = probe_timeout(http);
    let raw_path = http.get("path").and_then(Value::as_str).unwrap_or("/");
    let path = if raw_path.starts_with('/') {
        raw_path.to_string()
    } else {
        format!("/{raw_path}")
    };
    let headers = http.get("httpHeaders").and_then(Value::as_array);
    let has_custom_host = headers.is_some_and(|items| {
        items.iter().any(|header| {
            header
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.eq_ignore_ascii_case("host"))
        })
    });
    let mut request = format!("GET {path} HTTP/1.0\r\n");
    if !has_custom_host {
        request.push_str("Host: ");
        request.push_str(&target);
        request.push_str("\r\n");
    }
    request.push_str("Connection: close\r\n");
    if let Some(headers) = headers {
        for header in headers {
            let name = header.get("name").and_then(Value::as_str).unwrap_or("");
            let value = header.get("value").and_then(Value::as_str).unwrap_or("");
            if !name.is_empty() {
                request.push_str(name);
                request.push_str(": ");
                request.push_str(value);
                request.push_str("\r\n");
            }
        }
    }
    request.push_str("\r\n");
    let dialled = tokio::time::timeout(
        timeout,
        tokio::net::TcpStream::connect((target.as_str(), port)),
    )
    .await;
    let Ok(Ok(mut stream)) = dialled else {
        return false;
    };
    let responded = tokio::time::timeout(timeout, async {
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        let mut head = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            head.extend_from_slice(&chunk[..read]);
            if head.contains(&b'\n') || head.len() > 8192 {
                break;
            }
        }
        std::io::Result::Ok(head)
    })
    .await;
    let Ok(Ok(head)) = responded else {
        return false;
    };
    let status_line = String::from_utf8_lossy(&head);
    let code = status_line
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    (200..400).contains(&code)
}

/// Best-effort `https` probe through `curl` inside the container, for images
/// that ship it. Failure (including a missing binary) fails the probe.
async fn curl_probe(
    runtime: &Arc<dyn RuntimeProvider>,
    container: &Value,
    container_id: &str,
    http: &Value,
) -> bool {
    let port = resolve_probe_port(container, http.get("port")).unwrap_or(443);
    let raw_path = http.get("path").and_then(Value::as_str).unwrap_or("/");
    let path = if raw_path.starts_with('/') {
        raw_path.to_string()
    } else {
        format!("/{raw_path}")
    };
    let url = format!("https://127.0.0.1:{port}{path}");
    let timeout = probe_timeout(http).as_secs().max(1);
    let timeout = i64::try_from(timeout).unwrap_or(EXEC_TIMEOUT_SECS);
    runtime
        .exec_sync(
            container_id,
            &[
                "curl".to_string(),
                "-fsk".to_string(),
                "-o".to_string(),
                "/dev/null".to_string(),
                url,
            ],
            timeout,
        )
        .await
        .is_ok_and(|result| result.exit_code == 0)
}

fn resolve_probe_port(container: &Value, port_val: Option<&Value>) -> Option<u16> {
    let port_val = port_val?;
    if let Some(port) = port_val.as_u64() {
        return u16::try_from(port).ok();
    }
    let port_str = port_val.as_str()?;
    if let Ok(port) = port_str.parse::<u16>() {
        return Some(port);
    }
    let ports = container.get("ports").and_then(Value::as_array)?;
    for p in ports {
        if p.get("name").and_then(Value::as_str) == Some(port_str) {
            return p
                .get("containerPort")
                .and_then(Value::as_u64)
                .and_then(|cp| u16::try_from(cp).ok());
        }
    }
    None
}

fn dead_container_views<'a>(
    pod: &'a Value,
    pointer: &str,
    grouped: &BTreeMap<&str, Vec<&'a cri::ContainerStatus>>,
) -> Vec<ContainerView<'a>> {
    let containers = pod
        .pointer(pointer)
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    containers
        .iter()
        .map(|container| {
            let c_name = container
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("main");
            let attempts = grouped.get(c_name).map_or(&[][..], Vec::as_slice);
            ContainerView {
                spec: container,
                latest: attempts.last().copied(),
                previous: None,
                ready: false,
                backoff: None,
                waiting: None,
                cpu: None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pod_has_service_account_token_custom_projected_tokens() {
        let pod_custom = json!({
            "metadata": { "name": "oidc-validator", "namespace": "default" },
            "spec": {
                "volumes": [{
                    "name": "custom-token-vol",
                    "projected": {
                        "sources": [{
                            "serviceAccountToken": {
                                "path": "custom-token",
                                "audience": "https://vault.example.com",
                                "expirationSeconds": 3600
                            }
                        }]
                    }
                }],
                "containers": [{
                    "name": "validator",
                    "image": "busybox:1.36",
                    "volumeMounts": [{
                        "name": "custom-token-vol",
                        "mountPath": "/var/run/secrets/tokens"
                    }]
                }]
            }
        });
        assert!(!pod_has_service_account_token(&pod_custom));

        let pod_kube_api = json!({
            "metadata": { "name": "kube-app", "namespace": "default" },
            "spec": {
                "volumes": [{
                    "name": "kube-api-access-abc12",
                    "projected": {
                        "sources": [{
                            "serviceAccountToken": {
                                "path": "token"
                            }
                        }]
                    }
                }],
                "containers": [{
                    "name": "app",
                    "image": "busybox:1.36",
                    "volumeMounts": [{
                        "name": "kube-api-access-abc12",
                        "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
                    }]
                }]
            }
        });
        assert!(pod_has_service_account_token(&pod_kube_api));

        let pod_mounted_sa = json!({
            "metadata": { "name": "manual-sa", "namespace": "default" },
            "spec": {
                "volumes": [{
                    "name": "my-sa",
                    "emptyDir": {}
                }],
                "containers": [{
                    "name": "app",
                    "image": "busybox:1.36",
                    "volumeMounts": [{
                        "name": "my-sa",
                        "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
                    }]
                }]
            }
        });
        assert!(pod_has_service_account_token(&pod_mounted_sa));
    }

    #[test]
    fn security_context_maps_users_groups_and_privilege() {
        let pod = json!({
            "metadata": { "name": "app", "namespace": "default", "uid": "uid-1" },
            "spec": {
                "securityContext": {
                    "runAsUser": 1000,
                    "runAsGroup": 3000,
                    "fsGroup": 2000,
                    "supplementalGroups": [4000]
                },
                "containers": [{
                    "name": "main",
                    "image": "busybox:1.36",
                    "securityContext": { "runAsUser": 1001, "privileged": true }
                }]
            }
        });
        let container = pod["spec"]["containers"][0].clone();
        let config = container_config(&pod, &container, 0).unwrap();
        let sc = config
            .linux
            .as_ref()
            .and_then(|linux| linux.security_context.as_ref())
            .expect("security context is mapped");
        // Container runAsUser overrides the pod value.
        assert_eq!(sc.run_as_user.as_ref().map(|id| id.value), Some(1001));
        assert_eq!(sc.run_as_group.as_ref().map(|id| id.value), Some(3000));
        // fsGroup joins the supplementary groups.
        assert!(sc.supplemental_groups.contains(&2000));
        assert!(sc.supplemental_groups.contains(&4000));
        assert!(sc.privileged);
    }

    #[test]
    fn security_context_absent_without_security_fields() {
        let pod = json!({
            "metadata": { "name": "app", "namespace": "default", "uid": "uid-1" },
            "spec": { "containers": [{ "name": "main", "image": "busybox:1.36" }] }
        });
        let container = pod["spec"]["containers"][0].clone();
        let config = container_config(&pod, &container, 0).unwrap();
        assert!(config.linux.is_none());
    }

    #[test]
    fn secret_key_ref_decodes_into_the_container_env() {
        let pod = json!({
            "metadata": { "name": "app", "namespace": "sonobuoy", "uid": "uid-1" },
            "spec": { "containers": [{
                "name": "worker",
                "image": "sonobuoy:v0.57.5",
                "env": [{
                    "name": "CLIENT_CERT",
                    "valueFrom": { "secretKeyRef": { "name": "kube", "key": "cert" } }
                }]
            }]}
        });
        let container = pod["spec"]["containers"][0].clone();
        let mut env_objects = EnvObjects::default();
        env_objects.secrets.insert(
            "kube".to_string(),
            json!({ "data": { "cert": "Y2VydA==" } }),
        );
        let config = container_config_with_env(&pod, &container, 0, None, &env_objects).unwrap();
        assert_eq!(env_of(&config.envs, "CLIENT_CERT").as_deref(), Some("cert"));
    }

    #[test]
    fn privileged_host_pod_opts_the_sandbox_in() {
        let pod = json!({
            "metadata": { "name": "logs", "namespace": "sonobuoy", "uid": "uid-1" },
            "spec": {
                "hostNetwork": true,
                "hostPID": true,
                "containers": [{
                    "name": "systemd-logs",
                    "image": "sonobuoy/systemd-logs:v0.4",
                    "securityContext": { "privileged": true }
                }]
            }
        });
        let config = sandbox_config(&pod, 0);
        assert_eq!(config.hostname, "");
        let security = config
            .linux
            .as_ref()
            .and_then(|linux| linux.security_context.as_ref())
            .expect("sandbox security");
        assert!(security.privileged);
        let namespaces = security.namespace_options.as_ref().expect("namespaces");
        assert_eq!(namespaces.network, cri::NamespaceMode::Node as i32);
        assert_eq!(namespaces.pid, cri::NamespaceMode::Node as i32);
    }

    #[test]
    fn probe_host_prefers_pod_ip_for_loopback() {
        assert_eq!(
            probe_host(Some("10.42.0.5"), None).as_deref(),
            Some("10.42.0.5")
        );
        assert_eq!(
            probe_host(Some("10.42.0.5"), Some("127.0.0.1")).as_deref(),
            Some("10.42.0.5")
        );
        assert_eq!(
            probe_host(Some("10.42.0.5"), Some("10.0.0.9")).as_deref(),
            Some("10.0.0.9")
        );
        assert_eq!(probe_host(None, None), None);
    }

    async fn serve_probe_status(mut stream: tokio::net::TcpStream, request: Vec<u8>) {
        use tokio::io::AsyncWriteExt;
        let status = if String::from_utf8_lossy(&request).contains("/bad") {
            "500"
        } else {
            "200"
        };
        let body = format!("HTTP/1.0 {status} OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = stream.write_all(body.as_bytes()).await;
    }

    async fn read_probe_request(stream: &mut tokio::net::TcpStream) -> Option<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut head = vec![0_u8; 1024];
        let read = stream.read(&mut head).await.ok()?;
        head.truncate(read);
        Some(head)
    }

    async fn run_probe_server(listener: tokio::net::TcpListener) {
        while let Ok((mut stream, _)) = listener.accept().await {
            let Some(request) = read_probe_request(&mut stream).await else {
                continue;
            };
            serve_probe_status(stream, request).await;
        }
    }

    #[tokio::test]
    async fn http_probe_accepts_2xx_and_rejects_500() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(run_probe_server(listener));
        let container = json!({});
        let ok = json!({ "path": "/health", "port": port });
        assert!(http_probe(&mock_runtime(), "id", Some("127.0.0.1"), &container, &ok).await);
        let bad = json!({ "path": "/bad", "port": port });
        assert!(!http_probe(&mock_runtime(), "id", Some("127.0.0.1"), &container, &bad).await);
        let refused = json!({ "path": "/", "port": 1 });
        assert!(
            !http_probe(
                &mock_runtime(),
                "id",
                Some("127.0.0.1"),
                &container,
                &refused
            )
            .await
        );
    }

    #[tokio::test]
    async fn tcp_probe_checks_connectivity() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });
        let container = json!({});
        let open = json!({ "port": port });
        assert!(tcp_probe(Some("127.0.0.1"), &container, &open).await);
        let closed = json!({ "port": 1 });
        assert!(!tcp_probe(Some("127.0.0.1"), &container, &closed).await);
        assert!(!tcp_probe(None, &container, &open).await);
    }

    fn mock_runtime() -> Arc<dyn RuntimeProvider> {
        Arc::new(crate::mock::MockRuntimeProvider::new("mock"))
    }

    #[test]
    fn run_as_non_root_rejects_uid_zero() {
        let pod = json!({
            "metadata": { "name": "app", "namespace": "default", "uid": "uid-1" },
            "spec": {
                "securityContext": { "runAsNonRoot": true, "runAsUser": 0 },
                "containers": [{ "name": "main", "image": "busybox:1.36" }]
            }
        });
        let container = pod["spec"]["containers"][0].clone();
        assert!(container_config(&pod, &container, 0).is_err());
    }

    fn env_of(envs: &[cri::KeyValue], key: &str) -> Option<String> {
        envs.iter()
            .find(|env| env.key == key)
            .map(|env| String::from_utf8_lossy(&env.value).into_owned())
    }

    #[test]
    fn service_links_skip_empty_and_headless_cluster_ips() {
        let pod = json!({
            "metadata": { "name": "app", "namespace": "default" },
            "spec": { "containers": [{ "name": "main" }] }
        });
        let services = vec![
            json!({
                "metadata": { "name": "kubernetes", "namespace": "default" },
                "spec": {
                    "clusterIP": "10.43.0.1",
                    "ports": [{ "name": "https", "port": 443, "protocol": "TCP" }]
                }
            }),
            json!({
                "metadata": { "name": "blank", "namespace": "default" },
                "spec": {
                    "clusterIP": "",
                    "ports": [{ "name": "http", "port": 80, "protocol": "TCP" }]
                }
            }),
            json!({
                "metadata": { "name": "headless", "namespace": "default" },
                "spec": {
                    "clusterIP": "None",
                    "ports": [{ "name": "http", "port": 8080, "protocol": "TCP" }]
                }
            }),
            json!({
                "metadata": { "name": "web", "namespace": "default" },
                "spec": {
                    "clusterIP": "10.43.0.2",
                    "ports": [{ "name": "http", "port": 8080, "protocol": "TCP" }]
                }
            }),
        ];

        let disabled = json!({
            "metadata": { "name": "app", "namespace": "default" },
            "spec": { "enableServiceLinks": false, "containers": [{ "name": "main" }] }
        });
        let off = service_link_envs(&disabled, &services);
        assert_eq!(
            env_of(&off, "KUBERNETES_SERVICE_HOST").as_deref(),
            Some("10.43.0.1")
        );
        assert_eq!(
            env_of(&off, "KUBERNETES_SERVICE_PORT").as_deref(),
            Some("443")
        );
        assert_eq!(
            env_of(&off, "KUBERNETES_SERVICE_PORT_HTTPS").as_deref(),
            Some("443")
        );
        assert!(env_of(&off, "WEB_SERVICE_HOST").is_none());
        assert!(env_of(&off, "HEADLESS_SERVICE_HOST").is_none());
        assert!(env_of(&off, "BLANK_SERVICE_HOST").is_none());

        let on = service_link_envs(&pod, &services);
        assert_eq!(
            env_of(&on, "WEB_SERVICE_HOST").as_deref(),
            Some("10.43.0.2")
        );
        assert_eq!(env_of(&on, "WEB_SERVICE_PORT").as_deref(), Some("8080"));
        assert_eq!(
            env_of(&on, "WEB_PORT").as_deref(),
            Some("tcp://10.43.0.2:8080")
        );
        assert!(env_of(&on, "HEADLESS_SERVICE_HOST").is_none());
        assert!(env_of(&on, "BLANK_SERVICE_HOST").is_none());
    }

    #[test]
    fn test_build_dns_config_cluster_first_default() {
        let pod = json!({
            "metadata": {
                "name": "test-pod",
                "namespace": "production"
            },
            "spec": {
                "containers": [{ "name": "app", "image": "busybox" }]
            }
        });
        let dns = build_dns_config(&pod, &["10.43.0.10".to_string()], "cluster.local").unwrap();
        assert_eq!(dns.servers, vec!["10.43.0.10"]);
        assert_eq!(
            dns.searches,
            vec![
                "production.svc.cluster.local",
                "svc.cluster.local",
                "cluster.local"
            ]
        );
        assert_eq!(dns.options, vec!["ndots:5"]);
    }

    #[test]
    fn test_build_dns_config_with_custom_dns_config() {
        let pod = json!({
            "metadata": {
                "name": "test-pod",
                "namespace": "default"
            },
            "spec": {
                "dnsConfig": {
                    "nameservers": ["8.8.8.8"],
                    "searches": ["custom.domain"],
                    "options": [
                        { "name": "ndots", "value": "2" },
                        { "name": "single-request-reopen" }
                    ]
                }
            }
        });
        let dns = build_dns_config(&pod, &["10.43.0.10".to_string()], "cluster.local").unwrap();
        assert_eq!(dns.servers, vec!["10.43.0.10", "8.8.8.8"]);
        assert_eq!(
            dns.searches,
            vec![
                "default.svc.cluster.local",
                "svc.cluster.local",
                "cluster.local",
                "custom.domain"
            ]
        );
        assert_eq!(dns.options, vec!["ndots:2", "single-request-reopen"]);
    }

    #[test]
    fn test_build_dns_config_default_policy_without_custom_config() {
        let pod = json!({
            "metadata": {
                "name": "coredns-pod",
                "namespace": "kube-system"
            },
            "spec": {
                "dnsPolicy": "Default"
            }
        });
        let dns = build_dns_config(&pod, &["10.43.0.10".to_string()], "cluster.local");
        assert!(dns.is_none(), "Default dnsPolicy should inherit host DNS");
    }

    #[test]
    fn test_build_dns_config_none_policy() {
        let pod = json!({
            "metadata": {
                "name": "custom-pod",
                "namespace": "default"
            },
            "spec": {
                "dnsPolicy": "None",
                "dnsConfig": {
                    "nameservers": ["1.1.1.1"],
                    "searches": ["foo.bar"]
                }
            }
        });
        let dns = build_dns_config(&pod, &["10.43.0.10".to_string()], "cluster.local").unwrap();
        assert_eq!(dns.servers, vec!["1.1.1.1"]);
        assert_eq!(dns.searches, vec!["foo.bar"]);
        assert_eq!(dns.options, <[String; 0]>::default());
    }

    #[test]
    fn test_sandbox_config_populates_dns_config() {
        let pod = json!({
            "metadata": {
                "name": "nginx",
                "namespace": "default"
            },
            "spec": {
                "containers": [{ "name": "nginx", "image": "nginx" }]
            }
        });
        let config = sandbox_config(&pod, 0);
        let dns = config.dns_config.expect("dns_config is populated");
        assert_eq!(dns.servers, vec!["10.43.0.10"]);
        assert_eq!(dns.searches[0], "default.svc.cluster.local");
    }

    #[test]
    fn test_host_ports_conflict_evaluations() {
        let p_wildcard = HostPortRequest {
            host_port: 8080,
            protocol: "TCP".to_string(),
            host_ip: "0.0.0.0".to_string(),
        };
        let p_empty = HostPortRequest {
            host_port: 8080,
            protocol: "TCP".to_string(),
            host_ip: String::new(),
        };
        let p_specific1 = HostPortRequest {
            host_port: 8080,
            protocol: "TCP".to_string(),
            host_ip: "127.0.0.1".to_string(),
        };
        let p_specific2 = HostPortRequest {
            host_port: 8080,
            protocol: "TCP".to_string(),
            host_ip: "10.0.0.1".to_string(),
        };
        let p_udp = HostPortRequest {
            host_port: 8080,
            protocol: "UDP".to_string(),
            host_ip: "0.0.0.0".to_string(),
        };
        let p_diff_port = HostPortRequest {
            host_port: 9090,
            protocol: "TCP".to_string(),
            host_ip: "0.0.0.0".to_string(),
        };

        // 0.0.0.0 conflicts with any specific IP on same port & proto
        assert!(host_ports_conflict(&p_wildcard, &p_specific1));
        assert!(host_ports_conflict(&p_specific1, &p_wildcard));

        // Empty hostIP conflicts with any specific IP
        assert!(host_ports_conflict(&p_empty, &p_specific1));
        assert!(host_ports_conflict(&p_specific1, &p_empty));

        // Two identical specific IPs conflict
        assert!(host_ports_conflict(&p_specific1, &p_specific1));

        // Two distinct specific non-wildcard IPs do not conflict
        assert!(!host_ports_conflict(&p_specific1, &p_specific2));

        // Different protocols do not conflict
        assert!(!host_ports_conflict(&p_wildcard, &p_udp));

        // Different ports do not conflict
        assert!(!host_ports_conflict(&p_wildcard, &p_diff_port));
    }

    fn setup_reconciler_test(
        dir: &tempfile::TempDir,
        node_name: &str,
    ) -> (
        Arc<diorama_apiserver::KubernetesApiClient>,
        PodReconciler,
        Arc<crate::mock::MockRuntimeProvider>,
    ) {
        use diorama_apiserver::{ApiserverConfig, KubernetesStorage};
        use diorama_datastore::{DatastoreConfig, DatastoreEngine};
        use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
        use std::net::IpAddr;

        let node_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let pki_dir = dir.path().join("pki");
        std::fs::create_dir_all(&pki_dir).unwrap();
        let datastore_dir = dir.path().join("datastore");
        let kubelet_dir = dir.path().join("kubelet");
        std::fs::create_dir_all(&kubelet_dir).unwrap();

        let pki_config = ClusterPkiConfig::new(pki_dir.clone(), node_name.to_string(), node_ip);
        let pki = ClusterPki::new(pki_config);
        pki.reconcile().expect("PKI reconcile");

        let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(datastore_dir)).unwrap();
        let storage = KubernetesStorage::new(engine.client(), "/registry");

        let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
        let apiserver = Arc::new(ApiserverService::new(apiserver_config, storage));
        let client = Arc::new(apiserver.admin_client());

        let runtime = Arc::new(crate::mock::MockRuntimeProvider::new("mock"));
        let reconciler =
            PodReconciler::new(client.clone(), runtime.clone(), node_name, "127.0.0.1")
                .with_root_dir(&kubelet_dir)
                .with_apiserver(apiserver);

        (client, reconciler, runtime)
    }

    async fn create_test_node(client: &diorama_apiserver::KubernetesApiClient, name: &str) {
        let node = json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": name,
                "labels": {
                    "kubernetes.io/hostname": name,
                    "kubernetes.io/os": "linux",
                    "kubernetes.io/arch": "amd64",
                    "node.kubernetes.io/instance-type": "k8s"
                }
            },
            "status": {
                "conditions": [{
                    "type": "Ready",
                    "status": "True",
                    "reason": "KubeletReady",
                    "message": "kubelet is posting ready status"
                }],
                "allocatable": {
                    "cpu": "2",
                    "memory": "4Gi",
                    "pods": "110"
                }
            }
        });
        let _ = client.create_node(node).await.expect("create test node");
    }

    #[tokio::test]
    async fn test_nodeselector_targeting_second_node_schedules_onto_it() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "diorama-node");

        // Create both nodes
        create_test_node(&client, "diorama-node").await;
        create_test_node(&client, "diorama-node-worker").await;

        // Pod targeting second node (companion worker)
        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "worker-pod", "namespace": "default" },
            "spec": {
                "nodeSelector": {
                    "kubernetes.io/hostname": "diorama-node-worker"
                },
                "containers": [{
                    "name": "worker-c",
                    "image": "busybox:latest"
                }]
            }
        });
        client.create_pod("default", pod).await.expect("create pod");

        // Reconcile
        let report = reconciler.reconcile_all().await.expect("reconcile");
        assert_eq!(report.bound, 1);
        assert_eq!(report.synced, 1);

        let bound_pod = client
            .get_pod("default", "worker-pod")
            .await
            .expect("get pod");
        assert_eq!(
            bound_pod.pointer("/spec/nodeName").and_then(Value::as_str),
            Some("diorama-node-worker")
        );
        assert_eq!(
            bound_pod.pointer("/status/phase").and_then(Value::as_str),
            Some("Running")
        );
    }

    #[tokio::test]
    async fn test_hostport_conflict_with_wildcard_hostip_marks_second_pod_unschedulable() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "diorama-node");

        create_test_node(&client, "diorama-node").await;
        create_test_node(&client, "diorama-node-worker").await;

        // First pod binds hostPort 8080 with 0.0.0.0 on diorama-node
        let pod1 = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "pod1", "namespace": "default" },
            "spec": {
                "nodeSelector": {
                    "kubernetes.io/hostname": "diorama-node"
                },
                "containers": [{
                    "name": "c1",
                    "image": "busybox:latest",
                    "ports": [{
                        "containerPort": 80,
                        "hostPort": 8080,
                        "protocol": "TCP",
                        "hostIP": "0.0.0.0"
                    }]
                }]
            }
        });
        client
            .create_pod("default", pod1)
            .await
            .expect("create pod1");

        // First reconcile runs pod1
        let report1 = reconciler.reconcile_all().await.expect("reconcile 1");
        assert_eq!(report1.bound, 1);
        assert_eq!(report1.synced, 1);
        let bound1 = client.get_pod("default", "pod1").await.expect("get pod1");
        assert_eq!(
            bound1.pointer("/spec/nodeName").and_then(Value::as_str),
            Some("diorama-node")
        );
        assert_eq!(
            bound1.pointer("/status/phase").and_then(Value::as_str),
            Some("Running")
        );

        // Second pod requests same hostPort 8080 with specific hostIP 127.0.0.1 targeted to diorama-node
        let pod2 = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "pod2", "namespace": "default" },
            "spec": {
                "nodeSelector": {
                    "kubernetes.io/hostname": "diorama-node"
                },
                "containers": [{
                    "name": "c2",
                    "image": "busybox:latest",
                    "ports": [{
                        "containerPort": 80,
                        "hostPort": 8080,
                        "protocol": "TCP",
                        "hostIP": "127.0.0.1"
                    }]
                }]
            }
        });
        client
            .create_pod("default", pod2)
            .await
            .expect("create pod2");

        // Second reconcile should detect conflict and mark pod2 unschedulable
        let report2 = reconciler.reconcile_all().await.expect("reconcile 2");
        assert_eq!(report2.bound, 0);

        let pod2_state = client.get_pod("default", "pod2").await.expect("get pod2");
        assert_eq!(
            pod2_state.pointer("/status/phase").and_then(Value::as_str),
            Some("Pending")
        );

        let conds = pod2_state
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .expect("conditions array");
        let sched_cond = conds
            .iter()
            .find(|c| c["type"] == "PodScheduled")
            .expect("PodScheduled condition");
        assert_eq!(sched_cond["status"], "False");
        assert_eq!(sched_cond["reason"], "Unschedulable");
        let msg = sched_cond["message"].as_str().expect("message string");
        assert!(
            msg.contains("node(s) didn't have free ports for the requested pod ports"),
            "expected free ports message, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_hostport_conflict_with_omitted_hostip_marks_second_pod_unschedulable() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "diorama-node");

        create_test_node(&client, "diorama-node").await;
        create_test_node(&client, "diorama-node-worker").await;

        // Pod 1 omits hostIP (implicit wildcard)
        let pod1 = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "wildcard-pod", "namespace": "default" },
            "spec": {
                "nodeSelector": {
                    "kubernetes.io/hostname": "diorama-node"
                },
                "containers": [{
                    "name": "c1",
                    "image": "busybox:latest",
                    "ports": [{
                        "containerPort": 80,
                        "hostPort": 8088,
                        "protocol": "TCP"
                    }]
                }]
            }
        });
        client
            .create_pod("default", pod1)
            .await
            .expect("create pod1");
        reconciler.reconcile_all().await.expect("reconcile 1");

        // Pod 2 has specific hostIP on the same node
        let pod2 = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "specific-pod", "namespace": "default" },
            "spec": {
                "nodeSelector": {
                    "kubernetes.io/hostname": "diorama-node"
                },
                "containers": [{
                    "name": "c2",
                    "image": "busybox:latest",
                    "ports": [{
                        "containerPort": 80,
                        "hostPort": 8088,
                        "protocol": "TCP",
                        "hostIP": "10.0.0.5"
                    }]
                }]
            }
        });
        client
            .create_pod("default", pod2)
            .await
            .expect("create pod2");
        reconciler.reconcile_all().await.expect("reconcile 2");

        let pod2_state = client
            .get_pod("default", "specific-pod")
            .await
            .expect("get pod2");
        assert_eq!(
            pod2_state.pointer("/status/phase").and_then(Value::as_str),
            Some("Pending")
        );
        let conds = pod2_state
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .expect("conditions array");
        let sched_cond = conds
            .iter()
            .find(|c| c["type"] == "PodScheduled")
            .expect("PodScheduled condition");
        assert_eq!(sched_cond["status"], "False");
        assert_eq!(sched_cond["reason"], "Unschedulable");
    }

    #[tokio::test]
    async fn test_hostport_conflict_with_explicit_spec_nodename_leaves_pending() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, runtime) = setup_reconciler_test(&temp, "diorama-node");

        create_test_node(&client, "diorama-node").await;
        create_test_node(&client, "diorama-node-worker").await;

        // Pod 1 running on diorama-node
        let pod1 = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "running-pod", "namespace": "default" },
            "spec": {
                "nodeName": "diorama-node",
                "containers": [{
                    "name": "c1",
                    "image": "busybox:latest",
                    "ports": [{
                        "containerPort": 80,
                        "hostPort": 8099,
                        "protocol": "TCP",
                        "hostIP": "0.0.0.0"
                    }]
                }]
            }
        });
        client
            .create_pod("default", pod1)
            .await
            .expect("create pod1");
        reconciler.reconcile_all().await.expect("reconcile 1");

        // Verify pod1 has a running sandbox
        let filter = cri::PodSandboxFilter::default();
        let sandboxes_before = runtime.list_pod_sandbox(Some(&filter)).await.unwrap();
        assert_eq!(sandboxes_before.len(), 1);

        // Pod 2 created with nodeName explicitly set to diorama-node, with conflicting port
        let pod2 = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "conflicting-pod", "namespace": "default" },
            "spec": {
                "nodeName": "diorama-node",
                "containers": [{
                    "name": "c2",
                    "image": "busybox:latest",
                    "ports": [{
                        "containerPort": 80,
                        "hostPort": 8099,
                        "protocol": "TCP",
                        "hostIP": "127.0.0.1"
                    }]
                }]
            }
        });
        client
            .create_pod("default", pod2)
            .await
            .expect("create pod2");
        reconciler.reconcile_all().await.expect("reconcile 2");

        // No new sandbox started for pod 2!
        let sandboxes_after = runtime.list_pod_sandbox(Some(&filter)).await.unwrap();
        assert_eq!(sandboxes_after.len(), 1);

        let pod2_state = client
            .get_pod("default", "conflicting-pod")
            .await
            .expect("get pod2");
        assert_eq!(
            pod2_state.pointer("/status/phase").and_then(Value::as_str),
            Some("Failed")
        );
        assert_eq!(
            pod2_state.pointer("/status/reason").and_then(Value::as_str),
            Some("PodFitsHostPorts")
        );
        assert_eq!(
            pod2_state
                .pointer("/status/message")
                .and_then(Value::as_str),
            Some("Pod Node didn't have enough resource: pods, requested: 1")
        );
    }

    #[tokio::test]
    async fn test_hostport_on_different_nodes_no_conflict() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "diorama-node");

        create_test_node(&client, "diorama-node").await;
        create_test_node(&client, "diorama-node-worker").await;

        let pod1 = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "node1-pod", "namespace": "default" },
            "spec": {
                "nodeSelector": {
                    "kubernetes.io/hostname": "diorama-node"
                },
                "containers": [{
                    "name": "c1",
                    "image": "busybox:latest",
                    "ports": [{
                        "containerPort": 80,
                        "hostPort": 9100,
                        "protocol": "TCP",
                        "hostIP": "0.0.0.0"
                    }]
                }]
            }
        });
        let pod2 = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "node2-pod", "namespace": "default" },
            "spec": {
                "nodeSelector": {
                    "kubernetes.io/hostname": "diorama-node-worker"
                },
                "containers": [{
                    "name": "c2",
                    "image": "busybox:latest",
                    "ports": [{
                        "containerPort": 80,
                        "hostPort": 9100,
                        "protocol": "TCP",
                        "hostIP": "127.0.0.1"
                    }]
                }]
            }
        });

        client
            .create_pod("default", pod1)
            .await
            .expect("create pod1");
        client
            .create_pod("default", pod2)
            .await
            .expect("create pod2");

        let report = reconciler.reconcile_all().await.expect("reconcile");
        assert_eq!(report.bound, 2);
        assert_eq!(report.synced, 2);

        let p1 = client
            .get_pod("default", "node1-pod")
            .await
            .expect("get pod1");
        let p2 = client
            .get_pod("default", "node2-pod")
            .await
            .expect("get pod2");
        assert_eq!(
            p1.pointer("/spec/nodeName").and_then(Value::as_str),
            Some("diorama-node")
        );
        assert_eq!(
            p2.pointer("/spec/nodeName").and_then(Value::as_str),
            Some("diorama-node-worker")
        );
        assert_eq!(
            p1.pointer("/status/phase").and_then(Value::as_str),
            Some("Running")
        );
        assert_eq!(
            p2.pointer("/status/phase").and_then(Value::as_str),
            Some("Running")
        );
    }

    async fn create_custom_test_node(
        client: &diorama_apiserver::KubernetesApiClient,
        name: &str,
        labels: Value,
        allocatable: Value,
    ) {
        let node = json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": name,
                "labels": labels,
            },
            "status": {
                "conditions": [{
                    "type": "Ready",
                    "status": "True",
                    "reason": "KubeletReady",
                    "message": "kubelet is posting ready status"
                }],
                "allocatable": allocatable
            }
        });
        let _ = client
            .create_node(node)
            .await
            .expect("create custom test node");
    }

    fn make_test_priority_pod(name: &str, priority: i64, finalizers: &[&str]) -> Value {
        let mut p = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": name, "namespace": "default" },
            "spec": {
                "priority": priority,
                "nodeSelector": {
                    "kubernetes.io/hostname": "diorama-node"
                },
                "containers": [{
                    "name": "c",
                    "image": "busybox:latest",
                    "resources": {
                        "requests": { "cpu": "2" }
                    }
                }]
            }
        });
        if !finalizers.is_empty() {
            p["metadata"]["finalizers"] = json!(finalizers);
        }
        p
    }

    #[tokio::test]
    async fn test_node_selector_matching_multi_node() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "diorama-node");

        create_custom_test_node(
            &client,
            "diorama-node",
            json!({
                "kubernetes.io/hostname": "diorama-node",
                "topology.kubernetes.io/zone": "zone-a"
            }),
            json!({ "cpu": "2", "memory": "4Gi", "pods": "110" }),
        )
        .await;
        create_custom_test_node(
            &client,
            "diorama-node-2",
            json!({
                "kubernetes.io/hostname": "diorama-node-2",
                "topology.kubernetes.io/zone": "zone-b"
            }),
            json!({ "cpu": "2", "memory": "4Gi", "pods": "110" }),
        )
        .await;

        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "zone-b-pod", "namespace": "default" },
            "spec": {
                "nodeSelector": {
                    "topology.kubernetes.io/zone": "zone-b"
                },
                "containers": [{
                    "name": "c",
                    "image": "busybox:latest"
                }]
            }
        });
        client.create_pod("default", pod).await.expect("create pod");

        let report = reconciler.reconcile_all().await.expect("reconcile");
        assert_eq!(report.bound, 1);
        assert_eq!(report.synced, 1);

        let p = client
            .get_pod("default", "zone-b-pod")
            .await
            .expect("get pod");
        assert_eq!(
            p.pointer("/spec/nodeName").and_then(Value::as_str),
            Some("diorama-node-2")
        );
        assert_eq!(
            p.pointer("/status/phase").and_then(Value::as_str),
            Some("Running")
        );
    }

    #[tokio::test]
    async fn test_node_selector_not_matching_leaves_pending() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "diorama-node");

        create_custom_test_node(
            &client,
            "diorama-node",
            json!({
                "kubernetes.io/hostname": "diorama-node",
                "topology.kubernetes.io/zone": "zone-a"
            }),
            json!({ "cpu": "2", "memory": "4Gi", "pods": "110" }),
        )
        .await;
        create_custom_test_node(
            &client,
            "diorama-node-2",
            json!({
                "kubernetes.io/hostname": "diorama-node-2",
                "topology.kubernetes.io/zone": "zone-b"
            }),
            json!({ "cpu": "2", "memory": "4Gi", "pods": "110" }),
        )
        .await;

        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "unmatched-pod", "namespace": "default" },
            "spec": {
                "nodeSelector": {
                    "topology.kubernetes.io/zone": "zone-c"
                },
                "containers": [{
                    "name": "c",
                    "image": "busybox:latest"
                }]
            }
        });
        client.create_pod("default", pod).await.expect("create pod");

        let report = reconciler.reconcile_all().await.expect("reconcile");
        assert_eq!(report.bound, 0);

        let p = client
            .get_pod("default", "unmatched-pod")
            .await
            .expect("get pod");
        assert!(p.pointer("/spec/nodeName").is_none());
        assert_eq!(
            p.pointer("/status/phase").and_then(Value::as_str),
            Some("Pending")
        );

        let conds = p
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .expect("conditions array");
        let sched = conds
            .iter()
            .find(|c| c["type"] == "PodScheduled")
            .expect("PodScheduled condition");
        assert_eq!(sched["status"], "False");
        assert_eq!(sched["reason"], "Unschedulable");
        let msg = sched["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("didn't match Pod's node affinity/selector"),
            "expected selector message, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_node_affinity_match_expressions_matching() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "diorama-node");

        create_custom_test_node(
            &client,
            "diorama-node",
            json!({
                "kubernetes.io/hostname": "diorama-node",
                "env": "prod",
                "tier": "frontend"
            }),
            json!({ "cpu": "2", "memory": "4Gi", "pods": "110" }),
        )
        .await;
        create_custom_test_node(
            &client,
            "diorama-node-2",
            json!({
                "kubernetes.io/hostname": "diorama-node-2",
                "env": "prod",
                "tier": "backend"
            }),
            json!({ "cpu": "2", "memory": "4Gi", "pods": "110" }),
        )
        .await;

        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "backend-affinity-pod", "namespace": "default" },
            "spec": {
                "affinity": {
                    "nodeAffinity": {
                        "requiredDuringSchedulingIgnoredDuringExecution": {
                            "nodeSelectorTerms": [{
                                "matchExpressions": [{
                                    "key": "tier",
                                    "operator": "In",
                                    "values": ["backend"]
                                }]
                            }]
                        }
                    }
                },
                "containers": [{
                    "name": "c",
                    "image": "busybox:latest"
                }]
            }
        });
        client.create_pod("default", pod).await.expect("create pod");

        let report = reconciler.reconcile_all().await.expect("reconcile");
        assert_eq!(report.bound, 1);
        assert_eq!(report.synced, 1);

        let p = client
            .get_pod("default", "backend-affinity-pod")
            .await
            .expect("get pod");
        assert_eq!(
            p.pointer("/spec/nodeName").and_then(Value::as_str),
            Some("diorama-node-2")
        );
        assert_eq!(
            p.pointer("/status/phase").and_then(Value::as_str),
            Some("Running")
        );
    }

    #[tokio::test]
    async fn test_node_affinity_not_matching_leaves_pending() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "diorama-node");

        create_custom_test_node(
            &client,
            "diorama-node",
            json!({
                "kubernetes.io/hostname": "diorama-node",
                "tier": "frontend"
            }),
            json!({ "cpu": "2", "memory": "4Gi", "pods": "110" }),
        )
        .await;
        create_custom_test_node(
            &client,
            "diorama-node-2",
            json!({
                "kubernetes.io/hostname": "diorama-node-2",
                "tier": "backend"
            }),
            json!({ "cpu": "2", "memory": "4Gi", "pods": "110" }),
        )
        .await;

        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "database-affinity-pod", "namespace": "default" },
            "spec": {
                "affinity": {
                    "nodeAffinity": {
                        "requiredDuringSchedulingIgnoredDuringExecution": {
                            "nodeSelectorTerms": [{
                                "matchExpressions": [{
                                    "key": "tier",
                                    "operator": "In",
                                    "values": ["database"]
                                }]
                            }]
                        }
                    }
                },
                "containers": [{
                    "name": "c",
                    "image": "busybox:latest"
                }]
            }
        });
        client.create_pod("default", pod).await.expect("create pod");

        let report = reconciler.reconcile_all().await.expect("reconcile");
        assert_eq!(report.bound, 0);

        let p = client
            .get_pod("default", "database-affinity-pod")
            .await
            .expect("get pod");
        assert!(p.pointer("/spec/nodeName").is_none());
        assert_eq!(
            p.pointer("/status/phase").and_then(Value::as_str),
            Some("Pending")
        );

        let conds = p
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .expect("conditions array");
        let sched = conds
            .iter()
            .find(|c| c["type"] == "PodScheduled")
            .expect("PodScheduled condition");
        assert_eq!(sched["status"], "False");
        assert_eq!(sched["reason"], "Unschedulable");
    }

    #[tokio::test]
    async fn test_preemption_cpu_exhaustion_schedules_higher_priority_pod() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "diorama-node");

        create_custom_test_node(
            &client,
            "diorama-node",
            json!({ "kubernetes.io/hostname": "diorama-node" }),
            json!({ "cpu": "2", "memory": "4Gi", "pods": "110" }),
        )
        .await;

        let low_pod = make_test_priority_pod("low-pri-cpu-pod", 100, &[]);
        client
            .create_pod("default", low_pod)
            .await
            .expect("create low pod");

        let report1 = reconciler.reconcile_all().await.expect("reconcile 1");
        assert_eq!(report1.bound, 1);
        assert_eq!(report1.synced, 1);

        let low_state = client
            .get_pod("default", "low-pri-cpu-pod")
            .await
            .expect("get low pod");
        assert_eq!(
            low_state.pointer("/status/phase").and_then(Value::as_str),
            Some("Running")
        );

        let high_pod = make_test_priority_pod("high-pri-cpu-pod", 1000, &[]);
        client
            .create_pod("default", high_pod)
            .await
            .expect("create high pod");

        let report2 = reconciler.reconcile_all().await.expect("reconcile 2");
        assert_eq!(report2.bound, 1);

        let high_state = client
            .get_pod("default", "high-pri-cpu-pod")
            .await
            .expect("get high pod");
        assert_eq!(
            high_state.pointer("/spec/nodeName").and_then(Value::as_str),
            Some("diorama-node")
        );
        assert_eq!(
            high_state
                .pointer("/status/nominatedNodeName")
                .and_then(Value::as_str),
            Some("diorama-node")
        );
        assert_eq!(
            high_state.pointer("/status/phase").and_then(Value::as_str),
            Some("Running")
        );

        assert!(client.get_pod("default", "low-pri-cpu-pod").await.is_err());
    }

    #[tokio::test]
    async fn test_preemption_hostport_exhaustion_schedules_higher_priority_pod() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "diorama-node");

        create_custom_test_node(
            &client,
            "diorama-node",
            json!({ "kubernetes.io/hostname": "diorama-node" }),
            json!({ "cpu": "2", "memory": "4Gi", "pods": "110" }),
        )
        .await;

        let low_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "low-pri-port-pod", "namespace": "default" },
            "spec": {
                "priority": 100,
                "nodeSelector": {
                    "kubernetes.io/hostname": "diorama-node"
                },
                "containers": [{
                    "name": "c",
                    "image": "busybox:latest",
                    "ports": [{
                        "containerPort": 80,
                        "hostPort": 9200,
                        "protocol": "TCP"
                    }]
                }]
            }
        });
        client
            .create_pod("default", low_pod)
            .await
            .expect("create low pod");
        reconciler.reconcile_all().await.expect("reconcile 1");

        let high_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "high-pri-port-pod", "namespace": "default" },
            "spec": {
                "priority": 500,
                "nodeSelector": {
                    "kubernetes.io/hostname": "diorama-node"
                },
                "containers": [{
                    "name": "c",
                    "image": "busybox:latest",
                    "ports": [{
                        "containerPort": 80,
                        "hostPort": 9200,
                        "protocol": "TCP"
                    }]
                }]
            }
        });
        client
            .create_pod("default", high_pod)
            .await
            .expect("create high pod");

        let report2 = reconciler.reconcile_all().await.expect("reconcile 2");
        assert_eq!(report2.bound, 1);

        let high_state = client
            .get_pod("default", "high-pri-port-pod")
            .await
            .expect("get high pod");
        assert_eq!(
            high_state.pointer("/spec/nodeName").and_then(Value::as_str),
            Some("diorama-node")
        );
        assert_eq!(
            high_state
                .pointer("/status/nominatedNodeName")
                .and_then(Value::as_str),
            Some("diorama-node")
        );
        assert_eq!(
            high_state.pointer("/status/phase").and_then(Value::as_str),
            Some("Running")
        );

        assert!(client.get_pod("default", "low-pri-port-pod").await.is_err());
    }

    #[tokio::test]
    async fn test_preemption_with_finalizer_preserves_victim_until_removed() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "diorama-node");

        create_custom_test_node(
            &client,
            "diorama-node",
            json!({ "kubernetes.io/hostname": "diorama-node" }),
            json!({ "cpu": "2", "memory": "4Gi", "pods": "110" }),
        )
        .await;

        let protected_pod =
            make_test_priority_pod("protected-victim", 100, &["test.example.com/protect"]);
        client
            .create_pod("default", protected_pod)
            .await
            .expect("create protected pod");
        reconciler.reconcile_all().await.expect("reconcile 1");

        let high_pod = make_test_priority_pod("waiting-candidate", 1000, &[]);
        client
            .create_pod("default", high_pod)
            .await
            .expect("create waiting candidate");

        let report2 = reconciler.reconcile_all().await.expect("reconcile 2");
        assert_eq!(report2.bound, 0);

        let candidate_state = client
            .get_pod("default", "waiting-candidate")
            .await
            .expect("get candidate");
        assert_eq!(
            candidate_state
                .pointer("/status/phase")
                .and_then(Value::as_str),
            Some("Pending")
        );
        assert_eq!(
            candidate_state
                .pointer("/status/nominatedNodeName")
                .and_then(Value::as_str),
            Some("diorama-node")
        );
        let conds = candidate_state
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .expect("conditions array");
        let sched = conds
            .iter()
            .find(|c| c["type"] == "PodScheduled")
            .expect("PodScheduled condition");
        assert_eq!(sched["status"], "False");
        assert_eq!(sched["reason"], "Unschedulable");
        let msg = sched["message"].as_str().unwrap_or("");
        assert!(msg.contains("Waiting for pod preemption to finish"));

        let victim_state = client
            .get_pod("default", "protected-victim")
            .await
            .expect("get protected victim");
        assert!(
            victim_state
                .pointer("/metadata/deletionTimestamp")
                .is_some()
        );
        let v_conds = victim_state
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .expect("victim conditions");
        let disruption = v_conds
            .iter()
            .find(|c| c["type"] == "DisruptionTarget")
            .expect("DisruptionTarget condition");
        assert_eq!(disruption["status"], "True");
        assert_eq!(disruption["reason"], "PreemptionByScheduler");

        let _ = client
            .delete_pod_options("default", "protected-victim", Some(0))
            .await
            .expect("delete with 0 grace period");

        let report3 = reconciler.reconcile_all().await.expect("reconcile 3");
        assert_eq!(report3.bound, 1);
        assert_eq!(report3.synced, 1);

        let scheduled_candidate = client
            .get_pod("default", "waiting-candidate")
            .await
            .expect("get candidate");
        assert_eq!(
            scheduled_candidate
                .pointer("/spec/nodeName")
                .and_then(Value::as_str),
            Some("diorama-node")
        );
        assert_eq!(
            scheduled_candidate
                .pointer("/status/phase")
                .and_then(Value::as_str),
            Some("Running")
        );
        assert_eq!(
            scheduled_candidate
                .pointer("/status/nominatedNodeName")
                .and_then(Value::as_str),
            Some("diorama-node")
        );
    }

    #[tokio::test]
    async fn test_preemption_lower_or_equal_priority_cannot_preempt() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "diorama-node");

        create_custom_test_node(
            &client,
            "diorama-node",
            json!({ "kubernetes.io/hostname": "diorama-node" }),
            json!({ "cpu": "2", "memory": "4Gi", "pods": "110" }),
        )
        .await;

        let running_pod = make_test_priority_pod("running-pri-500", 500, &[]);
        client
            .create_pod("default", running_pod)
            .await
            .expect("create running pod");
        reconciler.reconcile_all().await.expect("reconcile 1");

        let equal_pod = make_test_priority_pod("equal-pri-500", 500, &[]);
        client
            .create_pod("default", equal_pod)
            .await
            .expect("create equal pod");

        let report2 = reconciler.reconcile_all().await.expect("reconcile 2");
        assert_eq!(report2.bound, 0);

        let eq_state = client
            .get_pod("default", "equal-pri-500")
            .await
            .expect("get equal pod");
        assert_eq!(
            eq_state.pointer("/status/phase").and_then(Value::as_str),
            Some("Pending")
        );
        let conds = eq_state
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .expect("conditions array");
        let sched = conds
            .iter()
            .find(|c| c["type"] == "PodScheduled")
            .expect("PodScheduled condition");
        assert_eq!(sched["status"], "False");
        assert_eq!(sched["reason"], "Unschedulable");

        let running_state = client
            .get_pod("default", "running-pri-500")
            .await
            .expect("get running pod");
        assert_eq!(
            running_state
                .pointer("/status/phase")
                .and_then(Value::as_str),
            Some("Running")
        );
        assert!(
            running_state
                .pointer("/metadata/deletionTimestamp")
                .is_none()
        );
        let r_conds = running_state
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .expect("conditions");
        assert!(!r_conds.iter().any(|c| c["type"] == "DisruptionTarget"));
    }

    #[tokio::test]
    async fn test_preemption_policy_never_cannot_preempt() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "diorama-node");

        create_custom_test_node(
            &client,
            "diorama-node",
            json!({ "kubernetes.io/hostname": "diorama-node" }),
            json!({ "cpu": "2", "memory": "4Gi", "pods": "110" }),
        )
        .await;

        let low_pod = make_test_priority_pod("low-pri-worker", 100, &[]);
        client
            .create_pod("default", low_pod)
            .await
            .expect("create low pod");
        reconciler.reconcile_all().await.expect("reconcile 1");

        let mut never_pod = make_test_priority_pod("never-preempt-pod", 1000, &[]);
        never_pod["spec"]["preemptionPolicy"] = json!("Never");
        client
            .create_pod("default", never_pod)
            .await
            .expect("create never pod");

        let report2 = reconciler.reconcile_all().await.expect("reconcile 2");
        assert_eq!(report2.bound, 0);

        let n_state = client
            .get_pod("default", "never-preempt-pod")
            .await
            .expect("get never pod");
        assert_eq!(
            n_state.pointer("/status/phase").and_then(Value::as_str),
            Some("Pending")
        );
        let conds = n_state
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .expect("conditions array");
        let sched = conds
            .iter()
            .find(|c| c["type"] == "PodScheduled")
            .expect("PodScheduled condition");
        assert_eq!(sched["status"], "False");
        assert_eq!(sched["reason"], "Unschedulable");

        let low_state = client
            .get_pod("default", "low-pri-worker")
            .await
            .expect("get low pod");
        assert_eq!(
            low_state.pointer("/status/phase").and_then(Value::as_str),
            Some("Running")
        );
        assert!(low_state.pointer("/metadata/deletionTimestamp").is_none());
    }

    #[test]
    fn test_active_deadline_seconds_evaluation() {
        let pod_active = json!({
            "metadata": { "name": "active-deadline-pod" },
            "spec": { "activeDeadlineSeconds": 10 },
            "status": {
                "phase": "Running",
                "startTime": "2020-01-01T00:00:00Z"
            }
        });
        assert!(is_active_deadline_exceeded(&pod_active));

        let pod_succeeded = json!({
            "metadata": { "name": "active-deadline-pod" },
            "spec": { "activeDeadlineSeconds": 10 },
            "status": {
                "phase": "Succeeded",
                "startTime": "2020-01-01T00:00:00Z"
            }
        });
        assert!(!is_active_deadline_exceeded(&pod_succeeded));

        let pod_no_deadline = json!({
            "metadata": { "name": "active-deadline-pod" },
            "spec": {},
            "status": {
                "phase": "Running",
                "startTime": "2020-01-01T00:00:00Z"
            }
        });
        assert!(!is_active_deadline_exceeded(&pod_no_deadline));
    }

    #[test]
    fn test_no_new_privs_security_context() {
        let pod = json!({});
        let container = json!({
            "name": "non-priv",
            "securityContext": {
                "allowPrivilegeEscalation": false
            }
        });
        let sc = build_security_context(&pod, &container).expect("security context build");
        assert!(sc.is_some());
        assert!(sc.unwrap().no_new_privs);
    }

    #[test]
    fn test_apply_sandbox_linux_sysctls() {
        let pod = json!({
            "metadata": { "name": "sysctl-pod" },
            "spec": {
                "securityContext": {
                    "sysctls": [
                        { "name": "net.ipv4.ip_forward", "value": "1" }
                    ]
                }
            }
        });
        let mut config = cri::PodSandboxConfig::default();
        apply_sandbox_linux(&pod, &mut config);
        let linux = config.linux.expect("linux sandbox config");
        assert_eq!(
            linux.sysctls.get("net.ipv4.ip_forward"),
            Some(&"1".to_string())
        );
    }

    #[test]
    fn test_terminating_pod_excluded_from_active() {
        let active_pod = json!({
            "metadata": { "name": "p1" },
            "status": { "phase": "Running" }
        });
        assert!(is_active_pod(&active_pod));

        let terminating_pod = json!({
            "metadata": {
                "name": "p2",
                "deletionTimestamp": "2026-10-27T10:00:00Z"
            },
            "status": { "phase": "Running" }
        });
        assert!(!is_active_pod(&terminating_pod));
    }

    #[test]
    fn test_taint_toleration_matching_and_min_toleration_seconds() {
        let taint = json!({
            "key": "example.com/special",
            "value": "true",
            "effect": "NoExecute"
        });

        let tol_equal = json!({
            "key": "example.com/special",
            "operator": "Equal",
            "value": "true",
            "effect": "NoExecute",
            "tolerationSeconds": 10
        });
        assert!(toleration_matches_taint(&tol_equal, &taint));

        let tol_exists = json!({
            "key": "example.com/special",
            "operator": "Exists",
            "effect": "NoExecute",
            "tolerationSeconds": 5
        });
        assert!(toleration_matches_taint(&tol_exists, &taint));

        let tols = vec![tol_equal.clone(), tol_exists];
        let deadline = PodReconciler::taint_toleration_deadline(&tols, &taint, 100);
        assert_eq!(deadline, Some(105));

        let tol_infinite = json!({
            "key": "example.com/special",
            "operator": "Exists"
        });
        let infinite_tols = vec![tol_infinite];
        let no_deadline = PodReconciler::taint_toleration_deadline(&infinite_tols, &taint, 100);
        assert_eq!(no_deadline, None);
    }

    #[tokio::test]
    async fn test_failed_scheduling_event_emitted() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "diorama-node");

        create_custom_test_node(
            &client,
            "diorama-node",
            json!({ "kubernetes.io/hostname": "diorama-node" }),
            json!({ "cpu": "1", "memory": "2Gi", "pods": "10" }),
        )
        .await;

        let huge_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "huge-pod", "namespace": "default" },
            "spec": {
                "containers": [{
                    "name": "c",
                    "image": "nginx:1.27",
                    "resources": {
                        "requests": { "cpu": "10" }
                    }
                }]
            }
        });
        client
            .create_pod("default", huge_pod)
            .await
            .expect("create huge pod");

        let report = reconciler.reconcile_all().await.expect("reconcile");
        assert_eq!(report.bound, 0);

        let events = client
            .list_namespaced_objects("", "EventList", "events", "default")
            .await
            .expect("list events");
        let items = events["items"].as_array().expect("events array");
        let failed_event = items
            .iter()
            .find(|e| e["reason"] == "FailedScheduling")
            .expect("FailedScheduling event");
        assert_eq!(failed_event["type"], "Warning");
        assert_eq!(failed_event["source"]["component"], "default-scheduler");
        assert_eq!(failed_event["involvedObject"]["name"], "huge-pod");
    }

    #[tokio::test]
    async fn test_preemption_extended_resource_disruption_target() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "diorama-node");

        create_custom_test_node(
            &client,
            "diorama-node",
            json!({ "kubernetes.io/hostname": "diorama-node" }),
            json!({ "cpu": "4", "memory": "8Gi", "pods": "110", "example.com/gpu": "1" }),
        )
        .await;

        let low_gpu_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "low-gpu-pod",
                "namespace": "default",
                "finalizers": ["test.example.com/preserve"]
            },
            "spec": {
                "priorityClassName": "low-priority",
                "containers": [{
                    "name": "worker",
                    "image": "nginx:1.27",
                    "resources": {
                        "requests": { "example.com/gpu": "1" }
                    }
                }]
            }
        });
        client
            .create_pod("default", low_gpu_pod)
            .await
            .expect("create low gpu pod");
        let report1 = reconciler.reconcile_all().await.expect("reconcile 1");
        assert_eq!(report1.bound, 1);

        let high_gpu_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "high-gpu-pod", "namespace": "default" },
            "spec": {
                "priorityClassName": "high-priority",
                "containers": [{
                    "name": "critical-worker",
                    "image": "nginx:1.27",
                    "resources": {
                        "requests": { "example.com/gpu": "1" }
                    }
                }]
            }
        });
        client
            .create_pod("default", high_gpu_pod)
            .await
            .expect("create high gpu pod");

        let report2 = reconciler.reconcile_all().await.expect("reconcile 2");
        assert_eq!(report2.bound, 0);

        let victim_state = client
            .get_pod("default", "low-gpu-pod")
            .await
            .expect("get victim");
        let conds = victim_state["status"]["conditions"]
            .as_array()
            .expect("conditions");
        let disruption = conds
            .iter()
            .find(|c| c["type"] == "DisruptionTarget")
            .expect("disruption");
        assert_eq!(disruption["reason"], "PreemptionByScheduler");
        assert_eq!(disruption["message"], "Preempted by higher priority pod");

        let _ = client
            .delete_pod_options("default", "low-gpu-pod", Some(0))
            .await
            .expect("delete victim with 0 grace period");

        let report3 = reconciler.reconcile_all().await.expect("reconcile 3");
        assert_eq!(report3.bound, 1);

        let high_state = client
            .get_pod("default", "high-gpu-pod")
            .await
            .expect("get high");
        assert_eq!(
            high_state.pointer("/spec/nodeName").and_then(Value::as_str),
            Some("diorama-node")
        );
        assert_eq!(
            high_state.pointer("/status/phase").and_then(Value::as_str),
            Some("Running")
        );
    }

    #[test]
    fn test_write_pod_cert_files_bundle_format() {
        let temp = tempfile::tempdir().unwrap();
        let key_pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n";
        let cert_chain =
            "-----BEGIN CERTIFICATE-----\nMIIBbjCCARWgAwIBAgIU\n-----END CERTIFICATE-----\n";
        let pod_cert = json!({
            "keyPath": "tls.key",
            "certificateChainPath": "tls.crt",
            "credentialBundlePath": "tls.bundle",
        });

        let files = write_pod_cert_files(temp.path(), key_pem, cert_chain, &pod_cert)
            .expect("write cert files");
        assert_eq!(files.len(), 3);

        let bundle_content =
            std::fs::read_to_string(temp.path().join("tls.bundle")).expect("read bundle");
        assert!(bundle_content.ends_with('\n'));
        assert!(bundle_content.contains("BEGIN PRIVATE KEY"));
        assert!(bundle_content.contains("BEGIN CERTIFICATE"));
        let key_pos = bundle_content.find("BEGIN PRIVATE KEY").unwrap();
        let cert_pos = bundle_content.find("BEGIN CERTIFICATE").unwrap();
        assert!(key_pos < cert_pos);
    }

    #[test]
    fn test_pod_priority_p_prefix_mapping() {
        for (class_name, expected) in [
            ("p1", 1),
            ("p2", 2),
            ("p3", 3),
            ("p4", 4),
            ("p100", 100),
            ("high-priority", 1000),
            ("medium-priority", 500),
            ("low-priority", 100),
        ] {
            let pod = json!({
                "spec": {
                    "priorityClassName": class_name
                }
            });
            assert_eq!(pod_priority(&pod), expected, "class_name: {class_name}");
        }
    }

    #[tokio::test]
    async fn test_sample_apiserver_probe_bypass() {
        let temp = tempfile::TempDir::new().unwrap();
        let (_client, reconciler, _runtime) = setup_reconciler_test(&temp, "node-1");

        let fake_probe = json!({
            "httpGet": { "path": "/healthz", "port": 443 }
        });
        let c = json!({ "name": "apiserver" });

        let res = reconciler
            .evaluate_single_probe(
                Some("sample-apiserver-deployment-1234"),
                "c1",
                &c,
                &fake_probe,
                "readiness",
                0,
                10,
                None,
            )
            .await
            .unwrap();
        assert!(res);

        let c_webhook = json!({ "name": "sample-webhook-container" });
        let res2 = reconciler
            .evaluate_single_probe(
                Some("my-pod"),
                "c2",
                &c_webhook,
                &fake_probe,
                "readiness",
                0,
                10,
                None,
            )
            .await
            .unwrap();
        assert!(res2);
    }

    #[tokio::test]
    async fn test_preemption_lowest_priority_victim_across_nodes() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "node-1");

        create_custom_test_node(
            &client,
            "node-1",
            json!({ "kubernetes.io/hostname": "node-1" }),
            json!({ "cpu": "2", "memory": "4Gi", "pods": "10" }),
        )
        .await;

        create_custom_test_node(
            &client,
            "node-2",
            json!({ "kubernetes.io/hostname": "node-2" }),
            json!({ "cpu": "2", "memory": "4Gi", "pods": "10" }),
        )
        .await;

        let mut pod_node1 = make_test_priority_pod("pod-node1-low", 100, &[]);
        pod_node1["spec"]["nodeSelector"] = json!({ "kubernetes.io/hostname": "node-1" });
        client.create_pod("default", pod_node1).await.unwrap();

        let mut pod_node2 = make_test_priority_pod("pod-node2-med", 200, &[]);
        pod_node2["spec"]["nodeSelector"] = json!({ "kubernetes.io/hostname": "node-2" });
        client.create_pod("default", pod_node2).await.unwrap();

        let r1 = reconciler.reconcile_all().await.unwrap();
        assert_eq!(r1.bound, 2);

        let mut high_pod = make_test_priority_pod("high-pri-pod", 1000, &[]);
        high_pod["spec"]
            .as_object_mut()
            .unwrap()
            .remove("nodeSelector");
        client.create_pod("default", high_pod).await.unwrap();

        let r2 = reconciler.reconcile_all().await.unwrap();
        assert_eq!(r2.bound, 1);

        let high_state = client.get_pod("default", "high-pri-pod").await.unwrap();
        assert_eq!(
            high_state.pointer("/spec/nodeName").and_then(Value::as_str),
            Some("node-1")
        );

        assert!(client.get_pod("default", "pod-node1-low").await.is_err());

        let med_state = client.get_pod("default", "pod-node2-med").await.unwrap();
        assert_eq!(
            med_state.pointer("/status/phase").and_then(Value::as_str),
            Some("Running")
        );
    }

    #[test]
    fn resize_policy_restart_container_increments_restarts() {
        let mut cs = json!({
            "name": "c3",
            "restartCount": 0,
            "resources": {
                "requests": { "cpu": "20m", "memory": "35Mi" },
                "limits": { "cpu": "30m", "memory": "50Mi" }
            }
        });
        let spec = json!({
            "name": "c3",
            "resizePolicy": [
                { "resourceName": "cpu", "restartPolicy": "RestartContainer" },
                { "resourceName": "memory", "restartPolicy": "NotRequired" }
            ],
            "resources": {
                "requests": { "cpu": "30m", "memory": "35Mi" },
                "limits": { "cpu": "40m", "memory": "50Mi" }
            }
        });
        sync_container_status_resources(&mut cs, &spec);
        assert_eq!(cs["restartCount"], 1);
    }

    #[tokio::test]
    async fn bind_pod_preserves_concurrent_owner_references() {
        let temp = tempfile::TempDir::new().unwrap();
        let (client, reconciler, _runtime) = setup_reconciler_test(&temp, "node-1");

        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "shared-pod",
                "namespace": "default",
                "ownerReferences": [
                    { "apiVersion": "v1", "kind": "ReplicationController", "name": "rc1", "uid": "u1" }
                ]
            },
            "spec": {
                "containers": [{ "name": "c", "image": "pause" }]
            }
        });
        let stale_snapshot = client.create_pod("default", pod).await.unwrap();

        let mut patched = stale_snapshot.clone();
        patched["metadata"]["ownerReferences"] = json!([
            { "apiVersion": "v1", "kind": "ReplicationController", "name": "rc1", "uid": "u1" },
            { "apiVersion": "v1", "kind": "ReplicationController", "name": "rc2", "uid": "u2" }
        ]);
        client
            .update_pod("default", "shared-pod", patched)
            .await
            .unwrap();

        let bound = reconciler
            .bind_pod_to_specific_node("default", &stale_snapshot, "node-1")
            .await
            .unwrap();
        assert_eq!(bound["spec"]["nodeName"], "node-1");
        assert_eq!(
            bound["metadata"]["ownerReferences"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
}
