//! Pod status built from CRI container and sandbox state.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use diorama_apiserver::time::{now_rfc3339, rfc3339_seconds};

use crate::workload::{
    PodQoSClass, RestartPolicy, cri, determine_pod_qos, is_restartable_init, secs_from_nanos,
};

/// CPU-manager placement reported on a container status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuAssignment {
    pub cpuset: String,
    pub exclusive: bool,
}

/// Status of an in-place pod vertical scaling / resize operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PodResizeStatus {
    Proposed,
    InProgress,
    Deferred,
    Infeasible,
}

impl PodResizeStatus {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "Proposed",
            Self::InProgress => "InProgress",
            Self::Deferred => "Deferred",
            Self::Infeasible => "Infeasible",
        }
    }
}

impl std::fmt::Display for PodResizeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Everything the status builder needs about one spec container.
#[derive(Debug, Clone)]
pub struct ContainerView<'a> {
    pub spec: &'a Value,
    pub latest: Option<&'a cri::ContainerStatus>,
    pub previous: Option<&'a cri::ContainerStatus>,
    /// Readiness as decided by probes this tick.
    pub ready: bool,
    /// `CrashLoopBackOff` message while a restart waits.
    pub backoff: Option<String>,
    /// Image or create failure to report instead of a runtime state.
    pub waiting: Option<(&'static str, String)>,
    pub cpu: Option<CpuAssignment>,
}

fn state_of(status: &cri::ContainerStatus) -> cri::ContainerState {
    cri::ContainerState::try_from(status.state).unwrap_or(cri::ContainerState::ContainerUnknown)
}

fn nanos_to_rfc3339(nanos: i64) -> Value {
    secs_from_nanos(nanos).map_or(Value::Null, |secs| json!(rfc3339_seconds(secs)))
}

/// Spec and attempt views for regular and init containers of a pod.
#[derive(Clone, Copy, Debug, Default)]
pub struct PodViews<'a> {
    pub containers: &'a [ContainerView<'a>],
    pub init_containers: &'a [ContainerView<'a>],
}

fn derive_init_state<'a>(
    init_views: &'a [ContainerView<'a>],
    policy: RestartPolicy,
) -> (bool, bool, Vec<&'a str>) {
    let init_complete = init_views.is_empty()
        || init_views.iter().all(|v| {
            if is_restartable_init(v.spec) {
                v.latest.is_some_and(|s| {
                    state_of(s) == cri::ContainerState::ContainerRunning
                        || (state_of(s) == cri::ContainerState::ContainerExited && s.exit_code == 0)
                })
            } else {
                v.latest.is_some_and(|s| {
                    state_of(s) == cri::ContainerState::ContainerExited && s.exit_code == 0
                })
            }
        });

    let init_failed = init_views.iter().any(|v| {
        if is_restartable_init(v.spec) {
            false
        } else {
            v.latest.is_some_and(|s| {
                state_of(s) == cri::ContainerState::ContainerExited
                    && s.exit_code != 0
                    && !policy.restarts(s.exit_code)
            })
        }
    });

    let unready_init: Vec<&'a str> = init_views
        .iter()
        .filter(|v| {
            if is_restartable_init(v.spec) {
                !v.latest.is_some_and(|s| {
                    state_of(s) == cri::ContainerState::ContainerRunning
                        || (state_of(s) == cri::ContainerState::ContainerExited && s.exit_code == 0)
                })
            } else {
                !v.latest.is_some_and(|s| {
                    state_of(s) == cri::ContainerState::ContainerExited && s.exit_code == 0
                })
            }
        })
        .filter_map(|v| v.spec.get("name").and_then(Value::as_str))
        .collect();

    (init_complete, init_failed, unready_init)
}

fn collect_unready_containers<'a>(
    regular_statuses: &'a [Value],
    init_views: &'a [ContainerView<'_>],
    init_statuses: &'a [Value],
) -> Vec<&'a str> {
    let mut unready: Vec<&'a str> = regular_statuses
        .iter()
        .filter(|s| s["ready"].as_bool() != Some(true))
        .filter_map(|s| s["name"].as_str())
        .collect();
    for (view, s) in init_views.iter().zip(init_statuses.iter()) {
        if is_restartable_init(view.spec)
            && s["ready"].as_bool() != Some(true)
            && let Some(n) = s["name"].as_str()
        {
            unready.push(n);
        }
    }
    unready
}

/// Builds a Pod status from the latest container attempts.
#[must_use]
pub fn pod_status(
    pod: &Value,
    provider: &str,
    node_ip: &str,
    pod_ip: Option<&str>,
    sandbox_ready: bool,
    policy: RestartPolicy,
    views: PodViews<'_>,
) -> Value {
    let init_views = views.init_containers;
    let regular_views = views.containers;
    let (init_complete, init_failed, unready_init) = derive_init_state(init_views, policy);

    let init_container_statuses: Vec<Value> = init_views
        .iter()
        .map(|view| container_status_json(provider, view, false))
        .collect();

    let container_statuses: Vec<Value> = regular_views
        .iter()
        .map(|view| container_status_json(provider, view, !init_complete))
        .collect();

    let attempts: Vec<Option<&cri::ContainerStatus>> =
        regular_views.iter().map(|v| v.latest).collect();
    let restarting = regular_views.iter().any(|v| v.backoff.is_some())
        || init_views.iter().any(|v| v.backoff.is_some());

    let phase = if init_complete {
        observed_phase(&attempts, policy, restarting)
    } else if init_failed {
        "Failed"
    } else {
        "Pending"
    };

    let unready =
        collect_unready_containers(&container_statuses, init_views, &init_container_statuses);

    let conditions = observed_conditions(
        pod,
        phase,
        &unready,
        sandbox_ready,
        init_complete,
        &unready_init,
    );

    let start_time = pod
        .pointer("/status/startTime")
        .cloned()
        .unwrap_or_else(|| json!(now_rfc3339()));
    let qos = match determine_pod_qos(pod) {
        PodQoSClass::Guaranteed => "Guaranteed",
        PodQoSClass::Burstable => "Burstable",
        PodQoSClass::BestEffort => "BestEffort",
    };
    let pod_ip = pod_ip.filter(|ip| !ip.is_empty()).unwrap_or(node_ip);
    let pod_ips =
        if let Some(existing_ips) = pod.pointer("/status/podIPs").and_then(Value::as_array) {
            if !existing_ips.is_empty()
                && existing_ips[0].get("ip").and_then(Value::as_str) == Some(pod_ip)
            {
                existing_ips.clone()
            } else {
                vec![json!({ "ip": pod_ip })]
            }
        } else {
            vec![json!({ "ip": pod_ip })]
        };
    let generation = pod
        .pointer("/metadata/generation")
        .and_then(Value::as_i64)
        .unwrap_or(1);
    let mut status = json!({
        "phase": phase,
        "qosClass": qos,
        "hostIP": node_ip,
        "hostIPs": [{ "ip": node_ip }],
        "podIP": pod_ip,
        "podIPs": pod_ips,
        "startTime": start_time,
        "conditions": conditions,
        "containerStatuses": container_statuses,
        "observedGeneration": generation,
    });
    if let Some(resize_status) = determine_resize_status(pod, &container_statuses) {
        status["resize"] = json!(resize_status.as_str());
    }
    let has_spec_inits = pod
        .pointer("/spec/initContainers")
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty());
    if has_spec_inits || !init_container_statuses.is_empty() {
        status["initContainerStatuses"] = json!(init_container_statuses);
    }
    status
}

/// Maps the latest container attempts onto a Pod phase under `policy`.
///
/// Exited containers that the policy will restart keep the pod `Running`, as
/// does an explicit `restarting` flag for containers in back-off.
#[must_use]
pub fn observed_phase(
    attempts: &[Option<&cri::ContainerStatus>],
    policy: RestartPolicy,
    restarting: bool,
) -> &'static str {
    if attempts.is_empty() {
        return "Pending";
    }
    let states: Vec<(cri::ContainerState, i32)> = attempts
        .iter()
        .flatten()
        .map(|s| (state_of(s), s.exit_code))
        .collect();
    if restarting
        || states
            .iter()
            .any(|(state, _)| *state == cri::ContainerState::ContainerRunning)
    {
        return "Running";
    }
    let all_exited = states.len() == attempts.len()
        && states
            .iter()
            .all(|(state, _)| *state == cri::ContainerState::ContainerExited);
    if !all_exited {
        return "Pending";
    }
    if states.iter().any(|(_, code)| policy.restarts(*code)) {
        "Running"
    } else if states.iter().all(|(_, code)| *code == 0) {
        "Succeeded"
    } else {
        "Failed"
    }
}

fn terminated_state(provider: &str, status: &cri::ContainerStatus) -> Value {
    json!({
        "terminated": {
            "exitCode": status.exit_code,
            "reason": if status.exit_code == 0 { "Completed" } else { "Error" },
            "startedAt": nanos_to_rfc3339(status.started_at),
            "finishedAt": nanos_to_rfc3339(status.finished_at),
            "containerID": format!("{provider}://{}", status.id)
        }
    })
}

fn effective_container_resources(spec: &Value) -> (Value, Option<Value>) {
    let Some(res_obj) = spec.get("resources").and_then(Value::as_object) else {
        return (json!({}), None);
    };
    let limits = res_obj.get("limits").and_then(Value::as_object).cloned();
    let mut requests = res_obj
        .get("requests")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(lim) = &limits {
        for (k, v) in lim {
            requests.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    let mut out = serde_json::Map::new();
    if let Some(lim) = limits
        && !lim.is_empty()
    {
        out.insert("limits".to_string(), Value::Object(lim));
    }
    let alloc = if requests.is_empty() {
        None
    } else {
        out.insert("requests".to_string(), Value::Object(requests.clone()));
        Some(Value::Object(requests))
    };
    (Value::Object(out), alloc)
}

fn container_status_json(
    provider: &str,
    view: &ContainerView<'_>,
    pod_initializing: bool,
) -> Value {
    let name = view
        .spec
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("main");
    let image = view
        .spec
        .get("image")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let (res, alloc) = effective_container_resources(view.spec);
    let mut status = json!({
        "name": name,
        "image": image,
        "imageID": view.latest.map_or("", |s| s.image_ref.as_str()),
        "ready": false,
        "started": false,
        "restartCount": view.latest.and_then(|s| s.metadata.as_ref()).map_or(0, |m| m.attempt),
        "resources": res,
    });
    if let Some(alloc_res) = alloc {
        status["allocatedResources"] = alloc_res;
    }
    if let Some(latest) = view.latest {
        status["containerID"] = json!(format!("{provider}://{}", latest.id));
    }
    if let Some((reason, message)) = &view.waiting {
        status["state"] = json!({ "waiting": { "reason": reason, "message": message } });
    } else if let (Some(message), Some(latest)) = (&view.backoff, view.latest) {
        status["state"] = json!({
            "waiting": { "reason": "CrashLoopBackOff", "message": message }
        });
        status["lastState"] = terminated_state(provider, latest);
    } else if let Some(latest) = view.latest {
        status["state"] = match state_of(latest) {
            cri::ContainerState::ContainerCreated => {
                json!({ "waiting": { "reason": "ContainerCreating" } })
            },
            cri::ContainerState::ContainerRunning => {
                let ready = if is_restartable_init(view.spec)
                    && view.spec.get("readinessProbe").is_none()
                    && view.spec.get("startupProbe").is_none()
                {
                    true
                } else {
                    view.ready
                };
                status["ready"] = json!(ready);
                status["started"] = json!(true);
                json!({ "running": { "startedAt": nanos_to_rfc3339(latest.started_at) } })
            },
            cri::ContainerState::ContainerExited => terminated_state(provider, latest),
            cri::ContainerState::ContainerUnknown => {
                json!({ "waiting": { "reason": "ContainerStatusUnknown" } })
            },
        };
        if status.get("lastState").is_none()
            && let Some(previous) = view.previous
            && state_of(previous) == cri::ContainerState::ContainerExited
        {
            status["lastState"] = terminated_state(provider, previous);
        }
    } else if pod_initializing {
        status["state"] = json!({ "waiting": { "reason": "PodInitializing" } });
    } else {
        status["state"] = json!({ "waiting": { "reason": "ContainerCreating" } });
    }
    if let Some(cpu) = &view.cpu {
        status["cpuset"] = json!(cpu.cpuset);
        status["exclusiveCPU"] = json!(cpu.exclusive);
        if cpu.exclusive {
            status["allocatedResources"] = json!({ "cpu": cpu.cpuset });
        }
    }
    status
}

/// Pod conditions in the kubelet's order, keeping `lastTransitionTime` from the
/// pod's current status whenever a condition's status is unchanged.
#[must_use]
pub fn observed_conditions(
    pod: &Value,
    phase: &str,
    unready: &[&str],
    sandbox_ready: bool,
    init_complete: bool,
    unready_init: &[&str],
) -> Vec<Value> {
    let empty = Vec::new();
    let existing = pod
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let now = now_rfc3339();
    let terminal = matches!(phase, "Succeeded" | "Failed");
    let (ready_status, ready_reason, ready_message) = if terminal {
        ("False", "PodCompleted", String::new())
    } else if !init_complete {
        let msg = if unready.is_empty() {
            String::new()
        } else {
            format!("containers with unready status: [{}]", unready.join(" "))
        };
        ("False", "ContainersNotReady", msg)
    } else if unready.is_empty() {
        ("True", "", String::new())
    } else {
        (
            "False",
            "ContainersNotReady",
            format!("containers with unready status: [{}]", unready.join(" ")),
        )
    };
    let (init_status, init_reason, init_message) = if init_complete {
        ("True", "", String::new())
    } else {
        let msg = if unready_init.is_empty() {
            String::new()
        } else {
            format!(
                "containers with incomplete status: [{}]",
                unready_init.join(" ")
            )
        };
        ("False", "ContainersNotInitialized", msg)
    };
    let generation = pod
        .pointer("/metadata/generation")
        .and_then(Value::as_i64)
        .unwrap_or(1);
    let condition = |kind: &str, status: &str, reason: &str, message: &str| {
        let transition = existing
            .iter()
            .find(|c| c["type"].as_str() == Some(kind) && c["status"].as_str() == Some(status))
            .and_then(|c| c.get("lastTransitionTime"))
            .cloned()
            .unwrap_or_else(|| json!(now));
        let mut value = json!({
            "type": kind,
            "status": status,
            "lastProbeTime": Value::Null,
            "lastTransitionTime": transition,
            "observedGeneration": generation,
        });
        if !reason.is_empty() {
            value["reason"] = json!(reason);
        }
        if !message.is_empty() {
            value["message"] = json!(message);
        }
        value
    };
    vec![
        condition(
            "PodReadyToStartContainers",
            if sandbox_ready { "True" } else { "False" },
            "",
            "",
        ),
        condition("Initialized", init_status, init_reason, &init_message),
        condition("Ready", ready_status, ready_reason, &ready_message),
        condition(
            "ContainersReady",
            ready_status,
            ready_reason,
            &ready_message,
        ),
        condition("PodScheduled", "True", "", ""),
    ]
}

/// A status with every container waiting for `reason`; used before anything runs
/// and when sandbox creation fails.
#[must_use]
pub fn pending_status(pod: &Value, node_ip: &str, reason: &str, message: Option<&str>) -> Value {
    let empty = Vec::new();
    let init_containers = pod
        .pointer("/spec/initContainers")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let has_inits = !init_containers.is_empty();

    let init_statuses: Vec<Value> = init_containers
        .iter()
        .map(|c| {
            let mut waiting = json!({ "reason": reason });
            if let Some(message) = message {
                waiting["message"] = json!(message);
            }
            json!({
                "name": c.get("name").and_then(Value::as_str).unwrap_or("init"),
                "image": c.get("image").and_then(Value::as_str).unwrap_or("unknown"),
                "imageID": "",
                "ready": false,
                "started": false,
                "restartCount": 0,
                "state": { "waiting": waiting }
            })
        })
        .collect();

    let app_reason = if has_inits { "PodInitializing" } else { reason };
    let containers = pod
        .pointer("/spec/containers")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let statuses: Vec<Value> = containers
        .iter()
        .map(|c| {
            let mut waiting = json!({ "reason": app_reason });
            if !has_inits && let Some(message) = message {
                waiting["message"] = json!(message);
            }
            json!({
                "name": c.get("name").and_then(Value::as_str).unwrap_or("main"),
                "image": c.get("image").and_then(Value::as_str).unwrap_or("unknown"),
                "imageID": "",
                "ready": false,
                "started": false,
                "restartCount": 0,
                "state": { "waiting": waiting }
            })
        })
        .collect();
    let unready: Vec<&str> = statuses.iter().filter_map(|s| s["name"].as_str()).collect();
    let unready_inits: Vec<&str> = init_statuses
        .iter()
        .filter_map(|s| s["name"].as_str())
        .collect();
    let qos = match determine_pod_qos(pod) {
        PodQoSClass::Guaranteed => "Guaranteed",
        PodQoSClass::Burstable => "Burstable",
        PodQoSClass::BestEffort => "BestEffort",
    };
    let generation = pod
        .pointer("/metadata/generation")
        .and_then(Value::as_i64)
        .unwrap_or(1);
    let mut status = json!({
        "phase": "Pending",
        "qosClass": qos,
        "hostIP": node_ip,
        "hostIPs": [{ "ip": node_ip }],
        "startTime": pod.pointer("/status/startTime").cloned().unwrap_or_else(|| json!(now_rfc3339())),
        "conditions": observed_conditions(pod, "Pending", &unready, false, !has_inits, &unready_inits),
        "containerStatuses": statuses,
        "observedGeneration": generation,
    });
    if let Some(pip) = pod
        .pointer("/status/podIP")
        .and_then(Value::as_str)
        .filter(|ip| !ip.is_empty())
    {
        status["podIP"] = json!(pip);
        if let Some(pips) = pod.pointer("/status/podIPs").cloned() {
            status["podIPs"] = pips;
        } else {
            status["podIPs"] = json!([{ "ip": pip }]);
        }
    }
    if let Some(resize_status) = determine_resize_status(pod, &statuses) {
        status["resize"] = json!(resize_status.as_str());
    }
    if has_inits {
        status["initContainerStatuses"] = json!(init_statuses);
    }
    status
}

/// Container-level labels and annotations present in a CRI status, as a map for
/// matching the attempt back to the kubelet's bookkeeping.
#[must_use]
pub fn attempt_of(status: &cri::ContainerStatus) -> u32 {
    status.metadata.as_ref().map_or(0, |m| m.attempt)
}

/// Groups container statuses by container name, newest attempt last.
#[must_use]
pub fn attempts_by_name(
    statuses: &[cri::ContainerStatus],
) -> BTreeMap<&str, Vec<&cri::ContainerStatus>> {
    let mut map: BTreeMap<&str, Vec<&cri::ContainerStatus>> = BTreeMap::new();
    for status in statuses {
        let name = status.metadata.as_ref().map_or("", |m| m.name.as_str());
        map.entry(name).or_default().push(status);
    }
    for attempts in map.values_mut() {
        attempts.sort_by_key(|s| attempt_of(s));
    }
    map
}

/// Evaluates in-place pod resize status by comparing spec container resources
/// with reported container resources and allocatedResources.
#[must_use]
pub fn determine_resize_status(
    pod: &Value,
    container_statuses: &[Value],
) -> Option<PodResizeStatus> {
    let existing_resize = pod.pointer("/status/resize").and_then(Value::as_str);

    let spec_containers = pod.pointer("/spec/containers").and_then(Value::as_array)?;
    let mut any_pending = false;

    for spec_c in spec_containers {
        let name = spec_c.get("name").and_then(Value::as_str).unwrap_or("");
        let spec_res = spec_c.get("resources");
        let reported_c = container_statuses
            .iter()
            .find(|s| s["name"].as_str() == Some(name));
        let reported_res = reported_c.and_then(|s| s.get("resources"));

        if let Some(spec_res_obj) = spec_res.and_then(Value::as_object)
            && !spec_res_obj.is_empty()
            && spec_res != reported_res
        {
            any_pending = true;
            break;
        }
    }

    if !any_pending {
        return None;
    }

    match existing_resize {
        Some("Infeasible") => Some(PodResizeStatus::Infeasible),
        Some("Deferred") => Some(PodResizeStatus::Deferred),
        _ => Some(PodResizeStatus::InProgress),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_observed_conditions_sandbox_and_inits() {
        let pod = json!({
            "metadata": { "name": "test-pod" },
            "spec": { "containers": [{ "name": "app" }] }
        });

        // Sandbox ready = false, inits complete = false
        let conds = observed_conditions(&pod, "Pending", &["app"], false, false, &["init-1"]);
        let cond_map: BTreeMap<String, String> = conds
            .iter()
            .map(|c| {
                (
                    c["type"].as_str().unwrap().to_string(),
                    c["status"].as_str().unwrap().to_string(),
                )
            })
            .collect();

        assert_eq!(cond_map["PodReadyToStartContainers"], "False");
        assert_eq!(cond_map["Initialized"], "False");
        assert_eq!(cond_map["Ready"], "False");
        assert_eq!(cond_map["ContainersReady"], "False");
        assert_eq!(cond_map["PodScheduled"], "True");

        // Sandbox ready = true, inits complete = true, unready = empty
        let conds_ready = observed_conditions(&pod, "Running", &[], true, true, &[]);
        let cond_map_ready: BTreeMap<String, String> = conds_ready
            .iter()
            .map(|c| {
                (
                    c["type"].as_str().unwrap().to_string(),
                    c["status"].as_str().unwrap().to_string(),
                )
            })
            .collect();

        assert_eq!(cond_map_ready["PodReadyToStartContainers"], "True");
        assert_eq!(cond_map_ready["Initialized"], "True");
        assert_eq!(cond_map_ready["Ready"], "True");
        assert_eq!(cond_map_ready["ContainersReady"], "True");
    }

    #[test]
    fn test_observed_conditions_terminal_phase() {
        let pod = json!({});
        let conds = observed_conditions(&pod, "Succeeded", &[], true, true, &[]);
        let ready_cond = conds.iter().find(|c| c["type"] == "Ready").unwrap();
        assert_eq!(ready_cond["status"], "False");
        assert_eq!(ready_cond["reason"], "PodCompleted");
    }

    #[test]
    fn test_pod_status_ip_and_qos() {
        let pod = json!({
            "metadata": { "name": "qos-pod" },
            "spec": {
                "containers": [{
                    "name": "c1",
                    "resources": {
                        "limits": { "cpu": "1", "memory": "256Mi" },
                        "requests": { "cpu": "1", "memory": "256Mi" }
                    }
                }]
            }
        });

        let views = PodViews::default();
        let status = pod_status(
            &pod,
            "mock",
            "192.168.1.10",
            Some("10.244.0.15"),
            true,
            RestartPolicy::Always,
            views,
        );

        assert_eq!(status["qosClass"], "Guaranteed");
        assert_eq!(status["hostIP"], "192.168.1.10");
        assert_eq!(status["hostIPs"], json!([{ "ip": "192.168.1.10" }]));
        assert_eq!(status["podIP"], "10.244.0.15");
        assert_eq!(status["podIPs"], json!([{ "ip": "10.244.0.15" }]));
        assert!(status["startTime"].is_string());
    }

    #[test]
    fn test_pending_status_preserves_start_time_and_ips() {
        let pod = json!({
            "metadata": { "name": "pending-pod" },
            "spec": {
                "containers": [{ "name": "app" }]
            },
            "status": {
                "startTime": "2026-10-15T12:00:00Z",
                "podIP": "10.244.1.20",
                "podIPs": [{ "ip": "10.244.1.20" }, { "ip": "fd00::20" }]
            }
        });

        let status = pending_status(&pod, "192.168.1.5", "ContainerCreating", None);
        assert_eq!(status["phase"], "Pending");
        assert_eq!(status["startTime"], "2026-10-15T12:00:00Z");
        assert_eq!(status["hostIP"], "192.168.1.5");
        assert_eq!(status["hostIPs"], json!([{ "ip": "192.168.1.5" }]));
        assert_eq!(status["podIP"], "10.244.1.20");
        assert_eq!(
            status["podIPs"],
            json!([{ "ip": "10.244.1.20" }, { "ip": "fd00::20" }])
        );
    }

    #[test]
    fn test_in_place_resize_status_transitions() {
        let spec_pod = json!({
            "spec": {
                "containers": [{
                    "name": "worker",
                    "resources": {
                        "requests": { "cpu": "2", "memory": "512Mi" }
                    }
                }]
            }
        });

        // 1. Initial / matching container status: resize should be None
        let container_statuses_matching = vec![json!({
            "name": "worker",
            "resources": {
                "requests": { "cpu": "2", "memory": "512Mi" }
            },
            "allocatedResources": { "cpu": "2", "memory": "512Mi" }
        })];
        assert_eq!(
            determine_resize_status(&spec_pod, &container_statuses_matching),
            None
        );

        // 2. Unmatched resources without existing status.resize defaults to InProgress
        let container_statuses_old = vec![json!({
            "name": "worker",
            "resources": {
                "requests": { "cpu": "1", "memory": "256Mi" }
            },
            "allocatedResources": { "cpu": "1", "memory": "256Mi" }
        })];
        assert_eq!(
            determine_resize_status(&spec_pod, &container_statuses_old),
            Some(PodResizeStatus::InProgress)
        );

        // 3. Proposed transitions to InProgress
        let mut pod_proposed = spec_pod.clone();
        pod_proposed["status"] = json!({ "resize": "Proposed" });
        assert_eq!(
            determine_resize_status(&pod_proposed, &container_statuses_old),
            Some(PodResizeStatus::InProgress)
        );

        // 4. Deferred is preserved
        let mut pod_deferred = spec_pod.clone();
        pod_deferred["status"] = json!({ "resize": "Deferred" });
        assert_eq!(
            determine_resize_status(&pod_deferred, &container_statuses_old),
            Some(PodResizeStatus::Deferred)
        );

        // 5. Infeasible is preserved
        let mut pod_infeasible = spec_pod.clone();
        pod_infeasible["status"] = json!({ "resize": "Infeasible" });
        assert_eq!(
            determine_resize_status(&pod_infeasible, &container_statuses_old),
            Some(PodResizeStatus::Infeasible)
        );
    }
}
