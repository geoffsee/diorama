pub mod cronjob;
pub mod daemonset;
pub mod deployment;
pub mod endpoints;
pub mod endpointslice;
pub mod garbage_collector;
pub mod job;
pub mod policy;
pub mod replicaset;
pub mod replicationcontroller;
pub mod statefulset;

use std::sync::Arc;

pub use cronjob::CronJobReconciler;
pub use daemonset::DaemonSetReconciler;
pub use deployment::DeploymentReconciler;
use diorama_apiserver::client::KubernetesApiClient;
pub use endpoints::EndpointsReconciler;
pub use endpointslice::EndpointSliceReconciler;
pub use garbage_collector::GarbageCollector;
pub use job::JobReconciler;
pub use policy::{DisruptionReconciler, ResourceQuotaReconciler};
pub use replicaset::ReplicaSetReconciler;
pub use replicationcontroller::ReplicationControllerReconciler;
pub use statefulset::StatefulSetReconciler;

use crate::error::ControllerError;
use serde_json::{Value, json};

/// Outcome of reconciling a specific workload resource collection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReconcileOutcome {
    pub reconciled: usize,
    pub errors: Vec<String>,
}

/// Coordinates workload controllers, endpoint reconciliation and garbage collection.
#[derive(Clone, Debug)]
pub struct WorkloadManager {
    client: Arc<KubernetesApiClient>,
}

impl WorkloadManager {
    #[must_use]
    pub fn new(client: Arc<KubernetesApiClient>) -> Self {
        Self { client }
    }

    #[must_use]
    pub fn client(&self) -> &Arc<KubernetesApiClient> {
        &self.client
    }

    /// Performs a full reconciliation pass across all workloads and services in the specified namespace:
    /// Deployments -> `ReplicaSets` -> `ReplicationControllers` -> `StatefulSets` -> `DaemonSets` ->
    /// `CronJobs` -> Jobs -> `EndpointSlices` -> `Endpoints` -> Garbage Collection.
    pub async fn reconcile_namespace(
        &self,
        namespace: &str,
    ) -> Result<ReconciliationSummary, ControllerError> {
        let mut errors = Vec::new();

        let (deployments, replicasets, statefulsets, daemonsets, cronjobs, jobs) =
            self.reconcile_workloads(namespace, &mut errors).await;

        let (endpointslices, endpoints) = self
            .reconcile_endpoint_resources(namespace, &mut errors)
            .await;

        let disruption = DisruptionReconciler::new(self.client.clone());
        let quotas = ResourceQuotaReconciler::new(self.client.clone());
        let _ = run_stage(|| disruption.reconcile_all(namespace), &mut errors).await;
        let _ = run_stage(|| quotas.reconcile_all(namespace), &mut errors).await;

        let gc = GarbageCollector::new(self.client.clone());
        let garbage_collected = match gc.reconcile(namespace).await {
            Ok(count) => count,
            Err(e) => {
                errors.push(e.to_string());
                0
            },
        };

        Ok(ReconciliationSummary {
            deployments_reconciled: deployments,
            replicasets_reconciled: replicasets,
            statefulsets_reconciled: statefulsets,
            daemonsets_reconciled: daemonsets,
            cronjobs_reconciled: cronjobs,
            jobs_reconciled: jobs,
            endpointslices_reconciled: endpointslices,
            endpoints_reconciled: endpoints,
            garbage_collected,
            errors,
        })
    }

    async fn reconcile_workloads(
        &self,
        namespace: &str,
        errors: &mut Vec<String>,
    ) -> (usize, usize, usize, usize, usize, usize) {
        let deployment_reconciler = DeploymentReconciler::new(self.client.clone());
        let replicaset_reconciler = ReplicaSetReconciler::new(self.client.clone());
        let rc_reconciler = ReplicationControllerReconciler::new(self.client.clone());
        let statefulset_reconciler = StatefulSetReconciler::new(self.client.clone());
        let daemonset_reconciler = DaemonSetReconciler::new(self.client.clone());
        let cronjob_reconciler = CronJobReconciler::new(self.client.clone());
        let job_reconciler = JobReconciler::new(self.client.clone());

        let deployments =
            run_stage(|| deployment_reconciler.reconcile_all(namespace), errors).await;
        let replicasets =
            run_stage(|| replicaset_reconciler.reconcile_all(namespace), errors).await;
        let _rcs = run_stage(|| rc_reconciler.reconcile_all(namespace), errors).await;
        let statefulsets =
            run_stage(|| statefulset_reconciler.reconcile_all(namespace), errors).await;
        let daemonsets = run_stage(|| daemonset_reconciler.reconcile_all(namespace), errors).await;
        let cronjobs = run_stage(|| cronjob_reconciler.reconcile_all(namespace), errors).await;
        let jobs = run_stage(|| job_reconciler.reconcile_all(namespace), errors).await;

        (
            deployments,
            replicasets,
            statefulsets,
            daemonsets,
            cronjobs,
            jobs,
        )
    }

    async fn reconcile_endpoint_resources(
        &self,
        namespace: &str,
        errors: &mut Vec<String>,
    ) -> (usize, usize) {
        let endpointslice_reconciler = EndpointSliceReconciler::new(self.client.clone());
        let endpoints_reconciler = EndpointsReconciler::new(self.client.clone());

        let endpointslices =
            run_stage(|| endpointslice_reconciler.reconcile_all(namespace), errors).await;
        let endpoints = run_stage(|| endpoints_reconciler.reconcile_all(namespace), errors).await;

        (endpointslices, endpoints)
    }
}

async fn run_stage<F, Fut>(f: F, errors: &mut Vec<String>) -> usize
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<ReconcileOutcome, ControllerError>>,
{
    match f().await {
        Ok(outcome) => {
            errors.extend(outcome.errors);
            outcome.reconciled
        },
        Err(e) => {
            errors.push(e.to_string());
            0
        },
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReconciliationSummary {
    pub deployments_reconciled: usize,
    pub replicasets_reconciled: usize,
    pub statefulsets_reconciled: usize,
    pub daemonsets_reconciled: usize,
    pub cronjobs_reconciled: usize,
    pub jobs_reconciled: usize,
    pub endpointslices_reconciled: usize,
    pub endpoints_reconciled: usize,
    pub garbage_collected: usize,
    pub errors: Vec<String>,
}

impl ReconciliationSummary {
    #[must_use]
    pub fn total_workloads(&self) -> usize {
        self.deployments_reconciled
            + self.replicasets_reconciled
            + self.statefulsets_reconciled
            + self.daemonsets_reconciled
            + self.cronjobs_reconciled
            + self.jobs_reconciled
            + self.endpointslices_reconciled
            + self.endpoints_reconciled
            + self.garbage_collected
    }
}

/// Returns true if a pod is ready and not marked for deletion.
#[must_use]
pub fn is_pod_ready(pod: &Value) -> bool {
    if pod
        .pointer("/metadata/deletionTimestamp")
        .and_then(Value::as_str)
        .is_some()
    {
        return false;
    }

    if let Some(conditions) = pod.pointer("/status/conditions").and_then(|c| c.as_array()) {
        for condition in conditions {
            if condition.get("type").and_then(|t| t.as_str()) == Some("Ready") {
                return condition.get("status").and_then(|s| s.as_str()) == Some("True");
            }
        }
    }

    if let Some(phase) = pod.pointer("/status/phase").and_then(|p| p.as_str()) {
        return phase == "Running";
    }

    false
}

/// Returns true if `selector` defines at least one `matchLabels` or `matchExpressions` rule
/// (or at least one key-value pair for a flat selector map like `ReplicationController.spec.selector`).
#[must_use]
pub fn has_label_selector(selector: Option<&Value>) -> bool {
    let Some(obj) = selector.and_then(Value::as_object) else {
        return false;
    };
    if obj.is_empty() {
        return false;
    }
    if obj.contains_key("matchLabels") || obj.contains_key("matchExpressions") {
        let has_match_labels = obj
            .get("matchLabels")
            .and_then(Value::as_object)
            .is_some_and(|m| !m.is_empty());
        let has_match_exprs = obj
            .get("matchExpressions")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty());
        return has_match_labels || has_match_exprs;
    }
    true
}

/// Evaluates a Kubernetes `LabelSelector` (`matchLabels` + `matchExpressions`) or a flat
/// key-value map (`ReplicationController.spec.selector`) against a candidate's `metadata.labels`.
#[must_use]
pub fn matches_label_selector(selector: &Value, labels: Option<&Value>) -> bool {
    let Some(sel_obj) = selector.as_object() else {
        return false;
    };
    if sel_obj.is_empty() {
        return false;
    }
    let labels_map = labels.and_then(Value::as_object);
    if sel_obj.contains_key("matchLabels") || sel_obj.contains_key("matchExpressions") {
        if let Some(ml) = sel_obj.get("matchLabels").and_then(Value::as_object) {
            for (k, v) in ml {
                let Some(expected) = v.as_str() else {
                    continue;
                };
                if labels_map.and_then(|m| m.get(k)).and_then(Value::as_str) != Some(expected) {
                    return false;
                }
            }
        }
        if let Some(me) = sel_obj.get("matchExpressions").and_then(Value::as_array) {
            for expr in me {
                let key = expr.get("key").and_then(Value::as_str).unwrap_or("");
                let op = expr.get("operator").and_then(Value::as_str).unwrap_or("");
                let vals: Vec<&str> = expr
                    .get("values")
                    .and_then(Value::as_array)
                    .map(|arr| arr.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let actual = labels_map.and_then(|m| m.get(key)).and_then(Value::as_str);
                let ok = match op {
                    "In" => actual.is_some_and(|a| vals.contains(&a)),
                    "NotIn" => actual.is_none_or(|a| !vals.contains(&a)),
                    "Exists" => actual.is_some(),
                    "DoesNotExist" => actual.is_none(),
                    _ => false,
                };
                if !ok {
                    return false;
                }
            }
        }
        true
    } else {
        for (k, v) in sel_obj {
            let Some(expected) = v.as_str() else {
                continue;
            };
            if labels_map.and_then(|m| m.get(k)).and_then(Value::as_str) != Some(expected) {
                return false;
            }
        }
        true
    }
}

fn is_pod_owned_by(pod: &Value, owner_kind: &str, owner_name: &str, owner_uid: &str) -> bool {
    pod.get("metadata")
        .and_then(|m| m.get("ownerReferences"))
        .and_then(Value::as_array)
        .is_some_and(|owners| {
            owners.iter().any(|o| {
                let matches_kind = o.get("kind").and_then(Value::as_str) == Some(owner_kind);
                let matches_uid = !owner_uid.is_empty()
                    && o.get("uid").and_then(Value::as_str) == Some(owner_uid);
                let matches_name = o.get("name").and_then(Value::as_str) == Some(owner_name);
                matches_kind && (matches_uid || matches_name)
            })
        })
}

fn remove_owner_reference(pod: &mut Value, owner_kind: &str, owner_name: &str, owner_uid: &str) {
    let Some(owners) = pod
        .pointer_mut("/metadata/ownerReferences")
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    owners.retain(|o| {
        let same_kind = o.get("kind").and_then(Value::as_str) == Some(owner_kind);
        let same_uid =
            !owner_uid.is_empty() && o.get("uid").and_then(Value::as_str) == Some(owner_uid);
        let same_name = o.get("name").and_then(Value::as_str) == Some(owner_name);
        !(same_kind && (same_uid || same_name))
    });
}

async fn adopt_pod_if_eligible(
    client: &KubernetesApiClient,
    namespace: &str,
    mut pod: Value,
    owner_ref: Value,
) -> Value {
    if let Some(meta) = pod.get_mut("metadata").and_then(Value::as_object_mut) {
        let owners = meta
            .entry("ownerReferences".to_string())
            .or_insert_with(|| json!([]));
        if let Some(arr) = owners.as_array_mut() {
            arr.push(owner_ref);
        }
    }
    let Some(pname) = pod
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return pod;
    };
    match client.update_pod(namespace, &pname, pod.clone()).await {
        Ok(updated) => updated,
        Err(_) => pod,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn adopt_and_release_pods(
    client: &KubernetesApiClient,
    namespace: &str,
    owner_api_version: &str,
    owner_kind: &str,
    owner_name: &str,
    owner_uid: &str,
    owner_deleting: bool,
    selector: Option<&Value>,
) -> Result<Vec<Value>, ControllerError> {
    let pod_list =
        client
            .list_pods(namespace)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: "pods".to_string(),
                reason: e.to_string(),
            })?;

    let all_pods = pod_list
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let active_selector = selector.filter(|s| has_label_selector(Some(s)));
    let mut owned_pods = Vec::new();

    for mut pod in all_pods {
        let not_terminating = pod
            .get("metadata")
            .and_then(|m| m.get("deletionTimestamp"))
            .and_then(Value::as_str)
            .is_none();
        if !not_terminating {
            continue;
        }

        let is_owned = is_pod_owned_by(&pod, owner_kind, owner_name, owner_uid);

        if is_owned {
            if let Some(sel) = active_selector
                && !matches_label_selector(sel, pod.pointer("/metadata/labels"))
            {
                remove_owner_reference(&mut pod, owner_kind, owner_name, owner_uid);
                if let Some(pname) = pod
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                {
                    let _ = client.update_pod(namespace, &pname, pod).await;
                }
                continue;
            }
            owned_pods.push(pod);
        } else if !owner_deleting && let Some(sel) = active_selector {
            let has_controller = pod
                .pointer("/metadata/ownerReferences")
                .and_then(Value::as_array)
                .is_some_and(|owners| {
                    owners
                        .iter()
                        .any(|o| o.get("controller").and_then(Value::as_bool).unwrap_or(true))
                });
            if !has_controller && matches_label_selector(sel, pod.pointer("/metadata/labels")) {
                let owner_ref = json!({
                    "apiVersion": owner_api_version,
                    "kind": owner_kind,
                    "name": owner_name,
                    "uid": owner_uid,
                    "controller": true,
                    "blockOwnerDeletion": true
                });
                owned_pods.push(adopt_pod_if_eligible(client, namespace, pod, owner_ref).await);
            }
        }
    }

    owned_pods.sort_by(|a, b| {
        let name_a = a
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let name_b = b
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("");
        name_a.cmp(name_b)
    });

    Ok(owned_pods)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_is_pod_ready() {
        let ready_pod = json!({
            "metadata": { "name": "pod-1" },
            "status": {
                "phase": "Running",
                "conditions": [
                    { "type": "Ready", "status": "True" }
                ]
            }
        });
        assert!(is_pod_ready(&ready_pod));

        let not_ready_pod = json!({
            "metadata": { "name": "pod-2" },
            "status": {
                "phase": "Running",
                "conditions": [
                    { "type": "Ready", "status": "False" }
                ]
            }
        });
        assert!(!is_pod_ready(&not_ready_pod));

        let deleting_pod = json!({
            "metadata": {
                "name": "pod-3",
                "deletionTimestamp": "2026-10-12T00:00:00Z"
            },
            "status": {
                "phase": "Running",
                "conditions": [
                    { "type": "Ready", "status": "True" }
                ]
            }
        });
        assert!(!is_pod_ready(&deleting_pod));

        let null_deleting_pod = json!({
            "metadata": {
                "name": "pod-3-null",
                "deletionTimestamp": null
            },
            "status": {
                "phase": "Running",
                "conditions": [
                    { "type": "Ready", "status": "True" }
                ]
            }
        });
        assert!(is_pod_ready(&null_deleting_pod));

        let running_pod = json!({
            "metadata": { "name": "pod-4" },
            "status": { "phase": "Running" }
        });
        assert!(is_pod_ready(&running_pod));

        let pending_pod = json!({
            "metadata": { "name": "pod-5" },
            "status": { "phase": "Pending" }
        });
        assert!(!is_pod_ready(&pending_pod));
    }

    #[test]
    fn test_total_workloads() {
        let summary = ReconciliationSummary {
            deployments_reconciled: 1,
            replicasets_reconciled: 2,
            statefulsets_reconciled: 3,
            daemonsets_reconciled: 4,
            cronjobs_reconciled: 5,
            jobs_reconciled: 6,
            endpointslices_reconciled: 7,
            endpoints_reconciled: 8,
            garbage_collected: 9,
            errors: Vec::new(),
        };
        assert_eq!(summary.total_workloads(), 45);
    }
}
