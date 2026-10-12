pub mod cronjob;
pub mod daemonset;
pub mod deployment;
pub mod endpoints;
pub mod endpointslice;
pub mod garbage_collector;
pub mod job;
pub mod replicaset;
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
pub use replicaset::ReplicaSetReconciler;
pub use statefulset::StatefulSetReconciler;

use crate::error::ControllerError;
use serde_json::Value;

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
    /// Deployments -> `ReplicaSets` -> `StatefulSets` -> `DaemonSets` -> `CronJobs` -> Jobs ->
    /// `EndpointSlices` -> `Endpoints` -> Garbage Collection.
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
        let statefulset_reconciler = StatefulSetReconciler::new(self.client.clone());
        let daemonset_reconciler = DaemonSetReconciler::new(self.client.clone());
        let cronjob_reconciler = CronJobReconciler::new(self.client.clone());
        let job_reconciler = JobReconciler::new(self.client.clone());

        let deployments =
            run_stage(|| deployment_reconciler.reconcile_all(namespace), errors).await;
        let replicasets =
            run_stage(|| replicaset_reconciler.reconcile_all(namespace), errors).await;
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
    if pod.pointer("/metadata/deletionTimestamp").is_some() {
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
