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
