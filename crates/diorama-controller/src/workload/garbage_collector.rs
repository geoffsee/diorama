use std::sync::Arc;

use diorama_apiserver::client::KubernetesApiClient;
use serde_json::Value;

use crate::error::ControllerError;

use diorama_apiserver::ApiserverError;

fn matches_uid(item: &Value, expected_uid: Option<&str>) -> bool {
    let Some(uid) = expected_uid else { return true };
    if uid.is_empty() {
        return true;
    }
    item.get("metadata")
        .and_then(|m| m.get("uid"))
        .and_then(Value::as_str)
        == Some(uid)
}

fn owner_present(res: Result<Value, ApiserverError>, expected_uid: Option<&str>) -> bool {
    match res {
        Ok(owner) => matches_uid(&owner, expected_uid),
        Err(ApiserverError::NotFound { .. }) => false,
        Err(_) => true, // Transient/permission error: assume owner present to prevent eager deletion
    }
}

#[derive(Clone, Debug)]
pub struct GarbageCollector {
    client: Arc<KubernetesApiClient>,
}

impl GarbageCollector {
    #[must_use]
    pub fn new(client: Arc<KubernetesApiClient>) -> Self {
        Self { client }
    }

    /// Reconciles garbage collection in the specified namespace, removing eligible dependents
    /// whose `ownerReferences` point to non-existent parents. Runs recursively until cascading deletes converge.
    pub async fn reconcile(&self, namespace: &str) -> Result<usize, ControllerError> {
        let mut total_deleted = 0;
        let mut iterations = 0;

        loop {
            if iterations > 100 {
                return Err(ControllerError::ReconciliationFailed {
                    resource: format!("garbage collection in namespace '{namespace}'"),
                    reason: "cascading deletion did not converge within 100 passes".to_string(),
                });
            }
            iterations += 1;
            let pass_deleted = self.reconcile_pass(namespace).await?;
            if pass_deleted == 0 {
                break;
            }
            total_deleted += pass_deleted;
        }

        Ok(total_deleted)
    }

    async fn reconcile_pass(&self, namespace: &str) -> Result<usize, ControllerError> {
        let rs_count = self.reconcile_replicasets(namespace).await;
        let job_count = self.reconcile_jobs(namespace).await;
        let pod_count = self.reconcile_pods(namespace).await;
        let slice_count = self.reconcile_endpointslices(namespace).await;
        let endpoint_count = self.reconcile_endpoints(namespace).await;
        Ok(rs_count + job_count + pod_count + slice_count + endpoint_count)
    }

    async fn reconcile_replicasets(&self, namespace: &str) -> usize {
        let Ok(rs_list) = self.client.list_replicasets(namespace).await else {
            return 0;
        };
        let Some(items) = rs_list.get("items").and_then(Value::as_array) else {
            return 0;
        };

        let mut deleted = 0;
        for rs in items {
            if !self.is_eligible_dependent(namespace, rs).await {
                continue;
            }
            let Some(name) = rs
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            if self.client.delete_replicaset(namespace, name).await.is_ok() {
                deleted += 1;
            }
        }
        deleted
    }

    async fn reconcile_jobs(&self, namespace: &str) -> usize {
        let Ok(job_list) = self.client.list_jobs(namespace).await else {
            return 0;
        };
        let Some(items) = job_list.get("items").and_then(Value::as_array) else {
            return 0;
        };

        let mut deleted = 0;
        for job in items {
            if !self.is_eligible_dependent(namespace, job).await {
                continue;
            }
            let Some(name) = job
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            if self.client.delete_job(namespace, name).await.is_ok() {
                deleted += 1;
            }
        }
        deleted
    }

    async fn reconcile_pods(&self, namespace: &str) -> usize {
        let Ok(pod_list) = self.client.list_pods(namespace).await else {
            return 0;
        };
        let Some(items) = pod_list.get("items").and_then(Value::as_array) else {
            return 0;
        };

        let mut deleted = 0;
        for pod in items {
            if !self.is_eligible_dependent(namespace, pod).await {
                continue;
            }
            let Some(name) = pod
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            if self.client.delete_pod(namespace, name).await.is_ok() {
                deleted += 1;
            }
        }
        deleted
    }

    async fn reconcile_endpointslices(&self, namespace: &str) -> usize {
        let Ok(list) = self.client.list_endpointslices(namespace).await else {
            return 0;
        };
        let Some(items) = list.get("items").and_then(Value::as_array) else {
            return 0;
        };

        let mut deleted = 0;
        for item in items {
            if !self.is_eligible_dependent(namespace, item).await {
                continue;
            }
            let Some(name) = item
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            if self
                .client
                .delete_endpointslice(namespace, name)
                .await
                .is_ok()
            {
                deleted += 1;
            }
        }
        deleted
    }

    async fn reconcile_endpoints(&self, namespace: &str) -> usize {
        let Ok(list) = self.client.list_endpoints(namespace).await else {
            return 0;
        };
        let Some(items) = list.get("items").and_then(Value::as_array) else {
            return 0;
        };

        let mut deleted = 0;
        for item in items {
            if !self.is_eligible_dependent(namespace, item).await {
                continue;
            }
            let Some(name) = item
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            if self.client.delete_endpoints(namespace, name).await.is_ok() {
                deleted += 1;
            }
        }
        deleted
    }

    async fn check_owner_exists(
        &self,
        namespace: &str,
        kind: &str,
        name: &str,
        expected_uid: Option<&str>,
    ) -> bool {
        match kind {
            "Deployment" => owner_present(
                self.client.get_deployment(namespace, name).await,
                expected_uid,
            ),
            "ReplicaSet" => owner_present(
                self.client.get_replicaset(namespace, name).await,
                expected_uid,
            ),
            "StatefulSet" => owner_present(
                self.client.get_statefulset(namespace, name).await,
                expected_uid,
            ),
            "DaemonSet" => owner_present(
                self.client.get_daemonset(namespace, name).await,
                expected_uid,
            ),
            "Job" => owner_present(self.client.get_job(namespace, name).await, expected_uid),
            "CronJob" => {
                owner_present(self.client.get_cronjob(namespace, name).await, expected_uid)
            },
            "Service" => {
                owner_present(self.client.get_service(namespace, name).await, expected_uid)
            },
            _ => true,
        }
    }

    async fn is_eligible_dependent(&self, namespace: &str, resource: &Value) -> bool {
        if resource
            .get("metadata")
            .and_then(|m| m.get("deletionTimestamp"))
            .and_then(Value::as_str)
            .is_some()
        {
            return false;
        }

        let Some(owner_refs) = resource
            .get("metadata")
            .and_then(|m| m.get("ownerReferences"))
            .and_then(Value::as_array)
        else {
            return false;
        };

        if owner_refs.is_empty() {
            return false;
        }

        let mut valid_owner_count = 0;
        for owner in owner_refs {
            let Some(kind) = owner.get("kind").and_then(Value::as_str) else {
                continue;
            };
            let Some(name) = owner.get("name").and_then(Value::as_str) else {
                continue;
            };
            valid_owner_count += 1;
            let expected_uid = owner.get("uid").and_then(Value::as_str);

            if self
                .check_owner_exists(namespace, kind, name, expected_uid)
                .await
            {
                return false;
            }
        }

        valid_owner_count > 0
    }
}
