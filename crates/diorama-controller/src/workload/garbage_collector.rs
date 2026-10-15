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

fn has_foreground_deletion(item: &Value) -> bool {
    let has_del_ts = item
        .pointer("/metadata/deletionTimestamp")
        .and_then(Value::as_str)
        .is_some();
    let has_fg_finalizer = item
        .pointer("/metadata/finalizers")
        .and_then(Value::as_array)
        .is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some("foregroundDeletion")));
    has_del_ts && has_fg_finalizer
}

fn owner_present(res: Result<Value, ApiserverError>, expected_uid: Option<&str>) -> bool {
    match res {
        Ok(owner) => matches_uid(&owner, expected_uid) && !has_foreground_deletion(&owner),
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
        let fg_count = self.reconcile_foreground_owners(namespace).await;
        Ok(rs_count + job_count + pod_count + slice_count + endpoint_count + fg_count)
    }

    async fn reconcile_foreground_owners(&self, namespace: &str) -> usize {
        let pods = self
            .client
            .list_pods(namespace)
            .await
            .ok()
            .and_then(|l| l.get("items").and_then(Value::as_array).cloned())
            .unwrap_or_default();
        let rs_items = self
            .client
            .list_replicasets(namespace)
            .await
            .ok()
            .and_then(|l| l.get("items").and_then(Value::as_array).cloned())
            .unwrap_or_default();

        let mut dep_deployments = rs_items.clone();
        dep_deployments.extend(pods.iter().cloned());

        let mut finalized = 0;
        if let Ok(list) = self.client.list_deployments(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            finalized += self
                .finalize_foreground_owner(namespace, "Deployment", items, &dep_deployments)
                .await;
        }
        finalized += self
            .finalize_foreground_owner(namespace, "ReplicaSet", &rs_items, &pods)
            .await;
        if let Ok(list) = self.client.list_replicationcontrollers(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            finalized += self
                .finalize_foreground_owner(namespace, "ReplicationController", items, &pods)
                .await;
        }
        if let Ok(list) = self.client.list_jobs(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            finalized += self
                .finalize_foreground_owner(namespace, "Job", items, &pods)
                .await;
        }
        if let Ok(list) = self.client.list_statefulsets(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            finalized += self
                .finalize_foreground_owner(namespace, "StatefulSet", items, &pods)
                .await;
        }
        if let Ok(list) = self.client.list_daemonsets(namespace).await
            && let Some(items) = list.get("items").and_then(Value::as_array)
        {
            finalized += self
                .finalize_foreground_owner(namespace, "DaemonSet", items, &pods)
                .await;
        }
        finalized
    }

    async fn finalize_foreground_owner(
        &self,
        namespace: &str,
        kind: &str,
        items: &[Value],
        dependents: &[Value],
    ) -> usize {
        let mut count = 0;
        for item in items {
            if !has_foreground_deletion(item) {
                continue;
            }
            let Some(name) = item.pointer("/metadata/name").and_then(Value::as_str) else {
                continue;
            };
            let uid = item.pointer("/metadata/uid").and_then(Value::as_str);
            if self
                .has_blocking_dependent(namespace, dependents, kind, name, uid)
                .await
            {
                continue;
            }
            if self.strip_and_delete(namespace, kind, name, item).await {
                count += 1;
            }
        }
        count
    }

    async fn strip_and_delete(
        &self,
        namespace: &str,
        kind: &str,
        name: &str,
        item: &Value,
    ) -> bool {
        let mut cleaned = item.clone();
        Self::strip_deletion_metadata(&mut cleaned);
        match kind {
            "Deployment" => {
                let _ = self
                    .client
                    .update_deployment(namespace, name, cleaned)
                    .await;
                self.client.delete_deployment(namespace, name).await.is_ok()
            },
            "ReplicaSet" => {
                let _ = self
                    .client
                    .update_replicaset(namespace, name, cleaned)
                    .await;
                self.client.delete_replicaset(namespace, name).await.is_ok()
            },
            "ReplicationController" => {
                let _ = self
                    .client
                    .update_replicationcontroller(namespace, name, cleaned)
                    .await;
                self.client
                    .delete_replicationcontroller(namespace, name)
                    .await
                    .is_ok()
            },
            "Job" => {
                let _ = self.client.update_job(namespace, name, cleaned).await;
                self.client.delete_job(namespace, name).await.is_ok()
            },
            "StatefulSet" => {
                let _ = self
                    .client
                    .update_statefulset(namespace, name, cleaned)
                    .await;
                self.client
                    .delete_statefulset(namespace, name)
                    .await
                    .is_ok()
            },
            "DaemonSet" => {
                let _ = self.client.update_daemonset(namespace, name, cleaned).await;
                self.client.delete_daemonset(namespace, name).await.is_ok()
            },
            _ => false,
        }
    }

    fn strip_deletion_metadata(obj: &mut Value) {
        if let Some(meta) = obj.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.remove("finalizers");
            meta.remove("deletionTimestamp");
        }
    }

    async fn has_blocking_dependent(
        &self,
        namespace: &str,
        dependents: &[Value],
        owner_kind: &str,
        owner_name: &str,
        owner_uid: Option<&str>,
    ) -> bool {
        for dep in dependents {
            let Some(owners) = dep
                .pointer("/metadata/ownerReferences")
                .and_then(Value::as_array)
            else {
                continue;
            };
            let references_this_owner = owners.iter().any(|o| {
                o.get("kind").and_then(Value::as_str) == Some(owner_kind)
                    && (o.get("name").and_then(Value::as_str) == Some(owner_name)
                        || (owner_uid.is_some()
                            && o.get("uid").and_then(Value::as_str) == owner_uid))
            });
            if !references_this_owner {
                continue;
            }
            // If the dependent is terminating or has no other valid live owner, it blocks foreground deletion
            if dep.pointer("/metadata/deletionTimestamp").is_some() {
                return true;
            }
            let mut has_other_live_owner = false;
            for o in owners {
                let Some(k) = o.get("kind").and_then(Value::as_str) else {
                    continue;
                };
                let Some(n) = o.get("name").and_then(Value::as_str) else {
                    continue;
                };
                if k == owner_kind && n == owner_name {
                    continue;
                }
                let uid = o.get("uid").and_then(Value::as_str);
                if self.check_owner_exists(namespace, k, n, uid).await {
                    has_other_live_owner = true;
                    break;
                }
            }
            if !has_other_live_owner {
                return true;
            }
        }
        false
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
            "ReplicationController" => owner_present(
                self.client.get_replicationcontroller(namespace, name).await,
                expected_uid,
            ),
            "Pod" => owner_present(self.client.get_pod(namespace, name).await, expected_uid),
            "ConfigMap" => owner_present(
                self.client.get_configmap(namespace, name).await,
                expected_uid,
            ),
            "Secret" => owner_present(self.client.get_secret(namespace, name).await, expected_uid),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn foreground_deletion_detection() {
        let clean = json!({
            "metadata": { "name": "test" }
        });
        assert!(!has_foreground_deletion(&clean));

        let del_only = json!({
            "metadata": {
                "name": "test",
                "deletionTimestamp": "2026-10-15T00:00:00Z"
            }
        });
        assert!(!has_foreground_deletion(&del_only));

        let finalizer_only = json!({
            "metadata": {
                "name": "test",
                "finalizers": ["foregroundDeletion"]
            }
        });
        assert!(!has_foreground_deletion(&finalizer_only));

        let foreground = json!({
            "metadata": {
                "name": "test",
                "deletionTimestamp": "2026-10-15T00:00:00Z",
                "finalizers": ["foregroundDeletion"]
            }
        });
        assert!(has_foreground_deletion(&foreground));
    }

    #[test]
    fn uid_matching() {
        let item = json!({
            "metadata": { "name": "test", "uid": "abc-123" }
        });
        assert!(matches_uid(&item, None));
        assert!(matches_uid(&item, Some("")));
        assert!(matches_uid(&item, Some("abc-123")));
        assert!(!matches_uid(&item, Some("xyz-789")));
    }
}
