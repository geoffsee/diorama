use std::sync::Arc;

use diorama_apiserver::client::KubernetesApiClient;
use serde_json::{Value, json};

use crate::error::ControllerError;
use crate::workload::ReconcileOutcome;

#[derive(Clone, Debug)]
pub struct ReplicaSetReconciler {
    client: Arc<KubernetesApiClient>,
}

impl ReplicaSetReconciler {
    #[must_use]
    pub fn new(client: Arc<KubernetesApiClient>) -> Self {
        Self { client }
    }

    /// Reconciles all `ReplicaSets` in the specified namespace.
    pub async fn reconcile_all(
        &self,
        namespace: &str,
    ) -> Result<ReconcileOutcome, ControllerError> {
        let list = self.client.list_replicasets(namespace).await.map_err(|e| {
            ControllerError::ReconciliationFailed {
                resource: "replicasets".to_string(),
                reason: e.to_string(),
            }
        })?;

        let items = list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut count = 0;
        let mut errors = Vec::new();
        for replicaset in items {
            match self.reconcile_replicaset(namespace, &replicaset).await {
                Ok(_) => count += 1,
                Err(err) => errors.push(err.to_string()),
            }
        }

        Ok(ReconcileOutcome {
            reconciled: count,
            errors,
        })
    }

    async fn get_owned_pods(
        &self,
        namespace: &str,
        name: &str,
        uid: &str,
        deleting: bool,
        selector: Option<&Value>,
    ) -> Result<Vec<Value>, ControllerError> {
        super::adopt_and_release_pods(
            &self.client,
            namespace,
            "apps/v1",
            "ReplicaSet",
            name,
            uid,
            deleting,
            selector,
        )
        .await
    }

    async fn scale_up_pods(
        &self,
        namespace: &str,
        name: &str,
        uid: &str,
        current_count: usize,
        desired_replicas: usize,
        template: &Value,
    ) -> Result<(), ControllerError> {
        let template_labels = template
            .get("metadata")
            .and_then(|m| m.get("labels"))
            .cloned()
            .unwrap_or_else(|| json!({}));

        let template_spec = template
            .get("spec")
            .cloned()
            .unwrap_or_else(|| json!({ "containers": [] }));

        let needed = desired_replicas.saturating_sub(current_count);
        let mut created = 0;
        let mut idx = 0;

        while created < needed {
            let pod_name = format!("{name}-{idx}");
            idx += 1;
            if self.client.get_pod(namespace, &pod_name).await.is_ok() {
                continue;
            }

            let new_pod = json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": pod_name,
                    "namespace": namespace,
                    "labels": template_labels,
                    "ownerReferences": [{
                        "apiVersion": "apps/v1",
                        "kind": "ReplicaSet",
                        "name": name,
                        "uid": uid,
                        "controller": true,
                        "blockOwnerDeletion": true
                    }]
                },
                "spec": template_spec,
                "status": {
                    "phase": "Pending"
                }
            });

            self.client
                .create_pod(namespace, new_pod)
                .await
                .map_err(|e| ControllerError::ReconciliationFailed {
                    resource: format!("pods/{pod_name}"),
                    reason: e.to_string(),
                })?;
            created += 1;
        }
        Ok(())
    }

    async fn scale_down_pods(
        &self,
        namespace: &str,
        owned_pods: &[Value],
        desired_replicas: usize,
    ) -> Result<(), ControllerError> {
        for pod in owned_pods.iter().skip(desired_replicas) {
            if let Some(pod_name) = pod
                .get("metadata")
                .and_then(|m| m.get("name"))
                .and_then(Value::as_str)
            {
                self.client
                    .delete_pod(namespace, pod_name)
                    .await
                    .map_err(|e| ControllerError::ReconciliationFailed {
                        resource: format!("pods/{pod_name}"),
                        reason: e.to_string(),
                    })?;
            }
        }
        Ok(())
    }

    /// Reconciles a single `ReplicaSet` by creating or removing child Pods to match desired replicas.
    pub async fn reconcile_replicaset(
        &self,
        namespace: &str,
        replicaset: &Value,
    ) -> Result<Value, ControllerError> {
        let name = replicaset
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ControllerError::InvalidConfiguration {
                field: "metadata.name".to_string(),
                reason: "ReplicaSet missing metadata.name".to_string(),
            })?;

        let uid = replicaset
            .get("metadata")
            .and_then(|m| m.get("uid"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let deleting = replicaset
            .pointer("/metadata/deletionTimestamp")
            .and_then(Value::as_str)
            .is_some();

        let desired_replicas = replicaset
            .get("spec")
            .and_then(|s| s.get("replicas"))
            .and_then(Value::as_i64)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(1);

        let selector = replicaset.pointer("/spec/selector");
        let template = replicaset
            .get("spec")
            .and_then(|s| s.get("template"))
            .cloned()
            .unwrap_or_else(|| json!({ "spec": { "containers": [] } }));

        let owned_pods = self
            .get_owned_pods(namespace, name, uid, deleting, selector)
            .await?;
        let current_count = owned_pods.len();

        if !deleting {
            if current_count < desired_replicas {
                self.scale_up_pods(
                    namespace,
                    name,
                    uid,
                    current_count,
                    desired_replicas,
                    &template,
                )
                .await?;
            } else if current_count > desired_replicas {
                self.scale_down_pods(namespace, &owned_pods, desired_replicas)
                    .await?;
            }
        }
        let updated_owned_pods = if current_count == desired_replicas || deleting {
            owned_pods
        } else {
            self.get_owned_pods(namespace, name, uid, deleting, selector)
                .await?
        };
        let actual_replicas = updated_owned_pods.len();
        let ready_replicas = updated_owned_pods
            .iter()
            .take(actual_replicas)
            .filter(|p| super::is_pod_ready(p))
            .count();
        let observed_generation = replicaset
            .pointer("/metadata/generation")
            .and_then(Value::as_i64)
            .unwrap_or(1);

        let mut updated_rs = replicaset.clone();
        if let Some(status) = updated_rs.get_mut("status").and_then(Value::as_object_mut) {
            status.insert("replicas".to_string(), json!(actual_replicas));
            status.insert("fullyLabeledReplicas".to_string(), json!(actual_replicas));
            status.insert("readyReplicas".to_string(), json!(ready_replicas));
            status.insert("availableReplicas".to_string(), json!(ready_replicas));
            status.insert("observedGeneration".to_string(), json!(observed_generation));
        } else if let Some(rs_obj) = updated_rs.as_object_mut() {
            rs_obj.insert(
                "status".to_string(),
                json!({
                    "replicas": actual_replicas,
                    "fullyLabeledReplicas": actual_replicas,
                    "readyReplicas": ready_replicas,
                    "availableReplicas": ready_replicas,
                    "observedGeneration": observed_generation
                }),
            );
        }

        if updated_rs.get("status") == replicaset.get("status") {
            return Ok(updated_rs);
        }

        self.client
            .update_replicaset(namespace, name, updated_rs)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: format!("replicasets/{name}"),
                reason: e.to_string(),
            })
    }
}

pub(crate) fn is_pod_ready(pod: &Value) -> bool {
    super::is_pod_ready(pod)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_replicaset_is_pod_ready_respects_not_ready_condition() {
        let pod = json!({
            "metadata": { "name": "rs-pod-1" },
            "status": {
                "phase": "Running",
                "conditions": [
                    { "type": "Ready", "status": "False" }
                ]
            }
        });
        assert!(!is_pod_ready(&pod));
    }
}
